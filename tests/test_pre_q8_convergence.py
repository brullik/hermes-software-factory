from __future__ import annotations

import base64
import hashlib
import json
import runpy
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from factory.common import sha256_text, stable_json
from factory.functional_readiness import PRE_Q8_SCENARIOS
from factory.pre_q8_convergence import (
    ConvergenceScenarioResult,
    ConvergenceStore,
    matrix_body,
    resource_idempotency_key,
    resource_namespace,
    run_sweep,
)
from factory.pre_q8_fixture import fixture_files, fixture_manifest
from factory.pre_q8_seal import (
    PreQ8SealError,
    build_seal_payload,
    qualification_config_semantic_digest,
    sign_seal,
    verify_seal,
)
from scripts.pre_q8_fixture import GitHubAPIError, GitHubClient, archive, provision

RUN_ID = "run-20260810-a1"
CANDIDATE = "a" * 64
ROOT = Path(__file__).parents[1]


def _result(scenario_id: str, status: str = "PASS") -> ConvergenceScenarioResult:
    return ConvergenceScenarioResult(
        scenario_id=scenario_id,
        status=status,
        evidence_digest=sha256_text(f"evidence:{scenario_id}:{status}"),
        config_digest=sha256_text(f"config:{scenario_id}"),
        failure_class="SCENARIO_FAILED" if status == "FAIL" else None,
    )


def test_convergence_runs_all_ten_after_individual_failures() -> None:
    calls: list[str] = []

    def execute(scenario_id: str) -> ConvergenceScenarioResult:
        calls.append(scenario_id)
        if scenario_id in {PRE_Q8_SCENARIOS[1], PRE_Q8_SCENARIOS[7]}:
            raise RuntimeError("fixture failure")
        return _result(scenario_id)

    results = run_sweep(RUN_ID, execute)
    assert tuple(calls) == PRE_Q8_SCENARIOS
    assert len(results) == 10
    assert sum(result.status == "FAIL" for result in results) == 2
    matrix = matrix_body(
        run_id=RUN_ID,
        git_tree="b" * 40,
        release_tree_digest="c" * 64,
        toolchain_digest="d" * 64,
        results=results,
    )
    assert matrix["scenario_count"] == 10
    assert matrix["pass_count"] == 8
    assert matrix["status"] == "SWEEP_FAILED"


def test_convergence_pre_q8_q8_namespaces_do_not_collide() -> None:
    names = {
        resource_namespace(
            plane=plane,
            run_id=RUN_ID,
            candidate_digest=CANDIDATE,
            scenario_id=PRE_Q8_SCENARIOS[0],
        )
        for plane in ("convergence", "pre-q8", "q8")
    }
    keys = {
        resource_idempotency_key(
            plane=plane,
            run_id=RUN_ID,
            candidate_digest=CANDIDATE,
            scenario_id=PRE_Q8_SCENARIOS[0],
        )
        for plane in ("convergence", "pre-q8", "q8")
    }
    assert len(names) == 3
    assert len(keys) == 3
    assert resource_namespace(
        plane="convergence",
        run_id="run-prefix-a111",
        candidate_digest=CANDIDATE,
        scenario_id=PRE_Q8_SCENARIOS[0],
    ) != resource_namespace(
        plane="convergence",
        run_id="run-prefix-a222",
        candidate_digest=CANDIDATE,
        scenario_id=PRE_Q8_SCENARIOS[0],
    )


def _signed_seal(tmp_path: Path) -> tuple[dict[str, object], str, dict[str, str]]:
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    key_path = tmp_path / "verifier.key"
    key_path.write_bytes(raw_private)
    public = private.public_key().public_bytes_raw()
    public_digest = hashlib.sha256(public).hexdigest()
    generated = {scenario: sha256_text(f"config:{scenario}") for scenario in PRE_Q8_SCENARIOS}
    evidence = {scenario: sha256_text(f"evidence:{scenario}") for scenario in PRE_Q8_SCENARIOS}
    payload = build_seal_payload(
        run_id=RUN_ID,
        source_commit="1" * 40,
        git_tree="2" * 40,
        release_tree_digest="3" * 64,
        requirements_lock_digest="4" * 64,
        toolchain_digest="5" * 64,
        systemd_bundle_digest="6" * 64,
        catalog_digest="7" * 64,
        base_config_digest="8" * 64,
        generated_config_digests=generated,
        capability_attestation_digest="9" * 64,
        fixture_seed_digest="a" * 64,
        evidence_digests=evidence,
        matrix_digest="b" * 64,
        public_key_digest=public_digest,
    )
    return sign_seal(payload, key_path), base64.b64encode(public).decode("ascii"), generated


def _identity() -> dict[str, str]:
    return {
        "git_tree": "2" * 40,
        "release_tree_digest": "3" * 64,
        "requirements_lock_digest": "4" * 64,
        "toolchain_digest": "5" * 64,
        "systemd_bundle_digest": "6" * 64,
        "catalog_digest": "7" * 64,
        "base_config_digest": "8" * 64,
        "capability_attestation_digest": "9" * 64,
        "fixture_seed_digest": "a" * 64,
        "matrix_digest": "b" * 64,
    }


def test_seal_rejects_any_identity_change(
    tmp_path: Path,
) -> None:
    seal, public_key, generated = _signed_seal(tmp_path)
    trust = str(seal["verifier_public_key_digest"])
    digest = verify_seal(
        seal,
        verifier_public_key=public_key,
        trusted_public_key_digest=trust,
        expected_identity=_identity(),
        expected_generated_config_digests=generated,
    )
    assert digest == seal["seal_digest"]
    # The admitted commit SHA may differ after merge; exact tree/release bytes may not.
    changed = _identity()
    changed["release_tree_digest"] = "f" * 64
    with pytest.raises(PreQ8SealError, match="release_tree_digest"):
        verify_seal(
            seal,
            verifier_public_key=public_key,
            trusted_public_key_digest=trust,
            expected_identity=changed,
            expected_generated_config_digests=generated,
        )


def test_convergence_store_persists_complete_canonical_sweep(tmp_path: Path) -> None:
    store = ConvergenceStore((tmp_path / "convergence.db").resolve())
    try:
        assert store.start(
            run_id=RUN_ID,
            candidate_digest=CANDIDATE,
            git_tree="b" * 40,
            release_tree_digest="c" * 64,
            toolchain_digest="d" * 64,
        )
        for scenario_id in PRE_Q8_SCENARIOS:
            assert store.record(RUN_ID, _result(scenario_id))
        assert store.finalize(RUN_ID) == "CONVERGENCE_10_OF_10"
        assert tuple(result.scenario_id for result in store.results(RUN_ID)) == (
            PRE_Q8_SCENARIOS
        )
        store.mark_sealed(RUN_ID)
        store.mark_sealed(RUN_ID)
    finally:
        store.close()


def test_seal_config_digest_normalizes_only_isolation_coordinates() -> None:
    def payload(
        plane: str,
        epoch: str,
        root: str,
        port: int,
        repository: str,
    ) -> dict[str, object]:
        state = f"{root}/{epoch}/{RUN_ID}/{PRE_Q8_SCENARIOS[0]}"
        logs = f"{root}-logs/{epoch}/{RUN_ID}/{PRE_Q8_SCENARIOS[0]}"
        return {
            "controller": {"database_url": f"sqlite:///{state}/controller.db"},
            "paths": {"state": state, "logs": logs, "worktrees": f"{state}/worktrees"},
            "network": {"admin_port": port},
            "deployment": {"health_probe_url": f"http://127.0.0.1:{port}/healthz"},
            "qualification": {
                "qualification_plane": plane,
                "epoch_id": epoch,
                "run_id": RUN_ID,
                "candidate_digest": CANDIDATE,
                "isolated_target_root": f"{state}/isolated-target",
                "existing_repository_url": repository,
            },
        }

    convergence = payload(
        "CONVERGENCE",
        "RE-" + "A" * 24,
        "/convergence",
        8990,
        "https://github.com/brullik/hermes-canary-convergence-run-a",
    )
    official = payload(
        "PRE_Q8",
        "RE-" + "B" * 24,
        "/official",
        8890,
        "https://github.com/brullik/hermes-canary-preq8-run-a",
    )
    assert qualification_config_semantic_digest(convergence) == (
        qualification_config_semantic_digest(official)
    )
    official["qualification"]["candidate_digest"] = "f" * 64  # type: ignore[index]
    assert qualification_config_semantic_digest(convergence) != (
        qualification_config_semantic_digest(official)
    )


def test_existing_repository_fixture_seed_is_content_addressed() -> None:
    first = fixture_manifest()
    second = fixture_manifest()
    assert first == second
    assert first["fixture_seed_digest"] == second["fixture_seed_digest"]
    assert tuple(fixture_files()) == tuple(item["path"] for item in first["files"])


def test_generated_convergence_and_official_configs_have_same_semantics(
    tmp_path: Path,
) -> None:
    namespace = runpy.run_path(str(ROOT / "scripts/bootstrap/build-canary-configs.py"))
    builder = cast(Callable[..., dict[str, Any]], namespace["build_configs"])
    base = yaml.safe_load(
        (ROOT / "config/factory-config.example.yaml").read_text(encoding="utf-8")
    )
    assert isinstance(base, dict)
    attestation = (tmp_path / "attestation.json").resolve()
    attestation.write_text("{}\n", encoding="utf-8")
    common = {
        "base": base,
        "catalog_path": (ROOT / "qualification/canaries/catalog.yaml").resolve(),
        "candidate_digest": CANDIDATE,
        "controller_release_digest": "b" * 64,
        "stable_release_digest": "c" * 64,
        "policy_digest": "d" * 64,
        "toolchain_digest": "e" * 64,
        "git_tree": "1" * 40,
        "requirements_lock_digest": "f" * 64,
        "systemd_bundle_digest": "0" * 64,
        "run_id": RUN_ID,
        "fixture_seed_digest": "2" * 64,
        "matrix_digest": "3" * 64,
        "capability_attestation_path": attestation,
        "capability_attestation_digest": hashlib.sha256(b"{}\n").hexdigest(),
        "schema_registry_root": (tmp_path / "schema-registry").resolve(),
    }
    convergence = builder(
        **common,
        output_root=(tmp_path / "convergence-config").resolve(),
        state_root=(tmp_path / "convergence-state").resolve(),
        log_root=(tmp_path / "convergence-log").resolve(),
        source_commit="4" * 40,
        epoch_id="RE-" + "A" * 24,
        qualification_plane="CONVERGENCE",
        existing_repository_url="https://github.com/brullik/convergence-fixture",
        first_port=8990,
    )
    official = builder(
        **common,
        output_root=(tmp_path / "official-config").resolve(),
        state_root=(tmp_path / "official-state").resolve(),
        log_root=(tmp_path / "official-log").resolve(),
        source_commit="5" * 40,
        epoch_id="RE-" + "B" * 24,
        qualification_plane="PRE_Q8",
        existing_repository_url="https://github.com/brullik/official-fixture",
        first_port=8890,
    )
    q8 = builder(
        **common,
        output_root=(tmp_path / "q8-config").resolve(),
        state_root=(tmp_path / "q8-state").resolve(),
        log_root=(tmp_path / "q8-log").resolve(),
        source_commit="5" * 40,
        epoch_id="RE-" + "B" * 24,
        qualification_plane="Q8",
        existing_repository_url="https://github.com/brullik/q8-fixture",
        first_port=8790,
    )

    assert convergence["schema_version"] == official["schema_version"] == "2.0"
    assert [entry["seal_config_digest"] for entry in convergence["scenarios"]] == [
        entry["seal_config_digest"] for entry in official["scenarios"]
    ]
    assert set(q8) == {
        "schema_version",
        "candidate_digest",
        "controller_release_digest",
        "catalog_digest",
        "scenarios",
        "index_digest",
    }
    assert q8["schema_version"] == "1.0"
    assert all("seal_config_digest" not in entry for entry in q8["scenarios"])
    convergence_config = yaml.safe_load(
        (tmp_path / "convergence-config" / "zero-dependency-cli.yaml").read_text(
            encoding="utf-8"
        )
    )
    official_config = yaml.safe_load(
        (tmp_path / "official-config" / "zero-dependency-cli.yaml").read_text(
            encoding="utf-8"
        )
    )
    assert convergence_config["paths"]["schemas"] == official_config["paths"]["schemas"]
    schema_root = Path(convergence_config["paths"]["schemas"])
    task_schema = json.loads(
        (schema_root / "task-contract-v2.schema.json").read_text(encoding="utf-8")
    )
    from factory.lifecycle import STAGES

    assert task_schema["properties"]["lifecycle_stage"]["enum"] == list(STAGES)
    registry_manifest = json.loads(
        (schema_root.parent / f"{schema_root.name}.manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert registry_manifest["registry_digest"] == schema_root.name
    assert all(
        "$schema" in json.loads(path.read_text(encoding="utf-8"))
        for path in schema_root.glob("*.json")
    )


def test_fixture_archive_is_verified_and_idempotent(tmp_path: Path) -> None:
    class FakeGitHubClient(GitHubClient):
        def __init__(self) -> None:
            self.archived = False
            self.patch_count = 0

        def request(
            self,
            method: str,
            path: str,
            payload: Mapping[str, Any] | None = None,
        ) -> dict[str, Any]:
            if method == "PATCH":
                assert payload == {"archived": True}
                self.patch_count += 1
                self.archived = True
            if path.endswith("/git/ref/heads/main"):
                return {"object": {"sha": "1" * 40}}
            if "/git/commits/" in path:
                return {
                    "sha": "1" * 40,
                    "message": (
                        "Hermes fixture "
                        + str(fixture_manifest()["fixture_seed_digest"])
                    ),
                    "tree": {"sha": "2" * 40},
                }
            if "/git/trees/" in path:
                return {
                    "tree": [
                        {
                            "path": relative,
                            "mode": "100644",
                            "type": "blob",
                            "sha": hashlib.sha1(
                                f"blob {len(content)}\0".encode("ascii") + content,
                                usedforsecurity=False,
                            ).hexdigest(),
                        }
                        for relative, content in fixture_files().items()
                    ]
                }
            return {
                "id": 42,
                "name": "hermes-canary-preq8-run-fixture",
                "private": True,
                "visibility": "private",
                "archived": self.archived,
                "default_branch": "main",
            }

    body = {
        "schema_version": "1.0",
        "receipt_type": "PREQ8_EXISTING_REPOSITORY_FIXTURE",
        "qualification_plane": "PRE_Q8",
        "run_id": RUN_ID,
        "candidate_digest": CANDIDATE,
        "scenario_id": "existing-repository-repair",
        "fixture_seed_digest": fixture_manifest()["fixture_seed_digest"],
        "repository_name": "hermes-canary-preq8-run-fixture",
        "repository_url": (
            "https://github.com/brullik/hermes-canary-preq8-run-fixture"
        ),
        "repository_id": 42,
        "visibility": "private",
        "default_branch": "main",
        "seed_commit": "1" * 40,
    }
    receipt = tmp_path / "fixture-provision.json"
    receipt.write_text(
        json.dumps(
            {
                **body,
                "receipt_digest": sha256_text(stable_json(body)),
                "observed_at": "2026-08-10T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "fixture-archive.json"
    client = FakeGitHubClient()

    first = archive(
        client=client,
        owner="brullik",
        receipt_path=receipt,
        output=output,
    )
    second = archive(
        client=client,
        owner="brullik",
        receipt_path=receipt,
        output=output,
    )

    assert first["receipt_digest"] == second["receipt_digest"]
    assert client.patch_count == 1


def test_fixture_provision_initializes_empty_repository_and_resumes(
    tmp_path: Path,
) -> None:
    class FakeGitHubClient(GitHubClient):
        def __init__(self) -> None:
            self.repository_created = False
            self.branch_commit = ""
            self.final_commit = ""
            self.tree_sha = "b" * 40
            self.blobs: dict[str, str] = {}
            self.repo_posts = 0
            self.bootstrap_puts = 0
            self.ref_patches = 0

        def request(
            self,
            method: str,
            path: str,
            payload: Mapping[str, Any] | None = None,
        ) -> dict[str, Any]:
            if method == "GET" and path == "/user":
                return {"login": "brullik"}
            if method == "POST" and path == "/user/repos":
                self.repo_posts += 1
                self.repository_created = True
                assert payload is not None
                return {
                    "id": 42,
                    "name": payload["name"],
                    "private": True,
                    "archived": False,
                }
            if path.startswith("/repos/brullik/") and path.count("/") == 3:
                if method == "GET":
                    if not self.repository_created:
                        raise GitHubAPIError(404)
                    return {
                        "id": 42,
                        "name": path.rsplit("/", 1)[1],
                        "private": True,
                        "visibility": "private",
                        "archived": False,
                        "default_branch": "main",
                    }
                if method == "PATCH":
                    return {"default_branch": "main"}
            if method == "GET" and path.endswith("/git/ref/heads/main"):
                if not self.branch_commit:
                    # GitHub uses 409 for a ref lookup in an empty repository.
                    raise GitHubAPIError(409)
                return {"object": {"sha": self.branch_commit}}
            if method == "PATCH" and path.endswith("/git/refs/heads/main"):
                assert payload is not None
                self.ref_patches += 1
                self.branch_commit = str(payload["sha"])
                return {"object": {"sha": self.branch_commit}}
            if method == "PUT" and "/contents/.hermes-bootstrap" in path:
                self.bootstrap_puts += 1
                self.branch_commit = "a" * 40
                return {"commit": {"sha": self.branch_commit}}
            if method == "POST" and path.endswith("/git/blobs"):
                assert payload is not None
                content = base64.b64decode(str(payload["content"]))
                digest = hashlib.sha1(
                    f"blob {len(content)}\0".encode("ascii") + content,
                    usedforsecurity=False,
                ).hexdigest()
                return {"sha": digest}
            if method == "POST" and path.endswith("/git/trees"):
                assert payload is not None
                self.blobs = {
                    str(item["path"]): str(item["sha"])
                    for item in payload["tree"]
                }
                return {"sha": self.tree_sha}
            if method == "POST" and path.endswith("/git/commits"):
                self.final_commit = "c" * 40
                return {"sha": self.final_commit}
            if method == "GET" and "/git/commits/" in path:
                return {
                    "sha": self.final_commit,
                    "message": (
                        "Hermes fixture "
                        + str(fixture_manifest()["fixture_seed_digest"])
                    ),
                    "tree": {"sha": self.tree_sha},
                }
            if method == "GET" and "/git/trees/" in path:
                return {
                    "tree": [
                        {
                            "path": name,
                            "mode": "100644",
                            "type": "blob",
                            "sha": digest,
                        }
                        for name, digest in self.blobs.items()
                    ]
                }
            raise AssertionError((method, path, payload))

    client = FakeGitHubClient()
    receipt = tmp_path / "fixture-provision.json"
    first = provision(
        client=client,
        owner="brullik",
        plane="convergence",
        run_id=RUN_ID,
        candidate_digest=CANDIDATE,
        receipt_path=receipt,
    )
    second = provision(
        client=client,
        owner="brullik",
        plane="convergence",
        run_id=RUN_ID,
        candidate_digest=CANDIDATE,
        receipt_path=receipt,
    )

    assert first["seed_commit"] == "c" * 40
    assert first["receipt_digest"] == second["receipt_digest"]
    assert (client.repo_posts, client.bootstrap_puts, client.ref_patches) == (1, 1, 1)
