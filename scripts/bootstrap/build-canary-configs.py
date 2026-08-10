#!/usr/bin/env python3
"""Build immutable root-owned configs for the exact ten clean canaries."""

from __future__ import annotations

import argparse
import copy
import json
import re
import stat
from pathlib import Path
from typing import Any

import yaml

from factory.canary_qualification import load_canary_catalog
from factory.common import sha256_text, stable_json
from factory.config import FactoryConfig, validate_config
from factory.functional_readiness import PRE_Q8_SCENARIOS as CANONICAL_CANARY_SCENARIOS
from factory.lifecycle import LIFECYCLE_VERSION, STAGES
from factory.pre_q8_seal import qualification_config_semantic_digest

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SHA40 = re.compile(r"^[a-f0-9]{40}$")
_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9-]{7,63}$")
_PLANES = frozenset({"CONVERGENCE", "PRE_Q8", "Q8"})


def _write_immutable(path: Path, content: str) -> None:
    if path.is_symlink():
        raise ValueError(f"clean canary artifact path is unsafe: {path.name}")
    if path.exists():
        if not path.is_file() or path.read_text(encoding="utf-8") != content:
            raise ValueError(f"clean canary config conflicts: {path.name}")
        return
    path.write_text(content, encoding="utf-8", newline="\n")


def _build_schema_registry(root: Path) -> Path:
    """Materialize an immutable PRE-Q8 registry from the exact Candidate tree."""

    source_root = Path(__file__).resolve().parents[2] / "schemas"
    if not root.is_absolute() or not source_root.is_dir() or source_root.is_symlink():
        raise ValueError("PRE-Q8 schema registry roots are invalid")
    sources = sorted(source_root.glob("*.json"), key=lambda path: path.name)
    if not sources or any(not path.is_file() or path.is_symlink() for path in sources):
        raise ValueError("Candidate schema registry is incomplete")
    rendered: dict[str, str] = {}
    for source in sources:
        content = source.read_text(encoding="utf-8")
        if source.name == "task-contract-v2.schema.json":
            schema = json.loads(content)
            try:
                lifecycle = schema["properties"]["lifecycle_stage"]
            except (KeyError, TypeError) as error:
                raise ValueError("Candidate task lifecycle schema is invalid") from error
            if not isinstance(lifecycle, dict) or not isinstance(lifecycle.get("enum"), list):
                raise ValueError("Candidate task lifecycle enum is invalid")
            lifecycle["enum"] = list(STAGES)
            content = json.dumps(
                schema,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ) + "\n"
        rendered[source.name] = content
    registry_digest = sha256_text(
        stable_json(
            [
                [name, sha256_text(content)]
                for name, content in rendered.items()
            ]
        )
    )
    if root.exists() and (not root.is_dir() or root.is_symlink()):
        raise ValueError("PRE-Q8 schema registry root is unsafe")
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(
        stat.S_IRUSR
        | stat.S_IWUSR
        | stat.S_IXUSR
        | stat.S_IRGRP
        | stat.S_IXGRP
        | stat.S_IROTH
        | stat.S_IXOTH
    )
    destination = root / registry_digest
    if destination.exists() and (
        not destination.is_dir() or destination.is_symlink()
    ):
        raise ValueError("PRE-Q8 schema registry destination is unsafe")
    destination.mkdir(parents=True, exist_ok=True)
    destination.chmod(
        stat.S_IRUSR
        | stat.S_IWUSR
        | stat.S_IXUSR
        | stat.S_IRGRP
        | stat.S_IXGRP
        | stat.S_IROTH
        | stat.S_IXOTH
    )
    for name, content in rendered.items():
        path = destination / name
        _write_immutable(path, content)
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    manifest = {
        "schema_version": "1.0",
        "registry_digest": registry_digest,
        "lifecycle_version": LIFECYCLE_VERSION,
        "lifecycle_stages": list(STAGES),
        "files": [
            {"name": name, "digest": sha256_text(content)}
            for name, content in rendered.items()
        ],
    }
    manifest["manifest_digest"] = sha256_text(stable_json(manifest))
    manifest_path = root / f"{registry_digest}.manifest.json"
    _write_immutable(
        manifest_path,
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    manifest_path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    return destination


def build_configs(
    base: dict[str, Any],
    *,
    catalog_path: Path,
    output_root: Path,
    state_root: Path,
    log_root: Path,
    candidate_digest: str,
    controller_release_digest: str,
    source_commit: str,
    stable_release_digest: str,
    policy_digest: str,
    toolchain_digest: str,
    git_tree: str,
    requirements_lock_digest: str,
    systemd_bundle_digest: str,
    qualification_plane: str,
    run_id: str,
    epoch_id: str,
    fixture_seed_digest: str,
    matrix_digest: str,
    capability_attestation_path: Path,
    capability_attestation_digest: str,
    schema_registry_root: Path,
    existing_repository_url: str,
    first_port: int,
) -> dict[str, Any]:
    catalog = load_canary_catalog(catalog_path)
    if tuple(catalog) != CANONICAL_CANARY_SCENARIOS:
        raise ValueError("clean canary catalog order differs from canonical order")
    if not all(
        _SHA256.fullmatch(value)
        for value in (
            candidate_digest,
            controller_release_digest,
            stable_release_digest,
            policy_digest,
            toolchain_digest,
            requirements_lock_digest,
            systemd_bundle_digest,
            fixture_seed_digest,
            matrix_digest,
            capability_attestation_digest,
        )
    ):
        raise ValueError("clean canary digest argument is invalid")
    if (
        _SHA40.fullmatch(source_commit) is None
        or _SHA40.fullmatch(git_tree) is None
        or qualification_plane not in _PLANES
        or _RUN_ID.fullmatch(run_id) is None
        or re.fullmatch(r"RE-[A-F0-9]{24}", epoch_id) is None
    ):
        raise ValueError("clean canary release namespace is invalid")
    if not all(
        path.is_absolute()
        for path in (
            catalog_path,
            output_root,
            state_root,
            log_root,
            capability_attestation_path,
            schema_registry_root,
        )
    ):
        raise ValueError("clean canary paths must be absolute")
    if first_port < 1024 or first_port + len(catalog) - 1 > 65535:
        raise ValueError("clean canary port range is invalid")
    base_config_digest = sha256_text(stable_json(base))
    catalog_digest = sha256_text(
        stable_json(
            [
                [scenario_id, catalog[scenario_id].scenario_digest]
                for scenario_id in CANONICAL_CANARY_SCENARIOS
            ]
        )
    )
    schema_registry = _build_schema_registry(schema_registry_root)
    output_root.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    for index, scenario_id in enumerate(CANONICAL_CANARY_SCENARIOS):
        scenario = catalog[scenario_id]
        scenario_state = state_root / epoch_id / run_id / scenario_id
        scenario_logs = log_root / epoch_id / run_id / scenario_id
        payload = copy.deepcopy(base)
        payload["controller"].update(
            {
                "database_url": f"sqlite:///{(scenario_state / 'controller.db').as_posix()}",
                "max_active_products": 1,
                "max_active_workers": 1,
                "observation_seconds": 60,
            }
        )
        payload["paths"].update(
            {
                "schemas": str(schema_registry),
                "state": str(scenario_state),
                "worktrees": str(scenario_state / "worktrees"),
                "logs": str(scenario_logs),
                "canary_catalog": str(catalog_path),
            }
        )
        payload["network"].update(
            {"admin_bind": "127.0.0.1", "admin_port": first_port + index}
        )
        payload["telegram"]["allowed_user_ids"] = []
        payload["deployment"].update(
            {
                "current_vps_high_risk_production": False,
                "staging_root": str(scenario_state / "staging"),
                "production_helper": "",
                "rollback_helper": "",
                "qualification_manifest_root": "",
                "verifier_public_key_digest": "",
                "health_probe_url": f"http://127.0.0.1:{first_port + index}/healthz",
                "production_target": {
                    "mode": "isolated_candidate",
                    "host": "clean-canary.invalid",
                    "install_root": str(scenario_state / "isolated-target"),
                    "entrypoint": "disabled",
                },
            }
        )
        payload["backup"].update(
            {
                "offsite_configured": False,
                "proof_path": str(scenario_state / "qualification" / "backup-proof.json"),
            }
        )
        payload["qualification"] = {
            "plane": "CLEAN_CANARY",
            "qualification_plane": qualification_plane,
            "run_id": run_id,
            "epoch_id": epoch_id,
            "fixture_seed_digest": fixture_seed_digest,
            "release_adapter": "IsolatedCanaryReleaseExecutor",
            "capability_attestation_path": str(capability_attestation_path),
            "capability_attestation_digest": capability_attestation_digest,
            "scenario_id": scenario.scenario_id,
            "scenario_digest": scenario.scenario_digest,
            "controller_release_digest": controller_release_digest,
            "candidate_digest": candidate_digest,
            "faults": list(scenario.injected_faults),
            "fault_receipt_root": str(scenario_state / "fault-receipts"),
            "isolated_target_root": str(scenario_state / "isolated-target"),
            "existing_repository_url": (
                existing_repository_url
                if scenario.delivery_mode == "existing_repository"
                else ""
            ),
        }
        destination = output_root / f"{scenario_id}.yaml"
        errors = validate_config(FactoryConfig(payload, destination))
        if errors:
            raise ValueError(f"{scenario_id}: {errors[0]}")
        encoded = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
        _write_immutable(destination, encoded)
        config_digest = sha256_text(stable_json(payload))
        seal_config_digest = qualification_config_semantic_digest(payload)
        entry = {
            "scenario_id": scenario_id,
            "scenario_digest": scenario.scenario_digest,
            "config_path": str(destination),
            "config_digest": config_digest,
            "database_path": str(scenario_state / "controller.db"),
            "fault_receipt_root": str(scenario_state / "fault-receipts"),
            "port": first_port + index,
        }
        if qualification_plane != "Q8":
            entry["seal_config_digest"] = seal_config_digest
        entries.append(entry)
    extended_index = {
        "schema_version": "2.0",
        "qualification_plane": qualification_plane,
        "run_id": run_id,
        "epoch_id": epoch_id,
        "source_commit": source_commit,
        "candidate_digest": candidate_digest,
        "controller_release_digest": controller_release_digest,
        "git_tree": git_tree,
        "release_tree_digest": candidate_digest,
        "requirements_lock_digest": requirements_lock_digest,
        "toolchain_digest": toolchain_digest,
        "systemd_bundle_digest": systemd_bundle_digest,
        "catalog_digest": catalog_digest,
        "base_config_digest": base_config_digest,
        "capability_attestation_digest": capability_attestation_digest,
        "fixture_seed_digest": fixture_seed_digest,
        "matrix_digest": matrix_digest,
        "scenarios": entries,
    }
    legacy_q8_index = {
        "schema_version": "1.0",
        "candidate_digest": candidate_digest,
        "controller_release_digest": controller_release_digest,
        "catalog_digest": sha256_text(
            stable_json(
                {
                    key: value.scenario_digest
                    for key, value in sorted(catalog.items())
                }
            )
        ),
        "scenarios": entries,
    }
    index_payload = legacy_q8_index if qualification_plane == "Q8" else extended_index
    index_payload["index_digest"] = sha256_text(stable_json(index_payload))
    _write_immutable(
        output_root / "index.json",
        json.dumps(index_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    return index_payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-config", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--log-root", type=Path, required=True)
    parser.add_argument("--candidate-digest", required=True)
    parser.add_argument("--controller-release-digest", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--stable-release-digest", required=True)
    parser.add_argument("--policy-digest", required=True)
    parser.add_argument("--toolchain-digest", required=True)
    parser.add_argument("--git-tree", required=True)
    parser.add_argument("--requirements-lock-digest", required=True)
    parser.add_argument("--systemd-bundle-digest", required=True)
    parser.add_argument("--qualification-plane", choices=sorted(_PLANES), required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--epoch-id", required=True)
    parser.add_argument("--fixture-seed-digest", required=True)
    parser.add_argument("--matrix-digest", required=True)
    parser.add_argument("--capability-attestation-path", type=Path, required=True)
    parser.add_argument("--capability-attestation-digest", required=True)
    parser.add_argument("--schema-registry-root", type=Path, required=True)
    parser.add_argument("--existing-repository-url", default="")
    parser.add_argument("--first-port", type=int, default=8800)
    args = parser.parse_args()
    raw = yaml.safe_load(args.base_config.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError("base Candidate B config must be an object")
    result = build_configs(
        raw,
        catalog_path=args.catalog,
        output_root=args.output_root,
        state_root=args.state_root,
        log_root=args.log_root,
        candidate_digest=args.candidate_digest,
        controller_release_digest=args.controller_release_digest,
        source_commit=args.source_commit,
        stable_release_digest=args.stable_release_digest,
        policy_digest=args.policy_digest,
        toolchain_digest=args.toolchain_digest,
        git_tree=args.git_tree,
        requirements_lock_digest=args.requirements_lock_digest,
        systemd_bundle_digest=args.systemd_bundle_digest,
        qualification_plane=args.qualification_plane,
        run_id=args.run_id,
        epoch_id=args.epoch_id,
        fixture_seed_digest=args.fixture_seed_digest,
        matrix_digest=args.matrix_digest,
        capability_attestation_path=args.capability_attestation_path,
        capability_attestation_digest=args.capability_attestation_digest,
        schema_registry_root=args.schema_registry_root,
        existing_repository_url=args.existing_repository_url,
        first_port=args.first_port,
    )
    print(stable_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
