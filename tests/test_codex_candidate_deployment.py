from __future__ import annotations

import fcntl
import json
import os
import socket
import subprocess
import threading
import tomllib
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from factory.codex_candidate_deployment import (
    CANONICAL_REPOSITORY,
    DEPLOY_OPERATION,
    PREPARE_SCRIPT,
    CandidateDeploymentBroker,
    CandidateDeploymentClient,
    CandidateDeploymentError,
    CandidateDeploymentRequest,
    peer_credentials,
    require_exact_peer,
)
from factory.common import sha256_text, stable_json

COMMIT = "a" * 40
TREE = "b" * 40
HEAD = "c" * 40
POLICY = "d" * 64
EVIDENCE = "e" * 64
MERGE_REQUEST_ID = "CODEX-DEPLOYMENT-MERGE-RECEIPT-0001"
ROOT = Path(__file__).resolve().parents[1]


class StrictGitRunner:
    def __init__(self, source: Path, remote: str) -> None:
        self.source = source
        self.remote = remote
        self.remote_commit = COMMIT
        self.remote_tree = TREE
        self.head = COMMIT
        self.dirty = False
        self.calls: list[list[str]] = []

    def __call__(
        self, argv: list[str], environment: dict[str, str], cwd: Path
    ) -> subprocess.CompletedProcess[str]:
        assert cwd == self.source
        assert environment["GIT_TERMINAL_PROMPT"] == "0"
        assert environment["GIT_ASKPASS"] == "/bin/false"
        self.calls.append(argv)
        arguments = argv[argv.index(str(self.source)) + 1 :]
        returncode = 0
        if arguments == ["rev-parse", "--is-inside-work-tree"]:
            output = "true\n"
        elif arguments == ["rev-parse", "--show-toplevel"]:
            output = f"{self.source}\n"
        elif arguments == ["remote"]:
            output = "origin\n"
        elif arguments == ["remote", "get-url", "origin"]:
            output = f"{self.remote}\n"
        elif arguments in (
            ["config", "--local", "--get-all", "remote.origin.pushurl"],
            [
                "config",
                "--local",
                "--name-only",
                "--get-regexp",
                r"^(credential|http|url|include|includeIf)\.",
            ],
        ):
            returncode, output = 1, ""
        elif arguments == ["status", "--porcelain=v1", "--untracked-files=all"]:
            output = " M tracked\n" if self.dirty else ""
        elif arguments == [
            "fetch",
            "--no-tags",
            "origin",
            "+refs/heads/main:refs/remotes/origin/main",
        ]:
            output = ""
        elif arguments == ["rev-parse", "refs/remotes/origin/main^{commit}"]:
            output = f"{self.remote_commit}\n"
        elif arguments == ["rev-parse", f"{self.remote_commit}^{{tree}}"]:
            output = f"{self.remote_tree}\n"
        elif arguments == ["rev-list", "--parents", "-n", "1", self.remote_commit]:
            output = f"{self.remote_commit} {'f' * 40}\n"
        elif arguments == ["rev-parse", "HEAD^{commit}"]:
            output = f"{self.head}\n"
        elif arguments == ["switch", "--detach", self.remote_commit]:
            self.head = self.remote_commit
            output = ""
        elif arguments == ["ls-remote", "--heads", "origin", "refs/heads/main"]:
            output = f"{self.remote_commit}\trefs/heads/main\n"
        elif arguments == ["rev-parse", "HEAD^{tree}"]:
            output = f"{self.remote_tree}\n"
        elif arguments == ["ls-files", "--error-unmatch", PREPARE_SCRIPT]:
            output = f"{PREPARE_SCRIPT}\n"
        elif arguments in (
            ["rev-parse", f"{self.remote_commit}:{PREPARE_SCRIPT}"],
            ["hash-object", PREPARE_SCRIPT],
        ):
            output = f"{'1' * 40}\n"
        else:  # pragma: no cover - every new command expands authority
            raise AssertionError(arguments)
        return subprocess.CompletedProcess(argv, returncode, output, "")


class StrictPrepareRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict[str, str], Path, float]] = []
        self.returncode = 0
        self.stdout = "Candidate prepared\n"
        self.stderr = ""

    def __call__(
        self,
        argv: list[str],
        environment: dict[str, str],
        cwd: Path,
        timeout_seconds: float,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((argv, environment, cwd, timeout_seconds))
        return subprocess.CompletedProcess(
            argv, self.returncode, self.stdout, self.stderr
        )


class StrictFailureProbeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict[str, str], Path, float]] = []
        self.responses: dict[str, subprocess.CompletedProcess[str]] = {}

    def __call__(
        self,
        argv: list[str],
        environment: dict[str, str],
        cwd: Path,
        timeout_seconds: float,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((argv, environment, cwd, timeout_seconds))
        scenario_id = Path(argv[-2]).parent.name
        return self.responses.get(
            scenario_id,
            subprocess.CompletedProcess(argv, 1, "", "sanitizer unavailable"),
        )


def _merge_receipt(receipt_root: Path) -> str:
    core: dict[str, Any] = {
        "credential_epoch_id": "CE-CODEX-TEST-1",
        "object_ids": [
            "number:42",
            "state:squash_merge_verified",
            f"head_sha:{HEAD}",
            f"merge_sha:{COMMIT}",
            "merged:True",
            "branch:codex/candidate-deployment-boundary",
            "branch_cleanup:deleted",
            f"policy_digest:{POLICY}",
            f"evidence_manifest_digest:{EVIDENCE}",
            "merge_method:squash",
            "parents:1",
            "unresolved_threads:0",
        ],
        "operation": "pull_request.merge_or_close",
        "request_digest": "2" * 64,
        "request_id": MERGE_REQUEST_ID,
        "result": "PASS",
        "subject_identity": "brullik",
        "target_slug": CANONICAL_REPOSITORY,
        "timestamp": "2026-08-09T00:00:00Z",
    }
    digest = sha256_text(stable_json(core))
    path = receipt_root / f"{MERGE_REQUEST_ID}.json"
    path.write_text(stable_json({**core, "receipt_digest": digest}) + "\n", encoding="utf-8")
    path.chmod(0o440)
    return digest


def _request(digest: str) -> CandidateDeploymentRequest:
    return CandidateDeploymentRequest.from_mapping(
        {
            "schema_version": "1.0",
            "request_id": "CANDIDATE-DEPLOYMENT-REQUEST-0001",
            "operation": DEPLOY_OPERATION,
            "repository": CANONICAL_REPOSITORY,
            "commit_sha": COMMIT,
            "tree_sha": TREE,
            "merge_receipt_id": MERGE_REQUEST_ID,
            "merge_receipt_digest": digest,
        }
    )


def _fixture(
    tmp_path: Path,
) -> tuple[
    CandidateDeploymentBroker,
    CandidateDeploymentRequest,
    StrictGitRunner,
    StrictPrepareRunner,
    StrictFailureProbeRunner,
]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    source = state / "source"
    source.mkdir(mode=0o755)
    (source / ".git").mkdir(mode=0o755)
    script = source / PREPARE_SCRIPT
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o755)
    receipt_root = tmp_path / "github-receipts"
    receipt_root.mkdir(mode=0o750)
    digest = _merge_receipt(receipt_root)
    remote = "https://example.invalid/canonical.git"
    git_runner = StrictGitRunner(source, remote)
    prepare_runner = StrictPrepareRunner()
    failure_probe_runner = StrictFailureProbeRunner()
    pre_q8_state_root = tmp_path / "pre-q8"
    broker = CandidateDeploymentBroker(
        source_root=source,
        state_root=state,
        merge_receipt_root=receipt_root,
        expected_source_uid=os.getuid(),
        expected_merge_receipt_uid=os.getuid(),
        expected_remote_url=remote,
        git_runner=git_runner,
        prepare_runner=prepare_runner,
        failure_probe_runner=failure_probe_runner,
        pre_q8_state_root=pre_q8_state_root,
        verifier_python=tmp_path / "verifier-python",
    )
    return broker, _request(digest), git_runner, prepare_runner, failure_probe_runner


def _replace_with_legacy_receipt(
    broker: CandidateDeploymentBroker,
    request: CandidateDeploymentRequest,
    receipt: dict[str, Any],
) -> tuple[Path, dict[str, Any]]:
    unsigned = dict(receipt)
    unsigned.pop("receipt_digest")
    unsigned.pop("failure_classification")
    unsigned.pop("failure_evidence_ref")
    legacy = {
        **unsigned,
        "receipt_digest": sha256_text(stable_json(unsigned)),
    }
    path = broker.result_root / f"{request.request_id}.json"
    path.unlink()
    broker._write_immutable(path, legacy)
    return path, legacy


def test_exact_main_merge_invokes_only_prepare_and_replays_receipt(tmp_path: Path) -> None:
    broker, request, _git, prepare, failure_probe = _fixture(tmp_path)

    first = broker.execute(request.__dict__)
    second = broker.execute(request.__dict__)

    assert first == second
    assert first["result"] == "PASS"
    assert first["failure_classification"] == ""
    assert first["failure_evidence_ref"] == ""
    assert len(prepare.calls) == 1
    assert failure_probe.calls == []
    argv, environment, cwd, timeout = prepare.calls[0]
    assert argv == [str(broker.source_root / PREPARE_SCRIPT)]
    assert cwd == broker.source_root
    assert timeout == 21_600.0
    assert set(environment) == {
        "GIT_ASKPASS",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_TERMINAL_PROMPT",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
    }
    receipt = broker.result_root / f"{request.request_id}.json"
    assert receipt.stat().st_mode & 0o777 == 0o400
    assert not receipt.stat().st_mode & 0o222


@pytest.mark.parametrize(
    ("returncode", "expected_classification"),
    [(0, ""), (1, "sanitized_failure_evidence_unavailable")],
)
def test_exact_legacy_receipt_replays_as_current_schema_without_side_effects(
    tmp_path: Path,
    returncode: int,
    expected_classification: str,
) -> None:
    broker, request, _git, prepare, failure_probe = _fixture(tmp_path)
    raw_marker = "ghp_" + "R" * 24
    prepare.returncode = returncode
    prepare.stderr = raw_marker
    first = broker.execute(request.__dict__)
    path, legacy = _replace_with_legacy_receipt(broker, request, first)

    replayed = broker.execute(request.__dict__)
    repeated = broker.execute(request.__dict__)

    assert replayed == repeated
    assert replayed["result"] == ("PASS" if returncode == 0 else "FAILED")
    assert replayed["failure_classification"] == expected_classification
    expected_ref = (
        ""
        if not expected_classification
        else broker._failure_reference(request, expected_classification)
    )
    assert replayed["failure_evidence_ref"] == expected_ref
    replayed_unsigned = dict(replayed)
    replayed_digest = replayed_unsigned.pop("receipt_digest")
    assert replayed_digest == sha256_text(stable_json(replayed_unsigned))
    assert json.loads(path.read_text(encoding="utf-8")) == legacy
    assert raw_marker not in stable_json(replayed)
    assert len(prepare.calls) == 1
    assert failure_probe.calls == []
    assert not path.stat().st_mode & 0o222


def test_unknown_legacy_receipt_shape_still_fails_closed(tmp_path: Path) -> None:
    broker, request, _git, _prepare, _failure_probe = _fixture(tmp_path)
    first = broker.execute(request.__dict__)
    path, legacy = _replace_with_legacy_receipt(broker, request, first)
    unsigned = dict(legacy)
    unsigned.pop("receipt_digest")
    unsigned.pop("stderr_digest")
    malformed = {**unsigned, "receipt_digest": sha256_text(stable_json(unsigned))}
    path.unlink()
    broker._write_immutable(path, malformed)

    with pytest.raises(
        CandidateDeploymentError, match="deployment_result_fields_differ"
    ):
        broker.execute(request.__dict__)


def test_secret_free_client_sends_only_the_typed_request(tmp_path: Path) -> None:
    broker, request, _git, _prepare, _failure_probe = _fixture(tmp_path)
    receipt = broker.execute(request.__dict__)
    socket_path = tmp_path / "client.sock"
    observed: list[dict[str, str]] = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        listener.listen(1)

        def respond() -> None:
            connection, _address = listener.accept()
            with connection:
                encoded = bytearray()
                while b"\n" not in encoded:
                    encoded.extend(connection.recv(4096))
                observed.append(json.loads(bytes(encoded).decode("utf-8")))
                response = {"status": "PASS", "receipt": receipt}
                connection.sendall((stable_json(response) + "\n").encode("utf-8"))

        worker = threading.Thread(target=respond)
        worker.start()
        response = CandidateDeploymentClient(socket_path, timeout_seconds=5).execute(request)
        worker.join(timeout=5)
    assert response["status"] == "PASS"
    assert observed == [request.__dict__]


@pytest.mark.parametrize(
    "extra_field",
    ["argv", "source_path", "ref", "stable_path", "credential_path"],
)
def test_request_rejects_every_generic_authority_field(extra_field: str) -> None:
    value = _request("3" * 64).__dict__.copy()
    value[extra_field] = "/opt/hermes-factory/current"
    with pytest.raises(
        CandidateDeploymentError, match="deployment_request_fields_differ"
    ):
        CandidateDeploymentRequest.from_mapping(value)


def test_stale_non_main_commit_is_rejected_before_prepare(tmp_path: Path) -> None:
    broker, request, git_runner, prepare, _failure_probe = _fixture(tmp_path)
    git_runner.remote_commit = "9" * 40
    with pytest.raises(CandidateDeploymentError, match="origin_main_commit_differs"):
        broker.execute(request.__dict__)
    assert prepare.calls == []


def test_dirty_or_writable_source_checkout_is_rejected(tmp_path: Path) -> None:
    broker, request, git_runner, prepare, _failure_probe = _fixture(tmp_path)
    git_runner.dirty = True
    with pytest.raises(CandidateDeploymentError, match="source_checkout_not_clean"):
        broker.execute(request.__dict__)
    assert prepare.calls == []

    git_runner.dirty = False
    broker.source_root.chmod(0o775)
    with pytest.raises(
        CandidateDeploymentError, match="source_checkout_ownership_invalid"
    ):
        broker.execute(request.__dict__)


def test_forged_merge_receipt_and_tree_are_rejected(tmp_path: Path) -> None:
    broker, request, _git, prepare, _failure_probe = _fixture(tmp_path)
    forged = replace(request, merge_receipt_digest="8" * 64)
    with pytest.raises(CandidateDeploymentError, match="merge_receipt_digest_differs"):
        broker.execute(forged.__dict__)
    assert prepare.calls == []

    wrong_tree = replace(request, tree_sha="7" * 40)
    with pytest.raises(CandidateDeploymentError, match="origin_main_tree_differs"):
        broker.execute(wrong_tree.__dict__)


def test_replay_conflict_and_new_request_cannot_repeat_commit(tmp_path: Path) -> None:
    broker, request, _git, prepare, _failure_probe = _fixture(tmp_path)
    broker.execute(request.__dict__)
    conflict = replace(request, tree_sha="6" * 40)
    with pytest.raises(CandidateDeploymentError, match="deployment_replay_conflict"):
        broker.execute(conflict.__dict__)
    new_id = replace(request, request_id="CANDIDATE-DEPLOYMENT-REQUEST-0002")
    with pytest.raises(
        CandidateDeploymentError, match="deployment_commit_already_attempted"
    ):
        broker.execute(new_id.__dict__)
    assert len(prepare.calls) == 1


def test_exclusive_lock_rejects_concurrent_deployment(tmp_path: Path) -> None:
    broker, request, _git, _prepare, _failure_probe = _fixture(tmp_path)
    broker._prepare_state()
    descriptor = os.open(broker.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(CandidateDeploymentError, match="deployment_in_progress"):
            broker.execute(request.__dict__)
    finally:
        os.close(descriptor)


def test_result_receipt_redacts_output_and_failure_is_immutable(tmp_path: Path) -> None:
    broker, request, _git, prepare, failure_probe = _fixture(tmp_path)
    marker = "ghp_" + "A" * 24
    prepare.returncode = 1
    prepare.stderr = f"bootstrap failed near {marker}"
    receipt = broker.execute(request.__dict__)
    encoded = stable_json(receipt)
    assert receipt["result"] == "FAILED"
    assert marker not in encoded
    assert receipt["stdout_tail"] == ""
    assert receipt["stderr_tail"] == ""
    assert receipt["failure_classification"] == "sanitized_failure_evidence_unavailable"
    expected_evidence = {
        "schema_version": "1.0",
        "commit_sha": request.commit_sha,
        "tree_sha": request.tree_sha,
        "classification": "sanitized_failure_evidence_unavailable",
    }
    assert receipt["failure_evidence_ref"] == (
        "artifact://candidate-deployment-failure/"
        + sha256_text(stable_json(expected_evidence))
    )
    assert receipt["redactions"] == [{"type": "github_token", "count": 1}]
    assert failure_probe.calls == []
    assert not (broker.result_root / f"{request.request_id}.json").stat().st_mode & 0o222


def test_failed_receipt_uses_only_allowlisted_sanitized_cause_and_replays(
    tmp_path: Path,
) -> None:
    broker, request, _git, prepare, failure_probe = _fixture(tmp_path)
    database = (
        broker.pre_q8_state_root / request.commit_sha / "deploy-rollback" / "controller.db"
    )
    database.parent.mkdir(parents=True)
    database.write_bytes(b"synthetic fixture")
    raw_marker = "raw-provider-payload-must-not-cross-boundary"
    truth = {
        "product_status": "FAILED_SAFE",
        "scenario_status": "TERMINAL_FAILURE",
        "task_statuses": ["DONE", "FAILED_SAFE"],
        "failure_reasons": [raw_marker, "model_requested_repair"],
        "open_incidents": ["path_governor_problem_budget_exhausted"],
        "completion_manifest_count": 0,
        "liveness_finding": False,
    }
    command = ["candidate-truth"]
    failure_probe.responses["deploy-rollback"] = subprocess.CompletedProcess(
        command, 0, stable_json(truth), ""
    )
    prepare.returncode = 1
    prepare.stdout = ""
    prepare.stderr = ""

    first = broker.execute(request.__dict__)
    second = broker.execute(request.__dict__)

    assert first == second
    assert first["result"] == "FAILED"
    assert first["stdout_tail"] == first["stderr_tail"] == ""
    assert first["failure_classification"] == "path_governor_problem_budget_exhausted"
    safe_evidence = {
        "schema_version": "1.0",
        "commit_sha": request.commit_sha,
        "tree_sha": request.tree_sha,
        "classification": "path_governor_problem_budget_exhausted",
    }
    assert first["failure_evidence_ref"] == (
        "artifact://candidate-deployment-failure/"
        + sha256_text(stable_json(safe_evidence))
    )
    assert raw_marker not in stable_json(first)
    assert len(prepare.calls) == 1
    assert len(failure_probe.calls) == 1
    argv, environment, cwd, timeout = failure_probe.calls[0]
    assert argv[:5] == [
        "/usr/sbin/runuser",
        "-u",
        "hermesverifier",
        "--",
        str(broker.verifier_python),
    ]
    assert argv[5:7] == ["-m", "scripts.candidate_truth"]
    assert argv[-2:] == [str(database), "--worker-idle"]
    assert cwd == broker.source_root
    assert timeout == 30.0
    assert not any("telegram" in item or "notif" in item for item in argv)
    assert not any("telegram" in key.lower() or "notif" in key.lower() for key in environment)


def test_linux_peer_credentials_are_exact() -> None:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        pid, uid, gid = peer_credentials(left)
    finally:
        left.close()
        right.close()
    assert pid == os.getpid()
    assert uid == os.getuid()
    assert gid == os.getgid()

    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(CandidateDeploymentError, match="deployment_peer_not_allowed"):
            require_exact_peer(
                left, allowed_uid=os.getuid() + 1, allowed_gid=os.getgid()
            )
    finally:
        left.close()
        right.close()


def test_systemd_and_codex_permissions_expose_only_typed_socket() -> None:
    unit = (
        ROOT / "config/systemd/hermes-codex-candidate-deployment-broker.service"
    ).read_text(encoding="utf-8")
    assert "User=root" in unit
    assert "ProtectSystem=strict" in unit
    assert "RestrictSUIDSGID=false" in unit
    assert "RestrictSUIDSGID=true" not in unit
    assert "LoadCredential=" not in unit
    assert "sudo" not in unit
    assert "bash -c" not in unit
    assert "scripts.codex_candidate_deployment_broker" in unit
    assert "ReadOnlyPaths=/opt/hermes-factory" in unit
    assert "ReadOnlyPaths=/var/lib/hermes-factory" in unit
    assert "InaccessiblePaths=/etc/hermes-factory/credentials.d" in unit
    writable = {
        line.removeprefix("ReadWritePaths=")
        for line in unit.splitlines()
        if line.startswith("ReadWritePaths=")
    }
    assert "/etc/.pwd.lock" in writable
    assert "/etc" not in writable
    assert "/opt/hermes-factory" not in writable
    assert "/var/lib/hermes-factory" not in writable

    config = tomllib.loads(
        (ROOT / "config/codex-vps/config.toml").read_text(encoding="utf-8")
    )
    sockets = config["permissions"]["codex-vps-workspace"]["network"]["unix_sockets"]
    assert set(sockets) == {
        "/run/hermes-codex-candidate-deployment-broker/broker.sock",
        "/run/hermes-codex-github-broker/broker.sock",
    }
    supervisor = (ROOT / "config/systemd/hermes-codex-vps@.service").read_text(
        encoding="utf-8"
    )
    assert "Requires=hermes-codex-candidate-deployment-broker.service" in supervisor
    gateway = (ROOT / "config/systemd/hermes-factory-gateway.service").read_text(
        encoding="utf-8"
    )
    gateway_dependencies = [
        line
        for line in gateway.splitlines()
        if line.startswith(("After=", "Before=", "BindsTo=", "PartOf=", "Requires=", "Wants="))
    ]
    assert not any("hermes-codex" in line for line in gateway_dependencies)


def test_candidate_account_group_reconciliation_is_idempotent() -> None:
    bootstrap = (
        ROOT / "scripts/bootstrap/prepare-candidate-plane.sh"
    ).read_text(encoding="utf-8")
    assert "group_member()" in bootstrap
    assert "id -nG \"${member}\"" in bootstrap
    assert bootstrap.count("usermod --append --groups") == 2
    assert 'if ! group_member "${shadow_member}" hermesshadow; then' in bootstrap
    assert 'usermod --append --groups hermesshadow "${shadow_member}"' in bootstrap
    assert (
        'if ! group_member "${functional_member}" "${FUNCTIONAL_GROUP}"; then'
        in bootstrap
    )


def test_candidate_local_package_install_disables_pip_cache() -> None:
    bootstrap = (
        ROOT / "scripts/bootstrap/prepare-candidate-plane.sh"
    ).read_text(encoding="utf-8")
    assert (
        '--no-cache-dir --no-deps "git+file://${release_root}@${SOURCE_COMMIT}"'
        in bootstrap
    )
    assert "PIP_CACHE_DIR=" not in bootstrap
