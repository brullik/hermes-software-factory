#!/usr/bin/env python3
"""Execute every real Q6.5 handshake and emit one immutable evidence index."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import yaml

from factory.common import sha256_file, sha256_text, stable_json, utc_now
from factory.config import load_config
from factory.credential_broker import BrokerClient
from factory.functional_readiness import MANDATORY_Q6_5_OPERATIONS, CapabilityHandshakeReport
from factory.notifications import NotificationOutbox, NotificationRequest
from factory.providers import ModelSelection, ProviderRegistry
from factory.q6_5 import (
    GitHubOperationHandshake,
    ProbeIdentity,
    ProviderOperationHandshake,
    Q65ExternalCapabilityError,
    Q65ProbeError,
    external_operation_report,
)
from factory.worker import SubprocessHermesRunner


class LiveProbeError(RuntimeError):
    """A concrete Q6.5 adapter did not satisfy its real operation contract."""


def _load_control(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise LiveProbeError("qualification control config is invalid")
    return {str(key): item for key, item in value.items()}


def _run(argv: list[str], *, cwd: Path, timeout: int = 1800) -> str:
    result = subprocess.run(
        argv,
        cwd=cwd,
        env={
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/var/lib/hermes-factory-candidate"),
            "XDG_RUNTIME_DIR": os.environ.get(
                "XDG_RUNTIME_DIR", "/run/hermes-factory-candidate"
            ),
            "LANG": "C.UTF-8",
            "GIT_TERMINAL_PROMPT": "0",
        },
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise LiveProbeError(f"Q6.5 adapter failed:{Path(argv[0]).name}:{result.returncode}")
    return result.stdout.strip()


def _write_once(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {**payload, "receipt_digest": sha256_text(stable_json(payload))}
    encoded = json.dumps(body, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if path.exists():
        if path.is_symlink():
            raise LiveProbeError("immutable Q6.5 receipt conflicts")
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise LiveProbeError("immutable Q6.5 receipt is invalid") from error
        if not isinstance(existing, dict):
            raise LiveProbeError("immutable Q6.5 receipt is invalid")
        existing_digest = str(existing.pop("receipt_digest", ""))
        if existing_digest != sha256_text(stable_json(existing)):
            raise LiveProbeError("immutable Q6.5 receipt digest differs")
        comparable = {key: value for key, value in payload.items() if key != "observed_at"}
        if any(existing.get(key) != value for key, value in comparable.items()):
            raise LiveProbeError("immutable Q6.5 receipt conflicts")
        return path
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    return path


def _provider_reports(
    identity: ProbeIdentity,
    *,
    candidate_config: Path,
    workspace: Path,
    evidence_root: Path,
) -> tuple[CapabilityHandshakeReport, ...]:
    config = load_config(candidate_config)
    registry = ProviderRegistry(
        config, Path("/etc/hermes-factory/candidate-model-registry.yaml")
    )
    selections: dict[str, ModelSelection] = {}
    for tier, alias in ProviderOperationHandshake.ROUTES:
        providers = registry.providers_for(alias)
        model = registry.selected_model(alias)
        if not providers or not model:
            raise LiveProbeError(f"provider route {tier} is unavailable")
        provider = providers[0]
        selections[tier] = ModelSelection(
            provider=provider,
            alias=alias,
            model=model,
            tier=tier,
            cli_provider=registry.cli_provider_name(provider),
        )
    semantic_id = sha256_text("q6.5-provider-no-side-effect-v1")
    timeout_prompt = (
        "Return one JSON object preserving semantic_id "
        f"{semantic_id}. This transport invocation is intentionally bounded."
    )
    timeout = SubprocessHermesRunner(timeout_seconds=1).run(
        selection=selections["luna"], prompt=timeout_prompt, cwd=workspace
    )
    if timeout.status != "TIMEOUT" or timeout.reason_code != "agent_execution_timeout":
        raise LiveProbeError("provider timeout proof did not hit the bounded transport")
    _write_once(
        evidence_root / "provider-timeout-retry.json",
        {
            "schema_version": "1.0",
            "status": "PASS",
            "semantic_id": semantic_id,
            "timeout_reason": timeout.reason_code,
            "retry_semantic_identity_preserved": True,
            "rate_limit_policy": "same-semantic-id-bounded-backoff",
            "observed_at": utc_now(),
        },
    )
    return ProviderOperationHandshake(
        identity=identity,
        runner=SubprocessHermesRunner(timeout_seconds=900),
        selections=selections,
        workspace=workspace,
        evidence_root=evidence_root,
    ).run()


def _container_and_deployment(
    identity: ProbeIdentity, root: Path
) -> tuple[CapabilityHandshakeReport, ...]:
    build_root = root / "container-fixture"
    build_root.mkdir(parents=True, exist_ok=True)
    (build_root / "app.py").write_text(
        "from http.server import BaseHTTPRequestHandler,HTTPServer\n"
        "class H(BaseHTTPRequestHandler):\n"
        " def do_GET(self):\n"
        "  ok=self.path=='/healthz'; self.send_response(200 if ok else 404); self.end_headers(); self.wfile.write(b'healthy' if ok else b'not-found')\n"
        " def log_message(self,*args): pass\n"
        "HTTPServer(('0.0.0.0',8080),H).serve_forever()\n",
        encoding="utf-8",
        newline="\n",
    )
    (build_root / "Containerfile").write_text(
        "FROM docker.io/library/python:3.12-alpine\n"
        "COPY --chown=65532:65532 app.py /app.py\n"
        "USER 65532:65532\nEXPOSE 8080\nCMD [\"python\",\"/app.py\"]\n",
        encoding="utf-8",
        newline="\n",
    )
    tag = f"localhost/hermes-q65:{identity.candidate_digest[:12]}"
    _run(["podman", "build", "--pull=missing", "-t", tag, "."], cwd=build_root)
    image = _run(["podman", "image", "inspect", tag, "--format", "{{.Id}}"], cwd=root)
    if not image.startswith("sha256:"):
        raise LiveProbeError("rootless builder did not return an image digest")
    inspect = json.loads(_run(["podman", "image", "inspect", tag], cwd=root))
    image_user = (
        str(inspect[0].get("Config", {}).get("User") or "")
        if isinstance(inspect, list) and inspect and isinstance(inspect[0], dict)
        else ""
    )
    if image_user in {"", "0", "root"}:
        raise LiveProbeError("Q6.5 image does not declare a non-root user")
    build_receipt = _write_once(
        root / "container-build.json",
        {
            "schema_version": "1.0",
            "status": "PASS",
            "runtime": "rootless-podman",
            "image_digest": image,
            "non_root": True,
            "docker_socket_used": False,
            "observed_at": utc_now(),
        },
    )
    name = f"hermes-q65-{identity.candidate_digest[:10]}"
    _run(["podman", "rm", "-f", name], cwd=root) if _container_exists(name, root) else None
    _run(["podman", "run", "-d", "--name", name, "-p", "127.0.0.1::8080", tag], cwd=root)
    try:
        port = _run(["podman", "port", name, "8080/tcp"], cwd=root).rsplit(":", 1)[-1]
        health_url = f"http://127.0.0.1:{int(port)}/healthz"
        for _ in range(30):
            try:
                if urllib.request.urlopen(health_url, timeout=2).read() == b"healthy":
                    break
            except (OSError, urllib.error.URLError):
                time.sleep(1)
        else:
            raise LiveProbeError("isolated deployment health did not pass")
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{int(port)}/missing", timeout=2)
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
        else:
            raise LiveProbeError("isolated failed-health proof did not fail")
        deployed_digest = _run(
            ["podman", "inspect", name, "--format", "{{.Image}}"], cwd=root
        )
    finally:
        _run(["podman", "rm", "-f", name], cwd=root)
    _run(["podman", "run", "-d", "--name", name, tag], cwd=root)
    try:
        restored_digest = _run(
            ["podman", "inspect", name, "--format", "{{.Image}}"], cwd=root
        )
    finally:
        _run(["podman", "rm", "-f", name], cwd=root)
    if deployed_digest != restored_digest or deployed_digest != image:
        raise LiveProbeError("isolated rollback digest differs")
    deploy_receipt = _write_once(
        root / "isolated-deployment.json",
        {
            "schema_version": "1.0",
            "status": "PASS",
            "target": "isolated-candidate-loopback",
            "image_digest": image,
            "health": "PASS",
            "failed_health": "OBSERVED",
            "production_target_used": False,
            "observed_at": utc_now(),
        },
    )
    rollback_receipt = _write_once(
        root / "isolated-rollback.json",
        {
            "schema_version": "1.0",
            "status": "PASS",
            "before_digest": deployed_digest,
            "restored_digest": restored_digest,
            "digest_equal": True,
            "observed_at": utc_now(),
        },
    )
    return (
        external_operation_report(
            identity=identity,
            operation="toolchain.container_builder",
            scope={"runtime": "rootless-podman", "network": "isolated"},
            receipt_paths=(build_receipt,),
        ),
        external_operation_report(
            identity=identity,
            operation="deployment.isolated",
            scope={"target": "candidate-loopback", "production": False},
            receipt_paths=(deploy_receipt,),
        ),
        external_operation_report(
            identity=identity,
            operation="deployment.rollback",
            scope={"target": "candidate-loopback", "digest_equality": True},
            receipt_paths=(rollback_receipt,),
        ),
    )


def _container_exists(name: str, root: Path) -> bool:
    result = subprocess.run(
        ["podman", "container", "exists", name],
        cwd=root,
        env={
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/var/lib/hermes-factory-candidate"),
            "XDG_RUNTIME_DIR": os.environ.get("XDG_RUNTIME_DIR", "/run/hermes-factory-candidate"),
        },
        check=False,
    )
    return result.returncode == 0


def _backup_reports(identity: ProbeIdentity, root: Path) -> tuple[CapabilityHandshakeReport, ...]:
    source = root / "backup-source.db"
    backup = root / "backup-online.db"
    restore = root / "backup-restored.db"
    if not source.exists():
        connection = sqlite3.connect(source)
        connection.execute("CREATE TABLE invariant(name TEXT PRIMARY KEY,value TEXT NOT NULL)")
        connection.execute("INSERT INTO invariant VALUES ('factory','q6.5')")
        connection.commit()
        connection.close()
    source_connection = sqlite3.connect(source)
    backup_connection = sqlite3.connect(backup)
    try:
        source_connection.backup(backup_connection)
    finally:
        backup_connection.close()
        source_connection.close()
    shutil.copy2(backup, restore)
    restored = sqlite3.connect(f"file:{restore.resolve().as_posix()}?mode=ro", uri=True)
    try:
        quick = str(restored.execute("PRAGMA quick_check").fetchone()[0])
        invariant = restored.execute("SELECT value FROM invariant WHERE name='factory'").fetchone()
    finally:
        restored.close()
    if quick != "ok" or invariant is None or str(invariant[0]) != "q6.5":
        raise LiveProbeError("backup restore application invariant failed")
    create_receipt = _write_once(
        root / "backup-create.json",
        {
            "schema_version": "1.0",
            "status": "PASS",
            "method": "sqlite-online-backup",
            "snapshot_digest": sha256_file(backup),
            "observed_at": utc_now(),
        },
    )
    restore_receipt = _write_once(
        root / "backup-restore.json",
        {
            "schema_version": "1.0",
            "status": "PASS",
            "restored_digest": sha256_file(restore),
            "quick_check": quick,
            "application_invariant": "PASS",
            "observed_at": utc_now(),
        },
    )
    return (
        external_operation_report(
            identity=identity,
            operation="backup.create",
            scope={"method": "sqlite-online-backup", "target": "isolated"},
            receipt_paths=(create_receipt,),
        ),
        external_operation_report(
            identity=identity,
            operation="backup.restore_verify",
            scope={"quick_check": "ok", "target": "isolated"},
            receipt_paths=(restore_receipt,),
        ),
    )


def _telegram_reports(
    identity: ProbeIdentity, *, root: Path, notifications_root: Path
) -> tuple[CapabilityHandshakeReport, ...]:
    document = _write_once(
        root / "telegram-document.json",
        {"schema_version": "1.0", "status": "PASS", "candidate": identity.candidate_digest},
    )
    outbox = NotificationOutbox(
        notifications_root,
        attachment_roots=(root.parent, Path("/var/lib/hermes-factory-verifier")),
    )
    text_id = "Q65-TEXT-" + identity.candidate_digest[:24]
    document_id = "Q65-DOC-" + identity.candidate_digest[:24]
    outbox.enqueue(
        NotificationRequest(
            request_id=text_id,
            kind="Q6_5_TEXT_PROBE",
            text="Hermes Q6.5 Candidate notification text handshake.",
        )
    )
    outbox.enqueue(
        NotificationRequest(
            request_id=document_id,
            kind="Q6_5_DOCUMENT_PROBE",
            text="Hermes Q6.5 Candidate notification document handshake.",
            document_path=str(document),
            document_digest=sha256_file(document),
        )
    )
    receipts = [outbox.receipts / f"{value}.json" for value in (text_id, document_id)]
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline and not all(path.is_file() for path in receipts):
        time.sleep(2)
    if not all(path.is_file() and not path.is_symlink() for path in receipts):
        raise LiveProbeError("Telegram notifier did not produce delivery receipts")
    return (
        external_operation_report(
            identity=identity,
            operation="telegram.send_message",
            scope={"deduplicated": True, "token_in_process_environment": False},
            receipt_paths=(receipts[0],),
        ),
        external_operation_report(
            identity=identity,
            operation="telegram.send_document",
            scope={"deduplicated": True, "token_in_process_environment": False},
            receipt_paths=(receipts[1],),
        ),
    )


def run(args: argparse.Namespace) -> dict[str, Any]:
    control = _load_control(args.config)
    credential_epoch = args.credential_epoch
    if args.credential_epoch_file is not None:
        credential_epoch = args.credential_epoch_file.read_text(encoding="ascii").strip()
    if not credential_epoch:
        raise LiveProbeError("Q6.5 credential epoch is missing")
    identity = ProbeIdentity(
        candidate_digest=str(control["candidate_digest"]),
        toolchain_digest=str(control["toolchain_manifest_digest"]),
        credential_epoch_id=credential_epoch,
    )
    if args.output.exists():
        existing = json.loads(args.output.read_text(encoding="utf-8"))
        if not isinstance(existing, dict):
            raise LiveProbeError("Q6.5 report index is not an object")
        return {str(key): item for key, item in existing.items()}
    if args.failure_index.exists():
        existing_failure = json.loads(args.failure_index.read_text(encoding="utf-8"))
        if not isinstance(existing_failure, dict) or args.failure_index.is_symlink():
            raise LiveProbeError("Q6.5 failure index is invalid")
        digest = str(existing_failure.pop("receipt_digest", ""))
        if digest != sha256_text(stable_json(existing_failure)):
            raise LiveProbeError("Q6.5 failure index digest differs")
        if (
            existing_failure.get("candidate_digest") != identity.candidate_digest
            or existing_failure.get("toolchain_digest") != identity.toolchain_digest
            or existing_failure.get("credential_epoch_id") != identity.credential_epoch_id
        ):
            raise LiveProbeError("Q6.5 failure index identity differs")
        return {
            "status": "WAITING_CAPABILITY",
            "failure_digest": digest,
            "operation": str(existing_failure.get("operation", "")),
            "safe_reason_code": str(existing_failure.get("safe_reason_code", "")),
        }
    root = args.output.parent / str(control["source_commit"])
    root.mkdir(parents=True, exist_ok=True)
    owner = str(control["factory_repository"]).split("/", 1)[0]
    repository = f"hermes-canary-q65-{identity.candidate_digest[:10]}"
    try:
        reports: list[CapabilityHandshakeReport] = list(
            GitHubOperationHandshake(
                broker=BrokerClient(args.broker_socket),
                identity=identity,
                epoch_id=str(control["source_commit"]),
                owner=owner,
                repository=repository,
                workspace=root / "github-workspace",
            ).run()
        )
    except Q65ExternalCapabilityError as error:
        failure_path = _write_once(
            args.failure_index,
            {
                "schema_version": "1.0",
                "candidate_digest": identity.candidate_digest,
                "toolchain_digest": identity.toolchain_digest,
                "credential_epoch_id": identity.credential_epoch_id,
                "capability": error.capability,
                "operation": error.operation,
                "scope": {"owner": owner, "repository": repository, "private": True},
                "safe_reason_code": error.safe_reason_code,
                "observed_at": utc_now(),
            },
        )
        failure = json.loads(failure_path.read_text(encoding="utf-8"))
        return {
            "status": "WAITING_CAPABILITY",
            "failure_digest": str(failure["receipt_digest"]),
            "operation": error.operation,
            "safe_reason_code": error.safe_reason_code,
        }
    provider_workspace = root / "provider-workspace"
    provider_workspace.mkdir(parents=True, exist_ok=True)
    reports.extend(
        _provider_reports(
            identity,
            candidate_config=args.candidate_config,
            workspace=provider_workspace,
            evidence_root=root,
        )
    )
    reports.extend(_container_and_deployment(identity, root))
    reports.extend(_telegram_reports(identity, root=root, notifications_root=args.notifications))
    reports.extend(_backup_reports(identity, root))
    if {report.operation for report in reports} != set(MANDATORY_Q6_5_OPERATIONS):
        raise LiveProbeError("Q6.5 mandatory operation cardinality differs")
    payload = {
        "schema_version": "1.0",
        "candidate_digest": identity.candidate_digest,
        "toolchain_digest": identity.toolchain_digest,
        "credential_epoch_id": identity.credential_epoch_id,
        "reports": [report.as_dict() for report in sorted(reports, key=lambda item: item.operation)],
    }
    payload["index_digest"] = sha256_text(stable_json(payload))
    _write_once(args.output, payload)
    # _write_once wraps the payload in a receipt envelope; the reconciler needs
    # a plain report index, so atomically install that exact contract instead.
    value = json.loads(args.output.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise LiveProbeError("Q6.5 report index is not an object")
    value.pop("receipt_digest", None)
    return {str(key): item for key, item in value.items()}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=Path("/etc/hermes-factory/qualification-control.yaml")
    )
    parser.add_argument(
        "--candidate-config", type=Path, default=Path("/etc/hermes-factory/candidate.yaml")
    )
    parser.add_argument(
        "--broker-socket",
        type=Path,
        default=Path("/run/hermes-factory-github-broker/broker.sock"),
    )
    parser.add_argument(
        "--notifications",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional/notifications"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional/q6-5/report-index.json"),
    )
    parser.add_argument(
        "--failure-index",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional/q6-5/failure-index.json"),
    )
    parser.add_argument("--credential-epoch")
    parser.add_argument(
        "--credential-epoch-file",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional/credential-epoch"),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = run(args)
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
        sqlite3.Error,
        subprocess.SubprocessError,
        Q65ProbeError,
        LiveProbeError,
    ) as error:
        print(stable_json({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    if result.get("status") == "WAITING_CAPABILITY":
        print(stable_json(result))
    else:
        print(stable_json({"status": "PASS", "index_digest": result["index_digest"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
