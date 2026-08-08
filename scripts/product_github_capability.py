#!/usr/bin/env python3
"""Prove Stable product GitHub operations through its dedicated typed broker."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from factory.common import sha256_text, stable_json, utc_now
from factory.credential_broker import BrokerClient, CredentialBrokerError
from factory.q6_5 import (
    GitHubOperationHandshake,
    ProbeIdentity,
    Q65ExternalCapabilityError,
    Q65ProbeError,
)


class ProductCapabilityError(RuntimeError):
    """The permanent product GitHub lane lacks an operational proof."""


def _write_once(path: Path, payload: dict[str, Any]) -> Path:
    encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_text(encoding="utf-8") != encoded:
            raise ProductCapabilityError("immutable product capability evidence conflicts")
        return path
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    return path


def _control(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ProductCapabilityError("qualification control is invalid")
    required = {
        "source_commit",
        "candidate_digest",
        "toolchain_manifest_digest",
        "factory_repository",
    }
    if not required <= value.keys():
        raise ProductCapabilityError("qualification control is incomplete")
    return {str(key): item for key, item in value.items()}


def _credential_epoch(path: Path) -> str | None:
    if not path.is_file() or path.is_symlink():
        return None
    value = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"CE-[A-F0-9]{32}", value):
        raise ProductCapabilityError("product broker credential epoch is invalid")
    return value


def _archive_stale_failure(
    path: Path, *, credential_epoch: str | None, candidate_digest: str
) -> None:
    if not path.exists():
        return
    if path.is_symlink() or not path.is_file():
        raise ProductCapabilityError("product capability failure index is unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ProductCapabilityError("product capability failure index is invalid")
    unsigned = dict(value)
    failure_digest = str(unsigned.pop("failure_digest", ""))
    if (
        set(unsigned)
        == {
            "schema_version",
            "candidate_digest",
            "credential_epoch_id",
            "capability",
            "status",
            "safe_reason_code",
            "observed_at",
        }
        and value.get("credential_epoch_id") == credential_epoch
        and value.get("candidate_digest") == candidate_digest
        and failure_digest == sha256_text(stable_json(unsigned))
    ):
        return
    digest = sha256_text(stable_json(value))
    archive = path.parent / "archive"
    archive.mkdir(parents=True, exist_ok=True)
    destination = archive / f"failure-{digest}.json"
    if destination.exists():
        if destination.is_symlink() or destination.read_bytes() != path.read_bytes():
            raise ProductCapabilityError("product capability failure archive conflicts")
        path.unlink()
        return
    path.replace(destination)


def _existing_failure(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ProductCapabilityError("product capability failure index is invalid")
    status = str(value.get("status") or "")
    reason = str(value.get("safe_reason_code") or "")
    if (status, reason) == (
        "MISSING_EXTERNAL",
        "missing_stable_product_github_credential",
    ):
        return {"status": "WAITING_CAPABILITY", "safe_reason_code": reason}
    if (status, reason) == (
        "BROKEN_INTERNAL",
        "stable_product_github_operation_failed",
    ):
        return {"status": "QUALIFICATION_FAILED", "safe_reason_code": reason}
    raise ProductCapabilityError("product capability failure classification is invalid")


def _failure_payload(
    *,
    candidate_digest: str,
    credential_epoch: str | None,
    status: str,
    safe_reason_code: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "candidate_digest": candidate_digest,
        "credential_epoch_id": credential_epoch,
        "capability": "github.product.runtime",
        "status": status,
        "safe_reason_code": safe_reason_code,
        "observed_at": utc_now(),
    }
    payload["failure_digest"] = sha256_text(stable_json(payload))
    return payload


def _reconcile_existing_success(
    path: Path, *, candidate_digest: str, credential_epoch: str | None
) -> bool:
    if not path.exists():
        return False
    if path.is_symlink() or not path.is_file():
        raise ProductCapabilityError("product capability success index is unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    reports = value.get("reports") if isinstance(value, dict) else None
    identities = (
        {str(item.get("candidate_digest") or "") for item in reports if isinstance(item, dict)}
        if isinstance(reports, list)
        else set()
    )
    unsigned = dict(value) if isinstance(value, dict) else {}
    digest = str(unsigned.pop("report_digest", ""))
    current = (
        (
            identities == {candidate_digest}
            and value.get("credential_epoch_id") == credential_epoch
            and digest == sha256_text(stable_json(unsigned))
        )
        if isinstance(value, dict)
        else False
    )
    if current:
        return True
    archive = path.parent / "archive"
    archive.mkdir(parents=True, exist_ok=True)
    file_digest = sha256_text(path.read_text(encoding="utf-8"))
    destination = archive / f"report-{file_digest}.json"
    if destination.exists():
        if destination.is_symlink() or destination.read_bytes() != path.read_bytes():
            raise ProductCapabilityError("product capability success archive conflicts")
        path.unlink()
    else:
        path.replace(destination)
    return False


def _archive_resolved_failure(path: Path) -> None:
    if not path.exists():
        return
    if path.is_symlink() or not path.is_file():
        raise ProductCapabilityError("resolved product capability failure is unsafe")
    digest = sha256_text(path.read_text(encoding="utf-8"))
    archive = path.parent / "archive"
    archive.mkdir(parents=True, exist_ok=True)
    destination = archive / f"resolved-failure-{digest}.json"
    if destination.exists():
        if destination.is_symlink() or destination.read_bytes() != path.read_bytes():
            raise ProductCapabilityError("resolved product capability archive conflicts")
        path.unlink()
    else:
        path.replace(destination)


def run(args: argparse.Namespace) -> dict[str, Any]:
    control = _control(args.config)
    owner = str(control["factory_repository"]).split("/", 1)[0]
    credential_epoch = _credential_epoch(args.credential_epoch_file)
    broker_state = subprocess.run(
        [
            "systemctl",
            "show",
            args.broker_unit,
            "--property=ConditionResult,ActiveState",
        ],
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    broker_properties = dict(
        line.split("=", 1) for line in broker_state.stdout.splitlines() if "=" in line
    )
    if broker_properties.get("ConditionResult") == "no":
        credential_epoch = None
    _archive_stale_failure(
        args.failure_index,
        credential_epoch=credential_epoch,
        candidate_digest=str(control["candidate_digest"]),
    )
    existing_failure = _existing_failure(args.failure_index)
    if existing_failure is not None:
        return existing_failure
    if _reconcile_existing_success(
        args.output,
        candidate_digest=str(control["candidate_digest"]),
        credential_epoch=credential_epoch,
    ):
        return {"status": "PASS", "reconciliation": "existing"}
    if credential_epoch is None:
        failure = _failure_payload(
            candidate_digest=str(control["candidate_digest"]),
            credential_epoch=None,
            status="MISSING_EXTERNAL",
            safe_reason_code="missing_stable_product_github_credential",
        )
        _write_once(args.failure_index, failure)
        return {"status": "WAITING_CAPABILITY", "safe_reason_code": failure["safe_reason_code"]}
    repository = f"hermes-canary-runtime-{str(control['candidate_digest'])[:12]}"
    workspace_parent = args.workspace_root / str(control["candidate_digest"])
    workspace_parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        workspace_parent.chmod(0o770)
    identity = ProbeIdentity(
        candidate_digest=str(control["candidate_digest"]),
        toolchain_digest=str(control["toolchain_manifest_digest"]),
        credential_epoch_id=credential_epoch,
    )
    try:
        reports = GitHubOperationHandshake(
            broker=BrokerClient(args.broker_socket),
            identity=identity,
            epoch_id="PRODUCT-" + str(control["source_commit"]),
            owner=owner,
            repository=repository,
            repository_prefix="hermes-canary-runtime-",
            workspace=workspace_parent / "checkout",
        ).run()
    except (CredentialBrokerError, Q65ExternalCapabilityError, Q65ProbeError):
        # A credential epoch was already proven by the broker service. Any
        # subsequent typed-operation failure is technical qualification work,
        # never a request for the owner to diagnose GitHub or the broker.
        failure = _failure_payload(
            candidate_digest=str(control["candidate_digest"]),
            credential_epoch=credential_epoch,
            status="BROKEN_INTERNAL",
            safe_reason_code="stable_product_github_operation_failed",
        )
        _write_once(args.failure_index, failure)
        return {"status": "QUALIFICATION_FAILED", "safe_reason_code": failure["safe_reason_code"]}
    payload = {
        "schema_version": "1.0",
        "credential_epoch_id": credential_epoch,
        "reports": [
            report.as_dict() for report in sorted(reports, key=lambda item: item.operation)
        ],
    }
    payload["report_digest"] = sha256_text(stable_json(payload))
    _archive_resolved_failure(args.failure_index)
    _write_once(args.output, payload)
    return {"status": "PASS", "report_digest": payload["report_digest"]}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/hermes-factory/qualification-control.yaml"),
    )
    parser.add_argument(
        "--broker-socket",
        type=Path,
        default=Path("/run/hermes-factory-product-github-broker/broker.sock"),
    )
    parser.add_argument(
        "--broker-unit",
        default="hermes-factory-product-github-broker.service",
    )
    parser.add_argument(
        "--credential-epoch-file",
        type=Path,
        default=Path("/var/lib/hermes-factory/product-github/credential-epoch"),
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=Path("/var/lib/hermes-factory/worktrees/product-capability"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional/product-github/report-index.json"),
    )
    parser.add_argument(
        "--failure-index",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional/product-github/failure-index.json"),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        result = run(_parser().parse_args(argv))
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        Q65ProbeError,
        ProductCapabilityError,
    ) as error:
        print(stable_json({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    print(stable_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
