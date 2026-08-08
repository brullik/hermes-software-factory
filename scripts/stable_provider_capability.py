#!/usr/bin/env python3
"""Prove real provider invocations from the permanent Stable worker identity."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from factory.common import sha256_file, sha256_text, stable_json, utc_now
from factory.config import load_config
from factory.functional_readiness import CapabilityHandshakeReport, CapabilityStatus
from factory.providers import ModelSelection, ProviderRegistry
from factory.q6_5 import (
    ProbeIdentity,
    ProviderOperationHandshake,
    Q65ProbeError,
    Q65ProviderCapabilityError,
)
from factory.worker import SubprocessHermesRunner


class StableProviderCapabilityError(RuntimeError):
    """The Stable provider boundary could not produce authoritative evidence."""


_SAFE_PROVIDER = re.compile(r"^[A-Za-z0-9._-]+$")
_EXPECTED_OPERATIONS = {
    "provider.luna.invoke",
    "provider.terra.invoke",
    "provider.sol.invoke",
    "provider.terminal.sandbox",
}


def _mapping(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise StableProviderCapabilityError(f"{label} is unavailable")
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise StableProviderCapabilityError(f"{label} is invalid")
    return {str(key): item for key, item in value.items()}


def _write_once(path: Path, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_text(encoding="utf-8") != encoded:
            raise StableProviderCapabilityError("immutable Stable provider evidence conflicts")
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())


def _archive(path: Path, *, prefix: str) -> None:
    if not path.exists():
        return
    if path.is_symlink() or not path.is_file():
        raise StableProviderCapabilityError("Stable provider evidence archive source is unsafe")
    digest = sha256_file(path)
    archive = path.parent / "archive"
    archive.mkdir(parents=True, exist_ok=True)
    destination = archive / f"{prefix}-{digest}.json"
    if destination.exists():
        if destination.is_symlink() or destination.read_bytes() != path.read_bytes():
            raise StableProviderCapabilityError("Stable provider evidence archive conflicts")
        path.unlink()
    else:
        path.replace(destination)


def _parse_time(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as error:
        raise StableProviderCapabilityError("Stable provider timestamp is invalid") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _production_identity(control: dict[str, Any]) -> tuple[str, datetime | None]:
    path = Path(str(control.get("production_observation_path") or ""))
    if not path.is_file() or path.is_symlink():
        return "initial", None
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("proof_type") != "PRODUCTION_OBSERVATION"
        or value.get("status") != "PASS"
        or value.get("candidate_digest") != control["candidate_digest"]
    ):
        raise StableProviderCapabilityError("production observation binding is invalid")
    digest = str(value.get("proof_digest") or "")
    unsigned = dict(value)
    unsigned.pop("proof_digest", None)
    if not re.fullmatch(r"[a-f0-9]{64}", digest) or digest != sha256_text(stable_json(unsigned)):
        raise StableProviderCapabilityError("production observation digest differs")
    return f"production-{digest[:20]}", _parse_time(value.get("completed_at"))


def _existing_is_current(
    path: Path, *, candidate_digest: str, minimum_time: datetime | None
) -> bool:
    if not path.exists():
        return False
    if path.is_symlink() or not path.is_file():
        raise StableProviderCapabilityError("Stable provider report index is unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise StableProviderCapabilityError("Stable provider report index is invalid")
    digest = str(value.get("report_digest") or "")
    unsigned = dict(value)
    unsigned.pop("report_digest", None)
    reports = value.get("reports")
    if (
        set(unsigned) != {"schema_version", "observed_at", "reports"}
        or value.get("schema_version") != "1.0"
        or digest != sha256_text(stable_json(unsigned))
        or not isinstance(reports, list)
        or {str(item.get("candidate_digest") or "") for item in reports if isinstance(item, dict)}
        != {candidate_digest}
        or {str(item.get("operation") or "") for item in reports if isinstance(item, dict)}
        != _EXPECTED_OPERATIONS
    ):
        _archive(path, prefix="obsolete-report")
        return False
    observed = _parse_time(value.get("observed_at"))
    if minimum_time is None or observed > minimum_time:
        return True
    _archive(path, prefix="report")
    return False


def _auth_state(provider: str) -> str:
    if not _SAFE_PROVIDER.fullmatch(provider):
        raise StableProviderCapabilityError("Stable provider identity is invalid")
    executable = Path(sys.executable).resolve().with_name("hermes")
    try:
        result = subprocess.run(
            [str(executable), "auth", "status", provider],
            env={
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                "HOME": os.environ.get("HOME", "/var/lib/hermes-factory"),
                "NO_COLOR": "1",
            },
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return "BROKEN_INTERNAL"
    output = f"{result.stdout}\n{result.stderr}".strip().lower()
    if result.returncode == 0 and result.stdout.strip().startswith(f"{provider}: logged in"):
        return "AVAILABLE"
    if any(marker in output for marker in ("not logged in", "authentication required")):
        return "MISSING_EXTERNAL"
    return "BROKEN_INTERNAL"


def _selections(config_path: Path, registry_path: Path) -> dict[str, ModelSelection]:
    if not registry_path.is_file() or registry_path.is_symlink():
        raise StableProviderCapabilityError("Stable model registry is unavailable")
    registry = ProviderRegistry(load_config(config_path), registry_path)
    selections: dict[str, ModelSelection] = {}
    for tier, alias in ProviderOperationHandshake.ROUTES:
        providers = registry.providers_for(alias)
        model = registry.selected_model(alias)
        if not providers or not model:
            raise StableProviderCapabilityError(f"Stable provider route {tier} is unavailable")
        provider = providers[0]
        selections[tier] = ModelSelection(
            provider=provider,
            alias=alias,
            model=model,
            tier=tier,
            cli_provider=registry.cli_provider_name(provider),
        )
    return selections


def _failure(
    path: Path,
    *,
    control: dict[str, Any],
    status: str,
    reason_code: str,
    credential_provider: str | None,
) -> dict[str, Any]:
    payload = {
        "schema_version": "1.0",
        "candidate_digest": str(control["candidate_digest"]),
        "capability": "provider.stable.runtime",
        "status": status,
        "safe_reason_code": reason_code,
        "credential_provider": credential_provider,
        "observed_at": utc_now(),
    }
    envelope = {**payload, "failure_digest": sha256_text(stable_json(payload))}
    _write_once(path, envelope)
    return envelope


def _terminal_sandbox_report(
    *,
    control: dict[str, Any],
    selection: ModelSelection,
    identity: ProbeIdentity,
    workspace: Path,
    evidence_root: Path,
) -> CapabilityHandshakeReport:
    """Prove that a real model tool call executes only in credential-free OCI."""

    marker = workspace / "provider-terminal-sandbox.txt"
    nonce = sha256_text(
        stable_json(
            [
                "provider-terminal-sandbox-v1",
                control["candidate_digest"],
                workspace.name,
            ]
        )
    )
    command = (
        "set -eu; "
        "test -f /run/.containerenv; "
        "test ! -e /etc/hermes-factory/credentials.d; "
        "test ! -e /etc/hermes-factory/candidate-credentials.d; "
        "if env | grep -Eq "
        "'^(GH_TOKEN|GITHUB_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_API_KEY|"
        "AWS_SECRET_ACCESS_KEY|HERMES_API_KEY|TELEGRAM_BOT_TOKEN)='; "
        "then exit 70; fi; "
        f"umask 077; printf '%s\\n' '{nonce}' > provider-terminal-sandbox.txt"
    )
    semantic_id = sha256_text("stable-provider-terminal-sandbox-v1")
    prompt = (
        "Use the terminal tool exactly once. Run exactly this fixed command in the mounted "
        f"workspace:\n{command}\n"
        "After the command succeeds, return exactly one JSON object and no other text: "
        '{"schema_version":"1.0","status":"PASS",'
        f'"semantic_id":"{semantic_id}"}}'
    )
    usage_path = evidence_root / "provider-terminal-sandbox-usage.json"
    result = SubprocessHermesRunner(
        timeout_seconds=900,
        toolsets=("terminal",),
    ).run(
        selection=selection,
        prompt=prompt,
        cwd=workspace,
        usage_path=usage_path,
    )
    if result.status != "PASS":
        if result.reason_code == "missing_credential":
            raise Q65ProviderCapabilityError(
                tier="luna",
                alias="economy",
                selection=selection,
                semantic_id=semantic_id,
            )
        raise Q65ProbeError(f"provider terminal sandbox failed:{result.reason_code}")
    try:
        response = json.loads(result.output)
    except json.JSONDecodeError as error:
        raise Q65ProbeError("provider terminal sandbox output parser failed") from error
    if response != {
        "schema_version": "1.0",
        "status": "PASS",
        "semantic_id": semantic_id,
    }:
        raise Q65ProbeError("provider terminal sandbox output schema differs")
    if (
        not marker.is_file()
        or marker.is_symlink()
        or marker.read_text(encoding="ascii") != nonce + "\n"
        or marker.stat().st_uid != os.getuid()
        or marker.stat().st_mode & 0o077
    ):
        raise Q65ProbeError("provider terminal sandbox marker differs")
    receipts = [result.output_digest, sha256_file(marker)]
    if usage_path.is_file() and not usage_path.is_symlink():
        receipts.append(sha256_file(usage_path))
    return CapabilityHandshakeReport.create(
        candidate_digest=identity.candidate_digest,
        capability="provider.terminal.sandbox",
        operation="provider.terminal.sandbox",
        scope={
            "alias": selection.alias,
            "provider": selection.provider,
            "model": selection.model,
            "semantic_id": semantic_id,
            "runtime_principal": "hermesfactory",
            "execution_boundary": "rootless_oci",
            "container_identity": "/run/.containerenv",
            "workspace_mount": True,
            "credential_forwarding": False,
            "toolsets": ["terminal"],
            "marker_digest": sha256_file(marker),
        },
        status=CapabilityStatus.AVAILABLE,
        credential_epoch_id=None,
        toolchain_digest=identity.toolchain_digest,
        receipts=tuple(receipts),
    )


def run(args: argparse.Namespace) -> dict[str, Any]:
    control = _mapping(args.control, "qualification control")
    required = {"candidate_digest", "toolchain_manifest_digest", "source_commit"}
    if not required <= control.keys():
        raise StableProviderCapabilityError("qualification control is incomplete")
    run_id, minimum_time = _production_identity(control)
    if _existing_is_current(
        args.output,
        candidate_digest=str(control["candidate_digest"]),
        minimum_time=minimum_time,
    ):
        return {"status": "PASS", "reconciliation": "existing"}
    selections = _selections(args.stable_config, args.registry)
    auth_states = {
        provider: _auth_state(provider)
        for provider in {
            selection.cli_provider or selection.provider for selection in selections.values()
        }
    }
    missing = next(
        (
            provider
            for provider, state in sorted(auth_states.items())
            if state == "MISSING_EXTERNAL"
        ),
        None,
    )
    broken = next(
        (provider for provider, state in sorted(auth_states.items()) if state == "BROKEN_INTERNAL"),
        None,
    )
    if args.failure_index.exists():
        failure = json.loads(args.failure_index.read_text(encoding="utf-8"))
        if not isinstance(failure, dict) or args.failure_index.is_symlink():
            raise StableProviderCapabilityError("Stable provider failure index is invalid")
        if (
            failure.get("candidate_digest") != control["candidate_digest"]
            or failure.get("capability") != "provider.stable.runtime"
        ):
            _archive(args.failure_index, prefix="failure")
        elif failure.get("status") == "MISSING_EXTERNAL" and (
            missing is None or failure.get("credential_provider") != missing or broken is not None
        ):
            _archive(args.failure_index, prefix="resolved-failure")
        else:
            return {
                "status": "WAITING_CAPABILITY"
                if failure.get("status") == "MISSING_EXTERNAL"
                else "FAIL",
                "safe_reason_code": str(failure.get("safe_reason_code") or ""),
            }
    if broken is not None:
        failure = _failure(
            args.failure_index,
            control=control,
            status="BROKEN_INTERNAL",
            reason_code="stable_provider_operation_failed",
            credential_provider=None,
        )
        return {"status": "FAIL", "failure_digest": failure["failure_digest"]}
    if missing is not None:
        failure = _failure(
            args.failure_index,
            control=control,
            status="MISSING_EXTERNAL",
            reason_code="missing_stable_provider_credential",
            credential_provider=missing,
        )
        return {
            "status": "WAITING_CAPABILITY",
            "safe_reason_code": failure["safe_reason_code"],
        }
    workspace = args.workspace_root / str(control["candidate_digest"]) / run_id
    workspace.mkdir(parents=True, exist_ok=True)
    evidence_root = workspace / "evidence"
    evidence_root.mkdir(parents=True, exist_ok=True)
    identity = ProbeIdentity(
        candidate_digest=str(control["candidate_digest"]),
        toolchain_digest=str(control["toolchain_manifest_digest"]),
        credential_epoch_id=None,
    )
    try:
        raw_reports = list(
            ProviderOperationHandshake(
                identity=identity,
                runner=SubprocessHermesRunner(
                    timeout_seconds=900,
                    toolsets=("vision",),
                ),
                selections=selections,
                workspace=workspace,
                evidence_root=evidence_root,
            ).run()
        )
        raw_reports.append(
            _terminal_sandbox_report(
                control=control,
                selection=selections["luna"],
                identity=identity,
                workspace=workspace,
                evidence_root=evidence_root,
            )
        )
    except Q65ProviderCapabilityError as error:
        failure = _failure(
            args.failure_index,
            control=control,
            status="MISSING_EXTERNAL",
            reason_code="missing_stable_provider_credential",
            credential_provider=error.selection.cli_provider or error.selection.provider,
        )
        return {
            "status": "WAITING_CAPABILITY",
            "safe_reason_code": failure["safe_reason_code"],
        }
    except Q65ProbeError:
        failure = _failure(
            args.failure_index,
            control=control,
            status="BROKEN_INTERNAL",
            reason_code="stable_provider_operation_failed",
            credential_provider=None,
        )
        return {"status": "FAIL", "failure_digest": failure["failure_digest"]}
    reports = tuple(
        CapabilityHandshakeReport.create(
            candidate_digest=report.candidate_digest,
            capability=report.capability,
            operation=report.operation,
            scope={**dict(report.scope), "runtime_principal": "hermesfactory"},
            status=CapabilityStatus.AVAILABLE,
            credential_epoch_id=None,
            toolchain_digest=report.toolchain_digest,
            receipts=report.receipts,
        )
        for report in raw_reports
    )
    observed_at = utc_now()
    payload = {
        "schema_version": "1.0",
        "observed_at": observed_at,
        "reports": [
            report.as_dict() for report in sorted(reports, key=lambda item: item.operation)
        ],
    }
    envelope = {**payload, "report_digest": sha256_text(stable_json(payload))}
    _write_once(args.output, envelope)
    _archive(args.failure_index, prefix="resolved-failure")
    return {"status": "PASS", "report_digest": envelope["report_digest"]}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--control",
        type=Path,
        default=Path("/etc/hermes-factory/qualification-control.yaml"),
    )
    parser.add_argument(
        "--stable-config",
        type=Path,
        default=Path("/etc/hermes-factory/config.yaml"),
    )
    parser.add_argument(
        "--registry",
        type=Path,
        default=Path("/etc/hermes-factory/model-registry.yaml"),
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=Path("/var/lib/hermes-factory/worktrees/provider-capability"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional/stable-provider/report-index.json"),
    )
    parser.add_argument(
        "--failure-index",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional/stable-provider/failure-index.json"),
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
        StableProviderCapabilityError,
    ) as error:
        print(stable_json({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    print(stable_json(result))
    # BROKEN_INTERNAL is an immutable qualification outcome, not a crashed
    # system service. Returning success lets the durable reconciler consume it
    # in this same pass and transition the epoch to QUALIFICATION_FAILED.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
