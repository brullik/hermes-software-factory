#!/usr/bin/env python3
"""Durable functional-first reconciler for Q6.5, PRE-Q8, Golden, and Q7."""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from factory.canary_faults import CanaryFaultContract
from factory.canary_qualification import load_canary_catalog, observe_completion
from factory.common import sha256_file, sha256_text, stable_json, utc_now
from factory.config import load_config
from factory.functional_readiness import (
    MANDATORY_Q6_5_OPERATIONS,
    PRE_Q8_SCENARIOS,
    CapabilityHandshakeReport,
    CapabilityStatus,
    FunctionalQualificationGovernor,
    FunctionalReadinessError,
)
from factory.notifications import NotificationOutbox, NotificationRequest
from factory.pre_q8_runtime import (
    CrashReconciliationDecision,
    crash_reconciliation_decision,
)
from factory.pre_q8_seal import (
    PreQ8SealError,
    load_and_verify_seal,
    qualification_config_semantic_digest,
)
from factory.support_bundle import SupportBundleError, build_support_bundle


class FunctionalControlError(RuntimeError):
    """The autonomous functional control plane cannot safely advance."""


_CREDENTIAL_EPOCH = re.compile(r"^CE-[A-F0-9]{32}$")


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise FunctionalControlError(f"{label} must be an object")
    return {str(key): item for key, item in value.items()}


def _load_config(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise FunctionalControlError("qualification control config is unavailable")
    value = _mapping(yaml.safe_load(path.read_text(encoding="utf-8")), "control config")
    for key in (
        "governor_database",
        "source_commit",
        "candidate_digest",
        "toolchain_manifest_digest",
        "factory_repository",
    ):
        if not value.get(key):
            raise FunctionalControlError(f"control config lacks {key}")
    return value


def _release_snapshot(
    config: Mapping[str, Any],
) -> tuple[str, dict[str, tuple[str, str, str]]]:
    database = Path(str(config["governor_database"]))
    # The verifier StateStore uses WAL.  This reader is deliberately mounted
    # read-only by systemd, so it cannot participate in SQLite's mutable WAL
    # shared-memory protocol.  Q0-Q6 therefore checkpoints and validates an
    # immutable handoff before this reader is enabled.
    connection = sqlite3.connect(
        f"file:{database.resolve().as_posix()}?mode=ro&immutable=1", uri=True
    )
    try:
        connection.execute("PRAGMA query_only=ON")
        rows = connection.execute(
            "SELECT epoch_id,source_commit,candidate_digest,status "
            "FROM controller_release_epochs ORDER BY created_at DESC"
        ).fetchall()
    finally:
        connection.close()
    expected = (str(config["source_commit"]), str(config["candidate_digest"]))
    matches = [str(row[0]) for row in rows if (str(row[1]), str(row[2])) == expected]
    if len(matches) != 1:
        raise FunctionalControlError("exact Candidate release epoch is ambiguous")
    snapshot: dict[str, tuple[str, str, str]] = {}
    for row in rows:
        epoch_id = str(row[0])
        value = (str(row[1]), str(row[2]), str(row[3]))
        if epoch_id in snapshot and snapshot[epoch_id] != value:
            raise FunctionalControlError("release epoch snapshot identity conflicts")
        snapshot[epoch_id] = value
    return matches[0], snapshot


def _release_epoch(config: Mapping[str, Any]) -> str:
    return _release_snapshot(config)[0]


def _credential_epoch(path: Path, *, label: str) -> str | None:
    try:
        metadata = path.stat()
    except FileNotFoundError:
        return None
    if path.is_symlink() or not path.is_file():
        raise FunctionalControlError(f"Candidate {label} credential source is unsafe")
    if os.name != "nt" and metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise FunctionalControlError(f"Candidate {label} credential permissions are unsafe")
    return "CE-" + sha256_text(
        stable_json([metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns])
    )[:32].upper()


def _governor(database: Path) -> FunctionalQualificationGovernor:
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database)
    return FunctionalQualificationGovernor(connection)


def _retire_superseded_functional_epochs(
    governor: FunctionalQualificationGovernor,
    *,
    current_epoch_id: str,
    release_snapshot: Mapping[str, tuple[str, str, str]],
    state_root: Path,
) -> int:
    rows = governor.connection.execute(
        "SELECT epoch_id,source_commit,candidate_digest FROM functional_epochs "
        "WHERE epoch_id<>? "
        "AND status NOT IN ('NON_PROMOTABLE','QUALIFICATION_FAILED','Q7_STARTED')",
        (current_epoch_id,),
    ).fetchall()
    retired = 0
    for row in rows:
        epoch_id = str(row[0])
        release = release_snapshot.get(epoch_id)
        if release is None:
            raise FunctionalControlError("active functional epoch lacks release proof")
        source_commit, candidate_digest, release_status = release
        proof = {
            "epoch_id": epoch_id,
            "source_commit": source_commit,
            "candidate_digest": candidate_digest,
            "status": release_status,
        }
        action_rows = governor.connection.execute(
            "SELECT action_id FROM functional_owner_actions "
            "WHERE epoch_id=? AND status='OPEN'",
            (epoch_id,),
        ).fetchall()
        outbox = NotificationOutbox(
            state_root / "notifications",
            attachment_roots=(state_root, Path("/var/lib/hermes-factory-verifier")),
        )
        for action_row in action_rows:
            action_digest = sha256_text(str(action_row[0]))[:32]
            for prefix in ("WAITING", "NOTIFY"):
                notification = outbox.outbox / f"{prefix}-{action_digest}.json"
                if notification.exists():
                    outbox.retire_request(notification)
        if governor.retire_after_release_failure(
            epoch_id=epoch_id,
            source_commit=source_commit,
            candidate_digest=candidate_digest,
            release_status=release_status,
            release_snapshot_digest=sha256_text(stable_json(proof)),
        ):
            retired += 1
    return retired


def _install_epoch_file(path: Path, value: str) -> None:
    encoded = value + "\n"
    if path.exists():
        if path.is_symlink():
            raise FunctionalControlError("credential epoch path is unsafe")
        if path.read_text(encoding="ascii") == encoded:
            return
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _archive_stale_index(path: Path) -> None:
    if not path.exists():
        return
    if not path.is_file() or path.is_symlink():
        raise FunctionalControlError("Q6.5 report index is unsafe")
    digest = sha256_file(path)
    archive = path.parent / "archive"
    archive.mkdir(parents=True, exist_ok=True)
    destination = archive / f"{path.stem}-{digest}{path.suffix}"
    if destination.exists():
        if destination.is_symlink() or sha256_file(destination) != digest:
            raise FunctionalControlError("Q6.5 report index archive conflicts")
        path.unlink()
        return
    path.replace(destination)


def _notify_waiting(
    root: Path, *, epoch_id: str, action_id: str, text: str
) -> None:
    outbox = NotificationOutbox(
        root / "notifications",
        attachment_roots=(root, Path("/var/lib/hermes-factory-verifier")),
    )
    outbox.enqueue(
        NotificationRequest(
            request_id="WAITING-" + sha256_text(action_id)[:32],
            kind="CAPABILITY_WAITING",
            text=f"Hermes is waiting for one external capability; action {action_id}.",
        )
    )
    outbox.enqueue(
        NotificationRequest(
            request_id="NOTIFY-" + sha256_text(action_id)[:32],
            kind="OWNER_ACTION_REQUIRED",
            text=f"{text} Automatic resume is armed; action {action_id}, epoch {epoch_id}.",
        )
    )


def _notify(root: Path, *, kind: str, identity: str, text: str) -> None:
    NotificationOutbox(
        root / "notifications",
        attachment_roots=(root, Path("/var/lib/hermes-factory-verifier")),
    ).enqueue(
        NotificationRequest(
            request_id="EVENT-" + sha256_text(stable_json([kind, identity]))[:32],
            kind=kind,
            text=text,
        )
    )


def _write_identity_evidence(
    root: Path, label: str, body: Mapping[str, Any]
) -> tuple[Path, str, str]:
    """Write a deterministic body with a non-identity observation envelope."""

    normalized = {str(key): item for key, item in body.items()}
    digest = sha256_text(stable_json(normalized))
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{label}-{digest}.json"
    if path.exists():
        if path.is_symlink():
            raise FunctionalControlError("immutable PRE-Q8 evidence path is unsafe")
        existing = _mapping(
            json.loads(path.read_text(encoding="utf-8")), "PRE-Q8 evidence"
        )
        observed_at = str(existing.pop("observed_at", ""))
        existing_digest = str(existing.pop("evidence_digest", ""))
        if existing != normalized or existing_digest != digest or not observed_at:
            raise FunctionalControlError("immutable PRE-Q8 evidence conflicts")
        return path, digest, observed_at
    observed_at = utc_now()
    envelope = {**normalized, "evidence_digest": digest, "observed_at": observed_at}
    encoded = json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path, digest, observed_at


def _pre_q8_index(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise FunctionalControlError("root-owned PRE-Q8 index is unavailable")
    value = _mapping(json.loads(path.read_text(encoding="utf-8")), "PRE-Q8 index")
    index_digest = str(value.pop("index_digest", ""))
    if index_digest != sha256_text(stable_json(value)):
        raise FunctionalControlError("PRE-Q8 index digest differs")
    scenarios = value.get("scenarios")
    if not isinstance(scenarios, list):
        raise FunctionalControlError("PRE-Q8 index scenarios are invalid")
    ordered = tuple(
        str(_mapping(item, "PRE-Q8 scenario entry").get("scenario_id", ""))
        for item in scenarios
    )
    if ordered != PRE_Q8_SCENARIOS:
        raise FunctionalControlError("PRE-Q8 index order differs from canonical order")
    return {**value, "index_digest": index_digest}


def _scenario_entry(index: Mapping[str, Any], scenario_id: str) -> dict[str, Any]:
    scenarios = index.get("scenarios")
    if not isinstance(scenarios, list):
        raise FunctionalControlError("PRE-Q8 index scenarios are invalid")
    matches = [
        _mapping(item, "PRE-Q8 scenario entry")
        for item in scenarios
        if isinstance(item, Mapping) and str(item.get("scenario_id")) == scenario_id
    ]
    if len(matches) != 1:
        raise FunctionalControlError("PRE-Q8 scenario index identity is ambiguous")
    return matches[0]


def admit_pre_q8(
    config_path: Path,
    *,
    state_root: Path,
    seal_path: Path,
    index_path: Path,
) -> dict[str, Any]:
    control = _load_config(config_path)
    epoch_id = _release_epoch(control)
    index = _pre_q8_index(index_path)
    required = {
        "schema_version",
        "qualification_plane",
        "run_id",
        "epoch_id",
        "source_commit",
        "candidate_digest",
        "controller_release_digest",
        "git_tree",
        "release_tree_digest",
        "requirements_lock_digest",
        "toolchain_digest",
        "systemd_bundle_digest",
        "catalog_digest",
        "base_config_digest",
        "capability_attestation_digest",
        "fixture_seed_digest",
        "matrix_digest",
        "scenarios",
        "index_digest",
    }
    if set(index) != required or index.get("schema_version") != "2.0":
        raise FunctionalControlError("PRE-Q8 admission index schema differs")
    if (
        index.get("qualification_plane") != "PRE_Q8"
        or index.get("epoch_id") != epoch_id
        or index.get("source_commit") != control["source_commit"]
        or index.get("candidate_digest") != control["candidate_digest"]
        or index.get("controller_release_digest")
        != control["controller_release_digest"]
        or index.get("toolchain_digest") != control["toolchain_manifest_digest"]
        or index.get("release_tree_digest") != control["candidate_digest"]
    ):
        raise FunctionalControlError("PRE-Q8 admission index identity differs")
    generated: dict[str, str] = {}
    for scenario_id in PRE_Q8_SCENARIOS:
        entry = _scenario_entry(index, scenario_id)
        config = Path(str(entry.get("config_path", "")))
        if not config.is_file() or config.is_symlink():
            raise FunctionalControlError("PRE-Q8 generated config is unavailable")
        payload = yaml.safe_load(config.read_text(encoding="utf-8"))
        if not isinstance(payload, Mapping):
            raise FunctionalControlError("PRE-Q8 generated config is invalid")
        qualification = payload.get("qualification")
        if not isinstance(qualification, Mapping) or (
            qualification.get("qualification_plane"),
            qualification.get("run_id"),
            qualification.get("epoch_id"),
            qualification.get("scenario_id"),
        ) != (
            "PRE_Q8",
            index["run_id"],
            epoch_id,
            scenario_id,
        ):
            raise FunctionalControlError("PRE-Q8 generated config namespace differs")
        attestation_path = Path(str(qualification.get("capability_attestation_path") or ""))
        if (
            qualification.get("capability_attestation_digest")
            != index["capability_attestation_digest"]
            or not attestation_path.is_file()
            or attestation_path.is_symlink()
            or sha256_file(attestation_path) != index["capability_attestation_digest"]
        ):
            raise FunctionalControlError("PRE-Q8 capability attestation differs")
        digest = sha256_text(stable_json(dict(payload)))
        if digest != entry.get("config_digest"):
            raise FunctionalControlError("PRE-Q8 generated config digest differs")
        seal_digest = qualification_config_semantic_digest(payload)
        if seal_digest != entry.get("seal_config_digest"):
            raise FunctionalControlError("PRE-Q8 semantic config digest differs")
        generated[scenario_id] = seal_digest
    expected_identity = {
        key: index[key]
        for key in (
            "git_tree",
            "release_tree_digest",
            "requirements_lock_digest",
            "toolchain_digest",
            "systemd_bundle_digest",
            "catalog_digest",
            "base_config_digest",
            "capability_attestation_digest",
            "fixture_seed_digest",
            "matrix_digest",
        )
    }
    try:
        seal, seal_digest = load_and_verify_seal(
            seal_path,
            verifier_public_key=str(control["verifier_public_key"]),
            trusted_public_key_digest=str(control["trusted_verifier_public_key_digest"]),
            expected_identity=expected_identity,
            expected_generated_config_digests=generated,
        )
    except PreQ8SealError as error:
        raise FunctionalControlError("PRE-Q8 convergence seal rejected") from error
    git_tree_result = subprocess.run(
        [
            "git",
            "-C",
            str(control["candidate_repository_root"]),
            "rev-parse",
            "HEAD^{tree}",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if (
        seal.get("run_id") != index["run_id"]
        or git_tree_result.returncode != 0
        or git_tree_result.stdout.strip() != index["git_tree"]
    ):
        raise FunctionalControlError("PRE-Q8 convergence seal release differs")
    governor = _governor(state_root / "functional.db")
    try:
        governor.admit_pre_q8(
            epoch_id=epoch_id,
            run_id=str(seal["run_id"]),
            seal_digest=seal_digest,
            git_tree=str(seal["git_tree"]),
            release_tree_digest=str(seal["release_tree_digest"]),
            candidate_digest=str(control["candidate_digest"]),
        )
        return {
            "status": governor.epoch(epoch_id)["status"],
            "epoch_id": epoch_id,
            "run_id": seal["run_id"],
            "seal_digest": seal_digest,
        }
    finally:
        governor.connection.close()


def _missing_report(config: Mapping[str, Any]) -> CapabilityHandshakeReport:
    return CapabilityHandshakeReport.create(
        candidate_digest=str(config["candidate_digest"]),
        capability="github.identity.read",
        operation="github.identity.read",
        scope={"owner": str(config["factory_repository"]).split("/", 1)[0]},
        status=CapabilityStatus.MISSING_EXTERNAL,
        credential_epoch_id=None,
        toolchain_digest=str(config["toolchain_manifest_digest"]),
        safe_reason_code="missing_candidate_github_credential",
    )


def _external_failure_report(
    path: Path,
    *,
    config: Mapping[str, Any],
    credential_epoch: str,
) -> CapabilityHandshakeReport | None:
    if not path.exists():
        return None
    if not path.is_file() or path.is_symlink():
        raise FunctionalControlError("Q6.5 failure index is unsafe")
    failure = _mapping(json.loads(path.read_text(encoding="utf-8")), "Q6.5 failure index")
    receipt_digest = str(failure.pop("receipt_digest", ""))
    if receipt_digest != sha256_text(stable_json(failure)):
        raise FunctionalControlError("Q6.5 failure index digest differs")
    expected = {
        "schema_version",
        "candidate_digest",
        "toolchain_digest",
        "credential_epoch_id",
        "capability",
        "operation",
        "scope",
        "safe_reason_code",
        "observed_at",
    }
    if set(failure) != expected or failure.get("schema_version") != "1.0":
        raise FunctionalControlError("Q6.5 failure index schema differs")
    if (
        failure.get("candidate_digest") != config["candidate_digest"]
        or failure.get("toolchain_digest") != config["toolchain_manifest_digest"]
        or failure.get("credential_epoch_id") != credential_epoch
    ):
        raise FunctionalControlError("Q6.5 failure index identity differs")
    operation = str(failure["operation"])
    github_operations = set(MANDATORY_Q6_5_OPERATIONS[:8])
    provider_aliases = {
        "provider.luna.invoke": "economy",
        "provider.terra.invoke": "standard",
        "provider.sol.invoke": "expert",
    }
    reason_code = str(failure.get("safe_reason_code", ""))
    if failure.get("capability") != operation:
        raise FunctionalControlError("Q6.5 external failure classification differs")
    github_reason_codes = {
        "candidate_github_operation_denied",
        "candidate_github_workflow_permission_denied",
    }
    if operation in github_operations and reason_code in github_reason_codes:
        if (
            reason_code == "candidate_github_workflow_permission_denied"
            and operation != "git.branch.push"
        ):
            raise FunctionalControlError("Q6.5 workflow permission classification differs")
        owner = str(config["factory_repository"]).split("/", 1)[0]
        expected_scope = {
            "owner": owner,
            "repository": f"hermes-canary-q65-{str(config['candidate_digest'])[:10]}",
            "private": True,
        }
    elif (
        operation in provider_aliases
        and reason_code == "missing_candidate_provider_credential"
    ):
        expected_scope = _mapping(failure.get("scope"), "Q6.5 provider failure scope")
        if (
            set(expected_scope)
            != {
                "alias",
                "provider",
                "model",
                "credential_provider",
                "semantic_id",
                "stdout_contract",
            }
            or expected_scope.get("alias") != provider_aliases[operation]
            or expected_scope.get("stdout_contract") != "json-only"
            or not re.fullmatch(r"[A-Za-z0-9._-]+", str(expected_scope.get("provider", "")))
            or not re.fullmatch(
                r"[A-Za-z0-9._-]+", str(expected_scope.get("credential_provider", ""))
            )
            or not re.fullmatch(r"[A-Za-z0-9._-]+", str(expected_scope.get("model", "")))
            or not re.fullmatch(r"[a-f0-9]{64}", str(expected_scope.get("semantic_id", "")))
        ):
            raise FunctionalControlError("Q6.5 provider failure scope differs")
    else:
        raise FunctionalControlError("Q6.5 external failure operation is not allowlisted")
    if failure.get("scope") != expected_scope or not str(failure["observed_at"]):
        raise FunctionalControlError("Q6.5 external failure scope differs")
    return CapabilityHandshakeReport.create(
        candidate_digest=str(config["candidate_digest"]),
        capability=operation,
        operation=operation,
        scope=expected_scope,
        status=CapabilityStatus.MISSING_EXTERNAL,
        credential_epoch_id=credential_epoch,
        toolchain_digest=str(config["toolchain_manifest_digest"]),
        safe_reason_code=reason_code,
    )


def reconcile(
    config_path: Path,
    *,
    state_root: Path,
    credential_source: Path,
    telegram_credential_source: Path,
    report_index: Path,
    failure_index: Path,
) -> dict[str, Any]:
    config = _load_config(config_path)
    epoch_id, release_snapshot = _release_snapshot(config)
    governor = _governor(state_root / "functional.db")
    try:
        _retire_superseded_functional_epochs(
            governor,
            current_epoch_id=epoch_id,
            release_snapshot=release_snapshot,
            state_root=state_root,
        )
        governor.register_epoch(
            epoch_id=epoch_id,
            source_commit=str(config["source_commit"]),
            candidate_digest=str(config["candidate_digest"]),
            toolchain_digest=str(config["toolchain_manifest_digest"]),
        )
        credential_epoch = _credential_epoch(credential_source, label="GitHub")
        epoch = governor.epoch(epoch_id)
        if credential_epoch is None:
            governor.record_handshake(epoch_id, _missing_report(config))
            action_id = governor.ensure_owner_action(
                epoch_id=epoch_id,
                reason_code="missing_candidate_github_credential",
                capability="github.identity.read",
                capability_epoch=None,
            )
            _notify_waiting(
                state_root,
                epoch_id=epoch_id,
                action_id=action_id,
                text=(
                    "Install one separate Candidate-scoped GitHub credential in the protected "
                    "Candidate credential slot. Do not send the credential in Telegram."
                ),
            )
            return {
                "status": "WAITING_CAPABILITY",
                "reason_code": "missing_candidate_github_credential",
                "action_ref": f"state://functional-owner-actions/{action_id}",
                "automatic_resume": True,
                "epoch_id": epoch_id,
            }
        epoch_path = state_root / "credential-epoch"
        previous_epoch: str | None = None
        if epoch_path.exists():
            if not epoch_path.is_file() or epoch_path.is_symlink():
                raise FunctionalControlError("credential epoch path is unsafe")
            previous_epoch = epoch_path.read_text(encoding="ascii").strip()
            if not _CREDENTIAL_EPOCH.fullmatch(previous_epoch):
                raise FunctionalControlError("credential epoch identity is invalid")
        _install_epoch_file(epoch_path, credential_epoch)
        if previous_epoch != credential_epoch:
            governor.capability_epoch_changed(
                epoch_id=epoch_id,
                old_epoch=previous_epoch,
                new_epoch=credential_epoch,
            )
            _archive_stale_index(report_index)
            _archive_stale_index(failure_index)
            _notify(
                state_root,
                kind="CAPABILITY_READY",
                identity=credential_epoch,
                text="Candidate GitHub capability changed; automatic Q6.5 resume started.",
            )
            epoch = governor.epoch(epoch_id)
        if str(epoch.get("q6_5_status")) != "PASS":
            if report_index.exists() and (not report_index.is_file() or report_index.is_symlink()):
                raise FunctionalControlError("Q6.5 report index is unsafe")
            if report_index.exists() and failure_index.exists():
                raise FunctionalControlError("Q6.5 success and failure indexes conflict")
            if not report_index.exists():
                external_failure = _external_failure_report(
                    failure_index,
                    config=config,
                    credential_epoch=credential_epoch,
                )
                if external_failure is not None:
                    governor.record_handshake(epoch_id, external_failure)
                    reason_code = str(external_failure.safe_reason_code or "")
                    action_id = governor.ensure_owner_action(
                        epoch_id=epoch_id,
                        reason_code=reason_code,
                        capability=external_failure.capability,
                        capability_epoch=(
                            None
                            if reason_code == "missing_candidate_provider_credential"
                            else credential_epoch
                        ),
                    )
                    if reason_code == "missing_candidate_provider_credential":
                        notification_text = (
                            "Authenticate the isolated Candidate provider "
                            f"{external_failure.scope['credential_provider']} through its secure "
                            "OAuth device flow. Do not send credentials or device codes in Telegram."
                        )
                    elif reason_code == "candidate_github_workflow_permission_denied":
                        notification_text = (
                            "Candidate GitHub authentication reached the scoped Q6.5 handshake, "
                            "but GitHub denied the required workflow-file write. Replace the "
                            "protected Candidate classic personal access token with one authorized "
                            "for private repository operations and workflow-file writes (repo and "
                            "workflow scopes). Do not send the credential in Telegram."
                        )
                    else:
                        notification_text = (
                            "Candidate GitHub authentication reached the scoped Q6.5 handshake, "
                            f"but the required private canary operation "
                            f"{external_failure.operation} was denied. Replace "
                            "the protected Candidate credential with one authorized to create, "
                            "read, update, merge/close, and delete/archive private scoped canary "
                            f"repositories for {external_failure.scope['owner']}. Do not send the "
                            "credential in Telegram."
                        )
                    _notify_waiting(
                        state_root,
                        epoch_id=epoch_id,
                        action_id=action_id,
                        text=notification_text,
                    )
                    return {
                        "status": "WAITING_CAPABILITY",
                        "reason_code": reason_code,
                        "operation": external_failure.operation,
                        "action_ref": f"state://functional-owner-actions/{action_id}",
                        "automatic_resume": True,
                        "epoch_id": epoch_id,
                    }
                return {
                    "status": "Q6_5_PROBE_REQUIRED",
                    "epoch_id": epoch_id,
                    "credential_epoch_id": credential_epoch,
                }
            index = _mapping(json.loads(report_index.read_text(encoding="utf-8")), "Q6.5 index")
            receipt_digest = index.pop("receipt_digest", None)
            if receipt_digest is not None:
                receipt_payload = dict(index)
                if receipt_digest != sha256_text(stable_json(receipt_payload)):
                    raise FunctionalControlError("Q6.5 receipt envelope digest differs")
            index_digest = str(index.pop("index_digest", ""))
            if index_digest != sha256_text(stable_json(index)):
                raise FunctionalControlError("Q6.5 report index digest differs")
            if (
                index.get("candidate_digest") != config["candidate_digest"]
                or index.get("toolchain_digest") != config["toolchain_manifest_digest"]
                or index.get("credential_epoch_id") != credential_epoch
            ):
                raise FunctionalControlError("Q6.5 report index identity differs")
            raw_reports = index.get("reports")
            if not isinstance(raw_reports, list):
                raise FunctionalControlError("Q6.5 report index is invalid")
            reports = tuple(
                CapabilityHandshakeReport.from_dict(_mapping(value, "Q6.5 report"))
                for value in raw_reports
            )
            if {report.operation for report in reports} != set(MANDATORY_Q6_5_OPERATIONS):
                raise FunctionalControlError("Q6.5 report set is incomplete")
            if any(report.credential_epoch_id not in {None, credential_epoch} for report in reports):
                raise FunctionalControlError("Q6.5 report credential epoch differs")
            for report in reports:
                if report.status == CapabilityStatus.AVAILABLE:
                    governor.recover_external_capability(
                        epoch_id=epoch_id, capability=report.capability
                    )
                governor.record_handshake(epoch_id, report)
        current = governor.epoch(epoch_id)
        if str(current["status"]) == "PRE_Q8_PENDING":
            _notify(
                state_root,
                kind="PRE_Q8_STARTED",
                identity=epoch_id,
                text="Hermes PRE-Q8 started: ten isolated first-run scenarios, no skip.",
            )
        if str(current["status"]) == "GOLDEN_PRODUCT_PENDING":
            telegram_epoch = _credential_epoch(
                telegram_credential_source, label="Telegram"
            )
            if telegram_epoch is None:
                action_id = governor.ensure_owner_action(
                    epoch_id=epoch_id,
                    reason_code="missing_candidate_telegram_credential",
                    capability="telegram.owner_intake",
                    capability_epoch=None,
                )
                _notify_waiting(
                    state_root,
                    epoch_id=epoch_id,
                    action_id=action_id,
                    text=(
                        "Install one separate Candidate-scoped Telegram bot credential in the "
                        "protected Candidate credential slot, then send the pre-authorized Golden "
                        "Product idea to that bot. Do not send the credential in Telegram."
                    ),
                )
                return {
                    "status": "WAITING_CAPABILITY",
                    "reason_code": "missing_candidate_telegram_credential",
                    "action_ref": f"state://functional-owner-actions/{action_id}",
                    "automatic_resume": True,
                    "epoch_id": epoch_id,
                }
            governor.resolve_owner_action(
                epoch_id=epoch_id, capability="telegram.owner_intake"
            )
        return {"status": current["status"], "epoch_id": epoch_id}
    finally:
        governor.connection.close()


def status(config_path: Path, *, state_root: Path) -> dict[str, Any]:
    config = _load_config(config_path)
    epoch_id = _release_epoch(config)
    governor = _governor(state_root / "functional.db")
    try:
        epoch = governor.epoch(epoch_id)
        reports = governor.connection.execute(
            "SELECT operation,status,report_digest FROM capability_handshake_reports "
            "WHERE epoch_id=? ORDER BY operation",
            (epoch_id,),
        ).fetchall()
        actions = governor.connection.execute(
            "SELECT action_id,reason_code,status FROM functional_owner_actions "
            "WHERE epoch_id=? ORDER BY created_at",
            (epoch_id,),
        ).fetchall()
        pre_q8 = governor.connection.execute(
            "SELECT scenario_id,attempt,status,evidence_digest FROM pre_q8_scenarios "
            "WHERE epoch_id=? ORDER BY rowid",
            (epoch_id,),
        ).fetchall()
        failures = governor.connection.execute(
            "SELECT scenario_id,attempt,failure_class,evidence_digest,support_bundle_digest "
            "FROM pre_q8_failures WHERE epoch_id=? ORDER BY rowid",
            (epoch_id,),
        ).fetchall()
        runs = governor.connection.execute(
            "SELECT scenario_id,attempt,status,database_path,config_digest,product_id "
            "FROM pre_q8_runs WHERE epoch_id=? ORDER BY rowid",
            (epoch_id,),
        ).fetchall()
        admission = governor.connection.execute(
            "SELECT run_id,seal_digest,git_tree,release_tree_digest "
            "FROM pre_q8_admissions WHERE epoch_id=?",
            (epoch_id,),
        ).fetchone()
        return {
            "epoch": epoch,
            "capabilities": [
                {"operation": row[0], "status": row[1], "report_digest": row[2]}
                for row in reports
            ],
            "owner_actions": [
                {"action_id": row[0], "reason_code": row[1], "status": row[2]}
                for row in actions
            ],
            "pre_q8": [
                {
                    "scenario_id": row[0],
                    "attempt": row[1],
                    "status": row[2],
                    "evidence_digest": row[3],
                }
                for row in pre_q8
            ],
            "pre_q8_failures": [
                {
                    "scenario_id": row[0],
                    "attempt": row[1],
                    "failure_class": row[2],
                    "evidence_digest": row[3],
                    "support_bundle_digest": row[4],
                }
                for row in failures
            ],
            "pre_q8_runs": [
                {
                    "scenario_id": row[0],
                    "attempt": row[1],
                    "status": row[2],
                    "database_path": row[3],
                    "config_digest": row[4],
                    "product_id": row[5],
                }
                for row in runs
            ],
            "pre_q8_admission": (
                {
                    "run_id": admission[0],
                    "seal_digest": admission[1],
                    "git_tree": admission[2],
                    "release_tree_digest": admission[3],
                }
                if admission is not None
                else None
            ),
        }
    finally:
        governor.connection.close()


def start_pre_q8(
    config_path: Path,
    *,
    state_root: Path,
    index_path: Path,
    scenario_id: str,
    candidate_config: Path,
) -> dict[str, Any]:
    control = _load_config(config_path)
    epoch_id = _release_epoch(control)
    index = _pre_q8_index(index_path)
    entry = _scenario_entry(index, scenario_id)
    if candidate_config != Path(str(entry.get("config_path", ""))):
        raise FunctionalControlError("PRE-Q8 scenario config path differs from index")
    scenario_config = load_config(candidate_config)
    contract = CanaryFaultContract.from_config(scenario_config)
    if (
        contract.qualification_plane != "PRE_Q8"
        or contract.epoch_id != epoch_id
        or contract.run_id != index.get("run_id")
        or contract.scenario_id != scenario_id
    ):
        raise FunctionalControlError("PRE-Q8 scenario namespace differs")
    digest = sha256_text(stable_json(scenario_config.raw))
    if digest != entry.get("config_digest"):
        raise FunctionalControlError("PRE-Q8 scenario config digest differs")
    database = str(scenario_config.database_path)
    if database != str(entry.get("database_path", "")):
        raise FunctionalControlError("PRE-Q8 scenario database differs from index")
    governor = _governor(state_root / "functional.db")
    try:
        created = governor.start_pre_q8_scenario(
            epoch_id=epoch_id,
            scenario_id=scenario_id,
            attempt=1,
            database_path=database,
            config_digest=digest,
        )
        current = governor.pre_q8_run(epoch_id=epoch_id, scenario_id=scenario_id)
        if current is None:
            raise FunctionalControlError("PRE-Q8 run disappeared after durable start")
        return {
            "status": "RUNNING" if created else str(current["status"]),
            "epoch_id": epoch_id,
            "scenario_id": scenario_id,
            "attempt": 1,
        }
    finally:
        governor.connection.close()


def record_pre_q8_progress(
    config_path: Path,
    *,
    state_root: Path,
    scenario_id: str,
    snapshot_path: Path,
) -> dict[str, Any]:
    control = _load_config(config_path)
    epoch_id = _release_epoch(control)
    if not snapshot_path.is_file() or snapshot_path.is_symlink():
        raise FunctionalControlError("PRE-Q8 progress snapshot is unavailable")
    value = _mapping(
        json.loads(snapshot_path.read_text(encoding="utf-8")), "PRE-Q8 progress snapshot"
    )
    fingerprint = str(value.pop("progress_fingerprint", ""))
    if fingerprint != sha256_text(stable_json(value)):
        raise FunctionalControlError("PRE-Q8 progress fingerprint differs")
    governor = _governor(state_root / "functional.db")
    try:
        changed = governor.record_pre_q8_progress(
            epoch_id=epoch_id,
            scenario_id=scenario_id,
            attempt=1,
            progress_fingerprint=fingerprint,
            snapshot=value,
        )
        progress = governor.connection.execute(
            "SELECT last_changed_at,checked_at FROM pre_q8_progress "
            "WHERE epoch_id=? AND scenario_id=?",
            (epoch_id, scenario_id),
        ).fetchone()
        if progress is None:
            raise FunctionalControlError("PRE-Q8 progress state disappeared")
        last_changed = datetime.fromisoformat(str(progress[0]))
        checked = datetime.fromisoformat(str(progress[1]))
        if last_changed.tzinfo is None or checked.tzinfo is None:
            raise FunctionalControlError("PRE-Q8 progress time is not UTC")
        seconds_without_progress = max(
            0, int((checked.astimezone(UTC) - last_changed.astimezone(UTC)).total_seconds())
        )
        return {
            "status": "CHANGED" if changed else "UNCHANGED",
            "epoch_id": epoch_id,
            "scenario_id": scenario_id,
            "progress_fingerprint": fingerprint,
            "seconds_without_progress": seconds_without_progress,
        }
    finally:
        governor.connection.close()


def record_pre_q8_failure(
    config_path: Path,
    *,
    state_root: Path,
    scenario_id: str,
    failure_class: str,
    candidate_config: Path,
    support_sources: tuple[Path, ...] = (),
) -> dict[str, Any]:
    """Create immutable evidence/bundle, then commit one terminal DB transaction."""

    control = _load_config(config_path)
    epoch_id = _release_epoch(control)
    scenario_config = load_config(candidate_config)
    contract = CanaryFaultContract.from_config(scenario_config)
    if (
        contract.scenario_id != scenario_id
        or contract.qualification_plane != "PRE_Q8"
        or contract.epoch_id != epoch_id
    ):
        raise FunctionalControlError("PRE-Q8 failure scenario config identity differs")
    governor = _governor(state_root / "functional.db")
    try:
        admission = governor.connection.execute(
            "SELECT run_id FROM pre_q8_admissions WHERE epoch_id=?", (epoch_id,)
        ).fetchone()
        run_id = str(admission[0]) if admission is not None else contract.run_id
        if admission is not None and run_id != contract.run_id:
            raise FunctionalControlError("PRE-Q8 failure admission run differs")
        source_digests: dict[str, str] = {}
        for source in support_sources:
            if not source.is_file() or source.is_symlink():
                raise FunctionalControlError("PRE-Q8 failure support source is unsafe")
            if source.name in source_digests:
                raise FunctionalControlError("PRE-Q8 support source name is duplicated")
            source_digests[source.name] = sha256_file(source)
        body = {
            "schema_version": "1.0",
            "evidence_type": "OFFICIAL_PRE_Q8_FAILURE",
            "epoch_id": epoch_id,
            "run_id": run_id,
            "scenario_id": scenario_id,
            "attempt": 1,
            "candidate_digest": str(control["candidate_digest"]),
            "failure_class": failure_class,
            "candidate_database_ref": str(scenario_config.database_path),
            "config_digest": sha256_text(stable_json(scenario_config.raw)),
            "support_source_digests": source_digests,
        }
        evidence_root = state_root / "pre-q8-evidence" / epoch_id / run_id / scenario_id
        evidence_path, evidence_digest, observed_at = _write_identity_evidence(
            evidence_root, "failure", body
        )
        bundle, bundle_digest = build_support_bundle(
            incident_id=f"preq8-{epoch_id}-{scenario_id}-attempt1",
            source_files=(evidence_path, *support_sources),
            allowed_roots=(
                state_root,
                Path("/var/lib/hermes-factory-pre-q8"),
                Path("/var/log/hermes-factory-pre-q8"),
            ),
            output_root=state_root / "support-bundles",
            metadata={
                "status": "QUALIFICATION_FAILED",
                "epoch_id": epoch_id,
                "run_id": run_id,
                "scenario_id": scenario_id,
                "attempt": 1,
                "failure_class": failure_class,
            },
            created_at=observed_at,
        )
        created = governor.record_pre_q8_failure(
            epoch_id=epoch_id,
            scenario_id=scenario_id,
            attempt=1,
            failure_class=failure_class,
            failure_digest=evidence_digest,
            evidence_ref=f"artifact://qualification/pre-q8/{epoch_id}/{run_id}/{scenario_id}/{evidence_digest}",
            evidence_digest=evidence_digest,
            candidate_database_ref=str(scenario_config.database_path),
            config_digest=str(body["config_digest"]),
            support_bundle_ref=str(bundle),
            support_bundle_digest=bundle_digest,
        )
        _notify(
            state_root,
            kind="PRE_Q8_FAILED",
            identity=f"{epoch_id}:{scenario_id}:{evidence_digest}",
            text=(
                f"Hermes official PRE-Q8 terminalized Candidate at {scenario_id}; "
                "a sanitized support bundle is available."
            ),
        )
        return {
            "status": "QUALIFICATION_FAILED",
            "created": created,
            "epoch_id": epoch_id,
            "scenario_id": scenario_id,
            "attempt": 1,
            "failure_class": failure_class,
            "evidence_digest": evidence_digest,
            "support_bundle": str(bundle),
            "support_bundle_digest": bundle_digest,
        }
    finally:
        governor.connection.close()


def reconcile_pre_q8(
    config_path: Path,
    *,
    state_root: Path,
    scenario_id: str,
    candidate_config: Path,
    support_sources: tuple[Path, ...] = (),
) -> dict[str, Any]:
    """Reconcile a crash without ever executing an official scenario twice."""

    control = _load_config(config_path)
    epoch_id = _release_epoch(control)
    scenario_config = load_config(candidate_config)
    contract = CanaryFaultContract.from_config(scenario_config)
    if (
        contract.scenario_id != scenario_id
        or contract.qualification_plane != "PRE_Q8"
        or contract.epoch_id != epoch_id
    ):
        raise FunctionalControlError("PRE-Q8 reconciliation config identity differs")
    governor = _governor(state_root / "functional.db")
    try:
        failure = governor.connection.execute(
            "SELECT failure_class,evidence_digest FROM pre_q8_failures "
            "WHERE epoch_id=? AND scenario_id=?",
            (epoch_id, scenario_id),
        ).fetchone()
        if failure is not None:
            return {
                "status": "FAIL",
                "scenario_id": scenario_id,
                "failure_class": failure[0],
                "evidence_digest": failure[1],
            }
        passed = governor.connection.execute(
            "SELECT evidence_digest FROM pre_q8_scenarios "
            "WHERE epoch_id=? AND scenario_id=?",
            (epoch_id, scenario_id),
        ).fetchone()
        if passed is not None:
            return {
                "status": "PASS",
                "scenario_id": scenario_id,
                "evidence_digest": passed[0],
            }
        run = governor.pre_q8_run(epoch_id=epoch_id, scenario_id=scenario_id)
    finally:
        governor.connection.close()
    database_exists = scenario_config.database_path.exists()
    decision = crash_reconciliation_decision(
        durable_run_status=str(run["status"]) if run is not None else None,
        database_exists=database_exists,
        product_completed=False,
    )
    if decision == CrashReconciliationDecision.MISSING:
        return {"status": "MISSING", "scenario_id": scenario_id}
    if decision == CrashReconciliationDecision.STALE_DATABASE:
        return record_pre_q8_failure(
            config_path,
            state_root=state_root,
            scenario_id=scenario_id,
            failure_class="STALE_DATABASE",
            candidate_config=candidate_config,
            support_sources=support_sources,
        )
    if scenario_config.database_path.is_file() and not scenario_config.database_path.is_symlink():
        connection = sqlite3.connect(
            f"file:{scenario_config.database_path.resolve().as_posix()}?mode=ro",
            uri=True,
        )
        try:
            connection.execute("PRAGMA query_only=ON")
            products = connection.execute(
                "SELECT product_id,status FROM products ORDER BY created_at"
            ).fetchall()
        finally:
            connection.close()
        if len(products) == 1 and str(products[0][1]) == "COMPLETED":
            decision = crash_reconciliation_decision(
                durable_run_status="RUNNING",
                database_exists=True,
                product_completed=True,
            )
        if decision == CrashReconciliationDecision.OBSERVE_COMPLETED:
            return record_pre_q8(
                config_path,
                state_root=state_root,
                scenario_id=scenario_id,
                product_id=str(products[0][0]),
                candidate_config=candidate_config,
            )
    return record_pre_q8_failure(
        config_path,
        state_root=state_root,
        scenario_id=scenario_id,
        failure_class="INTERRUPTED_OFFICIAL_RUN",
        candidate_config=candidate_config,
        support_sources=support_sources,
    )


def finalize_pre_q8(config_path: Path, *, state_root: Path) -> dict[str, Any]:
    control = _load_config(config_path)
    epoch_id = _release_epoch(control)
    governor = _governor(state_root / "functional.db")
    try:
        changed = governor.finalize_pre_q8(epoch_id)
        return {
            "status": governor.epoch(epoch_id)["status"],
            "epoch_id": epoch_id,
            "changed": changed,
        }
    finally:
        governor.connection.close()


def record_pre_q8(
    config_path: Path,
    *,
    state_root: Path,
    scenario_id: str,
    product_id: str,
    candidate_config: Path,
) -> dict[str, Any]:
    control = _load_config(config_path)
    epoch_id = _release_epoch(control)
    scenario_config = load_config(candidate_config)
    contract = CanaryFaultContract.from_config(scenario_config)
    if (
        contract.scenario_id != scenario_id
        or contract.epoch_id != epoch_id
        or contract.qualification_plane != "PRE_Q8"
    ):
        raise FunctionalControlError("PRE-Q8 scenario config identity differs")
    catalog = load_canary_catalog(Path(str(control["canary_catalog_path"])))
    scenario = catalog.get(scenario_id)
    if scenario is None:
        raise FunctionalControlError("PRE-Q8 scenario is outside catalog")
    observation = observe_completion(
        scenario_config.database_path,
        state_root
        / "pre-q8-evidence"
        / epoch_id
        / contract.run_id
        / scenario_id,
        product_id=product_id,
        expected_controller_release_digest=str(control["controller_release_digest"]),
        scenario=scenario,
        fault_receipt_root=contract.receipt_root,
        expected_candidate_digest=str(control["candidate_digest"]),
        fault_contract=contract,
    )
    if any(
        (
            observation.controller_incidents,
            observation.recovery_applications,
            observation.routine_owner_actions,
            observation.duplicate_side_effects,
            observation.unverified_side_effects,
        )
    ):
        raise FunctionalControlError("PRE-Q8 first-run intervention counters are non-zero")
    governor = _governor(state_root / "functional.db")
    try:
        governor.record_pre_q8_pass(
            epoch_id=epoch_id,
            scenario_id=scenario_id,
            attempt=1,
            product_id=product_id,
            completion_manifest_ref=observation.completion_manifest_ref,
            evidence_digest=observation.observation_digest,
        )
        completed = int(
            governor.connection.execute(
                "SELECT COUNT(*) FROM pre_q8_scenarios WHERE epoch_id=? AND status='PASS'",
                (epoch_id,),
            ).fetchone()[0]
        )
        _notify(
            state_root,
            kind="PRE_Q8_PROGRESS",
            identity=f"{epoch_id}:{scenario_id}",
            text=f"Hermes PRE-Q8 progress: {completed}/10; {scenario_id} PASS on first run.",
        )
        return {
            "status": governor.epoch(epoch_id)["status"],
            "scenario_id": scenario_id,
            "evidence_digest": observation.observation_digest,
        }
    finally:
        governor.connection.close()


def record_golden(
    config_path: Path,
    *,
    state_root: Path,
    evidence_path: Path,
) -> dict[str, Any]:
    control = _load_config(config_path)
    epoch_id = _release_epoch(control)
    if not evidence_path.is_file() or evidence_path.is_symlink():
        raise FunctionalControlError("Golden Product verifier evidence is unavailable")
    evidence = _mapping(json.loads(evidence_path.read_text(encoding="utf-8")), "Golden evidence")
    exact = {
        "schema_version",
        "status",
        "product_id",
        "repository_ref",
        "merge_commit",
        "artifact_digest",
        "completion_manifest_ref",
        "verifier_digest",
        "intake_source",
        "private_repository",
        "merged_pr",
        "isolated_delivery",
        "product_acceptance",
        "observation_minutes",
        "documentation_clean_install",
    }
    if set(evidence) != exact or evidence.get("status") != "COMPLETED":
        raise FunctionalControlError("Golden Product evidence schema is invalid")
    required = {
        "intake_source": "telegram_owner",
        "private_repository": True,
        "merged_pr": True,
        "isolated_delivery": True,
        "product_acceptance": "PASS",
        "documentation_clean_install": "PASS",
    }
    if any(evidence.get(key) != value for key, value in required.items()) or int(
        evidence["observation_minutes"]
    ) < 15:
        raise FunctionalControlError("Golden Product mandatory journey is incomplete")
    governor = _governor(state_root / "functional.db")
    try:
        governor.record_golden_product(
            epoch_id=epoch_id,
            product_id=str(evidence["product_id"]),
            repository_ref=str(evidence["repository_ref"]),
            merge_commit=str(evidence["merge_commit"]),
            artifact_digest=str(evidence["artifact_digest"]),
            completion_manifest_ref=str(evidence["completion_manifest_ref"]),
            verifier_digest=str(evidence["verifier_digest"]),
        )
        return {"status": governor.epoch(epoch_id)["status"], "epoch_id": epoch_id}
    finally:
        governor.connection.close()


def record_factory_checks(
    config_path: Path,
    *,
    state_root: Path,
    internal_verifier_pass: bool,
    stable_health_pass: bool,
    stable_intake_pass: bool,
) -> dict[str, Any]:
    control = _load_config(config_path)
    epoch_id = _release_epoch(control)
    governor = _governor(state_root / "functional.db")
    try:
        governor.record_factory_checks(
            epoch_id=epoch_id,
            internal_verifier_pass=internal_verifier_pass,
            stable_health_pass=stable_health_pass,
            stable_intake_pass=stable_intake_pass,
        )
        current = governor.epoch(epoch_id)
        if str(current["status"]) == "FUNCTIONALLY_READY":
            _notify(
                state_root,
                kind="FACTORY_FUNCTIONALLY_READY",
                identity=epoch_id,
                text=(
                    "Hermes factory is functionally ready: Q6.5 PASS, PRE-Q8 10/10, "
                    "Golden Product COMPLETED, Stable health/intake PASS."
                ),
            )
        return {"status": current["status"], "epoch_id": epoch_id}
    finally:
        governor.connection.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=Path("/etc/hermes-factory/qualification-control.yaml")
    )
    parser.add_argument(
        "--state-root", type=Path, default=Path("/var/lib/hermes-factory-functional")
    )
    parser.add_argument(
        "--credential-source",
        type=Path,
        default=Path("/etc/hermes-factory/candidate-credentials.d/github-token"),
    )
    parser.add_argument(
        "--report-index",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional/q6-5/report-index.json"),
    )
    parser.add_argument(
        "--failure-index",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional/q6-5/failure-index.json"),
    )
    parser.add_argument(
        "--telegram-credential-source",
        type=Path,
        default=Path(
            "/etc/hermes-factory/candidate-credentials.d/candidate-telegram-token"
        ),
    )
    parser.add_argument(
        "--pre-q8-index",
        type=Path,
        default=Path("/etc/hermes-factory/pre-q8/index.json"),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("reconcile")
    commands.add_parser("status")
    admission = commands.add_parser("pre-q8-admit")
    admission.add_argument("seal_path", type=Path)
    start = commands.add_parser("pre-q8-start")
    start.add_argument("scenario_id")
    start.add_argument("candidate_config", type=Path)
    progress = commands.add_parser("pre-q8-progress")
    progress.add_argument("scenario_id")
    progress.add_argument("snapshot_path", type=Path)
    pre_q8_pass = commands.add_parser("pre-q8-pass")
    pre_q8_pass.add_argument("scenario_id")
    pre_q8_pass.add_argument("product_id")
    pre_q8_pass.add_argument("candidate_config", type=Path)
    failure = commands.add_parser("pre-q8-fail")
    failure.add_argument("scenario_id")
    failure.add_argument("failure_class")
    failure.add_argument("candidate_config", type=Path)
    failure.add_argument("--support-source", action="append", type=Path, default=[])
    crash = commands.add_parser("pre-q8-reconcile")
    crash.add_argument("scenario_id")
    crash.add_argument("candidate_config", type=Path)
    crash.add_argument("--support-source", action="append", type=Path, default=[])
    commands.add_parser("pre-q8-finalize")
    golden = commands.add_parser("golden-complete")
    golden.add_argument("evidence_path", type=Path)
    checks = commands.add_parser("factory-checks")
    checks.add_argument("--internal-verifier-pass", action="store_true")
    checks.add_argument("--stable-health-pass", action="store_true")
    checks.add_argument("--stable-intake-pass", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "reconcile":
            result = reconcile(
                args.config,
                state_root=args.state_root,
                credential_source=args.credential_source,
                telegram_credential_source=args.telegram_credential_source,
                report_index=args.report_index,
                failure_index=args.failure_index,
            )
        elif args.command == "status":
            result = status(args.config, state_root=args.state_root)
        elif args.command == "pre-q8-admit":
            result = admit_pre_q8(
                args.config,
                state_root=args.state_root,
                seal_path=args.seal_path,
                index_path=args.pre_q8_index,
            )
        elif args.command == "pre-q8-start":
            result = start_pre_q8(
                args.config,
                state_root=args.state_root,
                index_path=args.pre_q8_index,
                scenario_id=args.scenario_id,
                candidate_config=args.candidate_config,
            )
        elif args.command == "pre-q8-progress":
            result = record_pre_q8_progress(
                args.config,
                state_root=args.state_root,
                scenario_id=args.scenario_id,
                snapshot_path=args.snapshot_path,
            )
        elif args.command == "pre-q8-pass":
            result = record_pre_q8(
                args.config,
                state_root=args.state_root,
                scenario_id=args.scenario_id,
                product_id=args.product_id,
                candidate_config=args.candidate_config,
            )
        elif args.command == "pre-q8-fail":
            result = record_pre_q8_failure(
                args.config,
                state_root=args.state_root,
                scenario_id=args.scenario_id,
                failure_class=args.failure_class,
                candidate_config=args.candidate_config,
                support_sources=tuple(args.support_source),
            )
        elif args.command == "pre-q8-reconcile":
            result = reconcile_pre_q8(
                args.config,
                state_root=args.state_root,
                scenario_id=args.scenario_id,
                candidate_config=args.candidate_config,
                support_sources=tuple(args.support_source),
            )
        elif args.command == "pre-q8-finalize":
            result = finalize_pre_q8(args.config, state_root=args.state_root)
        elif args.command == "golden-complete":
            result = record_golden(
                args.config,
                state_root=args.state_root,
                evidence_path=args.evidence_path,
            )
        else:
            result = record_factory_checks(
                args.config,
                state_root=args.state_root,
                internal_verifier_pass=args.internal_verifier_pass,
                stable_health_pass=args.stable_health_pass,
                stable_intake_pass=args.stable_intake_pass,
            )
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
        sqlite3.Error,
        FunctionalReadinessError,
        FunctionalControlError,
        PreQ8SealError,
        SupportBundleError,
    ) as error:
        print(stable_json({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    print(stable_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
