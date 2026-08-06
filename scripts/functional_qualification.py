#!/usr/bin/env python3
"""Durable functional-first reconciler for Q6.5, PRE-Q8, Golden, and Q7."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from factory.canary_faults import CanaryFaultContract
from factory.canary_qualification import load_canary_catalog, observe_completion
from factory.common import sha256_file, sha256_text, stable_json
from factory.config import load_config
from factory.functional_readiness import (
    MANDATORY_Q6_5_OPERATIONS,
    CapabilityHandshakeReport,
    CapabilityStatus,
    FunctionalQualificationGovernor,
    FunctionalReadinessError,
)
from factory.notifications import NotificationOutbox, NotificationRequest


class FunctionalControlError(RuntimeError):
    """The autonomous functional control plane cannot safely advance."""


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


def _release_epoch(config: Mapping[str, Any]) -> str:
    database = Path(str(config["governor_database"]))
    connection = sqlite3.connect(f"file:{database.resolve().as_posix()}?mode=ro", uri=True)
    try:
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
    return matches[0]


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
    destination = archive / f"report-index-{digest}.json"
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


def reconcile(
    config_path: Path,
    *,
    state_root: Path,
    credential_source: Path,
    telegram_credential_source: Path,
    report_index: Path,
) -> dict[str, Any]:
    config = _load_config(config_path)
    epoch_id = _release_epoch(config)
    governor = _governor(state_root / "functional.db")
    try:
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
        previous = governor.connection.execute(
            "SELECT credential_epoch_id FROM capability_handshake_reports "
            "WHERE epoch_id=? AND operation='github.identity.read'",
            (epoch_id,),
        ).fetchone()
        previous_epoch = str(previous[0]) if previous and previous[0] else None
        epoch_path = state_root / "credential-epoch"
        _install_epoch_file(epoch_path, credential_epoch)
        if previous is not None and previous_epoch != credential_epoch:
            governor.capability_epoch_changed(
                epoch_id=epoch_id,
                old_epoch=previous_epoch,
                new_epoch=credential_epoch,
            )
            _archive_stale_index(report_index)
            _notify(
                state_root,
                kind="CAPABILITY_READY",
                identity=credential_epoch,
                text="Candidate GitHub capability changed; automatic Q6.5 resume started.",
            )
        if str(epoch.get("q6_5_status")) != "PASS":
            if not report_index.is_file() or report_index.is_symlink():
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
            "SELECT scenario_id,status,evidence_digest FROM pre_q8_scenarios "
            "WHERE epoch_id=? ORDER BY scenario_id",
            (epoch_id,),
        ).fetchall()
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
                {"scenario_id": row[0], "status": row[1], "evidence_digest": row[2]}
                for row in pre_q8
            ],
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
    if contract.scenario_id != scenario_id:
        raise FunctionalControlError("PRE-Q8 scenario config identity differs")
    catalog = load_canary_catalog(Path(str(control["canary_catalog_path"])))
    scenario = catalog.get(scenario_id)
    if scenario is None:
        raise FunctionalControlError("PRE-Q8 scenario is outside catalog")
    observation = observe_completion(
        scenario_config.database_path,
        state_root / "pre-q8-evidence" / scenario_id,
        product_id=product_id,
        expected_controller_release_digest=str(control["controller_release_digest"]),
        scenario=scenario,
        fault_receipt_root=contract.receipt_root,
        expected_candidate_digest=str(control["candidate_digest"]),
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
        "--telegram-credential-source",
        type=Path,
        default=Path(
            "/etc/hermes-factory/candidate-credentials.d/candidate-telegram-token"
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("reconcile")
    commands.add_parser("status")
    pre_q8 = commands.add_parser("pre-q8-pass")
    pre_q8.add_argument("scenario_id")
    pre_q8.add_argument("product_id")
    pre_q8.add_argument("candidate_config", type=Path)
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
            )
        elif args.command == "status":
            result = status(args.config, state_root=args.state_root)
        elif args.command == "pre-q8-pass":
            result = record_pre_q8(
                args.config,
                state_root=args.state_root,
                scenario_id=args.scenario_id,
                product_id=args.product_id,
                candidate_config=args.candidate_config,
            )
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
    ) as error:
        print(stable_json({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    print(stable_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
