#!/usr/bin/env python3
"""Build, sign, independently verify, and dispatch functional ready results."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from factory.common import sha256_file, sha256_text, stable_json
from factory.functional_readiness import (
    CapabilityHandshakeReport,
    CapabilityStatus,
    FunctionalQualificationGovernor,
    FunctionalReadinessError,
    ReadyResultManifest,
    verify_ready_result_manifest,
)
from factory.notifications import NotificationOutbox, NotificationRequest
from factory.release_qualification import QUALIFICATION_STAGES, REQUIRED_CANARY_SCENARIOS
from scripts.qualification_control import authorize_shadow
from scripts.release_qualify import _load_private_key


class ReadyControlError(RuntimeError):
    """A functional ready result is incomplete or not independently bound."""


def _config(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReadyControlError("qualification config is invalid")
    return {str(key): item for key, item in value.items()}


def _write_once(path: Path, value: dict[str, Any], *, mode: int = 0o440) -> None:
    encoded = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_text(encoding="utf-8") != encoded:
            raise ReadyControlError("immutable ready result conflicts")
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())


def _epoch(connection: sqlite3.Connection, config: dict[str, Any]) -> sqlite3.Row:
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        "SELECT * FROM functional_epochs WHERE source_commit=? AND candidate_digest=?",
        (str(config["source_commit"]), str(config["candidate_digest"])),
    ).fetchall()
    if len(rows) != 1:
        raise ReadyControlError("functional ready epoch is ambiguous")
    row: sqlite3.Row = rows[0]
    return row


def build_request(config: dict[str, Any], *, state_root: Path, output: Path) -> dict[str, Any]:
    functional = sqlite3.connect(state_root / "functional.db")
    functional.row_factory = sqlite3.Row
    qualification = sqlite3.connect(Path(str(config["governor_database"])))
    qualification.row_factory = sqlite3.Row
    try:
        epoch = _epoch(functional, config)
        if str(epoch["status"]) != "FUNCTIONALLY_READY":
            raise ReadyControlError("factory is not functionally ready")
        release = qualification.execute(
            "SELECT epoch_id FROM controller_release_epochs "
            "WHERE source_commit=? AND candidate_digest=?",
            (str(config["source_commit"]), str(config["candidate_digest"])),
        ).fetchall()
        if len(release) != 1:
            raise ReadyControlError("release epoch binding is ambiguous")
        q0_q6 = qualification.execute(
            "SELECT stage,status,evidence_ref FROM qualification_runs "
            "WHERE epoch_id=? ORDER BY created_at",
            (str(release[0][0]),),
        ).fetchall()
        if len(q0_q6) != 7 or any(str(row[1]) != "PASS" for row in q0_q6):
            raise ReadyControlError("Q0-Q6 exact PASS evidence is incomplete")
        capabilities = functional.execute(
            "SELECT operation,status,report_digest FROM capability_handshake_reports "
            "WHERE epoch_id=? ORDER BY operation",
            (str(epoch["epoch_id"]),),
        ).fetchall()
        runtime_capability = functional.execute(
            "SELECT capability,status,report_digest FROM runtime_capability_reports "
            "WHERE epoch_id=?",
            (str(epoch["epoch_id"]),),
        ).fetchall()
        pre_q8 = functional.execute(
            "SELECT scenario_id,status,evidence_digest FROM pre_q8_scenarios "
            "WHERE epoch_id=? ORDER BY scenario_id",
            (str(epoch["epoch_id"]),),
        ).fetchall()
        golden = functional.execute(
            "SELECT * FROM golden_products WHERE epoch_id=?", (str(epoch["epoch_id"]),)
        ).fetchone()
        if len(capabilities) != 18 or any(str(row[1]) != "AVAILABLE" for row in capabilities):
            raise ReadyControlError("Q6.5 exact PASS evidence is incomplete")
        if (
            len(runtime_capability) != 2
            or {str(row[0]) for row in runtime_capability}
            != {"github.product.runtime", "provider.stable.runtime"}
            or any(str(row[1]) != "AVAILABLE" for row in runtime_capability)
            or str(epoch["product_github_status"]) != "PASS"
            or str(epoch["stable_provider_status"]) != "PASS"
        ):
            raise ReadyControlError("permanent runtime capability proof is incomplete")
        if len(pre_q8) != 10 or any(str(row[1]) != "PASS" for row in pre_q8):
            raise ReadyControlError("PRE-Q8 exact 10/10 evidence is incomplete")
        if golden is None or str(golden["status"]) != "COMPLETED":
            raise ReadyControlError("Golden Product completion evidence is missing")
        obligations = [
            {
                "obligation_id": f"qualification.{row[0]}",
                "status": "PASS",
                "evidence_ref": str(row[2]),
            }
            for row in q0_q6
        ]
        obligations.extend(
            {
                "obligation_id": f"q6_5.{row[0]}",
                "status": "PASS",
                "evidence_ref": f"sha256:{row[2]}",
            }
            for row in capabilities
        )
        obligations.extend(
            {
                "obligation_id": f"runtime.{row[0]}",
                "status": "PASS",
                "evidence_ref": f"sha256:{row[2]}",
            }
            for row in runtime_capability
        )
        obligations.extend(
            {
                "obligation_id": f"pre_q8.{row[0]}",
                "status": "PASS",
                "evidence_ref": f"sha256:{row[2]}",
            }
            for row in pre_q8
        )
        obligations.append(
            {
                "obligation_id": "golden_product.completed",
                "status": "PASS",
                "evidence_ref": str(golden["completion_manifest_ref"]),
            }
        )
        evidence_refs = tuple(str(item["evidence_ref"]) for item in obligations)
        version = (
            (Path(str(config["candidate_repository_root"])) / "VERSION")
            .read_text(encoding="utf-8")
            .strip()
        )
        request = {
            "schema_version": "1.0",
            "manifest_type": "FACTORY_FUNCTIONALLY_READY",
            "status": "PASS",
            "subject": {
                "epoch_id": str(epoch["epoch_id"]),
                "q6_5": "PASS",
                "pre_q8": "10/10 PASS",
                "golden_product": "COMPLETED",
            },
            "release_identity": {
                "version": version,
                "commit": str(config["source_commit"]),
                "digest": str(config["candidate_digest"]),
            },
            "mandatory_obligations": obligations,
            "evidence_refs": list(evidence_refs),
            "open_blockers": [],
            "verifier": {"digest": str(config["verifier_digest"])},
        }
        _write_once(output, request)
        return request
    finally:
        functional.close()
        qualification.close()


def _systemd_pass(arguments: list[str]) -> bool:
    return (
        subprocess.run(
            ["systemctl", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        ).returncode
        == 0
    )


def _runtime_ready_proof(
    *,
    state_root: Path,
    output: Path,
    expected_observation_digest: str,
    expected_candidate_digest: str,
    production_observation_path: Path,
    improvement_root: Path = Path("/var/lib/hermes-factory-improvement-lab"),
) -> tuple[str, dict[str, Any]]:
    active_units = (
        "hermes-factory-controller.service",
        "hermes-factory-gateway.service",
        "hermes-factory-worker.service",
        "hermes-factory-worker-2.service",
        "hermes-factory-product-github-broker.service",
        "hermes-factory-owner-notifier.path",
        "hermes-factory-functional-qualification.timer",
        "hermes-factory-recursive-improvement.timer",
        "hermes-factory-support-bundle-reconciler.timer",
        "hermes-factory-backup.timer",
        "hermes-factory-backup-offsite.timer",
    )
    active = {unit: _systemd_pass(["is-active", "--quiet", unit]) for unit in active_units}
    enabled = {unit: _systemd_pass(["is-enabled", "--quiet", unit]) for unit in active_units}
    support_unit = Path("/etc/systemd/system/hermes-factory-support-bundle@.service")
    support_metadata = support_unit.stat()
    support_loaded = (
        support_unit.is_file()
        and not support_unit.is_symlink()
        and support_metadata.st_uid == 0
        and support_metadata.st_mode & 0o022 == 0
    )
    if not all(active.values()) or not all(enabled.values()) or not support_loaded:
        raise ReadyControlError("autonomous runtime services are incomplete")

    if not production_observation_path.is_file() or production_observation_path.is_symlink():
        raise ReadyControlError("production observation proof is unavailable")
    observation = json.loads(production_observation_path.read_text(encoding="utf-8"))
    if not isinstance(observation, dict):
        raise ReadyControlError("production observation proof is invalid")
    observed_observation_digest = str(observation.get("proof_digest") or "")
    unsigned_observation = dict(observation)
    unsigned_observation.pop("proof_digest", None)
    if (
        observed_observation_digest != expected_observation_digest
        or observed_observation_digest != sha256_text(stable_json(unsigned_observation))
        or observation.get("proof_type") != "PRODUCTION_OBSERVATION"
        or observation.get("status") != "PASS"
        or observation.get("candidate_digest") != expected_candidate_digest
    ):
        raise ReadyControlError("production observation proof identity differs")

    stable_provider_path = state_root / "stable-provider" / "report-index.json"
    if not stable_provider_path.is_file() or stable_provider_path.is_symlink():
        raise ReadyControlError("current Stable provider proof is unavailable")
    provider_value = json.loads(stable_provider_path.read_text(encoding="utf-8"))
    if not isinstance(provider_value, dict):
        raise ReadyControlError("current Stable provider proof is invalid")
    provider_digest = str(provider_value.get("report_digest") or "")
    unsigned_provider = dict(provider_value)
    unsigned_provider.pop("report_digest", None)
    raw_provider_reports = provider_value.get("reports")
    if not isinstance(raw_provider_reports, list) or not all(
        isinstance(item, dict) for item in raw_provider_reports
    ):
        raise ReadyControlError("current Stable provider reports are invalid")
    provider_reports = tuple(
        CapabilityHandshakeReport.from_dict(item) for item in raw_provider_reports
    )
    try:
        provider_observed = datetime.fromisoformat(str(provider_value["observed_at"]))
        production_completed = datetime.fromisoformat(str(observation["completed_at"]))
    except (KeyError, ValueError) as error:
        raise ReadyControlError("Stable provider proof time binding is invalid") from error
    if provider_observed.tzinfo is None:
        provider_observed = provider_observed.replace(tzinfo=UTC)
    if production_completed.tzinfo is None:
        production_completed = production_completed.replace(tzinfo=UTC)
    expected_provider_operations = {
        "provider.luna.invoke",
        "provider.terra.invoke",
        "provider.sol.invoke",
        "provider.terminal.sandbox",
    }
    if (
        set(unsigned_provider) != {"schema_version", "observed_at", "reports"}
        or provider_value.get("schema_version") != "1.0"
        or provider_digest != sha256_text(stable_json(unsigned_provider))
        or len(provider_reports) != 4
        or {report.operation for report in provider_reports} != expected_provider_operations
        or any(
            report.status != CapabilityStatus.AVAILABLE
            or report.candidate_digest != expected_candidate_digest
            or report.scope.get("runtime_principal") != "hermesfactory"
            for report in provider_reports
        )
        or any(
            report.scope.get("execution_boundary") != "rootless_oci"
            or report.scope.get("container_identity") != "/run/.containerenv"
            or report.scope.get("workspace_mount") is not True
            or report.scope.get("credential_forwarding") is not False
            or report.scope.get("toolsets") != ["terminal"]
            or not re.fullmatch(r"[a-f0-9]{64}", str(report.scope.get("marker_digest") or ""))
            for report in provider_reports
            if report.operation == "provider.terminal.sandbox"
        )
        or provider_observed.astimezone(UTC) <= production_completed.astimezone(UTC)
    ):
        raise ReadyControlError("Stable provider proof was not renewed after production")

    support_report_path = state_root / "support-reconciler" / "report-index.json"
    if not support_report_path.is_file() or support_report_path.is_symlink():
        raise ReadyControlError("support-bundle reconciliation proof is unavailable")
    support_report = json.loads(support_report_path.read_text(encoding="utf-8"))
    if not isinstance(support_report, dict):
        raise ReadyControlError("support-bundle reconciliation proof is invalid")
    support_digest = str(support_report.get("proof_digest") or "")
    unsigned_support = dict(support_report)
    unsigned_support.pop("proof_digest", None)
    try:
        support_observed = datetime.fromisoformat(str(support_report["observed_at"]))
    except (KeyError, ValueError) as error:
        raise ReadyControlError("support-bundle reconciliation time is invalid") from error
    if support_observed.tzinfo is None:
        support_observed = support_observed.replace(tzinfo=UTC)
    raw_receipts = support_report.get("bundle_receipts")
    if not isinstance(raw_receipts, list) or not all(
        isinstance(item, dict) for item in raw_receipts
    ):
        raise ReadyControlError("support-bundle receipts are invalid")
    immutable_support = state_root / "support-reconciler" / f"report-{support_digest}.json"
    if (
        support_report.get("schema_version") != "1.0"
        or support_report.get("proof_type") != "SUPPORT_BUNDLE_RECONCILIATION"
        or support_report.get("status") != "PASS"
        or support_digest != sha256_text(stable_json(unsigned_support))
        or int(support_report.get("confirmed_incidents", -1)) != len(raw_receipts)
        or support_observed.astimezone(UTC) <= production_completed.astimezone(UTC)
        or not immutable_support.is_file()
        or immutable_support.is_symlink()
        or immutable_support.read_bytes() != support_report_path.read_bytes()
    ):
        raise ReadyControlError("support-bundle reconciler was not proven after production")
    support_bundle_root = (state_root / "support-bundles").resolve()
    for receipt in raw_receipts:
        filename = str(receipt.get("filename") or "")
        bundle = (support_bundle_root / filename).resolve()
        if (
            Path(filename).name != filename
            or support_bundle_root not in bundle.parents
            or not bundle.is_file()
            or bundle.is_symlink()
            or sha256_file(bundle) != str(receipt.get("digest") or "")
        ):
            raise ReadyControlError("support-bundle receipt does not match its artifact")

    stable_state_path = state_root / "ready" / f"stable-runtime-{expected_candidate_digest}.json"
    if not stable_state_path.is_file() or stable_state_path.is_symlink():
        raise ReadyControlError("Stable internal-state attestation is unavailable")
    stable_state = json.loads(stable_state_path.read_text(encoding="utf-8"))
    if not isinstance(stable_state, dict):
        raise ReadyControlError("Stable internal-state attestation is invalid")
    stable_state_digest = str(stable_state.get("proof_digest") or "")
    unsigned_stable_state = dict(stable_state)
    unsigned_stable_state.pop("proof_digest", None)
    stable_metrics = stable_state.get("metrics")
    try:
        stable_observed = datetime.fromisoformat(str(stable_state["observed_at"]))
    except (KeyError, ValueError) as error:
        raise ReadyControlError("Stable internal-state time binding is invalid") from error
    if stable_observed.tzinfo is None:
        stable_observed = stable_observed.replace(tzinfo=UTC)
    expected_stable_metrics = {
        "database_quick_check": "ok",
        "open_controller_incidents": 0,
        "duplicate_side_effects": 0,
        "unverified_side_effects": 0,
        "completed_without_manifest": 0,
        "manifest_without_completed_product": 0,
        "uncertain_owner_notifications": 0,
        "unsandboxed_provider_workers": 0,
        "routine_codex_runtime_dependencies": 0,
        "pending_owner_notifications": 0,
        "invalid_open_owner_notifications": 0,
    }
    if (
        stable_state.get("schema_version") != "1.0"
        or stable_state.get("proof_type") != "STABLE_RUNTIME_INTERNAL_STATE"
        or stable_state.get("status") != "PASS"
        or stable_state.get("candidate_digest") != expected_candidate_digest
        or stable_metrics != expected_stable_metrics
        or stable_state_digest != sha256_text(stable_json(unsigned_stable_state))
        or stable_observed.astimezone(UTC) <= production_completed.astimezone(UTC)
    ):
        raise ReadyControlError("Stable internal and external state does not match")

    improvement_database = state_root / "recursive-improvement.db"
    improvement = sqlite3.connect(
        f"file:{improvement_database.resolve().as_posix()}?mode=ro", uri=True
    )
    improvement.row_factory = sqlite3.Row
    try:
        quick_check = str(improvement.execute("PRAGMA quick_check").fetchone()[0])
        tables = {
            str(row[0])
            for row in improvement.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        required_tables = {
            "improvement_objectives",
            "improvement_cycles",
            "improvement_release_epochs",
            "improvement_scans",
            "improvement_lane_proofs",
        }
        active_experiments = int(
            improvement.execute(
                """SELECT COUNT(*) FROM improvement_objectives
                    WHERE status IN ('PROPOSED','EXPERIMENT_RUNNING','NEXT_BOUNDED_CYCLE')"""
            ).fetchone()[0]
        )
        latest_scan = improvement.execute(
            """SELECT observation_digest,candidate_digest,outcome FROM improvement_scans
                WHERE observation_digest=?""",
            (expected_observation_digest,),
        ).fetchone()
        lane = improvement.execute(
            """SELECT * FROM improvement_lane_proofs
                WHERE release_digest=? AND observation_digest=?""",
            (expected_candidate_digest, expected_observation_digest),
        ).fetchone()
        lane_state = improvement.execute(
            """SELECT objective.status,cycle.decision,cycle.implementation_attempts
                 FROM improvement_objectives AS objective
                 JOIN improvement_cycles AS cycle USING(objective_id)
                WHERE objective.objective_id=(
                    SELECT objective_id FROM improvement_lane_proofs
                     WHERE release_digest=?
                )""",
            (expected_candidate_digest,),
        ).fetchone()
    finally:
        improvement.close()
    if lane is None or lane_state is None:
        raise ReadyControlError("isolated recursive improvement lane is unqualified")
    objective_id = str(lane["objective_id"])
    candidate_digest = str(lane["candidate_digest"])
    lane_values = {
        "release_digest": str(lane["release_digest"]),
        "observation_digest": str(lane["observation_digest"]),
        "objective_id": objective_id,
        "cycle_id": str(lane["cycle_id"]),
        "candidate_digest": candidate_digest,
        "decision": str(lane["decision"]),
        "implementation_attempts": int(lane["implementation_attempts"]),
        "stable_identity_before": str(lane["stable_identity_before"]),
        "stable_identity_after": str(lane["stable_identity_after"]),
        "isolated_artifact_ref": str(lane["isolated_artifact_ref"]),
    }
    lane_proof = {
        "schema_version": "1.0",
        "proof_type": "ISOLATED_IMPROVEMENT_LANE_QUALIFICATION",
        **lane_values,
        "independent_evaluation": True,
    }
    lane_proof_digest = sha256_text(stable_json(lane_proof))
    candidate_path = (
        improvement_root
        / "experiments"
        / objective_id
        / f"candidate-{candidate_digest}.json"
    )
    if not candidate_path.is_file() or candidate_path.is_symlink():
        raise ReadyControlError("isolated Candidate implementation is unavailable")
    candidate_value = json.loads(candidate_path.read_text(encoding="utf-8"))
    if not isinstance(candidate_value, dict):
        raise ReadyControlError("isolated Candidate implementation is invalid")
    unsigned_candidate = dict(candidate_value)
    observed_candidate_digest = str(unsigned_candidate.pop("candidate_digest", ""))
    authority = unsigned_candidate.get("authority")
    if (
        lane_values["release_digest"] != expected_candidate_digest
        or lane_values["observation_digest"] != expected_observation_digest
        or lane_values["decision"] != "REJECT"
        or lane_values["implementation_attempts"] != 1
        or lane_values["stable_identity_before"] != lane_values["stable_identity_after"]
        or tuple(lane_state) != ("IMPROVEMENT_REJECTED", "REJECT", 1)
        or str(lane["proof_digest"]) != lane_proof_digest
        or observed_candidate_digest != lane_values["candidate_digest"]
        or observed_candidate_digest != sha256_text(stable_json(unsigned_candidate))
        or authority
        != {
            "stable_write": False,
            "credential_expansion": False,
            "gate_changes": False,
        }
    ):
        raise ReadyControlError("isolated recursive improvement proof is invalid")
    if (
        quick_check != "ok"
        or not required_tables <= tables
        or active_experiments > 1
        or latest_scan is None
        or str(latest_scan[0]) != expected_observation_digest
        or str(latest_scan[1]) != expected_candidate_digest
        or str(latest_scan[2]) != "NO_MEASURABLE_OPPORTUNITY"
    ):
        raise ReadyControlError("recursive improvement runtime is invalid")
    proof = {
        "schema_version": "1.0",
        "proof_type": "AUTONOMOUS_RUNTIME_READY",
        "status": "PASS",
        "services": {
            "active": active,
            "enabled": enabled,
            "support_bundle_loaded": support_loaded,
            "support_reconciler_proof_digest": support_digest,
            "support_reconciler_verified_after_production_observation": True,
        },
        "capabilities": {
            "stable_provider_status": "PASS",
            "stable_provider_report_digest": provider_digest,
            "stable_provider_observed_at": str(provider_value["observed_at"]),
            "verified_after_production_observation": True,
        },
        "internal_state": {
            "status": "PASS",
            "attestation_digest": stable_state_digest,
            "metrics": stable_metrics,
            "verified_after_production_observation": True,
        },
        "self_improvement": {
            "status": "ACTIVE",
            "active_experiments": active_experiments,
            "last_observation_digest": str(latest_scan[0]),
            "last_detection_outcome": str(latest_scan[2]),
            "isolated_lane_proof_digest": lane_proof_digest,
            "isolated_lane_decision": lane_values["decision"],
            "qualified_implementation_attempts": lane_values["implementation_attempts"],
            "stable_self_write": False,
            "isolated_candidate_only": True,
            "max_recursion_depth": 3,
            "max_implementation_attempts": 2,
            "independent_evaluation": True,
        },
    }
    digest = sha256_text(stable_json(proof))
    proof_path = output.with_name(f"runtime-proof-{digest}.json")
    _write_once(proof_path, {**proof, "proof_digest": digest})
    return f"artifact://ready-runtime/{digest}", proof


def build_lts_request(config: dict[str, Any], *, state_root: Path, output: Path) -> dict[str, Any]:
    functional = sqlite3.connect(state_root / "functional.db")
    functional.row_factory = sqlite3.Row
    qualification = sqlite3.connect(Path(str(config["governor_database"])))
    qualification.row_factory = sqlite3.Row
    try:
        epoch = _epoch(functional, config)
        if str(epoch["status"]) != "Q7_STARTED":
            raise ReadyControlError("functional state is not awaiting final LTS result")
        release_rows = qualification.execute(
            "SELECT * FROM controller_release_epochs WHERE source_commit=? AND candidate_digest=?",
            (str(config["source_commit"]), str(config["candidate_digest"])),
        ).fetchall()
        if len(release_rows) != 1 or str(release_rows[0]["status"]) != "LTS":
            raise ReadyControlError("release epoch is not LTS")
        release = release_rows[0]
        runs = qualification.execute(
            "SELECT stage,status,evidence_ref FROM qualification_runs "
            "WHERE epoch_id=? ORDER BY stage_index",
            (str(release["epoch_id"]),),
        ).fetchall()
        if [str(row[0]) for row in runs] != list(QUALIFICATION_STAGES) or any(
            str(row[1]) != "PASS" for row in runs
        ):
            raise ReadyControlError("exact Q0-Q7 PASS evidence is incomplete")
        canaries = qualification.execute(
            "SELECT * FROM clean_canary_runs WHERE epoch_id=? ORDER BY scenario_id",
            (str(release["epoch_id"]),),
        ).fetchall()
        zero_fields = (
            "controller_recovery_applications",
            "manual_database_mutations",
            "routine_owner_actions",
            "unknown_controller_defects",
            "release_changes",
            "duplicate_side_effects",
        )
        if (
            len(canaries) != len(REQUIRED_CANARY_SCENARIOS)
            or {str(row["scenario_id"]) for row in canaries} != set(REQUIRED_CANARY_SCENARIOS)
            or any(
                str(row["status"]) != "PASS"
                or str(row["terminal_status"]) != "COMPLETED"
                or any(int(row[field]) != 0 for field in zero_fields)
                for row in canaries
            )
        ):
            raise ReadyControlError("exact zero-intervention Q8 evidence is incomplete")
        capabilities = functional.execute(
            "SELECT operation,status,report_digest FROM capability_handshake_reports "
            "WHERE epoch_id=? ORDER BY operation",
            (str(epoch["epoch_id"]),),
        ).fetchall()
        runtime_capability = functional.execute(
            "SELECT capability,status,report_digest FROM runtime_capability_reports "
            "WHERE epoch_id=?",
            (str(epoch["epoch_id"]),),
        ).fetchall()
        pre_q8 = functional.execute(
            "SELECT scenario_id,status,evidence_digest,completion_manifest_ref "
            "FROM pre_q8_scenarios WHERE epoch_id=? ORDER BY scenario_id",
            (str(epoch["epoch_id"]),),
        ).fetchall()
        golden = functional.execute(
            "SELECT * FROM golden_products WHERE epoch_id=?", (str(epoch["epoch_id"]),)
        ).fetchone()
        open_actions = int(
            functional.execute(
                "SELECT COUNT(*) FROM functional_owner_actions WHERE epoch_id=? AND status='OPEN'",
                (str(epoch["epoch_id"]),),
            ).fetchone()[0]
        )
        if (
            len(capabilities) != 18
            or any(str(row[1]) != "AVAILABLE" for row in capabilities)
            or len(runtime_capability) != 2
            or {str(row[0]) for row in runtime_capability}
            != {"github.product.runtime", "provider.stable.runtime"}
            or any(str(row[1]) != "AVAILABLE" for row in runtime_capability)
            or str(epoch["product_github_status"]) != "PASS"
            or str(epoch["stable_provider_status"]) != "PASS"
            or len(pre_q8) != 10
            or any(str(row[1]) != "PASS" for row in pre_q8)
            or golden is None
            or str(golden["status"]) != "COMPLETED"
            or int(golden["branch_protection_bypassed"]) != 0
            or int(golden["duplicate_side_effects"]) != 0
            or int(golden["credential_exposure"]) != 0
            or int(golden["manual_database_edits"]) != 0
            or open_actions != 0
            or int(release["controller_defect_count"]) != 0
        ):
            raise ReadyControlError("functional or internal-state evidence is incomplete")
        signed_qualification = qualification.execute(
            "SELECT manifest_ref FROM release_qualification_manifests WHERE epoch_id=?",
            (str(release["epoch_id"]),),
        ).fetchone()
        if signed_qualification is None:
            raise ReadyControlError("signed qualification manifest is absent")
        runtime_ref, runtime_proof = _runtime_ready_proof(
            state_root=state_root,
            output=output,
            expected_observation_digest=str(release["observation_digest"]),
            expected_candidate_digest=str(config["candidate_digest"]),
            production_observation_path=Path(str(config["production_observation_path"])),
        )
        obligations = [
            {
                "obligation_id": f"qualification.{row[0]}",
                "status": "PASS",
                "evidence_ref": str(row[2]),
            }
            for row in runs
        ]
        obligations.extend(
            {
                "obligation_id": f"q6_5.{row[0]}",
                "status": "PASS",
                "evidence_ref": f"sha256:{row[2]}",
            }
            for row in capabilities
        )
        obligations.extend(
            {
                "obligation_id": f"runtime.{row[0]}",
                "status": "PASS",
                "evidence_ref": f"sha256:{row[2]}",
            }
            for row in runtime_capability
        )
        obligations.append(
            {
                "obligation_id": "runtime.provider.stable.current",
                "status": "PASS",
                "evidence_ref": "sha256:"
                + str(runtime_proof["capabilities"]["stable_provider_report_digest"]),
            }
        )
        obligations.append(
            {
                "obligation_id": "runtime.internal_state.current",
                "status": "PASS",
                "evidence_ref": "sha256:"
                + str(runtime_proof["internal_state"]["attestation_digest"]),
            }
        )
        obligations.append(
            {
                "obligation_id": "runtime.support_bundle.reconciler",
                "status": "PASS",
                "evidence_ref": "sha256:"
                + str(runtime_proof["services"]["support_reconciler_proof_digest"]),
            }
        )
        obligations.append(
            {
                "obligation_id": "runtime.self_improvement.isolated_lane",
                "status": "PASS",
                "evidence_ref": "sha256:"
                + str(runtime_proof["self_improvement"]["isolated_lane_proof_digest"]),
            }
        )
        obligations.extend(
            {
                "obligation_id": f"pre_q8.{row[0]}",
                "status": "PASS",
                "evidence_ref": str(row[3]),
            }
            for row in pre_q8
        )
        obligations.extend(
            {
                "obligation_id": f"q8.{row['scenario_id']}",
                "status": "PASS",
                "evidence_ref": str(row["completion_manifest_ref"]),
            }
            for row in canaries
        )
        obligations.extend(
            (
                {
                    "obligation_id": "golden_product.completed",
                    "status": "PASS",
                    "evidence_ref": str(golden["completion_manifest_ref"]),
                },
                {
                    "obligation_id": "release.signed_qualification",
                    "status": "PASS",
                    "evidence_ref": str(signed_qualification[0]),
                },
                {
                    "obligation_id": "release.promotion",
                    "status": "PASS",
                    "evidence_ref": str(release["promotion_receipt_ref"]),
                },
                {
                    "obligation_id": "release.production_observation",
                    "status": "PASS",
                    "evidence_ref": str(release["observation_evidence_ref"]),
                },
                {
                    "obligation_id": "runtime.autonomy",
                    "status": "PASS",
                    "evidence_ref": runtime_ref,
                },
            )
        )
        evidence_refs = tuple(str(item["evidence_ref"]) for item in obligations)
        request = {
            "schema_version": "1.0",
            "manifest_type": "FACTORY_LTS_READY",
            "status": "PASS",
            "subject": {
                "status": "AUTONOMOUS_FACTORY_READY",
                "golden_product": "COMPLETED",
                "real_telegram_intake": "PASS",
                "github_delivery": "PASS",
                "product_delivery": "PASS",
                "internal_state_verification": "PASS",
                "autonomy": {
                    "routine_gpt_codex_required": False,
                    "routine_owner_action_required": False,
                    "restart_recovery": "PASS",
                    "automatic_continuation": "PASS",
                    "telegram_notifier": "ACTIVE",
                    "support_bundle": "ACTIVE",
                },
                "self_improvement": runtime_proof["self_improvement"],
                "safety": {
                    "credential_exposure": False,
                    "manual_database_edits": 0,
                    "branch_protection_bypassed": False,
                    "duplicate_side_effects": 0,
                    "open_controller_incidents": 0,
                },
            },
            "release_identity": {
                "version": (Path(str(config["candidate_repository_root"])) / "VERSION")
                .read_text(encoding="utf-8")
                .strip(),
                "commit": str(config["source_commit"]),
                "digest": str(config["candidate_digest"]),
            },
            "mandatory_obligations": obligations,
            "evidence_refs": list(evidence_refs),
            "open_blockers": [],
            "verifier": {"digest": str(config["verifier_digest"])},
        }
        _write_once(output, request)
        return request
    finally:
        functional.close()
        qualification.close()


def sign_request(config: dict[str, Any], *, request: Path, output: Path) -> dict[str, Any]:
    value = json.loads(request.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("verifier") != {
        "digest": str(config["verifier_digest"])
    }:
        raise ReadyControlError("ready request verifier identity differs")
    key = _load_private_key(Path(str(config["verifier_private_key_path"])))
    public = key.public_key().public_bytes_raw()
    if hashlib.sha256(public).hexdigest() != str(config["trusted_verifier_public_key_digest"]):
        raise ReadyControlError("ready signing key differs from trust root")
    signature = base64.b64encode(key.sign(stable_json(value).encode("utf-8"))).decode("ascii")
    release = value["release_identity"]
    manifest = ReadyResultManifest.create(
        manifest_type=str(value["manifest_type"]),
        subject=dict(value["subject"]),
        version=str(release["version"]),
        commit=str(release["commit"]),
        digest=str(release["digest"]),
        mandatory_obligations=tuple(value["mandatory_obligations"]),
        evidence_refs=tuple(str(item) for item in value["evidence_refs"]),
        verifier_digest=str(value["verifier"]["digest"]),
        verifier_signature=signature,
    )
    envelope = manifest.as_dict()
    _write_once(output, envelope)
    return envelope


def dispatch(config: dict[str, Any], *, state_root: Path, signed: Path) -> dict[str, Any]:
    value = json.loads(signed.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReadyControlError("signed ready result is invalid")
    digest = verify_ready_result_manifest(
        value,
        verifier_public_key=str(config["verifier_public_key"]),
        trusted_public_key_digest=str(config["trusted_verifier_public_key_digest"]),
    )
    connection = sqlite3.connect(state_root / "functional.db")
    governor = FunctionalQualificationGovernor(connection)
    try:
        epoch = _epoch(connection, config)
        effect = governor.authorize_q7(str(epoch["epoch_id"]))
    finally:
        connection.close()
    release_epoch, _ = authorize_shadow(config, digest)
    return {
        "status": "Q7_AUTHORIZED",
        "epoch_id": release_epoch,
        "effect": effect,
        "manifest_digest": digest,
    }


def dispatch_lts(config: dict[str, Any], *, state_root: Path, signed: Path) -> dict[str, Any]:
    value = json.loads(signed.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("manifest_type") != "FACTORY_LTS_READY"
        or not isinstance(value.get("subject"), dict)
        or value["subject"].get("status") != "AUTONOMOUS_FACTORY_READY"
    ):
        raise ReadyControlError("signed LTS ready result is invalid")
    digest = verify_ready_result_manifest(
        value,
        verifier_public_key=str(config["verifier_public_key"]),
        trusted_public_key_digest=str(config["trusted_verifier_public_key_digest"]),
    )
    manifest_ref = f"artifact://ready-result/{digest}"
    request = NotificationRequest(
        request_id="FACTORY-READY-" + digest[:32],
        kind="FACTORY_LTS_READY",
        text=(
            "Hermes Software Factory is AUTONOMOUS_FACTORY_READY. "
            "Golden Product COMPLETED; signed immutable result attached."
        ),
        document_path=str(signed),
        document_digest=hashlib.sha256(signed.read_bytes()).hexdigest(),
    )
    notifications = NotificationOutbox(
        state_root / "notifications",
        attachment_roots=(state_root, Path("/var/lib/hermes-factory-verifier")),
    )
    notifications.enqueue(request)
    receipt_path = notifications.receipts / f"{request.request_id}.json"
    if not receipt_path.is_file() or receipt_path.is_symlink():
        return {
            "status": "FINAL_NOTIFICATION_PENDING",
            "manifest_digest": digest,
            "notification_request_id": request.request_id,
        }
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if not isinstance(receipt, dict):
        raise ReadyControlError("final Telegram receipt is invalid")
    receipt_digest = str(receipt.get("receipt_digest") or "")
    unsigned_receipt = dict(receipt)
    unsigned_receipt.pop("receipt_digest", None)
    if (
        set(receipt)
        != {
            "schema_version",
            "request_id",
            "kind",
            "status",
            "document_digest",
            "sent_at",
            "receipt_digest",
        }
        or receipt.get("schema_version") != "1.0"
        or receipt.get("request_id") != request.request_id
        or receipt.get("kind") != request.kind
        or receipt.get("status") != "SENT"
        or receipt.get("document_digest") != request.document_digest
        or receipt_digest != sha256_text(stable_json(unsigned_receipt))
    ):
        raise ReadyControlError("final Telegram delivery is not authoritatively proven")
    connection = sqlite3.connect(state_root / "functional.db")
    governor = FunctionalQualificationGovernor(connection)
    try:
        epoch = _epoch(connection, config)
        changed = governor.record_factory_ready(
            epoch_id=str(epoch["epoch_id"]),
            manifest_digest=digest,
            manifest_ref=manifest_ref,
        )
        final_epoch = governor.epoch(str(epoch["epoch_id"]))
    finally:
        connection.close()
    if (
        str(final_epoch["status"]) != "AUTONOMOUS_FACTORY_READY"
        or str(final_epoch["ready_result_manifest_digest"]) != digest
        or str(final_epoch["ready_result_manifest_ref"]) != manifest_ref
    ):
        raise ReadyControlError("final internal state does not match the signed result")
    return {
        "status": "AUTONOMOUS_FACTORY_READY",
        "epoch_id": str(final_epoch["epoch_id"]),
        "ready_result_manifest": manifest_ref,
        "manifest_digest": digest,
        "telegram_receipt_digest": receipt_digest,
        "changed": changed,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=Path("/etc/hermes-factory/qualification-control.yaml")
    )
    parser.add_argument(
        "--state-root", type=Path, default=Path("/var/lib/hermes-factory-functional")
    )
    commands = parser.add_subparsers(dest="command", required=True)
    request = commands.add_parser("request")
    request.add_argument("output", type=Path)
    lts_request = commands.add_parser("lts-request")
    lts_request.add_argument("output", type=Path)
    sign = commands.add_parser("sign")
    sign.add_argument("request", type=Path)
    sign.add_argument("output", type=Path)
    dispatch_parser = commands.add_parser("dispatch")
    dispatch_parser.add_argument("signed", type=Path)
    lts_dispatch = commands.add_parser("lts-dispatch")
    lts_dispatch.add_argument("signed", type=Path)
    args = parser.parse_args(argv)
    try:
        config = _config(args.config)
        if args.command == "request":
            result = build_request(config, state_root=args.state_root, output=args.output)
        elif args.command == "lts-request":
            result = build_lts_request(config, state_root=args.state_root, output=args.output)
        elif args.command == "sign":
            result = sign_request(config, request=args.request, output=args.output)
        elif args.command == "dispatch":
            result = dispatch(config, state_root=args.state_root, signed=args.signed)
        else:
            result = dispatch_lts(config, state_root=args.state_root, signed=args.signed)
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
        sqlite3.Error,
        FunctionalReadinessError,
        ReadyControlError,
    ) as error:
        print(stable_json({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    print(stable_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
