"""Independent Q8 fresh-state and zero-intervention canary observations."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .canary_faults import CanaryFaultContract, CanaryFaultJournal
from .common import sha256_text, stable_json, utc_now
from .delivery_profiles import DELIVERY_PROFILES, DeliveryProfileName
from .failure_catalog import failure_disposition
from .release_qualification import (
    REQUIRED_CANARY_SCENARIOS,
    QualificationError,
    ReleaseQualificationGovernor,
)


class CanaryObservationError(RuntimeError):
    """Candidate state cannot prove a clean first-pass canary."""


@dataclass(frozen=True)
class FreshStateProof:
    database: str
    schema_version: int
    row_counts: dict[str, int]
    initial_state_digest: str
    evidence_ref: str
    report_path: str


@dataclass(frozen=True)
class CanaryCompletionObservation:
    product_id: str
    terminal_status: str
    completion_manifest_ref: str
    task_count: int
    baseline_task_count: int
    controller_incidents: int
    recovery_applications: int
    routine_owner_actions: int
    duplicate_side_effects: int
    unverified_side_effects: int
    decision_trace: tuple[str, ...]
    fault_receipt_digests: tuple[str, ...]
    database_integrity: str
    observation_digest: str
    evidence_ref: str
    report_path: str


@dataclass(frozen=True)
class CleanCanaryScenario:
    scenario_id: str
    delivery_profile: str
    delivery_mode: str
    initial_state: str
    idea: str
    events: tuple[str, ...]
    injected_faults: tuple[str, ...]
    expected_decisions: tuple[str, ...]
    forbidden_decisions: tuple[str, ...]
    expected_terminal: str
    scenario_digest: str


_FRESH_TABLES = (
    "products",
    "tasks",
    "attempts",
    "events",
    "outbox",
    "side_effect_intents",
    "side_effect_receipts",
    "completion_manifests",
)
_SQL_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]*$")
_GLOBAL_BASELINE_FILTERS = {
    "capability_grants": "product_id IS NOT NULL OR task_id IS NOT NULL",
    "toolchain_manifests": "product_id IS NOT NULL",
    "grant_epochs": "product_id IS NOT NULL",
}
_SCENARIO_KEYS = {
    "scenario_id",
    "delivery_profile",
    "delivery_mode",
    "initial_state",
    "idea",
    "events",
    "injected_faults",
    "expected_decisions",
    "forbidden_decisions",
    "expected_terminal",
}
_FAULTS = {
    "KNOWN_PRODUCT_DEFECT",
    "BOUNDED_EXTERNAL_BLOCK",
    "ONE_PROVIDER_TIMEOUT",
    "ONE_PROCESS_RESTART",
    "ONE_PRODUCT_TEST_FAILURE",
    "ONE_POST_DEPLOY_HEALTH_FAILURE",
}
_DECISIONS = {
    "CONTINUE",
    "RETRY_TRANSIENT",
    "REPAIR_NODE_VERSION",
    "RECOMPILE_AFFECTED_SUBGRAPH",
    "CONTROLLER_QUARANTINE",
    "WAIT_EXTERNAL",
    "ROLLBACK",
    "FAIL_SAFE",
    "COMPLETE",
    "OWNER_ACTION",
}


def _string_list(value: Any, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise CanaryObservationError(f"{label} must be a list")
    normalized = tuple(str(item).strip() for item in value)
    if any(not item for item in normalized) or len(set(normalized)) != len(normalized):
        raise CanaryObservationError(f"{label} contains an empty or duplicate value")
    return normalized


def load_canary_catalog(path: Path) -> dict[str, CleanCanaryScenario]:
    """Load the exact ten Q8 archetypes from a closed declarative catalog."""

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise CanaryObservationError("clean canary catalog is unreadable") from error
    if not isinstance(raw, Mapping) or set(raw) != {"schema_version", "scenarios"}:
        raise CanaryObservationError("clean canary catalog schema is invalid")
    scenarios_raw = raw.get("scenarios")
    if raw.get("schema_version") != "1.0" or not isinstance(scenarios_raw, list):
        raise CanaryObservationError("clean canary catalog version is invalid")
    catalog: dict[str, CleanCanaryScenario] = {}
    for value in scenarios_raw:
        if not isinstance(value, Mapping) or set(value) != _SCENARIO_KEYS:
            raise CanaryObservationError("clean canary scenario schema is invalid")
        payload = {str(key): item for key, item in value.items()}
        scenario_id = str(payload["scenario_id"]).strip()
        profile = str(payload["delivery_profile"]).strip()
        delivery_mode = str(payload["delivery_mode"]).strip()
        events = _string_list(payload["events"], f"{scenario_id}.events")
        faults = _string_list(
            payload["injected_faults"],
            f"{scenario_id}.injected_faults",
            allow_empty=True,
        )
        expected = _string_list(
            payload["expected_decisions"], f"{scenario_id}.expected_decisions"
        )
        forbidden = _string_list(
            payload["forbidden_decisions"], f"{scenario_id}.forbidden_decisions"
        )
        if scenario_id in catalog:
            raise CanaryObservationError("clean canary scenario is duplicated")
        try:
            profile_name = DeliveryProfileName(profile)
        except ValueError as error:
            raise CanaryObservationError("clean canary delivery profile is unknown") from error
        if profile_name not in DELIVERY_PROFILES:
            raise CanaryObservationError("clean canary delivery profile is unavailable")
        if delivery_mode not in {"new_repository", "existing_repository"}:
            raise CanaryObservationError("clean canary delivery mode is invalid")
        if str(payload["initial_state"]) != "EMPTY_DATABASE":
            raise CanaryObservationError("clean canary must start from an empty database")
        if str(payload["expected_terminal"]) != "COMPLETED":
            raise CanaryObservationError("clean canary must end COMPLETED")
        if not str(payload["idea"]).strip():
            raise CanaryObservationError("clean canary idea is empty")
        if not set(faults) <= _FAULTS:
            raise CanaryObservationError("clean canary fault is unknown")
        if not {*expected, *forbidden} <= _DECISIONS:
            raise CanaryObservationError("clean canary decision is unknown")
        if set(expected) & set(forbidden):
            raise CanaryObservationError("clean canary decision is both expected and forbidden")
        digest = sha256_text(stable_json(payload))
        catalog[scenario_id] = CleanCanaryScenario(
            scenario_id=scenario_id,
            delivery_profile=profile,
            delivery_mode=delivery_mode,
            initial_state="EMPTY_DATABASE",
            idea=str(payload["idea"]).strip(),
            events=events,
            injected_faults=faults,
            expected_decisions=expected,
            forbidden_decisions=forbidden,
            expected_terminal="COMPLETED",
            scenario_digest=digest,
        )
    if set(catalog) != set(REQUIRED_CANARY_SCENARIOS):
        raise CanaryObservationError("clean canary archetype set is incomplete")
    return catalog


def _connection(database: Path) -> sqlite3.Connection:
    if not database.is_absolute() or not database.is_file() or database.is_symlink():
        raise CanaryObservationError("candidate database must be an existing regular file")
    connection = sqlite3.connect(
        f"file:{database.resolve().as_posix()}?mode=ro",
        uri=True,
        timeout=30,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _write_evidence(root: Path, label: str, payload: dict[str, Any]) -> tuple[str, str, str]:
    body_digest = sha256_text(stable_json(payload))
    observation_time = utc_now()
    envelope = {**payload, "report_digest": body_digest, "observed_at": observation_time}
    encoded = json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    root.mkdir(parents=True, exist_ok=True)
    destination = root / f"{label}-{body_digest}.json"
    if destination.exists():
        if destination.is_symlink():
            raise CanaryObservationError("immutable canary evidence conflicts")
        existing = json.loads(destination.read_text(encoding="utf-8"))
        if not isinstance(existing, dict):
            raise CanaryObservationError("immutable canary evidence conflicts")
        observed_at = str(existing.pop("observed_at", ""))
        report_digest = str(existing.pop("report_digest", ""))
        if not observed_at or report_digest != body_digest or existing != payload:
            raise CanaryObservationError("immutable canary evidence conflicts")
    else:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                destination.unlink()
            except OSError:
                pass
            raise
        try:
            destination.chmod(0o440)
        except OSError:
            pass
    return (
        body_digest,
        f"artifact://qualification/canary/{label}/{body_digest}",
        str(destination),
    )


def prove_fresh_state(database: Path, evidence_root: Path) -> FreshStateProof:
    """Prove the migrated candidate database contains no product execution state."""

    connection = _connection(database)
    try:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        missing = set(_FRESH_TABLES) - tables
        if missing:
            raise CanaryObservationError(
                f"candidate fresh-state schema is incomplete: {min(missing)}"
            )
        execution_tables = sorted(
            table
            for table in tables
            if not table.startswith("sqlite_")
            and table not in {"schema_migrations", "factory_runtime_state"}
        )
        if any(_SQL_IDENTIFIER.fullmatch(table) is None for table in execution_tables):
            raise CanaryObservationError("candidate schema contains an unsafe table name")
        counts = {
            table: int(
                connection.execute(
                    f'SELECT COUNT(*) FROM "{table}"'
                    + (
                        f" WHERE {_GLOBAL_BASELINE_FILTERS[table]}"
                        if table in _GLOBAL_BASELINE_FILTERS
                        else ""
                    )
                ).fetchone()[0]
            )
            for table in execution_tables
        }
        if any(counts.values()):
            raise CanaryObservationError("candidate canary database is not fresh")
        version_row = connection.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()
        version = int(version_row[0]) if version_row and version_row[0] is not None else 0
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
    finally:
        connection.close()
    if integrity != "ok":
        raise CanaryObservationError("candidate fresh-state database is corrupt")
    identity = {
        "schema_version": "1.0",
        "database_role": "FRESH_CLEAN_CANARY",
        "migration_version": version,
        "row_counts": counts,
        "database_integrity": integrity,
    }
    initial_digest = sha256_text(stable_json(identity))
    payload = {**identity, "initial_state_digest": initial_digest}
    _, evidence_ref, report_path = _write_evidence(
        evidence_root, "fresh-state", payload
    )
    return FreshStateProof(
        database=str(database.resolve()),
        schema_version=version,
        row_counts=counts,
        initial_state_digest=initial_digest,
        evidence_ref=evidence_ref,
        report_path=report_path,
    )


def observe_completion(
    database: Path,
    evidence_root: Path,
    *,
    product_id: str,
    expected_controller_release_digest: str,
    scenario: CleanCanaryScenario | None = None,
    fault_receipt_root: Path | None = None,
    expected_candidate_digest: str | None = None,
    fault_contract: CanaryFaultContract | None = None,
) -> CanaryCompletionObservation:
    """Read final candidate state without mutation and derive every Q8 counter."""

    connection = _connection(database)
    try:
        product = connection.execute(
            """SELECT status,completion_evidence_ref
                 FROM products WHERE product_id=?""",
            (product_id,),
        ).fetchone()
        if product is None:
            raise CanaryObservationError("canary product is missing")
        manifest = connection.execute(
            """SELECT manifest_ref,controller_release_digest,manifest_digest
                 FROM completion_manifests WHERE product_id=?""",
            (product_id,),
        ).fetchone()
        if manifest is None:
            raise CanaryObservationError("canary completion manifest is missing")
        terminal_status = str(product["status"])
        completion_ref = str(product["completion_evidence_ref"] or "")
        if terminal_status != "COMPLETED" or completion_ref != str(manifest["manifest_ref"]):
            raise CanaryObservationError("canary terminal state is not proof-bound")
        if str(manifest["controller_release_digest"]) != expected_controller_release_digest:
            raise CanaryObservationError("canary controller release digest changed")
        task_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM tasks WHERE product_id=?", (product_id,)
            ).fetchone()[0]
        )
        baseline_count = int(
            connection.execute(
                """SELECT COUNT(*) FROM tasks
                    WHERE product_id=? AND COALESCE(task_revision,1)=1""",
                (product_id,),
            ).fetchone()[0]
        )
        incidents = int(
            connection.execute(
                "SELECT COUNT(*) FROM controller_incidents WHERE product_id=?",
                (product_id,),
            ).fetchone()[0]
        )
        recoveries = int(
            connection.execute(
                "SELECT COUNT(*) FROM recovery_applications WHERE product_id=?",
                (product_id,),
            ).fetchone()[0]
        )
        trajectory = connection.execute(
            """SELECT routine_owner_actions,recovery_applications
                 FROM trajectory_counters WHERE product_id=?""",
            (product_id,),
        ).fetchone()
        owner_actions = int(trajectory[0]) if trajectory is not None else 0
        recoveries = max(recoveries, int(trajectory[1]) if trajectory is not None else 0)
        side_effect_counts = connection.execute(
            """SELECT COUNT(*),COUNT(DISTINCT intent_id)
                 FROM side_effect_receipts
                WHERE intent_id IN (
                    SELECT intent_id FROM side_effect_intents WHERE product_id=?
                )""",
            (product_id,),
        ).fetchone()
        duplicate_effects = int(side_effect_counts[0]) - int(side_effect_counts[1])
        unverified_effects = int(
            connection.execute(
                """SELECT COUNT(*)
                     FROM side_effect_intents AS intent
                LEFT JOIN side_effect_receipts AS receipt
                       ON receipt.intent_id=intent.intent_id
                    WHERE intent.product_id=?
                      AND (intent.status!='VERIFIED' OR receipt.intent_id IS NULL)""",
                (product_id,),
            ).fetchone()[0]
        )
        decision_rows = connection.execute(
            "SELECT action FROM path_decisions WHERE product_id=? ORDER BY created_at,decision_id",
            (product_id,),
        ).fetchall()
        failure_rows = connection.execute(
            """SELECT reason_code,failure_action FROM failures
                 WHERE product_id=? ORDER BY first_seen_at,failure_id""",
            (product_id,),
        ).fetchall()
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        manifest_digest = str(manifest["manifest_digest"])
    finally:
        connection.close()
    if task_count < 1 or baseline_count < 1:
        raise CanaryObservationError("canary task cardinality is empty")
    if integrity != "ok":
        raise CanaryObservationError(
            f"canary database integrity failed: {integrity}"
        )
    if unverified_effects:
        raise CanaryObservationError("canary contains an unverified side-effect intent")
    decisions = {str(row["action"]) for row in decision_rows}
    decisions.update(
        str(row["failure_action"] or failure_disposition(str(row["reason_code"])).action.value)
        for row in failure_rows
    )
    decisions.update({"CONTINUE", "COMPLETE"})
    fault_receipt_digests: tuple[str, ...] = ()
    if scenario is not None:
        if fault_receipt_root is None or expected_candidate_digest is None:
            raise CanaryObservationError("canary fault verification contract is incomplete")
        contract = fault_contract
        if contract is None and scenario.injected_faults:
            first_receipt = fault_receipt_root / f"{scenario.injected_faults[0]}.json"
            try:
                namespace = json.loads(first_receipt.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise CanaryObservationError(
                    "canary fault receipt namespace is unavailable"
                ) from error
            if not isinstance(namespace, dict):
                raise CanaryObservationError(
                    "canary fault receipt namespace is not an object"
                )
            contract = CanaryFaultContract(
                qualification_plane=str(namespace.get("qualification_plane", "")),
                run_id=str(namespace.get("run_id", "")),
                epoch_id=str(namespace.get("epoch_id", "")),
                fixture_seed_digest=str(namespace.get("fixture_seed_digest", "")),
                scenario_id=scenario.scenario_id,
                scenario_digest=scenario.scenario_digest,
                controller_release_digest=expected_controller_release_digest,
                candidate_digest=expected_candidate_digest,
                faults=scenario.injected_faults,
                receipt_root=fault_receipt_root,
                isolated_target_root=fault_receipt_root.parent / "isolated-target",
            )
        if contract is None:
            contract = CanaryFaultContract(
                scenario_id=scenario.scenario_id,
                scenario_digest=scenario.scenario_digest,
                controller_release_digest=expected_controller_release_digest,
                candidate_digest=expected_candidate_digest,
                faults=scenario.injected_faults,
                receipt_root=fault_receipt_root,
                isolated_target_root=fault_receipt_root.parent / "isolated-target",
            )
        if (
            contract.scenario_id != scenario.scenario_id
            or contract.scenario_digest != scenario.scenario_digest
            or contract.controller_release_digest
            != expected_controller_release_digest
            or contract.candidate_digest != expected_candidate_digest
            or contract.receipt_root != fault_receipt_root
        ):
            raise CanaryObservationError("canary fault contract identity differs")
        journal = CanaryFaultJournal(contract)
        existing_receipts = (
            {
                path.stem
                for path in fault_receipt_root.glob("*.json")
                if path.is_file() and not path.is_symlink()
            }
            if fault_receipt_root.is_dir()
            else set()
        )
        if existing_receipts != set(scenario.injected_faults):
            raise CanaryObservationError("canary fault receipt cardinality differs")
        receipts = [journal.load(fault) for fault in scenario.injected_faults]
        fault_receipt_digests = tuple(str(value["receipt_digest"]) for value in receipts)
        receipt_by_fault = {str(value["fault"]): value for value in receipts}
        expected_points = {
            "KNOWN_PRODUCT_DEFECT": "existing_repository_fixture",
            "BOUNDED_EXTERNAL_BLOCK": "provider_preflight",
            "ONE_PROVIDER_TIMEOUT": "provider_transport",
            "ONE_PROCESS_RESTART": "after_durable_transient_retry",
            "ONE_PRODUCT_TEST_FAILURE": "mandatory_product_test",
            "ONE_POST_DEPLOY_HEALTH_FAILURE": "isolated_post_deploy_health",
        }
        if any(
            str(receipt_by_fault[fault].get("point")) != expected_points[fault]
            for fault in scenario.injected_faults
        ):
            raise CanaryObservationError("canary fault receipt point differs")
        if "ONE_PROVIDER_TIMEOUT" in scenario.injected_faults and not any(
            str(row["reason_code"]) == "agent_execution_timeout" for row in failure_rows
        ):
            raise CanaryObservationError("provider timeout fault did not reach durable state")
        if "BOUNDED_EXTERNAL_BLOCK" in scenario.injected_faults and not any(
            str(row["reason_code"]) == "network_timeout" for row in failure_rows
        ):
            raise CanaryObservationError("external blocker fault did not reach durable state")
        if "ONE_PRODUCT_TEST_FAILURE" in scenario.injected_faults and not any(
            str(row["reason_code"]) == "mandatory_gate_failed" for row in failure_rows
        ):
            raise CanaryObservationError("product test fault did not reach durable state")
        if "ONE_POST_DEPLOY_HEALTH_FAILURE" in scenario.injected_faults and not any(
            str(row["reason_code"]) == "deployment_health_failed" for row in failure_rows
        ):
            raise CanaryObservationError("deployment fault did not reach durable state")
        if not set(scenario.expected_decisions) <= decisions:
            raise CanaryObservationError("canary expected decision trace is incomplete")
        if set(scenario.forbidden_decisions) & decisions:
            raise CanaryObservationError("canary contains a forbidden decision")
    payload = {
        "schema_version": "1.0",
        "product_id": product_id,
        "terminal_status": terminal_status,
        "completion_manifest_ref": completion_ref,
        "completion_manifest_digest": manifest_digest,
        "controller_release_digest": expected_controller_release_digest,
        "task_count": task_count,
        "baseline_task_count": baseline_count,
        "controller_incidents": incidents,
        "recovery_applications": recoveries,
        "routine_owner_actions": owner_actions,
        "duplicate_side_effects": duplicate_effects,
        "unverified_side_effects": unverified_effects,
        "decision_trace": sorted(decisions),
        "fault_receipt_digests": list(fault_receipt_digests),
        "database_integrity": integrity,
    }
    observation_digest, evidence_ref, report_path = _write_evidence(
        evidence_root, f"completion-{product_id}", payload
    )
    return CanaryCompletionObservation(
        product_id=product_id,
        terminal_status=terminal_status,
        completion_manifest_ref=completion_ref,
        task_count=task_count,
        baseline_task_count=baseline_count,
        controller_incidents=incidents,
        recovery_applications=recoveries,
        routine_owner_actions=owner_actions,
        duplicate_side_effects=duplicate_effects,
        unverified_side_effects=unverified_effects,
        decision_trace=tuple(sorted(decisions)),
        fault_receipt_digests=fault_receipt_digests,
        database_integrity=integrity,
        observation_digest=observation_digest,
        evidence_ref=evidence_ref,
        report_path=report_path,
    )


def complete_observed_canary(
    governor: ReleaseQualificationGovernor,
    *,
    epoch_id: str,
    canary_id: str,
    observation: CanaryCompletionObservation,
) -> None:
    """Bind an independently observed completion to the running Q8 record."""

    if observation.controller_incidents:
        governor.record_controller_defect(
            epoch_id=epoch_id,
            canary_id=canary_id,
            reason_code="canary_controller_incident",
            evidence_ref=observation.evidence_ref,
        )
        raise QualificationError("canary contains a controller incident")
    if observation.recovery_applications:
        governor.record_recovery_application(
            epoch_id=epoch_id,
            canary_id=canary_id,
            recovery_ref=observation.evidence_ref,
        )
        raise QualificationError("canary contains a controller recovery")
    if observation.routine_owner_actions:
        governor.record_canary_violation(
            epoch_id=epoch_id,
            canary_id=canary_id,
            violation="routine_owner_action",
            evidence_ref=observation.evidence_ref,
        )
        raise QualificationError("canary contains a routine owner action")
    if observation.duplicate_side_effects:
        governor.record_canary_violation(
            epoch_id=epoch_id,
            canary_id=canary_id,
            violation="duplicate_side_effect",
            evidence_ref=observation.evidence_ref,
        )
        raise QualificationError("canary contains a duplicate side effect")
    governor.complete_clean_canary(
        epoch_id=epoch_id,
        canary_id=canary_id,
        terminal_status=observation.terminal_status,
        completion_manifest_ref=observation.completion_manifest_ref,
        product_id=observation.product_id,
        observation_evidence_ref=observation.evidence_ref,
        observation_digest=observation.observation_digest,
        task_count=observation.task_count,
        baseline_task_count=observation.baseline_task_count,
    )
