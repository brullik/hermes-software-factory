#!/usr/bin/env python3
"""Operate the verifier-owned Q0-Q8 release epoch without manual DB edits."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from factory.canary_qualification import (
    CanaryObservationError,
    complete_observed_canary,
    load_canary_catalog,
    observe_completion,
    prove_fresh_state,
)
from factory.common import sha256_text, stable_json, utc_now
from factory.qualification_runner import (
    QualificationRunError,
    QualificationStageReport,
    run_q0,
    run_q1,
    run_q2,
    run_q3,
    run_q4,
    run_q5,
    run_q6,
)
from factory.release_qualification import (
    QUALIFICATION_STAGES,
    REQUIRED_CANARY_SCENARIOS,
    QualificationError,
    ReleaseQualificationGovernor,
    verify_qualification_manifest_envelope,
)
from factory.shadow_feed import feed_paths, load_candidate_evaluation, load_feed_batch
from factory.shadow_projection import stable_observed_decision
from factory.shadow_qualification import ShadowEvidenceJournal, ShadowJournalError
from factory.state import StateStore
from factory.two_plane import PlaneBoundary, ShadowDifferentialLab, TwoPlaneLayout

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SHA40 = re.compile(r"^[a-f0-9]{40}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_CONFIG_KEYS = {
    "schema_version",
    "governor_database",
    "candidate_repository_root",
    "evidence_root",
    "shadow_journal_root",
    "shadow_feed_root",
    "candidate_shadow_output_root",
    "stable_release_root",
    "candidate_database",
    "q6_capability_attestation_path",
    "q6_capability_attestation_digest",
    "canary_catalog_path",
    "canary_config_index",
    "resilience_proof_index",
    "promotion_receipt_path",
    "production_observation_path",
    "production_rollback_path",
    "factory_repository",
    "source_commit",
    "stable_release_digest",
    "controller_release_digest",
    "candidate_digest",
    "policy_digest",
    "toolchain_manifest_digest",
    "trusted_verifier_public_key_digest",
    "verifier_digest",
    "verifier_public_key",
    "manifest_request_path",
    "signed_manifest_path",
    "verifier_private_key_path",
    "manifest_install_root",
}


class QualificationControlError(RuntimeError):
    """The independent qualification control boundary is invalid."""


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise QualificationControlError(f"{label} must be an object")
    return {str(key): item for key, item in value.items()}


def _load_config(path: Path) -> dict[str, Any]:
    metadata = path.stat()
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise QualificationControlError("qualification config must be an absolute regular file")
    if os.name != "nt" and (metadata.st_uid != 0 or metadata.st_mode & 0o022):
        raise QualificationControlError("qualification config is not root-owned read-only")
    raw = _mapping(yaml.safe_load(path.read_text(encoding="utf-8")), "qualification config")
    if set(raw) != _CONFIG_KEYS or raw.get("schema_version") != "1.0":
        raise QualificationControlError("qualification config schema is invalid")
    for key in (
        "governor_database",
        "candidate_repository_root",
        "evidence_root",
        "shadow_journal_root",
        "shadow_feed_root",
        "candidate_shadow_output_root",
        "stable_release_root",
        "candidate_database",
        "q6_capability_attestation_path",
        "manifest_request_path",
        "signed_manifest_path",
        "verifier_private_key_path",
        "manifest_install_root",
        "canary_catalog_path",
        "canary_config_index",
        "resilience_proof_index",
        "promotion_receipt_path",
        "production_observation_path",
        "production_rollback_path",
    ):
        if not Path(str(raw[key])).is_absolute():
            raise QualificationControlError(f"{key} must be absolute")
    if not _SHA40.fullmatch(str(raw["source_commit"])):
        raise QualificationControlError("source_commit is invalid")
    if not _REPOSITORY.fullmatch(str(raw["factory_repository"])):
        raise QualificationControlError("factory_repository is invalid")
    for key in (
        "stable_release_digest",
        "controller_release_digest",
        "candidate_digest",
        "policy_digest",
        "toolchain_manifest_digest",
        "trusted_verifier_public_key_digest",
        "verifier_digest",
        "q6_capability_attestation_digest",
    ):
        if not _SHA256.fullmatch(str(raw[key])):
            raise QualificationControlError(f"{key} is invalid")
    try:
        public_key = base64.b64decode(str(raw["verifier_public_key"]), validate=True)
    except (binascii.Error, ValueError) as error:
        raise QualificationControlError("verifier_public_key is invalid") from error
    if len(public_key) != 32:
        raise QualificationControlError("verifier_public_key is not Ed25519")
    if hashlib.sha256(public_key).hexdigest() != str(
        raw["trusted_verifier_public_key_digest"]
    ):
        raise QualificationControlError("verifier public key differs from trust root")
    repository = Path(str(raw["candidate_repository_root"]))
    if not repository.is_dir() or repository.is_symlink():
        raise QualificationControlError("candidate repository root is unavailable")
    load_canary_catalog(Path(str(raw["canary_catalog_path"])))
    return raw


def _store(config: Mapping[str, Any]) -> StateStore:
    database = Path(str(config["governor_database"]))
    database.parent.mkdir(parents=True, exist_ok=True)
    return StateStore(database)


def _canary_index(config: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    path = Path(str(config["canary_config_index"]))
    if not path.is_file() or path.is_symlink():
        raise QualificationControlError("clean canary config index is unavailable")
    metadata = path.stat()
    if os.name != "nt" and (metadata.st_uid != 0 or metadata.st_mode & 0o022):
        raise QualificationControlError("clean canary config index is not root-owned")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QualificationControlError("clean canary config index is unreadable") from error
    if not isinstance(raw, dict) or set(raw) != {
        "schema_version",
        "candidate_digest",
        "controller_release_digest",
        "catalog_digest",
        "scenarios",
        "index_digest",
    }:
        raise QualificationControlError("clean canary config index schema is invalid")
    digest = str(raw.pop("index_digest", ""))
    if sha256_text(stable_json(raw)) != digest:
        raise QualificationControlError("clean canary config index digest differs")
    if (
        raw.get("schema_version") != "1.0"
        or raw.get("candidate_digest") != config["candidate_digest"]
        or raw.get("controller_release_digest") != config["controller_release_digest"]
        or not _SHA256.fullmatch(str(raw.get("catalog_digest") or ""))
    ):
        raise QualificationControlError("clean canary config index identity differs")
    values = raw.get("scenarios")
    if not isinstance(values, list):
        raise QualificationControlError("clean canary config index scenarios are invalid")
    index: dict[str, dict[str, Any]] = {}
    expected_keys = {
        "scenario_id",
        "scenario_digest",
        "config_path",
        "config_digest",
        "database_path",
        "fault_receipt_root",
        "port",
    }
    for value in values:
        if not isinstance(value, dict) or set(value) != expected_keys:
            raise QualificationControlError("clean canary config index entry is invalid")
        scenario_id = str(value["scenario_id"])
        if scenario_id in index:
            raise QualificationControlError("clean canary config index is duplicated")
        for key in ("config_path", "database_path", "fault_receipt_root"):
            if not Path(str(value[key])).is_absolute():
                raise QualificationControlError("clean canary indexed path is relative")
        for key in ("scenario_digest", "config_digest"):
            if not _SHA256.fullmatch(str(value[key])):
                raise QualificationControlError("clean canary indexed digest is invalid")
        index[scenario_id] = dict(value)
    if set(index) != set(REQUIRED_CANARY_SCENARIOS):
        raise QualificationControlError("clean canary config index is incomplete")
    return index


def _governor(state: StateStore, config: Mapping[str, Any]) -> ReleaseQualificationGovernor:
    return ReleaseQualificationGovernor(
        state._connection,
        trusted_verifier_public_key_digest=str(
            config["trusted_verifier_public_key_digest"]
        ),
    )


def _resilience_proofs(config: Mapping[str, Any]) -> tuple[str, str]:
    path = Path(str(config["resilience_proof_index"]))
    if not path.is_file() or path.is_symlink():
        raise QualificationControlError("resilience proof index is unavailable")
    metadata = path.stat()
    if os.name != "nt" and (metadata.st_uid != 0 or metadata.st_mode & 0o022):
        raise QualificationControlError("resilience proof index is not root-owned immutable data")
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QualificationControlError("resilience proof index is unreadable") from error
    if not isinstance(envelope, dict):
        raise QualificationControlError("resilience proof index is not an object")
    digest = str(envelope.pop("proof_digest", ""))
    expected_keys = {
        "schema_version",
        "source_commit",
        "stable_release_digest",
        "candidate_digest",
        "backup_restore_proof_ref",
        "backup_restore_proof_digest",
        "backup_restore_proof_path",
        "rollback_proof_ref",
        "rollback_proof_digest",
        "rollback_proof_path",
    }
    if set(envelope) != expected_keys or sha256_text(stable_json(envelope)) != digest:
        raise QualificationControlError("resilience proof index digest differs")
    if (
        envelope.get("schema_version") != "1.0"
        or envelope.get("source_commit") != config["source_commit"]
        or envelope.get("stable_release_digest") != config["stable_release_digest"]
        or envelope.get("candidate_digest") != config["candidate_digest"]
    ):
        raise QualificationControlError("resilience proof release identity differs")
    references: list[str] = []
    for prefix in ("backup_restore", "rollback"):
        proof_path = Path(str(envelope[f"{prefix}_proof_path"]))
        proof_digest = str(envelope[f"{prefix}_proof_digest"])
        proof_ref = str(envelope[f"{prefix}_proof_ref"])
        if (
            not proof_path.is_absolute()
            or not proof_path.is_file()
            or proof_path.is_symlink()
            or not _SHA256.fullmatch(proof_digest)
            or proof_ref != f"artifact://qualification/resilience/{proof_digest}"
        ):
            raise QualificationControlError("resilience proof binding is invalid")
        proof_metadata = proof_path.stat()
        if os.name != "nt" and (proof_metadata.st_uid != 0 or proof_metadata.st_mode & 0o022):
            raise QualificationControlError("resilience proof is not root-owned immutable data")
        try:
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise QualificationControlError("resilience proof is unreadable") from error
        if not isinstance(proof, dict) or proof.pop("proof_digest", "") != proof_digest:
            raise QualificationControlError("resilience proof envelope is invalid")
        if sha256_text(stable_json(proof)) != proof_digest or proof.get("status") != "PASS":
            raise QualificationControlError("resilience proof did not pass")
        references.append(proof_ref)
    return references[0], references[1]


def _active_epoch(governor: ReleaseQualificationGovernor) -> str:
    rows = governor.connection.execute(
        """SELECT epoch_id FROM controller_release_epochs
            WHERE status NOT IN ('QUALIFICATION_FAILED','LTS')
            ORDER BY created_at DESC"""
    ).fetchall()
    if len(rows) != 1:
        raise QualificationControlError("qualification requires exactly one active epoch")
    return str(rows[0][0])


def _run_stage(
    stage: str,
    repository: Path,
    evidence_root: Path,
    *,
    q6_capability_attestation_path: Path,
    q6_capability_attestation_digest: str,
    expected_source_commit: str,
) -> QualificationStageReport:
    runners: dict[str, Callable[[], QualificationStageReport]] = {
        "Q0_SOURCE_INTEGRITY": lambda: run_q0(repository, evidence_root),
        "Q1_STATIC_CONTRACTS": lambda: run_q1(repository, evidence_root),
        "Q2_MODEL_CHECKING": lambda: run_q2(evidence_root),
        "Q3_PROPERTY_AND_MUTATION": lambda: run_q3(repository, evidence_root),
        "Q4_HISTORICAL_REPLAY": lambda: run_q4(repository, evidence_root),
        "Q5_MIGRATION_MATRIX": lambda: run_q5(evidence_root),
        "Q6_SERVICE_E2E": lambda: run_q6(
            repository,
            evidence_root,
            container_attestation_path=q6_capability_attestation_path,
            container_attestation_digest=q6_capability_attestation_digest,
            expected_source_commit=expected_source_commit,
        ),
    }
    try:
        runner = runners[stage]
    except KeyError as error:
        raise QualificationControlError("only Q0-Q6 are executable stages") from error
    return runner()


def _existing_run(
    governor: ReleaseQualificationGovernor,
    epoch_id: str,
    stage: str,
) -> dict[str, Any] | None:
    row = governor.connection.execute(
        "SELECT * FROM qualification_runs WHERE epoch_id=? AND stage=?",
        (epoch_id, stage),
    ).fetchone()
    return dict(row) if row is not None else None


def initialize_epoch(config: Mapping[str, Any]) -> str:
    state = _store(config)
    try:
        governor = _governor(state, config)
        existing = governor.connection.execute(
            """SELECT epoch_id,source_commit,candidate_digest
                 FROM controller_release_epochs
                WHERE status NOT IN ('QUALIFICATION_FAILED','LTS')"""
        ).fetchone()
        if existing is not None:
            if (
                str(existing["source_commit"]) != str(config["source_commit"])
                or str(existing["candidate_digest"]) != str(config["candidate_digest"])
            ):
                raise QualificationControlError("active epoch belongs to another candidate")
            return str(existing["epoch_id"])
        epoch_id = governor.create_epoch(
            source_commit=str(config["source_commit"]),
            stable_release_digest=str(config["stable_release_digest"]),
            controller_release_digest=str(config["controller_release_digest"]),
            candidate_digest=str(config["candidate_digest"]),
            policy_digest=str(config["policy_digest"]),
            toolchain_manifest_digest=str(config["toolchain_manifest_digest"]),
        )
        state._connection.commit()
        return epoch_id
    finally:
        state.close()


def run_and_record_stage(config: Mapping[str, Any], stage: str) -> tuple[str, str]:
    epoch_id = initialize_epoch(config)
    state = _store(config)
    try:
        governor = _governor(state, config)
        existing = _existing_run(governor, epoch_id, stage)
        if existing is not None:
            if str(existing["status"]) == "PASS":
                return epoch_id, str(existing["run_id"])
            raise QualificationControlError("qualification stage has already failed")
    finally:
        state.close()
    repository = Path(str(config["candidate_repository_root"])).resolve()
    evidence_root = Path(str(config["evidence_root"])).resolve()
    try:
        report = _run_stage(
            stage,
            repository,
            evidence_root,
            q6_capability_attestation_path=Path(
                str(config["q6_capability_attestation_path"])
            ),
            q6_capability_attestation_digest=str(
                config["q6_capability_attestation_digest"]
            ),
            expected_source_commit=str(config["source_commit"]),
        )
        if stage == "Q0_SOURCE_INTEGRITY":
            if report.artifacts.get("source_commit") != config["source_commit"]:
                raise QualificationControlError("Q0 source commit differs from root config")
            if report.artifacts.get("release_tree_digest") != config["candidate_digest"]:
                raise QualificationControlError("Q0 candidate digest differs from root config")
    except Exception as error:
        evidence_root.mkdir(parents=True, exist_ok=True)
        failure_coordinate = (
            error.safe_coordinate
            if isinstance(error, QualificationRunError)
            else f"{stage.lower()}-{type(error).__name__.lower()}"
        )
        payload = {
            "schema_version": "1.0",
            "stage": stage,
            "status": "FAIL",
            "error_type": type(error).__name__,
            "failure_coordinate": failure_coordinate,
            "source_commit": str(config["source_commit"]),
            "candidate_digest": str(config["candidate_digest"]),
            "created_at": utc_now(),
        }
        digest = sha256_text(stable_json(payload))
        envelope = {**payload, "report_digest": digest}
        failure_path = evidence_root / f"{stage.lower()}-{digest}.json"
        descriptor = os.open(
            failure_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o440,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        state = _store(config)
        try:
            governor = _governor(state, config)
            governor.record_qualification(
                epoch_id=epoch_id,
                stage=stage,
                evidence_ref=f"artifact://qualification/{stage.lower()}/{digest}",
                metrics={"unknown_transitions": 0},
                passed=False,
            )
            state._connection.commit()
        finally:
            state.close()
        raise
    state = _store(config)
    try:
        governor = _governor(state, config)
        run_id = governor.record_qualification(
            epoch_id=epoch_id,
            stage=stage,
            evidence_ref=report.evidence_ref,
            metrics=report.metrics,
            passed=True,
        )
        state._connection.commit()
        return epoch_id, run_id
    finally:
        state.close()


def finalize_shadow(
    config: Mapping[str, Any],
) -> tuple[str, str]:
    state = _store(config)
    try:
        governor = _governor(state, config)
        epoch_id = _active_epoch(governor)
        journal = ShadowEvidenceJournal(
            Path(str(config["shadow_journal_root"])), epoch_id=epoch_id
        )
        feeds = feed_paths(Path(str(config["shadow_feed_root"])))
        if not feeds or journal.entry_count() != len(feeds):
            raise QualificationControlError("Q7 has unverified shadow feed batches")
        first_batch = load_feed_batch(feeds[0])
        last_batch = load_feed_batch(feeds[-1])
        if int(first_batch["first_event_id"]) != 1:
            raise QualificationControlError("Q7 feed does not include complete history")
        historical_total = int(last_batch["stable_product_count"])
        if int(last_batch["last_event_id"]) < int(
            first_batch["stable_event_high_watermark"]
        ):
            raise QualificationControlError("Q7 historical high-watermark is incomplete")
        summary = journal.summarize()
        evidence_ref = (
            "artifact://qualification/shadow/" + summary.journal_head_digest
        )
        run_id = journal.finalize_q7(
            governor,
            evidence_ref=evidence_ref,
            historical_products_total=historical_total,
            historical_products_replayed=historical_total,
        )
        state._connection.commit()
        return epoch_id, run_id
    finally:
        state.close()


def fail_qualification_orchestration(
    config: Mapping[str, Any],
) -> tuple[str, str]:
    """Record a sanitized immutable failure when systemd cannot start Q0-Q6."""

    state = _store(config)
    try:
        governor = _governor(state, config)
        latest = governor.connection.execute(
            "SELECT * FROM controller_release_epochs ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        if latest is None:
            raise QualificationControlError("qualification epoch is unavailable")
        epoch_id = str(latest["epoch_id"])
        if str(latest["status"]) == "QUALIFICATION_FAILED":
            existing_ref = str(latest["failure_evidence_ref"] or "")
            if not existing_ref:
                raise QualificationControlError("failed epoch lacks immutable evidence")
            return epoch_id, existing_ref
        payload = {
            "schema_version": "1.0",
            "epoch_id": epoch_id,
            "status": "FAIL",
            "reason_code": "qualification_orchestrator_start_failed",
            "source_commit": str(config["source_commit"]),
            "candidate_digest": str(config["candidate_digest"]),
            "created_at": utc_now(),
        }
        digest = sha256_text(stable_json(payload))
        envelope = {**payload, "report_digest": digest}
        encoded = json.dumps(
            envelope,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ) + "\n"
        evidence_root = Path(str(config["evidence_root"])).resolve()
        evidence_root.mkdir(parents=True, exist_ok=True)
        failure_path = evidence_root / f"orchestration-failure-{digest}.json"
        descriptor = os.open(
            failure_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o440,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        evidence_ref = f"artifact://qualification/orchestration-failure/{digest}"
        governor.fail_orchestration(epoch_id=epoch_id, evidence_ref=evidence_ref)
        state._connection.commit()
        return epoch_id, evidence_ref
    finally:
        state.close()


_SHADOW_FAILURE_COMPONENTS = frozenset(
    {"export", "evaluate", "verify", "finalize"}
)


def fail_shadow_pipeline(
    config: Mapping[str, Any],
    component: str,
) -> tuple[str, str]:
    """Terminally fail Q7 with sanitized evidence for a failed shadow unit."""

    if component not in _SHADOW_FAILURE_COMPONENTS:
        raise QualificationControlError("shadow failure component is invalid")
    state = _store(config)
    try:
        governor = _governor(state, config)
        latest = governor.connection.execute(
            "SELECT * FROM controller_release_epochs ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        if latest is None:
            raise QualificationControlError("qualification epoch is unavailable")
        epoch_id = str(latest["epoch_id"])
        if str(latest["status"]) == "QUALIFICATION_FAILED":
            existing_ref = str(latest["failure_evidence_ref"] or "")
            if not existing_ref:
                raise QualificationControlError("failed epoch lacks immutable evidence")
            return epoch_id, existing_ref
        if str(latest["status"]) != "SHADOW_RUNNING":
            raise QualificationControlError(
                "shadow pipeline failure requires an active Q7 epoch"
            )
        failure_coordinate = f"q7_shadow_pipeline-{component}"
        payload = {
            "schema_version": "1.0",
            "epoch_id": epoch_id,
            "stage": "Q7_SHADOW_DIFFERENTIAL",
            "status": "FAIL",
            "reason_code": "shadow_pipeline_unit_failed",
            "failure_coordinate": failure_coordinate,
            "source_commit": str(config["source_commit"]),
            "candidate_digest": str(config["candidate_digest"]),
            "created_at": utc_now(),
        }
        digest = sha256_text(stable_json(payload))
        envelope = {**payload, "report_digest": digest}
        encoded = json.dumps(
            envelope,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ) + "\n"
        evidence_root = Path(str(config["evidence_root"])).resolve()
        evidence_root.mkdir(parents=True, exist_ok=True)
        failure_path = evidence_root / f"shadow-pipeline-failure-{digest}.json"
        descriptor = os.open(
            failure_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o440,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        evidence_ref = f"artifact://qualification/shadow-pipeline-failure/{digest}"
        governor.record_qualification(
            epoch_id=epoch_id,
            stage="Q7_SHADOW_DIFFERENTIAL",
            evidence_ref=evidence_ref,
            metrics={
                "unknown_transitions": 0,
                "failure_coordinate": failure_coordinate,
            },
            passed=False,
        )
        state._connection.commit()
        return epoch_id, evidence_ref
    finally:
        state.close()


def shadow_finalization_ready(config: Mapping[str, Any]) -> tuple[str, bool]:
    """Return true only when verifier-clock Q7 duration has really elapsed."""

    state = _store(config)
    try:
        governor = _governor(state, config)
        epoch_id = _active_epoch(governor)
        epoch = governor.epoch(epoch_id)
        if str(epoch["status"]) != "SHADOW_RUNNING":
            return epoch_id, False
        raw_started = str(epoch.get("shadow_started_at") or "")
        try:
            started = datetime.fromisoformat(raw_started)
        except ValueError as error:
            raise QualificationControlError(
                "shadow start timestamp is invalid"
            ) from error
        if started.tzinfo is None:
            raise QualificationControlError("shadow start timestamp lacks timezone")
        observed_hours = (datetime.now(UTC) - started).total_seconds() / 3600
        return epoch_id, observed_hours >= governor.thresholds.minimum_shadow_hours
    finally:
        state.close()


def clean_canary_ready(config: Mapping[str, Any]) -> tuple[str, bool]:
    """Return true only after the governor has persisted Q7 PASS."""

    state = _store(config)
    try:
        governor = _governor(state, config)
        epoch_id = _active_epoch(governor)
        epoch = governor.epoch(epoch_id)
        q7 = governor.connection.execute(
            """SELECT status FROM qualification_runs
                 WHERE epoch_id=? AND stage='Q7_SHADOW_DIFFERENTIAL'""",
            (epoch_id,),
        ).fetchone()
        return (
            epoch_id,
            str(epoch["status"]) == "CLEAN_CANARY"
            and q7 is not None
            and str(q7["status"]) == "PASS",
        )
    finally:
        state.close()


def verify_shadow_batches(config: Mapping[str, Any]) -> tuple[str, int, int]:
    """Compare each Stable A feed batch with the separately produced B output."""

    state = _store(config)
    try:
        governor = _governor(state, config)
        epoch_id = _active_epoch(governor)
        if str(governor.epoch(epoch_id)["status"]) != "SHADOW_RUNNING":
            raise QualificationControlError("shadow verification requires Q0-Q6 PASS")
        feed_root = Path(str(config["shadow_feed_root"]))
        output_root = Path(str(config["candidate_shadow_output_root"]))
        journal = ShadowEvidenceJournal(
            Path(str(config["shadow_journal_root"])), epoch_id=epoch_id
        )
        feeds = feed_paths(feed_root)
        processed = journal.entry_count()
        if processed > len(feeds):
            raise QualificationControlError("shadow journal exceeds the stable feed")
        prior_last = 0
        for feed_path in feeds:
            batch = load_feed_batch(feed_path)
            first_id = int(batch["first_event_id"])
            last_id = int(batch["last_event_id"])
            if first_id != prior_last + 1:
                raise QualificationControlError("shadow feed event sequence has a gap")
            prior_last = last_id
        verified_events = 0
        for feed_path in feeds[processed:]:
            batch = load_feed_batch(feed_path)
            source_digest = str(batch["batch_digest"])
            candidate_values = load_candidate_evaluation(
                output_root / f"{source_digest}.json",
                source_batch_digest=source_digest,
            )
            candidate_by_event = {
                str(value["event_digest"]): dict(value["decision"])
                for value in candidate_values
            }
            events = list(batch["events"])
            expected_event_digests = {
                sha256_text(stable_json(event)) for event in events
            }
            if set(candidate_by_event) != expected_event_digests:
                raise QualificationControlError("candidate shadow decision set differs")

            def candidate_decide(
                event: Mapping[str, Any],
                decisions: Mapping[str, Mapping[str, Any]] = candidate_by_event,
            ) -> Mapping[str, Any]:
                return decisions[sha256_text(stable_json(dict(event)))]

            stable_root = Path(str(config["stable_release_root"]))
            candidate_root = Path(str(config["candidate_repository_root"]))
            verifier_root = Path(str(config["evidence_root"])).parent
            layout = TwoPlaneLayout(
                stable_a=PlaneBoundary(
                    "LTS_A",
                    stable_root,
                    stable_root / ".shadow-no-database",
                    frozenset(),
                    True,
                    True,
                ),
                candidate_b=PlaneBoundary(
                    "CANDIDATE_B",
                    candidate_root,
                    Path(str(config["candidate_database"])),
                    frozenset(),
                    False,
                    False,
                ),
                verifier=PlaneBoundary(
                    "INDEPENDENT_VERIFIER",
                    verifier_root,
                    Path(str(config["governor_database"])),
                    frozenset(),
                    False,
                    False,
                ),
            )
            report = ShadowDifferentialLab(
                layout=layout,
                governor=governor,
                epoch_id=epoch_id,
                stable_decide=stable_observed_decision,
                candidate_decide=candidate_decide,
            ).replay(events)
            state._connection.commit()
            journal.append(report, observed_at=str(batch["exported_at"]))
            verified_events += report.event_count
        return epoch_id, len(feeds) - processed, verified_events
    finally:
        state.close()


def start_canary(
    config: Mapping[str, Any],
    *,
    scenario_id: str,
    candidate_database: Path,
) -> tuple[str, str, str]:
    catalog = load_canary_catalog(Path(str(config["canary_catalog_path"])))
    if scenario_id not in catalog:
        raise QualificationControlError("clean canary scenario is unknown")
    indexed = _canary_index(config)[scenario_id]
    if str(indexed["scenario_digest"]) != catalog[scenario_id].scenario_digest:
        raise QualificationControlError("clean canary indexed scenario digest differs")
    if candidate_database.resolve() != Path(str(indexed["database_path"])).resolve():
        raise QualificationControlError("clean canary database differs from root index")
    evidence_root = Path(str(config["evidence_root"])) / "canaries" / scenario_id
    proof = prove_fresh_state(candidate_database, evidence_root)
    state = _store(config)
    try:
        governor = _governor(state, config)
        epoch_id = _active_epoch(governor)
        canary_id = governor.start_clean_canary(
            epoch_id=epoch_id,
            scenario_id=scenario_id,
            state_fresh_proof_ref=proof.evidence_ref,
            initial_state_digest=proof.initial_state_digest,
        )
        state._connection.commit()
        return epoch_id, canary_id, proof.evidence_ref
    finally:
        state.close()


def complete_canary(
    config: Mapping[str, Any],
    *,
    canary_id: str,
    product_id: str,
    candidate_database: Path,
) -> tuple[str, str]:
    state = _store(config)
    try:
        governor = _governor(state, config)
        epoch_id = _active_epoch(governor)
        canary = governor.clean_canary(canary_id)
        if str(canary["epoch_id"]) != epoch_id:
            raise QualificationControlError("clean canary belongs to another epoch")
        indexed = _canary_index(config)[str(canary["scenario_id"])]
        if candidate_database.resolve() != Path(str(indexed["database_path"])).resolve():
            raise QualificationControlError("clean canary database differs from root index")
        evidence_root = (
            Path(str(config["evidence_root"]))
            / "canaries"
            / str(canary["scenario_id"])
        )
        observation = observe_completion(
            candidate_database,
            evidence_root,
            product_id=product_id,
            expected_controller_release_digest=str(config["controller_release_digest"]),
            scenario=load_canary_catalog(
                Path(str(config["canary_catalog_path"]))
            )[str(canary["scenario_id"])],
            fault_receipt_root=Path(str(indexed["fault_receipt_root"])),
            expected_candidate_digest=str(config["candidate_digest"]),
        )
        complete_observed_canary(
            governor,
            epoch_id=epoch_id,
            canary_id=canary_id,
            observation=observation,
        )
        state._connection.commit()
        return epoch_id, observation.evidence_ref
    finally:
        state.close()


def fail_canary(
    config: Mapping[str, Any],
    *,
    canary_id: str,
    reason: str,
) -> tuple[str, str]:
    state = _store(config)
    try:
        governor = _governor(state, config)
        epoch_id = _active_epoch(governor)
        canary = governor.clean_canary(canary_id)
        if str(canary["epoch_id"]) != epoch_id:
            raise QualificationControlError("clean canary belongs to another epoch")
        payload = {
            "schema_version": "1.0",
            "epoch_id": epoch_id,
            "canary_id": canary_id,
            "scenario_id": str(canary["scenario_id"]),
            "reason": reason,
            "candidate_digest": str(config["candidate_digest"]),
            "controller_release_digest": str(config["controller_release_digest"]),
        }
        digest = sha256_text(stable_json(payload))
        destination = Path(str(config["evidence_root"])) / f"canary-failure-{digest}.json"
        encoded = json.dumps(
            {**payload, "report_digest": digest},
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ) + "\n"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if destination.is_symlink() or destination.read_text(encoding="utf-8") != encoded:
                raise QualificationControlError("clean canary failure evidence conflicts")
        else:
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        evidence_ref = f"artifact://qualification/canary-failure/{digest}"
        governor.fail_clean_canary(
            epoch_id=epoch_id,
            canary_id=canary_id,
            reason=reason,
            evidence_ref=evidence_ref,
        )
        state._connection.commit()
        return epoch_id, evidence_ref
    finally:
        state.close()


def _stage_report_payload(
    governor: ReleaseQualificationGovernor,
    config: Mapping[str, Any],
    *,
    epoch_id: str,
    stage: str,
) -> dict[str, Any]:
    run = _existing_run(governor, epoch_id, stage)
    if run is None or str(run["status"]) != "PASS":
        raise QualificationControlError(f"{stage} report is unavailable")
    report_digest = str(run["evidence_ref"]).rsplit("/", 1)[-1]
    if not _SHA256.fullmatch(report_digest):
        raise QualificationControlError("qualification evidence reference is invalid")
    path = Path(str(config["evidence_root"])) / f"{stage.lower()}-{report_digest}.json"
    if not path.is_file() or path.is_symlink():
        raise QualificationControlError("qualification evidence file is unavailable")
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QualificationControlError("qualification evidence file is unreadable") from error
    if not isinstance(envelope, dict):
        raise QualificationControlError("qualification evidence is not an object")
    observed_digest = str(envelope.pop("report_digest", ""))
    if observed_digest != report_digest or sha256_text(stable_json(envelope)) != report_digest:
        raise QualificationControlError("qualification evidence digest differs")
    if envelope.get("stage") != stage or envelope.get("status") != "PASS":
        raise QualificationControlError("qualification evidence stage differs")
    return {**envelope, "report_digest": observed_digest}


def create_manifest_request(
    config: Mapping[str, Any],
) -> tuple[str, str]:
    """Build the exact unsigned bytes accepted by the isolated signer."""

    state = _store(config)
    try:
        governor = _governor(state, config)
        epoch_id = _active_epoch(governor)
        q2 = _stage_report_payload(
            governor, config, epoch_id=epoch_id, stage="Q2_MODEL_CHECKING"
        )
        q4 = _stage_report_payload(
            governor, config, epoch_id=epoch_id, stage="Q4_HISTORICAL_REPLAY"
        )
        q5 = _stage_report_payload(
            governor, config, epoch_id=epoch_id, stage="Q5_MIGRATION_MATRIX"
        )
        q4_artifacts = _mapping(q4.get("artifacts"), "Q4 artifacts")
        q5_artifacts = _mapping(q5.get("artifacts"), "Q5 artifacts")
        shadow = ShadowEvidenceJournal(
            Path(str(config["shadow_journal_root"])), epoch_id=epoch_id
        ).summarize()
        shadow_ref = "artifact://qualification/shadow/" + shadow.journal_head_digest
        manifest_ref = f"worm://qualification/{config['source_commit']}.json"
        backup_restore_proof_ref, rollback_proof_ref = _resilience_proofs(config)
        payload = governor.qualification_manifest_payload(
            epoch_id=epoch_id,
            verifier_digest=str(config["verifier_digest"]),
            verifier_public_key=str(config["verifier_public_key"]),
            transition_model_digest=str(q2["report_digest"]),
            historical_corpus_digest=str(q4_artifacts["corpus_digest"]),
            migration_matrix_digest=str(q5_artifacts["matrix_digest"]),
            manifest_ref=manifest_ref,
            backup_restore_proof_ref=backup_restore_proof_ref,
            rollback_proof_ref=rollback_proof_ref,
            shadow_report_ref=shadow_ref,
        )
        destination = Path(str(config["manifest_request_path"]))
        encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if destination.exists():
            if destination.is_symlink() or destination.read_text(encoding="utf-8") != encoded:
                raise QualificationControlError("immutable manifest request conflicts")
        else:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o440,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        return epoch_id, sha256_text(stable_json(payload))
    finally:
        state.close()


def admit_signed_manifest(config: Mapping[str, Any]) -> tuple[str, str]:
    """Verify and persist the independently signed envelope in governor state."""

    source = Path(str(config["signed_manifest_path"]))
    if not source.is_file() or source.is_symlink():
        raise QualificationControlError("signed qualification manifest is unavailable")
    try:
        envelope = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QualificationControlError("signed qualification manifest is unreadable") from error
    if not isinstance(envelope, Mapping):
        raise QualificationControlError("signed qualification manifest is not an object")
    payload = dict(envelope)
    envelope_digest = verify_qualification_manifest_envelope(
        payload,
        trusted_verifier_public_key_digest=str(
            config["trusted_verifier_public_key_digest"]
        ),
        expected_source_commit=str(config["source_commit"]),
        expected_candidate_digest=str(config["candidate_digest"]),
    )
    state = _store(config)
    try:
        governor = _governor(state, config)
        epoch_id = _active_epoch(governor)
        existing = governor.connection.execute(
            """SELECT manifest_id,manifest_digest
                 FROM release_qualification_manifests WHERE epoch_id=?""",
            (epoch_id,),
        ).fetchone()
        if existing is not None:
            if str(existing["manifest_digest"]) != envelope_digest:
                raise QualificationControlError("admitted manifest conflicts")
            return epoch_id, str(existing["manifest_id"])
        manifest_id = governor.create_qualification_manifest(
            epoch_id=epoch_id,
            verifier_digest=str(config["verifier_digest"]),
            verifier_public_key=str(config["verifier_public_key"]),
            verifier_signature=str(payload["verifier_signature"]),
            transition_model_digest=str(payload["transition_model_digest"]),
            historical_corpus_digest=str(payload["historical_corpus_digest"]),
            migration_matrix_digest=str(payload["migration_matrix_digest"]),
            manifest_ref=str(payload["manifest_ref"]),
            backup_restore_proof_ref=str(payload["backup_restore_proof_ref"]),
            rollback_proof_ref=str(payload["rollback_proof_ref"]),
            shadow_report_ref=str(payload["shadow_report_ref"]),
        )
        state._connection.commit()
        return epoch_id, manifest_id
    finally:
        state.close()


def observe_promotion(config: Mapping[str, Any]) -> tuple[str, str]:
    """Independently bind the root helper receipt to the exact promoted tree."""

    receipt_path = Path(str(config["promotion_receipt_path"]))
    if not receipt_path.is_file() or receipt_path.is_symlink():
        raise QualificationControlError("root promotion receipt is unavailable")
    metadata = receipt_path.stat()
    if os.name != "nt" and (metadata.st_uid != 0 or metadata.st_mode & 0o022):
        raise QualificationControlError("root promotion receipt is not immutable")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QualificationControlError("root promotion receipt is unreadable") from error
    if not isinstance(receipt, dict):
        raise QualificationControlError("root promotion receipt is not an object")
    signed_path = Path(str(config["signed_manifest_path"]))
    signed = _mapping(
        json.loads(signed_path.read_text(encoding="utf-8")),
        "signed qualification manifest",
    )
    manifest_digest = verify_qualification_manifest_envelope(
        signed,
        trusted_verifier_public_key_digest=str(
            config["trusted_verifier_public_key_digest"]
        ),
        expected_source_commit=str(config["source_commit"]),
        expected_candidate_digest=str(config["candidate_digest"]),
    )
    expected_receipt = {
        "schema_version": "1.0",
        "status": "PROMOTED",
        "repository": str(config["factory_repository"]),
        "product_id": "",
        "release_id": str(config["source_commit"]),
        "image_digest": "sha256:" + str(config["candidate_digest"]),
        "qualification_manifest_digest": manifest_digest,
    }
    if receipt != expected_receipt:
        raise QualificationControlError("root promotion receipt differs from manifest")
    from factory.release_executor import _release_digest

    production_digest = _release_digest(
        Path(str(config["stable_release_root"]))
    ).removeprefix("sha256:")
    if production_digest != str(config["candidate_digest"]):
        raise QualificationControlError("production tree differs from qualified candidate")
    state = _store(config)
    try:
        governor = _governor(state, config)
        epoch_id = _active_epoch(governor)
        epoch = governor.epoch(epoch_id)
        if str(epoch["status"]) == "PROMOTED":
            return epoch_id, str(epoch["promotion_receipt_ref"])
        manifest = governor.connection.execute(
            "SELECT manifest_id FROM release_qualification_manifests WHERE epoch_id=?",
            (epoch_id,),
        ).fetchone()
        if manifest is None:
            raise QualificationControlError("admitted qualification manifest is unavailable")
        receipt_digest = sha256_text(stable_json(receipt))
        receipt_ref = f"artifact://root-promotion/{receipt_digest}"
        governor.promote(
            epoch_id=epoch_id,
            manifest_id=str(manifest["manifest_id"]),
            caller_plane="LTS_A",
            root_helper_receipt_ref=receipt_ref,
            exact_staging_production_digest=production_digest,
        )
        state._connection.commit()
        return epoch_id, receipt_ref
    finally:
        state.close()


def _root_proof(
    path: Path,
    *,
    proof_type: str,
    config: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    if not path.is_file() or path.is_symlink():
        raise QualificationControlError("root production proof is unavailable")
    metadata = path.stat()
    if os.name != "nt" and (metadata.st_uid != 0 or metadata.st_mode & 0o022):
        raise QualificationControlError("root production proof is not immutable")
    try:
        proof = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QualificationControlError("root production proof is unreadable") from error
    if not isinstance(proof, dict):
        raise QualificationControlError("root production proof is not an object")
    digest = str(proof.pop("proof_digest", ""))
    if (
        not _SHA256.fullmatch(digest)
        or sha256_text(stable_json(proof)) != digest
        or proof.get("schema_version") != "1.0"
        or proof.get("proof_type") != proof_type
        or proof.get("status") != "PASS"
        or proof.get("candidate_digest") != config["candidate_digest"]
    ):
        raise QualificationControlError("root production proof identity differs")
    return proof, digest


def observe_lts_graduation(config: Mapping[str, Any]) -> tuple[str, str]:
    proof, digest = _root_proof(
        Path(str(config["production_observation_path"])),
        proof_type="PRODUCTION_OBSERVATION",
        config=config,
    )
    if (
        float(proof.get("elapsed_hours", 0)) < 24
        or int(proof.get("entry_count", 0)) < 720
        or int(proof.get("controller_incidents", -1)) != 0
        or int(proof.get("digest_divergences", -1)) != 0
        or int(proof.get("health_failures", -1)) != 0
    ):
        raise QualificationControlError("production observation threshold failed")
    state = _store(config)
    try:
        governor = _governor(state, config)
        epoch_id = _active_epoch(governor)
        evidence_ref = f"artifact://production-observation/{digest}"
        governor.graduate_lts(
            epoch_id=epoch_id,
            observation_evidence_ref=evidence_ref,
        )
        state._connection.commit()
        return epoch_id, evidence_ref
    finally:
        state.close()


def observe_production_failure(config: Mapping[str, Any]) -> tuple[str, str]:
    proof, digest = _root_proof(
        Path(str(config["production_rollback_path"])),
        proof_type="PRODUCTION_ROLLBACK",
        config=config,
    )
    if (
        proof.get("release_id") != config["source_commit"]
        or proof.get("stable_release_digest") != config["stable_release_digest"]
        or proof.get("restored_release_digest") != config["stable_release_digest"]
        or proof.get("stable_health") != "PASS"
    ):
        raise QualificationControlError("production rollback postcondition differs")
    state = _store(config)
    try:
        governor = _governor(state, config)
        epoch_id = _active_epoch(governor)
        evidence_ref = f"artifact://production-rollback/{digest}"
        governor.fail_production_observation(
            epoch_id=epoch_id,
            rollback_evidence_ref=evidence_ref,
        )
        state._connection.commit()
        return epoch_id, evidence_ref
    finally:
        state.close()


def status(config: Mapping[str, Any]) -> dict[str, Any]:
    state = _store(config)
    try:
        governor = _governor(state, config)
        try:
            epoch_id = _active_epoch(governor)
        except QualificationControlError:
            latest = governor.connection.execute(
                "SELECT epoch_id FROM controller_release_epochs ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            if latest is None:
                raise
            epoch_id = str(latest["epoch_id"])
        epoch = governor.epoch(epoch_id)
        runs = governor.qualification_runs(epoch_id)
        canaries = governor.connection.execute(
            """SELECT canary_id,scenario_id,status,product_id
                 FROM clean_canary_runs WHERE epoch_id=? ORDER BY scenario_id""",
            (epoch_id,),
        ).fetchall()
        return {
            "epoch_id": epoch_id,
            "status": str(epoch["status"]),
            "source_commit": str(epoch["source_commit"]),
            "candidate_digest": str(epoch["candidate_digest"]),
            "qualification_stages": [
                {"stage": str(row["stage"]), "status": str(row["status"])}
                for row in runs
            ],
            "clean_canaries": [dict(row) for row in canaries],
        }
    finally:
        state.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/hermes-factory/qualification-control.yaml"),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    commands.add_parser("orchestration-fail")
    shadow_fail = commands.add_parser("shadow-fail")
    shadow_fail.add_argument("component", choices=sorted(_SHADOW_FAILURE_COMPONENTS))
    stage = commands.add_parser("stage")
    stage.add_argument("stage", choices=QUALIFICATION_STAGES[:7])
    commands.add_parser("shadow-verify")
    commands.add_parser("shadow-ready")
    commands.add_parser("shadow-finalize")
    commands.add_parser("canary-ready")
    start = commands.add_parser("canary-start")
    start.add_argument("scenario_id")
    start.add_argument("--candidate-database", type=Path, required=True)
    complete = commands.add_parser("canary-complete")
    complete.add_argument("canary_id")
    complete.add_argument("product_id")
    complete.add_argument("--candidate-database", type=Path, required=True)
    failed = commands.add_parser("canary-fail")
    failed.add_argument("canary_id")
    failed.add_argument(
        "reason",
        choices=("terminal_failure", "timeout", "orchestrator_error"),
    )
    commands.add_parser("manifest-request")
    commands.add_parser("manifest-admit")
    commands.add_parser("promotion-observe")
    commands.add_parser("lts-observe")
    commands.add_parser("production-fail")
    commands.add_parser("status")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        config = _load_config(args.config)
        if args.command == "init":
            result: dict[str, Any] = {"epoch_id": initialize_epoch(config)}
        elif args.command == "orchestration-fail":
            epoch_id, evidence_ref = fail_qualification_orchestration(config)
            result = {
                "epoch_id": epoch_id,
                "failure_evidence_ref": evidence_ref,
            }
        elif args.command == "shadow-fail":
            epoch_id, evidence_ref = fail_shadow_pipeline(config, args.component)
            result = {
                "epoch_id": epoch_id,
                "failure_evidence_ref": evidence_ref,
            }
        elif args.command == "stage":
            epoch_id, run_id = run_and_record_stage(config, args.stage)
            result = {"epoch_id": epoch_id, "run_id": run_id, "stage": args.stage}
        elif args.command == "shadow-verify":
            epoch_id, batch_count, event_count = verify_shadow_batches(config)
            result = {
                "epoch_id": epoch_id,
                "verified_batch_count": batch_count,
                "verified_event_count": event_count,
            }
        elif args.command == "shadow-ready":
            epoch_id, ready = shadow_finalization_ready(config)
            result = {"epoch_id": epoch_id, "ready": ready}
            if not ready:
                print(stable_json({"status": "WAIT", **result}))
                return 1
        elif args.command == "shadow-finalize":
            epoch_id, run_id = finalize_shadow(config)
            result = {"epoch_id": epoch_id, "run_id": run_id}
        elif args.command == "canary-ready":
            epoch_id, ready = clean_canary_ready(config)
            result = {"epoch_id": epoch_id, "ready": ready}
            if not ready:
                print(stable_json({"status": "WAIT", **result}))
                return 1
        elif args.command == "canary-start":
            epoch_id, canary_id, proof_ref = start_canary(
                config,
                scenario_id=args.scenario_id,
                candidate_database=args.candidate_database,
            )
            result = {
                "epoch_id": epoch_id,
                "canary_id": canary_id,
                "state_fresh_proof_ref": proof_ref,
            }
        elif args.command == "canary-complete":
            epoch_id, evidence_ref = complete_canary(
                config,
                canary_id=args.canary_id,
                product_id=args.product_id,
                candidate_database=args.candidate_database,
            )
            result = {"epoch_id": epoch_id, "observation_evidence_ref": evidence_ref}
        elif args.command == "canary-fail":
            epoch_id, evidence_ref = fail_canary(
                config,
                canary_id=args.canary_id,
                reason=args.reason,
            )
            result = {"epoch_id": epoch_id, "failure_evidence_ref": evidence_ref}
        elif args.command == "manifest-request":
            epoch_id, request_digest = create_manifest_request(config)
            result = {"epoch_id": epoch_id, "request_digest": request_digest}
        elif args.command == "manifest-admit":
            epoch_id, manifest_id = admit_signed_manifest(config)
            result = {"epoch_id": epoch_id, "manifest_id": manifest_id}
        elif args.command == "promotion-observe":
            epoch_id, receipt_ref = observe_promotion(config)
            result = {"epoch_id": epoch_id, "promotion_receipt_ref": receipt_ref}
        elif args.command == "lts-observe":
            epoch_id, evidence_ref = observe_lts_graduation(config)
            result = {"epoch_id": epoch_id, "observation_evidence_ref": evidence_ref}
        elif args.command == "production-fail":
            epoch_id, evidence_ref = observe_production_failure(config)
            result = {"epoch_id": epoch_id, "rollback_evidence_ref": evidence_ref}
        else:
            result = status(config)
    except (
        QualificationControlError,
        QualificationRunError,
        QualificationError,
        CanaryObservationError,
        ShadowJournalError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        yaml.YAMLError,
    ) as error:
        print(
            stable_json({"status": "FAIL", "error_type": type(error).__name__}),
            file=sys.stderr,
        )
        return 255 if args.command in {"shadow-ready", "canary-ready"} else 1
    print(stable_json({"status": "PASS", **result}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
