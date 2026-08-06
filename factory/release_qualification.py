"""Independent release-epoch governor for Stable A and Candidate B."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .common import sha256_text, stable_json, utc_now

_SHA256 = re.compile(r"[a-f0-9]{64}")
_SHA40 = re.compile(r"[a-f0-9]{40}")
_IMMUTABLE_REF = re.compile(
    r"^(?:artifact|b2|evidence|github|oci|s3|state|worm)://[^\s]+$"
)


class QualificationError(RuntimeError):
    """A candidate violated an ordered qualification or independence gate."""


class ReleaseEpochState(StrEnum):
    CANDIDATE_BUILT = "CANDIDATE_BUILT"
    STATIC_QUALIFIED = "STATIC_QUALIFIED"
    MODEL_CHECKED = "MODEL_CHECKED"
    MIGRATION_REPLAYED = "MIGRATION_REPLAYED"
    FUNCTIONAL_PENDING = "FUNCTIONAL_PENDING"
    SHADOW_RUNNING = "SHADOW_RUNNING"
    CLEAN_CANARY = "CLEAN_CANARY"
    PROMOTION_READY = "PROMOTION_READY"
    PROMOTED = "PROMOTED"
    LTS = "LTS"
    QUALIFICATION_FAILED = "QUALIFICATION_FAILED"


QUALIFICATION_STAGES: Final[tuple[str, ...]] = (
    "Q0_SOURCE_INTEGRITY",
    "Q1_STATIC_CONTRACTS",
    "Q2_MODEL_CHECKING",
    "Q3_PROPERTY_AND_MUTATION",
    "Q4_HISTORICAL_REPLAY",
    "Q5_MIGRATION_MATRIX",
    "Q6_SERVICE_E2E",
    "Q7_SHADOW_DIFFERENTIAL",
)

REQUIRED_CANARY_SCENARIOS: Final[frozenset[str]] = frozenset(
    {
        "zero-dependency-cli",
        "small-python-service",
        "telegram-bot",
        "existing-repository-repair",
        "high-fan-in",
        "external-blocker-resume",
        "provider-timeout-restart",
        "failed-product-test-one-repair",
        "package-only",
        "deploy-rollback",
    }
)

_CANARY_REPORT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "canary_id",
        "scenario_id",
        "product_id",
        "state_fresh_proof_ref",
        "initial_state_digest",
        "controller_release_digest",
        "completion_manifest_ref",
        "observation_evidence_ref",
        "observation_digest",
        "controller_recovery_applications",
        "manual_database_mutations",
        "routine_owner_actions",
        "unknown_controller_defects",
        "release_changes",
        "duplicate_side_effects",
        "task_count",
        "baseline_task_count",
    }
)


@dataclass(frozen=True)
class QualificationThresholds:
    transition_coverage_percent: int = 100
    mutation_score_percent: int = 90
    historical_replay_percent: int = 100
    migration_matrix_percent: int = 100
    minimum_shadow_hours: float = 72.0
    minimum_clean_canaries: int = 10
    maximum_task_amplification_ratio: float = 1.2
    maximum_evidence_indirection: int = 1
    maximum_shadow_heartbeat_gap_seconds: float = 300.0


def _digest(name: str, value: str) -> str:
    if not _SHA256.fullmatch(str(value)):
        raise QualificationError(f"{name} must be a lowercase SHA-256")
    return str(value)


def _immutable_ref(name: str, value: str) -> str:
    if not _IMMUTABLE_REF.fullmatch(str(value)):
        raise QualificationError(f"{name} must be an immutable evidence URI")
    return str(value)


def _strict_bool_metric(metrics: Mapping[str, Any], key: str) -> bool:
    value = metrics.get(key)
    if value is not True:
        raise QualificationError(f"qualification requires {key}=true")
    return True


def _zero_metric(metrics: Mapping[str, Any], key: str) -> None:
    value = metrics.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value != 0:
        raise QualificationError(f"qualification requires {key}=0")


def _positive_metric(metrics: Mapping[str, Any], key: str) -> int:
    value = metrics.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise QualificationError(f"qualification requires {key}>=1")
    return value


def _decode_verifier_key(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise QualificationError("verifier public key is not canonical base64") from error
    if len(decoded) != 32:
        raise QualificationError("verifier public key is not an Ed25519 public key")
    return decoded


def verify_qualification_manifest_envelope(
    envelope: Mapping[str, Any],
    *,
    trusted_verifier_public_key_digest: str,
    expected_source_commit: str,
    expected_candidate_digest: str,
) -> str:
    """Verify the complete independent manifest at the root-owned boundary."""

    trust_digest = _digest(
        "trusted_verifier_public_key_digest",
        trusted_verifier_public_key_digest,
    )
    if not _SHA40.fullmatch(expected_source_commit):
        raise QualificationError("expected source commit is invalid")
    candidate_digest = _digest("expected_candidate_digest", expected_candidate_digest)
    payload = dict(envelope)
    signature_text = str(payload.pop("verifier_signature", ""))
    expected_keys = {
        "schema_version",
        "epoch_id",
        "source_commit",
        "stable_release_digest",
        "controller_release_digest",
        "candidate_digest",
        "policy_digest",
        "toolchain_manifest_digest",
        "qualification_run_digests",
        "transition_model_digest",
        "historical_corpus_digest",
        "migration_matrix_digest",
        "clean_canary_reports",
        "verifier",
        "manifest_ref",
        "backup_restore_proof_ref",
        "rollback_proof_ref",
        "shadow_report_ref",
    }
    if set(payload) != expected_keys or payload.get("schema_version") != "1.0":
        raise QualificationError("qualification manifest schema is invalid")
    if payload.get("source_commit") != expected_source_commit:
        raise QualificationError("qualification manifest source commit differs")
    if payload.get("candidate_digest") != candidate_digest:
        raise QualificationError("qualification manifest candidate digest differs")
    for key in (
        "stable_release_digest",
        "controller_release_digest",
        "candidate_digest",
        "policy_digest",
        "toolchain_manifest_digest",
        "transition_model_digest",
        "historical_corpus_digest",
        "migration_matrix_digest",
    ):
        _digest(key, str(payload.get(key) or ""))
    for key in (
        "manifest_ref",
        "backup_restore_proof_ref",
        "rollback_proof_ref",
        "shadow_report_ref",
    ):
        _immutable_ref(key, str(payload.get(key) or ""))
    run_digests = payload.get("qualification_run_digests")
    if not isinstance(run_digests, list) or len(run_digests) != len(QUALIFICATION_STAGES):
        raise QualificationError("qualification manifest requires exact Q0-Q7 runs")
    for value in run_digests:
        _digest("qualification_run_digest", str(value))
    if len({str(value) for value in run_digests}) != len(run_digests):
        raise QualificationError("qualification run digests are not unique")

    canaries = payload.get("clean_canary_reports")
    if not isinstance(canaries, list) or len(canaries) != len(REQUIRED_CANARY_SCENARIOS):
        raise QualificationError("qualification manifest requires exactly ten canaries")
    scenarios: set[str] = set()
    for raw in canaries:
        if not isinstance(raw, Mapping) or set(raw) != _CANARY_REPORT_KEYS:
            raise QualificationError("clean canary report schema is invalid")
        scenario_id = str(raw["scenario_id"])
        scenarios.add(scenario_id)
        if str(raw["controller_release_digest"]) != str(
            payload["controller_release_digest"]
        ):
            raise QualificationError("clean canary controller release differs")
        _immutable_ref(
            "completion_manifest_ref", str(raw["completion_manifest_ref"])
        )
        _immutable_ref("state_fresh_proof_ref", str(raw["state_fresh_proof_ref"]))
        _immutable_ref(
            "observation_evidence_ref", str(raw["observation_evidence_ref"])
        )
        _digest("initial_state_digest", str(raw["initial_state_digest"]))
        _digest("observation_digest", str(raw["observation_digest"]))
        if not str(raw["product_id"]):
            raise QualificationError("clean canary product identity is missing")
        for key in (
            "controller_recovery_applications",
            "manual_database_mutations",
            "routine_owner_actions",
            "unknown_controller_defects",
            "release_changes",
            "duplicate_side_effects",
        ):
            _zero_metric(raw, key)
        task_count = raw["task_count"]
        baseline_count = raw["baseline_task_count"]
        if (
            isinstance(task_count, bool)
            or not isinstance(task_count, int)
            or task_count < 1
            or isinstance(baseline_count, bool)
            or not isinstance(baseline_count, int)
            or baseline_count < 1
            or task_count / baseline_count > 1.2
        ):
            raise QualificationError("clean canary task cardinality is invalid")
    if scenarios != set(REQUIRED_CANARY_SCENARIOS):
        raise QualificationError("clean canary archetype set is incomplete")

    verifier = payload.get("verifier")
    if not isinstance(verifier, Mapping) or set(verifier) != {
        "digest",
        "public_key",
        "public_key_digest",
        "signature_algorithm",
    }:
        raise QualificationError("independent verifier identity is invalid")
    verifier_digest = _digest("verifier_digest", str(verifier.get("digest") or ""))
    if verifier_digest in {
        str(payload["candidate_digest"]),
        str(payload["controller_release_digest"]),
        str(payload["stable_release_digest"]),
    }:
        raise QualificationError("independent verifier digest is not independent")
    if verifier.get("signature_algorithm") != "Ed25519":
        raise QualificationError("qualification signature algorithm is unsupported")
    public_key = _decode_verifier_key(str(verifier.get("public_key") or ""))
    public_key_digest = hashlib.sha256(public_key).hexdigest()
    if (
        verifier.get("public_key_digest") != public_key_digest
        or public_key_digest != trust_digest
    ):
        raise QualificationError("verifier key does not match root trust")
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise QualificationError("verifier signature is not canonical base64") from error
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            stable_json(payload).encode("utf-8"),
        )
    except (InvalidSignature, ValueError) as error:
        raise QualificationError("independent verifier signature is invalid") from error
    return sha256_text(stable_json(dict(envelope)))


class ReleaseQualificationGovernor:
    """Durable authority that Candidate B cannot bypass or self-promote through."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        thresholds: QualificationThresholds | None = None,
        trusted_verifier_public_key_digest: str | None = None,
    ) -> None:
        self.connection = connection
        self.thresholds = thresholds or QualificationThresholds()
        self.trusted_verifier_public_key_digest = (
            _digest(
                "trusted_verifier_public_key_digest",
                trusted_verifier_public_key_digest,
            )
            if trusted_verifier_public_key_digest is not None
            else None
        )

    def create_epoch(
        self,
        *,
        source_commit: str,
        controller_release_digest: str,
        candidate_digest: str,
        policy_digest: str,
        toolchain_manifest_digest: str,
        stable_release_digest: str,
    ) -> str:
        if not _SHA40.fullmatch(source_commit):
            raise QualificationError("source_commit must be a lowercase Git SHA")
        values = {
            "controller_release_digest": _digest(
                "controller_release_digest", controller_release_digest
            ),
            "candidate_digest": _digest("candidate_digest", candidate_digest),
            "policy_digest": _digest("policy_digest", policy_digest),
            "toolchain_manifest_digest": _digest(
                "toolchain_manifest_digest", toolchain_manifest_digest
            ),
            "stable_release_digest": _digest(
                "stable_release_digest", stable_release_digest
            ),
        }
        now = utc_now()
        seed = sha256_text(stable_json([source_commit, *values.values(), now]))
        epoch_id = f"RE-{seed[:24].upper()}"
        active = self.connection.execute(
            """SELECT epoch_id FROM controller_release_epochs
                 WHERE status NOT IN ('QUALIFICATION_FAILED','LTS') LIMIT 1"""
        ).fetchone()
        if active is not None:
            raise QualificationError("an unfinished release epoch already exists")
        self.connection.execute(
            """INSERT INTO controller_release_epochs
               (epoch_id, source_commit, stable_release_digest, controller_release_digest,
                candidate_digest, policy_digest, toolchain_manifest_digest,
                status, controller_defect_count, correction_count,
                migration_fixup_count, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'CANDIDATE_BUILT', 0, 0, 0, ?, ?)""",
            (
                epoch_id,
                source_commit,
                values["stable_release_digest"],
                values["controller_release_digest"],
                values["candidate_digest"],
                values["policy_digest"],
                values["toolchain_manifest_digest"],
                now,
                now,
            ),
        )
        return epoch_id

    def epoch(self, epoch_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM controller_release_epochs WHERE epoch_id=?",
            (epoch_id,),
        ).fetchone()
        if row is None:
            raise KeyError(epoch_id)
        return dict(row)

    def _assert_live(self, epoch_id: str) -> dict[str, Any]:
        row = self.epoch(epoch_id)
        if str(row["status"]) == ReleaseEpochState.QUALIFICATION_FAILED.value:
            raise QualificationError("failed release epoch cannot continue")
        if str(row["status"]) in {
            ReleaseEpochState.PROMOTED.value,
            ReleaseEpochState.LTS.value,
        }:
            raise QualificationError("promoted release epoch cannot run qualification")
        return row

    def qualification_runs(self, epoch_id: str) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                """SELECT * FROM qualification_runs WHERE epoch_id=?
                     ORDER BY stage_index, created_at""",
                (epoch_id,),
            ).fetchall()
        ]

    def record_qualification(
        self,
        *,
        epoch_id: str,
        stage: str,
        evidence_ref: str,
        metrics: Mapping[str, Any],
        passed: bool,
    ) -> str:
        epoch = self._assert_live(epoch_id)
        if stage not in QUALIFICATION_STAGES:
            raise QualificationError(f"unknown qualification stage: {stage}")
        evidence_ref = _immutable_ref("qualification evidence_ref", evidence_ref)
        stage_index = QUALIFICATION_STAGES.index(stage)
        prior = self.connection.execute(
            "SELECT stage,status FROM qualification_runs WHERE epoch_id=? ORDER BY stage_index",
            (epoch_id,),
        ).fetchall()
        passed_stages = [str(row[0]) for row in prior if str(row[1]) == "PASS"]
        if stage_index != len(passed_stages) or passed_stages != list(
            QUALIFICATION_STAGES[:stage_index]
        ):
            raise QualificationError("qualification stages must pass in exact order")
        if (
            stage == "Q7_SHADOW_DIFFERENTIAL"
            and str(epoch["status"]) != ReleaseEpochState.SHADOW_RUNNING.value
        ):
            raise QualificationError("Q7 cannot run before functional readiness")
        self._validate_stage_metrics(epoch_id, stage, metrics, passed)
        now = utc_now()
        run_digest = sha256_text(
            stable_json(
                [epoch_id, stage, evidence_ref, dict(metrics), bool(passed), now]
            )
        )
        run_id = f"QR-{run_digest[:24].upper()}"
        status = "PASS" if passed else "FAIL"
        self.connection.execute(
            """INSERT INTO qualification_runs
               (run_id, epoch_id, stage, stage_index, status, evidence_ref,
                metrics_json, run_digest, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                epoch_id,
                stage,
                stage_index,
                status,
                evidence_ref,
                stable_json(dict(metrics)),
                run_digest,
                now,
            ),
        )
        if not passed:
            self._fail_epoch(epoch_id, f"qualification_failed:{stage}", evidence_ref)
            return run_id
        next_state = self._state_after_stage(stage)
        self.connection.execute(
            "UPDATE controller_release_epochs SET status=?,updated_at=? WHERE epoch_id=?",
            (next_state.value, now, epoch_id),
        )
        if stage == "Q7_SHADOW_DIFFERENTIAL":
            self.connection.execute(
                "UPDATE controller_release_epochs SET shadow_completed_at=? WHERE epoch_id=?",
                (now, epoch_id),
            )
        _ = epoch
        return run_id

    def authorize_shadow_after_functional_ready(
        self,
        *,
        epoch_id: str,
        readiness_manifest_digest: str,
        caller_plane: str,
    ) -> None:
        """Start Q7 once, only from the independent functional governor."""

        epoch = self._assert_live(epoch_id)
        digest = _digest("functional readiness manifest", readiness_manifest_digest)
        existing_digest = str(epoch.get("functional_ready_manifest_digest") or "")
        if str(epoch["status"]) == ReleaseEpochState.SHADOW_RUNNING.value:
            if existing_digest != digest:
                raise QualificationError("functional readiness manifest conflicts")
            return
        if str(epoch["status"]) != ReleaseEpochState.FUNCTIONAL_PENDING.value:
            raise QualificationError("Q7 requires Q0-Q6 and functional gates")
        if caller_plane != "INDEPENDENT_FUNCTIONAL_GOVERNOR":
            raise QualificationError("Candidate cannot authorize its own Q7")
        runs = self.qualification_runs(epoch_id)
        if [str(row["stage"]) for row in runs] != list(QUALIFICATION_STAGES[:7]) or any(
            str(row["status"]) != "PASS" for row in runs
        ):
            raise QualificationError("Q7 requires exact Q0-Q6 PASS evidence")
        now = utc_now()
        self.connection.execute(
            """UPDATE controller_release_epochs
                  SET status='SHADOW_RUNNING',functional_ready_manifest_digest=?,
                      functional_ready_at=?,shadow_started_at=?,updated_at=?
                WHERE epoch_id=?""",
            (digest, now, now, now, epoch_id),
        )

    def _validate_stage_metrics(
        self,
        epoch_id: str,
        stage: str,
        metrics: Mapping[str, Any],
        passed: bool,
    ) -> None:
        if not passed:
            return
        _zero_metric(metrics, "unknown_transitions")
        required: dict[str, tuple[str, float]] = {
            "Q1_STATIC_CONTRACTS": (
                "transition_coverage_percent",
                float(self.thresholds.transition_coverage_percent),
            ),
            "Q3_PROPERTY_AND_MUTATION": (
                "mutation_score_percent",
                float(self.thresholds.mutation_score_percent),
            ),
            "Q4_HISTORICAL_REPLAY": (
                "historical_replay_percent",
                float(self.thresholds.historical_replay_percent),
            ),
            "Q5_MIGRATION_MATRIX": (
                "migration_matrix_percent",
                float(self.thresholds.migration_matrix_percent),
            ),
            "Q7_SHADOW_DIFFERENTIAL": (
                "shadow_hours",
                self.thresholds.minimum_shadow_hours,
            ),
        }
        threshold = required.get(stage)
        if threshold is not None:
            key, minimum = threshold
            value = metrics.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise QualificationError(f"{stage} requires numeric {key}")
            if float(value) < minimum:
                raise QualificationError(f"{stage} does not satisfy {key}")
        if stage == "Q0_SOURCE_INTEGRITY":
            for key in (
                "clean_commit",
                "version_manifest_sbom_consistent",
                "dependency_lock_present",
            ):
                _strict_bool_metric(metrics, key)
            _zero_metric(metrics, "secret_scan_findings")
            _digest(
                "reproducible_artifact_digest",
                str(metrics.get("reproducible_artifact_digest") or ""),
            )
        elif stage == "Q1_STATIC_CONTRACTS":
            for key in (
                "schemas_valid",
                "capability_catalog_total",
                "failure_catalog_total",
                "lifecycle_profile_total",
            ):
                _strict_bool_metric(metrics, key)
            for key in ("mypy_errors", "ruff_errors", "permissive_fallbacks"):
                _zero_metric(metrics, key)
        elif stage == "Q2_MODEL_CHECKING":
            _strict_bool_metric(metrics, "model_checked")
            _positive_metric(metrics, "bounded_model_states")
            for key in (
                "unsafe_terminal_states",
                "unranked_cycles",
                "duplicate_side_effect_paths",
            ):
                _zero_metric(metrics, key)
        elif stage == "Q3_PROPERTY_AND_MUTATION":
            _positive_metric(metrics, "property_examples")
            _zero_metric(metrics, "property_failures")
        elif stage == "Q4_HISTORICAL_REPLAY":
            _positive_metric(metrics, "historical_fixture_count")
            _zero_metric(metrics, "historical_replay_failures")
        elif stage == "Q5_MIGRATION_MATRIX":
            _positive_metric(metrics, "migration_fixture_count")
            _zero_metric(metrics, "migration_fixup_count")
            _strict_bool_metric(metrics, "backup_restore_verified")
        elif stage == "Q6_SERVICE_E2E":
            for key in (
                "service_scenarios",
                "controller_processes",
                "worker_processes",
            ):
                _positive_metric(metrics, key)
            for key in (
                "manual_database_mutations",
                "duplicate_side_effects",
                "controller_defects",
                "candidate_production_credentials",
                "candidate_writes_to_stable_db",
            ):
                _zero_metric(metrics, key)
        elif stage == "Q7_SHADOW_DIFFERENTIAL":
            for key in (
                "shadow_incidents",
                "unknown_controller_failures",
                "duplicate_side_effects",
                "candidate_side_effect_executions",
                "candidate_production_credentials",
                "candidate_writes_to_stable_db",
                "candidate_shadow_state_writes",
            ):
                _zero_metric(metrics, key)
            _positive_metric(metrics, "shadow_event_count")
            _positive_metric(metrics, "shadow_batch_count")
            _positive_metric(metrics, "shadow_heartbeat_count")
            _digest(
                "shadow_heartbeat_head_digest",
                str(metrics.get("shadow_heartbeat_head_digest") or ""),
            )
            for key in (
                "shadow_max_heartbeat_gap_seconds",
                "shadow_last_heartbeat_age_seconds",
            ):
                value = metrics.get(key)
                if (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or float(value) < 0
                    or float(value)
                    > self.thresholds.maximum_shadow_heartbeat_gap_seconds
                ):
                    raise QualificationError(
                        f"Q7 requires bounded {key}"
                    )
            historical_total = _positive_metric(metrics, "historical_products_total")
            historical_replayed = _positive_metric(
                metrics, "historical_products_replayed"
            )
            if historical_replayed != historical_total:
                raise QualificationError("Q7 historical product replay is incomplete")
        if stage == "Q7_SHADOW_DIFFERENTIAL":
            epoch = self.epoch(epoch_id)
            started_at = str(epoch.get("shadow_started_at") or "")
            try:
                started = datetime.fromisoformat(started_at)
            except ValueError as error:
                raise QualificationError("shadow start timestamp is invalid") from error
            observed_hours = (datetime.now(UTC) - started).total_seconds() / 3600
            if observed_hours < self.thresholds.minimum_shadow_hours:
                raise QualificationError("Q7 observed shadow duration is too short")
            reported_hours = float(metrics.get("shadow_hours", -1))
            if reported_hours > observed_hours + (1 / 60):
                raise QualificationError("Q7 reported duration exceeds verifier clock")
            comparisons = self.connection.execute(
                """SELECT COUNT(*),
                          SUM(CASE WHEN comparison!='MATCH' THEN 1 ELSE 0 END)
                     FROM shadow_decisions WHERE epoch_id=?""",
                (str(epoch["epoch_id"]),),
            ).fetchone()
            if comparisons is None or int(comparisons[0]) < 1 or int(comparisons[1] or 0) != 0:
                raise QualificationError("Q7 requires a non-empty matching decision replay")
            if float(metrics.get("task_amplification_ratio", 99)) > self.thresholds.maximum_task_amplification_ratio:
                raise QualificationError("shadow task amplification exceeds gate")
            if int(metrics.get("max_evidence_indirection", 99)) > self.thresholds.maximum_evidence_indirection:
                raise QualificationError("shadow evidence indirection exceeds gate")

    @staticmethod
    def _state_after_stage(stage: str) -> ReleaseEpochState:
        return {
            "Q0_SOURCE_INTEGRITY": ReleaseEpochState.CANDIDATE_BUILT,
            "Q1_STATIC_CONTRACTS": ReleaseEpochState.STATIC_QUALIFIED,
            "Q2_MODEL_CHECKING": ReleaseEpochState.MODEL_CHECKED,
            "Q3_PROPERTY_AND_MUTATION": ReleaseEpochState.MODEL_CHECKED,
            "Q4_HISTORICAL_REPLAY": ReleaseEpochState.MODEL_CHECKED,
            "Q5_MIGRATION_MATRIX": ReleaseEpochState.MIGRATION_REPLAYED,
            "Q6_SERVICE_E2E": ReleaseEpochState.FUNCTIONAL_PENDING,
            "Q7_SHADOW_DIFFERENTIAL": ReleaseEpochState.CLEAN_CANARY,
        }[stage]

    def fail_orchestration(self, *, epoch_id: str, evidence_ref: str) -> None:
        """Fail a built epoch when the qualification orchestrator cannot start."""

        epoch = self.epoch(epoch_id)
        if str(epoch["status"]) == ReleaseEpochState.QUALIFICATION_FAILED.value:
            return
        if str(epoch["status"]) != ReleaseEpochState.CANDIDATE_BUILT.value:
            raise QualificationError(
                "orchestration failure is only valid before ordered qualification"
            )
        immutable_ref = _immutable_ref(
            "orchestration failure evidence_ref",
            evidence_ref,
        )
        self._fail_epoch(
            epoch_id,
            "qualification_orchestrator_start_failed",
            immutable_ref,
        )

    def _fail_epoch(self, epoch_id: str, reason: str, evidence_ref: str) -> None:
        now = utc_now()
        self.connection.execute(
            """UPDATE controller_release_epochs
                  SET status='QUALIFICATION_FAILED', failure_reason=?,
                      failure_evidence_ref=?, failed_at=?, updated_at=?
                WHERE epoch_id=? AND status!='QUALIFICATION_FAILED'""",
            (reason, evidence_ref, now, now, epoch_id),
        )
        self.connection.execute(
            """UPDATE clean_canary_runs
                  SET status='REJECTED', rejection_reason=?, completed_at=?
                WHERE epoch_id=? AND status='RUNNING'""",
            (reason, now, epoch_id),
        )

    def start_clean_canary(
        self,
        *,
        epoch_id: str,
        scenario_id: str,
        state_fresh_proof_ref: str,
        initial_state_digest: str,
    ) -> str:
        epoch = self._assert_live(epoch_id)
        if str(epoch["status"]) != ReleaseEpochState.CLEAN_CANARY.value:
            raise QualificationError("clean canary requires completed Q0-Q7")
        if scenario_id not in REQUIRED_CANARY_SCENARIOS:
            raise QualificationError("clean canary scenario is not registered")
        fresh_ref = _immutable_ref("state_fresh_proof_ref", state_fresh_proof_ref)
        initial_digest = _digest("initial_state_digest", initial_state_digest)
        existing = self.connection.execute(
            "SELECT 1 FROM clean_canary_runs WHERE epoch_id=? AND scenario_id=?",
            (epoch_id, scenario_id),
        ).fetchone()
        if existing is not None:
            raise QualificationError("clean canary scenario is already represented")
        running = self.connection.execute(
            "SELECT 1 FROM clean_canary_runs WHERE epoch_id=? AND status='RUNNING'",
            (epoch_id,),
        ).fetchone()
        if running is not None:
            raise QualificationError("only one clean canary may run at a time")
        now = utc_now()
        digest = sha256_text(
            stable_json([epoch_id, scenario_id, epoch["controller_release_digest"], now])
        )
        canary_id = f"CC-{digest[:24].upper()}"
        self.connection.execute(
            """INSERT INTO clean_canary_runs
               (canary_id, epoch_id, scenario_id, state_fresh, state_fresh_proof_ref,
                initial_state_digest, controller_release_digest,
                status, controller_recovery_applications, manual_database_mutations,
                routine_owner_actions, unknown_controller_defects, release_changes,
                duplicate_side_effects, task_count, baseline_task_count, started_at)
               VALUES (?, ?, ?, 1, ?, ?, ?, 'RUNNING', 0, 0, 0, 0, 0, 0, 0, 0, ?)""",
            (
                canary_id,
                epoch_id,
                scenario_id,
                fresh_ref,
                initial_digest,
                epoch["controller_release_digest"],
                now,
            ),
        )
        return canary_id

    def clean_canary(self, canary_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM clean_canary_runs WHERE canary_id=?",
            (canary_id,),
        ).fetchone()
        if row is None:
            raise KeyError(canary_id)
        return dict(row)

    def record_controller_defect(
        self,
        *,
        epoch_id: str,
        reason_code: str,
        evidence_ref: str,
        canary_id: str | None = None,
    ) -> None:
        self._assert_live(epoch_id)
        self.connection.execute(
            """UPDATE controller_release_epochs
                  SET controller_defect_count=controller_defect_count+1,updated_at=?
                WHERE epoch_id=?""",
            (utc_now(), epoch_id),
        )
        if canary_id:
            self.connection.execute(
                """UPDATE clean_canary_runs
                      SET unknown_controller_defects=unknown_controller_defects+1
                    WHERE canary_id=? AND epoch_id=?""",
                (canary_id, epoch_id),
            )
        self._fail_epoch(epoch_id, f"controller_defect:{reason_code}", evidence_ref)

    def record_controller_release_change(
        self,
        *,
        epoch_id: str,
        canary_id: str,
        new_release_digest: str,
        evidence_ref: str,
    ) -> None:
        epoch = self._assert_live(epoch_id)
        _digest("new_release_digest", new_release_digest)
        if new_release_digest == str(epoch["controller_release_digest"]):
            return
        self.connection.execute(
            """UPDATE clean_canary_runs SET release_changes=release_changes+1
                WHERE canary_id=? AND epoch_id=?""",
            (canary_id, epoch_id),
        )
        self._fail_epoch(epoch_id, "controller_release_changed_during_canary", evidence_ref)

    def record_recovery_application(
        self,
        *,
        epoch_id: str,
        canary_id: str,
        recovery_ref: str,
    ) -> None:
        self._assert_live(epoch_id)
        self.connection.execute(
            """UPDATE clean_canary_runs
                  SET controller_recovery_applications=controller_recovery_applications+1
                WHERE canary_id=? AND epoch_id=? AND status='RUNNING'""",
            (canary_id, epoch_id),
        )
        self._fail_epoch(epoch_id, "clean_canary_used_controller_recovery", recovery_ref)

    def record_canary_violation(
        self,
        *,
        epoch_id: str,
        canary_id: str,
        violation: str,
        evidence_ref: str,
    ) -> None:
        """Persist an independently observed first-pass violation and fail the epoch."""

        columns = {
            "manual_database_mutation": "manual_database_mutations",
            "routine_owner_action": "routine_owner_actions",
            "duplicate_side_effect": "duplicate_side_effects",
        }
        try:
            column = columns[violation]
        except KeyError as error:
            raise QualificationError("unknown clean canary violation") from error
        self._assert_live(epoch_id)
        _immutable_ref("canary violation evidence_ref", evidence_ref)
        canary = self.clean_canary(canary_id)
        if str(canary["epoch_id"]) != epoch_id or str(canary["status"]) != "RUNNING":
            raise QualificationError("canary violation requires the active running canary")
        self.connection.execute(
            f"UPDATE clean_canary_runs SET {column}={column}+1 WHERE canary_id=?",
            (canary_id,),
        )
        self._fail_epoch(epoch_id, f"clean_canary_{violation}", evidence_ref)

    def fail_clean_canary(
        self,
        *,
        epoch_id: str,
        canary_id: str,
        reason: str,
        evidence_ref: str,
    ) -> None:
        """Stop Q8 when an archetype cannot reach its exact clean terminal state."""

        if reason not in {"terminal_failure", "timeout", "orchestrator_error"}:
            raise QualificationError("unknown clean canary execution failure")
        self._assert_live(epoch_id)
        reference = _immutable_ref("clean canary failure evidence_ref", evidence_ref)
        canary = self.clean_canary(canary_id)
        if str(canary["epoch_id"]) != epoch_id or str(canary["status"]) != "RUNNING":
            raise QualificationError("clean canary failure requires the active run")
        self._fail_epoch(epoch_id, f"clean_canary_execution_{reason}", reference)

    def complete_clean_canary(
        self,
        *,
        epoch_id: str,
        canary_id: str,
        terminal_status: str,
        completion_manifest_ref: str,
        product_id: str,
        observation_evidence_ref: str,
        observation_digest: str,
        controller_release_digest: str | None = None,
        task_count: int = 0,
        baseline_task_count: int = 0,
    ) -> None:
        epoch = self._assert_live(epoch_id)
        canary = self.clean_canary(canary_id)
        if str(canary["status"]) != "RUNNING":
            raise QualificationError("only a running clean canary can complete")
        if terminal_status != "COMPLETED" or not completion_manifest_ref:
            self._fail_epoch(epoch_id, "clean_canary_not_completed", completion_manifest_ref)
            raise QualificationError("clean canary must finish COMPLETED with manifest")
        completion_manifest_ref = _immutable_ref(
            "completion_manifest_ref", completion_manifest_ref
        )
        if not product_id.strip():
            raise QualificationError("clean canary product identity is required")
        observation_ref = _immutable_ref(
            "observation_evidence_ref", observation_evidence_ref
        )
        observed_digest = _digest("observation_digest", observation_digest)
        if task_count < 1 or baseline_task_count < 1:
            self._fail_epoch(epoch_id, "clean_canary_task_count_missing", completion_manifest_ref)
            raise QualificationError("clean canary requires positive observed and baseline task counts")
        observed_release = controller_release_digest or str(
            canary["controller_release_digest"]
        )
        if observed_release != str(epoch["controller_release_digest"]):
            self._fail_epoch(epoch_id, "controller_release_changed_during_canary", completion_manifest_ref)
            raise QualificationError("clean canary controller release changed")
        zero_fields = (
            "controller_recovery_applications",
            "manual_database_mutations",
            "routine_owner_actions",
            "unknown_controller_defects",
            "release_changes",
            "duplicate_side_effects",
        )
        if any(int(canary[name]) != 0 for name in zero_fields):
            self._fail_epoch(epoch_id, "clean_canary_not_first_pass", completion_manifest_ref)
            raise QualificationError("clean canary is not a zero-intervention first pass")
        ratio = float(task_count) / max(1, int(baseline_task_count or task_count or 1))
        if ratio > self.thresholds.maximum_task_amplification_ratio:
            self._fail_epoch(epoch_id, "clean_canary_task_amplification", completion_manifest_ref)
            raise QualificationError("clean canary task amplification exceeds gate")
        self.connection.execute(
            """UPDATE clean_canary_runs
                  SET status='PASS', terminal_status=?, completion_manifest_ref=?,
                      product_id=?, observation_evidence_ref=?, observation_digest=?,
                      task_count=?, baseline_task_count=?, completed_at=?
                WHERE canary_id=?""",
            (
                terminal_status,
                completion_manifest_ref,
                product_id,
                observation_ref,
                observed_digest,
                task_count,
                baseline_task_count,
                utc_now(),
                canary_id,
            ),
        )
        passed = self.connection.execute(
            "SELECT COUNT(*) FROM clean_canary_runs WHERE epoch_id=? AND status='PASS'",
            (epoch_id,),
        ).fetchone()[0]
        scenarios = {
            str(row[0])
            for row in self.connection.execute(
                "SELECT scenario_id FROM clean_canary_runs WHERE epoch_id=? AND status='PASS'",
                (epoch_id,),
            ).fetchall()
        }
        if int(passed) >= self.thresholds.minimum_clean_canaries and REQUIRED_CANARY_SCENARIOS <= scenarios:
            self.connection.execute(
                """UPDATE controller_release_epochs
                      SET status='PROMOTION_READY',updated_at=? WHERE epoch_id=?""",
                (utc_now(), epoch_id),
            )

    def compare_shadow_decision(
        self,
        *,
        epoch_id: str,
        event_digest: str,
        stable_decision: Mapping[str, Any],
        candidate_decision: Mapping[str, Any],
    ) -> str:
        self._assert_live(epoch_id)
        _digest("event_digest", event_digest)
        stable_digest = sha256_text(stable_json(dict(stable_decision)))
        candidate_digest = sha256_text(stable_json(dict(candidate_decision)))
        comparison = "MATCH" if stable_digest == candidate_digest else "DIVERGED"
        decision_id = f"SD-{sha256_text(stable_json([epoch_id,event_digest]))[:24].upper()}"
        existing = self.connection.execute(
            """SELECT stable_decision_digest,candidate_decision_digest,comparison
                 FROM shadow_decisions
                WHERE epoch_id=? AND event_digest=?""",
            (epoch_id, event_digest),
        ).fetchone()
        persisted = (stable_digest, candidate_digest, comparison)
        if existing is not None:
            if tuple(str(value) for value in existing) != persisted:
                self._fail_epoch(
                    epoch_id,
                    "shadow_decision_append_conflict",
                    f"state://shadow-decision/{decision_id}",
                )
                raise QualificationError("shadow decision replay conflicts with append-only history")
            return comparison
        self.connection.execute(
            """INSERT INTO shadow_decisions
               (shadow_decision_id, epoch_id, event_digest, stable_decision_digest,
                candidate_decision_digest, comparison, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                decision_id,
                epoch_id,
                event_digest,
                stable_digest,
                candidate_digest,
                comparison,
                utc_now(),
            ),
        )
        return comparison

    @staticmethod
    def _decode_public_key(value: str) -> bytes:
        return _decode_verifier_key(value)

    def qualification_manifest_payload(
        self,
        *,
        epoch_id: str,
        verifier_digest: str,
        verifier_public_key: str,
        transition_model_digest: str,
        historical_corpus_digest: str,
        migration_matrix_digest: str,
        manifest_ref: str,
        backup_restore_proof_ref: str,
        rollback_proof_ref: str,
        shadow_report_ref: str,
    ) -> dict[str, Any]:
        """Build the exact bytes an isolated verifier must sign."""

        epoch = self.epoch(epoch_id)
        if str(epoch["status"]) != ReleaseEpochState.PROMOTION_READY.value:
            raise QualificationError("manifest requires PROMOTION_READY epoch")
        verifier = _digest("verifier_digest", verifier_digest)
        if verifier in {
            str(epoch["candidate_digest"]),
            str(epoch["controller_release_digest"]),
            str(epoch["stable_release_digest"]),
        }:
            raise QualificationError("independent verifier digest must differ from both planes")
        public_key = self._decode_public_key(verifier_public_key)
        public_key_digest = hashlib.sha256(public_key).hexdigest()
        if self.trusted_verifier_public_key_digest is None:
            raise QualificationError("independent verifier trust root is not configured")
        if public_key_digest != self.trusted_verifier_public_key_digest:
            raise QualificationError("verifier public key does not match the root-owned trust root")
        references = {
            "manifest_ref": _immutable_ref("manifest_ref", manifest_ref),
            "backup_restore_proof_ref": _immutable_ref(
                "backup_restore_proof_ref", backup_restore_proof_ref
            ),
            "rollback_proof_ref": _immutable_ref(
                "rollback_proof_ref", rollback_proof_ref
            ),
            "shadow_report_ref": _immutable_ref("shadow_report_ref", shadow_report_ref),
        }
        qualification_artifacts = {
            "transition_model_digest": _digest(
                "transition_model_digest", transition_model_digest
            ),
            "historical_corpus_digest": _digest(
                "historical_corpus_digest", historical_corpus_digest
            ),
            "migration_matrix_digest": _digest(
                "migration_matrix_digest", migration_matrix_digest
            ),
        }
        runs = self.qualification_runs(epoch_id)
        if [str(row["stage"]) for row in runs] != list(QUALIFICATION_STAGES) or any(
            str(row["status"]) != "PASS" for row in runs
        ):
            raise QualificationError("manifest requires exact Q0-Q7 PASS evidence")
        canaries = [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM clean_canary_runs WHERE epoch_id=? ORDER BY scenario_id",
                (epoch_id,),
            ).fetchall()
        ]
        if (
            len(canaries) != len(REQUIRED_CANARY_SCENARIOS)
            or {str(row["scenario_id"]) for row in canaries}
            != set(REQUIRED_CANARY_SCENARIOS)
            or any(str(row["status"]) != "PASS" for row in canaries)
        ):
            raise QualificationError("manifest requires exactly ten clean PASS canaries")
        canary_reports = [
            {
                "canary_id": str(row["canary_id"]),
                "scenario_id": str(row["scenario_id"]),
                "product_id": str(row["product_id"]),
                "state_fresh_proof_ref": _immutable_ref(
                    "state_fresh_proof_ref", str(row["state_fresh_proof_ref"])
                ),
                "initial_state_digest": _digest(
                    "initial_state_digest", str(row["initial_state_digest"])
                ),
                "controller_release_digest": str(row["controller_release_digest"]),
                "completion_manifest_ref": _immutable_ref(
                    "completion_manifest_ref", str(row["completion_manifest_ref"])
                ),
                "observation_evidence_ref": _immutable_ref(
                    "observation_evidence_ref", str(row["observation_evidence_ref"])
                ),
                "observation_digest": _digest(
                    "observation_digest", str(row["observation_digest"])
                ),
                "controller_recovery_applications": int(
                    row["controller_recovery_applications"]
                ),
                "manual_database_mutations": int(row["manual_database_mutations"]),
                "routine_owner_actions": int(row["routine_owner_actions"]),
                "unknown_controller_defects": int(row["unknown_controller_defects"]),
                "release_changes": int(row["release_changes"]),
                "duplicate_side_effects": int(row["duplicate_side_effects"]),
                "task_count": int(row["task_count"]),
                "baseline_task_count": int(row["baseline_task_count"]),
            }
            for row in canaries
        ]
        return {
            "schema_version": "1.0",
            "epoch_id": epoch_id,
            "source_commit": str(epoch["source_commit"]),
            "stable_release_digest": str(epoch["stable_release_digest"]),
            "controller_release_digest": str(epoch["controller_release_digest"]),
            "candidate_digest": str(epoch["candidate_digest"]),
            "policy_digest": str(epoch["policy_digest"]),
            "toolchain_manifest_digest": str(epoch["toolchain_manifest_digest"]),
            "qualification_run_digests": [str(row["run_digest"]) for row in runs],
            **qualification_artifacts,
            "clean_canary_reports": canary_reports,
            "verifier": {
                "digest": verifier,
                "public_key": verifier_public_key,
                "public_key_digest": public_key_digest,
                "signature_algorithm": "Ed25519",
            },
            **references,
        }

    def create_qualification_manifest(
        self,
        *,
        epoch_id: str,
        verifier_digest: str,
        verifier_public_key: str,
        verifier_signature: str,
        transition_model_digest: str,
        historical_corpus_digest: str,
        migration_matrix_digest: str,
        manifest_ref: str,
        backup_restore_proof_ref: str,
        rollback_proof_ref: str,
        shadow_report_ref: str,
    ) -> str:
        payload = self.qualification_manifest_payload(
            epoch_id=epoch_id,
            verifier_digest=verifier_digest,
            verifier_public_key=verifier_public_key,
            transition_model_digest=transition_model_digest,
            historical_corpus_digest=historical_corpus_digest,
            migration_matrix_digest=migration_matrix_digest,
            manifest_ref=manifest_ref,
            backup_restore_proof_ref=backup_restore_proof_ref,
            rollback_proof_ref=rollback_proof_ref,
            shadow_report_ref=shadow_report_ref,
        )
        try:
            signature = base64.b64decode(verifier_signature, validate=True)
        except (binascii.Error, ValueError) as error:
            raise QualificationError("verifier signature is not canonical base64") from error
        signed_bytes = stable_json(payload).encode("utf-8")
        try:
            Ed25519PublicKey.from_public_bytes(
                self._decode_public_key(verifier_public_key)
            ).verify(signature, signed_bytes)
        except (InvalidSignature, ValueError) as error:
            raise QualificationError("independent verifier signature is invalid") from error
        signed_payload_digest = sha256_text(signed_bytes.decode("utf-8"))
        envelope = {**payload, "verifier_signature": verifier_signature}
        digest = sha256_text(stable_json(envelope))
        manifest_id = f"RQM-{digest[:24].upper()}"
        self.connection.execute(
            """INSERT INTO release_qualification_manifests
               (manifest_id, epoch_id, manifest_ref, manifest_digest,
                source_commit, transition_model_digest, historical_corpus_digest,
                migration_matrix_digest,
                verifier_digest, verifier_public_key, verifier_public_key_digest,
                signature_algorithm, verifier_signature, signed_payload_digest,
                backup_restore_proof_ref, rollback_proof_ref, shadow_report_ref,
                created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Ed25519', ?, ?, ?, ?, ?, ?)""",
            (
                manifest_id,
                epoch_id,
                manifest_ref,
                digest,
                str(payload["source_commit"]),
                str(payload["transition_model_digest"]),
                str(payload["historical_corpus_digest"]),
                str(payload["migration_matrix_digest"]),
                verifier_digest,
                verifier_public_key,
                str(payload["verifier"]["public_key_digest"]),
                verifier_signature,
                signed_payload_digest,
                backup_restore_proof_ref,
                rollback_proof_ref,
                shadow_report_ref,
                utc_now(),
            ),
        )
        return manifest_id

    def promote(
        self,
        *,
        epoch_id: str,
        manifest_id: str,
        caller_plane: str,
        root_helper_receipt_ref: str,
        exact_staging_production_digest: str,
    ) -> None:
        epoch = self.epoch(epoch_id)
        if str(epoch["status"]) != ReleaseEpochState.PROMOTION_READY.value:
            raise QualificationError("epoch is not promotion ready")
        if caller_plane != "LTS_A":
            raise QualificationError("Candidate B cannot promote itself")
        root_helper_receipt_ref = _immutable_ref(
            "root_helper_receipt_ref", root_helper_receipt_ref
        )
        _digest("exact_staging_production_digest", exact_staging_production_digest)
        if exact_staging_production_digest != str(epoch["candidate_digest"]):
            raise QualificationError("staging/production digest does not match candidate")
        manifest = self.connection.execute(
            """SELECT 1 FROM release_qualification_manifests
                WHERE manifest_id=? AND epoch_id=?""",
            (manifest_id, epoch_id),
        ).fetchone()
        if manifest is None:
            raise QualificationError("root-owned promotion receipt is required")
        self.connection.execute(
            """UPDATE controller_release_epochs
                  SET status='PROMOTED', promotion_receipt_ref=?, promoted_at=?,updated_at=?
                WHERE epoch_id=?""",
            (root_helper_receipt_ref, utc_now(), utc_now(), epoch_id),
        )

    def graduate_lts(self, *, epoch_id: str, observation_evidence_ref: str) -> None:
        epoch = self.epoch(epoch_id)
        if str(epoch["status"]) != ReleaseEpochState.PROMOTED.value:
            raise QualificationError("only a promoted epoch can graduate to LTS")
        if not observation_evidence_ref:
            raise QualificationError("LTS graduation requires observation evidence")
        self.connection.execute(
            """UPDATE controller_release_epochs
                  SET status='LTS', observation_evidence_ref=?,lts_at=?,updated_at=?
                WHERE epoch_id=?""",
            (observation_evidence_ref, utc_now(), utc_now(), epoch_id),
        )

    def fail_production_observation(
        self,
        *,
        epoch_id: str,
        rollback_evidence_ref: str,
    ) -> None:
        epoch = self.epoch(epoch_id)
        if str(epoch["status"]) != ReleaseEpochState.PROMOTED.value:
            raise QualificationError("production observation failure requires PROMOTED epoch")
        evidence_ref = _immutable_ref(
            "rollback_evidence_ref", rollback_evidence_ref
        )
        self._fail_epoch(epoch_id, "production_observation_failed", evidence_ref)
