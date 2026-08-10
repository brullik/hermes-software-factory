"""Functional-first qualification and independently verifiable ready results.

This module is deliberately separate from the production Controller.  The
functional governor owns only Candidate qualification state and never writes
Stable A.  It is the durable ordering authority for Q6.5, PRE-Q8, the Golden
Product, and the transition that permits Q7 to start.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .common import sha256_text, stable_json, utc_now

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SHA40 = re.compile(r"^[a-f0-9]{40}$")
_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9-]{7,63}$")
_FAILURE_CLASS = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")


class FunctionalReadinessError(RuntimeError):
    """A functional-first invariant was violated."""


class CapabilityStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    MISSING_EXTERNAL = "MISSING_EXTERNAL"
    DENIED_POLICY = "DENIED_POLICY"
    EXPIRED = "EXPIRED"
    BROKEN_INTERNAL = "BROKEN_INTERNAL"


MANDATORY_Q6_5_OPERATIONS: Final[tuple[str, ...]] = (
    "github.identity.read",
    "github.repository.create_private",
    "github.repository.read",
    "git.branch.push",
    "github.pull_request.create",
    "github.checks.read",
    "github.pull_request.merge_or_close",
    "github.repository.archive_or_delete",
    "provider.luna.invoke",
    "provider.terra.invoke",
    "provider.sol.invoke",
    "toolchain.container_builder",
    "deployment.isolated",
    "deployment.rollback",
    "telegram.send_message",
    "telegram.send_document",
    "backup.create",
    "backup.restore_verify",
)


PRE_Q8_SCENARIOS: Final[tuple[str, ...]] = (
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
)


@dataclass(frozen=True)
class CapabilityHandshakeReport:
    schema_version: str
    candidate_digest: str
    capability: str
    operation: str
    scope: Mapping[str, Any]
    status: CapabilityStatus
    credential_epoch_id: str | None
    toolchain_digest: str
    receipts: tuple[str, ...]
    safe_reason_code: str | None
    report_digest: str

    @classmethod
    def create(
        cls,
        *,
        candidate_digest: str,
        capability: str,
        operation: str,
        scope: Mapping[str, Any],
        status: CapabilityStatus | str,
        credential_epoch_id: str | None,
        toolchain_digest: str,
        receipts: Sequence[str] = (),
        safe_reason_code: str | None = None,
    ) -> CapabilityHandshakeReport:
        normalized_status = CapabilityStatus(status)
        payload = {
            "schema_version": "1.0",
            "candidate_digest": candidate_digest,
            "capability": capability,
            "operation": operation,
            "scope": dict(scope),
            "status": normalized_status.value,
            "credential_epoch_id": credential_epoch_id,
            "toolchain_digest": toolchain_digest,
            "receipts": list(receipts),
            "safe_reason_code": safe_reason_code,
        }
        report = cls(
            schema_version="1.0",
            candidate_digest=candidate_digest,
            capability=capability,
            operation=operation,
            scope=dict(scope),
            status=normalized_status,
            credential_epoch_id=credential_epoch_id,
            toolchain_digest=toolchain_digest,
            receipts=tuple(receipts),
            safe_reason_code=safe_reason_code,
            report_digest=sha256_text(stable_json(payload)),
        )
        report.validate()
        return report

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "candidate_digest": self.candidate_digest,
            "capability": self.capability,
            "operation": self.operation,
            "scope": dict(self.scope),
            "status": self.status.value,
            "credential_epoch_id": self.credential_epoch_id,
            "toolchain_digest": self.toolchain_digest,
            "receipts": list(self.receipts),
            "safe_reason_code": self.safe_reason_code,
        }

    def validate(self) -> None:
        if self.schema_version != "1.0":
            raise FunctionalReadinessError("capability report schema version differs")
        if not _SHA256.fullmatch(self.candidate_digest):
            raise FunctionalReadinessError("candidate digest is invalid")
        if not _SHA256.fullmatch(self.toolchain_digest):
            raise FunctionalReadinessError("toolchain digest is invalid")
        if not self.capability or not self.operation:
            raise FunctionalReadinessError("capability operation identity is required")
        if self.status == CapabilityStatus.AVAILABLE and self.safe_reason_code:
            raise FunctionalReadinessError("available capability cannot have a failure reason")
        if self.status != CapabilityStatus.AVAILABLE and not self.safe_reason_code:
            raise FunctionalReadinessError("unavailable capability requires a safe reason")
        if self.status == CapabilityStatus.AVAILABLE and not self.receipts:
            raise FunctionalReadinessError("available capability requires immutable receipts")
        if any(not _SHA256.fullmatch(value) for value in self.receipts):
            raise FunctionalReadinessError("capability receipt digest is invalid")
        if sha256_text(stable_json(self.payload())) != self.report_digest:
            raise FunctionalReadinessError("capability report digest differs")

    def as_dict(self) -> dict[str, Any]:
        return {**self.payload(), "report_digest": self.report_digest}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CapabilityHandshakeReport:
        expected = {
            "schema_version",
            "candidate_digest",
            "capability",
            "operation",
            "scope",
            "status",
            "credential_epoch_id",
            "toolchain_digest",
            "receipts",
            "safe_reason_code",
            "report_digest",
        }
        if set(value) != expected or not isinstance(value.get("scope"), Mapping):
            raise FunctionalReadinessError("capability report schema is invalid")
        receipts = value.get("receipts")
        if not isinstance(receipts, list):
            raise FunctionalReadinessError("capability report receipts are invalid")
        report = cls(
            schema_version=str(value["schema_version"]),
            candidate_digest=str(value["candidate_digest"]),
            capability=str(value["capability"]),
            operation=str(value["operation"]),
            scope=dict(value["scope"]),
            status=CapabilityStatus(str(value["status"])),
            credential_epoch_id=(
                str(value["credential_epoch_id"])
                if value["credential_epoch_id"] is not None
                else None
            ),
            toolchain_digest=str(value["toolchain_digest"]),
            receipts=tuple(str(item) for item in receipts),
            safe_reason_code=(
                str(value["safe_reason_code"])
                if value["safe_reason_code"] is not None
                else None
            ),
            report_digest=str(value["report_digest"]),
        )
        report.validate()
        return report


@dataclass(frozen=True)
class CandidateTruth:
    product_status: str
    scenario_status: str
    task_statuses: tuple[str, ...]
    failure_reasons: tuple[str, ...]
    open_incidents: tuple[str, ...]
    completion_manifest_count: int
    liveness_finding: bool


class CandidateDatabaseVerifier:
    """Read internal Candidate truth without trusting systemd process state."""

    TERMINAL_FAILURES: Final[frozenset[str]] = frozenset({"FAILED_SAFE", "CANCELLED"})
    RUNNABLE_TASKS: Final[frozenset[str]] = frozenset({"PENDING", "CLAIMED", "WAITING"})

    @staticmethod
    def inspect(
        database: Path,
        *,
        worker_idle: bool = False,
        independent_completion_verifier: Callable[[sqlite3.Connection, str], bool]
        | None = None,
    ) -> CandidateTruth:
        if not database.is_file() or database.is_symlink():
            raise FunctionalReadinessError("Candidate database is unavailable")
        connection = sqlite3.connect(
            f"file:{database.resolve().as_posix()}?mode=ro", uri=True, timeout=10
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            if integrity is None or str(integrity[0]) != "ok":
                raise FunctionalReadinessError("Candidate database integrity failed")
            products = connection.execute(
                "SELECT product_id,status FROM products ORDER BY created_at"
            ).fetchall()
            if len(products) != 1:
                raise FunctionalReadinessError("functional scenario requires one product")
            product_id = str(products[0]["product_id"])
            product_status = str(products[0]["status"])
            tasks = connection.execute(
                "SELECT status FROM tasks WHERE product_id=? ORDER BY created_at",
                (product_id,),
            ).fetchall()
            task_statuses = tuple(str(row[0]) for row in tasks)
            failures = connection.execute(
                "SELECT reason_code FROM failures WHERE product_id=? ORDER BY first_seen_at",
                (product_id,),
            ).fetchall()
            incidents = connection.execute(
                "SELECT reason_code FROM controller_incidents "
                "WHERE (product_id=? OR product_id IS NULL) AND status!='RESOLVED' "
                "ORDER BY created_at",
                (product_id,),
            ).fetchall()
            manifests = int(
                connection.execute(
                    "SELECT COUNT(*) FROM completion_manifests WHERE product_id=?",
                    (product_id,),
                ).fetchone()[0]
            )
            has_runnable = any(status in CandidateDatabaseVerifier.RUNNABLE_TASKS for status in task_statuses)
            external_wait = "BLOCKED_EXTERNAL" in task_statuses
            liveness = (
                worker_idle
                and product_status not in CandidateDatabaseVerifier.TERMINAL_FAILURES
                and product_status != "COMPLETED"
                and not has_runnable
                and not external_wait
            )
            if product_status in CandidateDatabaseVerifier.TERMINAL_FAILURES:
                scenario_status = "TERMINAL_FAILURE"
            elif external_wait:
                scenario_status = "WAITING_CAPABILITY"
            elif liveness:
                scenario_status = "LIVENESS_FINDING"
            elif product_status == "COMPLETED":
                verified = manifests == 1 and (
                    independent_completion_verifier is not None
                    and independent_completion_verifier(connection, product_id)
                )
                scenario_status = "PASS" if verified else "VERIFY_FAILED"
            else:
                scenario_status = "RUNNING"
            return CandidateTruth(
                product_status=product_status,
                scenario_status=scenario_status,
                task_statuses=task_statuses,
                failure_reasons=tuple(str(row[0]) for row in failures),
                open_incidents=tuple(str(row[0]) for row in incidents),
                completion_manifest_count=manifests,
                liveness_finding=liveness,
            )
        finally:
            connection.close()


class FunctionalQualificationGovernor:
    """Durable gate ordering for a single immutable Candidate epoch."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        self.connection.executescript(
            """
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS functional_epochs (
                epoch_id TEXT PRIMARY KEY,
                source_commit TEXT NOT NULL,
                candidate_digest TEXT NOT NULL,
                toolchain_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                q6_5_status TEXT NOT NULL DEFAULT 'PENDING',
                pre_q8_status TEXT NOT NULL DEFAULT 'PENDING',
                golden_product_status TEXT NOT NULL DEFAULT 'PENDING',
                internal_verifier_status TEXT NOT NULL DEFAULT 'PENDING',
                stable_health_status TEXT NOT NULL DEFAULT 'PENDING',
                stable_intake_status TEXT NOT NULL DEFAULT 'PENDING',
                q7_started_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_functional_one_active
              ON functional_epochs((1))
              WHERE status NOT IN ('NON_PROMOTABLE','QUALIFICATION_FAILED','Q7_STARTED');
            CREATE TABLE IF NOT EXISTS capability_handshake_reports (
                epoch_id TEXT NOT NULL REFERENCES functional_epochs(epoch_id),
                operation TEXT NOT NULL,
                credential_epoch_id TEXT,
                status TEXT NOT NULL,
                report_json TEXT NOT NULL,
                report_digest TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                PRIMARY KEY(epoch_id,operation)
            );
            CREATE TABLE IF NOT EXISTS pre_q8_scenarios (
                epoch_id TEXT NOT NULL REFERENCES functional_epochs(epoch_id),
                scenario_id TEXT NOT NULL,
                attempt INTEGER NOT NULL CHECK(attempt=1),
                status TEXT NOT NULL,
                product_id TEXT NOT NULL,
                completion_manifest_ref TEXT NOT NULL,
                evidence_digest TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(epoch_id,scenario_id)
            );
            CREATE TABLE IF NOT EXISTS pre_q8_admissions (
                epoch_id TEXT PRIMARY KEY REFERENCES functional_epochs(epoch_id),
                run_id TEXT NOT NULL,
                seal_digest TEXT NOT NULL UNIQUE,
                git_tree TEXT NOT NULL,
                release_tree_digest TEXT NOT NULL,
                candidate_digest TEXT NOT NULL,
                admitted_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pre_q8_runs (
                epoch_id TEXT NOT NULL REFERENCES functional_epochs(epoch_id),
                scenario_id TEXT NOT NULL,
                attempt INTEGER NOT NULL CHECK(attempt=1),
                status TEXT NOT NULL CHECK(status IN ('RUNNING','PASS','FAIL')),
                database_path TEXT NOT NULL,
                config_digest TEXT NOT NULL,
                product_id TEXT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                PRIMARY KEY(epoch_id,scenario_id)
            );
            CREATE TABLE IF NOT EXISTS pre_q8_progress (
                epoch_id TEXT NOT NULL REFERENCES functional_epochs(epoch_id),
                scenario_id TEXT NOT NULL,
                attempt INTEGER NOT NULL CHECK(attempt=1),
                progress_fingerprint TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                first_observed_at TEXT NOT NULL,
                last_changed_at TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                PRIMARY KEY(epoch_id,scenario_id)
            );
            CREATE TABLE IF NOT EXISTS pre_q8_failures (
                epoch_id TEXT NOT NULL REFERENCES functional_epochs(epoch_id),
                scenario_id TEXT NOT NULL,
                attempt INTEGER NOT NULL CHECK(attempt=1),
                failure_class TEXT NOT NULL,
                failure_digest TEXT NOT NULL UNIQUE,
                evidence_ref TEXT NOT NULL,
                evidence_digest TEXT NOT NULL,
                candidate_database_ref TEXT NOT NULL,
                config_digest TEXT NOT NULL,
                support_bundle_ref TEXT NOT NULL,
                support_bundle_digest TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(epoch_id,scenario_id)
            );
            CREATE TABLE IF NOT EXISTS functional_schema_migrations (
                version INTEGER PRIMARY KEY,
                description TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS trg_pre_q8_pass_excludes_failure
            BEFORE INSERT ON pre_q8_scenarios
            WHEN EXISTS (
                SELECT 1 FROM pre_q8_failures
                 WHERE epoch_id=NEW.epoch_id AND scenario_id=NEW.scenario_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'PRE-Q8 PASS conflicts with durable failure');
            END;
            CREATE TRIGGER IF NOT EXISTS trg_pre_q8_failure_excludes_pass
            BEFORE INSERT ON pre_q8_failures
            WHEN EXISTS (
                SELECT 1 FROM pre_q8_scenarios
                 WHERE epoch_id=NEW.epoch_id AND scenario_id=NEW.scenario_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'PRE-Q8 failure conflicts with PASS');
            END;
            CREATE TABLE IF NOT EXISTS golden_products (
                epoch_id TEXT PRIMARY KEY REFERENCES functional_epochs(epoch_id),
                product_id TEXT NOT NULL,
                repository_ref TEXT NOT NULL,
                merge_commit TEXT NOT NULL,
                artifact_digest TEXT NOT NULL,
                completion_manifest_ref TEXT NOT NULL,
                verifier_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS functional_owner_actions (
                action_id TEXT PRIMARY KEY,
                epoch_id TEXT NOT NULL REFERENCES functional_epochs(epoch_id),
                reason_code TEXT NOT NULL,
                capability TEXT NOT NULL,
                capability_epoch TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                resolved_at TEXT,
                UNIQUE(epoch_id,reason_code,capability,capability_epoch)
            );
            CREATE TABLE IF NOT EXISTS functional_effects (
                idempotency_key TEXT PRIMARY KEY,
                effect_type TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS functional_epoch_retirements (
                epoch_id TEXT PRIMARY KEY REFERENCES functional_epochs(epoch_id),
                release_status TEXT NOT NULL CHECK(release_status='QUALIFICATION_FAILED'),
                release_snapshot_digest TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        with self.connection:
            self.connection.execute(
                "INSERT OR IGNORE INTO functional_schema_migrations "
                "(version,description,applied_at) VALUES (2,?,?)",
                ("durable PRE-Q8 admission, run, progress, and failure state", utc_now()),
            )

    def register_epoch(
        self,
        *,
        epoch_id: str,
        source_commit: str,
        candidate_digest: str,
        toolchain_digest: str,
    ) -> None:
        if not epoch_id or not _SHA40.fullmatch(source_commit):
            raise FunctionalReadinessError("functional epoch identity is invalid")
        if not _SHA256.fullmatch(candidate_digest) or not _SHA256.fullmatch(
            toolchain_digest
        ):
            raise FunctionalReadinessError("functional epoch digest is invalid")
        now = utc_now()
        with self.connection:
            existing = self.connection.execute(
                "SELECT source_commit,candidate_digest,toolchain_digest FROM functional_epochs "
                "WHERE epoch_id=?",
                (epoch_id,),
            ).fetchone()
            expected = (source_commit, candidate_digest, toolchain_digest)
            if existing is not None:
                if tuple(str(value) for value in existing) != expected:
                    raise FunctionalReadinessError("functional epoch identity conflicts")
                return
            self.connection.execute(
                """INSERT INTO functional_epochs
                   (epoch_id,source_commit,candidate_digest,toolchain_digest,status,
                    created_at,updated_at) VALUES (?,?,?,?,'Q6_5_PENDING',?,?)""",
                (epoch_id, source_commit, candidate_digest, toolchain_digest, now, now),
            )

    def retire_after_release_failure(
        self,
        *,
        epoch_id: str,
        source_commit: str,
        candidate_digest: str,
        release_status: str,
        release_snapshot_digest: str,
    ) -> bool:
        """Mirror a checkpointed terminal release decision into functional state."""

        if release_status != "QUALIFICATION_FAILED" or not _SHA256.fullmatch(
            release_snapshot_digest
        ):
            raise FunctionalReadinessError("functional retirement proof is invalid")
        epoch = self.epoch(epoch_id)
        if (
            str(epoch["source_commit"]) != source_commit
            or str(epoch["candidate_digest"]) != candidate_digest
        ):
            raise FunctionalReadinessError("functional retirement identity differs")
        expected = (release_status, release_snapshot_digest)
        existing = self.connection.execute(
            "SELECT release_status,release_snapshot_digest "
            "FROM functional_epoch_retirements WHERE epoch_id=?",
            (epoch_id,),
        ).fetchone()
        if existing is not None:
            if tuple(str(value) for value in existing) != expected:
                raise FunctionalReadinessError("functional retirement proof conflicts")
            if str(epoch["status"]) != "QUALIFICATION_FAILED":
                raise FunctionalReadinessError("retired functional epoch is not terminal")
            return False
        if str(epoch["status"]) in {
            "NON_PROMOTABLE",
            "QUALIFICATION_FAILED",
            "Q7_STARTED",
        }:
            raise FunctionalReadinessError("functional epoch cannot be retired")
        now = utc_now()
        with self.connection:
            self.connection.execute(
                """INSERT INTO functional_epoch_retirements
                   (epoch_id,release_status,release_snapshot_digest,created_at)
                   VALUES (?,?,?,?)""",
                (epoch_id, release_status, release_snapshot_digest, now),
            )
            self.connection.execute(
                """UPDATE functional_owner_actions SET status='RESOLVED',resolved_at=?
                     WHERE epoch_id=? AND status='OPEN'""",
                (now, epoch_id),
            )
            self.connection.execute(
                "UPDATE functional_epochs SET status='QUALIFICATION_FAILED',updated_at=? "
                "WHERE epoch_id=?",
                (now, epoch_id),
            )
        return True

    def epoch(self, epoch_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM functional_epochs WHERE epoch_id=?", (epoch_id,)
        ).fetchone()
        if row is None:
            raise KeyError(epoch_id)
        return dict(row)

    def record_handshake(
        self, epoch_id: str, report: CapabilityHandshakeReport
    ) -> None:
        report.validate()
        epoch = self.epoch(epoch_id)
        if str(epoch["candidate_digest"]) != report.candidate_digest:
            raise FunctionalReadinessError("capability report Candidate differs")
        if str(epoch["toolchain_digest"]) != report.toolchain_digest:
            raise FunctionalReadinessError("capability report toolchain differs")
        now = utc_now()
        with self.connection:
            existing = self.connection.execute(
                "SELECT report_digest FROM capability_handshake_reports "
                "WHERE epoch_id=? AND operation=?",
                (epoch_id, report.operation),
            ).fetchone()
            if existing is not None:
                if str(existing[0]) != report.report_digest:
                    raise FunctionalReadinessError("immutable capability report conflicts")
                return
            self.connection.execute(
                """INSERT INTO capability_handshake_reports
                   (epoch_id,operation,credential_epoch_id,status,report_json,
                    report_digest,created_at) VALUES (?,?,?,?,?,?,?)""",
                (
                    epoch_id,
                    report.operation,
                    report.credential_epoch_id,
                    report.status.value,
                    stable_json(report.as_dict()),
                    report.report_digest,
                    now,
                ),
            )
            self._refresh_q6_5(epoch_id, now)

    def _refresh_q6_5(self, epoch_id: str, now: str) -> None:
        rows = self.connection.execute(
            "SELECT operation,status FROM capability_handshake_reports WHERE epoch_id=?",
            (epoch_id,),
        ).fetchall()
        statuses = {str(row[0]): str(row[1]) for row in rows}
        complete = set(statuses) == set(MANDATORY_Q6_5_OPERATIONS)
        passed = complete and all(
            statuses[operation] == CapabilityStatus.AVAILABLE.value
            for operation in MANDATORY_Q6_5_OPERATIONS
        )
        if passed:
            self.connection.execute(
                "UPDATE functional_epochs SET q6_5_status='PASS',status='PRE_Q8_PENDING',"
                "updated_at=? WHERE epoch_id=?",
                (now, epoch_id),
            )
        elif any(value == CapabilityStatus.BROKEN_INTERNAL.value for value in statuses.values()):
            self.connection.execute(
                "UPDATE functional_epochs SET q6_5_status='FAIL',status='QUALIFICATION_FAILED',"
                "updated_at=? WHERE epoch_id=?",
                (now, epoch_id),
            )
        elif any(value == CapabilityStatus.MISSING_EXTERNAL.value for value in statuses.values()):
            self.connection.execute(
                "UPDATE functional_epochs SET q6_5_status='WAITING_CAPABILITY',"
                "status='WAITING_CAPABILITY',updated_at=? WHERE epoch_id=?",
                (now, epoch_id),
            )

    def ensure_owner_action(
        self,
        *,
        epoch_id: str,
        reason_code: str,
        capability: str,
        capability_epoch: str | None,
    ) -> str:
        if reason_code not in {
            "candidate_github_operation_denied",
            "candidate_github_workflow_permission_denied",
            "missing_candidate_github_credential",
            "missing_candidate_provider_credential",
            "missing_candidate_telegram_credential",
        }:
            raise FunctionalReadinessError("owner action reason is not external")
        seed = sha256_text(
            stable_json([epoch_id, reason_code, capability, capability_epoch])
        )
        action_id = f"OA-{seed[:24].upper()}"
        with self.connection:
            self.connection.execute(
                """INSERT OR IGNORE INTO functional_owner_actions
                   (action_id,epoch_id,reason_code,capability,capability_epoch,status,
                    created_at) VALUES (?,?,?,?,?,'OPEN',?)""",
                (
                    action_id,
                    epoch_id,
                    reason_code,
                    capability,
                    capability_epoch,
                    utc_now(),
                ),
            )
        return action_id

    def recover_external_capability(self, *, epoch_id: str, capability: str) -> bool:
        """Replace one immutable missing-external observation after a real recovery probe."""

        existing = self.connection.execute(
            "SELECT status FROM capability_handshake_reports WHERE epoch_id=? AND operation=?",
            (epoch_id, capability),
        ).fetchone()
        if existing is None:
            return False
        if str(existing[0]) != CapabilityStatus.MISSING_EXTERNAL.value:
            raise FunctionalReadinessError("recovered capability was not missing externally")
        now = utc_now()
        with self.connection:
            self.connection.execute(
                "DELETE FROM capability_handshake_reports WHERE epoch_id=? AND operation=?",
                (epoch_id, capability),
            )
            self.connection.execute(
                "UPDATE functional_owner_actions SET status='RESOLVED',resolved_at=? "
                "WHERE epoch_id=? AND capability=? AND status='OPEN'",
                (now, epoch_id, capability),
            )
            self.connection.execute(
                "UPDATE functional_epochs SET status='Q6_5_PENDING',q6_5_status='PENDING',"
                "updated_at=? WHERE epoch_id=?",
                (now, epoch_id),
            )
        return True

    def resolve_owner_action(self, *, epoch_id: str, capability: str) -> int:
        with self.connection:
            cursor = self.connection.execute(
                """UPDATE functional_owner_actions SET status='RESOLVED',resolved_at=?
                     WHERE epoch_id=? AND capability=? AND status='OPEN'""",
                (utc_now(), epoch_id, capability),
            )
        return int(cursor.rowcount)

    def capability_epoch_changed(
        self,
        *,
        epoch_id: str,
        old_epoch: str | None,
        new_epoch: str | None,
    ) -> bool:
        if not new_epoch or new_epoch == old_epoch:
            return False
        with self.connection:
            self.connection.execute(
                """UPDATE functional_owner_actions SET status='RESOLVED',resolved_at=?
                     WHERE epoch_id=? AND status='OPEN'""",
                (utc_now(), epoch_id),
            )
            self.connection.execute(
                "DELETE FROM capability_handshake_reports WHERE epoch_id=?",
                (epoch_id,),
            )
            self.connection.execute(
                "UPDATE functional_epochs SET status='Q6_5_PENDING',q6_5_status='PENDING',"
                "updated_at=? WHERE epoch_id=?",
                (utc_now(), epoch_id),
            )
        return True

    def admit_pre_q8(
        self,
        *,
        epoch_id: str,
        run_id: str,
        seal_digest: str,
        git_tree: str,
        release_tree_digest: str,
        candidate_digest: str,
    ) -> bool:
        """Persist an independently verified convergence seal before official execution."""

        epoch = self.epoch(epoch_id)
        if (
            str(epoch["q6_5_status"]) != "PASS"
            or str(epoch["status"]) not in {"PRE_Q8_PENDING", "PRE_Q8_RUNNING"}
        ):
            raise FunctionalReadinessError("PRE-Q8 admission requires Q6.5 PASS")
        if str(epoch["candidate_digest"]) != candidate_digest:
            raise FunctionalReadinessError("PRE-Q8 admission Candidate differs")
        if (
            _RUN_ID.fullmatch(run_id) is None
            or _SHA256.fullmatch(seal_digest) is None
            or _SHA40.fullmatch(git_tree) is None
            or _SHA256.fullmatch(release_tree_digest) is None
        ):
            raise FunctionalReadinessError("PRE-Q8 admission identity is invalid")
        open_actions = int(
            self.connection.execute(
                "SELECT COUNT(*) FROM functional_owner_actions "
                "WHERE epoch_id=? AND status='OPEN'",
                (epoch_id,),
            ).fetchone()[0]
        )
        if open_actions:
            raise FunctionalReadinessError("PRE-Q8 admission requires zero open owner actions")
        identity = (
            run_id,
            seal_digest,
            git_tree,
            release_tree_digest,
            candidate_digest,
        )
        existing = self.connection.execute(
            "SELECT run_id,seal_digest,git_tree,release_tree_digest,candidate_digest "
            "FROM pre_q8_admissions WHERE epoch_id=?",
            (epoch_id,),
        ).fetchone()
        if existing is not None:
            if tuple(str(value) for value in existing) != identity:
                raise FunctionalReadinessError("immutable PRE-Q8 admission conflicts")
            return False
        now = utc_now()
        with self.connection:
            self.connection.execute(
                """INSERT INTO pre_q8_admissions
                   (epoch_id,run_id,seal_digest,git_tree,release_tree_digest,
                    candidate_digest,admitted_at) VALUES (?,?,?,?,?,?,?)""",
                (epoch_id, *identity, now),
            )
            self.connection.execute(
                "UPDATE functional_epochs SET status='PRE_Q8_RUNNING',"
                "pre_q8_status='0/10 RUNNING',updated_at=? WHERE epoch_id=?",
                (now, epoch_id),
            )
        return True

    def start_pre_q8_scenario(
        self,
        *,
        epoch_id: str,
        scenario_id: str,
        attempt: int,
        database_path: str,
        config_digest: str,
    ) -> bool:
        epoch = self.epoch(epoch_id)
        if str(epoch["status"]) != "PRE_Q8_RUNNING":
            raise FunctionalReadinessError("official PRE-Q8 is not admitted")
        if scenario_id not in PRE_Q8_SCENARIOS or attempt != 1:
            raise FunctionalReadinessError("PRE-Q8 requires exact first-run scenario")
        if not database_path or _SHA256.fullmatch(config_digest) is None:
            raise FunctionalReadinessError("PRE-Q8 run identity is incomplete")
        if (
            self.connection.execute(
                "SELECT 1 FROM pre_q8_admissions WHERE epoch_id=?", (epoch_id,)
            ).fetchone()
            is None
        ):
            raise FunctionalReadinessError("official PRE-Q8 lacks convergence admission")
        position = PRE_Q8_SCENARIOS.index(scenario_id)
        passed = {
            str(row[0])
            for row in self.connection.execute(
                "SELECT scenario_id FROM pre_q8_scenarios "
                "WHERE epoch_id=? AND status='PASS'",
                (epoch_id,),
            ).fetchall()
        }
        if passed != set(PRE_Q8_SCENARIOS[:position]):
            raise FunctionalReadinessError("PRE-Q8 scenario order differs from canonical order")
        existing = self.connection.execute(
            "SELECT attempt,database_path,config_digest,status FROM pre_q8_runs "
            "WHERE epoch_id=? AND scenario_id=?",
            (epoch_id, scenario_id),
        ).fetchone()
        identity = (attempt, database_path, config_digest)
        if existing is not None:
            if tuple(existing[:3]) != identity:
                raise FunctionalReadinessError("immutable PRE-Q8 run identity conflicts")
            return False
        with self.connection:
            self.connection.execute(
                """INSERT INTO pre_q8_runs
                   (epoch_id,scenario_id,attempt,status,database_path,config_digest,
                    started_at) VALUES (?,?,1,'RUNNING',?,?,?)""",
                (epoch_id, scenario_id, database_path, config_digest, utc_now()),
            )
        return True

    def pre_q8_run(self, *, epoch_id: str, scenario_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM pre_q8_runs WHERE epoch_id=? AND scenario_id=?",
            (epoch_id, scenario_id),
        ).fetchone()
        return dict(row) if row is not None else None

    def record_pre_q8_progress(
        self,
        *,
        epoch_id: str,
        scenario_id: str,
        attempt: int,
        progress_fingerprint: str,
        snapshot: Mapping[str, Any],
        observed_at: str | None = None,
    ) -> bool:
        run = self.pre_q8_run(epoch_id=epoch_id, scenario_id=scenario_id)
        if run is None or str(run["status"]) != "RUNNING" or attempt != 1:
            raise FunctionalReadinessError("PRE-Q8 progress requires a running first attempt")
        if _SHA256.fullmatch(progress_fingerprint) is None:
            raise FunctionalReadinessError("PRE-Q8 progress fingerprint is invalid")
        encoded = stable_json(dict(snapshot))
        if sha256_text(encoded) != progress_fingerprint:
            raise FunctionalReadinessError("PRE-Q8 progress snapshot differs from fingerprint")
        now = observed_at or utc_now()
        existing = self.connection.execute(
            "SELECT progress_fingerprint,first_observed_at,last_changed_at "
            "FROM pre_q8_progress WHERE epoch_id=? AND scenario_id=?",
            (epoch_id, scenario_id),
        ).fetchone()
        changed = existing is None or str(existing[0]) != progress_fingerprint
        first = str(existing[1]) if existing is not None else now
        last_changed = now if changed else str(existing[2])
        with self.connection:
            self.connection.execute(
                """INSERT INTO pre_q8_progress
                   (epoch_id,scenario_id,attempt,progress_fingerprint,snapshot_json,
                    first_observed_at,last_changed_at,checked_at)
                   VALUES (?,?,1,?,?,?,?,?)
                   ON CONFLICT(epoch_id,scenario_id) DO UPDATE SET
                     progress_fingerprint=excluded.progress_fingerprint,
                     snapshot_json=excluded.snapshot_json,
                     last_changed_at=excluded.last_changed_at,
                     checked_at=excluded.checked_at""",
                (
                    epoch_id,
                    scenario_id,
                    progress_fingerprint,
                    encoded,
                    first,
                    last_changed,
                    now,
                ),
            )
        return changed

    def record_pre_q8_failure(
        self,
        *,
        epoch_id: str,
        scenario_id: str,
        attempt: int,
        failure_class: str,
        failure_digest: str,
        evidence_ref: str,
        evidence_digest: str,
        candidate_database_ref: str,
        config_digest: str,
        support_bundle_ref: str,
        support_bundle_digest: str,
    ) -> bool:
        """Atomically terminalize one official Candidate on its first PRE-Q8 failure."""

        epoch = self.epoch(epoch_id)
        if str(epoch["q6_5_status"]) != "PASS" or str(epoch["status"]) not in {
            "PRE_Q8_PENDING",
            "PRE_Q8_RUNNING",
            "QUALIFICATION_FAILED",
        }:
            raise FunctionalReadinessError("PRE-Q8 failure requires a qualified Candidate")
        if scenario_id not in PRE_Q8_SCENARIOS or attempt != 1:
            raise FunctionalReadinessError("PRE-Q8 failure requires exact first attempt")
        if _FAILURE_CLASS.fullmatch(failure_class) is None:
            raise FunctionalReadinessError("PRE-Q8 failure class is invalid")
        if any(
            _SHA256.fullmatch(value) is None
            for value in (
                failure_digest,
                evidence_digest,
                config_digest,
                support_bundle_digest,
            )
        ) or not all(
            (evidence_ref, candidate_database_ref, support_bundle_ref)
        ):
            raise FunctionalReadinessError("PRE-Q8 failure evidence is incomplete")
        identity = (
            attempt,
            failure_class,
            failure_digest,
            evidence_ref,
            evidence_digest,
            candidate_database_ref,
            config_digest,
            support_bundle_ref,
            support_bundle_digest,
        )
        existing = self.connection.execute(
            """SELECT attempt,failure_class,failure_digest,evidence_ref,evidence_digest,
                      candidate_database_ref,config_digest,support_bundle_ref,
                      support_bundle_digest
                 FROM pre_q8_failures WHERE epoch_id=? AND scenario_id=?""",
            (epoch_id, scenario_id),
        ).fetchone()
        if existing is not None:
            if tuple(existing) != identity:
                raise FunctionalReadinessError("immutable PRE-Q8 failure conflicts")
            if str(epoch["status"]) != "QUALIFICATION_FAILED":
                raise FunctionalReadinessError("PRE-Q8 failure did not terminalize Candidate")
            return False
        if str(epoch["status"]) == "QUALIFICATION_FAILED":
            raise FunctionalReadinessError("terminal Candidate cannot record another PRE-Q8 failure")
        if (
            self.connection.execute(
                "SELECT 1 FROM pre_q8_scenarios WHERE epoch_id=? AND scenario_id=?",
                (epoch_id, scenario_id),
            ).fetchone()
            is not None
        ):
            raise FunctionalReadinessError("PRE-Q8 failure conflicts with PASS")
        now = utc_now()
        with self.connection:
            self.connection.execute(
                """INSERT INTO pre_q8_failures
                   (epoch_id,scenario_id,attempt,failure_class,failure_digest,
                    evidence_ref,evidence_digest,candidate_database_ref,
                    config_digest,support_bundle_ref,support_bundle_digest,created_at)
                   VALUES (?,?,1,?,?,?,?,?,?,?,?,?)""",
                (
                    epoch_id,
                    scenario_id,
                    failure_class,
                    failure_digest,
                    evidence_ref,
                    evidence_digest,
                    candidate_database_ref,
                    config_digest,
                    support_bundle_ref,
                    support_bundle_digest,
                    now,
                ),
            )
            run = self.pre_q8_run(epoch_id=epoch_id, scenario_id=scenario_id)
            if run is None:
                self.connection.execute(
                    """INSERT INTO pre_q8_runs
                       (epoch_id,scenario_id,attempt,status,database_path,config_digest,
                        started_at,finished_at) VALUES (?,?,1,'FAIL',?,?,?,?)""",
                    (
                        epoch_id,
                        scenario_id,
                        candidate_database_ref,
                        config_digest,
                        now,
                        now,
                    ),
                )
            else:
                if (
                    str(run["database_path"]) != candidate_database_ref
                    or str(run["config_digest"]) != config_digest
                ):
                    raise FunctionalReadinessError(
                        "PRE-Q8 failure run identity conflicts"
                    )
                self.connection.execute(
                    "UPDATE pre_q8_runs SET status='FAIL',finished_at=? "
                    "WHERE epoch_id=? AND scenario_id=?",
                    (now, epoch_id, scenario_id),
                )
            self.connection.execute(
                "UPDATE functional_epochs SET status='QUALIFICATION_FAILED',"
                "pre_q8_status=?,updated_at=? WHERE epoch_id=?",
                (f"FAIL {scenario_id}", now, epoch_id),
            )
        return True

    def record_pre_q8_pass(
        self,
        *,
        epoch_id: str,
        scenario_id: str,
        attempt: int,
        product_id: str,
        completion_manifest_ref: str,
        evidence_digest: str,
    ) -> None:
        epoch = self.epoch(epoch_id)
        if scenario_id not in PRE_Q8_SCENARIOS or attempt != 1:
            raise FunctionalReadinessError("PRE-Q8 requires exact first-run scenario")
        if str(epoch["q6_5_status"]) != "PASS" or str(epoch["status"]) != "PRE_Q8_RUNNING":
            raise FunctionalReadinessError("PRE-Q8 requires verified admission")
        if not product_id or not completion_manifest_ref or not _SHA256.fullmatch(
            evidence_digest
        ):
            raise FunctionalReadinessError("PRE-Q8 evidence is incomplete")
        now = utc_now()
        with self.connection:
            existing = self.connection.execute(
                "SELECT product_id,completion_manifest_ref,evidence_digest "
                "FROM pre_q8_scenarios WHERE epoch_id=? AND scenario_id=?",
                (epoch_id, scenario_id),
            ).fetchone()
            if existing is not None:
                if tuple(str(value) for value in existing) != (
                    product_id,
                    completion_manifest_ref,
                    evidence_digest,
                ):
                    raise FunctionalReadinessError("PRE-Q8 immutable evidence conflicts")
                return
            run = self.pre_q8_run(epoch_id=epoch_id, scenario_id=scenario_id)
            if run is None or str(run["status"]) != "RUNNING":
                raise FunctionalReadinessError("PRE-Q8 PASS requires one running attempt")
            if (
                self.connection.execute(
                    "SELECT 1 FROM pre_q8_failures WHERE epoch_id=? AND scenario_id=?",
                    (epoch_id, scenario_id),
                ).fetchone()
                is not None
            ):
                raise FunctionalReadinessError("PRE-Q8 PASS conflicts with durable failure")
            self.connection.execute(
                """INSERT OR IGNORE INTO pre_q8_scenarios
                   (epoch_id,scenario_id,attempt,status,product_id,
                    completion_manifest_ref,evidence_digest,created_at)
                   VALUES (?,?,1,'PASS',?,?,?,?)""",
                (
                    epoch_id,
                    scenario_id,
                    product_id,
                    completion_manifest_ref,
                    evidence_digest,
                    now,
                ),
            )
            self.connection.execute(
                "UPDATE pre_q8_runs SET status='PASS',product_id=?,finished_at=? "
                "WHERE epoch_id=? AND scenario_id=?",
                (product_id, now, epoch_id, scenario_id),
            )
            count = int(
                self.connection.execute(
                    "SELECT COUNT(*) FROM pre_q8_scenarios WHERE epoch_id=? AND status='PASS'",
                    (epoch_id,),
                ).fetchone()[0]
            )
            self.connection.execute(
                "UPDATE functional_epochs SET pre_q8_status=?,updated_at=? WHERE epoch_id=?",
                (f"{count}/10 PASS", now, epoch_id),
            )

    def finalize_pre_q8(self, epoch_id: str) -> bool:
        epoch = self.epoch(epoch_id)
        if str(epoch["status"]) == "GOLDEN_PRODUCT_PENDING":
            return False
        if str(epoch["status"]) != "PRE_Q8_RUNNING":
            raise FunctionalReadinessError("PRE-Q8 cannot be finalized from current state")
        rows = self.connection.execute(
            "SELECT scenario_id,attempt,status FROM pre_q8_runs "
            "WHERE epoch_id=? ORDER BY rowid",
            (epoch_id,),
        ).fetchall()
        identity = tuple((str(row[0]), int(row[1]), str(row[2])) for row in rows)
        expected = tuple((scenario, 1, "PASS") for scenario in PRE_Q8_SCENARIOS)
        if identity != expected:
            raise FunctionalReadinessError("PRE-Q8 finalization requires canonical 10/10 attempt=1")
        if (
            self.connection.execute(
                "SELECT COUNT(*) FROM pre_q8_failures WHERE epoch_id=?", (epoch_id,)
            ).fetchone()[0]
            != 0
        ):
            raise FunctionalReadinessError("PRE-Q8 finalization conflicts with failure")
        with self.connection:
            self.connection.execute(
                "UPDATE functional_epochs SET pre_q8_status='10/10 PASS',"
                "status='GOLDEN_PRODUCT_PENDING',updated_at=? WHERE epoch_id=?",
                (utc_now(), epoch_id),
            )
        return True

    def record_golden_product(
        self,
        *,
        epoch_id: str,
        product_id: str,
        repository_ref: str,
        merge_commit: str,
        artifact_digest: str,
        completion_manifest_ref: str,
        verifier_digest: str,
    ) -> None:
        epoch = self.epoch(epoch_id)
        if str(epoch["pre_q8_status"]) != "10/10 PASS":
            raise FunctionalReadinessError("Golden Product requires PRE-Q8 10/10 PASS")
        if (
            not product_id
            or not repository_ref.startswith("github://")
            or not _SHA40.fullmatch(merge_commit)
            or not _SHA256.fullmatch(artifact_digest)
            or not completion_manifest_ref
            or not _SHA256.fullmatch(verifier_digest)
        ):
            raise FunctionalReadinessError("Golden Product evidence is invalid")
        identity = (
            product_id,
            repository_ref,
            merge_commit,
            artifact_digest,
            completion_manifest_ref,
            verifier_digest,
        )
        with self.connection:
            existing = self.connection.execute(
                """SELECT product_id,repository_ref,merge_commit,artifact_digest,
                          completion_manifest_ref,verifier_digest
                     FROM golden_products WHERE epoch_id=?""",
                (epoch_id,),
            ).fetchone()
            if existing is not None:
                if tuple(str(value) for value in existing) != identity:
                    raise FunctionalReadinessError("Golden Product immutable evidence conflicts")
                return
            self.connection.execute(
                """INSERT INTO golden_products
                   (epoch_id,product_id,repository_ref,merge_commit,artifact_digest,
                    completion_manifest_ref,verifier_digest,status,created_at)
                   VALUES (?,?,?,?,?,?,?,'COMPLETED',?)""",
                (
                    epoch_id,
                    product_id,
                    repository_ref,
                    merge_commit,
                    artifact_digest,
                    completion_manifest_ref,
                    verifier_digest,
                    utc_now(),
                ),
            )
            self.connection.execute(
                "UPDATE functional_epochs SET golden_product_status='COMPLETED',"
                "status='READY_EVALUATION',updated_at=? WHERE epoch_id=?",
                (utc_now(), epoch_id),
            )

    def record_factory_checks(
        self,
        *,
        epoch_id: str,
        internal_verifier_pass: bool,
        stable_health_pass: bool,
        stable_intake_pass: bool,
    ) -> None:
        epoch = self.epoch(epoch_id)
        if str(epoch["golden_product_status"]) != "COMPLETED":
            raise FunctionalReadinessError("factory checks require Golden Product COMPLETED")
        open_actions = int(
            self.connection.execute(
                "SELECT COUNT(*) FROM functional_owner_actions WHERE epoch_id=? AND status='OPEN'",
                (epoch_id,),
            ).fetchone()[0]
        )
        if open_actions:
            raise FunctionalReadinessError("factory checks require zero open owner actions")
        values = (
            "PASS" if internal_verifier_pass else "FAIL",
            "PASS" if stable_health_pass else "FAIL",
            "PASS" if stable_intake_pass else "FAIL",
        )
        ready = all(value == "PASS" for value in values)
        with self.connection:
            self.connection.execute(
                """UPDATE functional_epochs
                      SET internal_verifier_status=?,stable_health_status=?,
                          stable_intake_status=?,status=?,updated_at=? WHERE epoch_id=?""",
                (*values, "FUNCTIONALLY_READY" if ready else "QUALIFICATION_FAILED", utc_now(), epoch_id),
            )

    def authorize_q7(self, epoch_id: str) -> dict[str, Any]:
        epoch = self.epoch(epoch_id)
        key = sha256_text(stable_json([epoch_id, "start-q7-v1"]))
        existing = self.connection.execute(
            "SELECT result_json FROM functional_effects WHERE idempotency_key=?", (key,)
        ).fetchone()
        if existing is not None:
            value = json.loads(str(existing[0]))
            if not isinstance(value, dict):
                raise FunctionalReadinessError("Q7 effect receipt is invalid")
            return dict(value)
        required = {
            "q6_5_status": "PASS",
            "pre_q8_status": "10/10 PASS",
            "golden_product_status": "COMPLETED",
            "internal_verifier_status": "PASS",
            "stable_health_status": "PASS",
            "stable_intake_status": "PASS",
            "status": "FUNCTIONALLY_READY",
        }
        if any(str(epoch[key]) != value for key, value in required.items()):
            raise FunctionalReadinessError("Q7 start rejected: functional gates incomplete")
        result = {
            "epoch_id": epoch_id,
            "effect": "START_Q7",
            "candidate_digest": str(epoch["candidate_digest"]),
            "authorized_at": utc_now(),
        }
        with self.connection:
            self.connection.execute(
                "INSERT INTO functional_effects VALUES (?,?,?,?)",
                (key, "START_Q7", stable_json(result), utc_now()),
            )
            self.connection.execute(
                "UPDATE functional_epochs SET status='Q7_STARTED',q7_started_at=?,"
                "updated_at=? WHERE epoch_id=?",
                (result["authorized_at"], result["authorized_at"], epoch_id),
            )
        return result


@dataclass(frozen=True)
class ReadyResultManifest:
    manifest_type: str
    subject: Mapping[str, Any]
    version: str
    commit: str
    digest: str
    mandatory_obligations: tuple[Mapping[str, Any], ...]
    evidence_refs: tuple[str, ...]
    verifier_digest: str
    verifier_signature: str
    manifest_digest: str

    @classmethod
    def create(
        cls,
        *,
        manifest_type: str,
        subject: Mapping[str, Any],
        version: str,
        commit: str,
        digest: str,
        mandatory_obligations: Sequence[Mapping[str, Any]],
        evidence_refs: Sequence[str],
        verifier_digest: str,
        verifier_signature: str,
    ) -> ReadyResultManifest:
        allowed = {
            "FACTORY_FUNCTIONALLY_READY",
            "FACTORY_PRODUCTION_READY",
            "FACTORY_LTS_READY",
            "PRODUCT_READY_RESULT",
        }
        if manifest_type not in allowed:
            raise FunctionalReadinessError("ready manifest type is invalid")
        if manifest_type == "PRODUCT_READY_RESULT" and str(subject.get("state")) != "COMPLETED":
            raise FunctionalReadinessError("product ready result requires COMPLETED state")
        if not _SHA40.fullmatch(commit) or not _SHA256.fullmatch(digest):
            raise FunctionalReadinessError("ready release identity is invalid")
        if not _SHA256.fullmatch(verifier_digest) or not verifier_signature:
            raise FunctionalReadinessError("independent verifier identity is invalid")
        obligations = tuple(dict(value) for value in mandatory_obligations)
        if not obligations or any(
            set(value) != {"obligation_id", "status", "evidence_ref"}
            or value["status"] != "PASS"
            or not value["evidence_ref"]
            for value in obligations
        ):
            raise FunctionalReadinessError("ready evidence obligations are incomplete")
        if not evidence_refs:
            raise FunctionalReadinessError("ready manifest evidence is empty")
        payload = {
            "schema_version": "1.0",
            "manifest_type": manifest_type,
            "status": "PASS",
            "subject": dict(subject),
            "release_identity": {"version": version, "commit": commit, "digest": digest},
            "mandatory_obligations": list(obligations),
            "evidence_refs": list(evidence_refs),
            "open_blockers": [],
            "verifier": {"digest": verifier_digest, "signature": verifier_signature},
        }
        return cls(
            manifest_type=manifest_type,
            subject=dict(subject),
            version=version,
            commit=commit,
            digest=digest,
            mandatory_obligations=obligations,
            evidence_refs=tuple(evidence_refs),
            verifier_digest=verifier_digest,
            verifier_signature=verifier_signature,
            manifest_digest=sha256_text(stable_json(payload)),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "manifest_type": self.manifest_type,
            "status": "PASS",
            "subject": dict(self.subject),
            "release_identity": {
                "version": self.version,
                "commit": self.commit,
                "digest": self.digest,
            },
            "mandatory_obligations": [dict(value) for value in self.mandatory_obligations],
            "evidence_refs": list(self.evidence_refs),
            "open_blockers": [],
            "verifier": {
                "digest": self.verifier_digest,
                "signature": self.verifier_signature,
            },
            "manifest_digest": self.manifest_digest,
        }


def ready_manifest_unsigned_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical payload signed by the independent verifier."""

    payload = {str(key): item for key, item in value.items() if key != "manifest_digest"}
    verifier = payload.get("verifier")
    if not isinstance(verifier, Mapping):
        raise FunctionalReadinessError("ready verifier identity is missing")
    payload["verifier"] = {"digest": str(verifier.get("digest") or "")}
    return payload


def verify_ready_result_manifest(
    value: Mapping[str, Any],
    *,
    verifier_public_key: str,
    trusted_public_key_digest: str,
) -> str:
    """Independently verify exact digests and an Ed25519 signature."""

    envelope = {str(key): item for key, item in value.items()}
    expected_keys = {
        "schema_version",
        "manifest_type",
        "status",
        "subject",
        "release_identity",
        "mandatory_obligations",
        "evidence_refs",
        "open_blockers",
        "verifier",
        "manifest_digest",
    }
    if set(envelope) != expected_keys:
        raise FunctionalReadinessError("ready manifest schema is invalid")
    manifest_digest = str(envelope.get("manifest_digest") or "")
    signed_payload = {key: item for key, item in envelope.items() if key != "manifest_digest"}
    if not _SHA256.fullmatch(manifest_digest) or sha256_text(
        stable_json(signed_payload)
    ) != manifest_digest:
        raise FunctionalReadinessError("ready manifest digest differs")
    verifier = envelope.get("verifier")
    if not isinstance(verifier, Mapping) or set(verifier) != {"digest", "signature"}:
        raise FunctionalReadinessError("ready verifier schema is invalid")
    try:
        public_bytes = base64.b64decode(verifier_public_key, validate=True)
        signature = base64.b64decode(str(verifier["signature"]), validate=True)
    except (ValueError, TypeError) as error:
        raise FunctionalReadinessError("ready signature encoding is invalid") from error
    if len(public_bytes) != 32 or hashlib.sha256(public_bytes).hexdigest() != (
        trusted_public_key_digest
    ):
        raise FunctionalReadinessError("ready verifier trust root differs")
    if not _SHA256.fullmatch(str(verifier["digest"])):
        raise FunctionalReadinessError("ready verifier digest is invalid")
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature,
            stable_json(ready_manifest_unsigned_payload(envelope)).encode("utf-8"),
        )
    except (ValueError, InvalidSignature) as error:
        raise FunctionalReadinessError("ready manifest signature is invalid") from error
    return manifest_digest
