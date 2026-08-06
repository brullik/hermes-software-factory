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
            "missing_candidate_github_credential",
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
        if str(epoch["q6_5_status"]) != "PASS":
            raise FunctionalReadinessError("PRE-Q8 requires Q6.5 PASS")
        if scenario_id not in PRE_Q8_SCENARIOS or attempt != 1:
            raise FunctionalReadinessError("PRE-Q8 requires exact first-run scenario")
        if not product_id or not completion_manifest_ref or not _SHA256.fullmatch(
            evidence_digest
        ):
            raise FunctionalReadinessError("PRE-Q8 evidence is incomplete")
        now = utc_now()
        with self.connection:
            existing = self.connection.execute(
                "SELECT evidence_digest FROM pre_q8_scenarios WHERE epoch_id=? AND scenario_id=?",
                (epoch_id, scenario_id),
            ).fetchone()
            if existing is not None and str(existing[0]) != evidence_digest:
                raise FunctionalReadinessError("PRE-Q8 immutable evidence conflicts")
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
            count = int(
                self.connection.execute(
                    "SELECT COUNT(*) FROM pre_q8_scenarios WHERE epoch_id=? AND status='PASS'",
                    (epoch_id,),
                ).fetchone()[0]
            )
            if count == len(PRE_Q8_SCENARIOS):
                self.connection.execute(
                    "UPDATE functional_epochs SET pre_q8_status='10/10 PASS',"
                    "status='GOLDEN_PRODUCT_PENDING',updated_at=? WHERE epoch_id=?",
                    (now, epoch_id),
                )

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
