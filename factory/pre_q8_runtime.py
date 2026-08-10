"""Typed PRE-Q8 worker liveness and deterministic progress observations."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from .common import sha256_text, stable_json


class PreQ8RuntimeError(RuntimeError):
    """The PRE-Q8 runtime state cannot be classified safely."""


class WorkerState(StrEnum):
    BUSY = "BUSY"
    RESTART_GRACE = "RESTART_GRACE"
    IDLE = "IDLE"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class OfficialTimerDecision(StrEnum):
    ADMIT = "ADMIT"
    RESUME = "RESUME"
    TERMINAL = "TERMINAL"
    COMPLETE = "COMPLETE"
    NOOP = "NOOP"


class CrashReconciliationDecision(StrEnum):
    MISSING = "MISSING"
    STALE_DATABASE = "STALE_DATABASE"
    OBSERVE_COMPLETED = "OBSERVE_COMPLETED"
    INTERRUPTED_OFFICIAL_RUN = "INTERRUPTED_OFFICIAL_RUN"


@dataclass(frozen=True)
class UnitSnapshot:
    active_state: str
    sub_state: str
    result: str
    n_restarts: int
    main_pid: int
    exec_main_code: int
    exec_main_status: int

    @classmethod
    def from_properties(cls, value: Mapping[str, object]) -> UnitSnapshot:
        def integer(name: str) -> int:
            try:
                return int(str(value.get(name, 0) or 0))
            except (TypeError, ValueError) as error:
                raise PreQ8RuntimeError(f"systemd property {name} is invalid") from error

        return cls(
            active_state=str(value.get("ActiveState", "")).strip(),
            sub_state=str(value.get("SubState", "")).strip(),
            result=str(value.get("Result", "")).strip(),
            n_restarts=integer("NRestarts"),
            main_pid=integer("MainPID"),
            exec_main_code=integer("ExecMainCode"),
            exec_main_status=integer("ExecMainStatus"),
        )


@dataclass(frozen=True)
class WorkerAssessment:
    state: WorkerState
    worker_idle: bool
    failure_class: str | None
    reason: str


_BUSY_ACTIVE_STATES: Final[frozenset[str]] = frozenset(
    {"active", "activating", "reloading", "deactivating"}
)
_BUSY_SUB_STATES: Final[frozenset[str]] = frozenset(
    {"running", "start", "start-pre", "start-post", "reload", "auto-restart", "stop-sigterm"}
)
_FRONTIER_STATES: Final[frozenset[str]] = frozenset(
    {"PENDING", "CLAIMED", "WAITING", "BLOCKED_EXTERNAL"}
)


def official_timer_decision(epoch_status: str) -> OfficialTimerDecision:
    """Return a retry-safe action for a functional timer tick."""

    if epoch_status == "PRE_Q8_PENDING":
        return OfficialTimerDecision.ADMIT
    if epoch_status == "PRE_Q8_RUNNING":
        return OfficialTimerDecision.RESUME
    if epoch_status == "QUALIFICATION_FAILED":
        return OfficialTimerDecision.TERMINAL
    if epoch_status in {
        "GOLDEN_PRODUCT_PENDING",
        "READY_EVALUATION",
        "FUNCTIONALLY_READY",
        "Q7_STARTED",
    }:
        return OfficialTimerDecision.COMPLETE
    return OfficialTimerDecision.NOOP


def crash_reconciliation_decision(
    *, durable_run_status: str | None, database_exists: bool, product_completed: bool
) -> CrashReconciliationDecision:
    """Decide crash recovery without permitting a second official execution."""

    if durable_run_status is None:
        return (
            CrashReconciliationDecision.STALE_DATABASE
            if database_exists
            else CrashReconciliationDecision.MISSING
        )
    if durable_run_status != "RUNNING":
        raise PreQ8RuntimeError("durable PRE-Q8 run has no terminal evidence")
    if product_completed:
        return CrashReconciliationDecision.OBSERVE_COMPLETED
    return CrashReconciliationDecision.INTERRUPTED_OFFICIAL_RUN


def classify_worker(
    snapshot: UnitSnapshot,
    *,
    restart_job_pending: bool,
    active_lease: bool,
    frontier_statuses: Sequence[str],
    no_progress_window_elapsed: bool,
    intentional_restart_expected: bool = False,
    intentional_restart_receipt_verified: bool = False,
) -> WorkerAssessment:
    """Classify a worker without treating process absence as proof of idleness."""

    active = snapshot.active_state.lower()
    sub = snapshot.sub_state.lower()
    result = snapshot.result.lower()
    if active == "failed" or result == "failed":
        return WorkerAssessment(
            WorkerState.FAILED,
            False,
            "WORKER_UNIT_FAILED",
            "systemd reports a failed worker unit",
        )
    if intentional_restart_expected and not intentional_restart_receipt_verified:
        return WorkerAssessment(
            WorkerState.RESTART_GRACE,
            False,
            None,
            "intentional restart receipt has not been verified",
        )
    if active in _BUSY_ACTIVE_STATES or sub in _BUSY_SUB_STATES:
        return WorkerAssessment(
            WorkerState.BUSY,
            False,
            None,
            "worker is active, transitioning, or in auto-restart",
        )
    if restart_job_pending:
        return WorkerAssessment(
            WorkerState.BUSY,
            False,
            None,
            "a worker restart job is pending",
        )
    normalized_frontier = {str(value).upper() for value in frontier_statuses}
    if active_lease or normalized_frontier & _FRONTIER_STATES:
        return WorkerAssessment(
            WorkerState.BUSY,
            False,
            None,
            "durable lease or runnable frontier remains",
        )
    normal_exit = result in {"", "success"} and snapshot.exec_main_status == 0
    if (
        active == "inactive"
        and sub == "dead"
        and normal_exit
        and no_progress_window_elapsed
        and (not intentional_restart_expected or intentional_restart_receipt_verified)
    ):
        return WorkerAssessment(
            WorkerState.IDLE,
            True,
            None,
            "inactive worker has no restart, lease, or frontier after the no-progress window",
        )
    return WorkerAssessment(
        WorkerState.UNKNOWN,
        False,
        "WORKER_STATE_UNCLASSIFIED",
        "worker state is not a proven idle or typed failure state",
    )


_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]*$")


def _table_exists(connection: sqlite3.Connection, name: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
        is not None
    )


def _grouped(connection: sqlite3.Connection, table: str, column: str) -> dict[str, int]:
    if not _IDENTIFIER.fullmatch(table) or not _IDENTIFIER.fullmatch(column):
        raise PreQ8RuntimeError("progress query identifier is invalid")
    if not _table_exists(connection, table):
        return {}
    rows = connection.execute(
        f'SELECT "{column}",COUNT(*) FROM "{table}" GROUP BY "{column}" ORDER BY "{column}"'
    ).fetchall()
    return {str(row[0]): int(row[1]) for row in rows}


def progress_snapshot(database: Path) -> dict[str, Any]:
    """Return a deterministic, wall-clock-free fingerprint body from Candidate state."""

    if not database.is_absolute() or not database.is_file() or database.is_symlink():
        raise PreQ8RuntimeError("Candidate progress database is unavailable")
    connection = sqlite3.connect(
        f"file:{database.resolve().as_posix()}?mode=ro", uri=True, timeout=20
    )
    try:
        connection.execute("PRAGMA query_only=ON")
        integrity = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        if integrity != "ok":
            raise PreQ8RuntimeError("Candidate progress database integrity failed")
        tasks = _grouped(connection, "tasks", "status")
        products = _grouped(connection, "products", "status")
        active_leases = 0
        frontier_ids: list[str] = []
        if _table_exists(connection, "tasks"):
            columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(tasks)").fetchall()
            }
            if {"task_id", "status"} <= columns:
                frontier_ids = [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT task_id FROM tasks WHERE status IN "
                        "('PENDING','CLAIMED','WAITING','BLOCKED_EXTERNAL') ORDER BY task_id"
                    ).fetchall()
                ]
            if {"status", "lease_owner", "lease_until"} <= columns:
                active_leases = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM tasks WHERE status='CLAIMED' "
                        "AND lease_owner IS NOT NULL AND lease_until IS NOT NULL"
                    ).fetchone()[0]
                )
        counts: dict[str, int] = {}
        for table in (
            "attempts",
            "side_effect_intents",
            "side_effect_receipts",
            "completion_manifests",
            "controller_incidents",
            "recovery_applications",
        ):
            counts[table] = (
                int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
                if _table_exists(connection, table)
                else 0
            )
        failures: list[dict[str, str]] = []
        if _table_exists(connection, "failures"):
            columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(failures)").fetchall()
            }
            if {"reason_code"} <= columns:
                order = "failure_id" if "failure_id" in columns else "reason_code"
                failures = [
                    {"reason_code": str(row[0]), "failure_action": str(row[1] or "")}
                    for row in connection.execute(
                        f"SELECT reason_code,"
                        f"{'failure_action' if 'failure_action' in columns else 'NULL'} "
                        f"FROM failures ORDER BY {order}"
                    ).fetchall()
                ]
        body = {
            "schema_version": "1.0",
            "database_integrity": integrity,
            "product_statuses": products,
            "task_statuses": tasks,
            "frontier_task_ids": frontier_ids,
            "active_lease_count": active_leases,
            "terminal_failures": failures,
            "counts": counts,
        }
        return {**body, "progress_fingerprint": sha256_text(stable_json(body))}
    finally:
        connection.close()


def parse_systemctl_show(text: str) -> UnitSnapshot:
    properties: dict[str, object] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        properties[key] = value
    return UnitSnapshot.from_properties(properties)


def assessment_json(assessment: WorkerAssessment) -> str:
    return json.dumps(
        {
            "state": assessment.state.value,
            "worker_idle": assessment.worker_idle,
            "failure_class": assessment.failure_class,
            "reason": assessment.reason,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
