"""Small durable SQLite state store for single-node controller deployments."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .common import utc_now


class ProductCapacityError(ValueError):
    """Raised when the configured active-product quota is exhausted."""


class IntakeRateLimitError(ValueError):
    """Raised when an intake source exceeds its durable request budget."""


_RECOVERABLE_PRODUCT_STATUSES = {
    "IDEA_RECEIVED",
    "CONTRACT_DRAFTED",
    "CONTRACT_VALIDATED",
    "RISK_CLASSIFIED",
    "ARCHITECTED",
    "BACKLOG_READY",
    "IMPLEMENTING",
    "INTEGRATING",
    "STAGING_DEPLOYED",
    "PRODUCT_ACCEPTANCE",
    "RELEASE_READY",
    "PRODUCTION_DEPLOYED",
    "OBSERVATION",
    "REPAIRING",
    "DELAYED_QUOTA",
    "ROLLING_BACK",
    "ROLLED_BACK",
}


class StateStore:
    def __init__(
        self,
        database_path: Path,
        *,
        max_active_workers: int = 2,
        max_active_products: int = 1,
    ) -> None:
        if max_active_workers < 1 or max_active_workers > 2:
            raise ValueError("max_active_workers must be between 1 and 2")
        if max_active_products < 1:
            raise ValueError("max_active_products must be positive")
        self.database_path = database_path
        self.max_active_workers = max_active_workers
        self.max_active_products = max_active_products
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.database_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._initialize()

    def _initialize(self) -> None:
        with self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS products (
                    product_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    idea TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    product_id TEXT NOT NULL REFERENCES products(product_id),
                    title TEXT NOT NULL,
                    role TEXT,
                    output_schema TEXT,
                    contract_ref TEXT,
                    priority INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    dependencies_json TEXT NOT NULL,
                    conflict_keys_json TEXT NOT NULL,
                    lease_owner TEXT,
                    lease_until TEXT,
                    heartbeat_at TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id TEXT,
                    task_id TEXT,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS attempts (
                    attempt_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    tier TEXT NOT NULL,
                    attempt_kind TEXT NOT NULL,
                    prompt_digest TEXT NOT NULL,
                    reason_code TEXT,
                    status TEXT NOT NULL,
                    semantic_counted INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(task_id, prompt_digest)
                );
                CREATE TABLE IF NOT EXISTS outbox (
                    outbox_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    lease_owner TEXT,
                    lease_until TEXT,
                    created_at TEXT NOT NULL,
                    delivered_at TEXT
                );
                CREATE TABLE IF NOT EXISTS intake_requests (
                    request_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    created_at_epoch INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
                CREATE INDEX IF NOT EXISTS idx_events_product ON events(product_id, event_id);
                CREATE INDEX IF NOT EXISTS idx_attempts_task ON attempts(task_id, tier);
                CREATE INDEX IF NOT EXISTS idx_intake_requests_owner
                    ON intake_requests(source, owner_id, created_at_epoch);
                """
            )
            try:
                self._connection.execute("ALTER TABLE tasks ADD COLUMN priority INTEGER NOT NULL DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            for column, definition in (
                ("role", "TEXT"),
                ("output_schema", "TEXT"),
                ("contract_ref", "TEXT"),
                ("next_tier", "TEXT"),
                ("next_attempt_kind", "TEXT NOT NULL DEFAULT 'initial'"),
                ("repair_context_ref", "TEXT"),
                ("stage_key", "TEXT"),
                ("cycle", "INTEGER NOT NULL DEFAULT 0"),
                ("terminal_reason", "TEXT"),
                ("terminal_detail", "TEXT"),
                ("result_ref", "TEXT"),
                ("failure_kind", "TEXT"),
                ("available_at", "TEXT"),
            ):
                try:
                    self._connection.execute(f"ALTER TABLE tasks ADD COLUMN {column} {definition}")
                except sqlite3.OperationalError:
                    pass
            for column, definition in (
                ("lease_until", "TEXT"),
                ("attempts", "INTEGER NOT NULL DEFAULT 0"),
                ("last_error", "TEXT"),
            ):
                try:
                    self._connection.execute(f"ALTER TABLE outbox ADD COLUMN {column} {definition}")
                except sqlite3.OperationalError:
                    pass

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def health(self) -> bool:
        with self._lock:
            return bool(self._connection.execute("SELECT 1").fetchone()[0] == 1)

    def create_product(
        self,
        *,
        product_id: str,
        owner_id: str,
        source: str,
        idea: str,
        idempotency_key: str,
        rate_limit: tuple[int, int] | None = None,
    ) -> tuple[dict[str, Any], bool]:
        now = utc_now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT * FROM products WHERE idempotency_key = ?", (idempotency_key,)
                ).fetchone()
                if existing:
                    self._connection.commit()
                    return dict(existing), False
                active_count = int(
                    self._connection.execute(
                        "SELECT COUNT(*) FROM products WHERE status NOT IN ('CANCELLED', 'COMPLETED', 'FAILED_SAFE')"
                    ).fetchone()[0]
                )
                if active_count >= self.max_active_products:
                    raise ProductCapacityError("active product capacity is exhausted")
                if rate_limit is not None:
                    limit, window_seconds = rate_limit
                    if limit < 1 or window_seconds < 1:
                        raise ValueError("intake rate limit must be positive")
                    now_epoch = int(time.time())
                    self._connection.execute(
                        "DELETE FROM intake_requests WHERE created_at_epoch < ?",
                        (now_epoch - window_seconds,),
                    )
                    recent = int(
                        self._connection.execute(
                            "SELECT COUNT(*) FROM intake_requests "
                            "WHERE source=? AND owner_id=? AND created_at_epoch >= ?",
                            (source, owner_id, now_epoch - window_seconds),
                        ).fetchone()[0]
                    )
                    if recent >= limit:
                        raise IntakeRateLimitError("intake rate limit exceeded")
                    self._connection.execute(
                        "INSERT INTO intake_requests "
                        "(source, owner_id, idempotency_key, created_at_epoch) VALUES (?, ?, ?, ?)",
                        (source, owner_id, idempotency_key, now_epoch),
                    )
                self._connection.execute(
                    """INSERT INTO products
                    (product_id, status, owner_id, source, idea, idempotency_key, created_at, updated_at)
                    VALUES (?, 'IDEA_RECEIVED', ?, ?, ?, ?, ?, ?)""",
                    (product_id, owner_id, source, idea, idempotency_key, now, now),
                )
                self._record_event(product_id, None, "product_created", {"source": source})
                row = self._connection.execute(
                    "SELECT * FROM products WHERE product_id = ?", (product_id,)
                ).fetchone()
                assert row is not None
                self._connection.commit()
                return dict(row), True
            except Exception:
                self._connection.rollback()
                raise

    def get_product(self, product_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM products WHERE product_id = ?", (product_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_products(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute("SELECT * FROM products ORDER BY created_at").fetchall()
            return [dict(row) for row in rows]

    def transition_product(self, product_id: str, status: str) -> dict[str, Any]:
        allowed = {
            "IDEA_RECEIVED": {"CONTRACT_DRAFTED", "CANCELLED"},
            "CONTRACT_DRAFTED": {"CONTRACT_VALIDATED", "PAUSED", "CANCELLED"},
            "CONTRACT_VALIDATED": {"RISK_CLASSIFIED", "PAUSED", "CANCELLED"},
            "RISK_CLASSIFIED": {"ARCHITECTED", "PAUSED", "CANCELLED"},
            "ARCHITECTED": {"BACKLOG_READY", "PAUSED", "CANCELLED"},
            "BACKLOG_READY": {"IMPLEMENTING", "REPAIRING", "PAUSED", "CANCELLED"},
            "IMPLEMENTING": {"INTEGRATING", "REPAIRING", "DELAYED_QUOTA", "PAUSED", "CANCELLED"},
            "INTEGRATING": {"STAGING_DEPLOYED", "REPAIRING", "PAUSED", "CANCELLED"},
            "STAGING_DEPLOYED": {"PRODUCT_ACCEPTANCE", "ROLLING_BACK", "PAUSED", "CANCELLED"},
            "PRODUCT_ACCEPTANCE": {"RELEASE_READY", "REPAIRING", "PAUSED", "CANCELLED"},
            "RELEASE_READY": {"PRODUCTION_DEPLOYED", "STAGING_DEPLOYED", "PAUSED", "CANCELLED"},
            "PRODUCTION_DEPLOYED": {"OBSERVATION", "ROLLING_BACK", "PAUSED", "CANCELLED"},
            "OBSERVATION": {"COMPLETED", "REPAIRING", "ROLLING_BACK", "PAUSED", "CANCELLED"},
            "REPAIRING": {"IMPLEMENTING", "INTEGRATING", "FAILED_SAFE", "PAUSED", "CANCELLED"},
            "DELAYED_QUOTA": {"IMPLEMENTING", "FAILED_SAFE", "PAUSED", "CANCELLED"},
            "BLOCKED_OWNER": {"IMPLEMENTING", "FAILED_SAFE", "PAUSED", "CANCELLED"},
            "ROLLING_BACK": {"ROLLED_BACK", "FAILED_SAFE"},
            "ROLLED_BACK": {"IMPLEMENTING", "STAGING_DEPLOYED", "FAILED_SAFE"},
            "PAUSED": {"IDEA_RECEIVED", "CONTRACT_DRAFTED", "CONTRACT_VALIDATED", "RISK_CLASSIFIED", "ARCHITECTED", "BACKLOG_READY", "IMPLEMENTING", "INTEGRATING", "STAGING_DEPLOYED", "PRODUCT_ACCEPTANCE", "RELEASE_READY", "PRODUCTION_DEPLOYED", "OBSERVATION", "CANCELLED"},
            "CANCELLED": set(),
            "COMPLETED": set(),
            "FAILED_SAFE": set(),
        }
        for current in set(allowed) - {"CANCELLED", "COMPLETED", "FAILED_SAFE"}:
            allowed[current].update({"BLOCKED_OWNER", "FAILED_SAFE"})
        for current in ("STAGING_DEPLOYED", "RELEASE_READY", "PRODUCTION_DEPLOYED"):
            allowed[current].add("REPAIRING")
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT * FROM products WHERE product_id = ?", (product_id,)
            ).fetchone()
            if row is None:
                raise KeyError(product_id)
            current = str(row["status"])
            if status not in allowed.get(current, set()):
                raise ValueError(f"Invalid product transition {current} -> {status}")
            now = utc_now()
            self._connection.execute(
                "UPDATE products SET status = ?, updated_at = ? WHERE product_id = ?",
                (status, now, product_id),
            )
            self._record_event(product_id, None, "product_transition", {"from": current, "to": status})
            updated = self._connection.execute(
                "SELECT * FROM products WHERE product_id = ?", (product_id,)
            ).fetchone()
            assert updated is not None
            return dict(updated)

    def add_task(
        self,
        *,
        task_id: str,
        product_id: str,
        title: str,
        role: str | None = None,
        output_schema: str | None = None,
        contract_ref: str | None = None,
        stage_key: str | None = None,
        cycle: int = 0,
        available_at: str | None = None,
        dependencies: list[str] | None = None,
        conflict_keys: list[str] | None = None,
        priority: int = 0,
    ) -> None:
        if priority < 0:
            raise ValueError("priority cannot be negative")
        if cycle < 0:
            raise ValueError("cycle cannot be negative")
        now = utc_now()
        initial_status = "WAITING" if available_at is not None and available_at > now else "PENDING"
        with self._lock, self._connection:
            self._connection.execute(
                """INSERT INTO tasks
                (task_id, product_id, title, role, output_schema, contract_ref, stage_key, cycle,
                 priority, status, available_at, dependencies_json, conflict_keys_json,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    task_id,
                    product_id,
                    title,
                    role,
                    output_schema,
                    contract_ref,
                    stage_key,
                    cycle,
                    priority,
                    initial_status,
                    available_at,
                    json.dumps(dependencies or []),
                    json.dumps(conflict_keys or []),
                    now,
                    now,
                ),
            )
            self._record_event(product_id, task_id, "task_created", {"title": title})

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_tasks(self, product_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if product_id is None:
                rows = self._connection.execute(
                    "SELECT * FROM tasks ORDER BY created_at"
                ).fetchall()
            else:
                rows = self._connection.execute(
                    "SELECT * FROM tasks WHERE product_id = ? ORDER BY created_at",
                    (product_id,),
                ).fetchall()
            return [dict(row) for row in rows]

    def active_tasks(self, product_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT * FROM tasks
                   WHERE product_id=? AND status IN ('PENDING', 'CLAIMED', 'WAITING')
                   ORDER BY priority DESC, created_at""",
                (product_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def latest_task(self, product_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM tasks WHERE product_id=? ORDER BY rowid DESC LIMIT 1",
                (product_id,),
            ).fetchone()
            return dict(row) if row else None

    def orphaned_product_count(self) -> int:
        with self._lock:
            row = self._connection.execute(
                """SELECT COUNT(*) FROM products
                   WHERE status NOT IN
                       ('CANCELLED', 'COMPLETED', 'FAILED_SAFE', 'PAUSED', 'BLOCKED_OWNER')
                     AND NOT EXISTS (
                         SELECT 1 FROM tasks
                         WHERE tasks.product_id=products.product_id
                           AND tasks.status IN ('PENDING', 'CLAIMED', 'WAITING')
                     )"""
            ).fetchone()
            return int(row[0]) if row else 0

    def cancel_active_tasks(self, product_id: str) -> list[str]:
        """Stop queued or leased work after an owner cancels a product."""

        with self._lock, self._connection:
            rows = self._connection.execute(
                """SELECT task_id, status FROM tasks
                   WHERE product_id=? AND status IN ('PENDING', 'CLAIMED', 'WAITING')
                   ORDER BY created_at""",
                (product_id,),
            ).fetchall()
            task_ids = [str(row["task_id"]) for row in rows]
            now = utc_now()
            for row in rows:
                task_id = str(row["task_id"])
                previous_status = str(row["status"])
                self._connection.execute(
                    """UPDATE tasks
                       SET status='FAILED_SAFE', lease_owner=NULL, lease_until=NULL,
                           heartbeat_at=NULL, updated_at=?
                       WHERE task_id=? AND product_id=? AND status=?""",
                    (now, task_id, product_id, previous_status),
                )
                self._record_event(
                    product_id,
                    task_id,
                    "task_cancelled",
                    {"previous_status": previous_status, "reason": "product_cancelled"},
                )
            return task_ids

    def claim_task(self, *, worker_id: str, lease_seconds: int = 300) -> dict[str, Any] | None:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    "UPDATE tasks SET status='PENDING', lease_owner=NULL, lease_until=NULL "
                    "WHERE status='CLAIMED' AND lease_until < ?",
                    (utc_now(),),
                )
                self._connection.execute(
                    """UPDATE tasks SET status='PENDING', updated_at=?
                       WHERE status='WAITING' AND available_at IS NOT NULL AND available_at <= ?""",
                    (utc_now(), utc_now()),
                )
                rows = self._connection.execute(
                    """SELECT tasks.* FROM tasks
                       JOIN products ON products.product_id = tasks.product_id
                       WHERE tasks.status='PENDING'
                         AND products.status NOT IN ('CANCELLED', 'COMPLETED', 'FAILED_SAFE', 'PAUSED')
                       ORDER BY tasks.priority DESC, tasks.created_at"""
                ).fetchall()
                claimed_rows = self._connection.execute(
                    "SELECT lease_owner, conflict_keys_json FROM tasks WHERE status='CLAIMED'"
                ).fetchall()
                active_workers = {
                    str(active_row["lease_owner"])
                    for active_row in claimed_rows
                    if active_row["lease_owner"]
                }
                if worker_id in active_workers or len(active_workers) >= self.max_active_workers:
                    self._connection.commit()
                    return None
                claimed_conflicts = {
                    conflict_key
                    for active_row in claimed_rows
                    for conflict_key in json.loads(active_row["conflict_keys_json"])
                }
                chosen = None
                for row in rows:
                    dependencies = json.loads(row["dependencies_json"])
                    dependency_statuses = [
                        self._connection.execute(
                            "SELECT status FROM tasks WHERE task_id = ?", (dependency,)
                        ).fetchone()
                        for dependency in dependencies
                    ]
                    if not all(status is not None and status[0] == "DONE" for status in dependency_statuses):
                        continue
                    conflict_keys = set(json.loads(row["conflict_keys_json"]))
                    if conflict_keys & claimed_conflicts:
                        continue
                    chosen = row
                    break
                if chosen is None:
                    self._connection.commit()
                    return None
                now = utc_now()
                lease_until = utc_now_from_seconds(lease_seconds)
                self._connection.execute(
                    "UPDATE tasks SET status='CLAIMED', lease_owner=?, lease_until=?, heartbeat_at=?, "
                    "attempts=attempts+1, updated_at=? WHERE task_id=?",
                    (worker_id, lease_until, now, now, chosen["task_id"]),
                )
                self._record_event(chosen["product_id"], chosen["task_id"], "task_claimed", {"worker": worker_id})
                self._connection.commit()
                result = dict(chosen)
                result.update({"status": "CLAIMED", "lease_owner": worker_id, "lease_until": lease_until})
                return result
            except Exception:
                self._connection.rollback()
                raise

    def heartbeat(self, task_id: str, worker_id: str, lease_seconds: int = 300) -> None:
        with self._lock, self._connection:
            updated = self._connection.execute(
                "UPDATE tasks SET heartbeat_at=?, lease_until=?, updated_at=? "
                "WHERE task_id=? AND status='CLAIMED' AND lease_owner=?",
                (utc_now(), utc_now_from_seconds(lease_seconds), utc_now(), task_id, worker_id),
            ).rowcount
            if updated != 1:
                raise ValueError("Task lease is missing or owned by another worker")

    def complete_task(
        self,
        task_id: str,
        worker_id: str,
        status: str = "DONE",
        *,
        reason_code: str | None = None,
        detail: str | None = None,
        result_ref: str | None = None,
        failure_kind: str | None = None,
    ) -> None:
        if status not in {"DONE", "FAILED_SAFE", "BLOCKED_EXTERNAL"}:
            raise ValueError(f"Unsupported terminal task status: {status}")
        if status == "DONE" and (
            reason_code is not None or detail is not None or failure_kind is not None
        ):
            raise ValueError("completed task cannot have a terminal failure")
        safe_detail = detail.strip()[:4000] if detail else None
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT product_id FROM tasks WHERE task_id=? AND status='CLAIMED' AND lease_owner=?",
                (task_id, worker_id),
            ).fetchone()
            if row is None:
                raise ValueError("Task lease is missing or owned by another worker")
            self._connection.execute(
                """UPDATE tasks
                   SET status=?, lease_owner=NULL, lease_until=NULL, heartbeat_at=NULL,
                       terminal_reason=?, terminal_detail=?, result_ref=?,
                       failure_kind=?, updated_at=?
                   WHERE task_id=?""",
                (
                    status,
                    reason_code,
                    safe_detail,
                    result_ref,
                    failure_kind,
                    utc_now(),
                    task_id,
                ),
            )
            self._record_event(
                row["product_id"],
                task_id,
                "task_completed",
                {
                    "status": status,
                    "reason_code": reason_code,
                    "detail": safe_detail,
                    "result_ref": result_ref,
                    "failure_kind": failure_kind,
                },
            )

    def requeue_task(
        self,
        task_id: str,
        worker_id: str,
        *,
        next_tier: str,
        attempt_kind: str,
        repair_context_ref: str,
    ) -> None:
        """Return a leased task to the queue with explicit repair routing."""

        if attempt_kind not in {"repair", "transient_retry"}:
            raise ValueError("requeued task must be a repair or transient retry")
        if next_tier not in {"luna", "terra", "sol"}:
            raise ValueError("requeued task tier is invalid")
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT product_id FROM tasks WHERE task_id=? AND status='CLAIMED' AND lease_owner=?",
                (task_id, worker_id),
            ).fetchone()
            if row is None:
                raise ValueError("Task lease is missing or owned by another worker")
            self._connection.execute(
                """UPDATE tasks
                   SET status='PENDING', lease_owner=NULL, lease_until=NULL,
                       heartbeat_at=NULL, next_tier=?, next_attempt_kind=?,
                       repair_context_ref=?, terminal_reason=NULL, terminal_detail=NULL,
                       result_ref=NULL, failure_kind=NULL, updated_at=?
                 WHERE task_id=?""",
                (next_tier, attempt_kind, repair_context_ref, utc_now(), task_id),
            )
            self._record_event(
                row["product_id"],
                task_id,
                "task_requeued",
                {
                    "next_tier": next_tier,
                    "attempt_kind": attempt_kind,
                    "repair_context_ref": repair_context_ref,
                },
            )

    def prepare_pending_repair(
        self,
        task_id: str,
        *,
        next_tier: str,
        repair_context_ref: str,
    ) -> None:
        """Attach trusted repair evidence to a newly created pending task."""

        if next_tier not in {"luna", "terra", "sol"}:
            raise ValueError("pending repair tier is invalid")
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT product_id FROM tasks WHERE task_id=? AND status='WAITING'",
                (task_id,),
            ).fetchone()
            if row is None:
                raise ValueError("waiting repair task is missing")
            self._connection.execute(
                """UPDATE tasks
                   SET status='PENDING', available_at=NULL, next_tier=?,
                       next_attempt_kind='repair', repair_context_ref=?, updated_at=?
                   WHERE task_id=?""",
                (next_tier, repair_context_ref, utc_now(), task_id),
            )
            self._record_event(
                row["product_id"],
                task_id,
                "task_repair_prepared",
                {
                    "next_tier": next_tier,
                    "repair_context_ref": repair_context_ref,
                },
            )

    def fail_waiting_task(
        self,
        task_id: str,
        *,
        reason_code: str,
        detail: str,
    ) -> None:
        """Fail closed if trusted repair evidence cannot be attached."""

        safe_detail = detail.strip()[:4000] or reason_code
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT product_id FROM tasks WHERE task_id=? AND status='WAITING'",
                (task_id,),
            ).fetchone()
            if row is None:
                return
            self._connection.execute(
                """UPDATE tasks
                   SET status='FAILED_SAFE', available_at=NULL,
                       terminal_reason=?, terminal_detail=?,
                       failure_kind='semantic', updated_at=?
                   WHERE task_id=? AND status='WAITING'""",
                (reason_code, safe_detail, utc_now(), task_id),
            )
            self._record_event(
                row["product_id"],
                task_id,
                "task_preparation_failed",
                {"reason_code": reason_code, "detail": safe_detail},
            )

    def requeue_terminal_task(
        self,
        task_id: str,
        *,
        next_tier: str,
        repair_context_ref: str,
    ) -> None:
        """Reconcile an internally failed task back into the durable queue."""

        if next_tier not in {"luna", "terra", "sol"}:
            raise ValueError("terminal repair tier is invalid")
        with self._lock, self._connection:
            row = self._connection.execute(
                """SELECT product_id, status FROM tasks
                   WHERE task_id=? AND status IN ('FAILED_SAFE', 'BLOCKED_EXTERNAL')""",
                (task_id,),
            ).fetchone()
            if row is None:
                raise ValueError("terminal repair task is missing")
            previous_status = str(row["status"])
            self._connection.execute(
                """UPDATE tasks
                   SET status='PENDING', lease_owner=NULL, lease_until=NULL,
                       heartbeat_at=NULL, next_tier=?, next_attempt_kind='repair',
                       repair_context_ref=?, terminal_reason=NULL, terminal_detail=NULL,
                       result_ref=NULL, failure_kind=NULL, updated_at=?
                   WHERE task_id=?""",
                (next_tier, repair_context_ref, utc_now(), task_id),
            )
            self._record_event(
                row["product_id"],
                task_id,
                "task_requeued",
                {
                    "next_tier": next_tier,
                    "attempt_kind": "repair",
                    "repair_context_ref": repair_context_ref,
                    "previous_status": previous_status,
                    "reason": "automatic_reconcile",
                },
            )

    def requeue_resumable_tasks(self, product_id: str) -> list[str]:
        """Explicitly return blocked or failed-safe tasks to the owner queue.

        Resume is an operator action, so retrying a stopped task is intentional.
        The attempt manager still rejects an identical prompt digest, preventing
        an unchanged task from consuming another provider call.
        """

        with self._lock, self._connection:
            rows = self._connection.execute(
                """SELECT task_id, status FROM tasks
                   WHERE product_id=? AND status IN ('BLOCKED_EXTERNAL', 'FAILED_SAFE')
                   ORDER BY created_at""",
                (product_id,),
            ).fetchall()
            task_ids = [str(row["task_id"]) for row in rows]
            now = utc_now()
            for row in rows:
                task_id = str(row["task_id"])
                previous_status = str(row["status"])
                self._connection.execute(
                    """UPDATE tasks
                       SET status='PENDING', lease_owner=NULL, lease_until=NULL,
                           heartbeat_at=NULL, next_tier=NULL, next_attempt_kind='initial',
                           repair_context_ref=NULL, terminal_reason=NULL, terminal_detail=NULL,
                           result_ref=NULL, failure_kind=NULL, updated_at=?
                       WHERE task_id=? AND product_id=? AND status=?""",
                    (now, task_id, product_id, previous_status),
                )
                self._record_event(
                    product_id,
                    task_id,
                    "task_requeued",
                    {
                        "attempt_kind": "owner_resume",
                        "previous_status": previous_status,
                        "reason": "owner_resume",
                    },
                )
            return task_ids

    def events(self, product_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if product_id:
                rows = self._connection.execute(
                    "SELECT * FROM events WHERE product_id=? ORDER BY event_id", (product_id,)
                ).fetchall()
            else:
                rows = self._connection.execute("SELECT * FROM events ORDER BY event_id").fetchall()
            return [dict(row) for row in rows]

    def record_event(
        self,
        *,
        product_id: str | None,
        task_id: str | None,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        with self._lock, self._connection:
            self._record_event(product_id, task_id, event_type, payload)

    def record_attempt(
        self,
        *,
        attempt_id: str,
        task_id: str,
        tier: str,
        attempt_kind: str,
        prompt_digest: str,
        status: str,
        semantic_counted: bool,
        reason_code: str | None = None,
    ) -> bool:
        """Persist an attempt once; identical prompt digests are never duplicated."""
        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT attempt_id FROM attempts WHERE task_id=? AND prompt_digest=?",
                (task_id, prompt_digest),
            ).fetchone()
            if existing is not None:
                return False
            self._connection.execute(
                """INSERT INTO attempts
                (attempt_id, task_id, tier, attempt_kind, prompt_digest, reason_code, status,
                 semantic_counted, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    attempt_id,
                    task_id,
                    tier,
                    attempt_kind,
                    prompt_digest,
                    reason_code,
                    status,
                    int(semantic_counted),
                    utc_now(),
                ),
            )
            return True

    def attempts_for_task(self, task_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM attempts WHERE task_id=? ORDER BY created_at", (task_id,)
            ).fetchall()
            return [dict(row) for row in rows]

    def recover_interrupted_attempt(
        self,
        *,
        product_id: str,
        task_id: str,
        resume_status: str,
    ) -> bool:
        """Resume only a terminal task backed by an unfinished durable attempt."""

        if resume_status not in _RECOVERABLE_PRODUCT_STATUSES:
            raise ValueError("interrupted attempt resume status is invalid")
        with self._lock, self._connection:
            row = self._connection.execute(
                """SELECT products.status AS product_status,
                          tasks.status AS task_status,
                          tasks.terminal_reason,
                          tasks.terminal_detail
                   FROM tasks
                   JOIN products ON products.product_id=tasks.product_id
                   WHERE tasks.task_id=? AND tasks.product_id=?
                     AND tasks.rowid=(
                         SELECT MAX(latest.rowid)
                         FROM tasks AS latest
                         WHERE latest.product_id=tasks.product_id
                     )""",
                (task_id, product_id),
            ).fetchone()
            if row is None:
                return False
            detail = str(row["terminal_detail"] or "")
            if (
                str(row["product_status"]) != "FAILED_SAFE"
                or str(row["task_status"]) not in {"FAILED_SAFE", "BLOCKED_EXTERNAL"}
                or str(row["terminal_reason"] or "")
                not in {"internal_blocker", "duplicate_prompt_attempt"}
                or not detail.startswith("Prompt digest already attempted for task ")
            ):
                return False
            unfinished = self._connection.execute(
                "SELECT 1 FROM attempts WHERE task_id=? AND status='started' LIMIT 1",
                (task_id,),
            ).fetchone()
            if unfinished is None:
                return False
            now = utc_now()
            self._connection.execute(
                "UPDATE products SET status=?, updated_at=? WHERE product_id=?",
                (resume_status, now, product_id),
            )
            self._connection.execute(
                """UPDATE tasks
                   SET status='PENDING', available_at=NULL,
                       lease_owner=NULL, lease_until=NULL, heartbeat_at=NULL,
                       terminal_reason=NULL, terminal_detail=NULL,
                       result_ref=NULL, failure_kind=NULL, updated_at=?
                   WHERE task_id=?""",
                (now, task_id),
            )
            self._record_event(
                product_id,
                None,
                "product_transition",
                {
                    "from": "FAILED_SAFE",
                    "to": resume_status,
                    "reason": "interrupted_attempt_recovery",
                },
            )
            self._record_event(
                product_id,
                task_id,
                "interrupted_attempt_recovered",
                {"resume_status": resume_status},
            )
            return True

    def recover_deferred_builder_gate(
        self,
        *,
        product_id: str,
        task_id: str,
        resume_status: str,
    ) -> bool:
        """Accept a completed Builder whose only blocker belongs to a later stage."""

        if resume_status not in _RECOVERABLE_PRODUCT_STATUSES:
            raise ValueError("deferred Builder gate resume status is invalid")
        with self._lock, self._connection:
            row = self._connection.execute(
                """SELECT products.status AS product_status,
                          tasks.status AS task_status,
                          tasks.role,
                          tasks.stage_key,
                          tasks.terminal_reason
                   FROM tasks
                   JOIN products ON products.product_id=tasks.product_id
                   WHERE tasks.task_id=? AND tasks.product_id=?
                     AND tasks.rowid=(
                         SELECT MAX(latest.rowid)
                         FROM tasks AS latest
                         WHERE latest.product_id=tasks.product_id
                     )""",
                (task_id, product_id),
            ).fetchone()
            if (
                row is None
                or str(row["product_status"]) != "FAILED_SAFE"
                or str(row["task_status"]) != "BLOCKED_EXTERNAL"
                or str(row["role"]) != "builder"
                or str(row["stage_key"]) != "builder-core"
                or str(row["terminal_reason"]) != "model_requested_repair"
            ):
                return False
            already_recovered = self._connection.execute(
                """SELECT 1 FROM events
                   WHERE product_id=? AND task_id=?
                     AND event_type='builder_downstream_gate_deferred'
                   LIMIT 1""",
                (product_id, task_id),
            ).fetchone()
            if already_recovered is not None:
                return False
            now = utc_now()
            self._connection.execute(
                "UPDATE products SET status=?, updated_at=? WHERE product_id=?",
                (resume_status, now, product_id),
            )
            self._connection.execute(
                """UPDATE tasks
                   SET status='DONE', lease_owner=NULL, lease_until=NULL,
                       heartbeat_at=NULL, terminal_reason=NULL,
                       terminal_detail=NULL, failure_kind=NULL, updated_at=?
                   WHERE task_id=?""",
                (now, task_id),
            )
            self._record_event(
                product_id,
                None,
                "product_transition",
                {
                    "from": "FAILED_SAFE",
                    "to": resume_status,
                    "reason": "builder_downstream_gate_deferred",
                },
            )
            self._record_event(
                product_id,
                task_id,
                "builder_downstream_gate_deferred",
                {
                    "resume_status": resume_status,
                    "deferred_gate": "pm-acceptance",
                    "next_stage": "test-engineer",
                },
            )
            return True

    def recover_undiagnosed_secret_exposure(
        self,
        *,
        product_id: str,
        task_id: str,
        resume_status: str,
        repair_context_ref: str,
    ) -> bool:
        """Retry one legacy opaque rejection under the sanitizing protocol."""

        if resume_status not in _RECOVERABLE_PRODUCT_STATUSES:
            raise ValueError("secret diagnostic resume status is invalid")
        if not repair_context_ref:
            raise ValueError("secret diagnostic repair context is required")
        with self._lock, self._connection:
            row = self._connection.execute(
                """SELECT products.status AS product_status,
                          tasks.status AS task_status,
                          tasks.terminal_reason,
                          tasks.terminal_detail
                   FROM tasks
                   JOIN products ON products.product_id=tasks.product_id
                   WHERE tasks.task_id=? AND tasks.product_id=?
                     AND tasks.rowid=(
                         SELECT MAX(latest.rowid)
                         FROM tasks AS latest
                         WHERE latest.product_id=tasks.product_id
                     )""",
                (task_id, product_id),
            ).fetchone()
            already_recovered = self._connection.execute(
                """SELECT 1 FROM events
                   WHERE product_id=? AND task_id=?
                     AND event_type='secret_sanitizer_retry_scheduled'
                   LIMIT 1""",
                (product_id, task_id),
            ).fetchone()
            active = self._connection.execute(
                """SELECT 1 FROM tasks
                   WHERE product_id=? AND status IN ('PENDING', 'CLAIMED', 'WAITING')
                   LIMIT 1""",
                (product_id,),
            ).fetchone()
            if (
                row is None
                or str(row["product_status"]) != "FAILED_SAFE"
                or str(row["task_status"]) not in {"FAILED_SAFE", "BLOCKED_EXTERNAL"}
                or str(row["terminal_reason"] or "") != "secret_exposure"
                or str(row["terminal_detail"] or "").strip()
                or already_recovered is not None
                or active is not None
            ):
                return False
            now = utc_now()
            self._connection.execute(
                "UPDATE products SET status=?, updated_at=? WHERE product_id=?",
                (resume_status, now, product_id),
            )
            self._connection.execute(
                """UPDATE tasks
                   SET status='PENDING', available_at=NULL,
                       lease_owner=NULL, lease_until=NULL, heartbeat_at=NULL,
                       next_tier='sol', next_attempt_kind='repair',
                       repair_context_ref=?, terminal_reason=NULL,
                       terminal_detail=NULL, result_ref=NULL,
                       failure_kind=NULL, updated_at=?
                   WHERE task_id=?""",
                (repair_context_ref, now, task_id),
            )
            self._record_event(
                product_id,
                None,
                "product_transition",
                {
                    "from": "FAILED_SAFE",
                    "to": resume_status,
                    "reason": "secret_sanitizer_upgrade",
                },
            )
            self._record_event(
                product_id,
                task_id,
                "secret_sanitizer_retry_scheduled",
                {
                    "protocol": "provider-output-sanitizer-v2",
                    "next_tier": "sol",
                    "attempt_kind": "repair",
                    "repair_context_ref": repair_context_ref,
                },
            )
            return True

    def adopt_controller_valid_builder(
        self,
        *,
        product_id: str,
        task_id: str,
    ) -> bool:
        """Adopt an earlier Builder result proven complete by controller gates."""

        with self._lock, self._connection:
            product = self._connection.execute(
                "SELECT status FROM products WHERE product_id=?",
                (product_id,),
            ).fetchone()
            candidate = self._connection.execute(
                """SELECT task_id, status, role, stage_key, cycle,
                          terminal_reason, result_ref
                   FROM tasks
                   WHERE task_id=? AND product_id=?""",
                (task_id, product_id),
            ).fetchone()
            latest = self._connection.execute(
                """SELECT task_id, status, role, stage_key, cycle
                   FROM tasks
                   WHERE product_id=?
                   ORDER BY rowid DESC
                   LIMIT 1""",
                (product_id,),
            ).fetchone()
            active = self._connection.execute(
                """SELECT 1 FROM tasks
                   WHERE product_id=? AND status IN ('PENDING', 'CLAIMED', 'WAITING')
                   LIMIT 1""",
                (product_id,),
            ).fetchone()
            attempt = self._connection.execute(
                """SELECT status FROM attempts
                   WHERE task_id=?
                   ORDER BY rowid DESC
                   LIMIT 1""",
                (task_id,),
            ).fetchone()
            if (
                product is None
                or str(product["status"]) != "FAILED_SAFE"
                or candidate is None
                or str(candidate["status"]) not in {"FAILED_SAFE", "BLOCKED_EXTERNAL"}
                or str(candidate["role"]) != "builder"
                or str(candidate["stage_key"]) != "builder-core"
                or str(candidate["terminal_reason"] or "") != "model_requested_repair"
                or not str(candidate["result_ref"] or "")
                or attempt is None
                or str(attempt["status"]) != "repair_required"
                or latest is None
                or str(latest["task_id"]) == task_id
                or str(latest["status"]) not in {"FAILED_SAFE", "BLOCKED_EXTERNAL"}
                or str(latest["role"]) != "builder"
                or str(latest["stage_key"]) != "builder-core"
                or int(latest["cycle"] or 0) < int(candidate["cycle"] or 0)
                or active is not None
            ):
                return False
            already_adopted = self._connection.execute(
                """SELECT 1 FROM events
                   WHERE product_id=? AND task_id=?
                     AND event_type='builder_controller_gates_adopted'
                   LIMIT 1""",
                (product_id, task_id),
            ).fetchone()
            if already_adopted is not None:
                return False
            now = utc_now()
            self._connection.execute(
                "UPDATE products SET status='IMPLEMENTING', updated_at=? WHERE product_id=?",
                (now, product_id),
            )
            self._connection.execute(
                """UPDATE tasks
                   SET status='DONE', lease_owner=NULL, lease_until=NULL,
                       heartbeat_at=NULL, terminal_reason=NULL,
                       terminal_detail=NULL, failure_kind=NULL, updated_at=?
                   WHERE task_id=?""",
                (now, task_id),
            )
            self._record_event(
                product_id,
                None,
                "product_transition",
                {
                    "from": "FAILED_SAFE",
                    "to": "IMPLEMENTING",
                    "reason": "builder_controller_gates_adopted",
                },
            )
            self._record_event(
                product_id,
                task_id,
                "builder_controller_gates_adopted",
                {
                    "resume_status": "IMPLEMENTING",
                    "next_stage": "test-engineer",
                    "candidate_cycle": int(candidate["cycle"] or 0),
                    "superseded_task_id": str(latest["task_id"]),
                },
            )
            return True

    def recover_deferred_dependency_consumer(
        self,
        *,
        product_id: str,
        task_id: str,
        dependency_task_id: str,
        resume_status: str,
    ) -> bool:
        """Retry a pre-provider consumer after a deferred Builder was accepted."""

        if resume_status not in _RECOVERABLE_PRODUCT_STATUSES:
            raise ValueError("deferred dependency resume status is invalid")
        with self._lock, self._connection:
            row = self._connection.execute(
                """SELECT products.status AS product_status,
                          tasks.status AS task_status,
                          tasks.role,
                          tasks.stage_key,
                          tasks.terminal_reason,
                          tasks.terminal_detail,
                          tasks.dependencies_json
                   FROM tasks
                   JOIN products ON products.product_id=tasks.product_id
                   WHERE tasks.task_id=? AND tasks.product_id=?
                     AND tasks.rowid=(
                         SELECT MAX(latest.rowid)
                         FROM tasks AS latest
                         WHERE latest.product_id=tasks.product_id
                     )""",
                (task_id, product_id),
            ).fetchone()
            if row is None:
                return False
            try:
                dependencies = json.loads(str(row["dependencies_json"]))
            except (TypeError, json.JSONDecodeError):
                return False
            expected_details = {
                f"accepted task result is missing for {dependency_task_id}",
                f"deferred Builder evidence is invalid for {dependency_task_id}",
            }
            if (
                str(row["product_status"]) != "FAILED_SAFE"
                or str(row["task_status"]) != "BLOCKED_EXTERNAL"
                or str(row["role"]) != "test-engineer"
                or str(row["stage_key"]) != "test-engineer"
                or str(row["terminal_reason"] or "") != "internal_blocker"
                or str(row["terminal_detail"] or "") not in expected_details
                or dependencies != [dependency_task_id]
            ):
                return False
            dependency = self._connection.execute(
                """SELECT status, role, stage_key FROM tasks
                   WHERE task_id=? AND product_id=?""",
                (dependency_task_id, product_id),
            ).fetchone()
            deferred = self._connection.execute(
                """SELECT 1 FROM events
                   WHERE product_id=? AND task_id=?
                     AND event_type='builder_downstream_gate_deferred'
                   LIMIT 1""",
                (product_id, dependency_task_id),
            ).fetchone()
            provider_attempt = self._connection.execute(
                "SELECT 1 FROM attempts WHERE task_id=? LIMIT 1",
                (task_id,),
            ).fetchone()
            if (
                dependency is None
                or str(dependency["status"]) != "DONE"
                or str(dependency["role"]) != "builder"
                or str(dependency["stage_key"]) != "builder-core"
                or deferred is None
                or provider_attempt is not None
            ):
                return False
            recovery_rows = self._connection.execute(
                """SELECT payload_json FROM events
                   WHERE product_id=? AND task_id=?
                     AND event_type='deferred_dependency_consumer_recovered'
                   ORDER BY event_id""",
                (product_id, task_id),
            ).fetchall()
            current_detail = str(row["terminal_detail"] or "")
            for recovery_row in recovery_rows:
                try:
                    recovery_payload = json.loads(
                        str(recovery_row["payload_json"] or "{}")
                    )
                except json.JSONDecodeError:
                    continue
                recorded_detail = recovery_payload.get("terminal_detail")
                if recorded_detail == current_detail or (
                    recorded_detail is None
                    and current_detail.startswith(
                        "accepted task result is missing for "
                    )
                ):
                    return False
            now = utc_now()
            self._connection.execute(
                "UPDATE products SET status=?, updated_at=? WHERE product_id=?",
                (resume_status, now, product_id),
            )
            self._connection.execute(
                """UPDATE tasks
                   SET status='PENDING', available_at=NULL,
                       lease_owner=NULL, lease_until=NULL, heartbeat_at=NULL,
                       next_tier=NULL, next_attempt_kind='initial',
                       repair_context_ref=NULL, terminal_reason=NULL,
                       terminal_detail=NULL, result_ref=NULL,
                       failure_kind=NULL, updated_at=?
                   WHERE task_id=?""",
                (now, task_id),
            )
            self._record_event(
                product_id,
                None,
                "product_transition",
                {
                    "from": "FAILED_SAFE",
                    "to": resume_status,
                    "reason": "deferred_dependency_consumer_recovery",
                },
            )
            self._record_event(
                product_id,
                task_id,
                "deferred_dependency_consumer_recovered",
                {
                    "dependency_task_id": dependency_task_id,
                    "resume_status": resume_status,
                    "attempt_kind": "initial",
                    "terminal_detail": current_detail,
                },
            )
            return True

    def recover_exhausted_builder_cycle(
        self,
        *,
        product_id: str,
        task_id: str,
        resume_status: str,
        max_repair_cycles: int,
    ) -> bool:
        """Reopen one exhausted Builder task so a new bounded cycle can be created."""

        if resume_status not in _RECOVERABLE_PRODUCT_STATUSES:
            raise ValueError("Builder cycle resume status is invalid")
        if max_repair_cycles < 1 or max_repair_cycles > 3:
            raise ValueError("repair budget is invalid")
        with self._lock, self._connection:
            row = self._connection.execute(
                """SELECT products.status AS product_status,
                          tasks.status AS task_status,
                          tasks.role,
                          tasks.stage_key,
                          tasks.cycle
                   FROM tasks
                   JOIN products ON products.product_id=tasks.product_id
                   WHERE tasks.task_id=? AND tasks.product_id=?
                     AND tasks.rowid=(
                         SELECT MAX(latest.rowid)
                         FROM tasks AS latest
                         WHERE latest.product_id=tasks.product_id
                     )""",
                (task_id, product_id),
            ).fetchone()
            if (
                row is None
                or str(row["product_status"]) != "FAILED_SAFE"
                or str(row["task_status"]) not in {"FAILED_SAFE", "BLOCKED_EXTERNAL"}
                or str(row["role"]) != "builder"
                or str(row["stage_key"]) != "builder-core"
                or int(row["cycle"] or 0) >= max_repair_cycles
            ):
                return False
            exhausted = self._connection.execute(
                """SELECT 1 FROM events
                   WHERE product_id=? AND task_id=?
                     AND event_type='repair_budget_exhausted'
                   LIMIT 1""",
                (product_id, task_id),
            ).fetchone()
            already_reopened = self._connection.execute(
                """SELECT 1 FROM events
                   WHERE product_id=? AND task_id=?
                     AND event_type='builder_cycle_reopened'
                   LIMIT 1""",
                (product_id, task_id),
            ).fetchone()
            if exhausted is None or already_reopened is not None:
                return False
            now = utc_now()
            completed_cycle = int(row["cycle"] or 0)
            self._connection.execute(
                "UPDATE products SET status=?, updated_at=? WHERE product_id=?",
                (resume_status, now, product_id),
            )
            self._record_event(
                product_id,
                None,
                "product_transition",
                {
                    "from": "FAILED_SAFE",
                    "to": resume_status,
                    "reason": "builder_cycle_recovery",
                },
            )
            self._record_event(
                product_id,
                task_id,
                "builder_cycle_reopened",
                {
                    "completed_cycle": completed_cycle,
                    "next_cycle": completed_cycle + 1,
                    "max_repair_cycles": max_repair_cycles,
                    "resume_status": resume_status,
                },
            )
            return True

    def recover_exhausted_product_budget(
        self,
        *,
        product_id: str,
        task_id: str,
        resume_status: str,
        max_repair_cycles: int,
    ) -> bool:
        """Reopen a product only when policy now grants a new bounded cycle."""

        if resume_status not in _RECOVERABLE_PRODUCT_STATUSES:
            raise ValueError("repair budget resume status is invalid")
        if max_repair_cycles < 1 or max_repair_cycles > 3:
            raise ValueError("repair budget is invalid")
        with self._lock, self._connection:
            row = self._connection.execute(
                """SELECT products.status AS product_status,
                          tasks.status AS task_status,
                          tasks.cycle
                   FROM tasks
                   JOIN products ON products.product_id=tasks.product_id
                   WHERE tasks.task_id=? AND tasks.product_id=?
                     AND tasks.rowid=(
                         SELECT MAX(latest.rowid)
                         FROM tasks AS latest
                         WHERE latest.product_id=tasks.product_id
                     )""",
                (task_id, product_id),
            ).fetchone()
            if (
                row is None
                or str(row["product_status"]) != "FAILED_SAFE"
                or str(row["task_status"]) not in {"FAILED_SAFE", "BLOCKED_EXTERNAL"}
                or int(row["cycle"] or 0) >= max_repair_cycles
            ):
                return False
            exhausted = self._connection.execute(
                """SELECT 1 FROM events
                   WHERE product_id=? AND task_id=?
                     AND event_type='repair_budget_exhausted'
                   LIMIT 1""",
                (product_id, task_id),
            ).fetchone()
            if exhausted is None:
                return False
            reopened_rows = self._connection.execute(
                """SELECT payload_json FROM events
                   WHERE product_id=? AND task_id=?
                     AND event_type='repair_budget_reopened'""",
                (product_id, task_id),
            ).fetchall()
            for reopened_row in reopened_rows:
                try:
                    reopened_payload = json.loads(
                        str(reopened_row["payload_json"] or "{}")
                    )
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                if (
                    isinstance(reopened_payload, dict)
                    and int(reopened_payload.get("max_repair_cycles") or 0)
                    >= max_repair_cycles
                ):
                    return False
            now = utc_now()
            self._connection.execute(
                "UPDATE products SET status=?, updated_at=? WHERE product_id=?",
                (resume_status, now, product_id),
            )
            self._record_event(
                product_id,
                None,
                "product_transition",
                {
                    "from": "FAILED_SAFE",
                    "to": resume_status,
                    "reason": "repair_budget_extended",
                },
            )
            self._record_event(
                product_id,
                task_id,
                "repair_budget_reopened",
                {
                    "completed_cycle": int(row["cycle"] or 0),
                    "max_repair_cycles": max_repair_cycles,
                    "resume_status": resume_status,
                },
            )
            return True

    def reopen_for_director_root_cause(
        self,
        *,
        product_id: str,
        task_id: str,
        blocker_signature: str,
        blocker_ids: list[str],
    ) -> bool:
        """Grant one bounded budget per unique diagnosed blocker."""

        if not blocker_signature or not blocker_ids:
            raise ValueError("director root-cause replan contract is invalid")
        with self._lock, self._connection:
            row = self._connection.execute(
                """SELECT products.status AS product_status,
                          tasks.status AS task_status
                   FROM tasks
                   JOIN products ON products.product_id=tasks.product_id
                   WHERE tasks.task_id=? AND tasks.product_id=?
                     AND tasks.rowid=(
                         SELECT MAX(latest.rowid)
                         FROM tasks AS latest
                         WHERE latest.product_id=tasks.product_id
                     )""",
                (task_id, product_id),
            ).fetchone()
            exhausted = self._connection.execute(
                """SELECT 1 FROM events
                   WHERE product_id=? AND task_id=?
                     AND event_type='repair_budget_exhausted'
                   LIMIT 1""",
                (product_id, task_id),
            ).fetchone()
            replan_rows = self._connection.execute(
                """SELECT payload_json FROM events
                   WHERE product_id=?
                     AND event_type='director_root_cause_replan'
                   ORDER BY event_id""",
                (product_id,),
            ).fetchall()
            signatures: set[str] = set()
            for replan_row in replan_rows:
                try:
                    payload = json.loads(str(replan_row["payload_json"] or "{}"))
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                if isinstance(payload, dict) and payload.get("blocker_signature"):
                    signatures.add(str(payload["blocker_signature"]))
            if (
                row is None
                or str(row["product_status"]) != "FAILED_SAFE"
                or str(row["task_status"]) not in {"FAILED_SAFE", "BLOCKED_EXTERNAL"}
                or exhausted is None
                or blocker_signature in signatures
            ):
                return False
            now = utc_now()
            self._connection.execute(
                "UPDATE products SET status='REPAIRING', updated_at=? WHERE product_id=?",
                (now, product_id),
            )
            self._record_event(
                product_id,
                None,
                "product_transition",
                {
                    "from": "FAILED_SAFE",
                    "to": "REPAIRING",
                    "reason": "director_root_cause_replan",
                },
            )
            self._record_event(
                product_id,
                task_id,
                "director_root_cause_replan",
                {
                    "blocker_signature": blocker_signature,
                    "blocker_ids": blocker_ids,
                    "replan_number": len(signatures) + 1,
                    "max_replans_per_hypothesis": 1,
                    "next_action": "new_bounded_builder_budget",
                },
            )
            return True

    def update_attempt(self, attempt_id: str, *, status: str, reason_code: str | None = None) -> None:
        with self._lock, self._connection:
            updated = self._connection.execute(
                "UPDATE attempts SET status=?, reason_code=? WHERE attempt_id=?",
                (status, reason_code, attempt_id),
            ).rowcount
            if updated != 1:
                raise KeyError(attempt_id)

    def attempt_counts(self, task_id: str, tier: str) -> tuple[int, int]:
        with self._lock:
            row = self._connection.execute(
                """SELECT
                    COALESCE(SUM(CASE WHEN semantic_counted=1 THEN 1 ELSE 0 END), 0) AS semantic,
                    COALESCE(SUM(CASE WHEN semantic_counted=0 AND attempt_kind='transient_retry' THEN 1 ELSE 0 END), 0) AS transient
                FROM attempts WHERE task_id=? AND tier=?""",
                (task_id, tier),
            ).fetchone()
            assert row is not None
            return int(row["semantic"]), int(row["transient"])

    def _record_event(self, product_id: str | None, task_id: str | None, event_type: str, payload: dict[str, Any]) -> None:
        self._connection.execute(
            "INSERT INTO events(product_id, task_id, event_type, payload_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (product_id, task_id, event_type, json.dumps(payload, ensure_ascii=False), utc_now()),
        )

    def backup_to(self, target: Path) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            destination = sqlite3.connect(target)
            try:
                self._connection.backup(destination)
            finally:
                destination.close()

    def recover_expired_leases(self) -> int:
        with self._lock, self._connection:
            rows = self._connection.execute(
                "SELECT task_id, product_id FROM tasks WHERE status='CLAIMED' AND lease_until < ?",
                (utc_now(),),
            ).fetchall()
            for row in rows:
                self._connection.execute(
                    "UPDATE tasks SET status='PENDING', lease_owner=NULL, lease_until=NULL, updated_at=? WHERE task_id=?",
                    (utc_now(), row["task_id"]),
                )
                self._record_event(row["product_id"], row["task_id"], "lease_recovered", {})
            return len(rows)

    def enqueue_outbox(self, *, outbox_id: str, idempotency_key: str, event_type: str, payload: dict[str, Any]) -> bool:
        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT outbox_id FROM outbox WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if existing is not None:
                return False
            self._connection.execute(
                """INSERT INTO outbox
                (outbox_id, idempotency_key, event_type, payload_json, status, created_at)
                VALUES (?, ?, ?, ?, 'PENDING', ?)""",
                (outbox_id, idempotency_key, event_type, json.dumps(payload, ensure_ascii=False), utc_now()),
            )
            return True

    def claim_outbox(self, worker_id: str, limit: int = 10, lease_seconds: int = 300) -> list[dict[str, Any]]:
        if limit < 1:
            return []
        if lease_seconds < 1:
            raise ValueError("lease_seconds must be positive")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                now = utc_now()
                self._connection.execute(
                    "UPDATE outbox SET status='PENDING', lease_owner=NULL, lease_until=NULL "
                    "WHERE status='CLAIMED' AND lease_until IS NOT NULL AND lease_until < ?",
                    (now,),
                )
                rows = self._connection.execute(
                    "SELECT * FROM outbox WHERE status='PENDING' ORDER BY created_at LIMIT ?", (limit,)
                ).fetchall()
                lease_until = utc_now_from_seconds(lease_seconds)
                result = []
                for row in rows:
                    self._connection.execute(
                        "UPDATE outbox SET status='CLAIMED', lease_owner=?, lease_until=? WHERE outbox_id=?",
                        (worker_id, lease_until, row["outbox_id"]),
                    )
                    item = dict(row)
                    item.update({"status": "CLAIMED", "lease_owner": worker_id, "lease_until": lease_until})
                    result.append(item)
                self._connection.commit()
                return result
            except Exception:
                self._connection.rollback()
                raise

    def mark_outbox_done(self, outbox_id: str, worker_id: str) -> None:
        with self._lock, self._connection:
            updated = self._connection.execute(
                "UPDATE outbox SET status='DONE', delivered_at=?, lease_owner=NULL, lease_until=NULL "
                "WHERE outbox_id=? AND status='CLAIMED' AND lease_owner=?",
                (utc_now(), outbox_id, worker_id),
            ).rowcount
            if updated != 1:
                raise ValueError("Outbox item is missing or owned by another worker")

    def mark_outbox_failed(self, outbox_id: str, worker_id: str, reason: str) -> None:
        safe_reason = reason.strip()[:240] or "delivery_failed"
        with self._lock, self._connection:
            updated = self._connection.execute(
                """UPDATE outbox
                   SET status='PENDING', lease_owner=NULL, lease_until=NULL,
                       attempts=attempts+1, last_error=?
                   WHERE outbox_id=? AND status='CLAIMED' AND lease_owner=?""",
                (safe_reason, outbox_id, worker_id),
            ).rowcount
            if updated != 1:
                raise ValueError("Outbox item is missing or owned by another worker")

    def list_outbox(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM outbox ORDER BY created_at, outbox_id"
            ).fetchall()
            return [dict(row) for row in rows]


def utc_now_from_seconds(seconds: int) -> str:
    import datetime

    return (datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=seconds)).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
