#!/usr/bin/env python3
"""Build a sanitized, reproducible Hermes 2.0.19 SQLite migration fixture."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

SCHEMA_2_0_19 = """
CREATE TABLE products (
    product_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    source TEXT NOT NULL,
    idea TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE tasks (
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
    updated_at TEXT NOT NULL,
    next_tier TEXT,
    next_attempt_kind TEXT NOT NULL DEFAULT 'initial',
    repair_context_ref TEXT,
    stage_key TEXT,
    cycle INTEGER NOT NULL DEFAULT 0,
    terminal_reason TEXT,
    terminal_detail TEXT,
    result_ref TEXT,
    failure_kind TEXT,
    available_at TEXT
);
CREATE TABLE events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id TEXT,
    task_id TEXT,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE attempts (
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
CREATE TABLE outbox (
    outbox_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL,
    lease_owner TEXT,
    lease_until TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TEXT NOT NULL,
    delivered_at TEXT
);
CREATE TABLE intake_requests (
    request_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    created_at_epoch INTEGER NOT NULL
);
"""


def build_fixture(target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()
    connection = sqlite3.connect(target)
    try:
        connection.executescript(SCHEMA_2_0_19)
        now = "2026-01-01T00:00:00Z"
        connection.execute(
            """INSERT INTO products
               VALUES ('legacy-product', 'IMPLEMENTING', 'sanitized-owner',
                       'cli', 'Build a sanitized legacy service',
                       'legacy-idempotency', ?, ?)""",
            (now, now),
        )
        connection.execute(
            """INSERT INTO tasks
               (task_id, product_id, title, role, output_schema, contract_ref,
                priority, status, dependencies_json, conflict_keys_json,
                attempts, created_at, updated_at, stage_key, cycle, result_ref)
               VALUES ('legacy-predecessor', 'legacy-product',
                       'Accepted predecessor', 'builder',
                       'attempt-result.schema.json',
                       'evidence/task-legacy-predecessor.json',
                       10, 'DONE', '[]', '["src/legacy.py"]', 1, ?, ?,
                       'builder-core', 0,
                       'evidence/result-legacy-predecessor.json')""",
            (now, now),
        )
        connection.execute(
            """INSERT INTO tasks
               (task_id, product_id, title, role, output_schema, contract_ref,
                priority, status, dependencies_json, conflict_keys_json,
                attempts, created_at, updated_at, next_tier,
                next_attempt_kind, repair_context_ref, stage_key, cycle)
               VALUES ('legacy-active-repair', 'legacy-product',
                       'Repair active node', 'builder',
                       'attempt-result.schema.json',
                       'evidence/node-legacy-active-repair.json',
                       20, 'PENDING', '["legacy-predecessor"]',
                       '["src/legacy.py"]', 1, ?, ?, 'terra', 'repair',
                       'evidence/repair-legacy.json', 'builder-core', 1)""",
            (now, now),
        )
        connection.execute(
            """INSERT INTO attempts
               VALUES ('legacy-attempt', 'legacy-active-repair', 'luna',
                       'initial', ?, 'mandatory_gate_failed', 'failed',
                       1, ?)""",
            ("a" * 64, now),
        )
        connection.execute(
            """INSERT INTO events
               (product_id, task_id, event_type, payload_json, created_at)
               VALUES ('legacy-product', 'legacy-active-repair',
                       'task_requeued', '{"cycle":1}', ?)""",
            (now,),
        )
        connection.execute(
            """INSERT INTO outbox
               (outbox_id, idempotency_key, event_type, payload_json,
                status, attempts, created_at)
               VALUES ('legacy-outbox', 'legacy-outbox-key',
                       'telegram.owner_notification', '{"kind":"status"}',
                       'PENDING', 0, ?)""",
            (now,),
        )
        connection.commit()
    finally:
        connection.close()
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=Path)
    args = parser.parse_args()
    build_fixture(args.target.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
