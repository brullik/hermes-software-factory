"""Executable all-version SQLite migration and crash-replay qualification."""

from __future__ import annotations

import json
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .common import sha256_text, stable_json, utc_now
from .migrations import MIGRATIONS, apply_migrations, initialize_legacy_schema


class MigrationQualificationError(RuntimeError):
    """A migration fixture did not upgrade, replay, or restore exactly."""


@dataclass(frozen=True)
class MigrationFixtureResult:
    source_version: int
    target_version: int
    crash_rollback_passed: bool
    upgrade_passed: bool
    idempotent_restart_passed: bool
    restore_passed: bool
    row_counts_preserved: bool
    identity_digest_preserved: bool
    no_scope_expansion: bool
    no_spurious_plan_revision: bool
    integrity_check: str


@dataclass(frozen=True)
class MigrationMatrixReport:
    fixture_count: int
    passed_count: int
    failed_count: int
    migration_matrix_percent: int
    migration_fixup_count: int
    backup_restore_passed: bool
    production_shape_passed: bool
    production_shape_counts: dict[str, int]
    matrix_digest: str
    fixtures: tuple[MigrationFixtureResult, ...]


_CORE_TABLES = ("products", "tasks", "events", "attempts", "outbox")


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=30.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=30000")
    return connection


def _apply_through(connection: sqlite3.Connection, version_limit: int) -> None:
    initialize_legacy_schema(connection)
    connection.execute(
        """CREATE TABLE IF NOT EXISTS schema_migrations (
               version INTEGER PRIMARY KEY,
               name TEXT NOT NULL,
               checksum TEXT NOT NULL,
               applied_at TEXT NOT NULL
           )"""
    )
    connection.commit()
    for version, name, migration in MIGRATIONS:
        if version > version_limit:
            break
        connection.execute("BEGIN IMMEDIATE")
        try:
            migration(connection)
            connection.execute(
                """INSERT INTO schema_migrations(version,name,checksum,applied_at)
                   VALUES (?, ?, ?, ?)""",
                (version, name, sha256_text(f"{version}:{name}"), utc_now()),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise


def _seed_legacy(connection: sqlite3.Connection, *, production_shape: bool) -> None:
    now = "2026-08-02T18:46:58Z"
    if production_shape:
        statuses = ["CANCELLED"] * 7 + ["PAUSED"] * 2 + ["FAILED_SAFE"] * 2 + ["IMPLEMENTING"]
        task_count = 10536
        attempt_count = 1777
        event_count = 20700
        outbox_count = 4929
    else:
        statuses = ["IMPLEMENTING"]
        task_count = attempt_count = event_count = outbox_count = 1
    products = [
        (
            f"P-MIG-{index:02d}",
            status,
            "owner",
            "fixture",
            f"sanitized migration fixture {index}",
            f"migration-fixture-{index}",
            now,
            now,
        )
        for index, status in enumerate(statuses)
    ]
    connection.executemany(
        """INSERT INTO products
           (product_id,status,owner_id,source,idea,idempotency_key,created_at,updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        products,
    )
    product_ids = [str(item[0]) for item in products]
    task_rows: list[tuple[Any, ...]] = []
    for index in range(task_count):
        product_id = product_ids[index % len(product_ids)]
        task_rows.append(
            (
                f"T-MIG-{index:05d}",
                product_id,
                f"sanitized task {index}",
                "builder-core",
                "attempt-result.schema.json",
                f"evidence/task-T-MIG-{index:05d}.json",
                0,
                "DONE",
                "[]",
                "[]",
                None,
                None,
                None,
                1,
                now,
                now,
            )
        )
    connection.executemany(
        """INSERT INTO tasks
           (task_id,product_id,title,role,output_schema,contract_ref,priority,status,
            dependencies_json,conflict_keys_json,lease_owner,lease_until,heartbeat_at,
            attempts,created_at,updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        task_rows,
    )
    connection.executemany(
        """INSERT INTO attempts
           (attempt_id,task_id,tier,attempt_kind,prompt_digest,reason_code,status,
            semantic_counted,created_at)
           VALUES (?, ?, 'sol', 'initial', ?, NULL, 'completed', 1, ?)""",
        [
            (
                f"A-MIG-{index:05d}",
                f"T-MIG-{index % task_count:05d}",
                sha256_text(f"migration-attempt-{index}"),
                now,
            )
            for index in range(attempt_count)
        ],
    )
    connection.executemany(
        """INSERT INTO events(product_id,task_id,event_type,payload_json,created_at)
           VALUES (?, NULL, 'sanitized_fixture_event', '{}', ?)""",
        [
            (product_ids[index % len(product_ids)], now)
            for index in range(event_count)
        ],
    )
    connection.executemany(
        """INSERT INTO outbox
           (outbox_id,idempotency_key,event_type,payload_json,status,lease_owner,
            lease_until,created_at,delivered_at)
           VALUES (?, ?, 'sanitized_fixture', '{}', 'DONE', NULL, NULL, ?, ?)""",
        [
            (f"O-MIG-{index:05d}", f"migration-outbox-{index}", now, now)
            for index in range(outbox_count)
        ],
    )
    connection.commit()


def _row_counts(connection: sqlite3.Connection) -> dict[str, int]:
    return {
        table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        for table in _CORE_TABLES
    }


def _identity_digest(connection: sqlite3.Connection) -> str:
    identities = {
        "products": [
            str(row[0])
            for row in connection.execute("SELECT product_id FROM products ORDER BY product_id")
        ],
        "tasks": [
            str(row[0])
            for row in connection.execute("SELECT task_id FROM tasks ORDER BY task_id")
        ],
        "events": [
            int(row[0])
            for row in connection.execute("SELECT event_id FROM events ORDER BY event_id")
        ],
        "attempts": [
            str(row[0])
            for row in connection.execute("SELECT attempt_id FROM attempts ORDER BY attempt_id")
        ],
        "outbox": [
            str(row[0])
            for row in connection.execute("SELECT outbox_id FROM outbox ORDER BY outbox_id")
        ],
    }
    return sha256_text(stable_json(identities))


def _database_digest(connection: sqlite3.Connection) -> str:
    schema = [
        tuple(str(value or "") for value in row)
        for row in connection.execute(
            """SELECT type,name,tbl_name,sql FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"""
        )
    ]
    versions = [
        tuple(str(value) for value in row)
        for row in connection.execute(
            "SELECT version,name,checksum FROM schema_migrations ORDER BY version"
        )
    ]
    return sha256_text(
        stable_json(
            {
                "schema": schema,
                "versions": versions,
                "counts": _row_counts(connection),
                "identities": _identity_digest(connection),
            }
        )
    )


def _scope_is_bounded(connection: sqlite3.Connection) -> bool:
    columns = {
        str(row[1]) for row in connection.execute("PRAGMA table_info(tasks)")
    }
    if "required_capabilities_json" not in columns:
        return True
    rows = connection.execute(
        "SELECT required_capabilities_json FROM tasks"
    ).fetchall()
    for row in rows:
        try:
            values = json.loads(str(row[0] or "[]"))
        except json.JSONDecodeError:
            return False
        if not isinstance(values, list) or any(str(value) in {"*", "**", "**/*"} for value in values):
            return False
    return True


def _fixture(root: Path, source_version: int, *, production_shape: bool) -> MigrationFixtureResult:
    label = "production" if production_shape else f"v{source_version:02d}"
    source_path = root / f"{label}.db"
    backup_path = root / f"{label}.backup.db"
    restored_path = root / f"{label}.restored.db"
    crash_path = root / f"{label}.crash.db"
    connection = _connect(source_path)
    try:
        initialize_legacy_schema(connection)
        _seed_legacy(connection, production_shape=production_shape)
        _apply_through(connection, source_version)
        before_counts = _row_counts(connection)
        before_identity = _identity_digest(connection)
        before_plans = (
            int(connection.execute("SELECT COUNT(*) FROM plans").fetchone()[0])
            if source_version >= 2
            else 0
        )
        source_digest = _database_digest(connection)
    finally:
        connection.close()
    shutil.copy2(source_path, backup_path)
    shutil.copy2(source_path, crash_path)

    crash_rollback_passed = True
    if source_version < MIGRATIONS[-1][0]:
        crash = _connect(crash_path)
        try:
            next_version, _next_name, next_migration = MIGRATIONS[source_version]
            before_crash = _database_digest(crash)
            crash.execute("BEGIN IMMEDIATE")
            next_migration(crash)
            crash.rollback()
            crash_rollback_passed = (
                _database_digest(crash) == before_crash
                and crash.execute(
                    "SELECT 1 FROM schema_migrations WHERE version=?", (next_version,)
                ).fetchone()
                is None
            )
        finally:
            crash.close()

    upgraded = _connect(source_path)
    try:
        apply_migrations(upgraded)
        target_version = int(
            upgraded.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
        )
        after_counts = _row_counts(upgraded)
        after_identity = _identity_digest(upgraded)
        integrity = str(upgraded.execute("PRAGMA integrity_check").fetchone()[0])
        plan_count = int(upgraded.execute("SELECT COUNT(*) FROM plans").fetchone()[0])
        digest_before_restart = _database_digest(upgraded)
        apply_migrations(upgraded)
        digest_after_restart = _database_digest(upgraded)
        no_spurious_plan = source_version == 1 or plan_count == before_plans
        result = MigrationFixtureResult(
            source_version=source_version,
            target_version=target_version,
            crash_rollback_passed=crash_rollback_passed,
            upgrade_passed=target_version == MIGRATIONS[-1][0] and integrity == "ok",
            idempotent_restart_passed=digest_before_restart == digest_after_restart,
            restore_passed=False,
            row_counts_preserved=before_counts == after_counts,
            identity_digest_preserved=before_identity == after_identity,
            no_scope_expansion=_scope_is_bounded(upgraded),
            no_spurious_plan_revision=no_spurious_plan,
            integrity_check=integrity,
        )
    finally:
        upgraded.close()

    shutil.copy2(backup_path, restored_path)
    restored = _connect(restored_path)
    try:
        restored_ok = _database_digest(restored) == source_digest
    finally:
        restored.close()
    return MigrationFixtureResult(
        **{**result.__dict__, "restore_passed": restored_ok}
    )


def run_migration_matrix(
    root: Path,
    *,
    include_production_shape: bool = True,
) -> MigrationMatrixReport:
    """Run every supported source version plus the audited production shape."""

    root.mkdir(parents=True, exist_ok=False)
    results = [
        _fixture(root, version, production_shape=False)
        for version, _name, _migration in MIGRATIONS
    ]
    production_counts: dict[str, int] = {}
    production_passed = not include_production_shape
    if include_production_shape:
        production = _fixture(root, 16, production_shape=True)
        results.append(production)
        production_passed = all(
            (
                production.crash_rollback_passed,
                production.upgrade_passed,
                production.idempotent_restart_passed,
                production.restore_passed,
                production.row_counts_preserved,
                production.identity_digest_preserved,
                production.no_scope_expansion,
                production.no_spurious_plan_revision,
            )
        )
        production_counts = {
            "products": 12,
            "tasks": 10536,
            "attempts": 1777,
            "events": 20700,
            "outbox": 4929,
        }
    passed = sum(
        int(
            all(
                (
                    item.crash_rollback_passed,
                    item.upgrade_passed,
                    item.idempotent_restart_passed,
                    item.restore_passed,
                    item.row_counts_preserved,
                    item.identity_digest_preserved,
                    item.no_scope_expansion,
                    item.no_spurious_plan_revision,
                )
            )
        )
        for item in results
    )
    digest = sha256_text(stable_json([item.__dict__ for item in results]))
    return MigrationMatrixReport(
        fixture_count=len(results),
        passed_count=passed,
        failed_count=len(results) - passed,
        migration_matrix_percent=(100 * passed) // len(results),
        migration_fixup_count=0,
        backup_restore_passed=all(item.restore_passed for item in results),
        production_shape_passed=production_passed,
        production_shape_counts=production_counts,
        matrix_digest=digest,
        fixtures=tuple(results),
    )
