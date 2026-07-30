"""Explicit, ordered SQLite migrations for the durable autonomy model."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable

from .common import sha256_text, utc_now

Migration = Callable[[sqlite3.Connection], None]

_LEGACY_GITHUB_REPOSITORY = re.compile(
    r"^https://github\.com/"
    r"(?P<owner>[A-Za-z0-9_.-]+)/"
    r"(?P<repository>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {
        str(row[1])
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }


def _add_columns(
    connection: sqlite3.Connection,
    table: str,
    definitions: tuple[tuple[str, str], ...],
) -> None:
    existing = _columns(connection, table)
    for name, definition in definitions:
        if name not in existing:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def _migration_001_baseline(connection: sqlite3.Connection) -> None:
    """Record the pre-v2 schema as an explicit migration baseline."""


def _migration_002_autonomy_v2(connection: sqlite3.Connection) -> None:
    _add_columns(
        connection,
        "products",
        (
            ("goal_text", "TEXT"),
            ("repository_url", "TEXT"),
            ("repository_name", "TEXT"),
            ("delivery_mode", "TEXT"),
            ("repository_visibility", "TEXT"),
            ("root_goal_ref", "TEXT"),
            ("constraints_ref", "TEXT"),
            ("owner_defaults_ref", "TEXT"),
            ("active_plan_id", "TEXT"),
            ("active_plan_revision", "INTEGER NOT NULL DEFAULT 0"),
            ("completion_evidence_ref", "TEXT"),
            ("terminal_reason", "TEXT"),
            ("repository_bootstrap_state", "TEXT"),
            ("default_branch", "TEXT"),
            ("starting_sha", "TEXT"),
            ("bootstrap_sha", "TEXT"),
        ),
    )
    _add_columns(
        connection,
        "tasks",
        (
            ("root_task_id", "TEXT"),
            ("parent_task_id", "TEXT"),
            ("source_task_id", "TEXT"),
            ("plan_id", "TEXT"),
            ("plan_node_id", "TEXT"),
            ("task_revision", "INTEGER NOT NULL DEFAULT 1"),
            ("root_context_ref", "TEXT"),
            ("active_context_ref", "TEXT"),
            ("failure_id", "TEXT"),
            ("hypothesis_id", "TEXT"),
            ("capability_profile", "TEXT"),
            ("idempotency_key", "TEXT"),
            ("supersedes_task_id", "TEXT"),
            ("blocked_reason", "TEXT"),
            ("blocked_ref", "TEXT"),
            ("graph_status", "TEXT"),
            ("required_capabilities_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("mandatory", "INTEGER NOT NULL DEFAULT 1"),
            ("result_digest", "TEXT"),
            ("lease_token", "TEXT"),
            ("critical_path_rank", "INTEGER NOT NULL DEFAULT 0"),
            ("required_predecessor_digest", "TEXT"),
        ),
    )
    _add_columns(
        connection,
        "attempts",
        (
            ("completed_at", "TEXT"),
            ("failure_id", "TEXT"),
            ("result_digest", "TEXT"),
        ),
    )
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS plans (
            plan_id TEXT PRIMARY KEY,
            product_id TEXT NOT NULL REFERENCES products(product_id),
            revision INTEGER NOT NULL,
            parent_plan_id TEXT,
            source_failure_id TEXT,
            status TEXT NOT NULL,
            plan_artifact_ref TEXT NOT NULL,
            plan_digest TEXT NOT NULL,
            goals_json TEXT NOT NULL DEFAULT '[]',
            completion_criteria_json TEXT NOT NULL DEFAULT '[]',
            created_by_task_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            activated_at TEXT,
            completed_at TEXT,
            UNIQUE(product_id, revision)
        );
        CREATE TABLE IF NOT EXISTS task_edges (
            plan_id TEXT NOT NULL,
            from_task_id TEXT NOT NULL,
            to_task_id TEXT NOT NULL,
            edge_type TEXT NOT NULL,
            required INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            PRIMARY KEY(plan_id, from_task_id, to_task_id, edge_type)
        );
        CREATE TABLE IF NOT EXISTS failures (
            failure_id TEXT PRIMARY KEY,
            product_id TEXT NOT NULL,
            task_id TEXT NOT NULL,
            attempt_id TEXT,
            parent_failure_id TEXT,
            failure_class TEXT NOT NULL,
            reason_code TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            safe_message TEXT NOT NULL,
            exception_type TEXT,
            stack_fingerprint TEXT,
            evidence_ref TEXT NOT NULL,
            status TEXT NOT NULL,
            retryable INTEGER NOT NULL DEFAULT 0,
            owner_action_eligible INTEGER NOT NULL DEFAULT 0,
            expected_json TEXT NOT NULL DEFAULT '{}',
            actual_json TEXT NOT NULL DEFAULT '{}',
            failed_gate_ids_json TEXT NOT NULL DEFAULT '[]',
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS hypotheses (
            hypothesis_id TEXT PRIMARY KEY,
            product_id TEXT NOT NULL,
            failure_id TEXT NOT NULL,
            parent_hypothesis_id TEXT,
            signature TEXT NOT NULL,
            statement TEXT NOT NULL,
            required_evidence_json TEXT NOT NULL,
            status TEXT NOT NULL,
            semantic_budget INTEGER NOT NULL,
            attempts_used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            closed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS capability_grants (
            grant_id TEXT PRIMARY KEY,
            product_id TEXT,
            task_id TEXT,
            capability TEXT NOT NULL,
            scope_json TEXT NOT NULL,
            provider TEXT NOT NULL,
            status TEXT NOT NULL,
            expires_at TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS task_outcomes (
            outcome_id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL UNIQUE,
            result_digest TEXT NOT NULL,
            status TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            committed_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS product_evidence (
            evidence_id TEXT PRIMARY KEY,
            product_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            goal_id TEXT,
            artifact_ref TEXT NOT NULL,
            artifact_digest TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(product_id, evidence_type, goal_id, artifact_digest)
        );
        CREATE TABLE IF NOT EXISTS controller_incidents (
            incident_id TEXT PRIMARY KEY,
            product_id TEXT,
            task_id TEXT,
            reason_code TEXT NOT NULL,
            evidence_ref TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            resolved_at TEXT
        );
        CREATE TABLE IF NOT EXISTS repository_sagas (
            product_id TEXT PRIMARY KEY,
            idempotency_key TEXT NOT NULL UNIQUE,
            repository_url TEXT,
            repository_name TEXT,
            visibility TEXT NOT NULL,
            state TEXT NOT NULL,
            default_branch TEXT,
            bootstrap_sha TEXT,
            last_error TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_tasks_graph_status
            ON tasks(graph_status, priority, critical_path_rank, created_at);
        CREATE INDEX IF NOT EXISTS idx_tasks_plan_node
            ON tasks(plan_id, plan_node_id, task_revision);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_tasks_v2_idempotency
            ON tasks(idempotency_key) WHERE idempotency_key IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_edges_to ON task_edges(plan_id, to_task_id);
        CREATE INDEX IF NOT EXISTS idx_failures_open
            ON failures(product_id, status, task_id);
        CREATE INDEX IF NOT EXISTS idx_hypotheses_active
            ON hypotheses(product_id, status, signature);
        CREATE INDEX IF NOT EXISTS idx_capability_lookup
            ON capability_grants(product_id, task_id, capability, status);
        """
    )
    _migrate_legacy_rows(connection)


def _migration_003_atomic_observation_binding(
    connection: sqlite3.Connection,
) -> None:
    _add_columns(
        connection,
        "tasks",
        (("required_predecessor_digest", "TEXT"),),
    )


def _migration_004_legacy_repository_binding(
    connection: sqlite3.Connection,
) -> None:
    """Repair only exact URL-only legacy intake without changing canonical v2."""

    rows = connection.execute(
        """SELECT product_id, idea, goal_text, active_plan_id
             FROM products
            WHERE active_plan_revision=0
              AND active_plan_id LIKE 'PLAN-LEGACY-%'
              AND delivery_mode='new_repository'
              AND (repository_url IS NULL OR repository_url='')"""
    ).fetchall()
    for row in rows:
        product_id = str(row[0])
        idea = str(row[1] or "").strip()
        match = _LEGACY_GITHUB_REPOSITORY.fullmatch(idea)
        if match is None:
            continue
        owner = match.group("owner")
        repository = match.group("repository")
        canonical_url = f"https://github.com/{owner}/{repository}"
        recovered_goal = (
            "Autonomously inspect the existing repository and complete all "
            f"documented product goals for {owner}/{repository}."
        )
        connection.execute(
            """UPDATE products
                  SET goal_text=CASE
                          WHEN goal_text IS NULL OR trim(goal_text)=trim(idea)
                          THEN ?
                          ELSE goal_text
                      END,
                      delivery_mode='existing_repository',
                      repository_url=?,
                      repository_name=?
                WHERE product_id=?""",
            (recovered_goal, canonical_url, repository, product_id),
        )
        plan_id = str(row[3] or "")
        if plan_id:
            connection.execute(
                """UPDATE plans
                      SET goals_json=?
                    WHERE plan_id=? AND product_id=? AND revision=0""",
                (
                    json.dumps(
                        [
                            {
                                "goal_id": "legacy-goal",
                                "statement": recovered_goal,
                            }
                        ],
                        ensure_ascii=False,
                    ),
                    plan_id,
                    product_id,
                ),
            )


def _migration_005_persistent_workspace_claim_recovery(
    connection: sqlite3.Connection,
) -> None:
    """Collapse workspace-contention incident trees and retry each causal root."""

    collision_rows = connection.execute(
        """
        SELECT tasks.product_id, tasks.task_id, failures.failure_id,
               tasks.created_at, tasks.rowid
          FROM failures
          JOIN tasks ON tasks.task_id=failures.task_id
         WHERE failures.failure_class='controller'
           AND failures.reason_code='controller_exception_runtime_error'
           AND failures.exception_type='RuntimeError'
           AND failures.safe_message='workspace already leased by another worker'
           AND failures.status<>'RESOLVED'
         ORDER BY tasks.product_id, tasks.created_at, tasks.rowid,
                  failures.first_seen_at
        """
    ).fetchall()
    product_ids = sorted({str(row[0]) for row in collision_rows})
    now = utc_now()
    for product_id in product_ids:
        product_collisions = list(
            dict.fromkeys(
                str(row[1])
                for row in collision_rows
                if str(row[0]) == product_id
            )
        )
        collision_set = set(product_collisions)
        collision_failure_ids = {
            task_id: [
                str(row[2])
                for row in collision_rows
                if str(row[0]) == product_id and str(row[1]) == task_id
            ]
            for task_id in product_collisions
        }
        branches: dict[str, set[str]] = {}
        branch_failures: dict[str, set[str]] = {}
        descendant_collisions: set[str] = set()
        for task_id in product_collisions:
            seed_failure_ids = collision_failure_ids[task_id]
            seed_placeholders = ",".join("?" for _ in seed_failure_ids)
            causal_failure_rows = connection.execute(
                f"""
                WITH RECURSIVE causal_failures(failure_id) AS (
                    SELECT failure_id FROM failures
                     WHERE failure_id IN ({seed_placeholders})
                    UNION
                    SELECT child.failure_id
                      FROM failures AS child
                      JOIN causal_failures AS parent
                        ON child.parent_failure_id=parent.failure_id
                )
                SELECT failure_id FROM causal_failures
                """,
                seed_failure_ids,
            ).fetchall()
            causal_failure_ids = {
                str(row[0]) for row in causal_failure_rows
            }
            causal_placeholders = ",".join(
                "?" for _ in causal_failure_ids
            )
            branch_rows = connection.execute(
                f"""
                SELECT task_id FROM tasks
                 WHERE product_id=?
                   AND (
                       task_id=?
                       OR failure_id IN ({causal_placeholders})
                       OR task_id IN (
                           SELECT task_id FROM failures
                            WHERE failure_id IN ({causal_placeholders})
                       )
                   )
                """,
                (
                    product_id,
                    task_id,
                    *sorted(causal_failure_ids),
                    *sorted(causal_failure_ids),
                ),
            ).fetchall()
            branch = {str(row[0]) for row in branch_rows}
            branches[task_id] = branch
            branch_failures[task_id] = causal_failure_ids
            descendant_collisions.update((branch & collision_set) - {task_id})
        survivors = [
            task_id
            for task_id in product_collisions
            if task_id not in descendant_collisions
        ]
        affected = sorted(
            {
                affected_task_id
                for survivor in survivors
                for affected_task_id in branches[survivor]
            }
        )
        if not affected:
            continue
        failure_ids = sorted(
            {
                failure_id
                for survivor in survivors
                for failure_id in branch_failures[survivor]
            }
        )
        superseded_count = 0
        for survivor in survivors:
            superseded = sorted(branches[survivor] - set(survivors))
            if not superseded:
                continue
            superseded_placeholders = ",".join("?" for _ in superseded)
            cursor = connection.execute(
                f"""
                UPDATE tasks
                   SET graph_status='SUPERSEDED', status='DONE',
                       lease_owner=NULL, lease_until=NULL, lease_token=NULL,
                       heartbeat_at=NULL, available_at=NULL,
                       blocked_reason='workspace_collision_superseded',
                       blocked_ref=?, updated_at=?
                 WHERE task_id IN ({superseded_placeholders})
                   AND graph_status NOT IN ('ACCEPTED','CANCELLED','SUPERSEDED')
                """,
                (survivor, now, *superseded),
            )
            superseded_count += cursor.rowcount
        survivor_placeholders = ",".join("?" for _ in survivors)
        connection.execute(
            f"""
            UPDATE tasks
               SET graph_status='READY', status='PENDING',
                   lease_owner=NULL, lease_until=NULL, lease_token=NULL,
                   heartbeat_at=NULL, available_at=NULL, next_tier=NULL,
                   next_attempt_kind='initial', repair_context_ref=NULL,
                   blocked_reason=NULL, blocked_ref=NULL,
                   terminal_reason=NULL, terminal_detail=NULL,
                   failure_kind=NULL, result_ref=NULL, result_digest=NULL,
                   updated_at=?
             WHERE task_id IN ({survivor_placeholders})
               AND graph_status NOT IN ('ACCEPTED','CANCELLED')
            """,
            (now, *survivors),
        )
        incident_task_ids = set(affected)
        if failure_ids:
            failure_placeholders = ",".join("?" for _ in failure_ids)
            connection.execute(
                f"""
                UPDATE failures
                   SET status='RESOLVED', last_seen_at=?
                 WHERE failure_id IN ({failure_placeholders})
                """,
                (now, *failure_ids),
            )
        if incident_task_ids:
            incident_placeholders = ",".join("?" for _ in incident_task_ids)
            connection.execute(
                f"""
                UPDATE controller_incidents
                   SET status='RESOLVED', resolved_at=?
                 WHERE task_id IN ({incident_placeholders})
                   AND status='OPEN'
                """,
                (now, *sorted(incident_task_ids)),
            )
        connection.execute(
            """
            INSERT INTO events
                (product_id, task_id, event_type, payload_json, created_at)
            VALUES (?, ?, 'workspace_collision_recovered', ?, ?)
            """,
            (
                product_id,
                survivors[0],
                json.dumps(
                    {
                        "survivor_task_ids": survivors,
                        "recovered_tasks": len(survivors),
                        "superseded_tasks": superseded_count,
                        "resolved_failures": len(failure_ids),
                        "reason_code": "persistent_workspace_claim_collision",
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                now,
            ),
        )


def _migration_006_resolved_failure_lineage(
    connection: sqlite3.Connection,
) -> None:
    """Close historical failure ancestors proven obsolete by accepted work."""

    seeds = [
        str(row[0])
        for row in connection.execute(
            """
            SELECT DISTINCT failure_id
              FROM tasks
             WHERE failure_id IS NOT NULL
               AND graph_status IN ('ACCEPTED','SUPERSEDED')
            """
        ).fetchall()
    ]
    if not seeds:
        return
    placeholders = ",".join("?" for _ in seeds)
    failure_ids = [
        str(row[0])
        for row in connection.execute(
            f"""
            WITH RECURSIVE causal_failures(failure_id) AS (
                SELECT failure_id
                  FROM failures
                 WHERE failure_id IN ({placeholders})
                UNION
                SELECT current.parent_failure_id
                  FROM failures AS current
                  JOIN causal_failures AS child
                    ON current.failure_id=child.failure_id
                 WHERE current.parent_failure_id IS NOT NULL
            )
            SELECT failure_id FROM causal_failures
            """,
            seeds,
        ).fetchall()
    ]
    if not failure_ids:
        return
    now = utc_now()
    causal_placeholders = ",".join("?" for _ in failure_ids)
    connection.execute(
        f"""
        UPDATE failures
           SET status='RESOLVED', last_seen_at=?
         WHERE failure_id IN ({causal_placeholders})
        """,
        (now, *failure_ids),
    )
    connection.execute(
        f"""
        UPDATE hypotheses
           SET status='RESOLVED', closed_at=COALESCE(closed_at, ?)
         WHERE failure_id IN ({causal_placeholders})
           AND status='ACTIVE'
        """,
        (now, *failure_ids),
    )
    connection.execute(
        f"""
        UPDATE controller_incidents
           SET status='RESOLVED', resolved_at=?
         WHERE status='OPEN'
           AND task_id IN (
               SELECT task_id FROM failures
                WHERE failure_id IN ({causal_placeholders})
           )
        """,
        (now, *failure_ids),
    )


def _migration_007_causal_leaf_recovery(
    connection: sqlite3.Connection,
) -> None:
    """Supersede recovery branches shadowed by a live causal descendant."""

    active_statuses = (
        "DRAFT",
        "BLOCKED_DEPENDENCY",
        "BLOCKED_CAPABILITY",
        "READY",
        "CLAIMED",
        "WAITING_TIME",
        "WAITING_EXTERNAL",
    )
    placeholders = ",".join("?" for _ in active_statuses)
    rows = connection.execute(
        f"""
        WITH RECURSIVE ancestry(
            ancestor_failure_id,
            descendant_failure_id
        ) AS (
            SELECT parent_failure_id, failure_id
              FROM failures
             WHERE parent_failure_id IS NOT NULL
            UNION
            SELECT parent.parent_failure_id,
                   ancestry.descendant_failure_id
              FROM failures AS parent
              JOIN ancestry
                ON parent.failure_id=ancestry.ancestor_failure_id
             WHERE parent.parent_failure_id IS NOT NULL
        )
        SELECT DISTINCT ancestor.task_id,
               ancestor.product_id,
               descendant.task_id
          FROM tasks AS ancestor
          JOIN ancestry
            ON ancestry.ancestor_failure_id=ancestor.failure_id
          JOIN tasks AS descendant
            ON descendant.failure_id=ancestry.descendant_failure_id
           AND descendant.product_id=ancestor.product_id
         WHERE ancestor.graph_status IN ({placeholders})
           AND descendant.graph_status IN ({placeholders})
        ORDER BY ancestor.product_id, ancestor.created_at, ancestor.task_id
        """,
        (*active_statuses, *active_statuses),
    ).fetchall()
    if not rows:
        return
    now = utc_now()
    by_product: dict[str, list[tuple[str, str]]] = {}
    for row in rows:
        task_id = str(row[0])
        product_id = str(row[1])
        descendant_task_id = str(row[2])
        by_product.setdefault(product_id, []).append(
            (task_id, descendant_task_id)
        )
        connection.execute(
            """
            UPDATE tasks
               SET status='DONE', graph_status='SUPERSEDED',
                   lease_owner=NULL, lease_until=NULL, lease_token=NULL,
                   heartbeat_at=NULL, available_at=NULL,
                   blocked_reason='causal_leaf_superseded',
                   blocked_ref=?, updated_at=?
             WHERE task_id=?
               AND graph_status NOT IN
                   ('ACCEPTED','CANCELLED','SUPERSEDED')
            """,
            (descendant_task_id, now, task_id),
        )
    for product_id, pairs in by_product.items():
        superseded = sorted({task_id for task_id, _ in pairs})
        survivors = sorted({descendant for _, descendant in pairs})
        connection.execute(
            """
            INSERT INTO events
                (product_id, task_id, event_type, payload_json, created_at)
            VALUES (?, ?, 'causal_recovery_deduplicated', ?, ?)
            """,
            (
                product_id,
                superseded[0],
                json.dumps(
                    {
                        "superseded_task_ids": superseded,
                        "surviving_descendant_task_ids": survivors,
                        "reason_code": "causal_leaf_only",
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                now,
            ),
        )


def _migration_008_invalid_output_schema_replan(
    connection: sqlite3.Connection,
) -> None:
    """Reopen plan-schema controller faults as semantic replanning work."""

    rows = connection.execute(
        """
        SELECT failures.failure_id,
               failures.product_id,
               failures.task_id
          FROM failures
          JOIN tasks
            ON tasks.task_id=failures.task_id
           AND tasks.product_id=failures.product_id
         WHERE failures.reason_code=
                   'controller_exception_file_not_found_error'
           AND failures.failure_class='controller'
           AND tasks.output_schema IS NOT NULL
           AND tasks.output_schema LIKE '%.schema.json'
           AND REPLACE(failures.safe_message, '\', '/')
               LIKE '%/schemas/' || tasks.output_schema
           AND tasks.graph_status NOT IN
               ('ACCEPTED','CANCELLED','SUPERSEDED')
        ORDER BY failures.first_seen_at, failures.failure_id
        """
    ).fetchall()
    if not rows:
        return
    now = utc_now()
    failure_ids = sorted({str(row[0]) for row in rows})
    product_ids = sorted({str(row[1]) for row in rows})
    placeholders = ",".join("?" for _ in failure_ids)
    connection.execute(
        f"""
        UPDATE failures
           SET status='OPEN', retryable=0,
               owner_action_eligible=0, last_seen_at=?
         WHERE failure_id IN ({placeholders})
        """,
        (now, *failure_ids),
    )
    connection.execute(
        f"""
        UPDATE tasks
           SET status='DONE', graph_status='SUPERSEDED',
               lease_owner=NULL, lease_until=NULL, lease_token=NULL,
               heartbeat_at=NULL, available_at=NULL,
               blocked_reason='invalid_output_schema_replan',
               blocked_ref=failure_id, updated_at=?
         WHERE failure_id IN ({placeholders})
           AND role='incident-recovery'
           AND graph_status NOT IN
               ('ACCEPTED','CANCELLED','SUPERSEDED')
        """,
        (now, *failure_ids),
    )
    for product_id in product_ids:
        product_failures = sorted(
            str(row[0]) for row in rows if str(row[1]) == product_id
        )
        connection.execute(
            """
            INSERT INTO events
                (product_id, task_id, event_type, payload_json, created_at)
            VALUES (?, ?, 'invalid_output_schema_replan_required', ?, ?)
            """,
            (
                product_id,
                str(next(row[2] for row in rows if str(row[1]) == product_id)),
                json.dumps(
                    {
                        "failure_ids": product_failures,
                        "reason_code": "invalid_output_schema",
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                now,
            ),
        )


def _migration_009_invalid_output_schema_incidents(
    connection: sqlite3.Connection,
) -> None:
    """Close stale controller incidents for failures reclassified as plan defects."""

    rows = connection.execute(
        """
        SELECT DISTINCT failures.failure_id,
                        failures.product_id,
                        failures.task_id
          FROM failures
          JOIN tasks
            ON tasks.task_id=failures.task_id
           AND tasks.product_id=failures.product_id
         WHERE failures.reason_code=
                   'controller_exception_file_not_found_error'
           AND failures.failure_class='controller'
           AND tasks.output_schema IS NOT NULL
           AND tasks.output_schema LIKE '%.schema.json'
           AND REPLACE(failures.safe_message, '\', '/')
               LIKE '%/schemas/' || tasks.output_schema
        ORDER BY failures.failure_id
        """
    ).fetchall()
    if not rows:
        return
    now = utc_now()
    task_coordinates = sorted(
        {(str(row[1]), str(row[2])) for row in rows}
    )
    resolved_by_product: dict[str, int] = {}
    for product_id, task_id in task_coordinates:
        resolved_by_product[product_id] = (
            resolved_by_product.get(product_id, 0)
            + connection.execute(
                """
                UPDATE controller_incidents
                   SET status='RESOLVED', resolved_at=?
                 WHERE product_id=? AND task_id=?
                   AND reason_code='controller_exception_file_not_found_error'
                   AND status='OPEN'
                """,
                (now, product_id, task_id),
            ).rowcount
        )
    for product_id in sorted({str(row[1]) for row in rows}):
        failure_ids = sorted(
            str(row[0]) for row in rows if str(row[1]) == product_id
        )
        connection.execute(
            """
            INSERT INTO events
                (product_id, task_id, event_type, payload_json, created_at)
            VALUES (?, ?, 'invalid_output_schema_incident_resolved', ?, ?)
            """,
            (
                product_id,
                str(next(row[2] for row in rows if str(row[1]) == product_id)),
                json.dumps(
                    {
                        "failure_ids": failure_ids,
                        "resolved_incidents": resolved_by_product.get(
                            product_id,
                            0,
                        ),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                now,
            ),
        )


def _migration_010_durable_capability_reconciliation(
    connection: sqlite3.Connection,
) -> None:
    """Persist sanitized probe results and durable capability blockers."""

    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS capability_check_results (
            product_id TEXT NOT NULL REFERENCES products(product_id),
            capability TEXT NOT NULL,
            provider TEXT NOT NULL,
            status TEXT NOT NULL,
            reason_code TEXT,
            scope_json TEXT NOT NULL,
            checked_at TEXT NOT NULL,
            expires_at TEXT,
            check_fingerprint TEXT NOT NULL,
            PRIMARY KEY(product_id, capability)
        );
        CREATE TABLE IF NOT EXISTS capability_blocks (
            block_id TEXT PRIMARY KEY,
            product_id TEXT NOT NULL REFERENCES products(product_id),
            capability TEXT NOT NULL,
            reason_code TEXT NOT NULL,
            status TEXT NOT NULL,
            owner_action_ref TEXT,
            failure_ref TEXT NOT NULL,
            notification_outbox_id TEXT,
            created_at TEXT NOT NULL,
            resolved_at TEXT,
            UNIQUE(product_id, capability, reason_code)
        );
        CREATE INDEX IF NOT EXISTS idx_capability_checks_due
            ON capability_check_results(status, checked_at, product_id);
        CREATE INDEX IF NOT EXISTS idx_capability_blocks_open
            ON capability_blocks(product_id, status, capability);
        """
    )


def _migration_011_recurring_workspace_claim_recovery(
    connection: sqlite3.Connection,
) -> None:
    """Collapse collision trees created after the original one-time repair."""

    _migration_005_persistent_workspace_claim_recovery(connection)


def _migration_012_typed_semantic_lifecycle(
    connection: sqlite3.Connection,
) -> None:
    """Persist controller-owned lifecycle and evidence contracts."""

    _add_columns(
        connection,
        "tasks",
        (
            ("lifecycle_stage", "TEXT"),
            ("review_kind", "TEXT"),
            ("evidence_profile", "TEXT"),
            ("consumes_evidence_types_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("produces_evidence_types_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("completion_obligation_ids_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("goal_ids_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("semantic_node_key", "TEXT"),
            ("production_side_effects", "INTEGER NOT NULL DEFAULT 0"),
        ),
    )
    _add_columns(
        connection,
        "plans",
        (
            ("compiler_version", "TEXT"),
            ("lifecycle_version", "TEXT"),
            ("proposal_artifact_ref", "TEXT"),
            ("proposal_digest", "TEXT"),
        ),
    )
    connection.executescript(
        """
        CREATE INDEX IF NOT EXISTS idx_tasks_lifecycle_stage
            ON tasks(product_id, plan_id, lifecycle_stage, graph_status);
        CREATE INDEX IF NOT EXISTS idx_tasks_semantic_node
            ON tasks(product_id, semantic_node_key, graph_status);
        """
    )


def _migration_013_maintenance_and_recovery_control(
    connection: sqlite3.Connection,
) -> None:
    """Add durable maintenance and idempotent recovery coordination."""

    products_table = connection.execute(
        """SELECT 1 FROM sqlite_master
           WHERE type='table' AND name='products'"""
    ).fetchone()
    active_products = (
        int(
            connection.execute(
                """SELECT COUNT(*) FROM products
                   WHERE status NOT IN
                       ('CANCELLED', 'COMPLETED', 'FAILED_SAFE')"""
            ).fetchone()[0]
        )
        if products_table is not None
        else 0
    )
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS factory_runtime_state (
            singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
            maintenance_active INTEGER NOT NULL DEFAULT 0,
            maintenance_reason TEXT,
            maintenance_entered_at TEXT,
            maintenance_left_at TEXT,
            sqlite_busy_events INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS recovery_applications (
            recovery_plan_digest TEXT NOT NULL,
            product_id TEXT NOT NULL,
            recovery_task_id TEXT NOT NULL,
            status TEXT NOT NULL,
            applied_at TEXT NOT NULL,
            PRIMARY KEY(recovery_plan_digest, product_id)
        );
        """
    )
    connection.execute(
        """INSERT OR IGNORE INTO factory_runtime_state
           (singleton_id, maintenance_active, updated_at)
           VALUES (1, ?, ?)""",
        (int(active_products > 0), utc_now()),
    )


def _legacy_graph_status(status: str, dependency_statuses: list[str]) -> str:
    if status == "CLAIMED":
        return "CLAIMED"
    if status == "WAITING":
        return "WAITING_TIME"
    if status == "DONE":
        return "ACCEPTED"
    if status == "BLOCKED_EXTERNAL":
        return "WAITING_EXTERNAL"
    if status == "FAILED_SAFE":
        return "FAILED_SEMANTIC"
    if any(value in {"FAILED_SAFE", "BLOCKED_EXTERNAL"} for value in dependency_statuses):
        return "BLOCKED_DEPENDENCY"
    if dependency_statuses and any(value != "DONE" for value in dependency_statuses):
        return "BLOCKED_DEPENDENCY"
    return "READY"


def _migrate_legacy_rows(connection: sqlite3.Connection) -> None:
    now = utc_now()
    products = connection.execute(
        "SELECT product_id, idea FROM products ORDER BY created_at, rowid"
    ).fetchall()
    for product in products:
        product_id = str(product[0])
        idea = str(product[1])
        plan_id = f"PLAN-LEGACY-{sha256_text(product_id)[:16].upper()}"
        tasks = connection.execute(
            "SELECT task_id, dependencies_json, status, role FROM tasks "
            "WHERE product_id=? ORDER BY created_at, rowid",
            (product_id,),
        ).fetchall()
        root_task_id = str(tasks[0][0]) if tasks else f"T-ROOT-{sha256_text(product_id)[:12].upper()}"
        connection.execute(
            """UPDATE products
               SET goal_text=COALESCE(goal_text, idea),
                   delivery_mode=COALESCE(delivery_mode, 'new_repository'),
                   repository_visibility=COALESCE(repository_visibility, 'private'),
                   root_goal_ref=COALESCE(root_goal_ref, ?),
                   active_plan_id=COALESCE(active_plan_id, ?),
                   active_plan_revision=COALESCE(active_plan_revision, 0)
               WHERE product_id=?""",
            (f"evidence/intake-{product_id}.json", plan_id, product_id),
        )
        connection.execute(
            """INSERT OR IGNORE INTO plans
               (plan_id, product_id, revision, parent_plan_id, source_failure_id,
                status, plan_artifact_ref, plan_digest, goals_json,
                completion_criteria_json, created_by_task_id, created_at, activated_at)
               VALUES (?, ?, 0, NULL, NULL, 'ACTIVE', ?, ?, ?, '[]', ?, ?, ?)""",
            (
                plan_id,
                product_id,
                f"legacy://plan/{product_id}/0",
                sha256_text(f"legacy:{product_id}:0"),
                json.dumps([{"goal_id": "legacy-goal", "statement": idea}], ensure_ascii=False),
                root_task_id,
                now,
                now,
            ),
        )
        known_statuses = {
            str(row[0]): str(row[2])
            for row in tasks
        }
        previous_task_id: str | None = None
        for index, task in enumerate(tasks):
            task_id = str(task[0])
            try:
                dependencies = json.loads(str(task[1] or "[]"))
            except json.JSONDecodeError:
                dependencies = []
            source_task_id = (
                str(dependencies[0])
                if dependencies
                else previous_task_id
                if previous_task_id is not None
                else task_id
            )
            dependency_statuses = [
                known_statuses.get(str(dependency), "MISSING")
                for dependency in dependencies
            ]
            graph_status = _legacy_graph_status(str(task[2]), dependency_statuses)
            role = str(task[3] or "legacy")
            profile = (
                "planning_readonly"
                if role in {"product-director", "product-analyst", "solution-architect", "task-specifier"}
                else "reviewer_readonly"
                if role in {"independent-reviewer", "security-reviewer"}
                else "builder_workspace"
            )
            connection.execute(
                """UPDATE tasks
                   SET root_task_id=COALESCE(root_task_id, ?),
                       parent_task_id=COALESCE(parent_task_id, ?),
                       source_task_id=COALESCE(source_task_id, ?),
                       plan_id=COALESCE(plan_id, ?),
                       plan_node_id=COALESCE(plan_node_id, ?),
                       task_revision=COALESCE(task_revision, 1),
                       root_context_ref=COALESCE(root_context_ref, ?),
                       active_context_ref=COALESCE(active_context_ref, contract_ref),
                       capability_profile=COALESCE(capability_profile, ?),
                       idempotency_key=COALESCE(idempotency_key, ?),
                       graph_status=COALESCE(graph_status, ?)
                   WHERE task_id=?""",
                (
                    root_task_id,
                    previous_task_id,
                    source_task_id,
                    plan_id,
                    f"legacy-{index:04d}",
                    f"evidence/intake-{product_id}.json",
                    profile,
                    sha256_text(f"legacy-task:{task_id}"),
                    graph_status,
                    task_id,
                ),
            )
            for dependency in dependencies:
                connection.execute(
                    """INSERT OR IGNORE INTO task_edges
                       (plan_id, from_task_id, to_task_id, edge_type, required, created_at)
                       VALUES (?, ?, ?, 'depends_on', 1, ?)""",
                    (plan_id, str(dependency), task_id, now),
                )
            previous_task_id = task_id


MIGRATIONS: tuple[tuple[int, str, Migration], ...] = (
    (1, "legacy-schema-baseline", _migration_001_baseline),
    (2, "autonomy-v2-durable-graph", _migration_002_autonomy_v2),
    (3, "atomic-observation-release-binding", _migration_003_atomic_observation_binding),
    (4, "legacy-url-repository-binding", _migration_004_legacy_repository_binding),
    (
        5,
        "persistent-workspace-claim-recovery",
        _migration_005_persistent_workspace_claim_recovery,
    ),
    (
        6,
        "resolved-failure-lineage-recovery",
        _migration_006_resolved_failure_lineage,
    ),
    (
        7,
        "causal-leaf-recovery-deduplication",
        _migration_007_causal_leaf_recovery,
    ),
    (
        8,
        "invalid-output-schema-replan",
        _migration_008_invalid_output_schema_replan,
    ),
    (
        9,
        "invalid-output-schema-incident-resolution",
        _migration_009_invalid_output_schema_incidents,
    ),
    (
        10,
        "durable-capability-reconciliation",
        _migration_010_durable_capability_reconciliation,
    ),
    (
        11,
        "recurring-workspace-claim-recovery",
        _migration_011_recurring_workspace_claim_recovery,
    ),
    (
        12,
        "typed-semantic-lifecycle",
        _migration_012_typed_semantic_lifecycle,
    ),
    (
        13,
        "maintenance-and-recovery-control",
        _migration_013_maintenance_and_recovery_control,
    ),
)


def apply_migrations(connection: sqlite3.Connection) -> None:
    connection.execute(
        """CREATE TABLE IF NOT EXISTS schema_migrations (
               version INTEGER PRIMARY KEY,
               name TEXT NOT NULL,
               checksum TEXT NOT NULL,
               applied_at TEXT NOT NULL
           )"""
    )
    for version, name, migration in MIGRATIONS:
        checksum = sha256_text(f"{version}:{name}")
        connection.execute("BEGIN IMMEDIATE")
        try:
            # Re-read after acquiring the database writer lock. Multiple
            # services start together after a release; a pre-lock snapshot can
            # become stale while another process applies this same migration.
            applied = connection.execute(
                "SELECT checksum FROM schema_migrations WHERE version=?",
                (version,),
            ).fetchone()
            if applied is not None:
                if str(applied[0]) != checksum:
                    raise RuntimeError(
                        f"database migration checksum mismatch: {version}"
                    )
                connection.commit()
                continue
            migration(connection)
            connection.execute(
                "INSERT INTO schema_migrations(version, name, checksum, applied_at) "
                "VALUES (?, ?, ?, ?)",
                (version, name, checksum, utc_now()),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
