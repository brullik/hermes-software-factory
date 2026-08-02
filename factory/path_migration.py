"""Transactional migration from legacy accepted-task chains to Path Governor state."""

from __future__ import annotations

import json
import re
import sqlite3
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from scripts.prompt_compiler import find_secret_candidates

from .common import sha256_file, sha256_text, stable_json, utc_now
from .config import FactoryConfig
from .path_governor import PathGovernor, stable_root_problem_signature
from .policy import policy_digest
from .registry import SchemaRegistry
from .repair_brief import (
    builder_result_is_controller_complete,
    builder_result_is_locally_complete,
)
from .state import StateStore

FaultInjector = Callable[[str], None]


def _safe_evidence_path(root: Path, reference: str) -> Path:
    name = Path(reference).name
    candidate = (root / name).resolve()
    if (
        not name
        or candidate.parent != root.resolve()
        or not candidate.is_file()
        or candidate.is_symlink()
    ):
        raise RuntimeError("accepted result evidence is missing or unsafe")
    return candidate


def _accepted_output(
    config: FactoryConfig,
    state: StateStore,
    schemas: SchemaRegistry,
    source_task: Mapping[str, Any],
) -> tuple[str, str, str]:
    task_id = str(source_task["task_id"])
    attempts = state._connection.execute(
        """SELECT * FROM attempts
             WHERE task_id=? AND status IN ('completed','repair_required')
             ORDER BY created_at, attempt_id""",
        (task_id,),
    ).fetchall()
    if not attempts:
        raise RuntimeError(f"accepted source attempt is missing for {task_id}")
    attempt = dict(attempts[-1])
    attempt_id = str(attempt["attempt_id"])
    attempt_path = _safe_evidence_path(
        config.evidence_dir, f"attempt-{attempt_id}.json"
    )
    attempt_payload = json.loads(attempt_path.read_text(encoding="utf-8"))
    if not isinstance(attempt_payload, dict):
        raise TypeError(f"accepted source attempt is invalid for {task_id}")
    schemas.validate("attempt-result.schema.json", attempt_payload)
    if (
        str(attempt_payload.get("task_id") or "") != task_id
        or str(attempt_payload.get("attempt_id") or "") != attempt_id
    ):
        raise RuntimeError(f"accepted source attempt identity conflicts for {task_id}")
    refs = attempt_payload.get("evidence_refs", [])
    if not isinstance(refs, list):
        raise TypeError(f"accepted source evidence references are invalid for {task_id}")
    schema_output_names = {
        Path(str(item.get("evidence_ref") or "")).name
        for item in attempt_payload.get("test_results", [])
        if isinstance(item, Mapping)
        and item.get("gate_id") == "schema-validation"
        and item.get("status") == "PASS"
    }
    events = {
        str(row[0])
        for row in state._connection.execute(
            "SELECT event_type FROM events WHERE product_id=? AND task_id=?",
            (str(source_task["product_id"]), task_id),
        ).fetchall()
    }
    deferred_builder = "builder_downstream_gate_deferred" in events
    adopted_builder = "builder_controller_gates_adopted" in events
    output_schema = str(source_task.get("output_schema") or "")
    for reference in refs:
        try:
            candidate = _safe_evidence_path(config.evidence_dir, str(reference))
        except RuntimeError:
            continue
        if candidate == attempt_path or candidate.name.startswith(
            ("context-", "usage-", "task-", "risk-", "repair-", "gate-")
        ):
            continue
        try:
            raw = candidate.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict) or find_secret_candidates(raw):
            continue
        accepted = payload.get("status") in {"completed", "accepted"}
        if deferred_builder:
            accepted = (
                candidate.name in schema_output_names
                and builder_result_is_locally_complete(payload)
            )
        elif adopted_builder:
            accepted = (
                candidate.name in schema_output_names
                and builder_result_is_controller_complete(payload)
            )
        if not accepted:
            continue
        try:
            schemas.validate(output_schema, payload)
        except (TypeError, ValueError):
            continue
        return attempt_id, f"evidence/{candidate.name}", sha256_file(candidate)
    raise RuntimeError(f"accepted source output is missing for {task_id}")


def git_candidate(config: FactoryConfig, product_id: str) -> tuple[str, str]:
    configured = Path(str(config.raw["paths"]["worktrees"]))
    candidates = (configured / product_id, configured / product_id / "repository")
    workspace = next((path for path in candidates if (path / ".git").exists()), None)
    if workspace is None:
        raise RuntimeError(
            "candidate repository workspace is missing; pass --repository-commit and "
            "--tree-digest explicitly"
        )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=workspace,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    tree = subprocess.run(
        ["git", "ls-tree", "-r", "--full-tree", "HEAD"],
        cwd=workspace,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    commit = head.stdout.strip().lower()
    if head.returncode != 0 or not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise RuntimeError("candidate repository HEAD is unavailable")
    if tree.returncode != 0:
        raise RuntimeError("candidate repository tree is unavailable")
    return commit, f"sha256:{sha256_text(tree.stdout)}"


def _fresh_test_task(
    connection: sqlite3.Connection,
    *,
    product_id: str,
    plan_id: str,
    snapshot_id: str,
    root_signature: str,
) -> tuple[str, tuple[str, ...]]:
    failed_rows = connection.execute(
        """SELECT * FROM tasks
             WHERE product_id=? AND role='test-engineer'
               AND graph_status IN ('FAILED_SEMANTIC','REJECTED','SUPERSEDED')
               AND (plan_id=? OR supersedes_task_id IN (
                   SELECT task_id FROM tasks WHERE product_id=? AND plan_id=?
               ))
             ORDER BY CASE WHEN lifecycle_stage='test' THEN 0 ELSE 1 END,
                      created_at, task_id""",
        (product_id, plan_id, product_id, plan_id),
    ).fetchall()
    if not failed_rows:
        existing = connection.execute(
            """SELECT task_id FROM tasks
                 WHERE product_id=? AND plan_id=? AND role='test-engineer'
                   AND candidate_snapshot_id=?
                   AND graph_status IN ('READY','CLAIMED','ACCEPTED')""",
            (product_id, plan_id, snapshot_id),
        ).fetchone()
        if existing is None:
            raise RuntimeError("failed Test task for candidate recovery is missing")
        return str(existing[0]), ()
    source = dict(failed_rows[0])
    superseded_ids = tuple(str(row["task_id"]) for row in failed_rows)
    seed = stable_json([product_id, plan_id, snapshot_id, "fresh-test"])
    fresh_id = f"T-{sha256_text(seed)[:16].upper()}"
    existing = connection.execute(
        "SELECT task_id FROM tasks WHERE task_id=?", (fresh_id,)
    ).fetchone()
    now = utc_now()
    if existing is None:
        columns = [
            str(row[1])
            for row in connection.execute("PRAGMA table_info(tasks)").fetchall()
        ]
        values = {column: source.get(column) for column in columns}
        values.update(
            {
                "task_id": fresh_id,
                "title": "Validate frozen candidate snapshot",
                "status": "PENDING",
                "graph_status": "READY",
                "dependencies_json": "[]",
                "created_at": now,
                "updated_at": now,
                "lease_owner": None,
                "lease_until": None,
                "heartbeat_at": None,
                "lease_token": None,
                "available_at": None,
                "attempts": 0,
                "result_ref": None,
                "result_digest": None,
                "result_binding_id": None,
                "candidate_snapshot_id": snapshot_id,
                "failure_id": None,
                "hypothesis_id": None,
                "terminal_reason": None,
                "terminal_detail": None,
                "failure_kind": None,
                "blocked_reason": None,
                "blocked_ref": None,
                "next_attempt_kind": "initial",
                "repair_context_ref": None,
                "idempotency_key": sha256_text(f"path-governor:{seed}"),
                "supersedes_task_id": superseded_ids[0],
                "root_problem_signature": root_signature,
            }
        )
        placeholders = ",".join("?" for _ in columns)
        connection.execute(
            f"INSERT INTO tasks ({','.join(columns)}) VALUES ({placeholders})",
            tuple(values[column] for column in columns),
        )
    placeholders = ",".join("?" for _ in superseded_ids)
    connection.execute(
        f"""UPDATE tasks
               SET graph_status='SUPERSEDED', status='DONE',
                   terminal_reason='path_governor_candidate_compacted',
                   terminal_detail='Superseded by a fresh Test over one immutable Candidate Snapshot.',
                   lease_owner=NULL, lease_until=NULL, heartbeat_at=NULL,
                   lease_token=NULL, updated_at=?
             WHERE task_id IN ({placeholders})""",
        (now, *superseded_ids),
    )
    connection.execute(
        f"""UPDATE failures SET status='RESOLVED', last_seen_at=?
             WHERE task_id IN ({placeholders}) AND status!='RESOLVED'""",
        (now, *superseded_ids),
    )
    connection.execute(
        f"""UPDATE hypotheses SET status='RESOLVED', closed_at=COALESCE(closed_at, ?)
             WHERE failure_id IN (
                 SELECT failure_id FROM failures WHERE task_id IN ({placeholders})
             ) AND status='ACTIVE'""",
        (now, *superseded_ids),
    )
    connection.execute(
        f"""UPDATE controller_incidents SET status='RESOLVED', resolved_at=?
             WHERE task_id IN ({placeholders}) AND status='OPEN'""",
        (now, *superseded_ids),
    )

    implementation_ids = {
        str(row[0])
        for row in connection.execute(
            """SELECT task_id FROM tasks
                 WHERE product_id=? AND plan_id=?
                   AND lifecycle_stage='implementation-slice'""",
            (product_id, plan_id),
        ).fetchall()
    }
    for source_id in superseded_ids:
        outgoing = connection.execute(
            """SELECT to_task_id, edge_type, required FROM task_edges
                WHERE plan_id=? AND from_task_id=?""",
            (plan_id, source_id),
        ).fetchall()
        for target_id, edge_type, required in outgoing:
            target = connection.execute(
                "SELECT graph_status FROM tasks WHERE task_id=?", (str(target_id),)
            ).fetchone()
            if target is not None and str(target[0]) not in {
                "ACCEPTED",
                "SUPERSEDED",
                "CANCELLED",
            }:
                connection.execute(
                    """INSERT OR IGNORE INTO task_edges
                       (plan_id, from_task_id, to_task_id, edge_type, required, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (plan_id, fresh_id, str(target_id), str(edge_type), int(required), now),
                )
                connection.execute(
                    "UPDATE tasks SET candidate_snapshot_id=? WHERE task_id=?",
                    (snapshot_id, str(target_id)),
                )
    if implementation_ids:
        edge_placeholders = ",".join("?" for _ in implementation_ids)
        connection.execute(
            f"""DELETE FROM task_edges
                  WHERE plan_id=? AND from_task_id IN ({edge_placeholders})
                    AND to_task_id IN (
                        SELECT task_id FROM tasks WHERE product_id=? AND plan_id=?
                          AND lifecycle_stage IN
                              ('test','security-review','release-readiness-review')
                    )""",
            (plan_id, *sorted(implementation_ids), product_id, plan_id),
        )
    connection.execute(
        "DELETE FROM task_edges WHERE plan_id=? AND to_task_id=?",
        (plan_id, fresh_id),
    )
    connection.execute(
        "UPDATE tasks SET dependencies_json='[]', candidate_snapshot_id=? WHERE task_id=?",
        (snapshot_id, fresh_id),
    )
    return fresh_id, superseded_ids


def migrate_product_path(
    config: FactoryConfig,
    state: StateStore,
    *,
    product_id: str,
    dry_run: bool,
    repository_commit: str | None = None,
    tree_digest: str | None = None,
    fault_injector: FaultInjector | None = None,
) -> dict[str, Any]:
    """Apply the current production-copy recovery as one idempotent transaction."""

    def inject(point: str) -> None:
        if fault_injector is not None:
            fault_injector(point)

    schemas = SchemaRegistry(config)
    selected_commit: str
    selected_tree: str
    if repository_commit is None or tree_digest is None:
        discovered_commit, discovered_tree = git_candidate(config, product_id)
        selected_commit = repository_commit or discovered_commit
        selected_tree = tree_digest or discovered_tree
    else:
        selected_commit, selected_tree = repository_commit, tree_digest
    if not re.fullmatch(r"[a-f0-9]{40}", selected_commit):
        raise ValueError("repository commit must be a 40-character lowercase git SHA")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", selected_tree):
        raise ValueError("tree digest must be sha256-prefixed")

    with state._lock:
        state._connection.execute("BEGIN IMMEDIATE")
        try:
            product = state._connection.execute(
                "SELECT * FROM products WHERE product_id=?", (product_id,)
            ).fetchone()
            if product is None:
                raise KeyError(product_id)
            if str(product["status"]) != "PAUSED":
                raise RuntimeError("Path migration requires the product to be PAUSED")
            plan_id = str(product["active_plan_id"] or "")
            if not plan_id:
                raise RuntimeError("Path migration requires an active plan")
            governor = PathGovernor(
                state._connection,
                policy_digest=policy_digest(config),
            )
            accepted = state._connection.execute(
                """SELECT task_id FROM tasks
                     WHERE product_id=? AND plan_id=? AND graph_status='ACCEPTED'
                     ORDER BY created_at, task_id""",
                (product_id, plan_id),
            ).fetchall()
            binding_ids: list[str] = []
            depths: list[int] = []
            for row in accepted:
                task_id = str(row[0])
                existing = governor.direct_binding(task_id)
                if existing is not None:
                    binding_ids.append(existing.binding_id)
                    depths.append(0)
                    continue
                source = governor.resolve_legacy_source(task_id)
                attempt_id, result_ref, result_digest = _accepted_output(
                    config, state, schemas, source.task
                )
                binding = governor.bind_result(
                    task_id=task_id,
                    source_task_id=str(source.task["task_id"]),
                    source_attempt_id=attempt_id,
                    result_ref=result_ref,
                    result_digest=result_digest,
                    output_schema=str(source.task.get("output_schema") or ""),
                )
                binding_ids.append(binding.binding_id)
                depths.append(source.depth)
            inject("after_bindings")

            rows = state._connection.execute(
                """SELECT DISTINCT binding.binding_id, task.lifecycle_stage
                     FROM tasks AS task
                     JOIN result_bindings AS binding
                       ON binding.binding_id=task.result_binding_id
                    WHERE task.product_id=? AND task.plan_id=?
                      AND binding.status='ACTIVE'
                      AND task.lifecycle_stage IN
                          ('architecture-review','implementation-slice')
                    ORDER BY binding.binding_id""",
                (product_id, plan_id),
            ).fetchall()
            snapshot_bindings = [str(row[0]) for row in rows]
            architecture = [
                str(row[0]) for row in rows if str(row[1]) == "architecture-review"
            ]
            if len(architecture) != 1:
                raise RuntimeError("candidate requires exactly one architecture binding")
            snapshot_id = governor.create_candidate_snapshot(
                product_id=product_id,
                plan_id=plan_id,
                repository_commit=selected_commit,
                tree_digest=selected_tree,
                architecture_binding_id=architecture[0],
                result_binding_ids=snapshot_bindings,
            )
            inject("after_snapshot")
            root_signature = stable_root_problem_signature(
                {
                    "product_id": product_id,
                    "failure_class": "controller",
                    "reason_code": "controller_result_lineage_depth_exceeded",
                    "semantic_node_key": "test",
                    "lifecycle_stage": "test",
                    "failed_gate_ids": ["accepted-result-provenance"],
                }
            )
            fresh_test_id, superseded_ids = _fresh_test_task(
                state._connection,
                product_id=product_id,
                plan_id=plan_id,
                snapshot_id=snapshot_id,
                root_signature=root_signature,
            )
            governor.register_execution_membership(fresh_test_id)
            inject("after_fresh_task")
            from .autonomy import AutonomyStore

            AutonomyStore(state)._recompute_frontier(state._connection, product_id)
            state._record_event(
                product_id,
                fresh_test_id,
                "path_governor_migration_applied",
                {
                    "plan_id": plan_id,
                    "bindings": len(set(binding_ids)),
                    "snapshot_id": snapshot_id,
                    "fresh_test_id": fresh_test_id,
                    "superseded_task_ids": superseded_ids,
                    "max_legacy_depth": max(depths, default=0),
                },
            )
            report = {
                "status": "PASS",
                "mode": "DRY_RUN" if dry_run else "APPLIED",
                "product_id": product_id,
                "plan_id": plan_id,
                "bindings": len(set(binding_ids)),
                "accepted_tasks": len(accepted),
                "literal_cycles": 0,
                "max_legacy_depth": max(depths, default=0),
                "candidate_snapshot_id": snapshot_id,
                "candidate_binding_count": len(snapshot_bindings),
                "fresh_test_id": fresh_test_id,
                "superseded_test_ids": list(superseded_ids),
                "repository_commit": selected_commit,
                "tree_digest": selected_tree,
            }
            inject("before_commit")
            if dry_run:
                state._connection.rollback()
            else:
                state._connection.commit()
            inject("after_commit")
            return report
        except Exception:
            if state._connection.in_transaction:
                state._connection.rollback()
            raise
