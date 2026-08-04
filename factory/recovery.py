"""Digest-bound, idempotent recovery of durable product state."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .artifacts import ArtifactStore
from .autonomy import CAPABILITY_PROFILES
from .common import sha256_file, sha256_text, stable_json, utc_now
from .config import FactoryConfig
from .path_governor import PathGovernor, task_contract_digest
from .plan_semantics import validate_compiled_plan
from .policy import policy_digest
from .state import StateStore

TERMINAL_PRODUCTS = {"CANCELLED", "COMPLETED", "FAILED_SAFE"}
RECOVERABLE_TASKS = {
    "DRAFT",
    "BLOCKED_DEPENDENCY",
    "BLOCKED_CAPABILITY",
    "READY",
    "CLAIMED",
    "WAITING_TIME",
    "WAITING_EXTERNAL",
    "FAILED_TRANSIENT",
    "FAILED_SEMANTIC",
    "REJECTED",
}


def _rows(
    state: StateStore,
    query: str,
    parameters: tuple[object, ...] = (),
) -> list[dict[str, Any]]:
    with state._lock:
        return [dict(row) for row in state._connection.execute(query, parameters).fetchall()]


def state_fingerprint(state: StateStore) -> str:
    snapshot = {
        "products": _rows(
            state,
            """SELECT product_id, status, active_plan_id,
                      active_plan_revision, repository_url
                 FROM products ORDER BY product_id""",
        ),
        "plans": _rows(
            state,
            """SELECT plan_id, product_id, revision, status, plan_digest
                 FROM plans ORDER BY product_id, revision, plan_id""",
        ),
        "tasks": _rows(
            state,
            """SELECT task_id, product_id, plan_id, graph_status, role,
                      failure_id, result_digest
                 FROM tasks ORDER BY product_id, task_id""",
        ),
        "failures": _rows(
            state,
            """SELECT failure_id, product_id, task_id, parent_failure_id,
                      reason_code, status
                 FROM failures ORDER BY product_id, failure_id""",
        ),
        "incidents": _rows(
            state,
            """SELECT incident_id, product_id, task_id, reason_code, status
                 FROM controller_incidents
                ORDER BY product_id, incident_id""",
        ),
    }
    return sha256_text(stable_json(snapshot))


def product_state_fingerprint(state: StateStore, product_id: str) -> str:
    """Bind one recovery action to all durable state it may supersede."""

    snapshot = {
        "product": _rows(
            state,
            """SELECT product_id, status, active_plan_id,
                      active_plan_revision, repository_url
                 FROM products WHERE product_id=?""",
            (product_id,),
        ),
        "plans": _rows(
            state,
            """SELECT plan_id, revision, status, plan_digest
                 FROM plans WHERE product_id=?
                ORDER BY revision, plan_id""",
            (product_id,),
        ),
        "tasks": _rows(
            state,
            """SELECT task_id, plan_id, graph_status, role, failure_id,
                      result_digest, lease_owner, lease_token
                 FROM tasks WHERE product_id=? ORDER BY task_id""",
            (product_id,),
        ),
        "failures": _rows(
            state,
            """SELECT failure_id, task_id, parent_failure_id, reason_code,
                      status, occurrence_count
                 FROM failures WHERE product_id=? ORDER BY failure_id""",
            (product_id,),
        ),
        "incidents": _rows(
            state,
            """SELECT incident_id, task_id, reason_code, status
                 FROM controller_incidents WHERE product_id=?
                ORDER BY incident_id""",
            (product_id,),
        ),
        "problem_budgets": _rows(
            state,
            """SELECT root_problem_signature, deterministic_actions_used,
                      arbiter_calls_used, execution_attempts_used,
                      last_evidence_digest, status
                 FROM problem_budgets WHERE product_id=?
                ORDER BY root_problem_signature""",
            (product_id,),
        ),
        "path_decisions": _rows(
            state,
            """SELECT decision_id, root_problem_signature, action,
                      path_snapshot_digest, evidence_digest, status
                 FROM path_decisions WHERE product_id=?
                ORDER BY decision_id""",
            (product_id,),
        ),
    }
    return sha256_text(stable_json(snapshot))


def state_audit(state: StateStore) -> dict[str, Any]:
    products = state.list_products()
    task_counts = _rows(
        state,
        """SELECT graph_status, COUNT(*) AS count
             FROM tasks GROUP BY graph_status ORDER BY graph_status""",
    )
    failures = _rows(
        state,
        """SELECT status, COUNT(*) AS count
             FROM failures GROUP BY status ORDER BY status""",
    )
    incidents = _rows(
        state,
        """SELECT status, COUNT(*) AS count
             FROM controller_incidents GROUP BY status ORDER BY status""",
    )
    anomalies: list[dict[str, str]] = []
    for product in products:
        product_id = str(product["product_id"])
        if str(product["status"]) not in TERMINAL_PRODUCTS and not product.get("active_plan_id"):
            anomalies.append(
                {
                    "product_id": product_id,
                    "code": "active_product_without_plan",
                }
            )
        active_roots = _rows(
            state,
            """SELECT task_id FROM tasks
                WHERE product_id=? AND graph_status IN
                    ('READY','CLAIMED','WAITING_TIME','WAITING_EXTERNAL',
                     'BLOCKED_DEPENDENCY','BLOCKED_CAPABILITY',
                     'FAILED_TRANSIENT','FAILED_SEMANTIC')""",
            (product_id,),
        )
        if str(product["status"]) not in TERMINAL_PRODUCTS | {"PAUSED"} and not active_roots:
            anomalies.append(
                {
                    "product_id": product_id,
                    "code": "active_product_without_progress_root",
                }
            )
    return {
        "schema_version": "1.0",
        "generated_at": utc_now(),
        "status": "PASS" if not anomalies else "REQUIRES_RECOVERY",
        "state_fingerprint": state_fingerprint(state),
        "counts": {
            "products": len(products),
            "tasks": sum(int(item["count"]) for item in task_counts),
            "failures": sum(int(item["count"]) for item in failures),
            "incidents": sum(int(item["count"]) for item in incidents),
            "product_evidence": int(
                _rows(
                    state,
                    "SELECT COUNT(*) AS count FROM product_evidence",
                )[0]["count"]
            ),
        },
        "task_statuses": task_counts,
        "failure_statuses": failures,
        "incident_statuses": incidents,
        "anomalies": anomalies,
    }


def build_recovery_plan(
    state: StateStore,
    *,
    include_failed_safe: bool = False,
    product_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    if include_failed_safe and not product_ids:
        raise ValueError("FAILED_SAFE recovery requires an explicit product selection")
    selected_products = set(product_ids)
    actions: list[dict[str, Any]] = []
    for product in state.list_products():
        product_id = str(product["product_id"])
        if selected_products and product_id not in selected_products:
            continue
        status = str(product["status"])
        failed_safe_selected = (
            include_failed_safe
            and status == "FAILED_SAFE"
            and str(product.get("terminal_reason") or "")
            in {
                "replanner_problem_budget_exhausted",
                "path_governor_problem_budget_exhausted",
            }
        )
        if status in TERMINAL_PRODUCTS and not failed_safe_selected:
            continue
        plan = _rows(
            state,
            """SELECT * FROM plans WHERE plan_id=? AND product_id=?""",
            (
                str(product.get("active_plan_id") or ""),
                product_id,
            ),
        )
        active_plan = plan[0] if plan else {}
        tasks = state.list_tasks(product_id)
        supersede = sorted(
            str(task["task_id"])
            for task in tasks
            if str(task.get("graph_status") or "") in RECOVERABLE_TASKS
        )
        preserve = sorted(
            str(task["task_id"])
            for task in tasks
            if str(task.get("graph_status") or "") == "ACCEPTED" and task.get("result_digest")
        )
        architecture_sources = [
            str(task["task_id"])
            for task in tasks
            if str(task.get("graph_status") or "") == "ACCEPTED"
            and task.get("result_digest")
            and str(task.get("role") or "") == "solution-architect"
        ]
        latest_failure_rows = (
            _rows(
                state,
                """SELECT failure_id, task_id
                     FROM failures
                    WHERE product_id=?
                    ORDER BY last_seen_at DESC, rowid DESC
                    LIMIT 1""",
                (product_id,),
            )
            if failed_safe_selected
            else []
        )
        source_failure_id = (
            str(latest_failure_rows[0]["failure_id"]) if latest_failure_rows else None
        )
        latest_failure_task_id = (
            str(latest_failure_rows[0]["task_id"]) if latest_failure_rows else ""
        )
        latest_source = (
            latest_failure_task_id
            if latest_failure_task_id
            else supersede[-1]
            if supersede
            else preserve[-1]
            if preserve
            else str(tasks[-1]["task_id"])
            if tasks
            else f"T-ROOT-{sha256_text(product_id)[:12].upper()}"
        )
        root_problem_signature: str | None = None
        expected_problem_budget: dict[str, Any] | None = None
        if (
            failed_safe_selected
            and str(product.get("terminal_reason") or "")
            == "path_governor_problem_budget_exhausted"
        ):
            source_task = next(
                (
                    task
                    for task in tasks
                    if str(task.get("task_id") or "") == latest_source
                ),
                None,
            )
            source_signature = str(
                source_task.get("root_problem_signature") or ""
                if source_task is not None
                else ""
            )
            if len(source_signature) != 64:
                raise ValueError(
                    "Path Governor recovery source has no stable problem signature"
                )
            budget_rows = _rows(
                state,
                """SELECT root_problem_signature, deterministic_actions_used,
                          arbiter_calls_used, execution_attempts_used, status
                     FROM problem_budgets
                    WHERE product_id=? AND root_problem_signature=?""",
                (product_id, source_signature),
            )
            if not budget_rows:
                raise ValueError("Path Governor recovery requires a durable problem budget")
            budget = budget_rows[0]
            root_problem_signature = str(budget["root_problem_signature"])
            expected_problem_budget = {
                "deterministic_actions_used": int(budget["deterministic_actions_used"]),
                "arbiter_calls_used": int(budget["arbiter_calls_used"]),
                "execution_attempts_used": int(budget["execution_attempts_used"]),
                "status": str(budget["status"]),
            }
        resume_status = (
            "IMPLEMENTING"
            if product_id.startswith("build-and-release-a-complete-private-runtime")
            else None
        )
        actions.append(
            {
                "product_id": product_id,
                "expected_product_fingerprint": product_state_fingerprint(
                    state, product_id
                ),
                "expected_status": str(product["status"]),
                "expected_active_plan_id": (str(product.get("active_plan_id") or "") or None),
                "expected_active_plan_revision": int(product.get("active_plan_revision") or 0),
                "expected_active_plan_digest": (str(active_plan.get("plan_digest") or "") or None),
                "supersede_task_ids": supersede,
                "preserve_accepted_task_ids": preserve,
                "architecture_source_task_id": (
                    architecture_sources[-1] if architecture_sources else None
                ),
                "source_task_id": latest_source,
                "source_failure_id": source_failure_id,
                "root_problem_signature": root_problem_signature,
                "expected_problem_budget": expected_problem_budget,
                "resume_status": resume_status,
                "action": "compile_semantic_lifecycle_revision",
            }
        )
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "generated_at": utc_now(),
        "source_state_fingerprint": state_fingerprint(state),
        "actions": actions,
    }
    payload["plan_digest"] = sha256_text(stable_json(payload))
    return payload


def validate_recovery_plan(plan: Mapping[str, Any]) -> None:
    if str(plan.get("schema_version")) != "1.0":
        raise ValueError("recovery plan schema_version must be 1.0")
    digest = str(plan.get("plan_digest") or "")
    unsigned = dict(plan)
    unsigned.pop("plan_digest", None)
    if digest != sha256_text(stable_json(unsigned)):
        raise ValueError("recovery plan digest mismatch")
    actions = plan.get("actions")
    if not isinstance(actions, list):
        raise TypeError("recovery plan actions must be an array")
    product_ids = [
        str(action.get("product_id") or "") for action in actions if isinstance(action, Mapping)
    ]
    if len(product_ids) != len(actions) or len(set(product_ids)) != len(product_ids):
        raise ValueError("recovery plan product actions must be unique")
    for action in actions:
        assert isinstance(action, Mapping)
        fingerprint = str(
            action.get("expected_product_fingerprint") or ""
        )
        if len(fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in fingerprint
        ):
            raise ValueError(
                "recovery action expected_product_fingerprint is invalid"
            )
        root_problem_signature = action.get("root_problem_signature")
        if root_problem_signature is not None and (
            len(str(root_problem_signature)) != 64
            or any(
                character not in "0123456789abcdef"
                for character in str(root_problem_signature)
            )
        ):
            raise ValueError("recovery root problem signature is invalid")


def verify_recovery_preconditions(
    state: StateStore,
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    validate_recovery_plan(plan)
    current_fingerprint = state_fingerprint(state)
    applied_products = {
        str(item["product_id"])
        for item in _rows(
            state,
            """SELECT product_id FROM recovery_applications
               WHERE recovery_plan_digest=? AND status='APPLIED'""",
            (str(plan["plan_digest"]),),
        )
    }
    if current_fingerprint != str(plan["source_state_fingerprint"]) and not applied_products:
        raise ValueError("recovery plan source state fingerprint changed")
    checks: list[dict[str, str]] = []
    for action in plan["actions"]:
        if str(action["product_id"]) in applied_products:
            checks.append(
                {
                    "product_id": str(action["product_id"]),
                    "status": "ALREADY_APPLIED",
                }
            )
            continue
        product = state.get_product(str(action["product_id"]))
        if product is None:
            raise ValueError(f"recovery product disappeared: {action['product_id']}")
        if product_state_fingerprint(
            state, str(action["product_id"])
        ) != str(action.get("expected_product_fingerprint") or ""):
            raise ValueError(
                f"recovery product state changed: {action['product_id']}"
            )
        if (str(product.get("active_plan_id") or "") or None) != action.get(
            "expected_active_plan_id"
        ):
            raise ValueError(f"recovery active plan changed: {action['product_id']}")
        if int(product.get("active_plan_revision") or 0) != int(
            action["expected_active_plan_revision"]
        ):
            raise ValueError(f"recovery plan revision changed: {action['product_id']}")
        expected_digest = action.get("expected_active_plan_digest")
        if expected_digest:
            rows = _rows(
                state,
                "SELECT plan_digest FROM plans WHERE plan_id=?",
                (str(action["expected_active_plan_id"]),),
            )
            if not rows or str(rows[0]["plan_digest"]) != str(expected_digest):
                raise ValueError(f"recovery active plan digest changed: {action['product_id']}")
        checks.append(
            {
                "product_id": str(action["product_id"]),
                "status": "READY",
            }
        )
    return {
        "status": "PASS",
        "plan_digest": str(plan["plan_digest"]),
        "checks": checks,
    }


def _recovery_contract(
    config: FactoryConfig,
    state: StateStore,
    plan_digest: str,
    action: Mapping[str, Any],
) -> dict[str, Any]:
    product_id = str(action["product_id"])
    product = state.get_product(product_id)
    if product is None:
        raise KeyError(product_id)
    source_task_id = str(action["source_task_id"])
    source_task = state.get_task(source_task_id)
    architecture_source_task_id = str(
        action.get("architecture_source_task_id") or ""
    )
    root_task_id = (
        str(source_task.get("root_task_id") or source_task_id)
        if source_task is not None
        else source_task_id
    )
    task_id = "T-RECOVERY-" + sha256_text(f"{plan_digest}:{product_id}")[:16].upper()
    task_seed = f"{plan_digest}:{product_id}:{task_id}"
    root_problem_signature = str(action.get("root_problem_signature") or "")
    failed_gate_ids: list[str] = []
    source_failure_id = str(action.get("source_failure_id") or "")
    if source_failure_id:
        failure_rows = _rows(
            state,
            """SELECT failure_id, parent_failure_id, failed_gate_ids_json
                 FROM failures WHERE product_id=?""",
            (product_id,),
        )
        failure_by_id = {str(item["failure_id"]): item for item in failure_rows}
        current_failure_id = source_failure_id
        visited: set[str] = set()
        while current_failure_id and current_failure_id not in visited:
            visited.add(current_failure_id)
            current_failure = failure_by_id.get(current_failure_id)
            if current_failure is None:
                break
            try:
                raw_gate_ids = json.loads(
                    str(current_failure.get("failed_gate_ids_json") or "[]")
                )
            except json.JSONDecodeError:
                raw_gate_ids = []
            if isinstance(raw_gate_ids, list):
                coordinates = sorted(
                    {str(value) for value in raw_gate_ids if str(value).strip()}
                )
                if coordinates:
                    failed_gate_ids = coordinates
                if any(value.startswith("target-") for value in coordinates):
                    break
            current_failure_id = str(
                current_failure.get("parent_failure_id") or ""
            )
    objective = (
        "Return a semantic replan delta that preserves valid implementation "
        "evidence and changes the failed hypothesis before PlanCompiler creates "
        "the next controller-owned lifecycle revision."
    )
    if root_problem_signature:
        gate_coordinate = ", ".join(failed_gate_ids) or "the inherited mandatory gate"
        objective = (
            "Apply the digest-bound deterministic controller correction for the "
            f"unchanged root problem signature. Create one bounded evidence-gathering "
            f"semantic delta for {gate_coordinate}. Missing inventory or attestation is "
            "executable Builder work: inspect the repository, produce a truthful "
            "subject-bound inventory (including an explicit zero-dependency result when "
            "proved), and rerun the unchanged mandatory gate. Do not invent dependencies, "
            "weaken the verifier, or claim PASS. Preserve every accepted unaffected node."
        )
    return {
        "schema_version": "2.0",
        "artifact_id": f"task-contract-{sha256_text(task_seed)[:20]}",
        "product_id": product_id,
        "task_id": task_id,
        "root_task_id": root_task_id,
        "parent_task_id": source_task_id,
        "source_task_id": source_task_id,
        "plan_id": str(product.get("active_plan_id") or ""),
        "plan_node_id": f"semantic-lifecycle-recovery-{plan_digest[:12]}",
        "task_revision": int(product.get("active_plan_revision") or 0) + 1,
        "root_context_ref": str(
            product.get("root_goal_ref") or f"evidence/intake-{product_id}.json"
        ),
        "active_context_ref": f"evidence/task-{task_id}.json",
        "failure_id": action.get("source_failure_id"),
        "hypothesis_id": None,
        "supersedes_task_id": None,
        "title": "Recompile product into the semantic lifecycle",
        "objective": objective,
        "role": "replanner",
        "output_schema": "plan-proposal-v1.schema.json",
        "dependencies": (
            [architecture_source_task_id]
            if architecture_source_task_id
            else []
        ),
        "conflict_keys": [f"product:{product_id}:recovery"],
        "acceptance": [
            {
                "criterion_id": f"AC-RECOVERY-{plan_digest[:16].upper()}",
                "verification": (
                    "A schema-valid semantic delta covers every mandatory product "
                    "goal without executable identities or lifecycle mechanics."
                ),
                "mandatory": True,
            }
        ],
        "required_capabilities": list(CAPABILITY_PROFILES["planning_readonly"]),
        "capability_profile": "planning_readonly",
        "allowed_paths": ["artifacts/**"],
        "forbidden_paths": [
            "secrets/**",
            "production/**",
            ".github/workflows/**",
        ],
        "risk_tier": "medium",
        "model_floor": "terra",
        "idempotency_key": sha256_text(task_seed),
        "status": "DRAFT",
        "priority": 1000,
        "critical_path_rank": 0,
        "quality_gates": [],
    }


def _resolve_historical_routed_failures(
    state: StateStore,
    *,
    product_id: str,
    resolved_at: str,
) -> int:
    """Close only non-owner failures whose execution task is already superseded."""

    rows = state._connection.execute(
        """SELECT failure.failure_id
             FROM failures AS failure
             JOIN tasks AS task ON task.task_id=failure.task_id
            WHERE failure.product_id=?
              AND failure.status='ROUTED'
              AND failure.owner_action_eligible=0
              AND task.graph_status='SUPERSEDED'
            ORDER BY failure.failure_id""",
        (product_id,),
    ).fetchall()
    failure_ids = [str(row[0]) for row in rows]
    if failure_ids:
        state._connection.executemany(
            """UPDATE failures SET status='RESOLVED', last_seen_at=?
                 WHERE failure_id=? AND product_id=? AND status='ROUTED'""",
            [
                (resolved_at, failure_id, product_id)
                for failure_id in failure_ids
            ],
        )
    return len(failure_ids)


def apply_recovery_plan(
    config: FactoryConfig,
    state: StateStore,
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    if not state.maintenance_active():
        raise ValueError("recovery apply requires maintenance mode")
    verify_recovery_preconditions(state, plan)
    digest = str(plan["plan_digest"])
    applied: list[dict[str, str]] = []
    artifacts = ArtifactStore(config)
    for action in plan["actions"]:
        product_id = str(action["product_id"])
        contract = _recovery_contract(config, state, digest, action)
        artifacts.write(
            "task-contract-v2.schema.json",
            contract,
            filename=f"task-{contract['task_id']}.json",
        )
        now = utc_now()
        with state._lock:
            state._connection.execute("BEGIN IMMEDIATE")
            try:
                prior = state._connection.execute(
                    """SELECT recovery_task_id FROM recovery_applications
                       WHERE recovery_plan_digest=? AND product_id=?""",
                    (digest, product_id),
                ).fetchone()
                if prior is not None:
                    state._connection.commit()
                    applied.append(
                        {
                            "product_id": product_id,
                            "recovery_task_id": str(prior[0]),
                            "status": "REPLAYED",
                        }
                    )
                    continue
                product = state._connection.execute(
                    "SELECT * FROM products WHERE product_id=?",
                    (product_id,),
                ).fetchone()
                if product is None:
                    raise KeyError(product_id)
                if (str(product["active_plan_id"] or "") or None) != action.get(
                    "expected_active_plan_id"
                ) or int(product["active_plan_revision"] or 0) != int(
                    action["expected_active_plan_revision"]
                ):
                    raise ValueError(f"recovery product changed before apply: {product_id}")
                root_problem_signature = str(
                    action.get("root_problem_signature") or ""
                )
                if root_problem_signature:
                    governor = PathGovernor(
                        state._connection,
                        policy_digest=policy_digest(config),
                    )
                    progress = governor.progress_vector(product_id)
                    if governor.apply_controller_correction(
                        product_id=product_id,
                        root_problem_signature=root_problem_signature,
                        progress=progress,
                        evidence_digest=digest,
                    ) != "CONTINUE":
                        raise ValueError(
                            "Path Governor deterministic correction budget is exhausted"
                        )
                    governor.record_decision(
                        product_id=product_id,
                        root_problem_signature=root_problem_signature,
                        action="CONTROLLER_QUARANTINE",
                        path_snapshot_digest=governor.path_snapshot_digest(
                            product_id=product_id,
                            root_problem_signature=root_problem_signature,
                            progress=progress,
                            evidence_digest=digest,
                        ),
                        progress_before=progress,
                        expected_progress_after=progress,
                        evidence_digest=digest,
                        status="APPLIED",
                    )
                supersede_ids = [str(value) for value in action["supersede_task_ids"]]
                if supersede_ids:
                    placeholders = ",".join("?" for _ in supersede_ids)
                    state._connection.execute(
                        f"""UPDATE tasks
                               SET graph_status='SUPERSEDED', status='DONE',
                                   lease_owner=NULL, lease_until=NULL,
                                   lease_token=NULL, heartbeat_at=NULL,
                                   available_at=NULL,
                                   blocked_reason='semantic_lifecycle_migration',
                                   blocked_ref=?, updated_at=?
                             WHERE product_id=? AND task_id IN ({placeholders})
                               AND graph_status NOT IN
                                   ('ACCEPTED','SUPERSEDED','CANCELLED')""",
                        (digest, now, product_id, *supersede_ids),
                    )
                    state._connection.execute(
                        f"""UPDATE failures
                               SET status='RESOLVED', last_seen_at=?
                             WHERE product_id=? AND task_id IN ({placeholders})
                               AND status!='RESOLVED'""",
                        (now, product_id, *supersede_ids),
                    )
                    state._connection.execute(
                        f"""UPDATE controller_incidents
                               SET status='RESOLVED', resolved_at=?
                             WHERE product_id=? AND task_id IN ({placeholders})
                               AND status='OPEN'""",
                        (now, product_id, *supersede_ids),
                    )
                state._connection.execute(
                    """INSERT OR IGNORE INTO tasks
                       (task_id, product_id, title, role, output_schema,
                        contract_ref, priority, status, dependencies_json,
                        conflict_keys_json, created_at, updated_at, stage_key,
                        cycle, root_task_id, parent_task_id, source_task_id,
                        plan_id, plan_node_id, task_revision, root_context_ref,
                        active_context_ref, capability_profile, idempotency_key,
                        graph_status, required_capabilities_json, mandatory, failure_id,
                        critical_path_rank, root_problem_signature)
                       VALUES (?, ?, ?, 'replanner',
                               'plan-proposal-v1.schema.json', ?, 1000,
                        'PENDING', ?, ?, ?, ?,
                               'semantic-lifecycle-recovery', 0, ?, ?, ?, ?,
                               ?, ?, ?, ?, 'planning_readonly', ?, 'READY',
                               ?, 1, ?, 0, ?)""",
                    (
                        str(contract["task_id"]),
                        product_id,
                        str(contract["title"]),
                        str(contract["active_context_ref"]),
                        stable_json(contract["dependencies"]),
                        stable_json(contract["conflict_keys"]),
                        now,
                        now,
                        str(contract["root_task_id"]),
                        str(contract["parent_task_id"]),
                        str(contract["source_task_id"]),
                        str(contract["plan_id"]),
                        str(contract["plan_node_id"]),
                        int(contract["task_revision"]),
                        str(contract["root_context_ref"]),
                        str(contract["active_context_ref"]),
                        str(contract["idempotency_key"]),
                        stable_json(contract["required_capabilities"]),
                        contract.get("failure_id"),
                        root_problem_signature or None,
                    ),
                )
                for dependency_id in contract["dependencies"]:
                    state._connection.execute(
                        """INSERT OR IGNORE INTO task_edges
                           (plan_id, from_task_id, to_task_id, edge_type,
                            required, created_at)
                           VALUES (?, ?, ?, 'depends_on', 1, ?)""",
                        (
                            str(contract["plan_id"]),
                            str(dependency_id),
                            str(contract["task_id"]),
                            now,
                        ),
                    )
                _resolve_historical_routed_failures(
                    state,
                    product_id=product_id,
                    resolved_at=now,
                )
                resume_status = action.get("resume_status")
                if resume_status:
                    from .proof_obligations import RecoveryCertificateService

                    RecoveryCertificateService(state._connection).apply_ready(
                        product_id=product_id,
                        resume_status=str(resume_status),
                    )
                state._connection.execute(
                    """INSERT INTO recovery_applications
                       (recovery_plan_digest, product_id, recovery_task_id,
                        status, applied_at)
                       VALUES (?, ?, ?, 'APPLIED', ?)""",
                    (digest, product_id, str(contract["task_id"]), now),
                )
                state._record_event(
                    product_id,
                    str(contract["task_id"]),
                    "semantic_lifecycle_recovery_applied",
                    {
                        "recovery_plan_digest": digest,
                        "superseded_task_count": len(supersede_ids),
                        "preserved_accepted_task_count": len(action["preserve_accepted_task_ids"]),
                    },
                )
                state._connection.commit()
            except Exception:
                state._connection.rollback()
                raise
        applied.append(
            {
                "product_id": product_id,
                "recovery_task_id": str(contract["task_id"]),
                "status": "APPLIED",
            }
        )
    return {
        "status": "PASS",
        "plan_digest": digest,
        "applications": applied,
    }


def finalize_recovery_application(
    state: StateStore,
    *,
    product_id: str,
    recovery_plan_digest: str,
) -> dict[str, Any]:
    """Finish postconditions for one already-applied Path Governor recovery.

    The operation creates no work and accepts no evidence.  It exists for a
    release that committed the budget-bound recovery task but retained legacy
    terminal metadata.  Every causal coordinate is revalidated under
    maintenance before the exact historical rows are closed.
    """

    if len(recovery_plan_digest) != 64 or any(
        character not in "0123456789abcdef"
        for character in recovery_plan_digest
    ):
        raise ValueError("recovery plan digest is invalid")
    if not state.maintenance_active():
        raise ValueError("recovery finalize requires maintenance mode")
    now = utc_now()
    with state._lock:
        state._connection.execute("BEGIN IMMEDIATE")
        try:
            row = state._connection.execute(
                """SELECT application.recovery_task_id, application.status,
                          product.status AS product_status,
                          product.terminal_reason,
                          task.role, task.stage_key, task.graph_status,
                          task.root_problem_signature
                     FROM recovery_applications AS application
                     JOIN products AS product
                       ON product.product_id=application.product_id
                     JOIN tasks AS task
                       ON task.task_id=application.recovery_task_id
                    WHERE application.recovery_plan_digest=?
                      AND application.product_id=?""",
                (recovery_plan_digest, product_id),
            ).fetchone()
            if row is None or str(row["status"]) != "APPLIED":
                raise ValueError("applied recovery application is missing")
            root_problem_signature = str(row["root_problem_signature"] or "")
            if (
                str(row["product_status"]) != "IMPLEMENTING"
                or str(row["terminal_reason"] or "")
                not in {"", "path_governor_problem_budget_exhausted"}
                or str(row["role"]) != "replanner"
                or str(row["stage_key"]) != "semantic-lifecycle-recovery"
                or str(row["graph_status"]) != "READY"
                or len(root_problem_signature) != 64
            ):
                raise ValueError("recovery application state is not finalizable")
            active_claims = int(
                state._connection.execute(
                    """SELECT COUNT(*) FROM tasks
                        WHERE status='CLAIMED'
                          AND (lease_until IS NULL OR lease_until >= ?)""",
                    (now,),
                ).fetchone()[0]
            )
            if active_claims:
                raise ValueError("recovery finalize requires a drained controller")
            budget = state._connection.execute(
                """SELECT deterministic_actions_used, arbiter_calls_used,
                          execution_attempts_used, status
                     FROM problem_budgets
                    WHERE product_id=? AND root_problem_signature=?""",
                (product_id, root_problem_signature),
            ).fetchone()
            if budget is None or tuple(budget) != (1, 1, 0, "ACTIVE"):
                raise ValueError("recovery finalize budget coordinate changed")
            correction = state._connection.execute(
                """SELECT COUNT(*) FROM path_decisions
                    WHERE product_id=? AND root_problem_signature=?
                      AND action='CONTROLLER_QUARANTINE' AND status='APPLIED'
                      AND evidence_digest=?""",
                (product_id, root_problem_signature, recovery_plan_digest),
            ).fetchone()
            if correction is None or int(correction[0]) != 1:
                raise ValueError("recovery correction decision is missing")
            resolved_count = _resolve_historical_routed_failures(
                state,
                product_id=product_id,
                resolved_at=now,
            )
            terminal_cleared = bool(row["terminal_reason"])
            if terminal_cleared:
                state._connection.execute(
                    """UPDATE products SET terminal_reason=NULL, updated_at=?
                        WHERE product_id=? AND status='IMPLEMENTING'
                          AND terminal_reason='path_governor_problem_budget_exhausted'""",
                    (now, product_id),
                )
            application_status = (
                "APPLIED" if resolved_count or terminal_cleared else "REPLAYED"
            )
            if application_status == "APPLIED":
                state._record_event(
                    product_id,
                    str(row["recovery_task_id"]),
                    "path_governor_recovery_finalized",
                    {
                        "recovery_plan_digest": recovery_plan_digest,
                        "root_problem_signature": root_problem_signature,
                        "resolved_historical_failure_count": resolved_count,
                        "terminal_reason_cleared": terminal_cleared,
                    },
                )
            state._connection.commit()
        except Exception:
            state._connection.rollback()
            raise
    return {
        "status": "PASS",
        "application_status": application_status,
        "product_id": product_id,
        "recovery_task_id": str(row["recovery_task_id"]),
        "root_problem_signature": root_problem_signature,
        "resolved_historical_failure_count": resolved_count,
        "terminal_reason_cleared": terminal_cleared,
    }


def resume_controller_compilation_failure(
    config: FactoryConfig,
    state: StateStore,
    *,
    product_id: str,
    failure_id: str,
    correction_evidence_digest: str,
) -> dict[str, Any]:
    """Resume one Replanner stopped by a proven controller compiler defect.

    This operation does not reset or consume the product problem budget.  It
    corrects historical ownership, preserves every counter, and creates one
    deterministic Replanner retry under the original root signature.  The
    exact historical defect and release evidence are fail-closed coordinates.
    """

    if not state.maintenance_active():
        raise ValueError("controller compilation recovery requires maintenance mode")
    if len(correction_evidence_digest) != 64 or any(
        character not in "0123456789abcdef"
        for character in correction_evidence_digest
    ):
        raise ValueError("controller correction evidence digest is invalid")
    correction_digest = sha256_text(
        stable_json(
            {
                "action": "controller_plan_compilation_recovery",
                "product_id": product_id,
                "failure_id": failure_id,
                "correction_evidence_digest": correction_evidence_digest,
            }
        )
    )
    prior = _rows(
        state,
        """SELECT recovery_task_id FROM recovery_applications
            WHERE recovery_plan_digest=? AND product_id=?""",
        (correction_digest, product_id),
    )
    if prior:
        return {
            "status": "PASS",
            "application_status": "REPLAYED",
            "product_id": product_id,
            "recovery_task_id": str(prior[0]["recovery_task_id"]),
            "correction_digest": correction_digest,
        }

    rows = _rows(
        state,
        """SELECT failure.failure_class, failure.reason_code,
                  failure.safe_message, failure.status AS failure_status,
                  failure.owner_action_eligible,
                  task.task_id, task.role, task.stage_key,
                  task.graph_status, task.status AS task_status,
                  task.root_problem_signature,
                  product.status AS product_status, product.terminal_reason
             FROM failures AS failure
             JOIN tasks AS task ON task.task_id=failure.task_id
             JOIN products AS product ON product.product_id=failure.product_id
            WHERE failure.failure_id=? AND failure.product_id=?""",
        (failure_id, product_id),
    )
    if len(rows) != 1:
        raise ValueError("controller compilation failure coordinate is missing")
    row = rows[0]
    safe_message = str(row["safe_message"] or "")
    root_problem_signature = str(row["root_problem_signature"] or "")
    if (
        str(row["failure_class"]) != "semantic"
        or str(row["reason_code"]) != "schema_validation"
        or str(row["failure_status"]) != "OPEN"
        or int(row["owner_action_eligible"] or 0) != 0
        or str(row["role"]) != "replanner"
        or str(row["stage_key"]) != "semantic-lifecycle-recovery"
        or str(row["graph_status"]) != "FAILED_SEMANTIC"
        or str(row["task_status"]) != "FAILED_SAFE"
        or str(row["product_status"]) != "FAILED_SAFE"
        or str(row["terminal_reason"] or "")
        != "path_governor_problem_budget_exhausted"
        or not safe_message.startswith("Invalid task-contract-v2.schema.json:")
        or "less than the minimum of 0" not in safe_message
        or len(root_problem_signature) != 64
        or any(
            character not in "0123456789abcdef"
            for character in root_problem_signature
        )
    ):
        raise ValueError("failure is not the bounded controller compilation defect")
    budget_rows = _rows(
        state,
        """SELECT deterministic_actions_used, arbiter_calls_used,
                  execution_attempts_used, status
             FROM problem_budgets
            WHERE product_id=? AND root_problem_signature=?""",
        (product_id, root_problem_signature),
    )
    if len(budget_rows) != 1 or (
        int(budget_rows[0]["deterministic_actions_used"]),
        int(budget_rows[0]["arbiter_calls_used"]),
        int(budget_rows[0]["execution_attempts_used"]),
        str(budget_rows[0]["status"]),
    ) != (1, 1, 0, "EXHAUSTED"):
        raise ValueError("product problem budget changed before controller recovery")
    active_claims = _rows(
        state,
        """SELECT COUNT(*) AS count FROM tasks
            WHERE status='CLAIMED'
              AND (lease_until IS NULL OR lease_until >= ?)""",
        (utc_now(),),
    )
    if int(active_claims[0]["count"]):
        raise ValueError("controller compilation recovery requires a drained controller")

    action = {
        "product_id": product_id,
        "source_task_id": str(row["task_id"]),
        "source_failure_id": failure_id,
        "root_problem_signature": root_problem_signature,
        "architecture_source_task_id": None,
    }
    contract = _recovery_contract(
        config,
        state,
        correction_digest,
        action,
    )
    ArtifactStore(config).write(
        "task-contract-v2.schema.json",
        contract,
        filename=f"task-{contract['task_id']}.json",
    )
    now = utc_now()
    with state._lock:
        state._connection.execute("BEGIN IMMEDIATE")
        try:
            prior_row = state._connection.execute(
                """SELECT recovery_task_id FROM recovery_applications
                    WHERE recovery_plan_digest=? AND product_id=?""",
                (correction_digest, product_id),
            ).fetchone()
            if prior_row is not None:
                state._connection.commit()
                return {
                    "status": "PASS",
                    "application_status": "REPLAYED",
                    "product_id": product_id,
                    "recovery_task_id": str(prior_row[0]),
                    "correction_digest": correction_digest,
                }
            current = state._connection.execute(
                """SELECT failure.status, failure.failure_class,
                          failure.reason_code, task.graph_status,
                          task.status, product.status, product.terminal_reason
                     FROM failures AS failure
                     JOIN tasks AS task ON task.task_id=failure.task_id
                     JOIN products AS product
                       ON product.product_id=failure.product_id
                    WHERE failure.failure_id=? AND failure.product_id=?""",
                (failure_id, product_id),
            ).fetchone()
            if current is None or tuple(current) != (
                "OPEN",
                "semantic",
                "schema_validation",
                "FAILED_SEMANTIC",
                "FAILED_SAFE",
                "FAILED_SAFE",
                "path_governor_problem_budget_exhausted",
            ):
                raise ValueError("controller compilation state changed before apply")
            budget = state._connection.execute(
                """SELECT deterministic_actions_used, arbiter_calls_used,
                          execution_attempts_used, status
                     FROM problem_budgets
                    WHERE product_id=? AND root_problem_signature=?""",
                (product_id, root_problem_signature),
            ).fetchone()
            if budget is None or tuple(budget) != (1, 1, 0, "EXHAUSTED"):
                raise ValueError("product problem budget changed before apply")
            state._connection.execute(
                """UPDATE failures
                      SET failure_class='controller',
                          reason_code='controller_plan_compilation_invariant',
                          status='RESOLVED', last_seen_at=?
                    WHERE failure_id=? AND product_id=? AND status='OPEN'""",
                (now, failure_id, product_id),
            )
            state._connection.execute(
                """UPDATE hypotheses SET status='RESOLVED',
                          closed_at=COALESCE(closed_at, ?)
                    WHERE failure_id=? AND status='ACTIVE'""",
                (now, failure_id),
            )
            state._connection.execute(
                """UPDATE tasks
                      SET graph_status='SUPERSEDED', status='DONE',
                          lease_owner=NULL, lease_until=NULL,
                          lease_token=NULL, heartbeat_at=NULL,
                          available_at=NULL,
                          blocked_reason='controller_plan_compilation_invariant',
                          blocked_ref=?, updated_at=?
                    WHERE task_id=? AND product_id=?
                      AND graph_status='FAILED_SEMANTIC'
                      AND status='FAILED_SAFE'""",
                (
                    correction_evidence_digest,
                    now,
                    str(row["task_id"]),
                    product_id,
                ),
            )
            state._connection.execute(
                """UPDATE problem_budgets SET status='ACTIVE', updated_at=?
                    WHERE product_id=? AND root_problem_signature=?
                      AND deterministic_actions_used=1
                      AND arbiter_calls_used=1
                      AND execution_attempts_used=0
                      AND status='EXHAUSTED'""",
                (now, product_id, root_problem_signature),
            )
            state._connection.execute(
                """INSERT INTO tasks
                   (task_id, product_id, title, role, output_schema,
                    contract_ref, priority, status, dependencies_json,
                    conflict_keys_json, created_at, updated_at, stage_key,
                    cycle, root_task_id, parent_task_id, source_task_id,
                    plan_id, plan_node_id, task_revision, root_context_ref,
                    active_context_ref, capability_profile, idempotency_key,
                    graph_status, required_capabilities_json, mandatory,
                    failure_id, critical_path_rank, root_problem_signature)
                   VALUES (?, ?, ?, 'replanner',
                           'plan-proposal-v1.schema.json', ?, 1000,
                           'PENDING', ?, ?, ?, ?,
                           'semantic-lifecycle-recovery', 0, ?, ?, ?, ?,
                           ?, ?, ?, ?, 'planning_readonly', ?, 'READY',
                           ?, 1, ?, 0, ?)""",
                (
                    str(contract["task_id"]),
                    product_id,
                    str(contract["title"]),
                    str(contract["active_context_ref"]),
                    stable_json(contract["dependencies"]),
                    stable_json(contract["conflict_keys"]),
                    now,
                    now,
                    str(contract["root_task_id"]),
                    str(contract["parent_task_id"]),
                    str(contract["source_task_id"]),
                    str(contract["plan_id"]),
                    str(contract["plan_node_id"]),
                    int(contract["task_revision"]),
                    str(contract["root_context_ref"]),
                    str(contract["active_context_ref"]),
                    str(contract["idempotency_key"]),
                    stable_json(contract["required_capabilities"]),
                    failure_id,
                    root_problem_signature,
                ),
            )
            for dependency_id in contract["dependencies"]:
                state._connection.execute(
                    """INSERT INTO task_edges
                       (plan_id, from_task_id, to_task_id, edge_type,
                        required, created_at)
                       VALUES (?, ?, ?, 'depends_on', 1, ?)""",
                    (
                        str(contract["plan_id"]),
                        str(dependency_id),
                        str(contract["task_id"]),
                        now,
                    ),
                )
            from .proof_obligations import RecoveryCertificateService

            RecoveryCertificateService(state._connection).apply_ready(
                product_id=product_id,
                resume_status="IMPLEMENTING",
            )
            incident_id = (
                "incident-" + sha256_text(f"{failure_id}:plan-compilation")[:20]
            )
            state._connection.execute(
                """INSERT OR IGNORE INTO controller_incidents
                   (incident_id, product_id, task_id, reason_code,
                    evidence_ref, status, created_at, resolved_at)
                   VALUES (?, ?, ?, 'controller_plan_compilation_invariant',
                           ?, 'RESOLVED', ?, ?)""",
                (
                    incident_id,
                    product_id,
                    str(row["task_id"]),
                    f"internal://release/{correction_evidence_digest}",
                    now,
                    now,
                ),
            )
            state._connection.execute(
                """INSERT INTO recovery_applications
                   (recovery_plan_digest, product_id, recovery_task_id,
                    status, applied_at)
                   VALUES (?, ?, ?, 'APPLIED', ?)""",
                (correction_digest, product_id, str(contract["task_id"]), now),
            )
            state._record_event(
                product_id,
                str(contract["task_id"]),
                "controller_plan_compilation_recovery_applied",
                {
                    "failure_id": failure_id,
                    "root_problem_signature": root_problem_signature,
                    "correction_digest": correction_digest,
                    "correction_evidence_digest": correction_evidence_digest,
                    "product_budget_counters_preserved": True,
                },
            )
            state._connection.commit()
        except Exception:
            state._connection.rollback()
            raise
    return {
        "status": "PASS",
        "application_status": "APPLIED",
        "product_id": product_id,
        "recovery_task_id": str(contract["task_id"]),
        "root_problem_signature": root_problem_signature,
        "correction_digest": correction_digest,
        "product_budget_counters": {
            "deterministic_actions_used": 1,
            "arbiter_calls_used": 1,
            "execution_attempts_used": 0,
            "status": "ACTIVE",
        },
    }


def resume_zero_dependency_audit_failure(
    config: FactoryConfig,
    state: StateStore,
    *,
    product_id: str,
    failure_id: str,
    correction_evidence_digest: str,
) -> dict[str, Any]:
    """Requeue one reviewer stopped by the historical empty-inventory defect.

    The failed gate was controller-owned: an explicit, truthful zero-dependency
    project could never pass.  This operation changes that failure's ownership,
    preserves all product path counters, and reuses the same lifecycle task with
    a fresh repair brief so attempt prompt uniqueness remains intact.
    """

    if not state.maintenance_active():
        raise ValueError("zero-dependency audit recovery requires maintenance mode")
    if len(correction_evidence_digest) != 64 or any(
        character not in "0123456789abcdef"
        for character in correction_evidence_digest
    ):
        raise ValueError("controller correction evidence digest is invalid")
    correction_digest = sha256_text(
        stable_json(
            {
                "action": "controller_zero_dependency_audit_recovery",
                "product_id": product_id,
                "failure_id": failure_id,
                "correction_evidence_digest": correction_evidence_digest,
            }
        )
    )
    prior = _rows(
        state,
        """SELECT recovery_task_id FROM recovery_applications
            WHERE recovery_plan_digest=? AND product_id=?""",
        (correction_digest, product_id),
    )
    if prior:
        return {
            "status": "PASS",
            "application_status": "REPLAYED",
            "product_id": product_id,
            "recovery_task_id": str(prior[0]["recovery_task_id"]),
            "correction_digest": correction_digest,
        }

    rows = _rows(
        state,
        """SELECT failure.failure_class, failure.reason_code,
                  failure.safe_message, failure.evidence_ref,
                  failure.failed_gate_ids_json,
                  failure.status AS failure_status,
                  failure.owner_action_eligible,
                  task.*, product.status AS product_status,
                  product.terminal_reason AS product_terminal_reason
             FROM failures AS failure
             JOIN tasks AS task ON task.task_id=failure.task_id
             JOIN products AS product ON product.product_id=failure.product_id
            WHERE failure.failure_id=? AND failure.product_id=?""",
        (failure_id, product_id),
    )
    if len(rows) != 1:
        raise ValueError("zero-dependency audit failure coordinate is missing")
    row = rows[0]
    try:
        failed_gate_ids = json.loads(str(row["failed_gate_ids_json"] or "[]"))
    except json.JSONDecodeError as error:
        raise ValueError("zero-dependency failure gates are invalid") from error
    safe_message = str(row["safe_message"] or "")
    root_problem_signature = str(row["root_problem_signature"] or "")
    if (
        str(row["failure_class"]) != "semantic"
        or str(row["reason_code"]) != "mandatory_gate_failed"
        or str(row["failure_status"]) != "ROUTED"
        or int(row["owner_action_eligible"] or 0) != 0
        or str(row["role"]) != "security-reviewer"
        or str(row["capability_profile"] or "") != "reviewer_readonly"
        or str(row["graph_status"]) != "FAILED_SEMANTIC"
        or str(row["status"]) != "FAILED_SAFE"
        or str(row["product_status"]) != "FAILED_SAFE"
        or str(row["product_terminal_reason"] or "")
        != "path_governor_problem_budget_exhausted"
        or "runtime dependency inventory is empty" not in safe_message
        or failed_gate_ids != ["target-dependency-audit"]
        or len(root_problem_signature) != 64
        or any(
            character not in "0123456789abcdef"
            for character in root_problem_signature
        )
    ):
        raise ValueError("failure is not the bounded zero-dependency audit defect")
    budget_rows = _rows(
        state,
        """SELECT deterministic_actions_used, arbiter_calls_used,
                  execution_attempts_used, status
             FROM problem_budgets
            WHERE product_id=? AND root_problem_signature=?""",
        (product_id, root_problem_signature),
    )
    if len(budget_rows) != 1 or (
        int(budget_rows[0]["deterministic_actions_used"]),
        int(budget_rows[0]["arbiter_calls_used"]),
        int(budget_rows[0]["execution_attempts_used"]),
        str(budget_rows[0]["status"]),
    ) != (1, 1, 1, "EXHAUSTED"):
        raise ValueError("product problem budget changed before audit recovery")
    active_claims = _rows(
        state,
        """SELECT COUNT(*) AS count FROM tasks
            WHERE status='CLAIMED'
              AND (lease_until IS NULL OR lease_until >= ?)""",
        (utc_now(),),
    )
    if int(active_claims[0]["count"]):
        raise ValueError("zero-dependency audit recovery requires a drained controller")

    contract_name = Path(str(row.get("contract_ref") or "")).name
    contract_path = config.evidence_dir / contract_name
    if not contract_name or not contract_path.is_file():
        raise ValueError("failed reviewer contract is unavailable")
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    acceptance = contract.get("acceptance") if isinstance(contract, dict) else None
    allowed_paths = contract.get("allowed_paths") if isinstance(contract, dict) else None
    if not isinstance(acceptance, list) or not acceptance:
        raise ValueError("failed reviewer acceptance is unavailable")
    if not isinstance(allowed_paths, list) or not allowed_paths:
        raise ValueError("failed reviewer scope is unavailable")

    hypothesis_rows = _rows(
        state,
        """SELECT * FROM hypotheses
            WHERE product_id=? AND status='ACTIVE'
              AND (hypothesis_id=? OR failure_id=?)
            ORDER BY CASE WHEN hypothesis_id=? THEN 0 ELSE 1 END,
                     created_at DESC LIMIT 1""",
        (
            product_id,
            str(row.get("hypothesis_id") or ""),
            failure_id,
            str(row.get("hypothesis_id") or ""),
        ),
    )
    hypothesis = hypothesis_rows[0] if hypothesis_rows else None
    hypothesis_id = (
        str(hypothesis["hypothesis_id"])
        if hypothesis is not None
        else "hypothesis-" + sha256_text(f"{correction_digest}:reverify")[:20]
    )
    parent_hypothesis_id = (
        str(hypothesis["parent_hypothesis_id"])
        if hypothesis is not None and hypothesis.get("parent_hypothesis_id")
        else None
    )
    task_id = str(row["task_id"])
    repair_brief = {
        "schema_version": "2.0",
        "artifact_id": "repair-brief-" + sha256_text(correction_digest)[:20],
        "product_id": product_id,
        "task_id": task_id,
        "root_task_id": str(row["root_task_id"]),
        "failed_task_id": task_id,
        "failure_id": failure_id,
        "hypothesis_id": hypothesis_id,
        "parent_hypothesis_id": parent_hypothesis_id,
        "plan_id": str(row["plan_id"]),
        "plan_node_id": str(row["plan_node_id"]),
        "inherited_goal_ref": str(row["root_context_ref"]),
        "inherited_acceptance": [dict(item) for item in acceptance if isinstance(item, dict)],
        "failed_gate_ids": ["target-dependency-audit"],
        "required_fixes": [
            "Re-run target-dependency-audit with explicit zero-dependency attestation support.",
            "Require project.dependencies=[] and reject undeclared third-party runtime imports.",
            safe_message,
        ],
        "evidence_refs": [
            str(row["evidence_ref"]),
            f"internal://release/{correction_evidence_digest}",
        ],
        "allowed_paths": [str(value) for value in allowed_paths],
        "capability_gaps": [],
        "supersedes_task_id": (
            str(row["supersedes_task_id"])
            if row.get("supersedes_task_id")
            else None
        ),
        "definition_of_done": [
            str(item["verification"])
            for item in acceptance
            if isinstance(item, dict) and item.get("verification")
        ],
    }
    repair_path = ArtifactStore(config).write(
        "repair-brief-v2.schema.json",
        repair_brief,
        filename=f"repair-brief-{task_id}-{correction_digest[:12]}.json",
    )
    repair_ref = f"evidence/{repair_path.name}"
    now = utc_now()
    with state._lock:
        state._connection.execute("BEGIN IMMEDIATE")
        try:
            prior_row = state._connection.execute(
                """SELECT recovery_task_id FROM recovery_applications
                    WHERE recovery_plan_digest=? AND product_id=?""",
                (correction_digest, product_id),
            ).fetchone()
            if prior_row is not None:
                state._connection.commit()
                return {
                    "status": "PASS",
                    "application_status": "REPLAYED",
                    "product_id": product_id,
                    "recovery_task_id": str(prior_row[0]),
                    "correction_digest": correction_digest,
                }
            current = state._connection.execute(
                """SELECT failure.status, failure.failure_class,
                          failure.reason_code, task.graph_status, task.status,
                          product.status, product.terminal_reason
                     FROM failures AS failure
                     JOIN tasks AS task ON task.task_id=failure.task_id
                     JOIN products AS product
                       ON product.product_id=failure.product_id
                    WHERE failure.failure_id=? AND failure.product_id=?""",
                (failure_id, product_id),
            ).fetchone()
            if current is None or tuple(current) != (
                "ROUTED",
                "semantic",
                "mandatory_gate_failed",
                "FAILED_SEMANTIC",
                "FAILED_SAFE",
                "FAILED_SAFE",
                "path_governor_problem_budget_exhausted",
            ):
                raise ValueError("zero-dependency audit state changed before apply")
            budget = state._connection.execute(
                """SELECT deterministic_actions_used, arbiter_calls_used,
                          execution_attempts_used, status
                     FROM problem_budgets
                    WHERE product_id=? AND root_problem_signature=?""",
                (product_id, root_problem_signature),
            ).fetchone()
            if budget is None or tuple(budget) != (1, 1, 1, "EXHAUSTED"):
                raise ValueError("product problem budget changed before apply")
            if hypothesis is None:
                state._connection.execute(
                    """INSERT INTO hypotheses
                       (hypothesis_id, product_id, failure_id, signature,
                        statement, required_evidence_json, status,
                        semantic_budget, attempts_used, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', 1, 0, ?)""",
                    (
                        hypothesis_id,
                        product_id,
                        failure_id,
                        sha256_text(f"{correction_digest}:zero-dependency-reverify"),
                        "Reverify the reviewer after the controller audit adapter correction.",
                        stable_json([repair_ref]),
                        now,
                    ),
                )
            state._connection.execute(
                """UPDATE failures
                      SET failure_class='controller',
                          reason_code='controller_zero_dependency_audit_invariant',
                          status='RESOLVED', last_seen_at=?
                    WHERE failure_id=? AND product_id=? AND status='ROUTED'""",
                (now, failure_id, product_id),
            )
            state._connection.execute(
                """UPDATE problem_budgets SET status='ACTIVE', updated_at=?
                    WHERE product_id=? AND root_problem_signature=?
                      AND deterministic_actions_used=1
                      AND arbiter_calls_used=1
                      AND execution_attempts_used=1
                      AND status='EXHAUSTED'""",
                (now, product_id, root_problem_signature),
            )
            state._connection.execute(
                """UPDATE tasks
                      SET status='PENDING', graph_status='READY',
                          lease_owner=NULL, lease_until=NULL,
                          lease_token=NULL, heartbeat_at=NULL,
                          available_at=NULL, next_tier='terra',
                          next_attempt_kind='repair', repair_context_ref=?,
                          terminal_reason=NULL, terminal_detail=NULL,
                          result_ref=NULL, result_digest=NULL,
                          failure_kind=NULL, blocked_reason=NULL,
                          blocked_ref=NULL, hypothesis_id=?, updated_at=?
                    WHERE task_id=? AND product_id=?
                      AND graph_status='FAILED_SEMANTIC'
                      AND status='FAILED_SAFE'""",
                (repair_ref, hypothesis_id, now, task_id, product_id),
            )
            from .proof_obligations import RecoveryCertificateService

            RecoveryCertificateService(state._connection).apply_ready(
                product_id=product_id,
                resume_status="IMPLEMENTING",
            )
            incident_id = "incident-" + sha256_text(f"{failure_id}:zero-dependency")[:20]
            state._connection.execute(
                """INSERT OR IGNORE INTO controller_incidents
                   (incident_id, product_id, task_id, reason_code,
                    evidence_ref, status, created_at, resolved_at)
                   VALUES (?, ?, ?, 'controller_zero_dependency_audit_invariant',
                           ?, 'RESOLVED', ?, ?)""",
                (
                    incident_id,
                    product_id,
                    task_id,
                    f"internal://release/{correction_evidence_digest}",
                    now,
                    now,
                ),
            )
            state._connection.execute(
                """INSERT INTO recovery_applications
                   (recovery_plan_digest, product_id, recovery_task_id,
                    status, applied_at)
                   VALUES (?, ?, ?, 'APPLIED', ?)""",
                (correction_digest, product_id, task_id, now),
            )
            state._record_event(
                product_id,
                task_id,
                "controller_zero_dependency_audit_recovery_applied",
                {
                    "failure_id": failure_id,
                    "root_problem_signature": root_problem_signature,
                    "correction_digest": correction_digest,
                    "correction_evidence_digest": correction_evidence_digest,
                    "repair_context_ref": repair_ref,
                    "product_budget_counters_preserved": True,
                },
            )
            state._connection.commit()
        except Exception:
            state._connection.rollback()
            raise
    return {
        "status": "PASS",
        "application_status": "APPLIED",
        "product_id": product_id,
        "recovery_task_id": task_id,
        "root_problem_signature": root_problem_signature,
        "correction_digest": correction_digest,
        "repair_context_ref": repair_ref,
        "product_budget_counters": {
            "deterministic_actions_used": 1,
            "arbiter_calls_used": 1,
            "execution_attempts_used": 1,
            "status": "ACTIVE",
        },
    }


def resume_reviewer_builder_route_failure(
    config: FactoryConfig,
    state: StateStore,
    *,
    product_id: str,
    failure_id: str,
    correction_evidence_digest: str,
) -> dict[str, Any]:
    """Recover a reviewer finding misrouted to an already-used Path Arbiter.

    The reviewer finding remains product-semantic.  Only the controller routing
    decision is corrected: the existing budget is reopened without changing its
    counters, then the normal Failure Router consumes the second Builder slot.
    """

    if not state.maintenance_active():
        raise ValueError("reviewer Builder-route recovery requires maintenance mode")
    if len(correction_evidence_digest) != 64 or any(
        character not in "0123456789abcdef"
        for character in correction_evidence_digest
    ):
        raise ValueError("controller correction evidence digest is invalid")
    correction_digest = sha256_text(
        stable_json(
            {
                "action": "controller_reviewer_builder_route_recovery",
                "product_id": product_id,
                "failure_id": failure_id,
                "correction_evidence_digest": correction_evidence_digest,
            }
        )
    )
    prior = _rows(
        state,
        """SELECT recovery_task_id FROM recovery_applications
            WHERE recovery_plan_digest=? AND product_id=?""",
        (correction_digest, product_id),
    )
    if prior:
        return {
            "status": "PASS",
            "application_status": "REPLAYED",
            "product_id": product_id,
            "recovery_task_id": str(prior[0]["recovery_task_id"]),
            "correction_digest": correction_digest,
        }

    rows = _rows(
        state,
        """SELECT failure.failure_class, failure.reason_code,
                  failure.safe_message, failure.failed_gate_ids_json,
                  failure.status AS failure_status,
                  failure.owner_action_eligible,
                  task.task_id, task.role, task.capability_profile,
                  task.graph_status, task.status AS task_status,
                  task.root_problem_signature,
                  product.status AS product_status, product.terminal_reason
             FROM failures AS failure
             JOIN tasks AS task ON task.task_id=failure.task_id
             JOIN products AS product ON product.product_id=failure.product_id
            WHERE failure.failure_id=? AND failure.product_id=?""",
        (failure_id, product_id),
    )
    if len(rows) != 1:
        raise ValueError("reviewer route failure coordinate is missing")
    row = rows[0]
    try:
        failed_gate_ids = json.loads(str(row["failed_gate_ids_json"] or "[]"))
    except json.JSONDecodeError as error:
        raise ValueError("reviewer route failure gates are invalid") from error
    safe_message = str(row["safe_message"] or "")
    root_problem_signature = str(row["root_problem_signature"] or "")
    if (
        str(row["failure_class"]) not in {"semantic", "policy"}
        or str(row["reason_code"]) != "model_requested_repair"
        or str(row["failure_status"]) != "ROUTED"
        or int(row["owner_action_eligible"] or 0) != 0
        or str(row["role"]) != "security-reviewer"
        or str(row["capability_profile"] or "") != "reviewer_readonly"
        or str(row["graph_status"]) != "FAILED_SEMANTIC"
        or str(row["task_status"]) != "FAILED_SAFE"
        or str(row["product_status"]) != "FAILED_SAFE"
        or str(row["terminal_reason"] or "")
        != "path_governor_problem_budget_exhausted"
        or failed_gate_ids != ["SECURITY-CONTAINER-SCAN-NOT-RUN"]
        or "SECURITY-CONTAINER-SCAN-NOT-RUN" not in safe_message
        or "immutable image" not in safe_message.lower()
        or len(root_problem_signature) != 64
        or any(
            character not in "0123456789abcdef"
            for character in root_problem_signature
        )
    ):
        raise ValueError("failure is not the bounded reviewer route defect")
    budget_rows = _rows(
        state,
        """SELECT deterministic_actions_used, arbiter_calls_used,
                  execution_attempts_used, status
             FROM problem_budgets
            WHERE product_id=? AND root_problem_signature=?""",
        (product_id, root_problem_signature),
    )
    if len(budget_rows) != 1 or (
        int(budget_rows[0]["deterministic_actions_used"]),
        int(budget_rows[0]["arbiter_calls_used"]),
        int(budget_rows[0]["execution_attempts_used"]),
        str(budget_rows[0]["status"]),
    ) != (1, 1, 1, "EXHAUSTED"):
        raise ValueError("product problem budget changed before route recovery")
    active_claims = _rows(
        state,
        """SELECT COUNT(*) AS count FROM tasks
            WHERE status='CLAIMED'
              AND (lease_until IS NULL OR lease_until >= ?)""",
        (utc_now(),),
    )
    if int(active_claims[0]["count"]):
        raise ValueError("reviewer Builder-route recovery requires a drained controller")

    now = utc_now()
    with state._lock:
        state._connection.execute("BEGIN IMMEDIATE")
        try:
            prior_row = state._connection.execute(
                """SELECT recovery_task_id FROM recovery_applications
                    WHERE recovery_plan_digest=? AND product_id=?""",
                (correction_digest, product_id),
            ).fetchone()
            if prior_row is not None:
                state._connection.commit()
                return {
                    "status": "PASS",
                    "application_status": "REPLAYED",
                    "product_id": product_id,
                    "recovery_task_id": str(prior_row[0]),
                    "correction_digest": correction_digest,
                }
            current = state._connection.execute(
                """SELECT failure.status, failure.failure_class,
                          failure.reason_code, task.graph_status, task.status,
                          product.status, product.terminal_reason
                     FROM failures AS failure
                     JOIN tasks AS task ON task.task_id=failure.task_id
                     JOIN products AS product
                       ON product.product_id=failure.product_id
                    WHERE failure.failure_id=? AND failure.product_id=?""",
                (failure_id, product_id),
            ).fetchone()
            if current is None or tuple(current) != (
                "ROUTED",
                str(row["failure_class"]),
                "model_requested_repair",
                "FAILED_SEMANTIC",
                "FAILED_SAFE",
                "FAILED_SAFE",
                "path_governor_problem_budget_exhausted",
            ):
                raise ValueError("reviewer route state changed before apply")
            budget = state._connection.execute(
                """SELECT deterministic_actions_used, arbiter_calls_used,
                          execution_attempts_used, status
                     FROM problem_budgets
                    WHERE product_id=? AND root_problem_signature=?""",
                (product_id, root_problem_signature),
            ).fetchone()
            if budget is None or tuple(budget) != (1, 1, 1, "EXHAUSTED"):
                raise ValueError("product problem budget changed before apply")
            state._connection.execute(
                """UPDATE failures SET status='OPEN', last_seen_at=?
                    WHERE failure_id=? AND product_id=? AND status='ROUTED'""",
                (now, failure_id, product_id),
            )
            state._connection.execute(
                """UPDATE problem_budgets SET status='ACTIVE', updated_at=?
                    WHERE product_id=? AND root_problem_signature=?
                      AND deterministic_actions_used=1
                      AND arbiter_calls_used=1
                      AND execution_attempts_used=1
                      AND status='EXHAUSTED'""",
                (now, product_id, root_problem_signature),
            )
            from .proof_obligations import RecoveryCertificateService

            RecoveryCertificateService(state._connection).apply_ready(
                product_id=product_id,
                resume_status="IMPLEMENTING",
            )
            state._record_event(
                product_id,
                str(row["task_id"]),
                "controller_reviewer_builder_route_reopened",
                {
                    "failure_id": failure_id,
                    "root_problem_signature": root_problem_signature,
                    "correction_digest": correction_digest,
                    "product_budget_counters_preserved": True,
                },
            )
            state._connection.commit()
        except Exception:
            state._connection.rollback()
            raise

    from .failure_router import FailureRouter

    routed_task_id = FailureRouter(config, state, ArtifactStore(config)).route(failure_id)
    routed = state.get_task(routed_task_id)
    if (
        routed is None
        or str(routed.get("role") or "") != "builder"
        or str(routed.get("output_schema") or "") != "attempt-result.schema.json"
        or str(routed.get("capability_profile") or "") != "builder_workspace"
        or str(routed.get("stage_key") or "") != "repair"
        or str(routed.get("root_problem_signature") or "") != root_problem_signature
        or not routed.get("repair_context_ref")
    ):
        raise RuntimeError("reviewer route recovery did not create a bounded Builder")
    post_budget = _rows(
        state,
        """SELECT deterministic_actions_used, arbiter_calls_used,
                  execution_attempts_used, status
             FROM problem_budgets
            WHERE product_id=? AND root_problem_signature=?""",
        (product_id, root_problem_signature),
    )
    if len(post_budget) != 1 or (
        int(post_budget[0]["deterministic_actions_used"]),
        int(post_budget[0]["arbiter_calls_used"]),
        int(post_budget[0]["execution_attempts_used"]),
        str(post_budget[0]["status"]),
    ) != (1, 1, 2, "ACTIVE"):
        raise RuntimeError("reviewer route recovery did not consume the remaining slot")

    now = utc_now()
    with state._lock, state._connection:
        failure_status = state._connection.execute(
            "SELECT status FROM failures WHERE failure_id=? AND product_id=?",
            (failure_id, product_id),
        ).fetchone()
        product_status = state._connection.execute(
            "SELECT status,terminal_reason FROM products WHERE product_id=?",
            (product_id,),
        ).fetchone()
        if (
            failure_status is None
            or str(failure_status[0]) != "ROUTED"
            or product_status is None
            or tuple(product_status) != ("IMPLEMENTING", None)
        ):
            raise RuntimeError("reviewer route recovery postcondition failed")
        incident_id = "incident-" + sha256_text(f"{failure_id}:reviewer-route")[:20]
        state._connection.execute(
            """INSERT OR IGNORE INTO controller_incidents
               (incident_id, product_id, task_id, reason_code,
                evidence_ref, status, created_at, resolved_at)
               VALUES (?, ?, ?, 'controller_reviewer_builder_route_invariant',
                       ?, 'RESOLVED', ?, ?)""",
            (
                incident_id,
                product_id,
                str(row["task_id"]),
                f"internal://release/{correction_evidence_digest}",
                now,
                now,
            ),
        )
        state._connection.execute(
            """INSERT INTO recovery_applications
               (recovery_plan_digest, product_id, recovery_task_id,
                status, applied_at)
               VALUES (?, ?, ?, 'APPLIED', ?)""",
            (correction_digest, product_id, routed_task_id, now),
        )
        state._record_event(
            product_id,
            routed_task_id,
            "controller_reviewer_builder_route_recovery_applied",
            {
                "failure_id": failure_id,
                "root_problem_signature": root_problem_signature,
                "correction_digest": correction_digest,
                "correction_evidence_digest": correction_evidence_digest,
                "product_budget_counters_preserved_before_route": True,
            },
        )
    return {
        "status": "PASS",
        "application_status": "APPLIED",
        "product_id": product_id,
        "recovery_task_id": routed_task_id,
        "root_problem_signature": root_problem_signature,
        "correction_digest": correction_digest,
        "product_budget_counters": {
            "deterministic_actions_used": 1,
            "arbiter_calls_used": 1,
            "execution_attempts_used": 2,
            "status": "ACTIVE",
        },
    }


def resume_opaque_subject_reference_failure(
    state: StateStore,
    *,
    product_id: str,
    failure_id: str,
    correction_evidence_digest: str,
) -> dict[str, Any]:
    """Resume one Builder after an optional subject-file probe crashed.

    This is a controller-only correction.  It restores the same repair task to
    its parent semantic finding and preserves every Path Governor counter so an
    interrupted immutable attempt can be resumed instead of spending a new
    execution slot.
    """

    if not state.maintenance_active():
        raise ValueError("opaque subject-reference recovery requires maintenance mode")
    if len(correction_evidence_digest) != 64 or any(
        character not in "0123456789abcdef"
        for character in correction_evidence_digest
    ):
        raise ValueError("controller correction evidence digest is invalid")
    correction_digest = sha256_text(
        stable_json(
            {
                "action": "controller_opaque_subject_reference_recovery",
                "product_id": product_id,
                "failure_id": failure_id,
                "correction_evidence_digest": correction_evidence_digest,
            }
        )
    )
    prior = _rows(
        state,
        """SELECT recovery_task_id FROM recovery_applications
            WHERE recovery_plan_digest=? AND product_id=?""",
        (correction_digest, product_id),
    )
    if prior:
        return {
            "status": "PASS",
            "application_status": "REPLAYED",
            "product_id": product_id,
            "recovery_task_id": str(prior[0]["recovery_task_id"]),
            "correction_digest": correction_digest,
        }

    rows = _rows(
        state,
        """SELECT failure.failure_class, failure.reason_code,
                  failure.safe_message, failure.exception_type,
                  failure.stack_fingerprint, failure.actual_json,
                  failure.status AS failure_status,
                  failure.parent_failure_id,
                  parent.failure_class AS parent_failure_class,
                  parent.status AS parent_failure_status,
                  task.task_id, task.role, task.capability_profile,
                  task.stage_key, task.graph_status,
                  task.status AS task_status, task.repair_context_ref,
                  task.root_problem_signature,
                  product.status AS product_status
             FROM failures AS failure
             JOIN failures AS parent
               ON parent.failure_id=failure.parent_failure_id
              AND parent.product_id=failure.product_id
             JOIN tasks AS task ON task.task_id=failure.task_id
             JOIN products AS product
               ON product.product_id=failure.product_id
            WHERE failure.failure_id=? AND failure.product_id=?""",
        (failure_id, product_id),
    )
    if len(rows) != 1:
        raise ValueError("opaque subject-reference failure coordinate is missing")
    row = rows[0]
    try:
        diagnostic = json.loads(str(row["actual_json"] or "{}"))
    except json.JSONDecodeError as error:
        raise ValueError("controller failure diagnostic is invalid") from error
    traceback_excerpt = (
        str(diagnostic.get("traceback_excerpt") or "")
        if isinstance(diagnostic, dict)
        else ""
    )
    root_problem_signature = str(row["root_problem_signature"] or "")
    parent_failure_id = str(row["parent_failure_id"] or "")
    if (
        str(row["failure_class"]) != "controller"
        or str(row["reason_code"]) != "controller_exception_permission_error"
        or str(row["failure_status"]) != "OPEN"
        or str(row["exception_type"]) != "PermissionError"
        or not str(row["stack_fingerprint"] or "")
        or not str(row["safe_message"] or "").endswith("/SHA256SUMS'")
        or "default_spec" not in traceback_excerpt
        or "subject_file.is_file()" not in traceback_excerpt
        or str(row["parent_failure_class"]) not in {"semantic", "policy"}
        or str(row["parent_failure_status"]) != "ROUTED"
        or not parent_failure_id
        or str(row["role"]) != "builder"
        or str(row["capability_profile"] or "") != "builder_workspace"
        or str(row["stage_key"] or "") != "repair"
        or str(row["graph_status"]) != "FAILED_SEMANTIC"
        or str(row["task_status"]) != "FAILED_SAFE"
        or str(row["product_status"]) != "IMPLEMENTING"
        or len(root_problem_signature) != 64
        or any(
            character not in "0123456789abcdef"
            for character in root_problem_signature
        )
    ):
        raise ValueError("failure is not the bounded subject-reference defect")
    budget_rows = _rows(
        state,
        """SELECT deterministic_actions_used, arbiter_calls_used,
                  execution_attempts_used, status
             FROM problem_budgets
            WHERE product_id=? AND root_problem_signature=?""",
        (product_id, root_problem_signature),
    )
    if len(budget_rows) != 1 or (
        int(budget_rows[0]["deterministic_actions_used"]),
        int(budget_rows[0]["arbiter_calls_used"]),
        int(budget_rows[0]["execution_attempts_used"]),
        str(budget_rows[0]["status"]),
    ) != (1, 1, 2, "ACTIVE"):
        raise ValueError("product problem budget changed before subject recovery")
    active_claims = _rows(
        state,
        """SELECT COUNT(*) AS count FROM tasks
            WHERE status='CLAIMED'
              AND (lease_until IS NULL OR lease_until >= ?)""",
        (utc_now(),),
    )
    if int(active_claims[0]["count"]):
        raise ValueError("subject-reference recovery requires a drained controller")

    now = utc_now()
    with state._lock:
        state._connection.execute("BEGIN IMMEDIATE")
        try:
            prior_row = state._connection.execute(
                """SELECT recovery_task_id FROM recovery_applications
                    WHERE recovery_plan_digest=? AND product_id=?""",
                (correction_digest, product_id),
            ).fetchone()
            if prior_row is not None:
                state._connection.commit()
                return {
                    "status": "PASS",
                    "application_status": "REPLAYED",
                    "product_id": product_id,
                    "recovery_task_id": str(prior_row[0]),
                    "correction_digest": correction_digest,
                }
            current = state._connection.execute(
                """SELECT failure.status, task.graph_status, task.status,
                          task.failure_id, product.status
                     FROM failures AS failure
                     JOIN tasks AS task ON task.task_id=failure.task_id
                     JOIN products AS product
                       ON product.product_id=failure.product_id
                    WHERE failure.failure_id=? AND failure.product_id=?""",
                (failure_id, product_id),
            ).fetchone()
            if current is None or tuple(current) != (
                "OPEN",
                "FAILED_SEMANTIC",
                "FAILED_SAFE",
                failure_id,
                "IMPLEMENTING",
            ):
                raise ValueError("subject-reference state changed before apply")
            budget = state._connection.execute(
                """SELECT deterministic_actions_used, arbiter_calls_used,
                          execution_attempts_used, status
                     FROM problem_budgets
                    WHERE product_id=? AND root_problem_signature=?""",
                (product_id, root_problem_signature),
            ).fetchone()
            if budget is None or tuple(budget) != (1, 1, 2, "ACTIVE"):
                raise ValueError("product problem budget changed before apply")
            state._connection.execute(
                """UPDATE failures SET status='RESOLVED', last_seen_at=?
                    WHERE failure_id=? AND product_id=? AND status='OPEN'""",
                (now, failure_id, product_id),
            )
            state._connection.execute(
                """UPDATE tasks
                      SET status='PENDING', graph_status='READY',
                          failure_id=?, lease_owner=NULL, lease_until=NULL,
                          lease_token=NULL, heartbeat_at=NULL,
                          available_at=NULL, terminal_reason=NULL,
                          terminal_detail=NULL, result_ref=NULL,
                          result_digest=NULL, failure_kind=NULL,
                          blocked_reason=NULL, blocked_ref=NULL, updated_at=?
                    WHERE task_id=? AND product_id=?
                      AND graph_status='FAILED_SEMANTIC'
                      AND status='FAILED_SAFE'""",
                (parent_failure_id, now, str(row["task_id"]), product_id),
            )
            incident_id = "incident-" + sha256_text(
                f"{failure_id}:opaque-subject-reference"
            )[:20]
            state._connection.execute(
                """INSERT OR IGNORE INTO controller_incidents
                   (incident_id, product_id, task_id, reason_code,
                    evidence_ref, status, created_at, resolved_at)
                   VALUES (?, ?, ?, 'controller_opaque_subject_reference_invariant',
                           ?, 'RESOLVED', ?, ?)""",
                (
                    incident_id,
                    product_id,
                    str(row["task_id"]),
                    f"internal://release/{correction_evidence_digest}",
                    now,
                    now,
                ),
            )
            state._connection.execute(
                """INSERT INTO recovery_applications
                   (recovery_plan_digest, product_id, recovery_task_id,
                    status, applied_at)
                   VALUES (?, ?, ?, 'APPLIED', ?)""",
                (
                    correction_digest,
                    product_id,
                    str(row["task_id"]),
                    now,
                ),
            )
            state._record_event(
                product_id,
                str(row["task_id"]),
                "controller_opaque_subject_reference_recovery_applied",
                {
                    "failure_id": failure_id,
                    "parent_failure_id": parent_failure_id,
                    "root_problem_signature": root_problem_signature,
                    "correction_digest": correction_digest,
                    "correction_evidence_digest": correction_evidence_digest,
                    "product_budget_counters_preserved": True,
                },
            )
            state._connection.commit()
        except Exception:
            state._connection.rollback()
            raise
    return {
        "status": "PASS",
        "application_status": "APPLIED",
        "product_id": product_id,
        "recovery_task_id": str(row["task_id"]),
        "root_problem_signature": root_problem_signature,
        "correction_digest": correction_digest,
        "parent_failure_id": parent_failure_id,
        "product_budget_counters": {
            "deterministic_actions_used": 1,
            "arbiter_calls_used": 1,
            "execution_attempts_used": 2,
            "status": "ACTIVE",
        },
    }


def resume_canonical_builder_schema_failure(
    config: FactoryConfig,
    state: StateStore,
    *,
    product_id: str,
    failure_id: str,
    correction_evidence_digest: str,
) -> dict[str, Any]:
    """Correct one controller-routed Builder to its canonical output schema."""

    if not state.maintenance_active():
        raise ValueError("canonical Builder-schema recovery requires maintenance mode")
    if len(correction_evidence_digest) != 64 or any(
        character not in "0123456789abcdef"
        for character in correction_evidence_digest
    ):
        raise ValueError("controller correction evidence digest is invalid")
    correction_digest = sha256_text(
        stable_json(
            {
                "action": "controller_canonical_builder_schema_recovery",
                "product_id": product_id,
                "failure_id": failure_id,
                "correction_evidence_digest": correction_evidence_digest,
            }
        )
    )
    prior = _rows(
        state,
        """SELECT recovery_task_id FROM recovery_applications
            WHERE recovery_plan_digest=? AND product_id=?""",
        (correction_digest, product_id),
    )
    if prior:
        return {
            "status": "PASS",
            "application_status": "REPLAYED",
            "product_id": product_id,
            "recovery_task_id": str(prior[0]["recovery_task_id"]),
            "correction_digest": correction_digest,
        }

    rows = _rows(
        state,
        """SELECT failure.failure_class, failure.reason_code,
                  failure.safe_message, failure.exception_type,
                  failure.stack_fingerprint, failure.actual_json,
                  failure.status AS failure_status,
                  failure.parent_failure_id,
                  parent.failure_class AS parent_failure_class,
                  parent.status AS parent_failure_status,
                  task.task_id, task.role, task.output_schema,
                  task.capability_profile, task.stage_key,
                  task.graph_status, task.status AS task_status,
                  task.contract_ref, task.semantic_node_id,
                  task.result_binding_id, task.root_problem_signature,
                  product.status AS product_status
             FROM failures AS failure
             JOIN failures AS parent
               ON parent.failure_id=failure.parent_failure_id
              AND parent.product_id=failure.product_id
             JOIN tasks AS task ON task.task_id=failure.task_id
             JOIN products AS product
               ON product.product_id=failure.product_id
            WHERE failure.failure_id=? AND failure.product_id=?""",
        (failure_id, product_id),
    )
    if len(rows) != 1:
        raise ValueError("canonical Builder-schema failure coordinate is missing")
    row = rows[0]
    try:
        diagnostic = json.loads(str(row["actual_json"] or "{}"))
    except json.JSONDecodeError as error:
        raise ValueError("controller failure diagnostic is invalid") from error
    traceback_excerpt = (
        str(diagnostic.get("traceback_excerpt") or "")
        if isinstance(diagnostic, dict)
        else ""
    )
    root_problem_signature = str(row["root_problem_signature"] or "")
    parent_failure_id = str(row["parent_failure_id"] or "")
    invalid_schema = "implementation-result.schema.json"
    canonical_schema = "attempt-result.schema.json"
    if (
        str(row["failure_class"]) != "controller"
        or str(row["reason_code"]) != "controller_exception_file_not_found_error"
        or str(row["failure_status"]) != "OPEN"
        or str(row["exception_type"]) != "FileNotFoundError"
        or not str(row["stack_fingerprint"] or "")
        or not str(row["safe_message"] or "").endswith(f"/schemas/{invalid_schema}")
        or "PromptCompiler" not in traceback_excerpt
        or invalid_schema not in traceback_excerpt
        or str(row["parent_failure_class"]) not in {"semantic", "policy"}
        or str(row["parent_failure_status"]) != "ROUTED"
        or not parent_failure_id
        or str(row["role"]) != "builder"
        or str(row["output_schema"]) != invalid_schema
        or str(row["capability_profile"] or "") != "builder_workspace"
        or str(row["stage_key"] or "") != "repair"
        or str(row["graph_status"]) != "FAILED_SEMANTIC"
        or str(row["task_status"]) != "FAILED_SAFE"
        or row["semantic_node_id"] is not None
        or row["result_binding_id"] is not None
        or str(row["product_status"]) != "IMPLEMENTING"
        or len(root_problem_signature) != 64
        or any(
            character not in "0123456789abcdef"
            for character in root_problem_signature
        )
        or not (config.schema_root() / canonical_schema).is_file()
    ):
        raise ValueError("failure is not the bounded canonical Builder-schema defect")
    budget_rows = _rows(
        state,
        """SELECT deterministic_actions_used, arbiter_calls_used,
                  execution_attempts_used, status
             FROM problem_budgets
            WHERE product_id=? AND root_problem_signature=?""",
        (product_id, root_problem_signature),
    )
    if len(budget_rows) != 1 or (
        int(budget_rows[0]["deterministic_actions_used"]),
        int(budget_rows[0]["arbiter_calls_used"]),
        int(budget_rows[0]["execution_attempts_used"]),
        str(budget_rows[0]["status"]),
    ) != (1, 1, 2, "ACTIVE"):
        raise ValueError("product problem budget changed before schema recovery")
    active_claims = _rows(
        state,
        """SELECT COUNT(*) AS count FROM tasks
            WHERE status='CLAIMED'
              AND (lease_until IS NULL OR lease_until >= ?)""",
        (utc_now(),),
    )
    if int(active_claims[0]["count"]):
        raise ValueError("canonical Builder-schema recovery requires a drained controller")

    contract_ref = str(row["contract_ref"] or "")
    contract_name = Path(contract_ref).name
    contract_path = (config.evidence_dir / contract_name).resolve()
    evidence_root = config.evidence_dir.resolve()
    if (
        contract_ref != f"evidence/{contract_name}"
        or contract_path.parent != evidence_root
        or not contract_path.is_file()
        or contract_path.is_symlink()
    ):
        raise ValueError("routed Builder contract reference is invalid")
    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("routed Builder contract is unreadable") from error
    task_id = str(row["task_id"])
    if (
        not isinstance(contract, dict)
        or str(contract.get("product_id") or "") != product_id
        or str(contract.get("task_id") or "") != task_id
        or str(contract.get("role") or "") != "builder"
        or str(contract.get("output_schema") or "") != invalid_schema
    ):
        raise ValueError("routed Builder contract identity is invalid")
    corrected_ref = (
        f"evidence/task-{task_id}-canonical-schema-{correction_digest[:12]}.json"
    )
    corrected_contract = dict(contract)
    corrected_contract.update(
        {
            "artifact_id": f"task-contract-{task_id}-canonical-{correction_digest[:12]}",
            "active_context_ref": corrected_ref,
            "output_schema": canonical_schema,
        }
    )
    corrected_path = ArtifactStore(config).write(
        "task-contract-v2.schema.json",
        corrected_contract,
        filename=Path(corrected_ref).name,
    )
    corrected_contract_digest = task_contract_digest(corrected_contract)

    now = utc_now()
    with state._lock:
        state._connection.execute("BEGIN IMMEDIATE")
        try:
            prior_row = state._connection.execute(
                """SELECT recovery_task_id FROM recovery_applications
                    WHERE recovery_plan_digest=? AND product_id=?""",
                (correction_digest, product_id),
            ).fetchone()
            if prior_row is not None:
                state._connection.commit()
                return {
                    "status": "PASS",
                    "application_status": "REPLAYED",
                    "product_id": product_id,
                    "recovery_task_id": str(prior_row[0]),
                    "correction_digest": correction_digest,
                }
            current = state._connection.execute(
                """SELECT failure.status, task.graph_status, task.status,
                          task.failure_id, task.output_schema, task.contract_ref,
                          product.status
                     FROM failures AS failure
                     JOIN tasks AS task ON task.task_id=failure.task_id
                     JOIN products AS product
                       ON product.product_id=failure.product_id
                    WHERE failure.failure_id=? AND failure.product_id=?""",
                (failure_id, product_id),
            ).fetchone()
            if current is None or tuple(current) != (
                "OPEN",
                "FAILED_SEMANTIC",
                "FAILED_SAFE",
                failure_id,
                invalid_schema,
                contract_ref,
                "IMPLEMENTING",
            ):
                raise ValueError("canonical Builder-schema state changed before apply")
            budget = state._connection.execute(
                """SELECT deterministic_actions_used, arbiter_calls_used,
                          execution_attempts_used, status
                     FROM problem_budgets
                    WHERE product_id=? AND root_problem_signature=?""",
                (product_id, root_problem_signature),
            ).fetchone()
            if budget is None or tuple(budget) != (1, 1, 2, "ACTIVE"):
                raise ValueError("product problem budget changed before apply")
            state._connection.execute(
                """UPDATE failures SET status='RESOLVED', last_seen_at=?
                    WHERE failure_id=? AND product_id=? AND status='OPEN'""",
                (now, failure_id, product_id),
            )
            state._connection.execute(
                """UPDATE tasks
                      SET status='PENDING', graph_status='READY', failure_id=?,
                          output_schema=?, contract_ref=?, active_context_ref=?,
                          contract_digest=?, lease_owner=NULL, lease_until=NULL,
                          lease_token=NULL, heartbeat_at=NULL, available_at=NULL,
                          terminal_reason=NULL, terminal_detail=NULL,
                          result_ref=NULL, result_digest=NULL, failure_kind=NULL,
                          blocked_reason=NULL, blocked_ref=NULL, updated_at=?
                    WHERE task_id=? AND product_id=?
                      AND graph_status='FAILED_SEMANTIC'
                      AND status='FAILED_SAFE'""",
                (
                    parent_failure_id,
                    canonical_schema,
                    f"evidence/{corrected_path.name}",
                    corrected_ref,
                    corrected_contract_digest,
                    now,
                    task_id,
                    product_id,
                ),
            )
            incident_id = "incident-" + sha256_text(
                f"{failure_id}:canonical-builder-schema"
            )[:20]
            state._connection.execute(
                """INSERT OR IGNORE INTO controller_incidents
                   (incident_id, product_id, task_id, reason_code,
                    evidence_ref, status, created_at, resolved_at)
                   VALUES (?, ?, ?, 'controller_canonical_builder_schema_invariant',
                           ?, 'RESOLVED', ?, ?)""",
                (
                    incident_id,
                    product_id,
                    task_id,
                    f"internal://release/{correction_evidence_digest}",
                    now,
                    now,
                ),
            )
            state._connection.execute(
                """INSERT INTO recovery_applications
                   (recovery_plan_digest, product_id, recovery_task_id,
                    status, applied_at)
                   VALUES (?, ?, ?, 'APPLIED', ?)""",
                (correction_digest, product_id, task_id, now),
            )
            state._record_event(
                product_id,
                task_id,
                "controller_canonical_builder_schema_recovery_applied",
                {
                    "failure_id": failure_id,
                    "parent_failure_id": parent_failure_id,
                    "root_problem_signature": root_problem_signature,
                    "correction_digest": correction_digest,
                    "contract_ref": f"evidence/{corrected_path.name}",
                    "contract_digest": corrected_contract_digest,
                    "product_budget_counters_preserved": True,
                },
            )
            state._connection.commit()
        except Exception:
            state._connection.rollback()
            raise
    return {
        "status": "PASS",
        "application_status": "APPLIED",
        "product_id": product_id,
        "recovery_task_id": task_id,
        "root_problem_signature": root_problem_signature,
        "correction_digest": correction_digest,
        "parent_failure_id": parent_failure_id,
        "corrected_contract_ref": f"evidence/{corrected_path.name}",
        "corrected_output_schema": canonical_schema,
        "product_budget_counters": {
            "deterministic_actions_used": 1,
            "arbiter_calls_used": 1,
            "execution_attempts_used": 2,
            "status": "ACTIVE",
        },
    }


def resume_repair_context_binding_failure(
    config: FactoryConfig,
    state: StateStore,
    *,
    product_id: str,
    failure_id: str,
    correction_evidence_digest: str,
) -> dict[str, Any]:
    """Restore the immutable repair brief lost by a controller failure."""

    if not state.maintenance_active():
        raise ValueError("repair-context binding recovery requires maintenance mode")
    if len(correction_evidence_digest) != 64 or any(
        character not in "0123456789abcdef"
        for character in correction_evidence_digest
    ):
        raise ValueError("controller correction evidence digest is invalid")
    correction_digest = sha256_text(
        stable_json(
            {
                "action": "controller_repair_context_binding_recovery",
                "product_id": product_id,
                "failure_id": failure_id,
                "correction_evidence_digest": correction_evidence_digest,
            }
        )
    )
    prior = _rows(
        state,
        """SELECT recovery_task_id FROM recovery_applications
            WHERE recovery_plan_digest=? AND product_id=?""",
        (correction_digest, product_id),
    )
    if prior:
        return {
            "status": "PASS",
            "application_status": "REPLAYED",
            "product_id": product_id,
            "recovery_task_id": str(prior[0]["recovery_task_id"]),
            "correction_digest": correction_digest,
        }
    rows = _rows(
        state,
        """SELECT failure.failure_class, failure.reason_code,
                  failure.safe_message, failure.failed_gate_ids_json,
                  failure.status AS failure_status,
                  failure.parent_failure_id,
                  parent.failure_class AS parent_failure_class,
                  parent.status AS parent_failure_status,
                  task.task_id, task.role, task.output_schema,
                  task.capability_profile, task.stage_key,
                  task.graph_status, task.status AS task_status,
                  task.repair_context_ref, task.root_problem_signature,
                  product.status AS product_status
             FROM failures AS failure
             JOIN failures AS parent
               ON parent.failure_id=failure.parent_failure_id
              AND parent.product_id=failure.product_id
             JOIN tasks AS task ON task.task_id=failure.task_id
             JOIN products AS product
               ON product.product_id=failure.product_id
            WHERE failure.failure_id=? AND failure.product_id=?""",
        (failure_id, product_id),
    )
    if len(rows) != 1:
        raise ValueError("repair-context failure coordinate is missing")
    row = rows[0]
    try:
        failed_gate_ids = json.loads(str(row["failed_gate_ids_json"] or "[]"))
    except json.JSONDecodeError as error:
        raise ValueError("repair-context failure gates are invalid") from error
    expected_findings = {
        "REPAIR_BRIEF_MISSING",
        "SUBJECT_SHA_WORKTREE_MISMATCH",
        "WORKTREE_HAS_UNCOMMITTED_CONTENT",
    }
    safe_message = str(row["safe_message"] or "")
    root_problem_signature = str(row["root_problem_signature"] or "")
    parent_failure_id = str(row["parent_failure_id"] or "")
    task_id = str(row["task_id"])
    if (
        str(row["failure_class"]) != "semantic"
        or str(row["reason_code"]) != "needs_replan"
        or str(row["failure_status"]) != "OPEN"
        or not isinstance(failed_gate_ids, list)
        or {str(value) for value in failed_gate_ids} != expected_findings
        or any(finding not in safe_message for finding in expected_findings)
        or str(row["parent_failure_class"]) not in {"semantic", "policy"}
        or str(row["parent_failure_status"]) != "ROUTED"
        or not parent_failure_id
        or str(row["role"]) != "builder"
        or str(row["output_schema"]) != "attempt-result.schema.json"
        or str(row["capability_profile"] or "") != "builder_workspace"
        or str(row["stage_key"] or "") != "repair"
        or str(row["graph_status"]) != "FAILED_SEMANTIC"
        or str(row["task_status"]) != "FAILED_SAFE"
        or row["repair_context_ref"] is not None
        or str(row["product_status"]) != "IMPLEMENTING"
        or len(root_problem_signature) != 64
        or any(
            character not in "0123456789abcdef"
            for character in root_problem_signature
        )
    ):
        raise ValueError("failure is not the bounded repair-context defect")
    budget_rows = _rows(
        state,
        """SELECT deterministic_actions_used, arbiter_calls_used,
                  execution_attempts_used, status
             FROM problem_budgets
            WHERE product_id=? AND root_problem_signature=?""",
        (product_id, root_problem_signature),
    )
    if len(budget_rows) != 1 or (
        int(budget_rows[0]["deterministic_actions_used"]),
        int(budget_rows[0]["arbiter_calls_used"]),
        int(budget_rows[0]["execution_attempts_used"]),
        str(budget_rows[0]["status"]),
    ) != (1, 1, 2, "ACTIVE"):
        raise ValueError("product problem budget changed before context recovery")
    active_claims = _rows(
        state,
        """SELECT COUNT(*) AS count FROM tasks
            WHERE status='CLAIMED'
              AND (lease_until IS NULL OR lease_until >= ?)""",
        (utc_now(),),
    )
    if int(active_claims[0]["count"]):
        raise ValueError("repair-context recovery requires a drained controller")

    repair_ref = f"evidence/repair-brief-{task_id}.json"
    repair_path = (config.evidence_dir / Path(repair_ref).name).resolve()
    if (
        repair_path.parent != config.evidence_dir.resolve()
        or not repair_path.is_file()
        or repair_path.is_symlink()
    ):
        raise ValueError("immutable repair brief is missing or unsafe")
    try:
        repair_brief = json.loads(repair_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("immutable repair brief is unreadable") from error
    if not isinstance(repair_brief, dict):
        raise TypeError("immutable repair brief is invalid")
    validation_errors = ArtifactStore(config).validate(
        "repair-brief-v2.schema.json",
        repair_brief,
    )
    repair_gate_ids = repair_brief.get("failed_gate_ids", [])
    allowed_paths = repair_brief.get("allowed_paths", [])
    if (
        validation_errors
        or str(repair_brief.get("product_id") or "") != product_id
        or str(repair_brief.get("task_id") or "") != task_id
        or str(repair_brief.get("failure_id") or "") != parent_failure_id
        or "SECURITY-CONTAINER-SCAN-NOT-RUN" not in repair_gate_ids
        or "Dockerfile" not in allowed_paths
        or "scripts/**" not in allowed_paths
    ):
        raise ValueError("immutable repair brief identity is invalid")

    now = utc_now()
    with state._lock:
        state._connection.execute("BEGIN IMMEDIATE")
        try:
            prior_row = state._connection.execute(
                """SELECT recovery_task_id FROM recovery_applications
                    WHERE recovery_plan_digest=? AND product_id=?""",
                (correction_digest, product_id),
            ).fetchone()
            if prior_row is not None:
                state._connection.commit()
                return {
                    "status": "PASS",
                    "application_status": "REPLAYED",
                    "product_id": product_id,
                    "recovery_task_id": str(prior_row[0]),
                    "correction_digest": correction_digest,
                }
            current = state._connection.execute(
                """SELECT failure.status, task.graph_status, task.status,
                          task.failure_id, task.repair_context_ref, product.status
                     FROM failures AS failure
                     JOIN tasks AS task ON task.task_id=failure.task_id
                     JOIN products AS product
                       ON product.product_id=failure.product_id
                    WHERE failure.failure_id=? AND failure.product_id=?""",
                (failure_id, product_id),
            ).fetchone()
            if current is None or tuple(current) != (
                "OPEN",
                "FAILED_SEMANTIC",
                "FAILED_SAFE",
                failure_id,
                None,
                "IMPLEMENTING",
            ):
                raise ValueError("repair-context state changed before apply")
            budget = state._connection.execute(
                """SELECT deterministic_actions_used, arbiter_calls_used,
                          execution_attempts_used, status
                     FROM problem_budgets
                    WHERE product_id=? AND root_problem_signature=?""",
                (product_id, root_problem_signature),
            ).fetchone()
            if budget is None or tuple(budget) != (1, 1, 2, "ACTIVE"):
                raise ValueError("product problem budget changed before apply")
            state._connection.execute(
                """UPDATE failures
                      SET failure_class='controller',
                          reason_code='controller_repair_context_binding_invariant',
                          status='RESOLVED', last_seen_at=?
                    WHERE failure_id=? AND product_id=? AND status='OPEN'""",
                (now, failure_id, product_id),
            )
            state._connection.execute(
                """UPDATE tasks
                      SET status='PENDING', graph_status='READY', failure_id=?,
                          next_tier='terra', next_attempt_kind='repair',
                          repair_context_ref=?, lease_owner=NULL, lease_until=NULL,
                          lease_token=NULL, heartbeat_at=NULL, available_at=NULL,
                          terminal_reason=NULL, terminal_detail=NULL,
                          result_ref=NULL, result_digest=NULL, failure_kind=NULL,
                          blocked_reason=NULL, blocked_ref=NULL, updated_at=?
                    WHERE task_id=? AND product_id=?
                      AND graph_status='FAILED_SEMANTIC'
                      AND status='FAILED_SAFE'""",
                (parent_failure_id, repair_ref, now, task_id, product_id),
            )
            incident_id = "incident-" + sha256_text(
                f"{failure_id}:repair-context-binding"
            )[:20]
            state._connection.execute(
                """INSERT OR IGNORE INTO controller_incidents
                   (incident_id, product_id, task_id, reason_code,
                    evidence_ref, status, created_at, resolved_at)
                   VALUES (?, ?, ?, 'controller_repair_context_binding_invariant',
                           ?, 'RESOLVED', ?, ?)""",
                (
                    incident_id,
                    product_id,
                    task_id,
                    f"internal://release/{correction_evidence_digest}",
                    now,
                    now,
                ),
            )
            state._connection.execute(
                """INSERT INTO recovery_applications
                   (recovery_plan_digest, product_id, recovery_task_id,
                    status, applied_at)
                   VALUES (?, ?, ?, 'APPLIED', ?)""",
                (correction_digest, product_id, task_id, now),
            )
            state._record_event(
                product_id,
                task_id,
                "controller_repair_context_binding_recovery_applied",
                {
                    "failure_id": failure_id,
                    "parent_failure_id": parent_failure_id,
                    "root_problem_signature": root_problem_signature,
                    "correction_digest": correction_digest,
                    "repair_context_ref": repair_ref,
                    "product_budget_counters_preserved": True,
                },
            )
            state._connection.commit()
        except Exception:
            state._connection.rollback()
            raise
    return {
        "status": "PASS",
        "application_status": "APPLIED",
        "product_id": product_id,
        "recovery_task_id": task_id,
        "root_problem_signature": root_problem_signature,
        "correction_digest": correction_digest,
        "parent_failure_id": parent_failure_id,
        "repair_context_ref": repair_ref,
        "product_budget_counters": {
            "deterministic_actions_used": 1,
            "arbiter_calls_used": 1,
            "execution_attempts_used": 2,
            "status": "ACTIVE",
        },
    }


def resume_reviewer_revalidation_lineage_failure(
    state: StateStore,
    *,
    product_id: str,
    failure_id: str,
    correction_evidence_digest: str,
) -> dict[str, Any]:
    """Require fresh reviewer acceptance after a cross-role Builder repair."""

    if not state.maintenance_active():
        raise ValueError("reviewer revalidation recovery requires maintenance mode")
    if len(correction_evidence_digest) != 64 or any(
        character not in "0123456789abcdef"
        for character in correction_evidence_digest
    ):
        raise ValueError("controller correction evidence digest is invalid")
    correction_digest = sha256_text(
        stable_json(
            {
                "action": "controller_reviewer_revalidation_lineage_recovery",
                "product_id": product_id,
                "failure_id": failure_id,
                "correction_evidence_digest": correction_evidence_digest,
            }
        )
    )
    prior = _rows(
        state,
        """SELECT recovery_task_id FROM recovery_applications
            WHERE recovery_plan_digest=? AND product_id=?""",
        (correction_digest, product_id),
    )
    if prior:
        return {
            "status": "PASS",
            "application_status": "REPLAYED",
            "product_id": product_id,
            "recovery_task_id": str(prior[0]["recovery_task_id"]),
            "correction_digest": correction_digest,
        }
    rows = _rows(
        state,
        """SELECT failure.failure_class, failure.reason_code,
                  failure.safe_message, failure.status AS failure_status,
                  task.task_id, task.role, task.capability_profile,
                  task.stage_key, task.graph_status,
                  task.status AS task_status, task.root_problem_signature,
                  product.status AS product_status
             FROM failures AS failure
             JOIN tasks AS task ON task.task_id=failure.task_id
             JOIN products AS product
               ON product.product_id=failure.product_id
            WHERE failure.failure_id=? AND failure.product_id=?""",
        (failure_id, product_id),
    )
    if len(rows) != 1:
        raise ValueError("reviewer revalidation failure coordinate is missing")
    row = rows[0]
    safe_message = str(row["safe_message"] or "")
    match = re.fullmatch(
        r"accepted task replacement identity conflicts for (T-[A-Z0-9_-]{4,})",
        safe_message,
    )
    reviewer_task_id = match.group(1) if match else ""
    reviewer_rows = _rows(
        state,
        """SELECT task_id,role,capability_profile,graph_status,status,plan_id
             FROM tasks WHERE task_id=? AND product_id=?""",
        (reviewer_task_id, product_id),
    )
    repair_rows = _rows(
        state,
        """SELECT task_id,role,stage_key,graph_status,status,plan_id
             FROM tasks
            WHERE product_id=? AND supersedes_task_id=?
              AND role='builder' AND stage_key='repair'
              AND graph_status='ACCEPTED' AND status='DONE'
            ORDER BY created_at,task_id""",
        (product_id, reviewer_task_id),
    )
    root_problem_signature = str(row["root_problem_signature"] or "")
    if (
        str(row["failure_class"]) != "semantic"
        or str(row["reason_code"]) != "internal_blocker"
        or str(row["failure_status"]) != "OPEN"
        or str(row["role"]) != "independent-reviewer"
        or str(row["capability_profile"] or "") != "reviewer_readonly"
        or str(row["stage_key"] or "") != "release-readiness-review"
        or str(row["graph_status"]) != "FAILED_SEMANTIC"
        or str(row["task_status"]) != "FAILED_SAFE"
        or str(row["product_status"]) != "IMPLEMENTING"
        or len(reviewer_rows) != 1
        or str(reviewer_rows[0]["role"]) != "security-reviewer"
        or str(reviewer_rows[0]["capability_profile"] or "") != "reviewer_readonly"
        or str(reviewer_rows[0]["graph_status"]) != "SUPERSEDED"
        or str(reviewer_rows[0]["status"]) != "DONE"
        or len(repair_rows) != 1
        or str(repair_rows[0]["plan_id"]) != str(reviewer_rows[0]["plan_id"])
        or len(root_problem_signature) != 64
        or any(
            character not in "0123456789abcdef"
            for character in root_problem_signature
        )
    ):
        raise ValueError("failure is not the bounded reviewer revalidation defect")
    independent_task_id = str(row["task_id"])
    repair_task_id = str(repair_rows[0]["task_id"])
    edge_rows = _rows(
        state,
        """SELECT required FROM task_edges
            WHERE plan_id=? AND from_task_id=? AND to_task_id=?
              AND edge_type='depends_on'""",
        (
            str(reviewer_rows[0]["plan_id"]),
            reviewer_task_id,
            independent_task_id,
        ),
    )
    if len(edge_rows) != 1 or int(edge_rows[0]["required"]) != 1:
        raise ValueError("reviewer downstream dependency is missing")
    budget_rows = _rows(
        state,
        """SELECT deterministic_actions_used, arbiter_calls_used,
                  execution_attempts_used, status
             FROM problem_budgets
            WHERE product_id=? AND root_problem_signature=?""",
        (product_id, root_problem_signature),
    )
    if len(budget_rows) != 1 or (
        int(budget_rows[0]["deterministic_actions_used"]),
        int(budget_rows[0]["arbiter_calls_used"]),
        int(budget_rows[0]["execution_attempts_used"]),
        str(budget_rows[0]["status"]),
    ) != (1, 1, 2, "ACTIVE"):
        raise ValueError("product problem budget changed before revalidation recovery")
    active_claims = _rows(
        state,
        """SELECT COUNT(*) AS count FROM tasks
            WHERE status='CLAIMED'
              AND (lease_until IS NULL OR lease_until >= ?)""",
        (utc_now(),),
    )
    if int(active_claims[0]["count"]):
        raise ValueError("reviewer revalidation recovery requires a drained controller")

    now = utc_now()
    plan_id = str(reviewer_rows[0]["plan_id"])
    with state._lock:
        state._connection.execute("BEGIN IMMEDIATE")
        try:
            prior_row = state._connection.execute(
                """SELECT recovery_task_id FROM recovery_applications
                    WHERE recovery_plan_digest=? AND product_id=?""",
                (correction_digest, product_id),
            ).fetchone()
            if prior_row is not None:
                state._connection.commit()
                return {
                    "status": "PASS",
                    "application_status": "REPLAYED",
                    "product_id": product_id,
                    "recovery_task_id": str(prior_row[0]),
                    "correction_digest": correction_digest,
                }
            current = state._connection.execute(
                """SELECT failure.status, reviewer.graph_status,
                          reviewer.status, independent.graph_status,
                          independent.status, independent.failure_id,
                          product.status
                     FROM failures AS failure
                     JOIN tasks AS independent
                       ON independent.task_id=failure.task_id
                     JOIN tasks AS reviewer
                       ON reviewer.task_id=?
                      AND reviewer.product_id=failure.product_id
                     JOIN products AS product
                       ON product.product_id=failure.product_id
                    WHERE failure.failure_id=? AND failure.product_id=?""",
                (reviewer_task_id, failure_id, product_id),
            ).fetchone()
            if current is None or tuple(current) != (
                "OPEN",
                "SUPERSEDED",
                "DONE",
                "FAILED_SEMANTIC",
                "FAILED_SAFE",
                failure_id,
                "IMPLEMENTING",
            ):
                raise ValueError("reviewer revalidation state changed before apply")
            budget = state._connection.execute(
                """SELECT deterministic_actions_used, arbiter_calls_used,
                          execution_attempts_used, status
                     FROM problem_budgets
                    WHERE product_id=? AND root_problem_signature=?""",
                (product_id, root_problem_signature),
            ).fetchone()
            if budget is None or tuple(budget) != (1, 1, 2, "ACTIVE"):
                raise ValueError("product problem budget changed before apply")
            state._connection.execute(
                """UPDATE failures
                      SET failure_class='controller',
                          reason_code='controller_reviewer_revalidation_lineage_invariant',
                          status='RESOLVED', last_seen_at=?
                    WHERE failure_id=? AND product_id=? AND status='OPEN'""",
                (now, failure_id, product_id),
            )
            for task_id, graph_status in (
                (reviewer_task_id, "READY"),
                (independent_task_id, "BLOCKED_DEPENDENCY"),
            ):
                state._connection.execute(
                    """UPDATE tasks
                          SET status='PENDING', graph_status=?, failure_id=NULL,
                              hypothesis_id=NULL, result_ref=NULL,
                              result_digest=NULL, result_binding_id=NULL,
                              lease_owner=NULL, lease_until=NULL,
                              lease_token=NULL, heartbeat_at=NULL,
                              available_at=NULL, next_tier='terra',
                              next_attempt_kind='initial', repair_context_ref=NULL,
                              terminal_reason=NULL, terminal_detail=NULL,
                              failure_kind=NULL, blocked_reason=NULL,
                              blocked_ref=NULL, updated_at=?
                        WHERE task_id=? AND product_id=?""",
                    (graph_status, now, task_id, product_id),
                )
            state._connection.execute(
                """DELETE FROM task_edges
                    WHERE plan_id=? AND from_task_id=? AND to_task_id=?
                      AND edge_type='supersedes' AND required=0""",
                (plan_id, reviewer_task_id, repair_task_id),
            )
            state._connection.execute(
                """INSERT OR IGNORE INTO task_edges
                   (plan_id, from_task_id, to_task_id, edge_type,
                    required, created_at)
                   VALUES (?, ?, ?, 'revalidates', 1, ?)""",
                (plan_id, repair_task_id, reviewer_task_id, now),
            )
            incident_id = "incident-" + sha256_text(
                f"{failure_id}:reviewer-revalidation"
            )[:20]
            state._connection.execute(
                """INSERT OR IGNORE INTO controller_incidents
                   (incident_id, product_id, task_id, reason_code,
                    evidence_ref, status, created_at, resolved_at)
                   VALUES (?, ?, ?,
                           'controller_reviewer_revalidation_lineage_invariant',
                           ?, 'RESOLVED', ?, ?)""",
                (
                    incident_id,
                    product_id,
                    reviewer_task_id,
                    f"internal://release/{correction_evidence_digest}",
                    now,
                    now,
                ),
            )
            state._connection.execute(
                """INSERT INTO recovery_applications
                   (recovery_plan_digest, product_id, recovery_task_id,
                    status, applied_at)
                   VALUES (?, ?, ?, 'APPLIED', ?)""",
                (correction_digest, product_id, reviewer_task_id, now),
            )
            state._record_event(
                product_id,
                reviewer_task_id,
                "controller_reviewer_revalidation_lineage_recovery_applied",
                {
                    "failure_id": failure_id,
                    "accepted_repair_task_id": repair_task_id,
                    "reviewer_task_id": reviewer_task_id,
                    "independent_reviewer_task_id": independent_task_id,
                    "root_problem_signature": root_problem_signature,
                    "correction_digest": correction_digest,
                    "fresh_reviewer_acceptance_required": True,
                    "product_budget_counters_preserved": True,
                },
            )
            state._connection.commit()
        except Exception:
            state._connection.rollback()
            raise
    return {
        "status": "PASS",
        "application_status": "APPLIED",
        "product_id": product_id,
        "recovery_task_id": reviewer_task_id,
        "accepted_repair_task_id": repair_task_id,
        "independent_reviewer_task_id": independent_task_id,
        "root_problem_signature": root_problem_signature,
        "correction_digest": correction_digest,
        "product_budget_counters": {
            "deterministic_actions_used": 1,
            "arbiter_calls_used": 1,
            "execution_attempts_used": 2,
            "status": "ACTIVE",
        },
    }


def _write_container_gated_security_contract(
    config: FactoryConfig,
    state: StateStore,
    *,
    reviewer: Mapping[str, Any],
    correction_digest: str,
) -> tuple[dict[str, Any], Path]:
    """Write one immutable revision of a persisted Security Reviewer contract."""

    from .failure_router import FailureRouter

    if (
        str(reviewer.get("role") or "") != "security-reviewer"
        or str(reviewer.get("capability_profile") or "") != "reviewer_readonly"
    ):
        raise ValueError("container-gate correction target is not Security Reviewer")
    router = FailureRouter(config, state, ArtifactStore(config))
    original = router._contract(dict(reviewer))
    quality_gates = list(
        dict.fromkeys(
            [
                *router._quality_gates(original),
                "target-container-image-scan",
            ]
        )
    )
    required_capabilities = list(
        dict.fromkeys(
            [
                *[
                    str(value)
                    for value in original.get("required_capabilities", [])
                    if isinstance(value, str) and value
                ],
                "toolchain.container_builder",
                "toolchain.scanners",
            ]
        )
    )
    revision = int(reviewer.get("task_revision") or 1) + 1
    task_id = str(reviewer["task_id"])
    corrected = {
        **original,
        "artifact_id": f"task-contract-{task_id}-container-gate-{correction_digest[:12]}",
        "task_revision": revision,
        "quality_gates": quality_gates,
        "required_capabilities": required_capabilities,
        "idempotency_key": sha256_text(
            stable_json(
                [
                    str(original.get("idempotency_key") or task_id),
                    "target-container-image-scan",
                    correction_digest,
                ]
            )
        ),
    }
    schema_name = (
        "task-contract-v2.schema.json"
        if str(corrected.get("schema_version") or "") == "2.0"
        else "task-contract.schema.json"
    )
    artifacts = ArtifactStore(config)
    errors = artifacts.validate(schema_name, corrected)
    if errors:
        raise ValueError(
            "corrected Security Reviewer contract is invalid: "
            + "; ".join(errors)
        )
    path = artifacts.write(
        schema_name,
        corrected,
        filename=f"task-{task_id}-container-gate-{correction_digest[:12]}.json",
    )
    return corrected, path


def resume_unverified_container_repair_failure(
    config: FactoryConfig,
    state: StateStore,
    *,
    product_id: str,
    failure_id: str,
    correction_evidence_digest: str,
) -> dict[str, Any]:
    """Replace a falsely accepted container repair with one controller-gated slot."""

    if not state.maintenance_active():
        raise ValueError("unverified container repair recovery requires maintenance mode")
    if len(correction_evidence_digest) != 64 or any(
        character not in "0123456789abcdef"
        for character in correction_evidence_digest
    ):
        raise ValueError("controller correction evidence digest is invalid")
    correction_digest = sha256_text(
        stable_json(
            {
                "action": "controller_unverified_container_repair_recovery",
                "product_id": product_id,
                "failure_id": failure_id,
                "correction_evidence_digest": correction_evidence_digest,
            }
        )
    )
    prior = _rows(
        state,
        """SELECT recovery_task_id FROM recovery_applications
            WHERE recovery_plan_digest=? AND product_id=?""",
        (correction_digest, product_id),
    )
    if prior:
        return {
            "status": "PASS",
            "application_status": "REPLAYED",
            "product_id": product_id,
            "recovery_task_id": str(prior[0]["recovery_task_id"]),
            "correction_digest": correction_digest,
        }

    rows = _rows(
        state,
        """SELECT failure.*, task.role, task.capability_profile,
                  task.stage_key, task.graph_status,
                  task.status AS task_status, task.root_problem_signature,
                  task.hypothesis_id AS task_hypothesis_id,
                  product.status AS product_status
             FROM failures AS failure
             JOIN tasks AS task ON task.task_id=failure.task_id
             JOIN products AS product
               ON product.product_id=failure.product_id
            WHERE failure.failure_id=? AND failure.product_id=?""",
        (failure_id, product_id),
    )
    if len(rows) != 1:
        raise ValueError("unverified container repair failure coordinate is missing")
    failure = rows[0]
    try:
        failed_gate_ids = json.loads(str(failure.get("failed_gate_ids_json") or "[]"))
    except json.JSONDecodeError as error:
        raise ValueError("unverified container repair gates are invalid") from error
    expected_gates = {
        "SEC-DEFAULT-TMP-CREDENTIAL-SOURCE",
        "SEC-CONTAINER-IMAGE-SCAN-NOT-RUN",
    }
    safe_message = str(failure.get("safe_message") or "")
    root_problem_signature = str(failure.get("root_problem_signature") or "")
    if (
        str(failure.get("failure_class")) != "semantic"
        or str(failure.get("reason_code")) != "model_requested_repair"
        or str(failure.get("status")) != "OPEN"
        or str(failure.get("role")) != "security-reviewer"
        or str(failure.get("capability_profile") or "") != "reviewer_readonly"
        or str(failure.get("stage_key") or "") != "security-review"
        or str(failure.get("graph_status")) != "FAILED_SEMANTIC"
        or str(failure.get("task_status")) != "FAILED_SAFE"
        or str(failure.get("product_status")) != "IMPLEMENTING"
        or not isinstance(failed_gate_ids, list)
        or {str(value) for value in failed_gate_ids} != expected_gates
        or not all(gate_id in safe_message for gate_id in expected_gates)
        or len(root_problem_signature) != 64
        or any(
            character not in "0123456789abcdef"
            for character in root_problem_signature
        )
    ):
        raise ValueError("failure is not the bounded unverified container repair defect")
    reviewer_task_id = str(failure["task_id"])
    accepted_repairs = _rows(
        state,
        """SELECT task_id,result_ref,result_digest,plan_id
             FROM tasks
            WHERE product_id=? AND supersedes_task_id=?
              AND role='builder' AND stage_key='repair'
              AND graph_status='ACCEPTED' AND status='DONE'
            ORDER BY created_at,task_id""",
        (product_id, reviewer_task_id),
    )
    if len(accepted_repairs) != 1:
        raise ValueError("accepted unverified container repair coordinate is ambiguous")
    accepted_repair = accepted_repairs[0]
    result_ref = str(accepted_repair.get("result_ref") or "")
    result_path = Path(result_ref)
    if not result_path.is_absolute():
        result_path = config.evidence_dir / result_path.name
    evidence_root = config.evidence_dir.resolve()
    try:
        result_path = result_path.resolve(strict=True)
        result_path.relative_to(evidence_root)
    except (OSError, ValueError) as error:
        raise ValueError("accepted repair result reference is not local evidence") from error
    if (
        result_path.is_symlink()
        or result_path.parent != evidence_root
        or sha256_file(result_path) != str(accepted_repair.get("result_digest") or "")
    ):
        raise ValueError("accepted repair result evidence binding is invalid")
    try:
        attempt_payload = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("accepted repair result evidence is invalid") from error
    validation_errors = ArtifactStore(config).validate(
        "attempt-result.schema.json", attempt_payload
    )
    if validation_errors:
        raise ValueError("accepted repair result does not match its bounded schema")
    recorded_gates = {
        str(item.get("gate_id"))
        for item in attempt_payload.get("test_results", [])
        if isinstance(item, Mapping) and item.get("status") == "PASS"
    }
    if (
        str(attempt_payload.get("task_id") or "") != str(accepted_repair["task_id"])
        or str(attempt_payload.get("status") or "") != "completed"
        or "target-container-image-scan" in recorded_gates
    ):
        raise ValueError("accepted repair is not missing the controller image gate")
    budget_rows = _rows(
        state,
        """SELECT deterministic_actions_used,arbiter_calls_used,
                  execution_attempts_used,status
             FROM problem_budgets
            WHERE product_id=? AND root_problem_signature=?""",
        (product_id, root_problem_signature),
    )
    if len(budget_rows) != 1 or (
        int(budget_rows[0]["deterministic_actions_used"]),
        int(budget_rows[0]["arbiter_calls_used"]),
        int(budget_rows[0]["execution_attempts_used"]),
        str(budget_rows[0]["status"]),
    ) != (1, 1, 2, "ACTIVE"):
        raise ValueError("product problem budget changed before container repair recovery")
    active_claims = _rows(
        state,
        """SELECT COUNT(*) AS count FROM tasks
            WHERE status='CLAIMED'
              AND (lease_until IS NULL OR lease_until >= ?)""",
        (utc_now(),),
    )
    if int(active_claims[0]["count"]):
        raise ValueError("unverified container repair recovery requires a drained controller")
    failed = state.get_task(reviewer_task_id)
    if failed is None:
        raise ValueError("reviewer task disappeared before container repair recovery")
    hypothesis_id = str(failed.get("hypothesis_id") or "")
    if not hypothesis_id:
        raise ValueError("reviewer failure hypothesis is missing")
    hypothesis_rows = _rows(
        state,
        """SELECT parent_hypothesis_id FROM hypotheses
            WHERE hypothesis_id=? AND failure_id=? AND status='ACTIVE'""",
        (hypothesis_id, failure_id),
    )
    if len(hypothesis_rows) != 1:
        raise ValueError("reviewer failure hypothesis is not active")

    from .failure_router import FailureRouter

    router = FailureRouter(config, state, ArtifactStore(config))
    allowed_paths = router._reviewer_gate_repair_paths(list(expected_gates))
    acceptance = router._reviewer_gate_repair_acceptance(list(expected_gates))
    original = router._contract(failed)
    corrected_reviewer_contract, corrected_reviewer_path = (
        _write_container_gated_security_contract(
            config,
            state,
            reviewer=failed,
            correction_digest=correction_digest,
        )
    )
    quality_gates = list(
        dict.fromkeys(
            [*router._quality_gates(original), "target-container-image-scan"]
        )
    )
    required_capabilities = list(
        dict.fromkeys(
            [
                *sorted(CAPABILITY_PROFILES["builder_workspace"]),
                "toolchain.container_builder",
                "toolchain.scanners",
            ]
        )
    )
    contract, contract_path = router._write_contract(
        failed=failed,
        failure=failure,
        hypothesis_id=hypothesis_id,
        role="builder",
        output_schema="attempt-result.schema.json",
        capability_profile="builder_workspace",
        objective=(
            "Repair every fresh Security Reviewer finding, remove the temporary-directory "
            "credential-source fallback, and pass the controller-owned immutable image scan."
        ),
        allowed_paths=allowed_paths,
        task_revision=int(failed.get("task_revision") or 1) + 1,
        node_suffix="controller-verified-repair",
        required_capabilities=required_capabilities,
        acceptance=acceptance,
        quality_gates=quality_gates,
        model_floor="terra",
    )
    repair_path = router._write_repair_brief(
        failed=failed,
        failure=failure,
        hypothesis_id=hypothesis_id,
        parent_hypothesis_id=(
            str(hypothesis_rows[0]["parent_hypothesis_id"])
            if hypothesis_rows[0].get("parent_hypothesis_id")
            else None
        ),
        repair_task_id=str(contract["task_id"]),
        allowed_paths=allowed_paths,
        acceptance=acceptance,
    )
    repair_ref = f"evidence/{repair_path.name}"
    now = utc_now()
    with state._lock:
        state._connection.execute("BEGIN IMMEDIATE")
        try:
            prior_row = state._connection.execute(
                """SELECT recovery_task_id FROM recovery_applications
                    WHERE recovery_plan_digest=? AND product_id=?""",
                (correction_digest, product_id),
            ).fetchone()
            if prior_row is not None:
                state._connection.commit()
                return {
                    "status": "PASS",
                    "application_status": "REPLAYED",
                    "product_id": product_id,
                    "recovery_task_id": str(prior_row[0]),
                    "correction_digest": correction_digest,
                }
            current = state._connection.execute(
                """SELECT failure.status,reviewer.status,reviewer.graph_status,
                          reviewer.failure_id,product.status
                     FROM failures AS failure
                     JOIN tasks AS reviewer ON reviewer.task_id=failure.task_id
                     JOIN products AS product
                       ON product.product_id=failure.product_id
                    WHERE failure.failure_id=? AND failure.product_id=?""",
                (failure_id, product_id),
            ).fetchone()
            if current is None or tuple(current) != (
                "OPEN",
                "FAILED_SAFE",
                "FAILED_SEMANTIC",
                failure_id,
                "IMPLEMENTING",
            ):
                raise ValueError("unverified container repair state changed before apply")
            budget = state._connection.execute(
                """SELECT deterministic_actions_used,arbiter_calls_used,
                          execution_attempts_used,status
                     FROM problem_budgets
                    WHERE product_id=? AND root_problem_signature=?""",
                (product_id, root_problem_signature),
            ).fetchone()
            if budget is None or tuple(budget) != (1, 1, 2, "ACTIVE"):
                raise ValueError("product problem budget changed before apply")
            state._connection.execute(
                """INSERT INTO tasks
                   (task_id,product_id,title,role,output_schema,contract_ref,
                    stage_key,cycle,priority,status,dependencies_json,
                    conflict_keys_json,created_at,updated_at,root_task_id,
                    parent_task_id,source_task_id,plan_id,plan_node_id,
                    task_revision,root_context_ref,active_context_ref,failure_id,
                    hypothesis_id,capability_profile,idempotency_key,
                    supersedes_task_id,graph_status,root_problem_signature,
                    required_capabilities_json,mandatory,critical_path_rank,
                    repair_context_ref,next_tier,next_attempt_kind)
                   VALUES (?,?,?,?,?,?, 'repair',0,?,'PENDING','[]',?,?,?,?,
                           ?,?,?,?,?,?,?,?,?,?,?,?,'READY',?,?,1,0,?,'terra','repair')""",
                (
                    str(contract["task_id"]),
                    product_id,
                    str(contract["title"]),
                    str(contract["role"]),
                    str(contract["output_schema"]),
                    f"evidence/{contract_path.name}",
                    int(contract["priority"]),
                    stable_json(contract["conflict_keys"]),
                    now,
                    now,
                    str(contract["root_task_id"]),
                    str(contract["parent_task_id"]),
                    str(contract["source_task_id"]),
                    str(contract["plan_id"]),
                    str(contract["plan_node_id"]),
                    int(contract["task_revision"]),
                    str(contract["root_context_ref"]),
                    str(contract["active_context_ref"]),
                    failure_id,
                    hypothesis_id,
                    str(contract["capability_profile"]),
                    str(contract["idempotency_key"]),
                    str(contract["supersedes_task_id"]),
                    root_problem_signature,
                    stable_json(contract["required_capabilities"]),
                    repair_ref,
                ),
            )
            state._connection.execute(
                """UPDATE failures SET status='ROUTED',last_seen_at=?
                    WHERE failure_id=? AND product_id=? AND status='OPEN'""",
                (now, failure_id, product_id),
            )
            state._connection.execute(
                """UPDATE hypotheses SET attempts_used=attempts_used+1
                    WHERE hypothesis_id=? AND failure_id=? AND status='ACTIVE'""",
                (hypothesis_id, failure_id),
            )
            state._connection.execute(
                """UPDATE tasks
                      SET status='PENDING',graph_status='BLOCKED_DEPENDENCY',
                          contract_ref=?,task_revision=?,
                          required_capabilities_json=?,
                          result_ref=NULL,result_digest=NULL,result_binding_id=NULL,
                          lease_owner=NULL,lease_until=NULL,lease_token=NULL,
                          heartbeat_at=NULL,available_at=NULL,
                          terminal_reason=NULL,terminal_detail=NULL,
                          failure_kind=NULL,blocked_reason=NULL,blocked_ref=NULL,
                          updated_at=?
                    WHERE task_id=? AND product_id=?""",
                (
                    f"evidence/{corrected_reviewer_path.name}",
                    int(corrected_reviewer_contract["task_revision"]),
                    stable_json(corrected_reviewer_contract["required_capabilities"]),
                    now,
                    reviewer_task_id,
                    product_id,
                ),
            )
            state._connection.execute(
                """INSERT INTO task_edges
                   (plan_id,from_task_id,to_task_id,edge_type,required,created_at)
                   VALUES (?, ?, ?, 'revalidates', 1, ?)""",
                (
                    str(contract["plan_id"]),
                    str(contract["task_id"]),
                    reviewer_task_id,
                    now,
                ),
            )
            incident_id = "incident-" + sha256_text(
                f"{failure_id}:unverified-container-repair"
            )[:20]
            state._connection.execute(
                """INSERT OR IGNORE INTO controller_incidents
                   (incident_id,product_id,task_id,reason_code,evidence_ref,
                    status,created_at,resolved_at)
                   VALUES (?, ?, ?,
                           'controller_unverified_container_repair_acceptance',
                           ?, 'RESOLVED', ?, ?)""",
                (
                    incident_id,
                    product_id,
                    str(accepted_repair["task_id"]),
                    f"internal://release/{correction_evidence_digest}",
                    now,
                    now,
                ),
            )
            state._connection.execute(
                """INSERT INTO recovery_applications
                   (recovery_plan_digest,product_id,recovery_task_id,status,applied_at)
                   VALUES (?, ?, ?, 'APPLIED', ?)""",
                (correction_digest, product_id, str(contract["task_id"]), now),
            )
            state._record_event(
                product_id,
                str(contract["task_id"]),
                "controller_unverified_container_repair_recovery_applied",
                {
                    "failure_id": failure_id,
                    "invalid_accepted_repair_task_id": str(
                        accepted_repair["task_id"]
                    ),
                    "replacement_repair_task_id": str(contract["task_id"]),
                    "reviewer_task_id": reviewer_task_id,
                    "root_problem_signature": root_problem_signature,
                    "correction_digest": correction_digest,
                    "required_gate": "target-container-image-scan",
                    "reviewer_contract_ref": f"evidence/{corrected_reviewer_path.name}",
                    "product_budget_counters_preserved": True,
                },
            )
            state._connection.commit()
        except Exception:
            state._connection.rollback()
            raise
    return {
        "status": "PASS",
        "application_status": "APPLIED",
        "product_id": product_id,
        "recovery_task_id": str(contract["task_id"]),
        "reviewer_task_id": reviewer_task_id,
        "reviewer_contract_ref": f"evidence/{corrected_reviewer_path.name}",
        "invalid_accepted_repair_task_id": str(accepted_repair["task_id"]),
        "repair_context_ref": repair_ref,
        "root_problem_signature": root_problem_signature,
        "correction_digest": correction_digest,
        "product_budget_counters": {
            "deterministic_actions_used": 1,
            "arbiter_calls_used": 1,
            "execution_attempts_used": 2,
            "status": "ACTIVE",
        },
    }


def resume_missing_security_container_gate_failure(
    config: FactoryConfig,
    state: StateStore,
    *,
    product_id: str,
    failure_id: str,
    correction_evidence_digest: str,
) -> dict[str, Any]:
    """Correct one persisted reviewer contract that predates the image gate."""

    if not state.maintenance_active():
        raise ValueError("security container-gate recovery requires maintenance mode")
    if len(correction_evidence_digest) != 64 or any(
        character not in "0123456789abcdef"
        for character in correction_evidence_digest
    ):
        raise ValueError("controller correction evidence digest is invalid")
    correction_digest = sha256_text(
        stable_json(
            {
                "action": "controller_security_container_gate_contract_recovery",
                "product_id": product_id,
                "failure_id": failure_id,
                "correction_evidence_digest": correction_evidence_digest,
            }
        )
    )
    prior = _rows(
        state,
        """SELECT recovery_task_id FROM recovery_applications
            WHERE recovery_plan_digest=? AND product_id=?""",
        (correction_digest, product_id),
    )
    if prior:
        return {
            "status": "PASS",
            "application_status": "REPLAYED",
            "product_id": product_id,
            "recovery_task_id": str(prior[0]["recovery_task_id"]),
            "correction_digest": correction_digest,
        }

    rows = _rows(
        state,
        """SELECT failure.*,task.role,task.capability_profile,task.stage_key,
                  task.graph_status,task.status AS task_status,
                  task.root_problem_signature,task.contract_ref,
                  task.task_revision,product.status AS product_status
             FROM failures AS failure
             JOIN tasks AS task ON task.task_id=failure.task_id
             JOIN products AS product ON product.product_id=failure.product_id
            WHERE failure.failure_id=? AND failure.product_id=?""",
        (failure_id, product_id),
    )
    if len(rows) != 1:
        raise ValueError("security container-gate failure coordinate is missing")
    failure = rows[0]
    try:
        failed_gate_ids = json.loads(str(failure.get("failed_gate_ids_json") or "[]"))
    except json.JSONDecodeError as error:
        raise ValueError("security container-gate finding IDs are invalid") from error
    root_problem_signature = str(failure.get("root_problem_signature") or "")
    if (
        str(failure.get("failure_class") or "") != "semantic"
        or str(failure.get("reason_code") or "") != "model_requested_repair"
        or str(failure.get("status") or "") != "OPEN"
        or str(failure.get("role") or "") != "security-reviewer"
        or str(failure.get("capability_profile") or "") != "reviewer_readonly"
        or str(failure.get("stage_key") or "") != "security-review"
        or str(failure.get("graph_status") or "") != "FAILED_SEMANTIC"
        or str(failure.get("task_status") or "") != "FAILED_SAFE"
        or str(failure.get("product_status") or "") != "IMPLEMENTING"
        or failed_gate_ids != ["CONTAINER-SCAN-EVIDENCE-MISSING"]
        or "CONTAINER-SCAN-EVIDENCE-MISSING"
        not in str(failure.get("safe_message") or "")
        or not re.fullmatch(r"[a-f0-9]{64}", root_problem_signature)
    ):
        raise ValueError("failure is not the bounded missing reviewer image-gate defect")
    reviewer_task_id = str(failure["task_id"])
    reviewer = state.get_task(reviewer_task_id)
    if reviewer is None:
        raise ValueError("Security Reviewer task disappeared")

    from .failure_router import FailureRouter

    original = FailureRouter(config, state, ArtifactStore(config))._contract(reviewer)
    if "target-container-image-scan" in original.get("quality_gates", []):
        raise ValueError("Security Reviewer contract already contains the image gate")
    budget_rows = _rows(
        state,
        """SELECT deterministic_actions_used,arbiter_calls_used,
                  execution_attempts_used,status
             FROM problem_budgets
            WHERE product_id=? AND root_problem_signature=?""",
        (product_id, root_problem_signature),
    )
    if len(budget_rows) != 1 or (
        int(budget_rows[0]["deterministic_actions_used"]),
        int(budget_rows[0]["arbiter_calls_used"]),
        int(budget_rows[0]["execution_attempts_used"]),
        str(budget_rows[0]["status"]),
    ) != (1, 1, 2, "ACTIVE"):
        raise ValueError("product problem budget changed before reviewer contract recovery")
    active_claims = _rows(
        state,
        """SELECT COUNT(*) AS count FROM tasks
            WHERE status='CLAIMED'
              AND (lease_until IS NULL OR lease_until >= ?)""",
        (utc_now(),),
    )
    if int(active_claims[0]["count"]):
        raise ValueError("security container-gate recovery requires a drained controller")

    accepted_builders = _rows(
        state,
        """SELECT task_id,result_ref,result_digest
             FROM tasks
            WHERE product_id=? AND role='builder'
              AND graph_status='ACCEPTED' AND status='DONE'
              AND root_problem_signature=?
            ORDER BY created_at,task_id""",
        (product_id, root_problem_signature),
    )
    evidence_root = config.evidence_dir.resolve()
    verified_builder_task_ids: list[str] = []
    for builder in accepted_builders:
        result_path = Path(str(builder.get("result_ref") or ""))
        if not result_path.is_absolute():
            result_path = config.evidence_dir / result_path.name
        try:
            result_path = result_path.resolve(strict=True)
            result_path.relative_to(evidence_root)
        except (OSError, ValueError):
            continue
        if (
            result_path.is_symlink()
            or result_path.parent != evidence_root
            or sha256_file(result_path) != str(builder.get("result_digest") or "")
        ):
            continue
        try:
            attempt_payload = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if ArtifactStore(config).validate("attempt-result.schema.json", attempt_payload):
            continue
        image_result = next(
            (
                item
                for item in attempt_payload.get("test_results", [])
                if isinstance(item, Mapping)
                and str(item.get("gate_id") or "") == "target-container-image-scan"
                and str(item.get("status") or "") == "PASS"
            ),
            None,
        )
        if image_result is None:
            continue
        evidence_ref = str(image_result.get("evidence_ref") or "")
        gate_path = (config.evidence_dir / Path(evidence_ref).name).resolve()
        if (
            evidence_ref != f"evidence/{gate_path.name}"
            and evidence_ref != str(gate_path)
        ):
            continue
        if gate_path.parent != evidence_root or not gate_path.is_file() or gate_path.is_symlink():
            continue
        try:
            gate_payload = json.loads(gate_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if ArtifactStore(config).validate("gate-evidence.schema.json", gate_payload):
            continue
        if (
            str(gate_payload.get("gate_id") or "") == "target-container-image-scan"
            and str(gate_payload.get("status") or "") == "PASS"
            and str(gate_payload.get("subject_sha") or "")
            == str(attempt_payload.get("subject_sha_before") or "")
        ):
            verified_builder_task_ids.append(str(builder["task_id"]))
    if len(verified_builder_task_ids) != 1:
        raise ValueError("subject-bound accepted Builder image evidence is ambiguous")

    corrected_contract, corrected_path = _write_container_gated_security_contract(
        config,
        state,
        reviewer=reviewer,
        correction_digest=correction_digest,
    )
    now = utc_now()
    with state._lock:
        state._connection.execute("BEGIN IMMEDIATE")
        try:
            current = state._connection.execute(
                """SELECT failure.status,reviewer.status,reviewer.graph_status,
                          reviewer.failure_id,reviewer.contract_ref,product.status
                     FROM failures AS failure
                     JOIN tasks AS reviewer ON reviewer.task_id=failure.task_id
                     JOIN products AS product ON product.product_id=failure.product_id
                    WHERE failure.failure_id=? AND failure.product_id=?""",
                (failure_id, product_id),
            ).fetchone()
            if current is None or tuple(current) != (
                "OPEN",
                "FAILED_SAFE",
                "FAILED_SEMANTIC",
                failure_id,
                str(failure["contract_ref"]),
                "IMPLEMENTING",
            ):
                raise ValueError("security container-gate state changed before apply")
            budget = state._connection.execute(
                """SELECT deterministic_actions_used,arbiter_calls_used,
                          execution_attempts_used,status
                     FROM problem_budgets
                    WHERE product_id=? AND root_problem_signature=?""",
                (product_id, root_problem_signature),
            ).fetchone()
            if budget is None or tuple(budget) != (1, 1, 2, "ACTIVE"):
                raise ValueError("product problem budget changed before apply")
            state._connection.execute(
                "UPDATE failures SET status='RESOLVED',last_seen_at=? WHERE failure_id=?",
                (now, failure_id),
            )
            updated = state._connection.execute(
                """UPDATE tasks
                      SET status='PENDING',graph_status='READY',failure_id=NULL,
                          contract_ref=?,task_revision=?,
                          required_capabilities_json=?,
                          result_ref=NULL,result_digest=NULL,result_binding_id=NULL,
                          lease_owner=NULL,lease_until=NULL,lease_token=NULL,
                          heartbeat_at=NULL,available_at=NULL,
                          terminal_reason=NULL,terminal_detail=NULL,
                          failure_kind=NULL,blocked_reason=NULL,blocked_ref=NULL,
                          updated_at=?
                    WHERE task_id=? AND status='FAILED_SAFE'
                      AND graph_status='FAILED_SEMANTIC'""",
                (
                    f"evidence/{corrected_path.name}",
                    int(corrected_contract["task_revision"]),
                    stable_json(corrected_contract["required_capabilities"]),
                    now,
                    reviewer_task_id,
                ),
            ).rowcount
            if updated != 1:
                raise ValueError("Security Reviewer contract recovery was not singular")
            incident_id = "incident-" + sha256_text(
                f"{failure_id}:missing-security-container-gate"
            )[:20]
            state._connection.execute(
                """INSERT OR IGNORE INTO controller_incidents
                   (incident_id,product_id,task_id,reason_code,evidence_ref,
                    status,created_at,resolved_at)
                   VALUES (?, ?, ?,
                           'controller_security_container_gate_contract_missing',
                           ?, 'RESOLVED', ?, ?)""",
                (
                    incident_id,
                    product_id,
                    reviewer_task_id,
                    f"internal://release/{correction_evidence_digest}",
                    now,
                    now,
                ),
            )
            state._connection.execute(
                """INSERT INTO recovery_applications
                   (recovery_plan_digest,product_id,recovery_task_id,status,applied_at)
                   VALUES (?, ?, ?, 'APPLIED', ?)""",
                (correction_digest, product_id, reviewer_task_id, now),
            )
            state._record_event(
                product_id,
                reviewer_task_id,
                "controller_security_container_gate_contract_recovery_applied",
                {
                    "failure_id": failure_id,
                    "verified_builder_task_id": verified_builder_task_ids[0],
                    "reviewer_contract_ref": f"evidence/{corrected_path.name}",
                    "required_gate": "target-container-image-scan",
                    "root_problem_signature": root_problem_signature,
                    "correction_digest": correction_digest,
                    "product_budget_counters_preserved": True,
                },
            )
            state._connection.commit()
        except Exception:
            state._connection.rollback()
            raise
    return {
        "status": "PASS",
        "application_status": "APPLIED",
        "product_id": product_id,
        "recovery_task_id": reviewer_task_id,
        "verified_builder_task_id": verified_builder_task_ids[0],
        "reviewer_contract_ref": f"evidence/{corrected_path.name}",
        "root_problem_signature": root_problem_signature,
        "correction_digest": correction_digest,
        "product_budget_counters": {
            "deterministic_actions_used": 1,
            "arbiter_calls_used": 1,
            "execution_attempts_used": 2,
            "status": "ACTIVE",
        },
    }


def resume_stale_reviewer_execution_failure(
    config: FactoryConfig,
    state: StateStore,
    *,
    product_id: str,
    failure_id: str,
    correction_evidence_digest: str,
) -> dict[str, Any]:
    """Re-execute one reviewer whose revised contract and toolchain were ignored."""

    if not state.maintenance_active():
        raise ValueError("stale reviewer execution recovery requires maintenance mode")
    if not re.fullmatch(r"[a-f0-9]{64}", correction_evidence_digest):
        raise ValueError("controller correction evidence digest is invalid")
    correction_digest = sha256_text(
        stable_json(
            {
                "action": "controller_stale_reviewer_execution_recovery",
                "product_id": product_id,
                "failure_id": failure_id,
                "correction_evidence_digest": correction_evidence_digest,
            }
        )
    )
    prior = _rows(
        state,
        """SELECT recovery_task_id FROM recovery_applications
            WHERE recovery_plan_digest=? AND product_id=?""",
        (correction_digest, product_id),
    )
    if prior:
        return {
            "status": "PASS",
            "application_status": "REPLAYED",
            "product_id": product_id,
            "recovery_task_id": str(prior[0]["recovery_task_id"]),
            "correction_digest": correction_digest,
        }

    rows = _rows(
        state,
        """SELECT failure.*,task.role,task.capability_profile,task.stage_key,
                  task.graph_status,task.status AS task_status,
                  task.root_problem_signature,task.contract_ref,
                  task.task_revision,product.status AS product_status
             FROM failures AS failure
             JOIN tasks AS task ON task.task_id=failure.task_id
             JOIN products AS product ON product.product_id=failure.product_id
            WHERE failure.failure_id=? AND failure.product_id=?""",
        (failure_id, product_id),
    )
    if len(rows) != 1:
        raise ValueError("stale reviewer execution failure coordinate is missing")
    failure = rows[0]
    try:
        failed_gate_ids = json.loads(str(failure.get("failed_gate_ids_json") or "[]"))
    except json.JSONDecodeError as error:
        raise ValueError("stale reviewer execution finding IDs are invalid") from error
    required_failure_ids = {
        "CONTAINER-SCAN-EVIDENCE-NOT-RUN",
        "TEST-RUNNER-UNAVAILABLE",
    }
    root_problem_signature = str(failure.get("root_problem_signature") or "")
    if (
        str(failure.get("failure_class") or "") != "semantic"
        or str(failure.get("reason_code") or "") != "model_requested_repair"
        or str(failure.get("status") or "") != "OPEN"
        or str(failure.get("role") or "") != "security-reviewer"
        or str(failure.get("capability_profile") or "") != "reviewer_readonly"
        or str(failure.get("stage_key") or "") != "security-review"
        or str(failure.get("graph_status") or "") != "FAILED_SEMANTIC"
        or str(failure.get("task_status") or "") != "FAILED_SAFE"
        or str(failure.get("product_status") or "") != "IMPLEMENTING"
        or not isinstance(failed_gate_ids, list)
        or set(failed_gate_ids) != required_failure_ids
        or len(failed_gate_ids) != len(required_failure_ids)
        or any(
            failure_id not in str(failure.get("safe_message") or "")
            for failure_id in required_failure_ids
        )
        or not re.fullmatch(r"[a-f0-9]{64}", root_problem_signature)
    ):
        raise ValueError("failure is not the bounded stale reviewer execution defect")

    reviewer_task_id = str(failure["task_id"])
    contract_ref = str(failure.get("contract_ref") or "")
    contract_name = Path(contract_ref).name
    unresolved_contract_path = config.evidence_dir / contract_name
    contract_path = unresolved_contract_path.resolve()
    if (
        contract_ref
        not in {f"evidence/{contract_name}", str(unresolved_contract_path)}
        or contract_path.parent != config.evidence_dir.resolve()
        or unresolved_contract_path.is_symlink()
        or not contract_path.is_file()
    ):
        raise ValueError("stale reviewer execution contract reference is invalid")
    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("stale reviewer execution contract is unreadable") from error
    if not isinstance(contract, dict):
        raise TypeError("stale reviewer execution contract is invalid")
    schema_name = (
        "task-contract-v2.schema.json"
        if str(contract.get("schema_version") or "") == "2.0"
        else "task-contract.schema.json"
    )
    if ArtifactStore(config).validate(
        schema_name,
        contract,
    ):
        raise ValueError("stale reviewer execution contract is invalid")
    required_capabilities = {
        str(value)
        for value in contract.get("required_capabilities", [])
        if isinstance(value, str)
    }
    if (
        str(contract.get("task_id") or "") != reviewer_task_id
        or str(contract.get("product_id") or "") != product_id
        or int(contract.get("task_revision") or 0)
        != int(failure.get("task_revision") or 0)
        or "target-container-image-scan" not in contract.get("quality_gates", [])
        or not {"toolchain.container_builder", "toolchain.scanners"}.issubset(
            required_capabilities
        )
    ):
        raise ValueError("reviewer contract does not prove the corrected execution intent")

    budget_rows = _rows(
        state,
        """SELECT deterministic_actions_used,arbiter_calls_used,
                  execution_attempts_used,status
             FROM problem_budgets
            WHERE product_id=? AND root_problem_signature=?""",
        (product_id, root_problem_signature),
    )
    if len(budget_rows) != 1 or (
        int(budget_rows[0]["deterministic_actions_used"]),
        int(budget_rows[0]["arbiter_calls_used"]),
        int(budget_rows[0]["execution_attempts_used"]),
        str(budget_rows[0]["status"]),
    ) != (1, 1, 2, "ACTIVE"):
        raise ValueError("product problem budget changed before reviewer execution recovery")
    active_claims = _rows(
        state,
        """SELECT COUNT(*) AS count FROM tasks
            WHERE status='CLAIMED'
              AND (lease_until IS NULL OR lease_until >= ?)""",
        (utc_now(),),
    )
    if int(active_claims[0]["count"]):
        raise ValueError("stale reviewer execution recovery requires a drained controller")

    now = utc_now()
    with state._lock:
        state._connection.execute("BEGIN IMMEDIATE")
        try:
            current = state._connection.execute(
                """SELECT failure.status,reviewer.status,reviewer.graph_status,
                          reviewer.failure_id,reviewer.contract_ref,
                          reviewer.task_revision,product.status
                     FROM failures AS failure
                     JOIN tasks AS reviewer ON reviewer.task_id=failure.task_id
                     JOIN products AS product ON product.product_id=failure.product_id
                    WHERE failure.failure_id=? AND failure.product_id=?""",
                (failure_id, product_id),
            ).fetchone()
            if current is None or tuple(current) != (
                "OPEN",
                "FAILED_SAFE",
                "FAILED_SEMANTIC",
                failure_id,
                contract_ref,
                int(failure["task_revision"]),
                "IMPLEMENTING",
            ):
                raise ValueError("stale reviewer execution state changed before apply")
            budget = state._connection.execute(
                """SELECT deterministic_actions_used,arbiter_calls_used,
                          execution_attempts_used,status
                     FROM problem_budgets
                    WHERE product_id=? AND root_problem_signature=?""",
                (product_id, root_problem_signature),
            ).fetchone()
            if budget is None or tuple(budget) != (1, 1, 2, "ACTIVE"):
                raise ValueError("product problem budget changed before apply")
            state._connection.execute(
                "UPDATE failures SET status='RESOLVED',last_seen_at=? WHERE failure_id=?",
                (now, failure_id),
            )
            updated = state._connection.execute(
                """UPDATE tasks
                      SET status='PENDING',graph_status='READY',failure_id=NULL,
                          result_ref=NULL,result_digest=NULL,result_binding_id=NULL,
                          lease_owner=NULL,lease_until=NULL,lease_token=NULL,
                          heartbeat_at=NULL,available_at=NULL,
                          terminal_reason=NULL,terminal_detail=NULL,
                          failure_kind=NULL,blocked_reason=NULL,blocked_ref=NULL,
                          updated_at=?
                    WHERE task_id=? AND status='FAILED_SAFE'
                      AND graph_status='FAILED_SEMANTIC'
                      AND contract_ref=? AND task_revision=?""",
                (
                    now,
                    reviewer_task_id,
                    contract_ref,
                    int(failure["task_revision"]),
                ),
            ).rowcount
            if updated != 1:
                raise ValueError("stale reviewer execution recovery was not singular")
            incident_id = "incident-" + sha256_text(
                f"{failure_id}:stale-reviewer-execution"
            )[:20]
            state._connection.execute(
                """INSERT OR IGNORE INTO controller_incidents
                   (incident_id,product_id,task_id,reason_code,evidence_ref,
                    status,created_at,resolved_at)
                   VALUES (?, ?, ?,
                           'controller_stale_reviewer_contract_and_toolchain',
                           ?, 'RESOLVED', ?, ?)""",
                (
                    incident_id,
                    product_id,
                    reviewer_task_id,
                    f"internal://release/{correction_evidence_digest}",
                    now,
                    now,
                ),
            )
            state._connection.execute(
                """INSERT INTO recovery_applications
                   (recovery_plan_digest,product_id,recovery_task_id,status,applied_at)
                   VALUES (?, ?, ?, 'APPLIED', ?)""",
                (correction_digest, product_id, reviewer_task_id, now),
            )
            state._record_event(
                product_id,
                reviewer_task_id,
                "controller_stale_reviewer_execution_recovery_applied",
                {
                    "failure_id": failure_id,
                    "reviewer_contract_ref": contract_ref,
                    "task_revision": int(failure["task_revision"]),
                    "required_gate": "target-container-image-scan",
                    "root_problem_signature": root_problem_signature,
                    "correction_digest": correction_digest,
                    "product_budget_counters_preserved": True,
                },
            )
            state._connection.commit()
        except Exception:
            state._connection.rollback()
            raise
    return {
        "status": "PASS",
        "application_status": "APPLIED",
        "product_id": product_id,
        "recovery_task_id": reviewer_task_id,
        "reviewer_contract_ref": contract_ref,
        "task_revision": int(failure["task_revision"]),
        "root_problem_signature": root_problem_signature,
        "correction_digest": correction_digest,
        "product_budget_counters": {
            "deterministic_actions_used": 1,
            "arbiter_calls_used": 1,
            "execution_attempts_used": 2,
            "status": "ACTIVE",
        },
    }


def verify_active_graphs(
    config: FactoryConfig,
    state: StateStore,
) -> dict[str, Any]:
    results: list[dict[str, str]] = []
    for product in state.list_products():
        if str(product["status"]) in TERMINAL_PRODUCTS:
            continue
        product_id = str(product["product_id"])
        active_plan_id = str(product.get("active_plan_id") or "")
        plans = [
            item for item in state.list_plans(product_id) if str(item["plan_id"]) == active_plan_id
        ]
        if not plans:
            raise ValueError(f"active product has no plan: {product_id}")
        plan = plans[0]
        if plan.get("compiler_version"):
            ref = Path(str(plan["plan_artifact_ref"])).name
            path = config.evidence_dir / ref
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError(f"compiled plan artifact is invalid: {product_id}")
            validate_compiled_plan(payload)
            results.append({"product_id": product_id, "status": "COMPILED_VALID"})
            continue
        recovery_roots = [
            task
            for task in state.list_tasks(product_id)
            if task.get("role") == "replanner"
            and task.get("stage_key") == "semantic-lifecycle-recovery"
            and task.get("graph_status")
            in {"READY", "CLAIMED", "WAITING_TIME", "BLOCKED_CAPABILITY"}
        ]
        if len(recovery_roots) != 1:
            raise ValueError(f"legacy graph needs exactly one recovery root: {product_id}")
        results.append({"product_id": product_id, "status": "RECOVERY_ROOT_VALID"})
    return {"status": "PASS", "products": results}


def write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
