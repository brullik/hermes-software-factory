"""Digest-bound, idempotent recovery of durable product state."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .artifacts import ArtifactStore
from .autonomy import CAPABILITY_PROFILES
from .common import sha256_text, stable_json, utc_now
from .config import FactoryConfig
from .path_governor import PathGovernor
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
                        action="CONTROLLER_RECOVERY",
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
                    state._connection.execute(
                        """UPDATE products
                              SET status=?, terminal_reason=NULL, updated_at=?
                            WHERE product_id=?""",
                        (str(resume_status), now, product_id),
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
                      AND action='CONTROLLER_RECOVERY' AND status='APPLIED'
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
