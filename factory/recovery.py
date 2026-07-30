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
from .plan_semantics import validate_compiled_plan
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


def build_recovery_plan(state: StateStore) -> dict[str, Any]:
    actions: list[dict[str, Any]] = []
    for product in state.list_products():
        product_id = str(product["product_id"])
        if str(product["status"]) in TERMINAL_PRODUCTS:
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
        latest_source = (
            supersede[-1]
            if supersede
            else preserve[-1]
            if preserve
            else str(tasks[-1]["task_id"])
            if tasks
            else f"T-ROOT-{sha256_text(product_id)[:12].upper()}"
        )
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
        "failure_id": None,
        "hypothesis_id": None,
        "supersedes_task_id": None,
        "title": "Recompile product into the semantic lifecycle",
        "objective": (
            "Return a semantic replan delta that preserves valid implementation "
            "evidence and changes the failed hypothesis before PlanCompiler creates "
            "the next controller-owned lifecycle revision."
        ),
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
                        graph_status, required_capabilities_json, mandatory,
                        critical_path_rank)
                       VALUES (?, ?, ?, 'replanner',
                               'plan-proposal-v1.schema.json', ?, 1000,
                        'PENDING', ?, ?, ?, ?,
                               'semantic-lifecycle-recovery', 0, ?, ?, ?, ?,
                               ?, ?, ?, ?, 'planning_readonly', ?, 'READY',
                               ?, 1, 0)""",
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
                resume_status = action.get("resume_status")
                if resume_status:
                    state._connection.execute(
                        "UPDATE products SET status=?, updated_at=? WHERE product_id=?",
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
