"""Controller-owned replan lineage and accepted semantic-node reuse."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .state import StateStore


@dataclass(frozen=True)
class ImplementationLineageNode:
    """Latest durable implementation contract for one semantic node key."""

    task_id: str
    plan_id: str
    plan_revision: int
    graph_status: str
    critical_path_rank: int
    proposal_node: dict[str, Any]
    result_ref: str
    result_digest: str


def _safe_artifact(evidence_dir: Path, reference: str) -> dict[str, Any]:
    name = Path(reference).name
    if reference not in {f"evidence/{name}", str(evidence_dir / name)}:
        return {}
    path = (evidence_dir / name).resolve()
    if path.parent != evidence_dir.resolve() or not path.is_file() or path.is_symlink():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if value in (None, ""):
        return []
    try:
        parsed = json.loads(str(value))
    except (TypeError, json.JSONDecodeError):
        return []
    return [str(item) for item in parsed if str(item)] if isinstance(parsed, list) else []


def plan_lineage(
    state: StateStore,
    product_id: str,
    active_plan_id: str,
) -> list[dict[str, Any]]:
    """Return the active plan followed by its immutable parent chain."""

    plans = {
        str(plan["plan_id"]): plan
        for plan in state.list_plans(product_id)
        if str(plan.get("plan_id") or "")
    }
    lineage: list[dict[str, Any]] = []
    current = active_plan_id
    visited: set[str] = set()
    while current and current not in visited:
        visited.add(current)
        plan = plans.get(current)
        if plan is None:
            if not lineage:
                product = state.get_product(product_id) or {}
                lineage.append(
                    {
                        "plan_id": current,
                        "revision": int(product.get("active_plan_revision") or 0),
                        "parent_plan_id": None,
                        "status": "LEGACY",
                    }
                )
            break
        lineage.append(plan)
        current = str(plan.get("parent_plan_id") or "")
    return lineage


def _semantic_key(row: dict[str, Any], contract: dict[str, Any]) -> str:
    return str(
        row.get("semantic_node_key")
        or contract.get("semantic_node_key")
        or contract.get("plan_node_id")
        or ""
    )


def implementation_lineage(
    state: StateStore,
    evidence_dir: Path,
    product_id: str,
    active_plan_id: str,
) -> list[ImplementationLineageNode]:
    """Select the latest contract for every semantic key across the plan lineage."""

    lineage = plan_lineage(state, product_id, active_plan_id)
    revision_by_plan = {
        str(plan["plan_id"]): int(plan.get("revision") or 0) for plan in lineage
    }
    if not revision_by_plan:
        return []
    rows = [
        row
        for row in state.list_tasks(product_id)
        if str(row.get("plan_id") or "") in revision_by_plan
        and str(row.get("stage_key") or "").startswith("implementation-")
    ]
    contracts = {
        str(row["task_id"]): _safe_artifact(
            evidence_dir,
            str(row.get("contract_ref") or ""),
        )
        for row in rows
    }
    rows_by_id = {str(row["task_id"]): row for row in rows}
    semantic_by_id = {
        task_id: _semantic_key(rows_by_id[task_id], contract)
        for task_id, contract in contracts.items()
    }
    dependencies_by_id: dict[str, list[str]] = {}
    for plan_id in revision_by_plan:
        for edge in state.list_edges(plan_id):
            if not bool(edge.get("required", True)):
                continue
            source_id = str(edge.get("from_task_id") or "")
            target_id = str(edge.get("to_task_id") or "")
            source_key = semantic_by_id.get(source_id, "")
            if source_key and target_id in rows_by_id:
                dependencies_by_id.setdefault(target_id, []).append(source_key)

    latest: dict[str, ImplementationLineageNode] = {}
    ordered_rows = sorted(
        rows,
        key=lambda row: (
            revision_by_plan[str(row.get("plan_id") or "")],
            int(row.get("task_revision") or 0),
            int(row.get("critical_path_rank") or 0),
            str(row.get("task_id") or ""),
        ),
        reverse=True,
    )
    for row in ordered_rows:
        task_id = str(row["task_id"])
        contract = contracts[task_id]
        node_key = semantic_by_id[task_id]
        if not contract or not node_key or node_key in latest:
            continue
        acceptance = contract.get("acceptance")
        proposal_node = {
            "node_key": node_key,
            "stage_kind": "implementation_slice",
            "title": str(contract.get("title") or row.get("title") or ""),
            "objective": str(contract.get("objective") or ""),
            "depends_on": sorted(set(dependencies_by_id.get(task_id, []))),
            "scope": _string_list(contract.get("allowed_paths")),
            "acceptance_intents": [
                str(item.get("verification") or "")
                for item in acceptance
                if isinstance(item, dict) and str(item.get("verification") or "")
            ]
            if isinstance(acceptance, list)
            else [],
            "goal_ids": _string_list(contract.get("goal_ids")),
        }
        if (
            not proposal_node["title"]
            or not proposal_node["objective"]
            or not proposal_node["scope"]
            or not proposal_node["acceptance_intents"]
            or not proposal_node["goal_ids"]
        ):
            continue
        latest[node_key] = ImplementationLineageNode(
            task_id=task_id,
            plan_id=str(row.get("plan_id") or ""),
            plan_revision=revision_by_plan[str(row.get("plan_id") or "")],
            graph_status=str(row.get("graph_status") or ""),
            critical_path_rank=int(row.get("critical_path_rank") or 0),
            proposal_node=proposal_node,
            result_ref=str(row.get("result_ref") or ""),
            result_digest=str(row.get("result_digest") or ""),
        )
    return sorted(
        latest.values(),
        key=lambda node: (
            node.plan_revision,
            node.critical_path_rank,
            str(node.proposal_node["node_key"]),
        ),
    )


def accepted_stage_task_id(
    state: StateStore,
    product_id: str,
    active_plan_id: str,
    stage_key: str,
) -> str | None:
    """Return the newest accepted task for a lifecycle stage in this lineage."""

    lineage = plan_lineage(state, product_id, active_plan_id)
    revision_by_plan = {
        str(plan["plan_id"]): int(plan.get("revision") or 0) for plan in lineage
    }
    candidates = [
        row
        for row in state.list_tasks(product_id)
        if str(row.get("plan_id") or "") in revision_by_plan
        and str(row.get("lifecycle_stage") or row.get("stage_key") or "") == stage_key
        and str(row.get("graph_status") or "") == "ACCEPTED"
        and str(row.get("result_ref") or "")
        and str(row.get("result_digest") or "")
    ]
    if not candidates:
        return None
    selected = max(
        candidates,
        key=lambda row: (
            revision_by_plan[str(row.get("plan_id") or "")],
            int(row.get("task_revision") or 0),
            str(row.get("task_id") or ""),
        ),
    )
    return str(selected["task_id"])


def architecture_source_task_id(
    state: StateStore,
    product_id: str,
    active_plan_id: str,
) -> str | None:
    """Return the newest accepted producer of the architecture package."""

    lineage_plan_ids = {
        str(plan["plan_id"])
        for plan in plan_lineage(state, product_id, active_plan_id)
    }
    candidates: list[dict[str, Any]] = []
    for row in state.list_tasks(product_id):
        if (
            str(row.get("plan_id") or "") not in lineage_plan_ids
            or str(row.get("graph_status") or "") != "ACCEPTED"
            or not str(row.get("result_ref") or "")
            or not str(row.get("result_digest") or "")
        ):
            continue
        produced = _string_list(row.get("produces_evidence_types_json"))
        if "architecture_package" in produced or str(row.get("role") or "") == (
            "solution-architect"
        ):
            candidates.append(row)
    if not candidates:
        return None
    selected = max(
        candidates,
        key=lambda row: (
            int(row.get("task_revision") or 0),
            str(row.get("updated_at") or ""),
            str(row.get("task_id") or ""),
        ),
    )
    return str(selected["task_id"])
