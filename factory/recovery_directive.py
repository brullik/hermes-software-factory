"""Controller-owned typed scope recovery directives."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .common import sha256_text, stable_json
from .config import FactoryConfig
from .policy import policy_digest
from .repair_scope import derive_scope_required_paths, infer_unique_test_source_paths
from .state import StateStore

_CONTROL_GATE_IDS = {
    "needs_replan",
    "model_requested_repair",
    "plan_contract_violation",
    "MODEL_REPAIR_REQUIRED",
    "PLAN_CONTRACT_VIOLATION",
}


def _json_object(value: object) -> dict[str, Any]:
    try:
        parsed = json.loads(str(value or "{}"))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _json_list(value: object) -> list[Any]:
    try:
        parsed = json.loads(str(value or "[]"))
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def build_scope_recovery_directive(
    config: FactoryConfig,
    state: StateStore,
    failures: Sequence[Mapping[str, Any]],
    *,
    product_id: str,
    source_failure_id: str,
    forbidden_paths: Sequence[str] = (),
    repository_root: Path | None = None,
) -> dict[str, Any]:
    """Build one compact, stable directive from a single causal chain."""

    by_id = {
        str(failure.get("failure_id") or ""): failure
        for failure in failures
        if str(failure.get("failure_id") or "")
    }
    chain: list[Mapping[str, Any]] = []
    failure_id = source_failure_id
    visited: set[str] = set()
    while failure_id and failure_id not in visited and len(chain) < 24:
        visited.add(failure_id)
        failure = by_id.get(failure_id)
        if failure is None:
            break
        chain.append(failure)
        failure_id = str(failure.get("parent_failure_id") or "")

    required_paths: list[str] = []
    failed_allowed_paths: list[str] = []
    failed_gate_ids: list[str] = []
    causal_task_ids: list[str] = []
    causal_tasks: list[Mapping[str, Any]] = []
    for failure in chain:
        actual = _json_object(failure.get("actual_json"))
        required_paths.extend(derive_scope_required_paths(actual))
        if actual.get("scope_reassessment_required") is True:
            blocked = actual.get("blocked_allowed_paths", [])
            if isinstance(blocked, list):
                failed_allowed_paths.extend(
                    str(value)
                    for value in blocked
                    if isinstance(value, str) and value
                )
            coordinates = actual.get("diagnostic_scope_coordinates", [])
            if (
                repository_root is not None
                and isinstance(coordinates, list)
                and isinstance(blocked, list)
            ):
                required_paths.extend(
                    infer_unique_test_source_paths(
                        repository_root,
                        [
                            str(value)
                            for value in coordinates
                            if isinstance(value, str) and value
                        ],
                        [
                            str(value)
                            for value in blocked
                            if isinstance(value, str) and value
                        ],
                    )
                )
        failed_gate_ids.extend(
            str(value)
            for value in _json_list(failure.get("failed_gate_ids_json"))
            if isinstance(value, str) and value and value not in _CONTROL_GATE_IDS
        )
        task_id = str(failure.get("task_id") or "")
        if task_id:
            causal_task_ids.append(task_id)
            task = state.get_task(task_id)
            if task is not None:
                causal_tasks.append(task)

    affected_product_task = next(
        (
            task for task in causal_tasks if str(task.get("role") or "") == "builder"
        ),
        next(
            (
                task
                for task in causal_tasks
                if str(task.get("role") or "")
                not in {"replanner", "incident-recovery"}
            ),
            causal_tasks[0] if causal_tasks else {},
        ),
    )
    affected_key = str(
        affected_product_task.get("semantic_node_key")
        or affected_product_task.get("plan_node_id")
        or affected_product_task.get("stage_key")
        or ""
    ).casefold()
    required_paths = list(dict.fromkeys(required_paths))
    failed_allowed_paths = list(dict.fromkeys(failed_allowed_paths))
    failed_gate_ids = list(dict.fromkeys(failed_gate_ids))
    affected_keys = [affected_key] if affected_key else []
    root_failure_id = str(chain[-1].get("failure_id") or "") if chain else ""
    root_problem_signature = sha256_text(
        stable_json(
            [
                "scope_reassessment",
                product_id,
                policy_digest(config),
                sorted(required_paths),
                sorted(affected_keys),
                sorted(failed_gate_ids),
            ]
        )
    )
    definition_of_done = [
        *(
            f"fresh {gate_id} PASS evidence"
            for gate_id in failed_gate_ids
        ),
        *(
            f"future implementation scope includes {path}"
            for path in required_paths
        ),
    ]
    return {
        "root_problem_signature": root_problem_signature,
        "root_failure_id": root_failure_id,
        "latest_failure_id": str(chain[0].get("failure_id") or "") if chain else "",
        "affected_semantic_node_keys": affected_keys,
        "failed_mandatory_gate_ids": failed_gate_ids,
        "failed_allowed_paths": failed_allowed_paths,
        "required_scope_paths": required_paths,
        "forbidden_paths": list(dict.fromkeys(str(value) for value in forbidden_paths)),
        "allow_bounded_expansion": bool(required_paths),
        "definition_of_done": definition_of_done,
        "causal_failure_ids": [
            str(failure.get("failure_id") or "")
            for failure in chain
            if str(failure.get("failure_id") or "")
        ],
        "causal_task_ids": list(dict.fromkeys(causal_task_ids)),
        "current_task_allowed_paths_semantics": "planning_artifact_write_scope_only",
        "proposal_scope_field": "slices[].scope",
    }
