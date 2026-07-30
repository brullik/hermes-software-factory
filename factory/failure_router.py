"""Generic causal failure router for repair, replan, and controller incidents."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .artifacts import ArtifactStore
from .autonomy import CAPABILITY_PROFILES
from .common import sha256_text, stable_json
from .config import FactoryConfig
from .registry import SchemaRegistry
from .repair_brief import repair_requirements
from .state import StateStore

_REPLAN_REASONS = {
    "needs_replan",
    "scope_contradiction",
    "architecture_impossible",
    "invalid_capability_contract",
    "invalid_quality_gate_contract",
    "plan_contract_violation",
    "missing_declared_predecessor",
    "evidence_profile_mismatch",
    "completion_unreachable",
    "toolchain_capability_missing",
    "liveness_invariant_violation",
    "repeated_hypothesis",
}
_CONTROLLER_PREFIXES = (
    "worker_",
    "controller_",
    "migration_",
    "artifact_",
    "repair_requeue_",
)
_MAX_CONTROLLER_RECOVERY_DEPTH = 3


class FailureRouter:
    def __init__(
        self,
        config: FactoryConfig,
        state: StateStore,
        artifacts: ArtifactStore | None = None,
    ) -> None:
        self.config = config
        self.state = state
        self.artifacts = artifacts or ArtifactStore(config)
        self.schemas = SchemaRegistry(config, self.artifacts)

    def _same_role_problem_count(
        self,
        failure: dict[str, Any],
        failed: dict[str, Any],
    ) -> int:
        """Count an identical causal problem without using task-specific IDs."""

        failures = {
            str(item["failure_id"]): item
            for item in self.state.list_failures(str(failed["product_id"]))
        }

        def signature(item: dict[str, Any]) -> str:
            try:
                failed_gates = sorted(
                    str(value)
                    for value in json.loads(
                        str(item.get("failed_gate_ids_json") or "[]")
                    )
                )
            except (TypeError, json.JSONDecodeError):
                failed_gates = []
            return sha256_text(
                stable_json(
                    [
                        item.get("failure_class"),
                        item.get("reason_code"),
                        item.get("safe_message"),
                        item.get("exception_type"),
                        failed_gates,
                    ]
                )
            )

        expected_signature = signature(failure)
        expected_role = str(failed.get("role") or "")
        count = 0
        failure_id = str(failure["failure_id"])
        seen: set[str] = set()
        while failure_id and failure_id not in seen:
            seen.add(failure_id)
            item = failures.get(failure_id)
            if item is None:
                break
            task = self.state.get_task(str(item.get("task_id") or ""))
            if (
                task is not None
                and str(task.get("role") or "") == expected_role
                and signature(item) == expected_signature
            ):
                count += 1
            failure_id = str(item.get("parent_failure_id") or "")
        return count

    def _contract(self, task: dict[str, Any]) -> dict[str, Any]:
        reference = str(task.get("contract_ref") or "")
        task_id = str(task.get("task_id") or "")
        candidates = [self.config.evidence_dir / Path(reference).name]
        if re.fullmatch(r"T-[A-Z0-9_-]{4,}", task_id):
            candidates.append(self.config.evidence_dir / f"task-{task_id}.json")
        inspected: set[Path] = set()
        for path in candidates:
            if path in inspected or not path.is_file():
                continue
            inspected.add(path)
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            if (
                isinstance(payload, dict)
                and str(payload.get("task_id") or "") == task_id
                and str(payload.get("product_id") or "")
                == str(task.get("product_id") or "")
            ):
                return payload
        readonly = str(task.get("capability_profile") or "") in {
            "planning_readonly",
            "reviewer_readonly",
        }
        return {
            "_reconstructed": True,
            "acceptance": [
                {
                    "criterion_id": (
                        "reconstruct-"
                        + sha256_text(
                            f"{task.get('product_id')}:{task_id}:task-contract"
                        )[:16]
                    ),
                    "verification": (
                        "Reconstruct this plan node from durable task metadata "
                        "and the active plan, then prove every mandatory active-plan "
                        "completion criterion before acceptance."
                    ),
                    "mandatory": True,
                }
            ],
            "allowed_paths": ["artifacts/**"] if readonly else ["**"],
        }

    def _record_contract_reconstruction(
        self,
        *,
        failed: dict[str, Any],
        failure: dict[str, Any],
    ) -> None:
        task_id = str(failed["task_id"])
        coordinate = sha256_text(
            stable_json(
                [
                    failed["product_id"],
                    task_id,
                    failed.get("contract_ref"),
                ]
            )
        )
        incident_id = f"incident-{coordinate[:20]}"
        with self.state._lock, self.state._connection:
            inserted = self.state._connection.execute(
                """
                INSERT OR IGNORE INTO controller_incidents
                    (incident_id, product_id, task_id, reason_code,
                     evidence_ref, status, created_at, resolved_at)
                VALUES (?, ?, ?, 'artifact_task_contract_reconstructed',
                        ?, 'RESOLVED', ?, ?)
                """,
                (
                    incident_id,
                    failed["product_id"],
                    task_id,
                    f"state://task-contract/{coordinate[:20]}",
                    failure["last_seen_at"],
                    failure["last_seen_at"],
                ),
            ).rowcount
            if inserted:
                self.state._record_event(
                    str(failed["product_id"]),
                    task_id,
                    "task_contract_reconstructed",
                    {
                        "incident_id": incident_id,
                        "failure_id": str(failure["failure_id"]),
                        "coordinate": coordinate[:20],
                    },
                )

    @staticmethod
    def _acceptance(contract: dict[str, Any]) -> list[dict[str, Any]]:
        values = contract.get("acceptance", [])
        if not isinstance(values, list) or not values:
            raise RuntimeError("failed task acceptance is unavailable")
        return [
            {
                "criterion_id": str(item["criterion_id"]),
                "verification": str(item["verification"]),
                "mandatory": bool(item.get("mandatory", True)),
            }
            for item in values
            if isinstance(item, dict)
        ]

    @staticmethod
    def _controller_incident_acceptance() -> list[dict[str, Any]]:
        """Keep controller recovery separate from product-semantic acceptance."""

        return [
            {
                "criterion_id": "AC-CONTROLLER-INCIDENT-CONTAINMENT",
                "verification": (
                    "The supplied controller incident is explicitly contained or "
                    "recovered using only allowlisted, non-destructive actions; "
                    "the result states when no production mutation was required."
                ),
                "mandatory": True,
            },
            {
                "criterion_id": "AC-CONTROLLER-INCIDENT-EVIDENCE",
                "verification": (
                    "The IncidentResult binds containment, data-integrity status, "
                    "and root-cause or validation-plan claims to supplied safe "
                    "controller evidence without inventing product findings."
                ),
                "mandatory": True,
            },
            {
                "criterion_id": "AC-CONTROLLER-INCIDENT-NEXT-STEP",
                "verification": (
                    "The result identifies a bounded controller recovery, repair, "
                    "or retry path and does not require the incident-recovery role "
                    "to prove the failed product task's semantic acceptance."
                ),
                "mandatory": True,
            },
        ]

    @staticmethod
    def _controller_replan_acceptance() -> list[dict[str, Any]]:
        """Require fresh product evidence after a contained controller incident."""

        return [
            {
                "criterion_id": "AC-CONTROLLER-REPLAN-AFFECTED-NODE",
                "verification": (
                    "Plan revision N+1 retries or replaces the affected product "
                    "node and requires fresh product-semantic evidence; an "
                    "IncidentResult is not reused as proof that the product node passed."
                ),
                "mandatory": True,
            },
            {
                "criterion_id": "AC-CONTROLLER-REPLAN-PRESERVE-ACCEPTED",
                "verification": (
                    "The plan preserves accepted unaffected implementation and "
                    "lifecycle evidence while invalidating only the affected causal path."
                ),
                "mandatory": True,
            },
            {
                "criterion_id": "AC-CONTROLLER-REPLAN-BOUNDED",
                "verification": (
                    "The plan is bound to the supplied controller failure chain, "
                    "uses a bounded scope, and does not invent a product finding."
                ),
                "mandatory": True,
            },
        ]

    @staticmethod
    def _row_required_capabilities(task: dict[str, Any]) -> list[str]:
        try:
            values = json.loads(str(task.get("required_capabilities_json") or "[]"))
        except json.JSONDecodeError:
            return []
        if not isinstance(values, list):
            return []
        return [str(value) for value in values if isinstance(value, str) and value]

    def _lineage_required_capabilities(
        self,
        failed: dict[str, Any],
        capability_profile: str,
    ) -> list[str]:
        """Preserve controller-granted tools when routing an exact-node repair."""

        required = set(CAPABILITY_PROFILES[capability_profile])
        current: dict[str, Any] | None = failed
        seen: set[str] = set()
        while current is not None and len(seen) < 64:
            task_id = str(current.get("task_id") or "")
            if not task_id or task_id in seen:
                break
            seen.add(task_id)
            required.update(self._row_required_capabilities(current))
            parent_id = str(current.get("parent_task_id") or "")
            if not parent_id:
                break
            parent = self.state.get_task(parent_id)
            if (
                parent is None
                or str(parent.get("product_id") or "")
                != str(failed.get("product_id") or "")
            ):
                break
            current = parent
        return sorted(required)

    def _write_contract(
        self,
        *,
        failed: dict[str, Any],
        failure: dict[str, Any],
        hypothesis_id: str | None,
        role: str,
        output_schema: str,
        capability_profile: str,
        objective: str,
        allowed_paths: list[str],
        task_revision: int,
        node_suffix: str,
        required_capabilities: list[str] | None = None,
        acceptance: list[dict[str, Any]] | None = None,
    ) -> tuple[dict[str, Any], Path]:
        task_id = (
            "T-"
            + sha256_text(
                f"{failed['task_id']}:{failure['failure_id']}:{node_suffix}:{task_revision}"
            )[:16].upper()
        )
        contract_ref = f"evidence/task-{task_id}.json"
        contract = {
            "schema_version": "2.0",
            "artifact_id": f"task-contract-{task_id}",
            "product_id": str(failed["product_id"]),
            "task_id": task_id,
            "root_task_id": str(failed["root_task_id"]),
            "parent_task_id": str(failed["task_id"]),
            "source_task_id": str(failed["task_id"]),
            "plan_id": str(failed["plan_id"]),
            "plan_node_id": f"{failed['plan_node_id']}:{node_suffix}",
            "task_revision": task_revision,
            "root_context_ref": str(failed["root_context_ref"]),
            "active_context_ref": contract_ref,
            "failure_id": str(failure["failure_id"]),
            "hypothesis_id": hypothesis_id,
            "supersedes_task_id": str(failed["task_id"]),
            "title": (
                "Replan affected product graph"
                if role == "replanner"
                else f"Repair {failed['title']}"
            ),
            "objective": objective,
            "role": role,
            "output_schema": output_schema,
            "dependencies": [],
            "conflict_keys": (
                []
                if capability_profile == "planning_readonly"
                else json.loads(str(failed.get("conflict_keys_json") or "[]"))
            ),
            "acceptance": (
                [dict(item) for item in acceptance]
                if acceptance is not None
                else self._acceptance(self._contract(failed))
            ),
            "required_capabilities": list(
                required_capabilities
                if required_capabilities is not None
                else CAPABILITY_PROFILES[capability_profile]
            ),
            "capability_profile": capability_profile,
            "allowed_paths": allowed_paths or ["artifacts/**"],
            "forbidden_paths": ["secrets/**", "production/**"],
            "risk_tier": "medium",
            "model_floor": "terra",
            "idempotency_key": sha256_text(
                f"failure-route:{failure['failure_id']}:{node_suffix}:{task_revision}"
            ),
            "status": "READY",
            "priority": int(failed.get("priority") or 0) + 10,
            "critical_path_rank": 0,
        }
        self.schemas.validate("task-contract-v2.schema.json", contract)
        path = self.artifacts.write(
            "task-contract-v2.schema.json",
            contract,
            filename=f"task-{task_id}.json",
        )
        return contract, path

    def _write_repair_brief(
        self,
        *,
        failed: dict[str, Any],
        failure: dict[str, Any],
        hypothesis_id: str,
        parent_hypothesis_id: str | None,
        repair_task_id: str,
        allowed_paths: list[str],
        acceptance: list[dict[str, Any]] | None = None,
    ) -> Path:
        original = self._contract(failed)
        inherited_acceptance = (
            [dict(item) for item in acceptance]
            if acceptance is not None
            else self._acceptance(original)
        )
        try:
            actual = json.loads(str(failure.get("actual_json") or "{}"))
        except json.JSONDecodeError:
            actual = {}
        required_fixes = actual.get("required_fixes", [])
        if not isinstance(required_fixes, list):
            required_fixes = []
        try:
            raw_failed_gate_ids = json.loads(
                str(failure.get("failed_gate_ids_json") or "[]")
            )
        except json.JSONDecodeError:
            raw_failed_gate_ids = []
        if not isinstance(raw_failed_gate_ids, list):
            raw_failed_gate_ids = []
        failed_gate_ids, fallback_fixes = repair_requirements(
            output=None,
            reason_code=str(failure.get("reason_code") or "internal_blocker"),
            detail=str(failure.get("safe_message") or "repair required"),
            failed_gate_ids=raw_failed_gate_ids,
        )
        actionable_fixes = [
            str(value) for value in required_fixes if str(value).strip()
        ]
        if not actionable_fixes:
            actionable_fixes = fallback_fixes
        brief = {
            "schema_version": "2.0",
            "artifact_id": (
                "repair-brief-"
                + sha256_text(
                    stable_json(
                        [
                            failure["failure_id"],
                            hypothesis_id,
                            repair_task_id,
                        ]
                    )
                )[:20]
            ),
            "product_id": str(failed["product_id"]),
            "task_id": repair_task_id,
            "root_task_id": str(failed["root_task_id"]),
            "failed_task_id": str(failed["task_id"]),
            "failure_id": str(failure["failure_id"]),
            "hypothesis_id": hypothesis_id,
            "parent_hypothesis_id": parent_hypothesis_id,
            "plan_id": str(failed["plan_id"]),
            "plan_node_id": str(failed["plan_node_id"]),
            "inherited_goal_ref": str(failed["root_context_ref"]),
            "inherited_acceptance": inherited_acceptance,
            "failed_gate_ids": failed_gate_ids,
            "required_fixes": [
                *actionable_fixes,
                str(failure["safe_message"]),
                "Prove every inherited acceptance criterion with fresh evidence.",
            ],
            "evidence_refs": [str(failure["evidence_ref"])],
            "allowed_paths": allowed_paths or ["artifacts/**"],
            "capability_gaps": [],
            "supersedes_task_id": str(failed["task_id"]),
            "definition_of_done": [
                str(item["verification"]) for item in inherited_acceptance
            ],
        }
        return self.artifacts.write(
            "repair-brief-v2.schema.json",
            brief,
            filename=f"repair-brief-{repair_task_id}.json",
        )

    def _active_plan_id(self, product_id: str) -> str | None:
        row = self.state._connection.execute(
            """
            SELECT products.active_plan_id
              FROM products
              JOIN plans
                ON plans.plan_id=products.active_plan_id
               AND plans.product_id=products.product_id
             WHERE products.product_id=? AND plans.status='ACTIVE'
            """,
            (product_id,),
        ).fetchone()
        return str(row[0]) if row is not None and row[0] else None

    def _controller_recovery_depth(self, task: dict[str, Any]) -> int:
        """Count the bounded causal chain of controller-recovery tasks."""

        depth = 0
        current = task
        visited: set[str] = set()
        while str(current.get("role") or "") == "incident-recovery":
            task_id = str(current.get("task_id") or "")
            if not task_id or task_id in visited:
                break
            visited.add(task_id)
            depth += 1
            parent_id = str(
                current.get("parent_task_id")
                or current.get("source_task_id")
                or ""
            )
            if not parent_id:
                break
            parent = self.state._connection.execute(
                "SELECT * FROM tasks WHERE task_id=? AND product_id=?",
                (parent_id, current["product_id"]),
            ).fetchone()
            if parent is None:
                break
            current = dict(parent)
        return depth

    def _invalid_plan_output_schema(
        self,
        *,
        failure: dict[str, Any],
        failed: dict[str, Any],
    ) -> bool:
        if str(failure.get("reason_code") or "") != (
            "controller_exception_file_not_found_error"
        ):
            return False
        output_schema = str(failed.get("output_schema") or "")
        if (
            not output_schema
            or Path(output_schema).name != output_schema
            or not output_schema.endswith(".schema.json")
        ):
            return False
        safe_path = str(failure.get("safe_message") or "").replace("\\", "/")
        return (
            safe_path.endswith(f"/schemas/{output_schema}")
            and not (self.config.schema_root() / output_schema).is_file()
        )

    def _reanchor_routed_task(
        self,
        *,
        failure: dict[str, Any],
        routed: dict[str, Any],
        active_plan_id: str,
    ) -> str:
        anchored = dict(routed)
        anchored["plan_id"] = active_plan_id
        original = self._contract(routed)
        allowed_paths = [
            str(value)
            for value in original.get("allowed_paths", ["artifacts/**"])
        ]
        role = str(routed.get("role") or "replanner")
        output_schema = str(
            routed.get("output_schema") or "plan-proposal-v1.schema.json"
        )
        capability_profile = str(
            routed.get("capability_profile") or "planning_readonly"
        )
        contract, path = self._write_contract(
            failed=anchored,
            failure=failure,
            hypothesis_id=(
                str(routed["hypothesis_id"])
                if routed.get("hypothesis_id")
                else None
            ),
            role=role,
            output_schema=output_schema,
            capability_profile=capability_profile,
            objective=(
                "Continue the routed recovery on the current active plan. "
                "Preserve the complete causal lineage and create executable work."
            ),
            allowed_paths=allowed_paths,
            task_revision=int(routed.get("task_revision") or 1) + 1,
            node_suffix="active-plan-reanchor",
            required_capabilities=(
                self._lineage_required_capabilities(
                    routed,
                    capability_profile,
                )
                if role != "replanner"
                else None
            ),
        )
        task_id = str(contract["task_id"])
        if self.state.get_task(task_id) is None:
            self.state.add_task(
                task_id=task_id,
                product_id=str(routed["product_id"]),
                title=str(contract["title"]),
                role=role,
                output_schema=output_schema,
                contract_ref=f"evidence/{path.name}",
                stage_key="active-plan-reanchor",
                dependencies=[],
                conflict_keys=[
                    str(value) for value in contract["conflict_keys"]
                ],
                priority=int(contract["priority"]),
                root_task_id=str(contract["root_task_id"]),
                parent_task_id=str(contract["parent_task_id"]),
                source_task_id=str(contract["source_task_id"]),
                plan_id=active_plan_id,
                plan_node_id=str(contract["plan_node_id"]),
                task_revision=int(contract["task_revision"]),
                root_context_ref=str(contract["root_context_ref"]),
                active_context_ref=str(contract["active_context_ref"]),
                failure_id=str(failure["failure_id"]),
                hypothesis_id=(
                    str(contract["hypothesis_id"])
                    if contract.get("hypothesis_id")
                    else None
                ),
                capability_profile=capability_profile,
                idempotency_key=str(contract["idempotency_key"]),
                supersedes_task_id=str(routed["task_id"]),
                required_capabilities=[
                    str(value)
                    for value in contract["required_capabilities"]
                ],
                graph_status="READY",
            )
        with self.state._lock, self.state._connection:
            self.state._connection.execute(
                """
                UPDATE tasks
                   SET status='DONE', graph_status='SUPERSEDED',
                       lease_owner=NULL, lease_until=NULL, lease_token=NULL,
                       heartbeat_at=NULL, available_at=NULL, updated_at=?
                 WHERE task_id=?
                   AND graph_status NOT IN ('ACCEPTED','CANCELLED','SUPERSEDED')
                """,
                (failure["last_seen_at"], routed["task_id"]),
            )
            self.state._record_event(
                str(routed["product_id"]),
                task_id,
                "recovery_task_reanchored",
                {
                    "failure_id": str(failure["failure_id"]),
                    "supersedes_task_id": str(routed["task_id"]),
                    "active_plan_id": active_plan_id,
                },
            )
        return task_id

    def route(self, failure_id: str) -> str:
        with self.state._lock:
            failure_row = self.state._connection.execute(
                "SELECT * FROM failures WHERE failure_id=?", (failure_id,)
            ).fetchone()
            if failure_row is None:
                raise KeyError(failure_id)
            failure = dict(failure_row)
            if str(failure["status"]) == "ROUTED":
                routed = self.state._connection.execute(
                    "SELECT * FROM tasks WHERE failure_id=? "
                    "ORDER BY created_at DESC LIMIT 1",
                    (failure_id,),
                ).fetchone()
                if routed is None:
                    return ""
                routed_task = dict(routed)
                active_plan_id = self._active_plan_id(
                    str(routed_task["product_id"])
                )
                if (
                    active_plan_id
                    and str(routed_task.get("plan_id") or "")
                    != active_plan_id
                    and str(routed_task.get("graph_status") or "")
                    not in {"ACCEPTED", "CANCELLED", "SUPERSEDED"}
                ):
                    return self._reanchor_routed_task(
                        failure=failure,
                        routed=routed_task,
                        active_plan_id=active_plan_id,
                    )
                return str(routed_task["task_id"])
            failed_row = self.state._connection.execute(
                "SELECT * FROM tasks WHERE task_id=?", (failure["task_id"],)
            ).fetchone()
            if failed_row is None:
                raise RuntimeError("failure source task is missing")
            failed = dict(failed_row)
            reason = str(failure["reason_code"])
            active_plan_id = self._active_plan_id(str(failed["product_id"]))
            if active_plan_id:
                failed["plan_id"] = active_plan_id
            invalid_plan_output_schema = self._invalid_plan_output_schema(
                failure=failure,
                failed=failed,
            )
            if invalid_plan_output_schema:
                resolved_incidents = self.state._connection.execute(
                    """
                    UPDATE controller_incidents
                       SET status='RESOLVED', resolved_at=?
                     WHERE product_id=? AND task_id=? AND reason_code=?
                       AND status='OPEN'
                    """,
                    (
                        failure["last_seen_at"],
                        failed["product_id"],
                        failed["task_id"],
                        reason,
                    ),
                ).rowcount
                if resolved_incidents:
                    self.state._record_event(
                        str(failed["product_id"]),
                        str(failed["task_id"]),
                        "invalid_output_schema_incident_resolved",
                        {
                            "failure_id": failure_id,
                            "resolved_incidents": resolved_incidents,
                        },
                    )
            controller_recovery_depth = self._controller_recovery_depth(failed)
            controller_handoff = (
                str(failed.get("role") or "") == "incident-recovery"
                and reason == "needs_replan"
            )
            controller_fault = (
                not invalid_plan_output_schema
                and not controller_handoff
                and controller_recovery_depth < _MAX_CONTROLLER_RECOVERY_DEPTH
                and (
                    str(failure["failure_class"]) in {"controller", "transient"}
                    or reason.startswith(_CONTROLLER_PREFIXES)
                )
            )
            hypothesis = None
            hypothesis_id: str | None = None
            attempts_used = 0
            same_role_problem_count = 0
            if not controller_fault and not controller_handoff:
                same_role_problem_count = self._same_role_problem_count(
                    dict(failure),
                    dict(failed),
                )
                inherited_hypothesis_id = str(
                    failed.get("hypothesis_id") or ""
                )
                if inherited_hypothesis_id:
                    hypothesis = self.state._connection.execute(
                        """SELECT * FROM hypotheses
                           WHERE hypothesis_id=? AND status='ACTIVE'""",
                        (inherited_hypothesis_id,),
                    ).fetchone()
                if hypothesis is None:
                    hypothesis = self.state._connection.execute(
                        """SELECT * FROM hypotheses
                           WHERE failure_id=? AND status='ACTIVE'
                           ORDER BY created_at DESC LIMIT 1""",
                        (failure_id,),
                    ).fetchone()
                if hypothesis is None:
                    signature = sha256_text(
                        stable_json(
                            [
                                failed["product_id"],
                                failure["reason_code"],
                                failure["fingerprint"],
                            ]
                        )
                    )
                    hypothesis_id = f"hypothesis-{signature[:20]}"
                    self.state._connection.execute(
                        """INSERT OR IGNORE INTO hypotheses
                           (hypothesis_id, product_id, failure_id, signature,
                            statement, required_evidence_json, status,
                            semantic_budget, attempts_used, created_at)
                           VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', 3, 0, ?)""",
                        (
                            hypothesis_id,
                            failed["product_id"],
                            failure_id,
                            signature,
                            failure["safe_message"],
                            stable_json([failure["evidence_ref"]]),
                            failure["first_seen_at"],
                        ),
                    )
                else:
                    hypothesis_id = str(hypothesis["hypothesis_id"])
                    attempts_used = int(hypothesis["attempts_used"] or 0)
            needs_replan = (
                invalid_plan_output_schema
                or controller_handoff
                or reason in _REPLAN_REASONS
                or attempts_used >= 3
                or same_role_problem_count >= 2
                or controller_recovery_depth >= _MAX_CONTROLLER_RECOVERY_DEPTH
            )
            if controller_fault:
                incident_id = f"incident-{sha256_text(failure_id)[:20]}"
                self.state._connection.execute(
                    """INSERT OR IGNORE INTO controller_incidents
                       (incident_id, product_id, task_id, reason_code,
                        evidence_ref, status, created_at)
                       VALUES (?, ?, ?, ?, ?, 'OPEN', ?)""",
                    (
                        incident_id,
                        failed["product_id"],
                        failed["task_id"],
                        reason,
                        failure["evidence_ref"],
                        failure["first_seen_at"],
                    ),
                )
                role = "incident-recovery"
                output_schema = "incident-result.schema.json"
                capability_profile = "controller_incident"
                suffix = "controller-incident"
                objective = (
                    "Repair the controller invariant using the exact safe failure "
                    "evidence; do not consume a product semantic budget."
                )
            elif needs_replan:
                if (
                    attempts_used >= 3
                    or same_role_problem_count >= 2
                    or controller_recovery_depth >= _MAX_CONTROLLER_RECOVERY_DEPTH
                ):
                    assert hypothesis_id is not None
                    self.state._connection.execute(
                        """UPDATE hypotheses SET status='EXHAUSTED', closed_at=?
                           WHERE hypothesis_id=?""",
                        (failure["last_seen_at"], hypothesis_id),
                    )
                    parent_hypothesis_id = hypothesis_id
                    reassessment_signature = sha256_text(
                        stable_json(
                            [
                                parent_hypothesis_id,
                                failure_id,
                                "director-diagnosis-reassessment",
                                same_role_problem_count,
                            ]
                        )
                    )
                    hypothesis_id = (
                        f"hypothesis-{reassessment_signature[:20]}"
                    )
                    self.state._connection.execute(
                        """INSERT OR IGNORE INTO hypotheses
                           (hypothesis_id, product_id, failure_id,
                            parent_hypothesis_id, signature, statement,
                            required_evidence_json, status, semantic_budget,
                            attempts_used, created_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 3, 0, ?)""",
                        (
                            hypothesis_id,
                            failed["product_id"],
                            failure_id,
                            parent_hypothesis_id,
                            reassessment_signature,
                            "Director diagnosis reassessment after exhausted hypothesis",
                            stable_json([failure["evidence_ref"]]),
                            failure["last_seen_at"],
                        ),
                    )
                    suffix = "diagnosis-reassessment"
                else:
                    suffix = "replan"
                role = "replanner"
                output_schema = "plan-proposal-v1.schema.json"
                capability_profile = "planning_readonly"
                objective = (
                    "Create plan revision N+1 from the inherited root goal, active "
                    "plan, affected node, complete failure chain, repository excerpts, "
                    "and capability inventory. Preserve accepted unaffected nodes."
                )
            else:
                role = str(failed.get("role") or "builder")
                output_schema = str(
                    failed.get("output_schema") or "attempt-result.schema.json"
                )
                capability_profile = str(
                    failed.get("capability_profile") or "builder_workspace"
                )
                suffix = "repair"
                objective = (
                    "Repair the exact failed plan node while preserving its root goal, "
                    "acceptance, scope, failure, and hypothesis lineage."
                )
            original = self._contract(failed)
            if bool(original.get("_reconstructed")):
                self._record_contract_reconstruction(
                    failed=failed,
                    failure=failure,
                )
            allowed_paths = [
                str(value)
                for value in (
                    ["artifacts/**"]
                    if bool(original.get("_reconstructed"))
                    and capability_profile
                    in {"planning_readonly", "reviewer_readonly"}
                    else original.get("allowed_paths", ["artifacts/**"])
                )
            ]
            contract_acceptance = (
                self._controller_incident_acceptance()
                if role == "incident-recovery"
                else self._controller_replan_acceptance()
                if role == "replanner" and controller_recovery_depth > 0
                else None
            )
            contract, path = self._write_contract(
                failed=failed,
                failure=failure,
                hypothesis_id=hypothesis_id,
                role=role,
                output_schema=output_schema,
                capability_profile=capability_profile,
                objective=objective,
                allowed_paths=allowed_paths,
                task_revision=int(failed.get("task_revision") or 1) + 1,
                node_suffix=suffix,
                acceptance=contract_acceptance,
                required_capabilities=(
                    self._lineage_required_capabilities(
                        failed,
                        capability_profile,
                    )
                    if suffix == "repair"
                    else None
                ),
            )
            repair_ref: str | None = None
            if suffix == "repair":
                assert hypothesis_id is not None
                repair_path = self._write_repair_brief(
                    failed=failed,
                    failure=failure,
                    hypothesis_id=hypothesis_id,
                    parent_hypothesis_id=(
                        str(hypothesis["parent_hypothesis_id"])
                        if hypothesis is not None
                        and hypothesis["parent_hypothesis_id"]
                        else None
                    ),
                    repair_task_id=str(contract["task_id"]),
                    allowed_paths=allowed_paths,
                    acceptance=contract_acceptance,
                )
                repair_ref = f"evidence/{repair_path.name}"
            self.state.add_task(
                task_id=str(contract["task_id"]),
                product_id=str(failed["product_id"]),
                title=str(contract["title"]),
                role=role,
                output_schema=output_schema,
                contract_ref=f"evidence/{path.name}",
                stage_key=suffix,
                dependencies=[],
                conflict_keys=[str(value) for value in contract["conflict_keys"]],
                priority=int(contract["priority"]),
                root_task_id=str(contract["root_task_id"]),
                parent_task_id=str(contract["parent_task_id"]),
                source_task_id=str(contract["source_task_id"]),
                plan_id=str(contract["plan_id"]),
                plan_node_id=str(contract["plan_node_id"]),
                task_revision=int(contract["task_revision"]),
                root_context_ref=str(contract["root_context_ref"]),
                active_context_ref=str(contract["active_context_ref"]),
                failure_id=failure_id,
                hypothesis_id=hypothesis_id,
                capability_profile=capability_profile,
                idempotency_key=str(contract["idempotency_key"]),
                supersedes_task_id=str(contract["supersedes_task_id"]),
                required_capabilities=[
                    str(value) for value in contract["required_capabilities"]
                ],
                graph_status="READY",
            )
            if repair_ref is not None:
                with self.state._lock, self.state._connection:
                    self.state._connection.execute(
                        """UPDATE tasks SET repair_context_ref=? WHERE task_id=?""",
                        (repair_ref, contract["task_id"]),
                    )
            with self.state._lock, self.state._connection:
                self.state._connection.execute(
                    "UPDATE failures SET status='ROUTED' WHERE failure_id=?",
                    (failure_id,),
                )
                if hypothesis_id is not None:
                    self.state._connection.execute(
                        """UPDATE hypotheses SET attempts_used=attempts_used+1
                           WHERE hypothesis_id=?""",
                        (hypothesis_id,),
                    )
                self.state._record_event(
                    str(failed["product_id"]),
                    str(contract["task_id"]),
                    "failure_routed",
                    {
                        "failure_id": failure_id,
                        "hypothesis_id": hypothesis_id,
                        "route": suffix,
                        "source_task_id": str(failed["task_id"]),
                        "same_role_problem_count": same_role_problem_count,
                    },
                )
            return str(contract["task_id"])

    def route_open_failures(self, product_id: str) -> list[str]:
        failures = self.state.list_failures(product_id)
        by_id = {
            str(failure["failure_id"]): failure
            for failure in failures
        }
        failures_with_live_descendants: set[str] = set()
        for failure in failures:
            if str(failure["status"]) == "RESOLVED":
                continue
            parent_id = str(failure.get("parent_failure_id") or "")
            seen: set[str] = set()
            while parent_id and parent_id not in seen:
                seen.add(parent_id)
                failures_with_live_descendants.add(parent_id)
                parent = by_id.get(parent_id)
                parent_id = (
                    str(parent.get("parent_failure_id") or "")
                    if parent is not None
                    else ""
                )
        routed: list[str] = []
        for failure in failures:
            if str(failure["status"]) != "OPEN":
                continue
            if str(failure["failure_id"]) in failures_with_live_descendants:
                # Only a causal leaf may create recovery work. Its unresolved
                # ancestors remain durable for audit and are closed atomically
                # when the leaf's recovery succeeds.
                continue
            task = self.state.get_task(str(failure["task_id"]))
            if (
                bool(failure["retryable"])
                and task is not None
                and str(task.get("next_attempt_kind") or "")
                in {"transient_retry", "repair"}
                and str(task.get("graph_status") or "")
                in {"WAITING_TIME", "READY", "CLAIMED"}
            ):
                # The worker has already scheduled a bounded, in-place retry.
                # Routing the same open FailureEnvelope at the same time would
                # create a second causal branch for one failed attempt.
                continue
            routed.append(self.route(str(failure["failure_id"])))
        return routed
