"""Generic causal failure router for repair, replan, and controller incidents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .artifacts import ArtifactStore
from .autonomy import CAPABILITY_PROFILES
from .common import sha256_text, stable_json
from .config import FactoryConfig
from .registry import SchemaRegistry
from .state import StateStore

_REPLAN_REASONS = {
    "needs_replan",
    "scope_contradiction",
    "architecture_impossible",
    "invalid_capability_contract",
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

    def _contract(self, task: dict[str, Any]) -> dict[str, Any]:
        reference = str(task.get("contract_ref") or "")
        path = self.config.evidence_dir / Path(reference).name
        if not path.is_file():
            raise RuntimeError("failed task contract is unavailable")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("failed task contract is invalid")
        return payload

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
            "acceptance": self._acceptance(self._contract(failed)),
            "required_capabilities": list(
                CAPABILITY_PROFILES[capability_profile]
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
    ) -> Path:
        original = self._contract(failed)
        acceptance = self._acceptance(original)
        try:
            actual = json.loads(str(failure.get("actual_json") or "{}"))
        except json.JSONDecodeError:
            actual = {}
        required_fixes = actual.get("required_fixes", [])
        if not isinstance(required_fixes, list):
            required_fixes = []
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
            "inherited_acceptance": acceptance,
            "failed_gate_ids": json.loads(
                str(failure.get("failed_gate_ids_json") or "[]")
            ),
            "required_fixes": [
                *[str(value) for value in required_fixes if str(value).strip()],
                str(failure["safe_message"]),
                "Prove every inherited acceptance criterion with fresh evidence.",
            ],
            "evidence_refs": [str(failure["evidence_ref"])],
            "allowed_paths": allowed_paths or ["artifacts/**"],
            "capability_gaps": [],
            "supersedes_task_id": str(failed["task_id"]),
            "definition_of_done": [
                str(item["verification"]) for item in acceptance
            ],
        }
        return self.artifacts.write(
            "repair-brief-v2.schema.json",
            brief,
            filename=f"repair-brief-{repair_task_id}.json",
        )

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
                    "SELECT task_id FROM tasks WHERE failure_id=? "
                    "ORDER BY created_at DESC LIMIT 1",
                    (failure_id,),
                ).fetchone()
                return str(routed[0]) if routed is not None else ""
            failed_row = self.state._connection.execute(
                "SELECT * FROM tasks WHERE task_id=?", (failure["task_id"],)
            ).fetchone()
            if failed_row is None:
                raise RuntimeError("failure source task is missing")
            failed = dict(failed_row)
            reason = str(failure["reason_code"])
            controller_fault = (
                str(failure["failure_class"]) in {"controller", "transient"}
                or reason.startswith(_CONTROLLER_PREFIXES)
            )
            hypothesis = None
            hypothesis_id: str | None = None
            attempts_used = 0
            if not controller_fault:
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
            needs_replan = reason in _REPLAN_REASONS or attempts_used >= 3
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
                if attempts_used >= 3:
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
                output_schema = "backlog-plan-v2.schema.json"
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
            allowed_paths = [
                str(value) for value in original.get("allowed_paths", ["artifacts/**"])
            ]
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
                    },
                )
            return str(contract["task_id"])

    def route_open_failures(self, product_id: str) -> list[str]:
        failures = self.state.list_failures(product_id)
        routed: list[str] = []
        for failure in failures:
            if str(failure["status"]) != "OPEN":
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
