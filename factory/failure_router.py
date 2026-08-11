"""Generic causal failure router for repair, replan, and controller incidents."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .artifacts import ArtifactStore
from .autonomy import CANONICAL_ROLE_OUTPUT_SCHEMAS, CAPABILITY_PROFILES
from .common import sha256_text, stable_json
from .config import FactoryConfig
from .failure_catalog import FailureAction, failure_disposition
from .path_governor import (
    PathGovernor,
    execution_slot_cost,
    semantic_node_id,
    stable_root_problem_signature,
    supersession_is_compatible,
    task_contract_digest,
)
from .plan_semantics import PlanContractViolation
from .policy import policy_digest
from .recovery_directive import build_scope_recovery_directive
from .registry import SchemaRegistry
from .repair_brief import repair_requirements
from .repair_scope import derive_scope_required_paths
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
_CONTROL_GATE_IDS = {
    "model_requested_repair",
    "needs_replan",
    "plan_contract_violation",
    "repeated_hypothesis",
    "liveness_invariant_violation",
}


class ContractIntegrityError(RuntimeError):
    """The exact immutable task contract is absent, invalid, or mismatched."""


@dataclass(frozen=True)
class ArchitectureCorrectionContext:
    reviewer_task_id: str
    hypothesis_id: str | None
    semantic_attempts_used: int
    semantic_budget: int = 3


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

    def _architecture_correction_context(
        self,
        failed: Mapping[str, Any],
        failure: Mapping[str, Any],
    ) -> ArchitectureCorrectionContext | None:
        """Resolve one bounded architecture-review correction hypothesis."""

        product_id = str(failed.get("product_id") or "")
        normalized_role = str(failed.get("role") or "").replace("_", "-")
        stage = str(failed.get("lifecycle_stage") or failed.get("stage_key") or "")
        reviewer: dict[str, Any] | None = None
        hypothesis_id = str(failed.get("hypothesis_id") or "") or None
        if normalized_role == "independent-reviewer" and stage == "architecture-review":
            if str(failure.get("failure_class") or "") not in {"semantic", "policy"}:
                return None
            reviewer = dict(failed)
            if hypothesis_id is None:
                sources = self.state._connection.execute(
                    """SELECT source.hypothesis_id
                         FROM task_edges AS edge
                         JOIN tasks AS source ON source.task_id=edge.from_task_id
                        WHERE edge.plan_id=? AND edge.to_task_id=?
                          AND edge.edge_type='evidence_from' AND edge.required=1
                          AND replace(source.role, '_', '-')='solution-architect'
                          AND source.stage_key='repair'
                        ORDER BY edge.created_at DESC, source.task_id""",
                    (
                        str(failed.get("plan_id") or ""),
                        str(failed.get("task_id") or ""),
                    ),
                ).fetchall()
                inherited = {
                    str(row[0]) for row in sources if str(row[0] or "")
                }
                if len(inherited) > 1:
                    raise ContractIntegrityError(
                        "architecture reviewer has ambiguous correction hypotheses"
                    )
                hypothesis_id = next(iter(inherited), None)
        elif normalized_role == "solution-architect" and str(
            failed.get("stage_key") or ""
        ) == "repair":
            if (
                str(failed.get("capability_profile") or "") != "planning_readonly"
                or str(failed.get("output_schema") or "")
                != "architecture-package.schema.json"
                or str(failure.get("reason_code") or "")
                not in {
                    "model_requested_repair",
                    "schema_validation",
                    "malformed_transport",
                }
            ):
                return None
            current = dict(failed)
            visited: set[str] = set()
            for _depth in range(12):
                parent_id = str(current.get("parent_task_id") or "")
                if not parent_id or parent_id in visited:
                    break
                visited.add(parent_id)
                parent_row = self.state._connection.execute(
                    "SELECT * FROM tasks WHERE task_id=? AND product_id=?",
                    (parent_id, product_id),
                ).fetchone()
                if parent_row is None:
                    break
                parent = dict(parent_row)
                parent_role = str(parent.get("role") or "").replace("_", "-")
                parent_stage = str(
                    parent.get("lifecycle_stage")
                    or parent.get("stage_key")
                    or ""
                )
                if (
                    parent_role == "independent-reviewer"
                    and parent_stage == "architecture-review"
                ):
                    reviewer = parent
                    hypothesis_id = (
                        hypothesis_id
                        or str(parent.get("hypothesis_id") or "")
                        or None
                    )
                    break
                if parent_role != "solution-architect" or str(
                    parent.get("stage_key") or ""
                ) != "repair":
                    break
                current = parent
        else:
            return None
        if reviewer is None:
            return None

        semantic_attempts = 0
        if hypothesis_id:
            rows = self.state._connection.execute(
                """SELECT task.task_id, task.graph_status,
                          GROUP_CONCAT(failure.reason_code) AS reasons
                     FROM tasks AS task
                     LEFT JOIN failures AS failure
                       ON failure.task_id=task.task_id
                    WHERE task.product_id=? AND task.hypothesis_id=?
                      AND replace(task.role, '_', '-')='solution-architect'
                      AND task.stage_key='repair'
                    GROUP BY task.task_id, task.graph_status""",
                (product_id, hypothesis_id),
            ).fetchall()
            for row in rows:
                graph_status = str(row["graph_status"] or "")
                reasons = {
                    value for value in str(row["reasons"] or "").split(",") if value
                }
                if graph_status in {"ACCEPTED", "SUPERSEDED"} or (
                    "model_requested_repair" in reasons
                ):
                    semantic_attempts += 1
        return ArchitectureCorrectionContext(
            reviewer_task_id=str(reviewer["task_id"]),
            hypothesis_id=hypothesis_id,
            semantic_attempts_used=semantic_attempts,
        )

    def _causal_scope_evidence(
        self,
        failure: dict[str, Any],
        *,
        product_id: str,
        max_depth: int = 24,
    ) -> tuple[bool, tuple[str, ...]]:
        """Promote exact scope evidence through plan-contract descendants."""

        failures = {
            str(item.get("failure_id") or ""): item
            for item in self.state.list_failures(product_id)
            if str(item.get("failure_id") or "")
        }
        current_id = str(failure.get("failure_id") or "")
        visited: set[str] = set()
        reassessment_required = False
        required_paths: list[str] = []
        while current_id and current_id not in visited and len(visited) < max_depth:
            visited.add(current_id)
            current = failures.get(current_id)
            if current is None:
                break
            try:
                actual = json.loads(str(current.get("actual_json") or "{}"))
            except json.JSONDecodeError:
                actual = {}
            if isinstance(actual, dict):
                reassessment_required = (
                    reassessment_required
                    or actual.get("scope_reassessment_required") is True
                )
                required_paths.extend(derive_scope_required_paths(actual))
            current_id = str(current.get("parent_failure_id") or "")
        return reassessment_required, tuple(dict.fromkeys(required_paths))

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
            scope_reassessment, _required_paths = self._causal_scope_evidence(
                item,
                product_id=str(failed["product_id"]),
            )
            if scope_reassessment:
                directive = build_scope_recovery_directive(
                    self.config,
                    self.state,
                    list(failures.values()),
                    product_id=str(failed["product_id"]),
                    source_failure_id=str(item.get("failure_id") or ""),
                )
                return str(directive["root_problem_signature"])
            try:
                failed_gates = sorted(
                    str(value)
                    for value in json.loads(str(item.get("failed_gate_ids_json") or "[]"))
                )
            except (TypeError, json.JSONDecodeError):
                failed_gates = []
            source_task = self.state.get_task(str(item.get("task_id") or "")) or failed
            return stable_root_problem_signature(
                {
                    "product_id": failed["product_id"],
                    "failure_class": item.get("failure_class"),
                    "reason_code": item.get("reason_code"),
                    "semantic_node_key": (
                        source_task.get("semantic_node_key")
                        or source_task.get("plan_node_id")
                        or source_task.get("semantic_node_id")
                    ),
                    "lifecycle_stage": source_task.get("lifecycle_stage"),
                    "failed_gate_ids": failed_gates,
                    "required_paths": _required_paths,
                }
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

    def _stable_causal_problem_signature(
        self,
        failure: dict[str, Any],
        failed: dict[str, Any],
        *,
        scope_reassessment_required: bool,
        required_scope_paths: tuple[str, ...],
    ) -> str:
        """Resolve one structural coordinate across task and wording changes."""

        product_id = str(failed["product_id"])
        inherited_signature = str(failed.get("root_problem_signature") or "")
        if re.fullmatch(r"[a-f0-9]{64}", inherited_signature):
            return inherited_signature
        failures = {
            str(item["failure_id"]): item
            for item in self.state.list_failures(product_id)
        }
        if scope_reassessment_required:
            directive = build_scope_recovery_directive(
                self.config,
                self.state,
                list(failures.values()),
                product_id=product_id,
                source_failure_id=str(failure["failure_id"]),
            )
            return str(directive["root_problem_signature"])

        chosen = failure
        current = failure
        seen: set[str] = set()
        while current and str(current.get("failure_id") or "") not in seen:
            current_id = str(current.get("failure_id") or "")
            seen.add(current_id)
            try:
                gate_ids = {
                    str(value)
                    for value in json.loads(
                        str(current.get("failed_gate_ids_json") or "[]")
                    )
                }
            except (TypeError, json.JSONDecodeError):
                gate_ids = set()
            if gate_ids - _CONTROL_GATE_IDS:
                chosen = current
                break
            parent_id = str(current.get("parent_failure_id") or "")
            parent = failures.get(parent_id)
            if parent is None:
                chosen = current
                break
            chosen = parent
            current = parent

        try:
            chosen_gates = [
                str(value)
                for value in json.loads(
                    str(chosen.get("failed_gate_ids_json") or "[]")
                )
            ]
        except (TypeError, json.JSONDecodeError):
            chosen_gates = []
        source_task = self.state.get_task(str(chosen.get("task_id") or "")) or failed
        return stable_root_problem_signature(
            {
                "product_id": product_id,
                "failure_class": chosen.get("failure_class"),
                "reason_code": chosen.get("reason_code"),
                "semantic_node_key": (
                    source_task.get("semantic_node_key")
                    or source_task.get("plan_node_id")
                    or source_task.get("semantic_node_id")
                ),
                "lifecycle_stage": source_task.get("lifecycle_stage"),
                "failed_gate_ids": chosen_gates,
                "required_paths": required_scope_paths,
            }
        )

    def _consume_path_budget(
        self,
        *,
        failed: dict[str, Any],
        failure: dict[str, Any],
        root_problem_signature: str,
        action_kind: str,
        action: str,
        reserve_execution: bool = False,
    ) -> str:
        governor = PathGovernor(
            self.state._connection,
            policy_digest=policy_digest(self.config),
        )
        progress = governor.progress_vector(str(failed["product_id"]))
        result = governor.consume_budget(
            product_id=str(failed["product_id"]),
            root_problem_signature=root_problem_signature,
            action_kind=action_kind,
            progress=progress,
            evidence_digest=str(failure["fingerprint"]),
        )
        if result == "CONTINUE" and reserve_execution:
            result = governor.reserve_execution_slots(
                product_id=str(failed["product_id"]),
                root_problem_signature=root_problem_signature,
                count=1,
                progress=progress,
            )
        governor.record_decision(
            product_id=str(failed["product_id"]),
            root_problem_signature=root_problem_signature,
            action=action,
            path_snapshot_digest=governor.path_snapshot_digest(
                product_id=str(failed["product_id"]),
                root_problem_signature=root_problem_signature,
                progress=progress,
                evidence_digest=str(failure["fingerprint"]),
            ),
            progress_before=progress,
            expected_progress_after=progress,
            evidence_digest=str(failure["fingerprint"]),
            status="APPLIED" if result == "CONTINUE" else "FAILED_SAFE",
        )
        return result

    def _record_path_action(
        self,
        *,
        failed: dict[str, Any],
        failure: dict[str, Any],
        root_problem_signature: str,
        action: str,
        status: str = "APPLIED",
    ) -> None:
        governor = PathGovernor(
            self.state._connection,
            policy_digest=policy_digest(self.config),
        )
        progress = governor.progress_vector(str(failed["product_id"]))
        governor.record_decision(
            product_id=str(failed["product_id"]),
            root_problem_signature=root_problem_signature,
            action=action,
            path_snapshot_digest=governor.path_snapshot_digest(
                product_id=str(failed["product_id"]),
                root_problem_signature=root_problem_signature,
                progress=progress,
                evidence_digest=str(failure["fingerprint"]),
            ),
            progress_before=progress,
            expected_progress_after=progress,
            evidence_digest=str(failure["fingerprint"]),
            status=status,
        )

    def _terminate_path_governor_budget(
        self,
        *,
        failed: dict[str, Any],
        failure: dict[str, Any],
        root_problem_signature: str,
    ) -> str:
        """Close an exhausted structural problem without creating more work."""

        now = str(failure.get("last_seen_at") or failure.get("first_seen_at") or "")
        incident_id = (
            "incident-"
            + sha256_text(
                stable_json(
                    [
                        failed["product_id"],
                        root_problem_signature,
                        "path_governor_problem_budget_exhausted",
                    ]
                )
            )[:20]
        )
        with self.state._lock, self.state._connection:
            self.state._connection.execute(
                "UPDATE failures SET status='ROUTED', last_seen_at=? WHERE failure_id=?",
                (now, failure["failure_id"]),
            )
            if failed.get("hypothesis_id"):
                self.state._connection.execute(
                    """UPDATE hypotheses SET status='EXHAUSTED', closed_at=?
                        WHERE hypothesis_id=? AND status='ACTIVE'""",
                    (now, failed["hypothesis_id"]),
                )
            self.state._connection.execute(
                """INSERT OR IGNORE INTO controller_incidents
                   (incident_id, product_id, task_id, reason_code,
                    evidence_ref, status, created_at)
                   VALUES (?, ?, ?, 'path_governor_problem_budget_exhausted',
                           ?, 'OPEN', ?)""",
                (
                    incident_id,
                    failed["product_id"],
                    failed["task_id"],
                    failure["evidence_ref"],
                    now,
                ),
            )
            from .transition_kernel import TransitionKernel

            TransitionKernel(self.state._connection).apply_product(
                product_id=str(failed["product_id"]),
                target="FAILED_SAFE",
                event="CONTROLLER_QUARANTINE",
                evidence={
                    "controller_incident": incident_id,
                    "terminal_evidence": str(failure["evidence_ref"]),
                },
                terminal_reason="path_governor_problem_budget_exhausted",
                terminal_evidence_ref=str(failure["evidence_ref"]),
            )
            self.state._record_event(
                str(failed["product_id"]),
                str(failed["task_id"]),
                "path_governor_budget_exhausted",
                {
                    "failure_id": str(failure["failure_id"]),
                    "incident_id": incident_id,
                    "root_problem_signature": root_problem_signature,
                },
            )
        return str(failed["task_id"])

    def _quarantine_failure(
        self,
        *,
        failure: dict[str, Any],
        failed: dict[str, Any],
        reason_code: str,
        evidence_ref: str,
    ) -> str:
        """Stop the line without creating model work for controller/data defects."""

        product_id = str(failed["product_id"])
        task_id = str(failed["task_id"])
        now = str(failure.get("last_seen_at") or failure.get("first_seen_at") or "")
        incident_id = "incident-" + sha256_text(
            stable_json([product_id, task_id, reason_code, evidence_ref])
        )[:20]
        disposition = failure_disposition(reason_code)
        with self.state._lock, self.state._connection:
            self.state._connection.execute(
                """INSERT OR IGNORE INTO controller_incidents
                   (incident_id, product_id, task_id, reason_code,
                    evidence_ref, status, created_at)
                   VALUES (?, ?, ?, ?, ?, 'OPEN', ?)""",
                (incident_id, product_id, task_id, reason_code, evidence_ref, now),
            )
            self.state._connection.execute(
                """UPDATE failures
                      SET status='ROUTED', failure_domain=?, failure_action=?
                    WHERE failure_id=?""",
                (
                    disposition.domain.value,
                    disposition.action.value,
                    failure["failure_id"],
                ),
            )
            from .transition_kernel import TransitionKernel

            TransitionKernel(self.state._connection).apply_product(
                product_id=product_id,
                target="FAILED_SAFE",
                event="CONTROLLER_QUARANTINE",
                evidence={
                    "controller_incident": incident_id,
                    "terminal_evidence": evidence_ref,
                },
                terminal_reason=reason_code,
                terminal_evidence_ref=evidence_ref,
            )
            self.state._record_event(
                product_id,
                task_id,
                "controller_quarantine",
                {
                    "failure_id": str(failure["failure_id"]),
                    "incident_id": incident_id,
                    "reason_code": reason_code,
                    "registered": disposition.registered,
                    "domain": disposition.domain.value,
                    "action": disposition.action.value,
                },
            )
        epoch_id = str(
            (self.state.get_product(product_id) or {}).get("controller_release_epoch_id")
            or ""
        )
        if epoch_id:
            from .release_qualification import (
                QualificationError,
                ReleaseQualificationGovernor,
            )

            try:
                ReleaseQualificationGovernor(
                    self.state._connection
                ).record_controller_defect(
                    epoch_id=epoch_id,
                    reason_code=reason_code,
                    evidence_ref=evidence_ref,
                )
            except (KeyError, QualificationError):
                # A terminal/previous epoch remains immutable; the product is
                # already quarantined and cannot continue.
                pass
        return ""

    def _contract(self, task: dict[str, Any]) -> dict[str, Any]:
        reference = str(task.get("contract_ref") or "")
        task_id = str(task.get("task_id") or "")
        expected_ref = f"evidence/task-{task_id}.json"
        if reference != expected_ref:
            raise ContractIntegrityError("task contract reference is not exact")
        unresolved = self.config.evidence_dir / Path(reference).name
        try:
            path = unresolved.resolve(strict=True)
        except OSError as error:
            raise ContractIntegrityError("task contract is missing") from error
        if (
            path.parent != self.config.evidence_dir.resolve()
            or unresolved.is_symlink()
            or not path.is_file()
        ):
            raise ContractIntegrityError("task contract path is outside immutable evidence")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ContractIntegrityError("task contract is unreadable") from error
        if not isinstance(payload, dict):
            raise ContractIntegrityError("task contract is not an object")
        if (
            str(payload.get("task_id") or "") != task_id
            or str(payload.get("product_id") or "")
            != str(task.get("product_id") or "")
        ):
            raise ContractIntegrityError("task contract identity mismatch")
        allowed_paths = payload.get("allowed_paths")
        if not isinstance(allowed_paths, list) or any(
            str(value).strip() in {"*", "**", "**/*"} for value in allowed_paths
        ):
            raise ContractIntegrityError("task contract has an unbounded write scope")
        schema = (
            "task-contract-v2.schema.json"
            if str(payload.get("schema_version") or "") == "2.0"
            else "task-contract.schema.json"
        )
        try:
            self.schemas.validate(schema, payload)
        except Exception as error:
            raise ContractIntegrityError("task contract schema is invalid") from error
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

    @staticmethod
    def _quality_gates(contract: dict[str, Any]) -> list[str]:
        values = contract.get("quality_gates", [])
        if not isinstance(values, list):
            raise TypeError("failed task quality_gates are invalid")
        return list(
            dict.fromkeys(str(value) for value in values if isinstance(value, str) and value)
        )

    @staticmethod
    def _failure_gate_ids(failure: dict[str, Any]) -> list[str]:
        try:
            values = json.loads(str(failure.get("failed_gate_ids_json") or "[]"))
        except json.JSONDecodeError:
            values = []
        if not isinstance(values, list):
            return []
        return list(
            dict.fromkeys(str(value) for value in values if isinstance(value, str) and value)
        )

    @staticmethod
    def _reviewer_gate_repair_paths(failed_gate_ids: list[str]) -> list[str]:
        """Give a post-arbitration Builder the smallest useful repository scope."""

        paths = ["pyproject.toml", "src/**", "tests/**"]
        normalized = [gate_id.lower() for gate_id in failed_gate_ids]
        if any("dependency" in gate_id or "license" in gate_id for gate_id in normalized):
            paths.insert(1, "requirements*.txt")
        if any("container" in gate_id or "image" in gate_id for gate_id in normalized):
            paths.extend(
                [
                    "Dockerfile",
                    "docker/**",
                    "container/**",
                    "compose*.yaml",
                    "compose*.yml",
                    "scripts/**",
                ]
            )
        return paths

    @staticmethod
    def _reviewer_gate_repair_acceptance(
        failed_gate_ids: list[str],
    ) -> list[dict[str, Any]]:
        gates = ", ".join(failed_gate_ids) or "the failed mandatory gate"
        return [
            {
                "criterion_id": "AC-REVIEWER-GATE-ROOT-CAUSE",
                "verification": (
                    "The implementation identifies and repairs the repository-level "
                    "cause of the reviewer failure without weakening or bypassing "
                    f"{gates}."
                ),
                "mandatory": True,
            },
            {
                "criterion_id": "AC-REVIEWER-GATE-FRESH-EVIDENCE",
                "verification": (
                    "Every failed mandatory gate is rerun and produces fresh, "
                    "subject-bound controller evidence that passes."
                ),
                "mandatory": True,
            },
        ]

    @staticmethod
    def _architecture_review_repair_acceptance(
        failed_gate_ids: list[str],
    ) -> list[dict[str, Any]]:
        gates = ", ".join(failed_gate_ids) or "the failed architecture review gate"
        return [
            {
                "criterion_id": "AC-ARCHITECTURE-REPAIR",
                "verification": (
                    "The replacement architecture_package resolves the exact "
                    f"required fixes for {gates} without weakening any review gate."
                ),
                "mandatory": True,
            },
            {
                "criterion_id": "AC-ARCHITECTURE-REVALIDATION",
                "verification": (
                    "The same independent architecture reviewer consumes the replacement "
                    "architecture_package and produces fresh accepted review evidence before "
                    "any dependent implementation work becomes runnable."
                ),
                "mandatory": True,
            },
        ]

    @staticmethod
    def _product_replan_acceptance() -> list[dict[str, Any]]:
        """Evaluate a product replan as a bounded planning handoff."""

        return [
            {
                "criterion_id": "AC-REPLAN-FAILURE-CHAIN",
                "verification": (
                    "The replan_delta is bound to the active parent plan, affected "
                    "node, and complete supplied failure chain, including failed "
                    "acceptance criteria and mandatory gate IDs."
                ),
                "mandatory": True,
            },
            {
                "criterion_id": "AC-REPLAN-EXECUTABLE-HANDOFF",
                "verification": (
                    "Unproven product criteria are carried into bounded executable "
                    "replacement slices that require fresh product evidence; the "
                    "PlanProposal does not claim that future product gates already pass."
                ),
                "mandatory": True,
            },
            {
                "criterion_id": "AC-REPLAN-PRESERVE-ACCEPTED",
                "verification": (
                    "Accepted unaffected implementation and lifecycle evidence is "
                    "preserved while only the affected causal path is replaced."
                ),
                "mandatory": True,
            },
            {
                "criterion_id": "AC-REPLAN-SEMANTIC-ONLY",
                "verification": (
                    "The proposal contains semantic implementation slices only; the "
                    "deterministic PlanCompiler retains ownership of task IDs, roles, "
                    "schemas, capabilities, lifecycle tasks, and release mechanics."
                ),
                "mandatory": True,
            },
        ]

    @staticmethod
    def _path_arbiter_acceptance() -> list[dict[str, Any]]:
        """Constrain Sol arbitration to one typed, read-only recommendation."""

        return [
            {
                "criterion_id": "AC-PATH-ARBITER-SIGNATURE",
                "verification": (
                    "The proposal preserves the supplied root problem signature "
                    "and cites only the bounded Path Snapshot evidence."
                ),
                "mandatory": True,
            },
            {
                "criterion_id": "AC-PATH-ARBITER-READONLY",
                "verification": (
                    "The proposal recommends RECOMPILE_AFFECTED_SUBGRAPH or reports no safe path; "
                    "it does not assign IDs, mutate state, run SQL, or use credentials."
                ),
                "mandatory": True,
            },
            {
                "criterion_id": "AC-PATH-ARBITER-PROGRESS",
                "verification": (
                    "The expected progress delta addresses the unresolved structural "
                    "problem without treating task or plan growth as progress."
                ),
                "mandatory": True,
            },
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
        required_capabilities: list[str] | None = None,
        acceptance: list[dict[str, Any]] | None = None,
        quality_gates: list[str] | None = None,
        model_floor: str = "terra",
        supersede_failed: bool = False,
        produces_evidence_types: list[str] | None = None,
    ) -> tuple[dict[str, Any], Path]:
        task_id = (
            "T-"
            + sha256_text(
                f"{failed['task_id']}:{failure['failure_id']}:{node_suffix}:{task_revision}"
            )[:16].upper()
        )
        contract_ref = f"evidence/task-{task_id}.json"
        plan_id = str(failed["plan_id"])
        plan_node_id = f"{failed['plan_node_id']}:{node_suffix}"
        semantic_node_key = (
            failed.get("semantic_node_key") or failed.get("semantic_node_id")
            if supersede_failed
            else f"{plan_node_id}@plan:{plan_id}"
            if role in {"replanner", "path-arbiter"}
            else None
        )
        same_role_repair = bool(
            node_suffix == "repair"
            and str(failed.get("role") or "").replace("_", "-")
            == role.replace("_", "-")
        )
        source_contract = self._contract(failed) if same_role_repair else None
        if source_contract is not None:
            semantic_node_key = str(
                source_contract.get("semantic_node_key")
                or source_contract.get("plan_node_id")
                or source_contract.get("stage_key")
                or failed.get("semantic_node_key")
                or failed.get("semantic_node_id")
                or failed["task_id"]
            )
        contract = {
            "schema_version": "2.0",
            "artifact_id": f"task-contract-{task_id}",
            "product_id": str(failed["product_id"]),
            "task_id": task_id,
            "root_task_id": str(failed["root_task_id"]),
            "parent_task_id": str(failed["task_id"]),
            "source_task_id": str(failed["task_id"]),
            "plan_id": plan_id,
            "plan_node_id": plan_node_id,
            "semantic_node_key": semantic_node_key,
            "task_revision": task_revision,
            "root_context_ref": str(failed["root_context_ref"]),
            "active_context_ref": contract_ref,
            "failure_id": str(failure["failure_id"]),
            "hypothesis_id": hypothesis_id,
            "supersedes_task_id": (
                str(failed["task_id"]) if supersede_failed else None
            ),
            "title": (
                "Replan affected product graph"
                if role == "replanner"
                else "Arbitrate the bounded recovery path"
                if role == "path-arbiter"
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
            "model_floor": model_floor,
            "idempotency_key": sha256_text(
                f"failure-route:{failure['failure_id']}:{node_suffix}:{task_revision}"
            ),
            "status": "READY",
            "priority": int(failed.get("priority") or 0) + 10,
            "critical_path_rank": 0,
            "quality_gates": list(quality_gates or []),
        }
        if source_contract is not None:
            for field in ("lifecycle_stage", "review_kind", "evidence_profile"):
                if field in source_contract:
                    contract[field] = source_contract[field]
            for field in (
                "consumes_evidence_types",
                "produces_evidence_types",
                "completion_obligation_ids",
                "goal_ids",
            ):
                contract[field] = list(source_contract.get(field, []))
            contract["production_side_effects"] = bool(
                source_contract.get("production_side_effects", False)
            )
        if supersede_failed:
            for field in ("lifecycle_stage", "review_kind", "evidence_profile"):
                value = failed.get(field)
                if value is not None and (field == "review_kind" or str(value)):
                    contract[field] = value
            compatibility_source = dict(failed)
            if source_contract is not None and not compatibility_source.get(
                "semantic_node_key"
            ):
                # Pre-projection tasks may carry only their derived node ID in
                # the durable row.  Their immutable contract still owns the
                # semantic key, so compare against that exact source fact.
                compatibility_source["semantic_node_key"] = semantic_node_key
            if not supersession_is_compatible(compatibility_source, contract):
                raise PlanContractViolation(
                    "cross-role supersession is incompatible with the source task contract",
                    reason_code="cross_role_supersession_invalid",
                )
        if produces_evidence_types is not None:
            contract["produces_evidence_types"] = list(produces_evidence_types)
        self.schemas.validate("task-contract-v2.schema.json", contract)
        path = self.artifacts.write(
            "task-contract-v2.schema.json",
            contract,
            filename=f"task-{task_id}.json",
        )
        return contract, path

    def _persist_routed_task_contract(
        self,
        task_id: str,
        contract: Mapping[str, Any],
        durable_role: str,
    ) -> dict[str, Any]:
        """Atomically project one immutable routed contract into its task row."""

        canonical_role = str(contract.get("role") or "")
        normalized_contract_role = canonical_role.replace("_", "-")
        normalized_durable_role = durable_role.replace("_", "-")
        if normalized_contract_role != normalized_durable_role or (
            durable_role != canonical_role
            and not (
                canonical_role == "solution-architect"
                and durable_role == "solution_architect"
            )
        ):
            raise ContractIntegrityError("routed durable role conflicts with contract")
        digest = task_contract_digest(contract)
        node_id = semantic_node_id(contract, digest)
        projection: dict[str, Any] = {
            "lifecycle_stage": contract.get("lifecycle_stage"),
            "review_kind": contract.get("review_kind"),
            "evidence_profile": contract.get("evidence_profile"),
            "consumes_evidence_types_json": stable_json(
                list(contract.get("consumes_evidence_types", []))
            ),
            "produces_evidence_types_json": stable_json(
                list(contract.get("produces_evidence_types", []))
            ),
            "completion_obligation_ids_json": stable_json(
                list(contract.get("completion_obligation_ids", []))
            ),
            "goal_ids_json": stable_json(list(contract.get("goal_ids", []))),
            "semantic_node_key": contract.get("semantic_node_key"),
            "production_side_effects": int(
                bool(contract.get("production_side_effects", False))
            ),
            "contract_digest": digest,
            "semantic_node_id": node_id,
        }
        with self.state._lock, self.state._connection:
            row = self.state._connection.execute(
                "SELECT * FROM tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if row is None:
                raise ContractIntegrityError("routed task is missing before projection")
            current = dict(row)
            if (
                str(current.get("product_id") or "")
                != str(contract.get("product_id") or "")
                or str(current.get("role") or "") != durable_role
                or str(current.get("output_schema") or "")
                != str(contract.get("output_schema") or "")
                or str(current.get("contract_ref") or "")
                != f"evidence/task-{task_id}.json"
            ):
                raise ContractIntegrityError(
                    "routed task identity conflicts before contract projection"
                )
            persisted_digest = str(current.get("contract_digest") or "")
            persisted_node = str(current.get("semantic_node_id") or "")
            if bool(persisted_digest) != bool(persisted_node):
                raise ContractIntegrityError(
                    "routed task has a partial semantic projection"
                )
            if persisted_digest:
                if persisted_digest != digest or persisted_node != node_id:
                    raise ContractIntegrityError(
                        "routed task semantic projection conflicts"
                    )
                for field, expected in projection.items():
                    actual = current.get(field)
                    if actual != expected:
                        raise ContractIntegrityError(
                            f"routed task projection conflicts for {field}"
                        )
                return current
            self.state._connection.execute(
                """UPDATE tasks
                      SET lifecycle_stage=?, review_kind=?, evidence_profile=?,
                          consumes_evidence_types_json=?,
                          produces_evidence_types_json=?,
                          completion_obligation_ids_json=?, goal_ids_json=?,
                          semantic_node_key=?, production_side_effects=?,
                          contract_digest=?, semantic_node_id=?, updated_at=updated_at
                    WHERE task_id=?""",
                (
                    projection["lifecycle_stage"],
                    projection["review_kind"],
                    projection["evidence_profile"],
                    projection["consumes_evidence_types_json"],
                    projection["produces_evidence_types_json"],
                    projection["completion_obligation_ids_json"],
                    projection["goal_ids_json"],
                    projection["semantic_node_key"],
                    projection["production_side_effects"],
                    digest,
                    node_id,
                    task_id,
                ),
            )
            persisted = self.state._connection.execute(
                "SELECT * FROM tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if persisted is None:
                raise ContractIntegrityError("routed task disappeared after projection")
            result = dict(persisted)
            if any(result.get(field) != expected for field, expected in projection.items()):
                raise ContractIntegrityError(
                    "routed task exact contract projection did not persist"
                )
            return result

    def prepare_replanner_after_arbiter(
        self,
        task: dict[str, Any],
        proposal: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate one read-only arbitration and prepare its bounded Replanner."""

        if (
            str(task.get("role") or "") != "path-arbiter"
            or str(task.get("output_schema") or "")
            != "path-decision-proposal.schema.json"
        ):
            raise ValueError("path arbitration source task is invalid")
        root_problem_signature = str(task.get("root_problem_signature") or "")
        if (
            str(proposal.get("status") or "") != "proposed"
            or str(proposal.get("root_problem_signature") or "")
            != root_problem_signature
            or str(proposal.get("recommended_action") or "")
            != FailureAction.RECOMPILE_AFFECTED_SUBGRAPH.value
        ):
            raise ValueError("Path Arbiter proposal is not an applicable replan delta")
        failure_id = str(task.get("failure_id") or "")
        failure_row = self.state._connection.execute(
            "SELECT * FROM failures WHERE failure_id=? AND product_id=?",
            (failure_id, task["product_id"]),
        ).fetchone()
        if failure_row is None:
            raise ValueError("Path Arbiter source failure is missing")
        failure = dict(failure_row)
        scope_reassessment_required, required_scope_paths = self._causal_scope_evidence(
            failure,
            product_id=str(task["product_id"]),
        )
        objective = (
            "Apply the accepted Path Arbiter RECOMPILE_AFFECTED_SUBGRAPH recommendation. Create "
            "one minimal semantic plan delta from the inherited root goal, active "
            "plan, affected nodes, complete failure chain, and immutable evidence. "
            "Preserve every accepted unaffected node."
        )
        if scope_reassessment_required:
            objective += (
                " The failed Builder proved its allowed_paths were too narrow. "
                "Expand the bounded implementation scope beyond the failed scope "
                "and include every controller-derived safe root-cause path."
            )
            if required_scope_paths:
                objective += " Required safe repository paths: " + ", ".join(
                    required_scope_paths
                ) + "."
        contract, path = self._write_contract(
            failed=task,
            failure=failure,
            hypothesis_id=(
                str(task["hypothesis_id"]) if task.get("hypothesis_id") else None
            ),
            role="replanner",
            output_schema="plan-proposal-v1.schema.json",
            capability_profile="planning_readonly",
            objective=objective,
            allowed_paths=["artifacts/**"],
            task_revision=int(task.get("task_revision") or 1) + 1,
            node_suffix="replan-after-arbiter",
            acceptance=self._product_replan_acceptance(),
            model_floor="terra",
            supersede_failed=False,
        )
        return {
            "task_id": str(contract["task_id"]),
            "title": str(contract["title"]),
            "role": "replanner",
            "output_schema": "plan-proposal-v1.schema.json",
            "contract_ref": f"evidence/{path.name}",
            "stage_key": "replan-after-arbiter",
            "dependencies": [str(task["task_id"])],
            "conflict_keys": [],
            "priority": int(contract["priority"]),
            "root_task_id": str(contract["root_task_id"]),
            "parent_task_id": str(contract["parent_task_id"]),
            "source_task_id": str(contract["source_task_id"]),
            "plan_id": str(contract["plan_id"]),
            "plan_node_id": str(contract["plan_node_id"]),
            "semantic_node_key": str(contract["semantic_node_key"]),
            "task_revision": int(contract["task_revision"]),
            "root_context_ref": str(contract["root_context_ref"]),
            "active_context_ref": str(contract["active_context_ref"]),
            "failure_id": failure_id,
            "hypothesis_id": contract.get("hypothesis_id"),
            "capability_profile": "planning_readonly",
            "idempotency_key": str(contract["idempotency_key"]),
            "supersedes_task_id": contract.get("supersedes_task_id"),
            "root_problem_signature": root_problem_signature,
            "required_capabilities": list(
                CAPABILITY_PROFILES["planning_readonly"]
            ),
            "graph_status": "DRAFT",
            "mandatory": True,
        }

    def _write_repair_brief(
        self,
        *,
        failed: dict[str, Any],
        failure: dict[str, Any],
        hypothesis_id: str,
        parent_hypothesis_id: str | None,
        repair_task_id: str,
        allowed_paths: list[str],
        supersedes_task_id: str | None,
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
            raw_failed_gate_ids = json.loads(str(failure.get("failed_gate_ids_json") or "[]"))
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
        actionable_fixes = [str(value) for value in required_fixes if str(value).strip()]
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
            "supersedes_task_id": supersedes_task_id,
            "definition_of_done": [str(item["verification"]) for item in inherited_acceptance],
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

    def _invalid_plan_output_schema(
        self,
        *,
        failure: dict[str, Any],
        failed: dict[str, Any],
    ) -> bool:
        if str(failure.get("reason_code") or "") != ("controller_exception_file_not_found_error"):
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
        allowed_paths = [str(value) for value in original.get("allowed_paths", ["artifacts/**"])]
        role = str(routed.get("role") or "replanner")
        output_schema = str(routed.get("output_schema") or "plan-proposal-v1.schema.json")
        capability_profile = str(routed.get("capability_profile") or "planning_readonly")
        contract, path = self._write_contract(
            failed=anchored,
            failure=failure,
            hypothesis_id=(str(routed["hypothesis_id"]) if routed.get("hypothesis_id") else None),
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
                sorted(CAPABILITY_PROFILES[capability_profile])
                if role != "replanner"
                else None
            ),
            quality_gates=(self._quality_gates(original) if role != "replanner" else None),
            supersede_failed=False,
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
                conflict_keys=[str(value) for value in contract["conflict_keys"]],
                priority=int(contract["priority"]),
                root_task_id=str(contract["root_task_id"]),
                parent_task_id=str(contract["parent_task_id"]),
                source_task_id=str(contract["source_task_id"]),
                plan_id=active_plan_id,
                plan_node_id=str(contract["plan_node_id"]),
                semantic_node_key=(
                    str(contract["semantic_node_key"])
                    if contract.get("semantic_node_key")
                    else None
                ),
                task_revision=int(contract["task_revision"]),
                root_context_ref=str(contract["root_context_ref"]),
                active_context_ref=str(contract["active_context_ref"]),
                failure_id=str(failure["failure_id"]),
                hypothesis_id=(
                    str(contract["hypothesis_id"]) if contract.get("hypothesis_id") else None
                ),
                capability_profile=capability_profile,
                idempotency_key=str(contract["idempotency_key"]),
                supersedes_task_id=None,
                root_problem_signature=(
                    str(routed["root_problem_signature"])
                    if routed.get("root_problem_signature")
                    else None
                ),
                required_capabilities=[str(value) for value in contract["required_capabilities"]],
                graph_status="READY",
            )
        with self.state._lock, self.state._connection:
            self.state._connection.execute(
                """
                UPDATE tasks
                   SET status='DONE', graph_status='CANCELLED',
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
                    "source_task_id": str(routed["task_id"]),
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
                    """SELECT * FROM tasks WHERE failure_id=?
                       ORDER BY created_at DESC, rowid DESC LIMIT 1""",
                    (failure_id,),
                ).fetchone()
                if routed is None:
                    return ""
                routed_task = dict(routed)
                active_plan_id = self._active_plan_id(str(routed_task["product_id"]))
                if (
                    active_plan_id
                    and str(routed_task.get("plan_id") or "") != active_plan_id
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
            disposition = failure_disposition(reason)
            if str(failed.get("role") or "") == "incident-recovery":
                return self._quarantine_failure(
                    failure=failure,
                    failed=failed,
                    reason_code="internal_task_route",
                    evidence_ref=str(failure["evidence_ref"]),
                )
            if disposition.action is FailureAction.CONTROLLER_QUARANTINE:
                return self._quarantine_failure(
                    failure=failure,
                    failed=failed,
                    reason_code=reason if disposition.registered else "unknown_reason_code",
                    evidence_ref=str(failure["evidence_ref"]),
                )
            if disposition.action is FailureAction.WAIT_EXTERNAL:
                with self.state._lock, self.state._connection:
                    self.state._connection.execute(
                        "UPDATE failures SET status='OWNER_BLOCKED',failure_domain=?,failure_action=? WHERE failure_id=?",
                        (
                            disposition.domain.value,
                            disposition.action.value,
                            failure_id,
                        ),
                    )
                    from .transition_kernel import TransitionKernel

                    TransitionKernel(self.state._connection).apply_product(
                        product_id=str(failed["product_id"]),
                        target="BLOCKED_OWNER",
                        event="EXTERNAL_BLOCK",
                        evidence={
                            "owner_action_contract": str(failure["evidence_ref"])
                        },
                    )
                return ""
            if disposition.action is FailureAction.ROLLBACK:
                with self.state._lock, self.state._connection:
                    self.state._connection.execute(
                        "UPDATE failures SET status='ROUTED',failure_domain=?,failure_action=? WHERE failure_id=?",
                        (
                            disposition.domain.value,
                            disposition.action.value,
                            failure_id,
                        ),
                    )
                    from .transition_kernel import TransitionKernel

                    TransitionKernel(self.state._connection).apply_product(
                        product_id=str(failed["product_id"]),
                        target="ROLLING_BACK",
                        event="ROLLBACK_REQUIRED",
                        evidence={"rollback_intent": str(failure["evidence_ref"])},
                    )
                    self.state._record_event(
                        str(failed["product_id"]),
                        str(failed["task_id"]),
                        "rollback_required",
                        {"failure_id": failure_id, "evidence_ref": failure["evidence_ref"]},
                    )
                return ""
            (
                scope_reassessment_required,
                required_scope_paths,
            ) = self._causal_scope_evidence(
                dict(failure),
                product_id=str(failed["product_id"]),
            )
            try:
                original = self._contract(failed)
            except ContractIntegrityError:
                coordinate = sha256_text(
                    stable_json(
                        [failed["product_id"], failed["task_id"], failed.get("contract_ref")]
                    )
                )
                return self._quarantine_failure(
                    failure=failure,
                    failed=failed,
                    reason_code="invalid_task_contract",
                    evidence_ref=f"internal://contract-integrity/{coordinate[:24]}",
                )
            original_allowed_paths = [
                str(value)
                for value in original.get("allowed_paths", ["artifacts/**"])
                if isinstance(value, str) and value
            ]
            legacy_replanner_scope_contract = (
                str(failed.get("role") or "") == "replanner"
                and scope_reassessment_required
                and original_allowed_paths != ["artifacts/**"]
            )
            active_plan_id = self._active_plan_id(str(failed["product_id"]))
            if active_plan_id:
                failed["plan_id"] = active_plan_id
            invalid_plan_output_schema = self._invalid_plan_output_schema(
                failure=failure,
                failed=failed,
            )
            if invalid_plan_output_schema:
                return self._quarantine_failure(
                    failure=failure,
                    failed=failed,
                    reason_code="invalid_output_schema",
                    evidence_ref=str(failure["evidence_ref"]),
                )
            if legacy_replanner_scope_contract:
                return self._quarantine_failure(
                    failure=failure,
                    failed=failed,
                    reason_code="invalid_capability_contract",
                    evidence_ref=str(failure["evidence_ref"]),
                )
            root_problem_signature = self._stable_causal_problem_signature(
                failure,
                failed,
                scope_reassessment_required=scope_reassessment_required,
                required_scope_paths=required_scope_paths,
            )
            self.state._connection.execute(
                "UPDATE tasks SET root_problem_signature=? WHERE task_id=?",
                (root_problem_signature, str(failed["task_id"])),
            )
            hypothesis = None
            hypothesis_id: str | None = None
            attempts_used = 0
            architecture_context = self._architecture_correction_context(
                failed,
                failure,
            )
            diagnosis_reassessment = str(failed.get("stage_key") or "") == "diagnosis-reassessment"
            same_role_problem_count = self._same_role_problem_count(
                dict(failure),
                dict(failed),
            )
            inherited_hypothesis_id = str(
                (
                    architecture_context.hypothesis_id
                    if architecture_context is not None
                    else None
                )
                or failed.get("hypothesis_id")
                or ""
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
            failed["hypothesis_id"] = hypothesis_id
            architecture_context = self._architecture_correction_context(
                failed,
                failure,
            )
            if (
                architecture_context is not None
                and architecture_context.semantic_attempts_used
                >= architecture_context.semantic_budget
            ):
                if hypothesis_id is not None:
                    self.state._connection.execute(
                        """UPDATE hypotheses SET status='EXHAUSTED', closed_at=?
                             WHERE hypothesis_id=? AND status='ACTIVE'""",
                        (failure["last_seen_at"], hypothesis_id),
                    )
                return self._quarantine_failure(
                    failure=failure,
                    failed=failed,
                    reason_code="architecture_correction_budget_exhausted",
                    evidence_ref=str(failure["evidence_ref"]),
                )
            reassessment_threshold = 3
            repeated_problem_requires_reassessment = (
                same_role_problem_count >= reassessment_threshold
                and not diagnosis_reassessment
                and not legacy_replanner_scope_contract
            )
            needs_replan = (
                reason in _REPLAN_REASONS
                or (
                    str(failed.get("capability_profile") or "") == "reviewer_readonly"
                    and str(failure.get("failure_class") or "") in {"semantic", "policy"}
                )
                or (
                    reason == "mandatory_gate_failed"
                    and str(failed.get("capability_profile") or "") != "builder_workspace"
                )
                or (
                    reason == "model_requested_repair"
                    and str(failed.get("capability_profile") or "")
                    in {"test_workspace", "reviewer_readonly"}
                )
                or attempts_used >= 3
                or repeated_problem_requires_reassessment
                or scope_reassessment_required
                or str(failed.get("role") or "") == "path-arbiter"
            )
            budget_row = self.state._connection.execute(
                """SELECT arbiter_calls_used, execution_attempts_used, status
                     FROM problem_budgets
                    WHERE product_id=? AND root_problem_signature=?""",
                (failed["product_id"], root_problem_signature),
            ).fetchone()
            architecture_review_failure = architecture_context is not None
            semantic_budget = (
                architecture_context.semantic_budget
                if architecture_context is not None
                else int(hypothesis["semantic_budget"] or 3)
                if hypothesis is not None
                else 3
            )
            # Architecture findings are corrected at their semantic source.
            # This read-only Solution Architect loop is bounded by the
            # hypothesis budget and must run before any Path Arbiter/Replanner
            # path can reserve repository execution slots.
            bounded_architecture_review_repair = bool(
                architecture_review_failure
                and architecture_context is not None
                and architecture_context.semantic_attempts_used < semantic_budget
            )
            bounded_reviewer_gate_repair = bool(
                bounded_architecture_review_repair
                or (
                    needs_replan
                    and not architecture_review_failure
                    and str(failed.get("capability_profile") or "")
                    == "reviewer_readonly"
                    and str(failure.get("failure_class") or "")
                    in {"semantic", "policy"}
                    and budget_row is not None
                    and int(budget_row["arbiter_calls_used"] or 0) >= 1
                    and int(budget_row["execution_attempts_used"] or 0) < 2
                    and str(budget_row["status"] or "") == "ACTIVE"
                )
            )
            actual_builder_repair = bool(
                (
                    bounded_reviewer_gate_repair
                    and not bounded_architecture_review_repair
                )
                or (
                    not needs_replan
                    and str(failed.get("role") or "").replace("_", "-") == "builder"
                    and str(failed.get("capability_profile") or "")
                    == "builder_workspace"
                )
            )
            if needs_replan and not bounded_reviewer_gate_repair:
                path_action = FailureAction.RECOMPILE_AFFECTED_SUBGRAPH.value
            else:
                path_action = FailureAction.REPAIR_NODE_VERSION.value
            if needs_replan and not bounded_reviewer_gate_repair:
                if self._consume_path_budget(
                    failed=failed,
                    failure=failure,
                    root_problem_signature=root_problem_signature,
                    action_kind="arbiter",
                    action=path_action,
                    reserve_execution=False,
                ) != "CONTINUE":
                    return self._terminate_path_governor_budget(
                        failed=failed,
                        failure=failure,
                        root_problem_signature=root_problem_signature,
                    )
            elif not actual_builder_repair:
                self._record_path_action(
                    failed=failed,
                    failure=failure,
                    root_problem_signature=root_problem_signature,
                    action=path_action,
                )
            if bounded_reviewer_gate_repair:
                role = (
                    "solution-architect"
                    if bounded_architecture_review_repair
                    else "builder"
                )
                output_schema = CANONICAL_ROLE_OUTPUT_SCHEMAS[role]
                capability_profile = (
                    "planning_readonly"
                    if bounded_architecture_review_repair
                    else "builder_workspace"
                )
                suffix = "repair"
                objective = (
                    "Use the bounded architecture-correction hypothesis to replace the rejected "
                    "architecture_package. Resolve every exact architecture-review finding "
                    "from the controller repair brief, remain read-only, preserve the root "
                    "problem signature and require fresh independent reviewer acceptance."
                    if bounded_architecture_review_repair
                    else (
                        "Use the remaining bounded execution slot to repair the exact "
                        "repository-level cause of the reviewer mandatory-gate failure. "
                        "Preserve the root problem signature, do not weaken a gate, and "
                        "produce fresh subject-bound evidence for every failed gate."
                    )
                )
            elif needs_replan:
                if legacy_replanner_scope_contract:
                    suffix = "scope-contract-correction"
                    objective = (
                        "Correct the controller-created Replanner contract that "
                        "incorrectly inherited a failed Builder write scope. Return "
                        "one bounded replan_delta using the typed replan scope policy."
                    )
                elif (
                    attempts_used >= 3
                    or repeated_problem_requires_reassessment
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
                    hypothesis_id = f"hypothesis-{reassessment_signature[:20]}"
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
                    suffix = "diagnosis-reassessment" if diagnosis_reassessment else "replan"
                role = "replanner"
                output_schema = "plan-proposal-v1.schema.json"
                capability_profile = "planning_readonly"
                if not legacy_replanner_scope_contract:
                    objective = (
                        "Create plan revision N+1 from the inherited root goal, active "
                        "plan, affected node, complete failure chain, repository excerpts, "
                        "and capability inventory. Preserve accepted unaffected nodes."
                    )
                if scope_reassessment_required:
                    objective += (
                        " The failed Builder proved its allowed_paths were too narrow. "
                        "Create fresh implementation work whose bounded scope expands "
                        "beyond the failed scope and includes the production root-cause "
                        "files named by controller gate diagnostics; a tests-only "
                        "substitute is invalid."
                    )
                    if required_scope_paths:
                        objective += (
                            " Required safe repository paths: "
                            + ", ".join(required_scope_paths)
                            + "."
                        )
                if needs_replan and not bounded_reviewer_gate_repair:
                    suffix = "path-arbiter"
                    role = "path-arbiter"
                    output_schema = "path-decision-proposal.schema.json"
                    capability_profile = "planning_readonly"
                    objective = (
                        "Evaluate the controller-supplied immutable Path Snapshot once. "
                        "Return one read-only path decision proposal bound to the exact "
                        "root problem signature. Recommend RECOMPILE_AFFECTED_SUBGRAPH when a bounded "
                        "semantic delta can produce fresh evidence, including a Builder "
                        "slice that truthfully discovers and attests missing inventory. "
                        "The future evidence need not already exist in the snapshot. "
                        "Never invent evidence or weaken a mandatory gate. Return "
                        "no_safe_path only when no bounded role can produce it."
                    )
            else:
                role = str(failed.get("role") or "builder")
                output_schema = str(failed.get("output_schema") or "attempt-result.schema.json")
                capability_profile = str(failed.get("capability_profile") or "builder_workspace")
                suffix = "repair"
                objective = (
                    "Repair the exact failed plan node while preserving its root goal, "
                    "acceptance, scope, failure, and hypothesis lineage."
                )
            # ``allowed_paths`` is the write boundary of the *current* task.
            # A Replanner is a read-only planning task and must never inherit a
            # failed Builder's repository write scope.  The latter describes the
            # exact scope that proved insufficient and belongs in the typed
            # replan scope policy, not in the Replanner's own execution sandbox.
            #
            # Keeping these concepts separate is essential: otherwise a failure
            # such as ``scripts/foo.py is outside src/**`` produces a Replanner
            # contract that still permits only ``src/**``.  The model then cannot
            # propose the controller-requested scope expansion and the router
            # creates an unbounded chain of semantically identical replans.
            if bounded_reviewer_gate_repair:
                allowed_paths = (
                    ["artifacts/**"]
                    if bounded_architecture_review_repair
                    else self._reviewer_gate_repair_paths(
                        self._failure_gate_ids(failure)
                    )
                )
            elif role in {"replanner", "path-arbiter"}:
                allowed_paths = ["artifacts/**"]
            else:
                allowed_paths = [
                    str(value)
                    for value in original.get("allowed_paths", ["artifacts/**"])
                ]
            if role == "path-arbiter":
                contract_acceptance = self._path_arbiter_acceptance()
            elif role == "replanner":
                contract_acceptance = self._product_replan_acceptance()
            elif bounded_reviewer_gate_repair:
                contract_acceptance = (
                    self._architecture_review_repair_acceptance(
                        self._failure_gate_ids(failure)
                    )
                    if bounded_architecture_review_repair
                    else self._reviewer_gate_repair_acceptance(
                        self._failure_gate_ids(failure)
                    )
                )
            else:
                contract_acceptance = None
            repair_quality_gates: list[str] | None = None
            if suffix == "repair":
                repair_quality_gates = self._quality_gates(original)
                if bounded_reviewer_gate_repair and any(
                    "container" in gate_id.lower() or "image" in gate_id.lower()
                    for gate_id in self._failure_gate_ids(failure)
                ):
                    repair_quality_gates = list(
                        dict.fromkeys(
                            [*repair_quality_gates, "target-container-image-scan"]
                        )
                    )
                if reason == "mandatory_gate_failed":
                    repair_quality_gates = list(
                        dict.fromkeys(
                            [
                                *repair_quality_gates,
                                *self._failure_gate_ids(failure),
                            ]
                        )
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
                    sorted(CAPABILITY_PROFILES[capability_profile])
                    if suffix == "repair"
                    else None
                ),
                quality_gates=repair_quality_gates,
                model_floor=(
                    "sol"
                    if needs_replan and not bounded_reviewer_gate_repair
                    or suffix == "scope-contract-correction"
                    else "terra"
                ),
                supersede_failed=(
                    suffix == "repair"
                    and role
                    not in {
                        "replanner",
                        "path-arbiter",
                        "solution-architect",
                        "solution_architect",
                    }
                    and role == str(failed.get("role") or "")
                    and output_schema == str(failed.get("output_schema") or "")
                ),
                produces_evidence_types=(
                    ["architecture_package"]
                    if bounded_architecture_review_repair
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
                        if hypothesis is not None and hypothesis["parent_hypothesis_id"]
                        else None
                    ),
                    repair_task_id=str(contract["task_id"]),
                    allowed_paths=allowed_paths,
                    supersedes_task_id=(
                        str(contract["supersedes_task_id"])
                        if contract.get("supersedes_task_id")
                        else None
                    ),
                    acceptance=contract_acceptance,
                )
                repair_ref = f"evidence/{repair_path.name}"
            execution_candidate = {**contract, "stage_key": suffix}
            if execution_slot_cost(execution_candidate) == 1:
                budget = self.state._connection.execute(
                    """SELECT execution_attempts_used, status
                         FROM problem_budgets
                        WHERE product_id=? AND root_problem_signature=?""",
                    (str(failed["product_id"]), root_problem_signature),
                ).fetchone()
                if budget is not None and (
                    str(budget["status"] or "") != "ACTIVE"
                    or int(budget["execution_attempts_used"] or 0) >= 2
                ):
                    self.state._connection.execute(
                        """UPDATE problem_budgets
                              SET status='EXHAUSTED', updated_at=?
                            WHERE product_id=? AND root_problem_signature=?""",
                        (
                            str(failure["last_seen_at"]),
                            str(failed["product_id"]),
                            root_problem_signature,
                        ),
                    )
                    self._record_path_action(
                        failed=failed,
                        failure=failure,
                        root_problem_signature=root_problem_signature,
                        action=path_action,
                        status="FAILED_SAFE",
                    )
                    return self._terminate_path_governor_budget(
                        failed=failed,
                        failure=failure,
                        root_problem_signature=root_problem_signature,
                    )
            # The persisted compatibility spelling normalizes to the canonical
            # solution-architect prompt role, while preventing the legacy v1
            # solution-architect -> task-specifier pipeline from recompiling an
            # already-active v2 plan.  The immutable contract remains canonical.
            durable_role = (
                "solution_architect" if bounded_architecture_review_repair else role
            )
            self.state.add_task(
                task_id=str(contract["task_id"]),
                product_id=str(failed["product_id"]),
                title=str(contract["title"]),
                role=durable_role,
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
                semantic_node_key=(
                    str(contract["semantic_node_key"])
                    if contract.get("semantic_node_key")
                    else None
                ),
                task_revision=int(contract["task_revision"]),
                root_context_ref=str(contract["root_context_ref"]),
                active_context_ref=str(contract["active_context_ref"]),
                failure_id=failure_id,
                hypothesis_id=hypothesis_id,
                capability_profile=capability_profile,
                idempotency_key=str(contract["idempotency_key"]),
                supersedes_task_id=(
                    str(contract["supersedes_task_id"])
                    if contract.get("supersedes_task_id")
                    else None
                ),
                root_problem_signature=root_problem_signature,
                required_capabilities=[str(value) for value in contract["required_capabilities"]],
                graph_status="READY",
            )
            new_routed_task = self._persist_routed_task_contract(
                str(contract["task_id"]),
                contract,
                durable_role,
            )
            if execution_slot_cost(new_routed_task) == 1:
                governor = PathGovernor(
                    self.state._connection,
                    policy_digest=policy_digest(self.config),
                )
                reservation = governor.reserve_task_execution_once(
                    task_id=str(contract["task_id"]),
                    root_problem_signature=root_problem_signature,
                    progress=governor.progress_vector(str(failed["product_id"])),
                )
                if reservation != "CONTINUE":
                    with self.state._connection:
                        self.state._connection.execute(
                            """UPDATE tasks
                                  SET status='FAILED_SAFE', graph_status='CANCELLED',
                                      terminal_reason='path_governor_problem_budget_exhausted',
                                      updated_at=?
                                WHERE task_id=?""",
                            (failure["last_seen_at"], contract["task_id"]),
                        )
                    return self._terminate_path_governor_budget(
                        failed=failed,
                        failure=failure,
                        root_problem_signature=root_problem_signature,
                    )
                self._record_path_action(
                    failed=failed,
                    failure=failure,
                    root_problem_signature=root_problem_signature,
                    action=path_action,
                )
            if repair_ref is not None:
                with self.state._lock, self.state._connection:
                    self.state._connection.execute(
                        """UPDATE tasks SET repair_context_ref=? WHERE task_id=?""",
                        (repair_ref, contract["task_id"]),
                    )
            if bounded_architecture_review_repair:
                with self.state._lock, self.state._connection:
                    assert architecture_context is not None
                    reviewer_task = self.state.get_task(
                        architecture_context.reviewer_task_id
                    )
                    if reviewer_task is None:
                        raise ContractIntegrityError(
                            "architecture correction reviewer disappeared"
                        )
                    dependencies = json.loads(
                        str(reviewer_task.get("dependencies_json") or "[]")
                    )
                    if not isinstance(dependencies, list):
                        raise TypeError("architecture reviewer dependencies are invalid")
                    dependencies = list(
                        dict.fromkeys(
                            [
                                *[str(value) for value in dependencies],
                                str(contract["task_id"]),
                            ]
                        )
                    )
                    self.state._connection.execute(
                        """UPDATE tasks
                              SET status='PENDING', graph_status='BLOCKED_DEPENDENCY',
                                  dependencies_json=?, failure_id=?, hypothesis_id=?,
                                  result_ref=NULL, result_digest=NULL,
                                  result_binding_id=NULL, lease_owner=NULL,
                                  lease_until=NULL, heartbeat_at=NULL, lease_token=NULL,
                                  available_at=NULL, next_tier='terra',
                                  next_attempt_kind='initial', repair_context_ref=NULL,
                                  terminal_reason=NULL, terminal_detail=NULL,
                                  failure_kind=NULL, blocked_reason='waiting_for_dependencies',
                                  blocked_ref=NULL, updated_at=?
                            WHERE task_id=? AND product_id=?
                              AND graph_status NOT IN ('ACCEPTED','CANCELLED')""",
                        (
                            stable_json(dependencies),
                            str(failure["failure_id"]),
                            hypothesis_id,
                            str(failure["last_seen_at"]),
                            str(reviewer_task["task_id"]),
                            str(reviewer_task["product_id"]),
                        ),
                    )
                    self.state._connection.execute(
                        """INSERT OR IGNORE INTO task_edges
                           (plan_id, from_task_id, to_task_id, edge_type,
                            required, created_at)
                           VALUES (?, ?, ?, 'revalidates', 1, ?)""",
                        (
                            str(contract["plan_id"]),
                            str(contract["task_id"]),
                            str(reviewer_task["task_id"]),
                            str(failure["last_seen_at"]),
                        ),
                    )
                    self.state._record_event(
                        str(failed["product_id"]),
                        str(reviewer_task["task_id"]),
                        "architecture_reviewer_revalidation_blocked",
                        {
                            "architecture_repair_task_id": str(contract["task_id"]),
                            "fresh_reviewer_acceptance_required": True,
                        },
                    )
            with self.state._lock, self.state._connection:
                self.state._connection.execute(
                    "UPDATE failures SET status='ROUTED' WHERE failure_id=?",
                    (failure_id,),
                )
                if hypothesis_id is not None and architecture_context is not None:
                    self.state._connection.execute(
                        """UPDATE hypotheses SET attempts_used=?
                           WHERE hypothesis_id=?""",
                        (
                            architecture_context.semantic_attempts_used,
                            hypothesis_id,
                        ),
                    )
                elif hypothesis_id is not None:
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
        by_id = {str(failure["failure_id"]): failure for failure in failures}
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
                parent_id = str(parent.get("parent_failure_id") or "") if parent is not None else ""
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
                and str(task.get("next_attempt_kind") or "") in {"transient_retry", "repair"}
                and str(task.get("graph_status") or "") in {"WAITING_TIME", "READY", "CLAIMED"}
            ):
                # The worker has already scheduled a bounded, in-place retry.
                # Routing the same open FailureEnvelope at the same time would
                # create a second causal branch for one failed attempt.
                continue
            task_id = self.route(str(failure["failure_id"]))
            if task_id:
                routed.append(task_id)
        return routed
