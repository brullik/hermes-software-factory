"""Semantic validation for controller-compiled executable plans."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from itertools import pairwise
from typing import Any

from .delivery_profiles import delivery_profile
from .lifecycle import (
    STAGES,
)


class PlanContractViolation(ValueError):
    """Raised before ingestion when a plan cannot complete safely."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str = "plan_contract_violation",
        failed_gate_ids: Iterable[str] = (),
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.failed_gate_ids = tuple(
            dict.fromkeys(str(value) for value in failed_gate_ids if str(value))
        )


def _typed_contracts(plan: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    contracts: dict[str, dict[str, Any]] = {}
    for node in plan.get("nodes", []):
        if not isinstance(node, Mapping):
            continue
        contract = node.get("task_contract")
        if isinstance(contract, Mapping):
            contracts[str(node.get("node_id", ""))] = dict(contract)
    return contracts


def validate_compiled_plan(plan: Mapping[str, Any]) -> None:
    """Prove lifecycle, evidence, and completion invariants pre-ingestion."""

    if str(plan.get("compiler_version") or "") == "":
        return
    contracts = _typed_contracts(plan)
    if not contracts:
        raise PlanContractViolation("compiled plan has no typed task contracts")

    try:
        selected_delivery_profile = delivery_profile(
            str(plan.get("delivery_profile") or "DEPLOYED_SERVICE")
        )
    except ValueError as error:
        raise PlanContractViolation(str(error)) from error
    if plan.get("delivery_profile_digest") not in {
        None,
        selected_delivery_profile.digest,
    }:
        raise PlanContractViolation("delivery profile digest mismatch")
    stages: dict[str, list[str]] = defaultdict(list)
    for node_id, contract in contracts.items():
        stage_key = str(contract.get("lifecycle_stage") or "")
        if stage_key not in STAGES:
            raise PlanContractViolation(
                f"{node_id}.lifecycle_stage is not controller-owned: {stage_key or '<missing>'}"
            )
        expected = STAGES[stage_key]
        actual_identity = (
            str(contract.get("role") or ""),
            str(contract.get("output_schema") or ""),
            str(contract.get("capability_profile") or ""),
            contract.get("review_kind"),
            str(contract.get("evidence_profile") or ""),
        )
        expected_identity = (
            expected.role,
            expected.output_schema,
            expected.capability_profile,
            expected.review_kind,
            expected.evidence_profile,
        )
        if actual_identity != expected_identity:
            raise PlanContractViolation(
                f"{node_id} identity does not match lifecycle stage {stage_key}",
                reason_code="evidence_profile_mismatch",
            )
        consumes = tuple(str(value) for value in contract.get("consumes_evidence_types", []))
        produces = tuple(str(value) for value in contract.get("produces_evidence_types", []))
        obligations = tuple(str(value) for value in contract.get("completion_obligation_ids", []))
        if consumes != expected.consumes:
            raise PlanContractViolation(
                f"{node_id}.consumes_evidence_types conflicts with {stage_key}",
                reason_code="evidence_profile_mismatch",
            )
        if produces != expected.produces:
            raise PlanContractViolation(
                f"{node_id}.produces_evidence_types conflicts with {stage_key}",
                reason_code="evidence_profile_mismatch",
            )
        if obligations != expected.obligations:
            raise PlanContractViolation(
                f"{node_id}.completion_obligation_ids conflicts with {stage_key}",
                reason_code="evidence_profile_mismatch",
            )
        required_effect_profile = (
            "release_production"
            if expected.key == "production"
            else "release_distribution"
        )
        if (
            expected.production_side_effects
            and expected.capability_profile != required_effect_profile
        ):
            raise PlanContractViolation(
                f"production side effects require {required_effect_profile}"
            )
        stages[stage_key].append(node_id)

    required_stages = selected_delivery_profile.lifecycle
    for required in required_stages:
        if required == "implementation-slice":
            if not stages[required]:
                raise PlanContractViolation("compiled plan needs an implementation slice")
        elif len(stages[required]) != 1:
            raise PlanContractViolation(
                f"compiled plan requires exactly one {required} stage",
                reason_code="completion_unreachable",
            )
    unexpected_stages = set(stages) - set(required_stages)
    if unexpected_stages:
        raise PlanContractViolation(
            f"compiled plan contains stage outside delivery profile: {min(unexpected_stages)}",
            reason_code="completion_unreachable",
        )

    adjacency: dict[str, set[str]] = {node_id: set() for node_id in contracts}
    predecessors: dict[str, set[str]] = {node_id: set() for node_id in contracts}
    for edge in plan.get("edges", []):
        if not isinstance(edge, Mapping) or not bool(edge.get("required", True)):
            continue
        source = str(edge.get("from") or "")
        target = str(edge.get("to") or "")
        if source in adjacency and target in adjacency:
            adjacency[source].add(target)
            predecessors[target].add(source)

    def ancestors(node_id: str) -> set[str]:
        found: set[str] = set()
        queue = deque(predecessors[node_id])
        while queue:
            current = queue.popleft()
            if current in found:
                continue
            found.add(current)
            queue.extend(predecessors[current])
        return found

    external_evidence = {"architecture_package"}
    for node_id, contract in contracts.items():
        available = set(external_evidence)
        for upstream in ancestors(node_id):
            available.update(
                str(value) for value in contracts[upstream].get("produces_evidence_types", [])
            )
        missing = {
            str(value) for value in contract.get("consumes_evidence_types", [])
        } - available
        if missing:
            raise PlanContractViolation(
                f"{node_id} consumes evidence not produced upstream: {min(missing)}",
                reason_code="missing_declared_predecessor",
            )

    architecture_review = stages["architecture-review"][0]
    if any(
        contracts[node_id]["lifecycle_stage"] in {"implementation-slice", "test"}
        for node_id in ancestors(architecture_review)
    ):
        raise PlanContractViolation("architecture review must not depend on implementation or test")

    release_review = stages["release-readiness-review"][0]
    release_ancestors = {
        str(contracts[node_id]["lifecycle_stage"]) for node_id in ancestors(release_review)
    }
    if not {"implementation-slice", "test", "security-review"}.issubset(release_ancestors):
        raise PlanContractViolation(
            "release readiness review requires implementation, test, and security evidence",
            reason_code="missing_declared_predecessor",
        )

    release_stage_keys = required_stages[
        required_stages.index("release-readiness-review") + 1 :
    ]
    release_path = tuple(stages[stage][0] for stage in release_stage_keys)
    for source, target in pairwise(release_path):
        if source not in ancestors(target):
            raise PlanContractViolation(
                "release path conflicts with the controller-owned delivery profile",
                reason_code="completion_unreachable",
            )

    completion_obligations = {
        str(value)
        for contract in contracts.values()
        for value in contract.get("completion_obligation_ids", [])
    }
    missing_obligations = (
        set(selected_delivery_profile.completion_obligations) - completion_obligations
    )
    if missing_obligations:
        raise PlanContractViolation(
            f"completion obligation is unreachable: {min(missing_obligations)}",
            reason_code="completion_unreachable",
        )

    mandatory_goal_ids = {
        str(goal.get("goal_id"))
        for goal in plan.get("goals", [])
        if isinstance(goal, Mapping) and bool(goal.get("mandatory", True))
    }
    implementation_goal_ids = {
        str(value)
        for node_id in stages["implementation-slice"]
        for value in contracts[node_id].get("goal_ids", [])
    }
    if mandatory_goal_ids and not mandatory_goal_ids.issubset(implementation_goal_ids):
        raise PlanContractViolation(
            "mandatory product goal is not implemented by an executable slice",
            reason_code="completion_unreachable",
        )
