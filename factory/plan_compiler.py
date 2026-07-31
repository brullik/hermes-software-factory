"""Compile a semantic model proposal into a controller-owned execution graph."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .autonomy import CAPABILITY_PROFILES
from .common import sha256_text, stable_json
from .lifecycle import (
    LIFECYCLE_VERSION,
    PLAN_COMPILER_VERSION,
    stage_contract,
)
from .plan_semantics import PlanContractViolation, validate_compiled_plan


@dataclass(frozen=True)
class CompileContext:
    product_id: str
    revision: int
    parent_plan_id: str | None
    source_failure_id: str | None
    created_by_task_id: str
    root_task_id: str
    root_context_ref: str
    external_repository: bool
    proposal_artifact_ref: str
    architecture_source_task_id: str | None = None
    mandatory_replan_gate_ids: tuple[str, ...] = ()
    blocked_replan_scope_paths: tuple[str, ...] = ()


def _node_key(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")
    normalized = re.sub(r"-+", "-", normalized)
    if not normalized:
        raise ValueError("proposal node_key cannot be normalized")
    return normalized[:80]


def _controller_id(prefix: str, seed: str, length: int = 20) -> str:
    return f"{prefix}-{sha256_text(seed)[:length].upper()}"


_PATH_GLOB = re.compile(
    r"^[A-Za-z0-9._*?\[\]{}!+@-]+"
    r"(?:/[A-Za-z0-9._*?\[\]{}!+@-]+)*$"
)
_ROOT_PATH_NAMES = {
    "Dockerfile",
    "Makefile",
    "README",
    "LICENSE",
    "SECURITY",
}


def _valid_path_scope(value: object) -> bool:
    path = str(value)
    if not path or path != path.strip() or not _PATH_GLOB.fullmatch(path):
        return False
    if path.startswith("/") or any(
        segment in {"", ".", ".."} for segment in path.split("/")
    ):
        return False
    name = path.rsplit("/", 1)[-1]
    return (
        "/" in path
        or "." in name
        or any(marker in path for marker in ("*", "?", "[", "{"))
        or name in _ROOT_PATH_NAMES
    )


class PlanCompiler:
    """The sole authority that assigns executable identities and release order."""

    def __init__(self, *, policy_digest: str) -> None:
        if not re.fullmatch(r"[a-f0-9]{64}", policy_digest):
            raise ValueError("compiler policy digest must be a lowercase SHA-256")
        self.policy_digest = policy_digest

    @staticmethod
    def _validate_semantic_proposal(
        proposal: Mapping[str, Any],
        slices: Sequence[Mapping[str, Any]],
        node_keys: Sequence[str],
    ) -> None:
        known_keys = set(node_keys)
        known_goals = {
            str(goal.get("goal_id") or "")
            for goal in proposal.get("goals", [])
            if isinstance(goal, Mapping)
        }
        mapped_goals: set[str] = set()
        dependencies: dict[str, list[str]] = {}
        for key, node in zip(node_keys, slices, strict=True):
            scope = node.get("scope", [])
            if not isinstance(scope, list) or not scope:
                raise ValueError(f"PlanProposal node {key} needs bounded scope")
            if any(str(value).strip() in {"*", "**", "**/*"} for value in scope):
                raise ValueError(
                    f"PlanProposal node {key} uses an unbounded repository scope"
                )
            invalid_scope = [
                str(value) for value in scope if not _valid_path_scope(value)
            ]
            if invalid_scope:
                raise ValueError(
                    "PlanProposal node "
                    f"{key}.scope must contain relative POSIX path globs, not prose: "
                    f"{invalid_scope[0][:120]}"
                )
            raw_dependencies = node.get("depends_on", [])
            if not isinstance(raw_dependencies, list):
                raise TypeError(
                    f"PlanProposal node {key}.depends_on must be an array"
                )
            normalized_dependencies = [
                _node_key(str(value)) for value in raw_dependencies
            ]
            unknown = set(normalized_dependencies) - known_keys
            if unknown:
                raise ValueError(
                    f"PlanProposal node {key} depends on unknown node {min(unknown)}"
                )
            if key in normalized_dependencies:
                raise ValueError(f"PlanProposal node {key} depends on itself")
            dependencies[key] = normalized_dependencies
            raw_goals = node.get("goal_ids", [])
            if not isinstance(raw_goals, list) or not raw_goals:
                raise ValueError(f"PlanProposal node {key} needs goal_ids")
            node_goals = {str(value) for value in raw_goals}
            unknown_goals = node_goals - known_goals
            if unknown_goals:
                raise ValueError(
                    f"PlanProposal node {key} maps unknown goal {min(unknown_goals)}"
                )
            mapped_goals.update(node_goals)

        mandatory_goals = {
            str(goal.get("goal_id") or "")
            for goal in proposal.get("goals", [])
            if isinstance(goal, Mapping) and bool(goal.get("mandatory", True))
        }
        missing_goals = mandatory_goals - mapped_goals
        if missing_goals:
            raise ValueError(
                f"mandatory goal has no implementation slice: {min(missing_goals)}"
            )

        indegree = {key: 0 for key in node_keys}
        adjacency: dict[str, list[str]] = {key: [] for key in node_keys}
        for target, sources in dependencies.items():
            for source in sources:
                adjacency[source].append(target)
                indegree[target] += 1
        frontier = [key for key, degree in indegree.items() if degree == 0]
        visited = 0
        while frontier:
            source = frontier.pop()
            visited += 1
            for target in adjacency[source]:
                indegree[target] -= 1
                if indegree[target] == 0:
                    frontier.append(target)
        if visited != len(node_keys):
            raise ValueError("PlanProposal implementation dependencies must be acyclic")

    @staticmethod
    def _validate_replan_handoff(
        proposed_slices: Sequence[Mapping[str, Any]],
        inherited_by_key: Mapping[str, Mapping[str, Any]],
        mandatory_gate_ids: Sequence[str],
        blocked_scope_paths: Sequence[str],
    ) -> None:
        """Require a replan to schedule fresh work for every failed mandatory gate."""

        fresh_slices: list[Mapping[str, Any]] = []
        for node in proposed_slices:
            key = _node_key(str(node.get("node_key") or ""))
            inherited = inherited_by_key.get(key)
            if inherited is None or stable_json(inherited) != stable_json(node):
                fresh_slices.append(node)
        if not fresh_slices:
            raise PlanContractViolation(
                "replan_delta has no fresh implementation slice; accepted inherited "
                "nodes cannot repair the causal failure"
            )

        fresh_text = "\n".join(
            value
            for node in fresh_slices
            for value in (
                str(node.get("title") or ""),
                str(node.get("objective") or ""),
                *[
                    str(item)
                    for item in node.get("acceptance_intents", [])
                    if isinstance(item, str)
                ],
            )
        )
        missing = [
            str(gate_id)
            for gate_id in dict.fromkeys(mandatory_gate_ids)
            if str(gate_id)
            and re.search(
                rf"(?<![A-Za-z0-9_-]){re.escape(str(gate_id))}(?![A-Za-z0-9_-])",
                fresh_text,
                flags=re.IGNORECASE,
            )
            is None
        ]
        if missing:
            raise PlanContractViolation(
                "fresh implementation slices do not cover failed mandatory gates: "
                + ", ".join(missing),
                failed_gate_ids=missing,
            )
        if blocked_scope_paths:
            blocked = tuple(dict.fromkeys(str(value) for value in blocked_scope_paths))

            def covered_by_blocked_scope(value: object) -> bool:
                candidate = str(value)
                for pattern in blocked:
                    if candidate == pattern:
                        return True
                    if pattern.endswith("/**"):
                        prefix = pattern[:-3].rstrip("/")
                        if candidate.startswith(prefix + "/"):
                            return True
                return False

            fresh_scopes = [
                str(value)
                for node in fresh_slices
                for value in node.get("scope", [])
            ]
            if not any(
                not covered_by_blocked_scope(value)
                for value in fresh_scopes
            ):
                raise PlanContractViolation(
                    "fresh implementation slices do not expand the failed "
                    "allowed_paths scope; add bounded production root-cause paths "
                    "outside: "
                    + ", ".join(blocked),
                    failed_gate_ids=mandatory_gate_ids,
                )

    @staticmethod
    def _quality_gates(stage_key: str, external_repository: bool) -> list[str]:
        if external_repository:
            implementation = [
                "target-environment",
                "target-tests",
                "target-compile",
                "target-lint",
                "target-secret-scan",
            ]
            security = [
                "target-sast",
                "target-dependency-audit",
                "target-license-check",
                "target-secret-scan",
            ]
        else:
            implementation = [
                "package-integrity",
                "unit-tests",
                "python-compile",
                "lint",
                "typecheck",
                "secret-scan",
                "manifest",
                "sbom",
            ]
            security = ["secret-scan", "sbom"]
        if stage_key == "implementation-slice":
            return implementation
        if stage_key == "test":
            return (
                implementation
                if external_repository
                else list(dict.fromkeys([*implementation, "pilot-tests"]))
            )
        if stage_key == "security-review":
            return security
        return []

    @staticmethod
    def _toolchain_capabilities(
        stage_key: str,
        external_repository: bool,
    ) -> list[str]:
        required: list[str] = []
        if stage_key in {"implementation-slice", "test"}:
            required.extend(("toolchain.python", "toolchain.scanners"))
        if stage_key == "implementation-slice":
            required.append("toolchain.container_builder")
        if external_repository and stage_key in {"implementation-slice", "test"}:
            required.append("toolchain.make")
        if stage_key == "security-review":
            required.append("toolchain.scanners")
        return required

    def compile(
        self,
        proposal: Mapping[str, Any],
        context: CompileContext,
        *,
        accepted_nodes: Mapping[str, str] | None = None,
        inherited_nodes: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        if str(proposal.get("schema_version")) != "1.0":
            raise ValueError("PlanProposal schema_version must be 1.0")
        if str(proposal.get("product_id")) != context.product_id:
            raise ValueError("PlanProposal product_id conflicts with compile context")
        proposal_nodes = proposal.get("nodes")
        if not isinstance(proposal_nodes, Sequence) or isinstance(proposal_nodes, (str, bytes)):
            raise TypeError("PlanProposal nodes must be an array")
        proposed_slices = [
            dict(node)
            for node in proposal_nodes
            if isinstance(node, Mapping) and str(node.get("stage_kind")) == "implementation_slice"
        ]
        if not proposed_slices:
            raise ValueError("PlanProposal requires at least one implementation_slice")
        proposed_keys = [
            _node_key(str(node.get("node_key") or "")) for node in proposed_slices
        ]
        if len(set(proposed_keys)) != len(proposed_keys):
            raise ValueError("PlanProposal node_key values must be unique")
        inherited_by_key: dict[str, dict[str, Any]] = {}
        if str(proposal.get("proposal_kind") or "") == "replan_delta":
            for node in inherited_nodes:
                if str(node.get("stage_kind") or "") != "implementation_slice":
                    continue
                key = _node_key(str(node.get("node_key") or ""))
                if key in inherited_by_key:
                    raise ValueError("inherited semantic node_key values must be unique")
                inherited_by_key[key] = dict(node)
            self._validate_replan_handoff(
                proposed_slices,
                inherited_by_key,
                context.mandatory_replan_gate_ids,
                context.blocked_replan_scope_paths,
            )
        merged_by_key = dict(inherited_by_key)
        for key, node in zip(proposed_keys, proposed_slices, strict=True):
            merged_by_key[key] = node
        slices = list(merged_by_key.values())
        raw_keys = list(merged_by_key)
        if len(set(raw_keys)) != len(raw_keys):
            raise ValueError("PlanProposal node_key values must be unique")
        self._validate_semantic_proposal(proposal, slices, raw_keys)

        proposal_digest = sha256_text(stable_json(proposal))
        accepted = dict(accepted_nodes or {})
        for reuse_key in tuple(accepted):
            if reuse_key == "lifecycle:architecture-review":
                continue
            if not reuse_key.startswith("semantic:"):
                accepted.pop(reuse_key)
                continue
            key = reuse_key.removeprefix("semantic:")
            if key not in inherited_by_key or key not in merged_by_key:
                accepted.pop(reuse_key)
                continue
            if stable_json(inherited_by_key[key]) != stable_json(merged_by_key[key]):
                accepted.pop(reuse_key)
        inheritance_digest = sha256_text(
            stable_json(
                {
                    "inherited_nodes": list(inherited_by_key.values()),
                    "accepted_nodes": accepted,
                    "architecture_source_task_id": context.architecture_source_task_id,
                }
            )
        )
        plan_seed = stable_json(
            [
                context.product_id,
                context.revision,
                context.parent_plan_id,
                proposal_digest,
                inheritance_digest,
                PLAN_COMPILER_VERSION,
            ]
        )
        plan_id = _controller_id("PLAN", plan_seed)
        created_at = str(proposal.get("created_at"))
        producer = {
            "role": "plan-compiler",
            "tier": "deterministic",
            "provider": None,
            "model": None,
        }
        nodes: list[dict[str, Any]] = []

        def add_node(
            node_id: str,
            stage_key: str,
            title: str,
            objective: str,
            acceptance_intents: Sequence[str],
            *,
            scope: Sequence[str] = ("artifacts/**",),
            goal_ids: Sequence[str] = (),
            external_dependencies: Sequence[str] = (),
            semantic_node_key: str | None = None,
            reuse_key: str | None = None,
        ) -> str:
            definition = stage_contract(stage_key)
            task_seed = stable_json([plan_id, node_id, context.revision])
            task_id = _controller_id("T", task_seed, 16)
            criteria = [
                {
                    "criterion_id": _controller_id(
                        "AC",
                        stable_json([plan_id, node_id, index, intent]),
                        16,
                    ),
                    "verification": str(intent),
                    "mandatory": True,
                }
                for index, intent in enumerate(acceptance_intents, start=1)
            ]
            contract: dict[str, Any] = {
                "schema_version": "2.0",
                "artifact_id": _controller_id("task-contract", task_seed),
                "product_id": context.product_id,
                "task_id": task_id,
                "root_task_id": context.root_task_id,
                "parent_task_id": context.created_by_task_id,
                "source_task_id": context.created_by_task_id,
                "plan_id": plan_id,
                "plan_node_id": node_id,
                "task_revision": context.revision,
                "root_context_ref": context.root_context_ref,
                "active_context_ref": f"evidence/task-{task_id}.json",
                "failure_id": context.source_failure_id,
                "hypothesis_id": None,
                "supersedes_task_id": accepted.get(reuse_key or node_id),
                "title": title,
                "objective": objective,
                "role": definition.role,
                "output_schema": definition.output_schema,
                "dependencies": list(external_dependencies),
                "conflict_keys": [f"product:{context.product_id}:workspace"],
                "acceptance": criteria,
                "required_capabilities": list(
                    dict.fromkeys(
                        [
                            *CAPABILITY_PROFILES[definition.capability_profile],
                            *self._toolchain_capabilities(
                                stage_key,
                                context.external_repository,
                            ),
                        ]
                    )
                ),
                "capability_profile": definition.capability_profile,
                "allowed_paths": list(dict.fromkeys(str(item) for item in scope)),
                "forbidden_paths": [
                    "secrets/**",
                    "production/**",
                    ".github/workflows/**",
                ],
                "risk_tier": "medium"
                if stage_key
                in {
                    "architecture-review",
                    "security-review",
                    "release-readiness-review",
                    "staging",
                    "production",
                    "observation",
                }
                else "low",
                "model_floor": "terra"
                if stage_key
                in {
                    "architecture-review",
                    "security-review",
                    "release-readiness-review",
                    "staging",
                    "production",
                    "observation",
                }
                else "luna",
                "idempotency_key": sha256_text(
                    stable_json([plan_id, node_id, context.revision, "task"])
                ),
                "status": "DRAFT",
                "priority": 100 - len(nodes),
                "critical_path_rank": len(nodes),
                "quality_gates": self._quality_gates(stage_key, context.external_repository),
                "lifecycle_stage": stage_key,
                "review_kind": definition.review_kind,
                "evidence_profile": definition.evidence_profile,
                "consumes_evidence_types": list(definition.consumes),
                "produces_evidence_types": list(definition.produces),
                "completion_obligation_ids": list(definition.obligations),
                "goal_ids": list(dict.fromkeys(str(value) for value in goal_ids)),
                "semantic_node_key": semantic_node_key,
                "production_side_effects": definition.production_side_effects,
            }
            nodes.append(
                {
                    "node_id": node_id,
                    "mandatory": True,
                    "task_contract": contract,
                    "task_contract_ref": f"evidence/task-{task_id}.json",
                    "task_contract_digest": sha256_text(stable_json(contract)),
                }
            )
            return node_id

        architecture_review = add_node(
            "architecture-review",
            "architecture-review",
            "Review architecture independently",
            "Review the accepted architecture before any implementation begins.",
            ("Architecture review is accepted without depending on Builder or Test evidence.",),
            external_dependencies=(
                context.architecture_source_task_id or context.created_by_task_id,
            ),
            reuse_key="lifecycle:architecture-review",
        )

        implementation_by_key: dict[str, str] = {}
        for index, (key, proposal_node) in enumerate(zip(raw_keys, slices, strict=True), start=1):
            scope_value = proposal_node.get("scope", [])
            scope = (
                [str(value) for value in scope_value]
                if isinstance(scope_value, list) and scope_value
                else ["src/**", "tests/**", "README.md"]
            )
            intents_value = proposal_node.get("acceptance_intents", [])
            intents = (
                [str(value) for value in intents_value]
                if isinstance(intents_value, list) and intents_value
                else ["The implementation slice satisfies its observable product outcome."]
            )
            goal_ids_value = proposal_node.get("goal_ids", [])
            goal_ids = (
                [str(value) for value in goal_ids_value] if isinstance(goal_ids_value, list) else []
            )
            compiled_node_id = add_node(
                f"implementation-{index:03d}-{key}",
                "implementation-slice",
                str(proposal_node.get("title") or f"Implement {key}"),
                str(proposal_node.get("objective") or ""),
                intents,
                scope=scope,
                goal_ids=goal_ids,
                semantic_node_key=key,
                reuse_key=f"semantic:{key}",
            )
            implementation_by_key[key] = compiled_node_id

        test = add_node(
            "test",
            "test",
            "Validate implementation evidence",
            "Prove all implementation slices and critical negative paths.",
            ("All controller-selected tests and acceptance checks pass.",),
            scope=("tests/**",),
        )
        security = add_node(
            "security-review",
            "security-review",
            "Review security posture",
            "Review the immutable implementation and test evidence for security risks.",
            ("No blocking security finding remains.",),
        )
        release_review = add_node(
            "release-readiness-review",
            "release-readiness-review",
            "Review release readiness independently",
            "Independently verify implementation, test, security, and release evidence.",
            ("The immutable candidate is independently accepted for staging.",),
        )
        staging = add_node(
            "staging",
            "staging",
            "Deploy immutable staging candidate",
            "Create a private pull request and deploy the exact candidate to staging.",
            ("Required checks, staging health, and rollback readiness are proven.",),
            scope=("artifacts/**", "release-artifacts/**"),
        )
        acceptance = add_node(
            "product-acceptance",
            "product-acceptance",
            "Run product acceptance in staging",
            "Exercise every critical journey against the isolated staging release.",
            ("Every mandatory product goal is proven in staging.",),
        )
        production = add_node(
            "production",
            "production",
            "Promote the accepted candidate",
            "Promote only the exact staging-accepted digest through the production adapter.",
            ("Production health and rollback proof bind to the exact release digest.",),
            scope=("artifacts/**", "release-artifacts/**"),
        )
        observation = add_node(
            "observation",
            "observation",
            "Observe production release",
            "Verify the production release remains healthy for the observation window.",
            ("Observation passes and every completion obligation is reachable.",),
        )

        edges: list[dict[str, Any]] = []

        def edge(source: str, target: str, edge_type: str = "depends_on") -> None:
            edges.append(
                {
                    "from": source,
                    "to": target,
                    "edge_type": edge_type,
                    "required": True,
                }
            )

        for key, proposal_node in zip(raw_keys, slices, strict=True):
            implementation = implementation_by_key[key]
            dependencies = [
                implementation_by_key[_node_key(str(value))]
                for value in proposal_node.get("depends_on", [])
            ]
            if dependencies:
                for dependency in dependencies:
                    edge(dependency, implementation)
            else:
                edge(architecture_review, implementation)
            edge(implementation, test)
            edge(implementation, security, "evidence_from")
            edge(implementation, release_review, "evidence_from")
        edge(test, security)
        edge(test, release_review, "evidence_from")
        edge(security, release_review)
        edge(release_review, staging)
        edge(staging, acceptance)
        edge(acceptance, production)
        edge(release_review, production, "evidence_from")
        edge(production, observation)

        goals = []
        acceptance_ids = [
            criterion["criterion_id"]
            for node in nodes
            for criterion in node["task_contract"]["acceptance"]
        ]
        proposal_goals = proposal.get("goals", [])
        if isinstance(proposal_goals, list):
            for index, goal in enumerate(proposal_goals, start=1):
                if not isinstance(goal, Mapping):
                    continue
                goals.append(
                    {
                        "goal_id": str(goal.get("goal_id") or f"goal-{index}"),
                        "statement": str(goal.get("statement") or ""),
                        "mandatory": bool(goal.get("mandatory", True)),
                        "acceptance_ids": acceptance_ids,
                    }
                )
        if not goals:
            goals.append(
                {
                    "goal_id": "root-goal",
                    "statement": str(proposal.get("summary") or "Deliver the product goal."),
                    "mandatory": True,
                    "acceptance_ids": acceptance_ids,
                }
            )
            for node in nodes:
                if node["task_contract"]["lifecycle_stage"] == "implementation-slice":
                    node["task_contract"]["goal_ids"] = ["root-goal"]

        plan: dict[str, Any] = {
            "schema_version": "2.0",
            "artifact_id": _controller_id("backlog-plan", plan_seed),
            "product_id": context.product_id,
            "created_at": created_at,
            "producer": producer,
            "policy_digest": self.policy_digest,
            "status": "completed",
            "plan_id": plan_id,
            "revision": context.revision,
            "parent_plan_id": context.parent_plan_id,
            "source_failure_id": context.source_failure_id,
            "goals": goals,
            "nodes": nodes,
            "edges": edges,
            "completion_criteria": [
                "All controller-owned completion obligations are satisfied.",
                "The exact staging digest is promoted and observed in production.",
                "No mandatory goal is closed by documentation-only evidence.",
            ],
            "summary": "Controller-compiled semantic lifecycle plan.",
            "compiler_version": PLAN_COMPILER_VERSION,
            "lifecycle_version": LIFECYCLE_VERSION,
            "proposal_artifact_ref": context.proposal_artifact_ref,
            "proposal_digest": proposal_digest,
        }
        validate_compiled_plan(plan)
        return plan
