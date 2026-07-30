from __future__ import annotations

import json
import sqlite3
import zipfile
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from test_worker import make_config, selected_registry

from factory.artifacts import ArtifactStore
from factory.autonomy import TaskOutcome
from factory.capabilities import CapabilityBroker, CapabilityCheck
from factory.common import sha256_text, stable_json
from factory.intake import IntakeRejected, IntakeService
from factory.pipeline import PipelineCoordinator
from factory.plan_compiler import CompileContext, PlanCompiler
from factory.plan_semantics import PlanContractViolation, validate_compiled_plan
from factory.policy import policy_digest
from factory.reconciler import ReconcilerLoop
from factory.recovery import (
    apply_recovery_plan,
    build_recovery_plan,
    state_audit,
    verify_active_graphs,
    verify_recovery_preconditions,
)
from factory.replan_lineage import implementation_lineage
from factory.state import StateStore
from scripts.verify_version_consistency import (
    VersionConsistencyError,
    verify_version_consistency,
)


def configured(tmp_path: Path):
    return make_config(
        tmp_path,
        selected_registry(tmp_path / "registry.yaml", selected="gpt-5.6-luna"),
    )


def proposal(config, *, product_id: str = "product-semantic") -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "artifact_id": "plan-proposal-semantic-001",
        "product_id": product_id,
        "created_at": "2026-07-30T00:00:00Z",
        "producer": {
            "role": "task-specifier",
            "tier": "luna",
            "provider": "fake",
            "model": "fake",
        },
        "policy_digest": policy_digest(config),
        "status": "completed",
        "proposal_kind": "initial",
        "parent_plan_id": None,
        "source_failure_id": None,
        "goals": [
            {
                "goal_id": "root-goal",
                "statement": "Deliver the complete observable product behavior",
                "mandatory": True,
            }
        ],
        "nodes": [
            {
                "node_key": "core-journey",
                "stage_kind": "implementation_slice",
                "title": "Implement the core journey",
                "objective": "Implement the complete observable core product journey",
                "depends_on": [],
                "scope": ["src/**", "tests/**", "README.md"],
                "acceptance_intents": [
                    "The critical user journey succeeds and its negative path is safe."
                ],
                "goal_ids": ["root-goal"],
            }
        ],
        "summary": "Semantic implementation proposal for the complete product goal.",
        "evidence_refs": ["evidence/architecture-product-semantic.json"],
    }


def compiled_plan(tmp_path: Path) -> dict[str, Any]:
    config = configured(tmp_path)
    semantic = proposal(config)
    ArtifactStore(config).validate("plan-proposal-v1.schema.json", semantic)
    return PlanCompiler(policy_digest=policy_digest(config)).compile(
        semantic,
        CompileContext(
            product_id="product-semantic",
            revision=1,
            parent_plan_id="PLAN-LEGACY-SEMANTIC",
            source_failure_id=None,
            created_by_task_id="T-TASKSPECIFIER001",
            root_task_id="T-ROOTSEMANTIC001",
            root_context_ref="evidence/intake-product-semantic.json",
            external_repository=False,
            proposal_artifact_ref="evidence/plan-proposal-semantic-001.json",
        ),
    )


def test_AUT_P0_028_architecture_review_has_no_builder_or_test_prerequisite(
    tmp_path: Path,
) -> None:
    plan = compiled_plan(tmp_path)
    architecture = next(
        node
        for node in plan["nodes"]
        if node["task_contract"]["lifecycle_stage"] == "architecture-review"
    )
    predecessors = {
        edge["from"]
        for edge in plan["edges"]
        if edge["to"] == architecture["node_id"] and edge["required"]
    }
    assert predecessors == set()
    assert architecture["task_contract"]["consumes_evidence_types"] == [
        "architecture_package"
    ]


def test_AUT_P0_029_release_review_without_security_is_rejected_pre_ingestion(
    tmp_path: Path,
) -> None:
    plan = compiled_plan(tmp_path)
    plan["edges"] = [
        edge
        for edge in plan["edges"]
        if not (
            edge["from"] == "security-review"
            and edge["to"] == "release-readiness-review"
        )
    ]
    with pytest.raises(
        PlanContractViolation,
        match="security_review|release readiness review requires",
    ) as captured:
        validate_compiled_plan(plan)
    assert captured.value.reason_code == "missing_declared_predecessor"


def test_AUT_P0_030_one_reviewer_node_cannot_close_product_goal(
    tmp_path: Path,
) -> None:
    plan = compiled_plan(tmp_path)
    plan["nodes"] = [
        node
        for node in plan["nodes"]
        if node["node_id"] == "architecture-review"
    ]
    plan["edges"] = []
    with pytest.raises(PlanContractViolation, match="implementation slice"):
        validate_compiled_plan(plan)


def test_AUT_P0_032_plan_compiler_is_deterministic_and_controller_owned(
    tmp_path: Path,
) -> None:
    first = compiled_plan(tmp_path)
    second = compiled_plan(tmp_path)
    assert first == second
    assert len({node["task_contract"]["task_id"] for node in first["nodes"]}) == len(
        first["nodes"]
    )
    for node in first["nodes"]:
        contract = node["task_contract"]
        assert contract["lifecycle_stage"]
        assert contract["evidence_profile"]
        assert contract["produces_evidence_types"]
        assert contract["role"] not in {"task-specifier", "replanner"}
        assert contract["idempotency_key"] != first["proposal_digest"]
    config = configured(tmp_path)
    store = ArtifactStore(config)
    assert not store.validate("backlog-plan-v2.schema.json", first)
    for node in first["nodes"]:
        assert not store.validate(
            "task-contract-v2.schema.json",
            node["task_contract"],
        )


def test_replan_compiler_merges_and_reuses_accepted_lineage_nodes(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    semantic = proposal(config)
    semantic.update(
        {
            "artifact_id": "plan-proposal-semantic-replan",
            "producer": {
                "role": "replanner",
                "tier": "terra",
                "provider": "fake",
                "model": "fake",
            },
            "proposal_kind": "replan_delta",
            "parent_plan_id": "PLAN-PARENT-001",
            "source_failure_id": "failure-container-runtime",
            "nodes": [
                {
                    "node_key": "container-runtime",
                    "stage_kind": "implementation_slice",
                    "title": "Repair the container runtime",
                    "objective": (
                        "Build the container with the controller-provided rootless runtime"
                    ),
                    "depends_on": ["architecture-review"],
                    "scope": ["Dockerfile", "compose.yaml", "tests/**"],
                    "acceptance_intents": [
                        "The image build and startup smoke test pass without a Docker socket."
                    ],
                    "goal_ids": ["root-goal"],
                }
            ],
        }
    )
    inherited = [
        {
            "node_key": "architecture-review",
            "stage_kind": "implementation_slice",
            "title": "Implement the architecture review view",
            "objective": "Implement the accepted architecture review product view",
            "depends_on": [],
            "scope": ["src/**", "tests/runtime/**"],
            "acceptance_intents": [
                "The runtime foundation passes its deterministic service checks."
            ],
            "goal_ids": ["root-goal"],
        }
    ]
    compiled = PlanCompiler(policy_digest=policy_digest(config)).compile(
        semantic,
        CompileContext(
            product_id="product-semantic",
            revision=2,
            parent_plan_id="PLAN-PARENT-001",
            source_failure_id="failure-container-runtime",
            created_by_task_id="T-REPLANNER-001",
            root_task_id="T-ROOTSEMANTIC001",
            root_context_ref="evidence/intake-product-semantic.json",
            external_repository=False,
            proposal_artifact_ref="evidence/plan-proposal-semantic-replan.json",
            architecture_source_task_id="T-ARCHITECTURE-SOURCE",
        ),
        inherited_nodes=inherited,
        accepted_nodes={
            "semantic:architecture-review": "T-ACCEPTED-FOUNDATION",
            "lifecycle:architecture-review": "T-ACCEPTED-ARCH-REVIEW",
        },
    )

    implementations = {
        str(node["task_contract"]["semantic_node_key"]): node["task_contract"]
        for node in compiled["nodes"]
        if node["task_contract"]["lifecycle_stage"] == "implementation-slice"
    }
    architecture = next(
        node["task_contract"]
        for node in compiled["nodes"]
        if node["task_contract"]["lifecycle_stage"] == "architecture-review"
    )
    assert set(implementations) == {"architecture-review", "container-runtime"}
    assert (
        implementations["architecture-review"]["supersedes_task_id"]
        == "T-ACCEPTED-FOUNDATION"
    )
    assert implementations["container-runtime"]["supersedes_task_id"] is None
    assert architecture["supersedes_task_id"] == "T-ACCEPTED-ARCH-REVIEW"
    assert architecture["dependencies"] == ["T-ARCHITECTURE-SOURCE"]
    assert compiled["proposal_digest"] == sha256_text(stable_json(semantic))


def test_replan_compiler_requires_fresh_mandatory_gate_coverage(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    semantic = proposal(config)
    inherited_dependency = {
        "node_key": "dependency-contract",
        "stage_kind": "implementation_slice",
        "title": "Implement dependency metadata",
        "objective": (
            "Provide metadata previously accepted by target-dependency-audit "
            "and target-license-check"
        ),
        "depends_on": [],
        "scope": ["pyproject.toml"],
        "acceptance_intents": [
            "The accepted dependency metadata remains available to repository checks."
        ],
        "goal_ids": ["root-goal"],
    }
    semantic.update(
        {
            "artifact_id": "plan-proposal-gate-obligation-replan",
            "producer": {
                "role": "replanner",
                "tier": "terra",
                "provider": "fake",
                "model": "fake",
            },
            "proposal_kind": "replan_delta",
            "parent_plan_id": "PLAN-PARENT-GATES",
            "source_failure_id": "failure-gates",
            "nodes": [
                dict(inherited_dependency),
                {
                    "node_key": "image-security",
                    "stage_kind": "implementation_slice",
                    "title": "Record immutable image security evidence",
                    "objective": "Bind the release candidate to an immutable image digest",
                    "depends_on": ["dependency-contract"],
                    "scope": ["Dockerfile", "tests/**"],
                    "acceptance_intents": [
                        "Container security evidence is bound to the candidate digest."
                    ],
                    "goal_ids": ["root-goal"],
                },
            ],
        }
    )
    context = CompileContext(
        product_id="product-semantic",
        revision=2,
        parent_plan_id="PLAN-PARENT-GATES",
        source_failure_id="failure-gates",
        created_by_task_id="T-REPLANNER-GATES",
        root_task_id="T-ROOTSEMANTIC001",
        root_context_ref="evidence/intake-product-semantic.json",
        external_repository=True,
        proposal_artifact_ref="evidence/plan-proposal-gate-obligation-replan.json",
        architecture_source_task_id="T-ARCHITECTURE-SOURCE",
        mandatory_replan_gate_ids=(
            "target-dependency-audit",
            "target-license-check",
        ),
    )

    with pytest.raises(
        PlanContractViolation,
        match=(
            "fresh implementation slices do not cover failed mandatory gates: "
            "target-dependency-audit, target-license-check"
        ),
    ):
        PlanCompiler(policy_digest=policy_digest(config)).compile(
            semantic,
            context,
            inherited_nodes=[inherited_dependency],
            accepted_nodes={
                "semantic:dependency-contract": "T-ACCEPTED-DEPENDENCIES"
            },
        )

    semantic["nodes"][1]["objective"] = (
        "Repair target-dependency-audit and target-license-check by adding the "
        "missing executable dependency contract"
    )
    compiled = PlanCompiler(policy_digest=policy_digest(config)).compile(
        semantic,
        context,
        inherited_nodes=[inherited_dependency],
        accepted_nodes={
            "semantic:dependency-contract": "T-ACCEPTED-DEPENDENCIES"
        },
    )
    implementations = [
        node["task_contract"]
        for node in compiled["nodes"]
        if node["task_contract"]["lifecycle_stage"] == "implementation-slice"
    ]
    assert any(
        node["semantic_node_key"] == "image-security"
        and node["supersedes_task_id"] is None
        for node in implementations
    )


def test_replan_compiler_rejects_delta_without_fresh_implementation(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    semantic = proposal(config)
    inherited = dict(semantic["nodes"][0])
    semantic.update(
        {
            "producer": {
                "role": "replanner",
                "tier": "terra",
                "provider": "fake",
                "model": "fake",
            },
            "proposal_kind": "replan_delta",
            "parent_plan_id": "PLAN-PARENT-NOOP",
            "source_failure_id": "failure-noop",
            "nodes": [dict(inherited)],
        }
    )

    with pytest.raises(
        PlanContractViolation,
        match="replan_delta has no fresh implementation slice",
    ):
        PlanCompiler(policy_digest=policy_digest(config)).compile(
            semantic,
            CompileContext(
                product_id="product-semantic",
                revision=2,
                parent_plan_id="PLAN-PARENT-NOOP",
                source_failure_id="failure-noop",
                created_by_task_id="T-REPLANNER-NOOP",
                root_task_id="T-ROOTSEMANTIC001",
                root_context_ref="evidence/intake-product-semantic.json",
                external_repository=False,
                proposal_artifact_ref="evidence/plan-proposal-noop.json",
                architecture_source_task_id="T-ARCHITECTURE-SOURCE",
            ),
            inherited_nodes=[inherited],
            accepted_nodes={"semantic:core-journey": "T-ACCEPTED-CORE"},
        )


def test_replan_compiler_does_not_reuse_changed_accepted_node(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    semantic = proposal(config)
    semantic.update(
        {
            "producer": {
                "role": "replanner",
                "tier": "terra",
                "provider": "fake",
                "model": "fake",
            },
            "proposal_kind": "replan_delta",
            "parent_plan_id": "PLAN-PARENT-001",
            "source_failure_id": "failure-foundation",
        }
    )
    inherited = [dict(semantic["nodes"][0])]
    semantic["nodes"][0]["objective"] = (
        "Replace the previously accepted foundation after new contrary evidence"
    )
    compiled = PlanCompiler(policy_digest=policy_digest(config)).compile(
        semantic,
        CompileContext(
            product_id="product-semantic",
            revision=2,
            parent_plan_id="PLAN-PARENT-001",
            source_failure_id="failure-foundation",
            created_by_task_id="T-REPLANNER-002",
            root_task_id="T-ROOTSEMANTIC001",
            root_context_ref="evidence/intake-product-semantic.json",
            external_repository=False,
            proposal_artifact_ref="evidence/plan-proposal-semantic-replan-2.json",
        ),
        inherited_nodes=inherited,
        accepted_nodes={"semantic:core-journey": "T-ACCEPTED-CORE"},
    )
    implementation = next(
        node["task_contract"]
        for node in compiled["nodes"]
        if node["task_contract"]["lifecycle_stage"] == "implementation-slice"
    )
    assert implementation["supersedes_task_id"] is None


def test_plan_compiler_rejects_product_requirements_used_as_path_scope(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    semantic = proposal(config)
    semantic["nodes"][0]["scope"] = [
        "Runtime HTTP service with protected runtime workflow",
        "Bearer authentication and authorization rejection paths",
    ]
    with pytest.raises(
        ValueError,
        match="relative POSIX path globs, not prose",
    ):
        PlanCompiler(policy_digest=policy_digest(config)).compile(
            semantic,
            CompileContext(
                product_id="product-semantic",
                revision=1,
                parent_plan_id=None,
                source_failure_id=None,
                created_by_task_id="T-TASKSPECIFIER001",
                root_task_id="T-ROOTSEMANTIC001",
                root_context_ref="evidence/intake-product-semantic.json",
                external_repository=False,
                proposal_artifact_ref="evidence/plan-proposal-semantic-001.json",
            ),
        )


def test_AUT_P0_038_product_acceptance_is_mandatory_between_staging_and_production(
    tmp_path: Path,
) -> None:
    plan = compiled_plan(tmp_path)
    required_edges = {
        (edge["from"], edge["to"])
        for edge in plan["edges"]
        if edge["required"]
    }
    assert ("staging", "product-acceptance") in required_edges
    assert ("product-acceptance", "production") in required_edges
    broken = deepcopy(plan)
    broken["nodes"] = [
        node for node in broken["nodes"] if node["node_id"] != "product-acceptance"
    ]
    broken["edges"] = [
        edge
        for edge in broken["edges"]
        if "product-acceptance" not in {edge["from"], edge["to"]}
    ]
    with pytest.raises(PlanContractViolation, match="product-acceptance") as captured:
        validate_compiled_plan(broken)
    assert captured.value.reason_code == "completion_unreachable"


def test_AUT_P1_012_evidence_types_are_not_interchangeable(
    tmp_path: Path,
) -> None:
    plan = compiled_plan(tmp_path)
    architecture = next(
        node
        for node in plan["nodes"]
        if node["node_id"] == "architecture-review"
    )
    architecture["task_contract"]["consumes_evidence_types"] = [
        "security_review"
    ]
    with pytest.raises(PlanContractViolation, match="consumes_evidence_types") as captured:
        validate_compiled_plan(plan)
    assert captured.value.reason_code == "evidence_profile_mismatch"


def test_AUT_P0_039_compilation_is_read_only_until_atomic_plan_ingestion(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    product_id = "product-semantic"
    state.create_product_v2(
        product_id=product_id,
        owner_id="owner",
        source="test",
        goal_text="Deliver the complete observable product behavior",
        delivery_mode="new_repository",
        repository_url=None,
        repository_name="semantic-product",
        repository_visibility="private",
        root_goal_ref=f"evidence/intake-{product_id}.json",
        constraints_ref=None,
        owner_defaults_ref=None,
        idempotency_key=sha256_text(f"intake:{product_id}"),
        rate_limit=None,
    )
    creator_id = "T-TASKSPECIFIER001"
    state.add_task(
        task_id=creator_id,
        product_id=product_id,
        title="Propose semantic product work",
        role="task-specifier",
        output_schema="plan-proposal-v1.schema.json",
        contract_ref=f"evidence/task-{creator_id}.json",
        stage_key="task-specifier",
        graph_status="ACCEPTED",
    )
    semantic = proposal(config)
    semantic_path = ArtifactStore(config).write(
        "plan-proposal-v1.schema.json",
        semantic,
        filename="plan-proposal-semantic-001.json",
    )
    creator = state.get_task(creator_id)
    assert creator is not None
    prepared = PipelineCoordinator(config, state).prepare_after(
        creator,
        semantic,
        semantic_path,
    )
    assert prepared.plan is not None
    assert len(state.list_tasks(product_id)) == 1
    assert state.get_product(product_id)["active_plan_revision"] == 0

    task_ids = state.ingest_plan(
        prepared.plan,
        plan_artifact_ref=prepared.plan["plan_artifact_ref"],
        plan_digest=prepared.plan["plan_digest"],
        created_by_task_id=creator_id,
    )
    assert len(task_ids) == 9
    assert state.get_product(product_id)["active_plan_revision"] == 1
    architecture = next(
        task
        for task in state.list_tasks(product_id)
        if task.get("lifecycle_stage") == "architecture-review"
    )
    assert architecture["graph_status"] == "READY"
    assert architecture["dependencies_json"] == f'["{creator_id}"]'
    state.close()


def test_replan_pipeline_carries_accepted_parent_results_into_new_revision(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    artifacts = ArtifactStore(config)
    product_id = "product-replan-lineage"
    state.create_product_v2(
        product_id=product_id,
        owner_id="owner",
        source="test",
        goal_text="Deliver the complete observable product behavior",
        delivery_mode="new_repository",
        repository_url=None,
        repository_name="replan-lineage",
        repository_visibility="private",
        root_goal_ref=f"evidence/intake-{product_id}.json",
        constraints_ref=None,
        owner_defaults_ref=None,
        idempotency_key=sha256_text(f"intake:{product_id}"),
        rate_limit=None,
    )
    architecture_source_id = "T-LINEAGE-ARCHITECT"
    state.add_task(
        task_id=architecture_source_id,
        product_id=product_id,
        title="Create the architecture package",
        role="solution-architect",
        output_schema="architecture-package.schema.json",
        contract_ref=f"evidence/task-{architecture_source_id}.json",
        stage_key="solution-architect",
        graph_status="ACCEPTED",
    )
    creator_id = "T-LINEAGE-SPECIFIER"
    state.add_task(
        task_id=creator_id,
        product_id=product_id,
        title="Propose the initial semantic plan",
        role="task-specifier",
        output_schema="plan-proposal-v1.schema.json",
        contract_ref=f"evidence/task-{creator_id}.json",
        stage_key="task-specifier",
        graph_status="ACCEPTED",
    )
    initial = proposal(config, product_id=product_id)
    initial["artifact_id"] = "plan-proposal-lineage-initial"
    initial_path = artifacts.write(
        "plan-proposal-v1.schema.json",
        initial,
        filename="plan-proposal-lineage-initial.json",
    )
    pipeline = PipelineCoordinator(config, state, artifacts)
    creator = state.get_task(creator_id)
    assert creator is not None
    prepared = pipeline.prepare_after(creator, initial, initial_path)
    assert prepared.plan is not None
    state.ingest_plan(
        prepared.plan,
        plan_artifact_ref=str(prepared.plan["plan_artifact_ref"]),
        plan_digest=str(prepared.plan["plan_digest"]),
        created_by_task_id=creator_id,
    )
    first_plan_id = str(state.get_product(product_id)["active_plan_id"])
    first_tasks = [
        task for task in state.list_tasks(product_id) if task["plan_id"] == first_plan_id
    ]
    first_architecture = next(
        task
        for task in first_tasks
        if task["lifecycle_stage"] == "architecture-review"
    )
    first_implementation = next(
        task
        for task in first_tasks
        if task["lifecycle_stage"] == "implementation-slice"
    )
    with state._lock, state._connection:
        for task, label in (
            (first_architecture, "architecture"),
            (first_implementation, "implementation"),
        ):
            result_path = config.evidence_dir / f"accepted-{label}.json"
            result_path.write_text(
                json.dumps({"summary": f"Accepted {label} result."}),
                encoding="utf-8",
            )
            state._connection.execute(
                """UPDATE tasks
                      SET graph_status='ACCEPTED', status='DONE',
                          result_ref=?, result_digest=?
                    WHERE task_id=?""",
                (
                    f"evidence/{result_path.name}",
                    sha256_text(f"accepted-{label}"),
                    task["task_id"],
                ),
            )
    refreshed_architecture = state.get_task(str(first_architecture["task_id"]))
    refreshed_implementation = state.get_task(str(first_implementation["task_id"]))
    assert refreshed_architecture is not None
    assert refreshed_implementation is not None
    first_architecture = refreshed_architecture
    first_implementation = refreshed_implementation

    replanner_id = "T-LINEAGE-REPLANNER"
    state.add_task(
        task_id=replanner_id,
        product_id=product_id,
        title="Repair the affected runtime slice",
        role="replanner",
        output_schema="plan-proposal-v1.schema.json",
        contract_ref=f"evidence/task-{replanner_id}.json",
        stage_key="replan",
        plan_id=first_plan_id,
        graph_status="ACCEPTED",
    )
    replan = proposal(config, product_id=product_id)
    replan.update(
        {
            "artifact_id": "plan-proposal-lineage-replan",
            "producer": {
                "role": "replanner",
                "tier": "terra",
                "provider": "fake",
                "model": "fake",
            },
            "proposal_kind": "replan_delta",
            "parent_plan_id": first_plan_id,
            "source_failure_id": "failure-runtime-extension",
            "nodes": [
                {
                    "node_key": "runtime-extension",
                    "stage_kind": "implementation_slice",
                    "title": "Implement the runtime extension",
                    "objective": "Implement and verify the newly isolated runtime extension",
                    "depends_on": ["core-journey"],
                    "scope": ["src/runtime/**", "tests/runtime/**"],
                    "acceptance_intents": [
                        "The isolated runtime extension passes its deterministic checks."
                    ],
                    "goal_ids": ["root-goal"],
                }
            ],
        }
    )
    replan_path = artifacts.write(
        "plan-proposal-v1.schema.json",
        replan,
        filename="plan-proposal-lineage-replan.json",
    )
    replanner = state.get_task(replanner_id)
    assert replanner is not None
    runtime_plan = pipeline._compile_proposal(replanner, replan, replan_path)
    implementation_contracts = {
        str(node["task_contract"]["semantic_node_key"]): node["task_contract"]
        for node in runtime_plan["nodes"]
        if node["task_contract"]["lifecycle_stage"] == "implementation-slice"
    }
    architecture_contract = next(
        node["task_contract"]
        for node in runtime_plan["nodes"]
        if node["task_contract"]["lifecycle_stage"] == "architecture-review"
    )
    assert set(implementation_contracts) == {"core-journey", "runtime-extension"}
    assert (
        implementation_contracts["core-journey"]["supersedes_task_id"]
        == first_implementation["task_id"]
    )
    assert (
        architecture_contract["supersedes_task_id"]
        == first_architecture["task_id"]
    )

    state.ingest_plan(
        runtime_plan,
        plan_artifact_ref=str(runtime_plan["plan_artifact_ref"]),
        plan_digest=str(runtime_plan["plan_digest"]),
        created_by_task_id=replanner_id,
    )
    second_plan_id = str(state.get_product(product_id)["active_plan_id"])
    second_tasks = [
        task for task in state.list_tasks(product_id) if task["plan_id"] == second_plan_id
    ]
    reused = {
        str(task["semantic_node_key"]): task
        for task in second_tasks
        if task.get("semantic_node_key")
    }
    second_architecture = next(
        task
        for task in second_tasks
        if task["lifecycle_stage"] == "architecture-review"
    )
    assert reused["core-journey"]["graph_status"] == "ACCEPTED"
    assert reused["core-journey"]["result_ref"] == first_implementation["result_ref"]
    assert reused["runtime-extension"]["graph_status"] != "BLOCKED_DEPENDENCY"
    assert second_architecture["graph_status"] == "ACCEPTED"
    assert second_architecture["result_ref"] == first_architecture["result_ref"]
    lineage = {
        str(node.proposal_node["node_key"]): node
        for node in implementation_lineage(
            state,
            config.evidence_dir,
            product_id,
            second_plan_id,
        )
    }
    assert lineage["core-journey"].graph_status == "ACCEPTED"
    assert lineage["runtime-extension"].proposal_node["depends_on"] == [
        "core-journey"
    ]
    state.close()


class MissingBuildToolProbe:
    def check(
        self,
        capability: str,
        *,
        product: dict[str, Any],
    ) -> CapabilityCheck:
        del product
        reasons = {
            "toolchain.make": "controller_toolchain_make_missing",
            "toolchain.container_builder": (
                "controller_toolchain_container_builder_unavailable"
            ),
        }
        if capability in reasons:
            return CapabilityCheck(
                capability,
                "DENIED_POLICY",
                "test-toolchain",
                reasons[capability],
            )
        return CapabilityCheck(capability, "AVAILABLE", "test-toolchain")


def test_AUT_P0_034_missing_make_and_container_block_builder_without_llm(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    product_id = "product-semantic"
    state.create_product_v2(
        product_id=product_id,
        owner_id="owner",
        source="test",
        goal_text="Deliver the complete observable product behavior",
        delivery_mode="existing_repository",
        repository_url="https://github.com/brullik/semantic-product",
        repository_name="semantic-product",
        repository_visibility="private",
        root_goal_ref=f"evidence/intake-{product_id}.json",
        constraints_ref=None,
        owner_defaults_ref=None,
        idempotency_key=sha256_text(f"intake:{product_id}"),
        rate_limit=None,
    )
    creator_id = "T-TASKSPECIFIER001"
    state.add_task(
        task_id=creator_id,
        product_id=product_id,
        title="Propose semantic product work",
        role="task-specifier",
        output_schema="plan-proposal-v1.schema.json",
        contract_ref=f"evidence/task-{creator_id}.json",
        stage_key="task-specifier",
        graph_status="ACCEPTED",
    )
    semantic = proposal(config)
    semantic_path = ArtifactStore(config).write(
        "plan-proposal-v1.schema.json",
        semantic,
        filename="plan-proposal-semantic-001.json",
    )
    creator = state.get_task(creator_id)
    assert creator is not None
    prepared = PipelineCoordinator(config, state).prepare_after(
        creator,
        semantic,
        semantic_path,
    )
    assert prepared.plan is not None
    state.ingest_plan(
        prepared.plan,
        plan_artifact_ref=prepared.plan["plan_artifact_ref"],
        plan_digest=prepared.plan["plan_digest"],
        created_by_task_id=creator_id,
    )
    CapabilityBroker(
        config,
        state,
        probe=MissingBuildToolProbe(),
    ).preflight_product(product_id)

    architecture = state.claim_task(worker_id="architecture-reviewer")
    assert architecture is not None
    assert architecture["lifecycle_stage"] == "architecture-review"
    state.commit_task_outcome(
        TaskOutcome(
            task_id=str(architecture["task_id"]),
            worker_id="architecture-reviewer",
            lease_token=str(architecture["lease_token"]),
            expected_plan_revision=1,
            idempotency_key=sha256_text("architecture-accepted"),
            result_ref="internal://architecture-review",
            result_digest=sha256_text("architecture-review"),
            status="ACCEPTED",
        )
    )
    builder = next(
        task
        for task in state.list_tasks(product_id)
        if task.get("lifecycle_stage") == "implementation-slice"
    )
    assert builder["graph_status"] == "BLOCKED_CAPABILITY"
    assert "toolchain.make" in str(builder["blocked_ref"])
    assert "toolchain.container_builder" in str(builder["blocked_ref"])
    assert not any(
        task.get("lifecycle_stage") == "implementation-slice"
        for task in state.runnable_tasks(product_id)
    )
    with state._lock:
        incidents = state._connection.execute(
            """SELECT reason_code FROM controller_incidents
               WHERE product_id=? AND status='OPEN'""",
            (product_id,),
        ).fetchall()
    assert {
        "controller_toolchain_make_missing",
        "controller_toolchain_container_builder_unavailable",
    }.issubset({str(row[0]) for row in incidents})
    state.close()


def test_maintenance_closes_intake_and_recovery_apply_is_restart_safe(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    product_id = "product-recovery"
    state.create_product_v2(
        product_id=product_id,
        owner_id="owner",
        source="test",
        goal_text="Recover the durable product without deleting history",
        delivery_mode="new_repository",
        repository_url=None,
        repository_name="recovery-product",
        repository_visibility="private",
        root_goal_ref=f"evidence/intake-{product_id}.json",
        constraints_ref=None,
        owner_defaults_ref=None,
        idempotency_key=sha256_text(f"intake:{product_id}"),
        rate_limit=None,
    )
    state.add_task(
        task_id="T-RECOVERY-SOURCE",
        product_id=product_id,
        title="Historical failed implementation",
        role="builder",
        output_schema="attempt-result.schema.json",
        contract_ref="evidence/task-T-RECOVERY-SOURCE.json",
        graph_status="FAILED_SEMANTIC",
    )
    state.enter_maintenance("semantic-lifecycle-migration")
    with pytest.raises(IntakeRejected, match="maintenance"):
        IntakeService(config, state, ArtifactStore(config)).submit(
            source="cli",
            owner_id="owner",
            goal_text="This intake must wait until maintenance ends",
            delivery_mode="new_repository",
            repository_name="blocked-intake",
        )
    audit = state_audit(state)
    assert audit["counts"]["products"] == 1
    recovery = build_recovery_plan(state)
    with state._lock, state._connection:
        state._record_event(
            product_id,
            None,
            "maintenance_heartbeat",
            {"reason": "append-only operational evidence"},
        )
    assert verify_recovery_preconditions(state, recovery)["status"] == "PASS"

    first = apply_recovery_plan(config, state, recovery)
    assert first["applications"][0]["status"] == "APPLIED"
    source = state.get_task("T-RECOVERY-SOURCE")
    assert source is not None
    assert source["graph_status"] == "SUPERSEDED"
    recovery_tasks = [
        task
        for task in state.list_tasks(product_id)
        if task.get("stage_key") == "semantic-lifecycle-recovery"
    ]
    assert len(recovery_tasks) == 1
    assert recovery_tasks[0]["graph_status"] == "READY"
    assert verify_active_graphs(config, state)["status"] == "PASS"

    replay = apply_recovery_plan(config, state, recovery)
    assert replay["applications"][0]["status"] == "REPLAYED"
    assert len(
        [
            task
            for task in state.list_tasks(product_id)
            if task.get("stage_key") == "semantic-lifecycle-recovery"
        ]
    ) == 1
    state.leave_maintenance()
    assert not state.maintenance_active()
    state.close()


def test_deploy_maintenance_auto_resumes_after_expiry_and_drain(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    product_id = "product-maintenance-lease"
    state.create_product_v2(
        product_id=product_id,
        owner_id="owner",
        source="test",
        goal_text="Prove a deploy maintenance lease cannot strand ready work",
        delivery_mode="new_repository",
        repository_url=None,
        repository_name="maintenance-lease",
        repository_visibility="private",
        root_goal_ref=f"evidence/intake-{product_id}.json",
        constraints_ref=None,
        owner_defaults_ref=None,
        idempotency_key=sha256_text(f"intake:{product_id}"),
        rate_limit=None,
    )
    for task_id in ("T-MAINT-LEASE-A", "T-MAINT-LEASE-B"):
        state.add_task(
            task_id=task_id,
            product_id=product_id,
            title=f"Maintenance lease task {task_id}",
            role="builder",
        )
    claimed = state.claim_task(worker_id="maintenance-drain-worker")
    assert claimed is not None
    maintenance = state.enter_maintenance(
        "transactional-deploy",
        mode="deploy",
        ttl_seconds=60,
        owner="release-helper",
    )
    lease_id = str(maintenance["maintenance_lease_id"])
    with state._lock, state._connection:
        state._connection.execute(
            "UPDATE factory_runtime_state SET maintenance_expires_at=? "
            "WHERE singleton_id=1",
            ("2000-01-01T00:00:00Z",),
        )
    assert state.maintenance_active()
    with pytest.raises(ValueError, match="lease changed"):
        state.leave_maintenance(lease_id="maintenance-wrong")
    with pytest.raises(ValueError, match="expired"):
        state.heartbeat_maintenance(lease_id)
    state.commit_task_outcome(
        TaskOutcome(
            task_id=str(claimed["task_id"]),
            worker_id="maintenance-drain-worker",
            lease_token=str(claimed["lease_token"]),
            expected_plan_revision=0,
            idempotency_key=sha256_text("maintenance-drained-outcome"),
            result_ref="internal://maintenance-drained",
            result_digest=sha256_text("maintenance-drained"),
            status="ACCEPTED",
        )
    )
    assert not state.maintenance_active()
    next_claim = state.claim_task(worker_id="maintenance-resumed-worker")
    assert next_claim is not None
    assert next_claim["task_id"] != claimed["task_id"]
    runtime = state.maintenance_status()
    assert runtime["maintenance_recovery_count"] == 1
    assert any(
        event["event_type"] == "maintenance_auto_resumed"
        for event in state.events()
    )
    state.close()


def test_deploy_maintenance_is_fenced_across_state_store_instances(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    first = StateStore(config.database_path)
    maintenance = first.enter_maintenance(
        "transactional-deploy",
        mode="deploy",
        ttl_seconds=60,
        owner="release-helper",
    )
    lease_id = str(maintenance["maintenance_lease_id"])
    second = StateStore(config.database_path)
    with pytest.raises(ValueError, match="already active"):
        second.enter_maintenance("manual-schema-repair")
    renewed = second.heartbeat_maintenance(lease_id, ttl_seconds=120)
    assert renewed["maintenance_active"]
    with pytest.raises(ValueError, match="lease changed"):
        second.leave_maintenance(lease_id="maintenance-stale")
    second.leave_maintenance(lease_id=lease_id)
    assert not first.maintenance_active()
    second.close()
    first.close()


def test_expired_task_lease_cannot_strand_expired_deploy_maintenance(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    product_id = "product-expired-maintenance-claim"
    state.create_product_v2(
        product_id=product_id,
        owner_id="owner",
        source="test",
        goal_text="Recover an abandoned claim before resuming after deploy",
        delivery_mode="new_repository",
        repository_url=None,
        repository_name="expired-maintenance-claim",
        repository_visibility="private",
        root_goal_ref=f"evidence/intake-{product_id}.json",
        constraints_ref=None,
        owner_defaults_ref=None,
        idempotency_key=sha256_text(f"intake:{product_id}"),
        rate_limit=None,
    )
    state.add_task(
        task_id="T-EXPIRED-MAINTENANCE-CLAIM",
        product_id=product_id,
        title="Recover an expired task lease",
        role="builder",
    )
    claimed = state.claim_task(worker_id="abandoned-worker")
    assert claimed is not None
    state.enter_maintenance(
        "transactional-deploy",
        mode="deploy",
        ttl_seconds=60,
        owner="release-helper",
    )
    with state._lock, state._connection:
        state._connection.execute(
            """UPDATE tasks SET lease_until='2000-01-01T00:00:00Z'
               WHERE task_id=?""",
            (claimed["task_id"],),
        )
        state._connection.execute(
            """UPDATE factory_runtime_state
               SET maintenance_expires_at='2000-01-01T00:00:00Z'
               WHERE singleton_id=1"""
        )
    assert not state.maintenance_active()
    reclaimed = state.claim_task(worker_id="recovery-worker")
    assert reclaimed is not None
    assert reclaimed["task_id"] == claimed["task_id"]
    assert reclaimed["lease_owner"] == "recovery-worker"
    state.close()


def test_manual_maintenance_requires_explicit_release(tmp_path: Path) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    state.enter_maintenance("manual-schema-repair")
    with state._lock, state._connection:
        state._connection.execute(
            "UPDATE factory_runtime_state SET updated_at=? WHERE singleton_id=1",
            ("2000-01-01T00:00:00Z",),
        )
    assert state.maintenance_active()
    assert not state.recover_expired_maintenance()
    state.leave_maintenance()
    assert not state.maintenance_active()
    state.close()


def test_migration_014_recovers_exact_stale_prompt_hotfix(tmp_path: Path) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    state.enter_maintenance(
        "prompt-input-limit-and-error-classification-hotfix"
    )
    with state._lock, state._connection:
        state._connection.execute(
            "DELETE FROM schema_migrations WHERE version=14"
        )
        state._connection.execute(
            """UPDATE factory_runtime_state
               SET maintenance_mode='manual', maintenance_owner=NULL,
                   maintenance_lease_id=NULL, maintenance_expires_at=NULL,
                   maintenance_heartbeat_at=NULL, maintenance_auto_resume=0,
                   updated_at='2000-01-01T00:00:00Z'
               WHERE singleton_id=1"""
        )
    state.close()

    restarted = StateStore(config.database_path)
    runtime = restarted.maintenance_status()
    assert not runtime["maintenance_active"]
    assert runtime["maintenance_mode"] == "deploy"
    assert runtime["maintenance_recovery_count"] == 1
    assert any(
        event["event_type"] == "maintenance_auto_resumed"
        for event in restarted.events()
    )
    restarted.close()


def test_AUT_P1_011_maintenance_drains_claims_and_sqlite_busy_is_bounded(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    product_id = "product-drain"
    state.create_product_v2(
        product_id=product_id,
        owner_id="owner",
        source="test",
        goal_text="Drain active work without losing a completed outcome",
        delivery_mode="new_repository",
        repository_url=None,
        repository_name="drain-product",
        repository_visibility="private",
        root_goal_ref=f"evidence/intake-{product_id}.json",
        constraints_ref=None,
        owner_defaults_ref=None,
        idempotency_key=sha256_text(f"intake:{product_id}"),
        rate_limit=None,
    )
    for task_id in ("T-DRAIN-A", "T-DRAIN-B"):
        state.add_task(
            task_id=task_id,
            product_id=product_id,
            title=f"Drain task {task_id}",
            role="builder",
        )
    claimed = state.claim_task(worker_id="draining-worker")
    assert claimed is not None
    state.enter_maintenance("bounded-drain-test")
    assert state.claim_task(worker_id="second-worker") is None
    state.commit_task_outcome(
        TaskOutcome(
            task_id=str(claimed["task_id"]),
            worker_id="draining-worker",
            lease_token=str(claimed["lease_token"]),
            expected_plan_revision=0,
            idempotency_key=sha256_text("drained-outcome"),
            result_ref="internal://drained-outcome",
            result_digest=sha256_text("drained-outcome"),
            status="ACCEPTED",
        )
    )
    state.leave_maintenance()
    next_claim = state.claim_task(worker_id="second-worker")
    assert next_claim is not None
    assert next_claim["task_id"] != claimed["task_id"]
    with state._lock:
        busy_timeout = int(
            state._connection.execute("PRAGMA busy_timeout").fetchone()[0]
        )
    assert busy_timeout == 30_000
    state.close()

    class BusyState:
        busy_events = 0

        @staticmethod
        def maintenance_active() -> bool:
            return False

        def record_sqlite_busy_event(self) -> None:
            self.busy_events += 1

    class BusyReconciler:
        def __init__(self) -> None:
            self.state = BusyState()
            self.calls = 0
            self.loop: ReconcilerLoop | None = None

        def reconcile_once(self):
            self.calls += 1
            if self.calls <= 2:
                raise sqlite3.OperationalError("database is locked")
            assert self.loop is not None
            self.loop._stop.set()
            return SimpleNamespace(
                repaired=0,
                owner_actions=0,
                exhausted=0,
                recovered_successors=0,
            )

    busy = BusyReconciler()
    loop = ReconcilerLoop(busy, 0.001)  # type: ignore[arg-type]
    busy.loop = loop
    loop._run()
    assert busy.calls == 3
    assert busy.state.busy_events == 2


def test_active_legacy_state_enters_maintenance_during_recovery_migration(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    state.create_product(
        product_id="legacy-active-product",
        owner_id="owner",
        source="test",
        idea="Existing active state must not run during migration",
        idempotency_key="legacy-active-product",
    )
    state.close()
    connection = sqlite3.connect(config.database_path)
    try:
        connection.execute(
            "DELETE FROM schema_migrations WHERE version IN (13,14,15)"
        )
        connection.execute("DROP TABLE factory_runtime_state")
        connection.execute("DROP TABLE recovery_applications")
        connection.commit()
    finally:
        connection.close()

    migrated = StateStore(config.database_path)
    assert migrated.maintenance_active()
    assert migrated.claim_task(worker_id="must-not-claim") is None
    migrated.close()


def test_migration_015_closes_hypothesis_for_resolved_failure(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    product_id = "product-resolved-hypothesis"
    state.create_product_v2(
        product_id=product_id,
        owner_id="owner",
        source="test",
        goal_text="Close stale diagnosis state after its failure is resolved",
        delivery_mode="new_repository",
        repository_url=None,
        repository_name="resolved-hypothesis",
        repository_visibility="private",
        root_goal_ref=f"evidence/intake-{product_id}.json",
        constraints_ref=None,
        owner_defaults_ref=None,
        idempotency_key=sha256_text(f"intake:{product_id}"),
        rate_limit=None,
    )
    now = "2026-07-30T00:00:00Z"
    with state._lock, state._connection:
        state._connection.execute(
            """INSERT INTO failures
               (failure_id, product_id, task_id, failure_class, reason_code,
                fingerprint, safe_message, evidence_ref, status, retryable,
                owner_action_eligible, expected_json, actual_json,
                failed_gate_ids_json, first_seen_at, last_seen_at)
               VALUES ('failure-resolved-hypothesis', ?,
                       'T-RESOLVED-HYPOTHESIS', 'semantic',
                       'scope_violation', ?, 'resolved diagnostic',
                       'internal://resolved', 'RESOLVED', 0, 0, '{}', '{}',
                       '[]', ?, ?)""",
            (product_id, sha256_text("resolved-hypothesis"), now, now),
        )
        state._connection.execute(
            """INSERT INTO hypotheses
               (hypothesis_id, product_id, failure_id, signature, statement,
                required_evidence_json, status, semantic_budget, attempts_used,
                created_at)
               VALUES ('hypothesis-stale-resolved', ?,
                       'failure-resolved-hypothesis', ?, 'stale diagnosis',
                       '[]', 'ACTIVE', 3, 1, ?)""",
            (product_id, sha256_text("stale-diagnosis"), now),
        )
        state._connection.execute(
            "DELETE FROM schema_migrations WHERE version=15"
        )
    state.close()

    restarted = StateStore(config.database_path)
    hypothesis = restarted._connection.execute(
        "SELECT status, closed_at FROM hypotheses WHERE hypothesis_id=?",
        ("hypothesis-stale-resolved",),
    ).fetchone()
    assert hypothesis is not None
    assert hypothesis["status"] == "RESOLVED"
    assert hypothesis["closed_at"]
    restarted.close()


def test_migration_016_reconciles_proven_duplicate_accepted_repairs(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    product_id = "product-redundant-repair"
    original_task_id = "T-REDUNDANT-ORIGINAL"
    state.create_product_v2(
        product_id=product_id,
        owner_id="owner",
        source="test",
        goal_text="Keep one accepted repair lineage per failed task",
        delivery_mode="new_repository",
        repository_url=None,
        repository_name="redundant-repair",
        repository_visibility="private",
        root_goal_ref=f"evidence/intake-{product_id}.json",
        constraints_ref=None,
        owner_defaults_ref=None,
        idempotency_key=sha256_text(f"intake:{product_id}"),
        rate_limit=None,
    )
    state.add_task(
        task_id=original_task_id,
        product_id=product_id,
        title="Original failed implementation",
        role="builder",
        output_schema="attempt-result.schema.json",
        contract_ref=f"evidence/task-{original_task_id}.json",
        stage_key="implementation-001",
        root_task_id=original_task_id,
        root_context_ref=f"evidence/intake-{product_id}.json",
        graph_status="SUPERSEDED",
    )
    for index, repair_task_id in enumerate(
        ("T-ACCEPTED-REPAIR-A", "T-ACCEPTED-REPAIR-B"),
        start=1,
    ):
        failure_id = f"failure-redundant-{index}"
        root_failure_id = (
            f"failure-redundant-root-{index}"
            if index == 1
            else failure_id
        )
        timestamp = f"2026-07-30T00:00:0{index}Z"
        with state._lock, state._connection:
            state._connection.execute(
                """INSERT INTO failures
                   (failure_id, product_id, task_id, failure_class,
                    reason_code, fingerprint, safe_message, evidence_ref,
                    status, retryable, owner_action_eligible, expected_json,
                    actual_json, failed_gate_ids_json, first_seen_at,
                    last_seen_at)
                   VALUES (?, ?, ?, 'semantic', 'schema_validation', ?,
                           'safe duplicate repair coordinate', ?,
                           'RESOLVED', 0, 0, '{}', '{}', '[]', ?, ?)""",
                (
                    root_failure_id,
                    product_id,
                    original_task_id,
                    sha256_text(root_failure_id),
                    f"internal://{root_failure_id}",
                    timestamp,
                    timestamp,
                ),
            )
            if index == 1:
                state._connection.execute(
                    """INSERT INTO failures
                       (failure_id, product_id, task_id, parent_failure_id,
                        failure_class, reason_code, fingerprint, safe_message,
                        evidence_ref, status, retryable, owner_action_eligible,
                        expected_json, actual_json, failed_gate_ids_json,
                        first_seen_at, last_seen_at)
                       VALUES (?, ?, ?, ?, 'transient', 'malformed_transport',
                               ?, 'safe child repair failure', ?,
                               'RESOLVED', 1, 0, '{}', '{}', '[]', ?, ?)""",
                    (
                        failure_id,
                        product_id,
                        repair_task_id,
                        root_failure_id,
                        sha256_text(failure_id),
                        f"internal://{failure_id}",
                        timestamp,
                        timestamp,
                    ),
                )
        state.add_task(
            task_id=repair_task_id,
            product_id=product_id,
            title="Accepted repair for one sibling failure",
            role="builder",
            output_schema="attempt-result.schema.json",
            contract_ref=f"evidence/task-{repair_task_id}.json",
            stage_key="repair",
            root_task_id=original_task_id,
            parent_task_id=original_task_id,
            source_task_id=original_task_id,
            root_context_ref=f"evidence/intake-{product_id}.json",
            failure_id=failure_id,
            supersedes_task_id=original_task_id,
            graph_status="ACCEPTED",
        )
        with state._lock, state._connection:
            state._connection.execute(
                """UPDATE tasks
                   SET result_ref=?, result_digest=?, created_at=?, updated_at=?
                   WHERE task_id=?""",
                (
                    f"internal://{repair_task_id}",
                    sha256_text(repair_task_id),
                    timestamp,
                    timestamp,
                    repair_task_id,
                ),
            )
    with state._lock, state._connection:
        state._connection.execute(
            "DELETE FROM schema_migrations WHERE version=16"
        )
    state.close()

    restarted = StateStore(config.database_path)
    canonical = restarted.get_task("T-ACCEPTED-REPAIR-A")
    redundant = restarted.get_task("T-ACCEPTED-REPAIR-B")
    assert canonical is not None
    assert canonical["graph_status"] == "ACCEPTED"
    assert redundant is not None
    assert redundant["graph_status"] == "REJECTED"
    assert (
        redundant["terminal_reason"]
        == "redundant_accepted_repair_branch"
    )
    assert redundant["result_ref"] == "internal://T-ACCEPTED-REPAIR-B"
    assert any(
        event["event_type"]
        == "redundant_accepted_repair_reconciled"
        for event in restarted.events(product_id)
    )
    restarted.close()


def test_AUT_P0_033_release_version_must_match_all_evidence(
    tmp_path: Path,
) -> None:
    version = "3.4.5"
    (tmp_path / "VERSION").write_text(f"{version}\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        'name = "hermes-software-factory-spec"\n'
        f'version = "{version}"\n',
        encoding="utf-8",
    )
    (tmp_path / "CHANGELOG.md").write_text(
        f"# Changelog\n\n## {version} - 2026-07-30\n",
        encoding="utf-8",
    )
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "sbom.spdx.json").write_text(
        json.dumps(
            {
                "packages": [
                    {
                        "name": "hermes-software-factory-spec",
                        "versionInfo": version,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    wheel = tmp_path / "factory.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "hermes_software_factory_spec-3.4.5.dist-info/METADATA",
            "Metadata-Version: 2.4\n"
            "Name: hermes-software-factory-spec\n"
            f"Version: {version}\n",
        )
    release_record = tmp_path / "release.json"
    release_record.write_text(
        json.dumps({"release": {"version": version}}),
        encoding="utf-8",
    )
    assert (
        verify_version_consistency(
            tmp_path,
            wheel=wheel,
            release_record=release_record,
            required_labels=(
                "VERSION",
                "pyproject.toml",
                "CHANGELOG.md",
                "SBOM",
                "wheel METADATA",
                "release record",
            ),
        )
        == version
    )
    release_record.write_text(
        json.dumps({"release": {"version": "3.4.6"}}),
        encoding="utf-8",
    )
    with pytest.raises(VersionConsistencyError, match="mismatch"):
        verify_version_consistency(
            tmp_path,
            wheel=wheel,
            release_record=release_record,
        )


def test_AUT_P0_037_large_failure_history_compacts_to_one_recovery_root(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    product_id = "product-compaction"
    state.create_product_v2(
        product_id=product_id,
        owner_id="owner",
        source="test",
        goal_text="Recover a product with a large immutable failure history",
        delivery_mode="new_repository",
        repository_url=None,
        repository_name="compaction-product",
        repository_visibility="private",
        root_goal_ref=f"evidence/intake-{product_id}.json",
        constraints_ref=None,
        owner_defaults_ref=None,
        idempotency_key=sha256_text(f"intake:{product_id}"),
        rate_limit=None,
    )
    for index in range(700):
        task_id = f"T-HISTORY-{index:04d}"
        state.add_task(
            task_id=task_id,
            product_id=product_id,
            title=f"Historical attempt {index}",
            role="builder",
            output_schema="attempt-result.schema.json",
            contract_ref=f"evidence/task-{task_id}.json",
            graph_status="FAILED_SEMANTIC",
        )
    with state._lock, state._connection:
        now = "2026-07-30T00:00:00Z"
        state._connection.executemany(
            """INSERT INTO failures
               (failure_id, product_id, task_id, failure_class, reason_code,
                fingerprint, safe_message, evidence_ref, status, retryable,
                owner_action_eligible, expected_json, actual_json,
                failed_gate_ids_json, first_seen_at, last_seen_at)
               VALUES (?, ?, ?, 'semantic', 'historical_failure', ?,
                       'Historical failure retained for audit.',
                       'internal://compaction-fixture', 'OPEN', 0, 0,
                       '{}', '{}', '[]', ?, ?)""",
            [
                (
                    f"F-HISTORY-{index:04d}",
                    product_id,
                    f"T-HISTORY-{index:04d}",
                    sha256_text(f"failure:{index}"),
                    now,
                    now,
                )
                for index in range(700)
            ],
        )
    state.enter_maintenance("large-history-compaction")
    recovery = build_recovery_plan(state)
    result = apply_recovery_plan(config, state, recovery)
    assert result["status"] == "PASS"
    tasks = state.list_tasks(product_id)
    assert (
        sum(
            task.get("stage_key") == "semantic-lifecycle-recovery"
            and task.get("graph_status") == "READY"
            for task in tasks
        )
        == 1
    )
    assert (
        sum(task.get("graph_status") == "SUPERSEDED" for task in tasks)
        == 700
    )
    with state._lock:
        history_count = int(
            state._connection.execute(
                "SELECT COUNT(*) FROM failures WHERE product_id=?",
                (product_id,),
            ).fetchone()[0]
        )
        resolved_count = int(
            state._connection.execute(
                """SELECT COUNT(*) FROM failures
                   WHERE product_id=? AND status='RESOLVED'""",
                (product_id,),
            ).fetchone()[0]
        )
    assert history_count == 700
    assert resolved_count == 700
    assert apply_recovery_plan(config, state, recovery)["applications"][0][
        "status"
    ] == "REPLAYED"
    state.close()


def test_rootless_bootstrap_enters_trusted_release_root_before_runuser() -> None:
    root = Path(__file__).resolve().parents[1]
    script = (
        root / "scripts" / "bootstrap" / "upgrade-autonomy-runtime.sh"
    ).read_text(encoding="utf-8")
    assert script.index('cd "${ROOT_DIR}"') < script.index(
        'runuser -u "${SERVICE_USER}"'
    )
    probe_created = script.index(
        'PROBE_DIR="$(mktemp -d "${STATE_DIR}/podman-preflight.XXXXXX")"'
    )
    probe_owned = script.index(
        'chown "${SERVICE_USER}:${SERVICE_USER}" "${PROBE_DIR}"'
    )
    assert probe_created < probe_owned < script.index(
        'runuser -u "${SERVICE_USER}"'
    )
