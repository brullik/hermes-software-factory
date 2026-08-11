"""Locked PRE-Q8 r02/r03 controller and scenario regressions."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from test_autonomy_v2 import failed_two_node_graph
from test_worker import FakeRunner, make_config, selected_registry

from factory.architecture_baseline import (
    ArchitectureBaselineToolchainMismatch,
    _fault_lifecycle_blueprint,
    _profile_protocol_blueprint,
    build_architecture_baseline,
)
from factory.artifacts import ArtifactStore
from factory.autonomy import (
    CAPABILITY_PROFILES,
    FailureData,
    HypothesisData,
    TaskOutcome,
)
from factory.common import sha256_text, stable_json
from factory.delivery_profile_obligations import delivery_profile_obligations
from factory.failure_catalog import FailureAction, failure_disposition
from factory.failure_router import ContractIntegrityError, FailureRouter
from factory.path_governor import (
    PathGovernor,
    ResultLineageIdentityError,
    execution_slot_cost,
    supersession_is_compatible,
    task_contract_digest,
)
from factory.pipeline import PipelineCoordinator
from factory.quality import ControllerContainerScanHelperInvalid, QualityGateEngine
from factory.reconciler import PipelineReconciler
from factory.state import StateStore
from factory.transition_kernel import TransitionKernel
from factory.worker import AgentWorker, _workspace_snapshot
from scripts.quality_gate import (
    _BoundedProcessResult,
    _controller_image_security_verifier,
    run_gate,
)

POLICY_DIGEST = "a" * 64


def _config(root: Path) -> Any:
    return make_config(
        root,
        selected_registry(root / "registry.yaml", selected="gpt-5.6-terra"),
    )


def _contract(
    task_id: str,
    *,
    product_id: str,
    plan_id: str,
    role: str,
    lifecycle_stage: str,
    semantic_node_key: str,
    revision: int,
    parent_task_id: str | None,
    dependencies: list[str] | None = None,
    capability_profile: str,
    output_schema: str,
    evidence_profile: str,
    produces: list[str],
    consumes: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "2.0",
        "artifact_id": f"task-contract-{task_id}",
        "product_id": product_id,
        "task_id": task_id,
        "root_task_id": "T-ARCHROOT",
        "parent_task_id": parent_task_id,
        "source_task_id": parent_task_id or "T-ARCHROOT",
        "plan_id": plan_id,
        "plan_node_id": f"architecture-{revision}",
        "semantic_node_key": semantic_node_key,
        "task_revision": revision,
        "root_context_ref": f"evidence/intake-{product_id}.json",
        "active_context_ref": f"evidence/task-{task_id}.json",
        "failure_id": None,
        "hypothesis_id": None,
        "supersedes_task_id": None,
        "title": f"Architecture revision {revision}",
        "objective": "Produce and independently validate the exact architecture package.",
        "role": role,
        "output_schema": output_schema,
        "dependencies": list(dependencies or []),
        "conflict_keys": [],
        "acceptance": [
            {
                "criterion_id": "ARCH-EXACT",
                "verification": "The immutable architecture contract is exact.",
                "mandatory": True,
            }
        ],
        "required_capabilities": list(CAPABILITY_PROFILES[capability_profile]),
        "capability_profile": capability_profile,
        "allowed_paths": ["artifacts/**"],
        "forbidden_paths": ["secrets/**", "production/**"],
        "risk_tier": "medium",
        "model_floor": "terra",
        "idempotency_key": sha256_text(f"contract:{task_id}"),
        "status": "READY",
        "priority": 100 + revision,
        "critical_path_rank": 0,
        "quality_gates": [],
        "lifecycle_stage": lifecycle_stage,
        "review_kind": "architecture",
        "evidence_profile": evidence_profile,
        "consumes_evidence_types": list(consumes or []),
        "produces_evidence_types": list(produces),
        "completion_obligation_ids": ["ARCH-COMPLETE"],
        "goal_ids": ["ROOT-GOAL"],
        "production_side_effects": False,
    }


def _add_projected_task(
    router: FailureRouter,
    contract: dict[str, Any],
    *,
    durable_role: str,
    stage_key: str,
    graph_status: str,
) -> dict[str, Any]:
    state = router.state
    artifacts = router.artifacts
    task_id = str(contract["task_id"])
    path = artifacts.write(
        "task-contract-v2.schema.json",
        contract,
        filename=f"task-{task_id}.json",
    )
    state.add_task(
        task_id=task_id,
        product_id=str(contract["product_id"]),
        title=str(contract["title"]),
        role=durable_role,
        output_schema=str(contract["output_schema"]),
        contract_ref=f"evidence/{path.name}",
        stage_key=stage_key,
        dependencies=[str(value) for value in contract["dependencies"]],
        conflict_keys=[],
        priority=int(contract["priority"]),
        root_task_id=str(contract["root_task_id"]),
        parent_task_id=(
            str(contract["parent_task_id"])
            if contract.get("parent_task_id")
            else None
        ),
        source_task_id=str(contract["source_task_id"]),
        plan_id=str(contract["plan_id"]),
        plan_node_id=str(contract["plan_node_id"]),
        semantic_node_key=str(contract["semantic_node_key"]),
        task_revision=int(contract["task_revision"]),
        root_context_ref=str(contract["root_context_ref"]),
        active_context_ref=str(contract["active_context_ref"]),
        capability_profile=str(contract["capability_profile"]),
        idempotency_key=str(contract["idempotency_key"]),
        required_capabilities=[str(value) for value in contract["required_capabilities"]],
        graph_status=graph_status,
    )
    return router._persist_routed_task_contract(task_id, contract, durable_role)


def _architecture_graph(tmp_path: Path) -> dict[str, Any]:
    config = _config(tmp_path)
    state = StateStore(config.database_path)
    product_id = "product-architecture-correction"
    state.create_product_v2(
        product_id=product_id,
        owner_id="owner",
        source="test",
        goal_text="Deliver one reviewed and correctable architecture package",
        delivery_mode="new_repository",
        repository_url=None,
        repository_name="architecture-correction",
        repository_visibility="private",
        root_goal_ref=f"evidence/intake-{product_id}.json",
        constraints_ref=None,
        owner_defaults_ref=None,
        idempotency_key=sha256_text("intake:architecture-correction"),
        rate_limit=None,
        delivery_profile="DEPLOYED_SERVICE",
    )
    for status in ("RISK_CLASSIFIED", "ARCHITECTED", "IMPLEMENTING"):
        state.transition_product(product_id, status)
    artifacts = ArtifactStore(config)
    router = FailureRouter(config, state, artifacts)
    plan_id = "PLAN-ARCHITECTURE-CORRECTION"
    with state._connection:
        state._connection.execute(
            """INSERT INTO plans
               (plan_id,product_id,revision,status,plan_artifact_ref,plan_digest,
                goals_json,completion_criteria_json,created_by_task_id,created_at,activated_at)
               VALUES (?,?,1,'ACTIVE','evidence/architecture-plan.json',?,
                       '[]','[]','T-ARCHROOT','2026-08-11T00:00:00Z',
                       '2026-08-11T00:00:00Z')""",
            (plan_id, product_id, "9" * 64),
        )
        state._connection.execute(
            "UPDATE products SET active_plan_id=?, active_plan_revision=1 WHERE product_id=?",
            (plan_id, product_id),
        )
    old_id = "T-ARCHOLD"
    correction_id = "T-ARCHCORRECTION"
    reviewer_id = "T-ARCHREVIEWER"
    common = {
        "product_id": product_id,
        "plan_id": plan_id,
        "role": "solution-architect",
        "lifecycle_stage": "architecture-review",
        "semantic_node_key": "architecture-package",
        "capability_profile": "planning_readonly",
        "output_schema": "architecture-package.schema.json",
        "evidence_profile": "architecture-package",
        "produces": ["architecture_package"],
    }
    old_contract = _contract(
        old_id,
        revision=1,
        parent_task_id="T-ARCHROOT",
        **common,
    )
    correction_contract = _contract(
        correction_id,
        revision=2,
        parent_task_id=reviewer_id,
        **common,
    )
    _add_projected_task(
        router,
        old_contract,
        durable_role="solution_architect",
        stage_key="architecture-review",
        graph_status="ACCEPTED",
    )
    _add_projected_task(
        router,
        correction_contract,
        durable_role="solution_architect",
        stage_key="repair",
        graph_status="READY",
    )
    reviewer_contract = _contract(
        reviewer_id,
        product_id=product_id,
        plan_id=plan_id,
        role="independent-reviewer",
        lifecycle_stage="architecture-review",
        semantic_node_key="architecture-independent-review",
        revision=1,
        parent_task_id=old_id,
        dependencies=[correction_id],
        capability_profile="reviewer_readonly",
        output_schema="review-report.schema.json",
        evidence_profile="architecture-review",
        produces=["architecture_review"],
        consumes=["architecture_package"],
    )
    _add_projected_task(
        router,
        reviewer_contract,
        durable_role="independent-reviewer",
        stage_key="architecture-review",
        graph_status="BLOCKED_DEPENDENCY",
    )
    with state._connection:
        state._connection.execute(
            """INSERT INTO task_edges
               (plan_id,from_task_id,to_task_id,edge_type,required,created_at)
               VALUES (?,? ,?,'revalidates',1,'2026-08-11T00:00:00Z')""",
            (plan_id, correction_id, reviewer_id),
        )
        state._connection.execute(
            """INSERT INTO task_edges
               (plan_id,from_task_id,to_task_id,edge_type,required,created_at)
               VALUES (?,? ,?,'evidence_from',1,'2026-08-11T00:00:00Z')""",
            (plan_id, old_id, reviewer_id),
        )
    attempt_id = "attempt-architecture-old"
    state.record_attempt(
        attempt_id=attempt_id,
        task_id=old_id,
        tier="terra",
        attempt_kind="initial",
        prompt_digest=sha256_text("prompt:architecture-old"),
        status="completed",
        semantic_counted=True,
    )
    old_binding = PathGovernor(
        state._connection,
        policy_digest=POLICY_DIGEST,
    ).bind_result(
        task_id=old_id,
        source_task_id=old_id,
        source_attempt_id=attempt_id,
        result_ref="evidence/architecture-old.json",
        result_digest="b" * 64,
        output_schema="architecture-package.schema.json",
    )
    state._connection.commit()
    return {
        "config": config,
        "state": state,
        "router": router,
        "product_id": product_id,
        "plan_id": plan_id,
        "old_id": old_id,
        "correction_id": correction_id,
        "reviewer_id": reviewer_id,
        "old_binding_id": old_binding.binding_id,
        "common": common,
    }


def _commit_architecture_correction(
    graph: dict[str, Any],
    *,
    fault_point: str | None = None,
) -> None:
    state: StateStore = graph["state"]
    correction_id = str(graph["correction_id"])
    claimed = state.claim_task(worker_id="architecture-worker")
    assert claimed is not None and claimed["task_id"] == correction_id
    attempt_id = f"attempt-{correction_id.lower()}"
    state.record_attempt(
        attempt_id=attempt_id,
        task_id=correction_id,
        tier="terra",
        attempt_kind="repair",
        prompt_digest=sha256_text(f"prompt:{correction_id}"),
        status="started",
        semantic_counted=True,
    )
    result_digest = sha256_text(f"architecture-result:{correction_id}")

    def inject(point: str) -> None:
        if point == fault_point:
            raise RuntimeError(f"injected:{point}")

    state.commit_task_outcome(
        TaskOutcome(
            task_id=correction_id,
            worker_id="architecture-worker",
            lease_token=str(claimed["lease_token"]),
            expected_task_revision=int(claimed["task_revision"]),
            idempotency_key=sha256_text(f"outcome:{correction_id}"),
            result_ref=f"evidence/{correction_id}.json",
            result_digest=result_digest,
            status="ACCEPTED",
            accepted_result_ref=f"evidence/{correction_id}.json",
            accepted_result_digest=result_digest,
            accepted_policy_digest=POLICY_DIGEST,
            attempt_id=attempt_id,
            attempt_status="completed",
        ),
        fault_injector=inject if fault_point else None,
    )


def _active_binding_rows(state: StateStore) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in state._connection.execute(
            "SELECT * FROM result_bindings WHERE status='ACTIVE' ORDER BY binding_id"
        )
    ]


def test_architecture_correction_retires_reviewed_binding_atomically(
    tmp_path: Path,
) -> None:
    graph = _architecture_graph(tmp_path)
    state: StateStore = graph["state"]
    try:
        _commit_architecture_correction(graph)
        active = _active_binding_rows(state)
        assert len(active) == 1
        assert active[0]["source_task_id"] == graph["correction_id"]
        old = state._connection.execute(
            "SELECT status FROM result_bindings WHERE binding_id=?",
            (graph["old_binding_id"],),
        ).fetchone()
        assert old is not None and old[0] == "SUPERSEDED"
    finally:
        state.close()


def test_second_architecture_correction_replaces_first_correction(
    tmp_path: Path,
) -> None:
    graph = _architecture_graph(tmp_path)
    state: StateStore = graph["state"]
    try:
        _commit_architecture_correction(graph)
        first_id = str(graph["correction_id"])
        second_id = "T-ARCHCORRECTION2"
        second_contract = _contract(
            second_id,
            revision=3,
            parent_task_id=str(graph["reviewer_id"]),
            **graph["common"],
        )
        _add_projected_task(
            graph["router"],
            second_contract,
            durable_role="solution_architect",
            stage_key="repair",
            graph_status="READY",
        )
        with state._connection:
            state._connection.execute(
                """INSERT INTO task_edges VALUES
                   (?,?,?,'revalidates',1,'2026-08-11T00:01:00Z')""",
                (graph["plan_id"], second_id, graph["reviewer_id"]),
            )
            state._connection.execute(
                "UPDATE tasks SET dependencies_json=? WHERE task_id=?",
                (stable_json([first_id, second_id]), graph["reviewer_id"]),
            )
        graph["correction_id"] = second_id
        _commit_architecture_correction(graph)
        active = _active_binding_rows(state)
        assert [row["source_task_id"] for row in active] == [second_id]
        first_binding = state._connection.execute(
            "SELECT status FROM result_bindings WHERE source_task_id=?",
            (first_id,),
        ).fetchone()
        assert first_binding is not None and first_binding[0] == "SUPERSEDED"
    finally:
        state.close()


def test_architecture_binding_swap_requires_revalidates_edge(tmp_path: Path) -> None:
    graph = _architecture_graph(tmp_path)
    state: StateStore = graph["state"]
    try:
        with state._connection:
            state._connection.execute("DELETE FROM task_edges WHERE edge_type='revalidates'")
        with pytest.raises(ResultLineageIdentityError, match="reviewer edge"):
            PathGovernor(
                state._connection, policy_digest=POLICY_DIGEST
            ).retire_reviewed_architecture_binding_for_correction(
                str(graph["correction_id"])
            )
        assert _active_binding_rows(state)[0]["source_task_id"] == graph["old_id"]
    finally:
        state.close()


def test_architecture_binding_swap_requires_exact_prior_evidence_edge(
    tmp_path: Path,
) -> None:
    graph = _architecture_graph(tmp_path)
    state: StateStore = graph["state"]
    try:
        with state._connection:
            state._connection.execute(
                "DELETE FROM task_edges WHERE edge_type='evidence_from'"
            )
        with pytest.raises(ResultLineageIdentityError, match="prior evidence"):
            PathGovernor(
                state._connection, policy_digest=POLICY_DIGEST
            ).retire_reviewed_architecture_binding_for_correction(
                str(graph["correction_id"])
            )
        assert len(_active_binding_rows(state)) == 1
    finally:
        state.close()


def _assert_architecture_binding_swap_rolls_back(
    tmp_path: Path,
    fault_point: str,
) -> None:
    graph = _architecture_graph(tmp_path)
    state: StateStore = graph["state"]
    try:
        with pytest.raises(RuntimeError, match=fault_point):
            _commit_architecture_correction(graph, fault_point=fault_point)
        active = _active_binding_rows(state)
        assert len(active) == 1
        assert active[0]["binding_id"] == graph["old_binding_id"]
        assert state._connection.execute(
            "SELECT COUNT(*) FROM result_bindings WHERE source_task_id=?",
            (graph["correction_id"],),
        ).fetchone()[0] == 0
    finally:
        state.close()


def test_architecture_binding_swap_rolls_back_before_new_binding(
    tmp_path: Path,
) -> None:
    _assert_architecture_binding_swap_rolls_back(
        tmp_path, "after_architecture_binding_retirement"
    )


def test_architecture_binding_swap_rolls_back_after_new_binding(
    tmp_path: Path,
) -> None:
    _assert_architecture_binding_swap_rolls_back(tmp_path, "after_result_binding_write")


def test_architecture_binding_swap_preserves_frozen_snapshot(tmp_path: Path) -> None:
    graph = _architecture_graph(tmp_path)
    state: StateStore = graph["state"]
    try:
        old_task = state.get_task(str(graph["old_id"]))
        assert old_task is not None
        with state._connection:
            state._connection.execute(
                """INSERT INTO candidate_snapshots VALUES
                   ('CS-ARCH',?,?,?,? ,?,?, 'FROZEN','2026-08-11T00:00:00Z')""",
                (
                    graph["product_id"],
                    graph["plan_id"],
                    "1" * 40,
                    "sha256:" + "2" * 64,
                    graph["old_binding_id"],
                    "3" * 64,
                ),
            )
            state._connection.execute(
                "INSERT INTO candidate_snapshot_items VALUES ('CS-ARCH',?,?)",
                (old_task["semantic_node_id"], graph["old_binding_id"]),
            )
        _commit_architecture_correction(graph)
        item = state._connection.execute(
            "SELECT binding_id FROM candidate_snapshot_items WHERE snapshot_id='CS-ARCH'"
        ).fetchone()
        assert item is not None and item[0] == graph["old_binding_id"]
    finally:
        state.close()


def test_architecture_binding_replay_is_idempotent(tmp_path: Path) -> None:
    graph = _architecture_graph(tmp_path)
    state: StateStore = graph["state"]
    try:
        _commit_architecture_correction(graph)
        governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
        assert governor.retire_reviewed_architecture_binding_for_correction(
            str(graph["correction_id"])
        ) is None
        assert len(_active_binding_rows(state)) == 1
    finally:
        state.close()


def test_cross_role_supersession_remains_forbidden() -> None:
    source = {
        "product_id": "product-cross-role",
        "role": "solution-architect",
        "output_schema": "architecture-package.schema.json",
        "lifecycle_stage": "architecture-review",
        "review_kind": "architecture",
        "evidence_profile": "architecture-package",
        "semantic_node_key": "architecture-package",
    }
    assert not supersession_is_compatible(
        source,
        {**source, "role": "independent-reviewer", "output_schema": "review-report.schema.json"},
    )


def test_routed_builder_row_matches_immutable_contract_before_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(tmp_path)
    observed: list[str] = []
    original = PathGovernor.reserve_task_execution_once

    def inspect_before_reservation(
        governor: PathGovernor,
        *,
        task_id: str,
        root_problem_signature: str,
        progress: Any,
    ) -> str:
        row = state.get_task(task_id)
        assert row is not None
        contract = json.loads(
            (config.evidence_dir / f"task-{task_id}.json").read_text(encoding="utf-8")
        )
        assert row["contract_digest"] == task_contract_digest(contract)
        assert row["semantic_node_key"] == contract["semantic_node_key"]
        assert row["goal_ids_json"] == stable_json(contract.get("goal_ids", []))
        observed.append(task_id)
        return original(
            governor,
            task_id=task_id,
            root_problem_signature=root_problem_signature,
            progress=progress,
        )

    try:
        monkeypatch.setattr(
            PathGovernor, "reserve_task_execution_once", inspect_before_reservation
        )
        routed = FailureRouter(config, state, artifacts).route(failure_id)
        assert observed == [routed]
    finally:
        state.close()


def _routed_builder_contract_fixture(tmp_path: Path) -> tuple[FailureRouter, dict[str, Any]]:
    config = _config(tmp_path)
    state = StateStore(config.database_path)
    product_id = "product-routed-contract"
    state.create_product_v2(
        product_id=product_id,
        owner_id="owner",
        source="test",
        goal_text="Preserve exact routed task semantics",
        delivery_mode="new_repository",
        repository_url=None,
        repository_name="routed-contract",
        repository_visibility="private",
        root_goal_ref=f"evidence/intake-{product_id}.json",
        constraints_ref=None,
        owner_defaults_ref=None,
        idempotency_key=sha256_text("intake:routed-contract"),
        rate_limit=None,
        delivery_profile="TELEGRAM_BOT",
    )
    router = FailureRouter(config, state, ArtifactStore(config))
    source = _contract(
        "T-ROUTEDSOURCE",
        product_id=product_id,
        plan_id="PLAN-ROUTED",
        role="builder",
        lifecycle_stage="implementation-slice",
        semantic_node_key="telegram-runtime",
        revision=1,
        parent_task_id="T-ROOT",
        capability_profile="builder_workspace",
        output_schema="attempt-result.schema.json",
        evidence_profile="repository-change",
        produces=["implementation_result", "capability_proof"],
        consumes=["architecture_package"],
    )
    failed = _add_projected_task(
        router,
        source,
        durable_role="builder",
        stage_key="implementation-slice",
        graph_status="FAILED_SEMANTIC",
    )
    failure = {
        "failure_id": "failure-routed-contract",
        "last_seen_at": "2026-08-11T00:00:00Z",
        "failed_gate_ids_json": stable_json(["target-tests"]),
    }
    contract, _path = router._write_contract(
        failed=failed,
        failure=failure,
        hypothesis_id="hypothesis-routed",
        role="builder",
        output_schema="attempt-result.schema.json",
        capability_profile="builder_workspace",
        objective="Repair the exact Telegram runtime defect with fresh test evidence.",
        allowed_paths=["src/**", "tests/**"],
        task_revision=2,
        node_suffix="repair",
        supersede_failed=True,
    )
    return router, contract


def test_routed_repair_preserves_goal_and_completion_ids(tmp_path: Path) -> None:
    router, contract = _routed_builder_contract_fixture(tmp_path)
    try:
        assert contract["goal_ids"] == ["ROOT-GOAL"]
        assert contract["completion_obligation_ids"] == ["ARCH-COMPLETE"]
    finally:
        router.state.close()


def test_routed_repair_preserves_lifecycle_and_evidence_profile(
    tmp_path: Path,
) -> None:
    router, contract = _routed_builder_contract_fixture(tmp_path)
    try:
        assert contract["lifecycle_stage"] == "implementation-slice"
        assert contract["evidence_profile"] == "repository-change"
        assert contract["consumes_evidence_types"] == ["architecture_package"]
    finally:
        router.state.close()


def test_telegram_repair_capability_proof_compiles(tmp_path: Path) -> None:
    router, contract = _routed_builder_contract_fixture(tmp_path)
    try:
        assert "capability_proof" in contract["produces_evidence_types"]
        assert contract["required_capabilities"] == list(
            CAPABILITY_PROFILES["builder_workspace"]
        )
        router.schemas.validate("task-contract-v2.schema.json", contract)
    finally:
        router.state.close()


def test_routed_contract_projection_is_idempotent(tmp_path: Path) -> None:
    router, contract = _routed_builder_contract_fixture(tmp_path)
    try:
        _add_projected_task(
            router,
            contract,
            durable_role="builder",
            stage_key="repair",
            graph_status="READY",
        )
        first = router._persist_routed_task_contract(
            str(contract["task_id"]), contract, "builder"
        )
        second = router._persist_routed_task_contract(
            str(contract["task_id"]), contract, "builder"
        )
        assert first["contract_digest"] == second["contract_digest"]
        assert first["semantic_node_id"] == second["semantic_node_id"]
    finally:
        router.state.close()


def test_routed_contract_projection_conflict_fails_closed(tmp_path: Path) -> None:
    router, contract = _routed_builder_contract_fixture(tmp_path)
    try:
        _add_projected_task(
            router,
            contract,
            durable_role="builder",
            stage_key="repair",
            graph_status="READY",
        )
        with router.state._connection:
            router.state._connection.execute(
                "UPDATE tasks SET goal_ids_json=? WHERE task_id=?",
                (stable_json(["DIFFERENT-GOAL"]), contract["task_id"]),
            )
        with pytest.raises(ContractIntegrityError, match="goal_ids_json"):
            router._persist_routed_task_contract(
                str(contract["task_id"]), contract, "builder"
            )
    finally:
        router.state.close()


@pytest.fixture(scope="module")
def exact_architecture_baseline(tmp_path_factory: pytest.TempPathFactory) -> Any:
    root = tmp_path_factory.mktemp("architecture-baseline")
    config = _config(root)
    obligations = delivery_profile_obligations("CLI_PACKAGE", "new_repository")
    return build_architecture_baseline(
        config,
        {
            "product_id": "product-baseline",
            "delivery_profile": "CLI_PACKAGE",
            "delivery_mode": "new_repository",
        },
        {
            "delivery_profile": "CLI_PACKAGE",
            "delivery_mode": "new_repository",
        },
        obligations,
    )


def test_architecture_baseline_attests_exact_candidate_toolchain(
    exact_architecture_baseline: Any,
) -> None:
    baseline = exact_architecture_baseline
    assert baseline.interpreter_path == str(Path(sys.executable).resolve(strict=True))
    assert len(baseline.interpreter_binary_sha256) == 64
    assert len(baseline.requirements_lock_sha256) == 64
    assert {item.name for item in baseline.distributions} == {
        "setuptools",
        "pip",
        "pytest",
        "ruff",
        "cryptography",
    }
    assert dict(baseline.commands)["test"] == (
        baseline.interpreter_path,
        "-m",
        "pytest",
        "-q",
    )


def test_architecture_baseline_pins_setuptools_83(
    exact_architecture_baseline: Any,
) -> None:
    baseline = exact_architecture_baseline
    assert baseline.build_system_requires == ("setuptools==83.0.0",)
    assert baseline.build_backend == "setuptools.build_meta"
    setuptools = next(
        item for item in baseline.distributions if item.name == "setuptools"
    )
    assert setuptools.version == "83.0.0"


def test_architecture_baseline_rejects_lock_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    obligations = delivery_profile_obligations("CLI_PACKAGE", "new_repository")
    monkeypatch.setattr(
        "factory.architecture_baseline._locked_versions",
        lambda _path: {"setuptools": "82.0.0"},
    )
    with pytest.raises(
        ArchitectureBaselineToolchainMismatch, match="setuptools pin"
    ):
        build_architecture_baseline(
            config,
            {
                "delivery_profile": "CLI_PACKAGE",
                "delivery_mode": "new_repository",
            },
            {
                "delivery_profile": "CLI_PACKAGE",
                "delivery_mode": "new_repository",
            },
            obligations,
        )


def test_architecture_reviewer_uses_baseline_not_model_tool_choice(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    state = StateStore(config.database_path)
    product_id = "product-baseline-reviewer"
    state.create_product_v2(
        product_id=product_id,
        owner_id="owner",
        source="test",
        goal_text="Review the controller-owned architecture baseline",
        delivery_mode="new_repository",
        repository_url=None,
        repository_name="baseline-reviewer",
        repository_visibility="private",
        root_goal_ref=f"evidence/intake-{product_id}.json",
        constraints_ref=None,
        owner_defaults_ref=None,
        idempotency_key=sha256_text("intake:baseline-reviewer"),
        rate_limit=None,
        delivery_profile="LIBRARY_PACKAGE",
    )
    artifacts = ArtifactStore(config)
    task_path = PipelineCoordinator(config, state, artifacts).create_task(
        product_id, "independent-reviewer"
    )
    task_id = str(json.loads(task_path.read_text(encoding="utf-8"))["task_id"])
    task = state.get_task(task_id)
    assert task is not None
    worker = AgentWorker(
        config,
        state,
        runner=FakeRunner("{}"),
        repository_root=Path.cwd(),
    )
    try:
        with patch.object(worker, "_completed_review_evidence", return_value=[]):
            spec = worker.default_spec(task)
        assert any(
            item["type"] == "controller-architecture-baseline"
            for item in spec.evidence
        )
        assert any(
            "do not ask the model to reselect them" in decision
            for decision in spec.decisions
        )
    finally:
        state.close()


def _architecture_context_with_hypothesis(tmp_path: Path) -> dict[str, Any]:
    graph = _architecture_graph(tmp_path)
    state: StateStore = graph["state"]
    hypothesis_id = "hypothesis-architecture-correction"
    with state._connection:
        state._connection.execute(
            "UPDATE tasks SET hypothesis_id=? WHERE task_id IN (?,?)",
            (hypothesis_id, graph["correction_id"], graph["reviewer_id"]),
        )
    graph["hypothesis_id"] = hypothesis_id
    return graph


def test_architecture_correction_repair_stays_in_same_hypothesis(
    tmp_path: Path,
) -> None:
    graph = _architecture_graph(tmp_path)
    state: StateStore = graph["state"]
    try:
        correction_id = str(graph["correction_id"])
        claimed = state.claim_task(worker_id="architecture-correction-worker")
        assert claimed is not None and claimed["task_id"] == correction_id
        attempt_id = "attempt-architecture-model-repair"
        state.record_attempt(
            attempt_id=attempt_id,
            task_id=correction_id,
            tier="terra",
            attempt_kind="repair",
            prompt_digest=sha256_text("prompt:architecture-model-repair"),
            status="started",
            semantic_counted=True,
        )
        failure = FailureData(
            failure_class="semantic",
            reason_code="model_requested_repair",
            safe_message="The architecture correction needs one bounded semantic revision.",
            evidence_ref="internal://architecture-model-repair",
            expected={"architecture_review": "accepted"},
            actual={"required_fixes": ["Correct the exact architecture finding."]},
            failed_gate_ids=("architecture-review",),
        )
        committed = state.commit_task_outcome(
            TaskOutcome(
                task_id=correction_id,
                worker_id="architecture-correction-worker",
                lease_token=str(claimed["lease_token"]),
                expected_task_revision=int(claimed["task_revision"]),
                idempotency_key=sha256_text("outcome:architecture-model-repair"),
                result_ref="internal://architecture-model-repair",
                result_digest=sha256_text("architecture-model-repair"),
                status="FAILED_SEMANTIC",
                attempt_id=attempt_id,
                attempt_status="repair_required",
                failure=failure,
                hypothesis=HypothesisData(
                    statement=failure.safe_message,
                    signature=sha256_text("hypothesis:architecture-correction"),
                    required_evidence=(failure.evidence_ref,),
                ),
            )
        )
        assert committed.failure_id is not None
        first = state.get_task(correction_id)
        assert first is not None and first["hypothesis_id"]
        next_id = graph["router"].route(committed.failure_id)
        next_correction = state.get_task(next_id)
        reviewer = state.get_task(str(graph["reviewer_id"]))
        assert next_correction is not None and reviewer is not None
        assert next_correction["role"] == "solution_architect"
        assert next_correction["hypothesis_id"] == first["hypothesis_id"]
        assert next_id in json.loads(reviewer["dependencies_json"])
        assert state.get_task(correction_id)["graph_status"] == "FAILED_SEMANTIC"
        edge = state._connection.execute(
            """SELECT 1 FROM task_edges WHERE from_task_id=? AND to_task_id=?
                 AND edge_type='revalidates' AND required=1""",
            (next_id, graph["reviewer_id"]),
        ).fetchone()
        assert edge is not None
    finally:
        state.close()


def test_architecture_correction_transport_retry_costs_zero_semantic_attempts(
    tmp_path: Path,
) -> None:
    graph = _architecture_context_with_hypothesis(tmp_path)
    state: StateStore = graph["state"]
    try:
        with state._connection:
            state._connection.execute(
                "UPDATE tasks SET graph_status='FAILED_SEMANTIC' WHERE task_id=?",
                (graph["correction_id"],),
            )
        correction = state.get_task(str(graph["correction_id"]))
        assert correction is not None
        for reason in ("schema_validation", "malformed_transport"):
            context = graph["router"]._architecture_correction_context(
                correction,
                {"failure_class": "product", "reason_code": reason},
            )
            assert context is not None
            assert context.semantic_attempts_used == 0
    finally:
        state.close()


def test_architecture_correction_costs_zero_arbiter_and_execution_slots(
    tmp_path: Path,
) -> None:
    graph = _architecture_context_with_hypothesis(tmp_path)
    state: StateStore = graph["state"]
    try:
        correction = state.get_task(str(graph["correction_id"]))
        assert correction is not None
        assert execution_slot_cost(correction) == 0
        assert state._connection.execute(
            "SELECT COUNT(*) FROM problem_budgets"
        ).fetchone()[0] == 0
        context = graph["router"]._architecture_correction_context(
            correction,
            {"failure_class": "product", "reason_code": "schema_validation"},
        )
        assert context is not None
        assert state._connection.execute(
            "SELECT COUNT(*) FROM problem_budgets"
        ).fetchone()[0] == 0
    finally:
        state.close()


def test_architecture_correction_fourth_semantic_attempt_fails_typed(
    tmp_path: Path,
) -> None:
    graph = _architecture_context_with_hypothesis(tmp_path)
    state: StateStore = graph["state"]
    try:
        with state._connection:
            state._connection.execute(
                "UPDATE tasks SET graph_status='ACCEPTED', status='DONE' WHERE task_id=?",
                (graph["correction_id"],),
            )
        for index in (2, 3):
            task_id = f"T-ARCHSEMANTIC{index}"
            contract = _contract(
                task_id,
                revision=index + 1,
                parent_task_id=str(graph["reviewer_id"]),
                **graph["common"],
            )
            _add_projected_task(
                graph["router"],
                contract,
                durable_role="solution_architect",
                stage_key="repair",
                graph_status="ACCEPTED",
            )
            with state._connection:
                state._connection.execute(
                    "UPDATE tasks SET hypothesis_id=? WHERE task_id=?",
                    (graph["hypothesis_id"], task_id),
                )
        reviewer = state.get_task(str(graph["reviewer_id"]))
        assert reviewer is not None
        context = graph["router"]._architecture_correction_context(
            reviewer,
            {"failure_class": "semantic", "reason_code": "model_requested_repair"},
        )
        assert context is not None
        assert context.semantic_attempts_used == context.semantic_budget == 3
        disposition = failure_disposition("architecture_correction_budget_exhausted")
        assert disposition.registered
        assert disposition.action is FailureAction.CONTROLLER_QUARANTINE
    finally:
        state.close()


def test_missing_architecture_baseline_is_controller_failure() -> None:
    error = ArchitectureBaselineToolchainMismatch(
        "architecture_baseline_toolchain_mismatch"
    )
    assert AgentWorker._exception_reason_code(error) == (
        "architecture_baseline_toolchain_mismatch"
    )
    assert failure_disposition(
        "architecture_baseline_toolchain_mismatch"
    ).action is FailureAction.CONTROLLER_QUARANTINE


def test_python_gate_disables_external_pytest_plugins(
    tmp_path: Path,
) -> None:
    observed: list[dict[str, str]] = []

    def record(
        _argv: list[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        timeout: int,
    ) -> _BoundedProcessResult:
        assert cwd == tmp_path
        assert timeout == 10
        observed.append(environment)
        return _BoundedProcessResult(0, "pass", "", False, (), False)

    gate = {
        "id": "target-tests",
        "command": "python3 -m pytest -q",
        "allowlist_prefixes": ["python3 -m pytest"],
        "timeout_seconds": 10,
        "mandatory": True,
    }
    with patch("scripts.quality_gate._run_bounded_python_gate", side_effect=record):
        result = run_gate(
            gate,
            tmp_path,
            "1" * 64,
            python_executable=sys.executable,
            temporary_root=tmp_path.parent / "controller-temp",
        )
    assert result["status"] == "PASS"
    environment = observed[0]
    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["PYTHONHASHSEED"] == "0"
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"


def test_python_gate_timeout_kills_process_group_and_keeps_evidence(
    tmp_path: Path,
) -> None:
    timed_out = _BoundedProcessResult(
        None,
        "partial stdout",
        "faulthandler stderr",
        True,
        ({"pid": 101, "ppid": 1, "name": "pytest"},),
        True,
    )
    gate = {
        "id": "target-tests",
        "command": "python3 -m pytest -q",
        "allowlist_prefixes": ["python3 -m pytest"],
        "timeout_seconds": 10,
        "mandatory": True,
    }
    with patch(
        "scripts.quality_gate._run_bounded_python_gate", return_value=timed_out
    ) as bounded:
        result = run_gate(
            gate,
            tmp_path,
            "2" * 64,
            python_executable=sys.executable,
            temporary_root=tmp_path.parent / "controller-timeout-temp",
        )
    assert bounded.call_count == 2
    assert result["status"] == "ERROR"
    assert result["exit_code"] is None
    assert '"reason_code":"python_gate_timeout"' in result["summary"]
    assert '"faulthandler_dump_requested":true' in result["summary"]
    assert '"product_execution_slot_cost":0' in result["summary"]
    assert "partial stdout" in result["summary"]


def test_container_scan_verifier_is_outside_product_workspace(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "product"
    temporary = tmp_path / "controller" / "helper"
    workspace.mkdir()
    temporary.mkdir(parents=True)
    helper = _controller_image_security_verifier(temporary)
    with pytest.raises(ValueError):
        helper.relative_to(workspace)
    assert helper.parent == temporary.resolve()
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == (
        "247cc0b6f8f55e081c2188ec1f5f50a45cf358923c02117a8a15a6d3e9760f8f"
    )


def test_missing_container_helper_is_controller_failure(tmp_path: Path) -> None:
    config = _config(tmp_path)
    engine = QualityGateEngine(config, ArtifactStore(config))
    evidence = {
        "schema_version": "1.0",
        "gate_id": "target-container-image-scan",
        "status": "ERROR",
        "subject_sha": "3" * 64,
        "command_digest": "4" * 64,
        "started_at": "2026-08-11T00:00:00Z",
        "finished_at": "2026-08-11T00:00:01Z",
        "exit_code": None,
        "artifact_digest": "5" * 64,
        "summary": "controller_container_scan_helper_invalid: packaged helper is missing",
        "mandatory": True,
    }
    with (
        patch("factory.quality.run_gate", return_value=evidence),
        pytest.raises(ControllerContainerScanHelperInvalid),
    ):
        engine.run(
            cwd=tmp_path,
            subject_sha="3" * 64,
            task_id="T-MISSINGHELPER",
            attempt_id="attempt-missing-helper",
            gate_ids=["target-container-image-scan"],
        )


def test_container_helper_failure_does_not_create_builder_repair() -> None:
    disposition = failure_disposition("controller_container_scan_helper_invalid")
    assert disposition.registered
    assert disposition.action is FailureAction.CONTROLLER_QUARANTINE
    assert disposition.action is not FailureAction.REPAIR_NODE_VERSION


def test_generated_bytecode_is_not_a_scope_change(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    source = repository / "src" / "sample.py"
    source.parent.mkdir(parents=True)
    source.write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(["git", "add", "src/sample.py"], cwd=repository, check=True)
    before = _workspace_snapshot(repository)
    cache = repository / "src" / "__pycache__" / "sample.cpython-312.pyc"
    cache.parent.mkdir()
    cache.write_bytes(b"generated bytecode")
    after = _workspace_snapshot(repository)
    assert after == before
    assert "src/__pycache__/sample.cpython-312.pyc" not in after


def test_terminal_controller_incident_does_not_emit_liveness_failure(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    state = StateStore(config.database_path)
    product_id = "product-terminal-controller-incident"
    state.create_product_v2(
        product_id=product_id,
        owner_id="owner",
        source="test",
        goal_text="Fail closed without secondary liveness noise",
        delivery_mode="new_repository",
        repository_url=None,
        repository_name="terminal-incident",
        repository_visibility="private",
        root_goal_ref=f"evidence/intake-{product_id}.json",
        constraints_ref=None,
        owner_defaults_ref=None,
        idempotency_key=sha256_text("intake:terminal-incident"),
        rate_limit=None,
    )
    for status in ("RISK_CLASSIFIED", "ARCHITECTED", "IMPLEMENTING"):
        state.transition_product(product_id, status)
    stale_product = state.get_product(product_id)
    assert stale_product is not None
    with state._connection:
        state._connection.execute(
            """INSERT INTO plans
               (plan_id,product_id,revision,status,plan_artifact_ref,plan_digest,
                goals_json,completion_criteria_json,created_by_task_id,created_at,activated_at)
               VALUES ('PLAN-TERMINAL',?,1,'ACTIVE','evidence/plan.json',?,
                       '[]','[]','T-ROOT','2026-08-11T00:00:00Z','2026-08-11T00:00:00Z')""",
            (product_id, "6" * 64),
        )
        state._connection.execute(
            "UPDATE products SET active_plan_id='PLAN-TERMINAL', active_plan_revision=1 WHERE product_id=?",
            (product_id,),
        )
        state._connection.execute(
            """INSERT INTO controller_incidents
               (incident_id,product_id,task_id,reason_code,evidence_ref,status,created_at)
               VALUES ('incident-terminal',?,NULL,'controller_container_scan_helper_invalid',
                       'internal://terminal','OPEN','2026-08-11T00:00:00Z')""",
            (product_id,),
        )
        TransitionKernel(state._connection).apply_product(
            product_id=product_id,
            target="FAILED_SAFE",
            event="CONTROLLER_QUARANTINE",
            evidence={
                "controller_incident": "incident-terminal",
                "terminal_evidence": "internal://terminal",
            },
            terminal_reason="controller_container_scan_helper_invalid",
            terminal_evidence_ref="internal://terminal",
        )
    reconciler = PipelineReconciler(config, state, ArtifactStore(config))
    try:
        with patch.object(
            reconciler,
            "_route_liveness_violation",
            wraps=reconciler._route_liveness_violation,
        ) as liveness:
            assert reconciler.reconcile_product(stale_product) == "incident"
        liveness.assert_not_called()
        assert not any(
            failure["reason_code"] == "liveness_invariant_violation"
            for failure in state.list_failures(product_id)
        )
    finally:
        state.close()


def _profile_blueprint(
    profile: str,
    *,
    delivery_mode: str = "new_repository",
) -> dict[str, Any]:
    return _profile_protocol_blueprint(
        delivery_profile_obligations(profile, delivery_mode)
    )


def _fault_blueprint(*faults: str) -> dict[str, Any]:
    return _fault_lifecycle_blueprint(
        delivery_profile_obligations(
            "DEPLOYED_SERVICE", "new_repository", faults
        )
    )


def test_cli_exact_one_text_argument_contract() -> None:
    blueprint = _profile_blueprint("CLI_PACKAGE")
    assert blueprint["package"] == "deterministic-cli"
    assert blueprint["command_shape"] == ["deterministic-cli", "run", "TEXT"]
    assert blueprint["exact_positional_count"] == 1
    assert blueprint["usage_exit"] == 2
    assert blueprint["invalid_stdout"] == ""
    assert blueprint["usage_stderr"] == (
        "E_USAGE: expected exactly one TEXT argument\n"
    )
    assert blueprint["valid_stdout"] == "strict UTF-8 TEXT plus newline"


def test_http_head_never_writes_body_for_405() -> None:
    blueprint = _profile_blueprint("DEPLOYED_SERVICE")
    assert blueprint["http_head_body_bytes"] == 0
    assert blueprint["http_head_statuses"] == ["success", "error", 405]
    assert blueprint["healthz_get_status"] == 200


def test_telegram_race_is_bounded_and_exactly_one_claims() -> None:
    race = _profile_blueprint("TELEGRAM_BOT")["race_test"]
    assert race == {
        "database_preinitialized": True,
        "barrier_timeout_seconds": 5,
        "join_timeout_seconds": 10,
        "expected_results": [False, True],
    }


def test_telegram_crash_after_possible_send_becomes_ambiguous() -> None:
    blueprint = _profile_blueprint("TELEGRAM_BOT")
    assert blueprint["crash_after_possible_send"] == "AMBIGUOUS"
    assert blueprint["ambiguous_terminal"] is True
    assert blueprint["retry_only"] == "FAILED_BEFORE_SEND"
    assert "FAILED_BEFORE_SEND->CLAIMED" in blueprint["transitions"]


def test_existing_repository_ignores_pyc_scope_noise() -> None:
    blueprint = _profile_blueprint(
        "DEPLOYED_SERVICE", delivery_mode="existing_repository"
    )
    assert "**/__pycache__/**" in blueprint["changed_path_ignores"]
    assert "**/*.pyc" in blueprint["changed_path_ignores"]
    assert blueprint["behavioral_defects_fixed"] == 1
    assert blueprint["mandatory_metadata_not_counted_as_behavioral_defect"] is True
    assert blueprint["generated_cache_not_changed_path"] is True


def test_batch_memory_limit_is_reachable_through_public_admission() -> None:
    blueprint = _profile_blueprint("OFFLINE_BATCH")
    assert (
        blueprint["node_fixed_overhead_bytes"]
        + blueprint["exact_boundary_node_spec_bytes"]
        == blueprint["max_node_memory_bytes"]
    )
    assert blueprint["exact_boundary_node_spec_bytes"] < blueprint[
        "max_definition_bytes"
    ]


def test_batch_limit_plus_one_opens_no_input_and_writes_no_output() -> None:
    blueprint = _profile_blueprint("OFFLINE_BATCH")
    assert blueprint["plus_one_node_spec_bytes"] == (
        blueprint["exact_boundary_node_spec_bytes"] + 1
    )
    assert blueprint["plus_one_error"] == "BATCH_LIMIT_NODE_MEMORY"
    assert blueprint["validation_order"].index("per_node_accounted_memory") < (
        blueprint["validation_order"].index("open_inputs")
    )
    assert blueprint["limit_failure_opens_inputs"] is False
    assert blueprint["limit_failure_creates_outputs"] is False


def test_github_ref_claim_allows_exactly_one_concurrent_creator() -> None:
    blueprint = _profile_blueprint("GITHUB_AUTOMATION")
    assert blueprint["authority"] == "github_git_refs"
    assert blueprint["ref_prefix"] == "refs/hermes/claims/"
    assert blueprint["initial_atomic_operation"] == "create_ref"
    assert blueprint["concurrent_create_successes"] == 1


def test_github_ref_transition_rejects_sibling_stale_update() -> None:
    blueprint = _profile_blueprint("GITHUB_AUTOMATION")
    assert blueprint["update_operation"] == "non_force_fast_forward_ref_update"
    assert blueprint["transition_force"] is False
    assert blueprint["sibling_stale_update"] == "reject"
    assert blueprint["fencing_token"] == "monotonic_integer"


def test_external_wait_has_scheduled_automatic_resume() -> None:
    blueprint = _profile_blueprint("GITHUB_AUTOMATION")
    assert blueprint["automatic_resume"] == "scheduled_sweeper_every_5_minutes"
    assert blueprint["correlation_pattern"] == "^[a-f0-9]{64}$"
    assert blueprint["probe_none"] == "INVALID"


def test_retry_intent_is_globally_unique() -> None:
    fault = _fault_blueprint("ONE_PROVIDER_TIMEOUT")["ONE_PROVIDER_TIMEOUT"]
    assert fault["retry_intent_unique"] is True
    assert fault["create_only_from_state"] == "TIMED_OUT"
    assert fault["same_request_same_intent"] == "idempotent"
    assert fault["other_request_same_intent"] == "sqlite3.IntegrityError"


def test_provider_restart_consumes_one_durable_retry_intent() -> None:
    faults = _fault_blueprint("ONE_PROVIDER_TIMEOUT", "ONE_PROCESS_RESTART")
    timeout = faults["ONE_PROVIDER_TIMEOUT"]
    restart = faults["ONE_PROCESS_RESTART"]
    assert timeout["durable_before_restart"] is True
    assert timeout["consume_once_after_restart"] is True
    assert restart == {"intent_is_durable": True, "intent_consumptions": 1}


def test_product_test_fault_targets_exactly_target_tests_once() -> None:
    fault = _fault_blueprint("ONE_PRODUCT_TEST_FAILURE")[
        "ONE_PRODUCT_TEST_FAILURE"
    ]
    assert fault["injected_gate"] == "target-tests"
    assert fault["injected_count"] == 1
    assert fault["fresh_test_required"] is True


def test_failed_product_test_routes_to_exactly_one_builder_repair(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(
        tmp_path, reason_code="model_requested_repair"
    )
    try:
        router = FailureRouter(config, state, artifacts)
        repair_id = router.route(failure_id)
        repair = state.get_task(repair_id)
        assert repair is not None
        assert repair["role"] == "builder"
        assert repair["stage_key"] == "repair"
        repairs = [
            task
            for task in state.list_tasks("product-autonomy")
            if task["stage_key"] == "repair" and task["role"] == "builder"
        ]
        assert [task["task_id"] for task in repairs] == [repair_id]
        assert router.route_open_failures("product-autonomy") == []
    finally:
        state.close()


def test_manifest_rejects_non_artifact_before_sort() -> None:
    blueprint = _profile_blueprint("LIBRARY_PACKAGE")
    assert blueprint["package"] == "artifactproof"
    assert blueprint["validate_artifact_type_before_sort"] is True
    assert blueprint["invalid_type_exception"] == "MalformedEvidenceError"
    assert blueprint["require_issued_at_before_expires_at"] is True


def test_ed25519_release_verification_failure_matrix() -> None:
    blueprint = _profile_blueprint("LIBRARY_PACKAGE")
    assert blueprint["algorithm"] == "Ed25519"
    assert blueprint["implementation"] == "cryptography==46.0.7"
    assert blueprint["signature_encoding"] == "base64url_raw_64_bytes_no_padding"
    assert blueprint["verification_failure_matrix"] == [
        "missing",
        "malformed",
        "mismatch",
        "expired",
        "revoked",
        "stale",
    ]


def test_clean_consumer_installs_exact_wheel_offline() -> None:
    blueprint = _profile_blueprint("LIBRARY_PACKAGE")
    assert blueprint["clean_consumer_offline"] is True
    assert blueprint["clean_consumer_install_args"] == ["--no-index", "--no-deps"]
    assert blueprint["clean_consumer_smoke"] == ["import_package", "public_api"]


def test_production_server_rejects_staging_fault_control() -> None:
    fault = _fault_blueprint("ONE_POST_DEPLOY_HEALTH_FAILURE")[
        "ONE_POST_DEPLOY_HEALTH_FAILURE"
    ]
    assert fault["target"] == "isolated_candidate_production_semantics"
    assert fault["fault_disabled_by_default"] is True
    assert fault["production_server_rejects_staging_control"] is True
    assert fault["fault_token_bound_to"] == [
        "plane",
        "run_id",
        "scenario_id",
        "candidate_digest",
        "lifecycle_id",
        "production_stage",
    ]


def test_isolated_production_fault_rolls_back_once_then_redeploys() -> None:
    fault = _fault_blueprint("ONE_POST_DEPLOY_HEALTH_FAILURE")[
        "ONE_POST_DEPLOY_HEALTH_FAILURE"
    ]
    assert fault["fault_consumptions"] == 1
    assert fault["rollback_count"] == 1
    assert fault["repair_ref_requires_distinct_candidate_digest"] is True
    assert fault["repaired_redeploy_required"] is True
    assert fault["final_receipt"] == "healthy_production_semantic_target"
