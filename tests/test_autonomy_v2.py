from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest
from test_worker import FakeRunner, make_config, selected_registry

from factory.artifacts import ArtifactStore
from factory.autonomy import (
    CAPABILITY_PROFILES,
    FailureData,
    HypothesisData,
    TaskOutcome,
    safe_exception_diagnostic,
)
from factory.capabilities import CapabilityBroker, CapabilityCheck
from factory.common import sha256_file, sha256_text, stable_json
from factory.context_builder import ContextBuilder
from factory.failure_router import FailureRouter
from factory.intake import IntakeService
from factory.migrations import MIGRATIONS, apply_migrations
from factory.path_governor import PathGovernor
from factory.pipeline import PipelineCoordinator
from factory.plan_semantics import PlanContractViolation
from factory.policy import policy_digest
from factory.providers import ExternalBlocker
from factory.reconciler import PipelineReconciler
from factory.recovery import resume_reviewer_builder_route_failure
from factory.recovery_directive import build_scope_recovery_directive
from factory.repository import RepositoryBootstrapper
from factory.state import StateStore
from factory.worker import AgentWorker, _plan_contract_repair_findings
from scripts.build_legacy_2_0_19_fixture import build_fixture


def configured(tmp_path: Path):
    return make_config(
        tmp_path,
        selected_registry(tmp_path / "registry.yaml", selected="gpt-5.6-luna"),
    )


def accept_path_arbiter_and_prepare_replanner(
    config: Any,
    state: StateStore,
    artifacts: ArtifactStore,
    arbiter_task_id: str,
) -> str:
    """Exercise the real accepted-outcome path from Arbiter to Replanner."""

    task = state.get_task(arbiter_task_id)
    assert task is not None
    assert task["role"] == "path-arbiter"
    claimed = state.claim_task(worker_id=f"arbiter-{arbiter_task_id}")
    assert claimed is not None and claimed["task_id"] == arbiter_task_id
    failure = next(
        item
        for item in state.list_failures(str(task["product_id"]))
        if item["failure_id"] == task["failure_id"]
    )
    proposal = {
        "schema_version": "1.0",
        "status": "proposed",
        "root_problem_signature": str(task["root_problem_signature"]),
        "root_cause_class": "product_semantic",
        "recommended_action": "REPLAN_DELTA",
        "affected_semantic_node_keys": [
            str(task.get("semantic_node_key") or task.get("plan_node_id") or "affected")
        ],
        "evidence_refs": [str(failure["evidence_ref"])],
        "expected_progress_delta": {"unresolved_root_problem_signatures": -1},
        "summary": "Create one bounded semantic delta with fresh product evidence.",
    }
    output_path = artifacts.write(
        "path-decision-proposal.schema.json",
        proposal,
        filename=f"path-decision-{arbiter_task_id}.json",
    )
    prepared = PipelineCoordinator(config, state, artifacts).prepare_after(
        task,
        proposal,
        output_path,
    )
    assert len(prepared.successors) == 1
    attempt_id = f"attempt-{sha256_text(arbiter_task_id)[:20]}"
    prompt_digest = sha256_text(f"prompt:{arbiter_task_id}")
    artifacts.write(
        "attempt-result.schema.json",
        {
            "schema_version": "1.0",
            "artifact_id": f"attempt-result-{attempt_id}",
            "product_id": str(task["product_id"]),
            "created_at": "2026-08-03T00:00:00Z",
            "producer": {"role": "path-arbiter", "tier": "sol"},
            "policy_digest": policy_digest(config),
            "task_id": arbiter_task_id,
            "attempt_id": attempt_id,
            "tier": "sol",
            "attempt_kind": "arbitration",
            "prompt_digest": prompt_digest,
            "subject_sha_before": "a" * 64,
            "status": "completed",
            "summary": "Accepted one read-only bounded path arbitration.",
            "changed_files": [],
            "commands": [],
            "test_results": [],
            "assumptions": [],
            "findings": [],
            "evidence_refs": [f"evidence/{output_path.name}"],
        },
        filename=f"attempt-{attempt_id}.json",
    )
    assert state.record_attempt(
        attempt_id=attempt_id,
        task_id=arbiter_task_id,
        tier="sol",
        attempt_kind="arbitration",
        prompt_digest=prompt_digest,
        status="started",
        semantic_counted=True,
    )
    active_revision = int(
        next(
            plan["revision"]
            for plan in state.list_plans(str(task["product_id"]))
            if plan["plan_id"] == task["plan_id"]
        )
    )
    digest = sha256_file(output_path)
    state.commit_task_outcome(
        TaskOutcome(
            task_id=arbiter_task_id,
            worker_id=f"arbiter-{arbiter_task_id}",
            lease_token=str(claimed["lease_token"]),
            expected_task_revision=int(claimed["task_revision"]),
            expected_plan_revision=active_revision,
            idempotency_key=sha256_text(f"arbiter-outcome:{arbiter_task_id}"),
            result_ref=f"evidence/{output_path.name}",
            result_digest=digest,
            status="ACCEPTED",
            accepted_result_ref=f"evidence/{output_path.name}",
            accepted_result_digest=digest,
            accepted_policy_digest=policy_digest(config),
            attempt_id=attempt_id,
            attempt_status="completed",
            product_status=prepared.product_status,
            successors=prepared.successors,
        )
    )
    successor_id = str(prepared.successors[0]["task_id"])
    successor = state.get_task(successor_id)
    assert successor is not None and successor["role"] == "replanner"
    return successor_id


def create_v2_product(
    state: StateStore,
    *,
    product_id: str = "product-autonomy",
) -> dict[str, Any]:
    product, _ = state.create_product_v2(
        product_id=product_id,
        owner_id="owner",
        source="cli",
        goal_text="Build a durable task service with verified release evidence",
        delivery_mode="new_repository",
        repository_url=None,
        repository_name="durable-task-service",
        repository_visibility="private",
        root_goal_ref=f"evidence/intake-{product_id}.json",
        constraints_ref=None,
        owner_defaults_ref=None,
        idempotency_key=sha256_text(f"intake:{product_id}"),
        rate_limit=None,
    )
    return product


def task_contract(
    *,
    product_id: str,
    plan_id: str,
    node_id: str,
    task_id: str,
    root_task_id: str,
    criterion_id: str,
    role: str = "builder",
    capabilities: list[str] | None = None,
    profile: str = "builder_workspace",
    supersedes_task_id: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "2.0",
        "artifact_id": f"task-contract-{task_id}",
        "product_id": product_id,
        "task_id": task_id,
        "root_task_id": root_task_id,
        "parent_task_id": root_task_id,
        "source_task_id": root_task_id,
        "plan_id": plan_id,
        "plan_node_id": node_id,
        "task_revision": 1,
        "root_context_ref": f"evidence/intake-{product_id}.json",
        "active_context_ref": f"evidence/task-{task_id}.json",
        "failure_id": None,
        "hypothesis_id": None,
        "supersedes_task_id": supersedes_task_id,
        "title": f"Execute node {node_id}",
        "objective": f"Implement and verify the complete behavior for node {node_id}",
        "role": role,
        "output_schema": "attempt-result.schema.json",
        "dependencies": [],
        "conflict_keys": [f"{product_id}:src/{node_id.lower()}"],
        "acceptance": [
            {
                "criterion_id": criterion_id,
                "verification": f"Automated evidence proves {criterion_id}",
                "mandatory": True,
            }
        ],
        "required_capabilities": capabilities
        if capabilities is not None
        else list(CAPABILITY_PROFILES[profile]),
        "capability_profile": profile,
        "allowed_paths": [f"src/{node_id.lower()}/**"],
        "forbidden_paths": ["secrets/**"],
        "risk_tier": "medium",
        "model_floor": "luna",
        "idempotency_key": sha256_text(f"{plan_id}:{node_id}:{task_id}"),
        "status": "DRAFT",
        "priority": 10,
        "critical_path_rank": 0,
    }


def executable_plan(
    config,
    *,
    product_id: str,
    plan_id: str,
    root_task_id: str,
    revision: int = 1,
    parent_plan_id: str | None = None,
    source_failure_id: str | None = None,
    node_specs: list[tuple[str, str, str]] | None = None,
    edges: list[tuple[str, str]] | None = None,
    supersedes: dict[str, str] | None = None,
) -> dict[str, Any]:
    specs = node_specs or [
        ("A", "T-NODEA001", "accept-a"),
        ("B", "T-NODEB001", "accept-b"),
        ("C", "T-NODEC001", "accept-c"),
        ("D", "T-NODED001", "accept-d"),
    ]
    edge_values = edges if edges is not None else [("A", "B"), ("A", "C"), ("B", "C"), ("B", "D")]
    acceptance_ids = [criterion for _, _, criterion in specs]
    return {
        "schema_version": "2.0",
        "artifact_id": f"backlog-plan-{plan_id}",
        "product_id": product_id,
        "created_at": "2026-07-29T00:00:00Z",
        "producer": {
            "role": "task-specifier",
            "tier": "terra",
            "provider": "fake",
            "model": "fake",
        },
        "policy_digest": policy_digest(config),
        "status": "completed",
        "plan_id": plan_id,
        "revision": revision,
        "parent_plan_id": parent_plan_id,
        "source_failure_id": source_failure_id,
        "goals": [
            {
                "goal_id": "root-goal",
                "statement": "Deliver the complete verified service",
                "mandatory": True,
                "acceptance_ids": acceptance_ids,
            }
        ],
        "nodes": [
            {
                "node_id": node,
                "mandatory": True,
                "task_contract": task_contract(
                    product_id=product_id,
                    plan_id=plan_id,
                    node_id=node,
                    task_id=task_id,
                    root_task_id=root_task_id,
                    criterion_id=criterion,
                    supersedes_task_id=(supersedes or {}).get(node),
                ),
            }
            for node, task_id, criterion in specs
        ],
        "edges": [
            {
                "from": source,
                "to": target,
                "edge_type": "depends_on",
                "required": True,
            }
            for source, target in edge_values
        ],
        "completion_criteria": ["Every mandatory node and root goal has immutable PASS evidence"],
        "summary": "Executable multi-node product graph",
    }


def persist_and_ingest_plan(
    config,
    state: StateStore,
    plan: dict[str, Any],
    *,
    created_by_task_id: str,
) -> tuple[str, ...]:
    artifacts = ArtifactStore(config)
    for node in plan["nodes"]:
        contract = node["task_contract"]
        artifacts.write(
            "task-contract-v2.schema.json",
            contract,
            filename=f"task-{contract['task_id']}.json",
        )
        node["task_contract_ref"] = f"evidence/task-{contract['task_id']}.json"
    plan_path = artifacts.write(
        "backlog-plan-v2.schema.json",
        plan,
        filename=f"backlog-plan-{plan['plan_id']}.json",
    )
    return state.ingest_plan(
        plan,
        plan_artifact_ref=f"evidence/{plan_path.name}",
        plan_digest=artifacts.digest(plan),
        created_by_task_id=created_by_task_id,
    )


def test_plan_delta_inherits_signature_and_reserves_two_execution_slots(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    signature = "d" * 64
    try:
        create_v2_product(state)
        state.add_task(
            task_id="T-PATH-ARBITER",
            product_id="product-autonomy",
            title="Bounded path arbitration",
            role="replanner",
            output_schema="plan-proposal-v1.schema.json",
            root_problem_signature=signature,
        )
        governor = PathGovernor(
            state._connection,
            policy_digest=policy_digest(config),
        )
        with state._connection:
            assert governor.consume_budget(
                product_id="product-autonomy",
                root_problem_signature=signature,
                action_kind="arbiter",
                progress=governor.progress_vector("product-autonomy"),
                evidence_digest="1" * 64,
            ) == "CONTINUE"

        product = state.get_product("product-autonomy")
        assert product is not None
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-PATH-BUDGET-1",
            root_task_id="T-PATH-ARBITER",
            parent_plan_id=str(product["active_plan_id"]),
            node_specs=[
                ("A", "T-PATH-EXEC-A", "accept-a"),
                ("B", "T-PATH-EXEC-B", "accept-b"),
            ],
            edges=[("A", "B")],
        )
        for node in plan["nodes"]:
            node["task_contract"]["lifecycle_stage"] = "implementation-slice"
        task_ids = persist_and_ingest_plan(
            config,
            state,
            plan,
            created_by_task_id="T-PATH-ARBITER",
        )
        assert len(task_ids) == 2
        assert {
            str(state.get_task(task_id)["root_problem_signature"])
            for task_id in task_ids
        } == {signature}
        budget = state._connection.execute(
            """SELECT arbiter_calls_used, execution_attempts_used, status
                 FROM problem_budgets
                WHERE product_id=? AND root_problem_signature=?""",
            ("product-autonomy", signature),
        ).fetchone()
        assert budget is not None
        assert tuple(budget) == (1, 2, "ACTIVE")

        next_plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-PATH-BUDGET-2",
            root_task_id="T-PATH-ARBITER",
            revision=2,
            parent_plan_id="PLAN-PATH-BUDGET-1",
            node_specs=[("C", "T-PATH-EXEC-C", "accept-c")],
            edges=[],
        )
        next_plan["nodes"][0]["task_contract"]["lifecycle_stage"] = (
            "implementation-slice"
        )
        tasks_before = len(state.list_tasks("product-autonomy"))
        with pytest.raises(ValueError, match="execution budget is exhausted"):
            persist_and_ingest_plan(
                config,
                state,
                next_plan,
                created_by_task_id="T-PATH-ARBITER",
            )
        assert len(state.list_tasks("product-autonomy")) == tasks_before
        assert state.get_product("product-autonomy")["active_plan_revision"] == 1
    finally:
        state.close()


def test_AUT_P0_001_intake_separates_goal_and_repository(tmp_path: Path) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path, max_active_products=2)
    try:
        service = IntakeService(config, state, ArtifactStore(config))
        result = service.submit(
            source="cli",
            owner_id="owner",
            goal_text="Создать сервис учёта задач с API и документацией",
            delivery_mode="existing_repository",
            repository_url="https://github.com/brullik/example-private",
            idempotency_key="aut-p0-001",
        )
        replay = service.submit(
            source="cli",
            owner_id="owner",
            goal_text="Создать сервис учёта задач с API и документацией",
            delivery_mode="existing_repository",
            repository_url="https://github.com/brullik/example-private",
            idempotency_key="aut-p0-001",
        )
        product = state.get_product(result.product_id)
        assert product is not None
        assert product["goal_text"].startswith("Создать сервис")
        assert product["repository_url"] == "https://github.com/brullik/example-private"
        assert product["delivery_mode"] == "existing_repository"
        assert replay.product_id == result.product_id
        artifact = json.loads(Path(result.artifact_path).read_text(encoding="utf-8"))
        assert artifact["goal_text"] != artifact["repository_url"]
    finally:
        state.close()


def test_AUT_P0_001_v2_intake_persists_products_beyond_execution_capacity(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(
        config.database_path,
        max_active_workers=2,
        max_active_products=1,
    )
    try:
        service = IntakeService(config, state, ArtifactStore(config))
        first = service.submit(
            source="cli",
            owner_id="owner",
            goal_text="Build the first queued private service",
            delivery_mode="new_repository",
            repository_name="first-queued-service",
            idempotency_key="queued-v2-first",
        )
        second = service.submit(
            source="cli",
            owner_id="owner",
            goal_text="Build the second queued private service",
            delivery_mode="new_repository",
            repository_name="second-queued-service",
            idempotency_key="queued-v2-second",
        )

        assert first.created is True
        assert second.created is True
        assert len(state.list_products()) == 2
        assert state.active_tasks(first.product_id)
        assert state.active_tasks(second.product_id)
    finally:
        state.close()


def test_AUT_P0_001_scheduler_rotates_products_before_task_priority(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(
        config.database_path,
        max_active_workers=1,
        max_active_products=1,
    )
    artifacts = ArtifactStore(config)
    try:
        service = IntakeService(config, state, artifacts)
        first = service.submit(
            source="cli",
            owner_id="owner",
            goal_text="Build the repeatedly repairing private service",
            delivery_mode="new_repository",
            repository_name="repairing-service",
            idempotency_key="fair-scheduler-first",
        )
        second = service.submit(
            source="cli",
            owner_id="owner",
            goal_text="Build the independently queued private service",
            delivery_mode="new_repository",
            repository_name="independent-service",
            idempotency_key="fair-scheduler-second",
        )

        first_claim = state.claim_task(worker_id="worker-a")
        assert first_claim is not None
        assert first_claim["product_id"] == first.product_id
        state.complete_task(str(first_claim["task_id"]), "worker-a")
        PipelineCoordinator(config, state, artifacts).create_task(
            first.product_id,
            "builder-core",
        )
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE tasks SET priority=1000 "
                "WHERE product_id=? AND role='builder' AND status='PENDING'",
                (first.product_id,),
            )

        rotated = state.claim_task(worker_id="worker-b")

        assert rotated is not None
        assert rotated["product_id"] == second.product_id
        assert (
            int(
                state._connection.execute(
                    "SELECT priority FROM tasks "
                    "WHERE product_id=? AND role='builder' AND status='PENDING'",
                    (first.product_id,),
                ).fetchone()[0]
            )
            == 1000
        )
        state.complete_task(str(rotated["task_id"]), "worker-b")
        resumed = state.claim_task(worker_id="worker-c")
        assert resumed is not None
        assert resumed["product_id"] == first.product_id
        assert resumed["role"] == "builder"
    finally:
        state.close()


class FakeRepositoryAdapter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def create_repository(self, **values: Any) -> str:
        self.calls.append(("create", str(values["idempotency_key"])))
        return "https://github.com/brullik/durable-task-service"

    def clone(self, **values: Any) -> tuple[str, str]:
        self.calls.append(("clone", str(values["idempotency_key"])))
        destination = Path(values["destination"])
        (destination / ".git").mkdir(parents=True, exist_ok=True)
        return "main", ""

    def bootstrap_commit(self, **values: Any) -> str:
        self.calls.append(("bootstrap", str(values["idempotency_key"])))
        return "a" * 40


def test_AUT_P0_002_new_product_bootstrap_is_durable_and_idempotent(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    adapter = FakeRepositoryAdapter()
    try:
        create_v2_product(state)
        bootstrapper = RepositoryBootstrapper(config, state, adapter)
        workspace = tmp_path / "product-workspace"
        first = bootstrapper.ensure("product-autonomy", workspace)
        second = bootstrapper.ensure("product-autonomy", workspace)
        assert [call[0] for call in adapter.calls].count("create") == 1
        assert first["repository_url"] == second["repository_url"]
        product = state.get_product("product-autonomy")
        assert product is not None
        assert product["repository_visibility"] == "private"
        assert product["bootstrap_sha"] == "a" * 40
        assert product["repository_bootstrap_state"] == "READY"
    finally:
        state.close()


class FakePrivateRepositoryAdapter(FakeRepositoryAdapter):
    def __init__(self, credential: str) -> None:
        super().__init__()
        self.credential = credential

    def create_repository(self, **values: Any) -> str:
        raise AssertionError("existing repository must not be created")

    def clone(self, **values: Any) -> tuple[str, str]:
        assert self.credential
        self.calls.append(("clone", str(values["idempotency_key"])))
        destination = Path(values["destination"])
        (destination / ".git").mkdir(parents=True, exist_ok=True)
        return "main", "b" * 40


def test_AUT_P0_003_private_repository_credential_stays_outside_agent_boundary(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    credential = "github_pat_" + "A" * 24
    try:
        state.create_product_v2(
            product_id="private-product",
            owner_id="owner",
            source="cli",
            goal_text="Repair and verify the existing private service",
            delivery_mode="existing_repository",
            repository_url="https://github.com/brullik/private-service",
            repository_name=None,
            repository_visibility="private",
            root_goal_ref="evidence/intake-private-product.json",
            constraints_ref=None,
            owner_defaults_ref=None,
            idempotency_key=sha256_text("private-product"),
            rate_limit=None,
        )
        adapter = FakePrivateRepositoryAdapter(credential)
        result = RepositoryBootstrapper(config, state, adapter).ensure(
            "private-product",
            tmp_path / "private-workspace",
        )
        assert result["starting_sha"] == "b" * 40
        assert adapter.calls == [
            (
                "clone",
                sha256_text("repository-bootstrap:private-product") + ":clone",
            )
        ]
        persisted = "\n".join(
            json.dumps(row, ensure_ascii=False, default=str)
            for row in [
                *state.list_products(),
                *state.list_tasks(),
                *state.events(),
            ]
        )
        assert credential not in persisted
    finally:
        state.close()


def test_AUT_P0_004_plan_ingestion_creates_complete_dag(tmp_path: Path) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        root_id = "T-ROOTAUTONOMY"
        state.add_task(
            task_id=root_id,
            product_id="product-autonomy",
            title="Root planner",
            role="task-specifier",
        )
        product = state.get_product("product-autonomy")
        assert product is not None
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-AUTONOMY-1",
            root_task_id=root_id,
            parent_plan_id=str(product["active_plan_id"]),
        )
        errors = ArtifactStore(config).validate("backlog-plan-v2.schema.json", plan)
        assert errors == []
        task_ids = state.ingest_plan(
            plan,
            plan_artifact_ref="evidence/backlog-plan.json",
            plan_digest=sha256_text(json.dumps(plan, sort_keys=True)),
            created_by_task_id=root_id,
        )
        assert len(task_ids) == 4
        tasks = {
            str(task["plan_node_id"]): str(task["graph_status"])
            for task in state.list_tasks("product-autonomy")
            if task["plan_id"] == "PLAN-AUTONOMY-1"
        }
        assert tasks == {
            "A": "READY",
            "B": "BLOCKED_DEPENDENCY",
            "C": "BLOCKED_DEPENDENCY",
            "D": "BLOCKED_DEPENDENCY",
        }
        assert len(state.list_edges("PLAN-AUTONOMY-1")) == 4
    finally:
        state.close()


def failed_two_node_graph(
    tmp_path: Path,
    *,
    reason_code: str = "model_requested_repair",
) -> tuple[Any, StateStore, ArtifactStore, str, str]:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    artifacts = ArtifactStore(config)
    create_v2_product(state)
    root_id = "T-ROOTFAILURE"
    state.add_task(
        task_id=root_id,
        product_id="product-autonomy",
        title="Root task specifier",
        role="task-specifier",
    )
    product = state.get_product("product-autonomy")
    assert product is not None
    plan = executable_plan(
        config,
        product_id="product-autonomy",
        plan_id="PLAN-FAILURE-1",
        root_task_id=root_id,
        parent_plan_id=str(product["active_plan_id"]),
        node_specs=[
            ("A", "T-FAILNODEA", "accept-a"),
            ("B", "T-FAILNODEB", "accept-b"),
        ],
        edges=[("A", "B")],
    )
    persist_and_ingest_plan(
        config,
        state,
        plan,
        created_by_task_id=root_id,
    )
    claimed = state.claim_task(worker_id="worker")
    assert claimed is not None
    assert claimed["task_id"] == "T-FAILNODEA"
    failure = FailureData(
        failure_class="semantic",
        reason_code=reason_code,
        safe_message=(
            "Persistence contract is incompatible with the allowed scope; "
            "add the exact transaction boundary and regression proof."
        ),
        evidence_ref="internal://failure-evidence",
        expected={"acceptance": ["accept-a"]},
        actual={
            "required_fixes": [
                "Implement the transaction boundary in src/a/**.",
                "Add the exact regression test for the failed write.",
            ]
        },
        failed_gate_ids=("target-tests", "target-lint"),
    )
    state.commit_task_outcome(
        TaskOutcome(
            task_id="T-FAILNODEA",
            worker_id="worker",
            lease_token=str(claimed["lease_token"]),
            expected_plan_revision=1,
            idempotency_key=sha256_text(f"failure:{reason_code}"),
            result_ref="internal://failure-evidence",
            result_digest=sha256_text("failure-evidence"),
            status="FAILED_SEMANTIC",
            failure=failure,
            hypothesis=HypothesisData(
                statement=failure.safe_message,
                signature=sha256_text(f"hypothesis:{reason_code}"),
                required_evidence=(failure.evidence_ref,),
            ),
        )
    )
    failure_id = str(state.get_task("T-FAILNODEA")["failure_id"])
    return config, state, artifacts, failure_id, root_id


def test_AUT_P0_005_lineage_is_preserved_through_repair(tmp_path: Path) -> None:
    config, state, artifacts, failure_id, root_id = failed_two_node_graph(tmp_path)
    try:
        repair_id = FailureRouter(config, state, artifacts).route(failure_id)
        failed = state.get_task("T-FAILNODEA")
        repair = state.get_task(repair_id)
        assert failed is not None and repair is not None
        assert repair["root_task_id"] == root_id
        assert repair["parent_task_id"] == failed["task_id"]
        assert repair["source_task_id"] == failed["task_id"]
        assert repair["failure_id"] == failure_id
        assert repair["hypothesis_id"] == failed["hypothesis_id"]
        assert repair["plan_id"] == failed["plan_id"]
        assert str(repair["plan_node_id"]).startswith("A:")
    finally:
        state.close()


def test_repair_inherits_toolchain_capabilities_from_failed_node_lineage(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(tmp_path)
    try:
        failed = state.get_task("T-FAILNODEA")
        assert failed is not None
        inherited = [
            *json.loads(str(failed["required_capabilities_json"])),
            "toolchain.container_builder",
            "toolchain.scanners",
        ]
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE tasks SET required_capabilities_json=? WHERE task_id=?",
                (stable_json(inherited), "T-FAILNODEA"),
            )

        repair_id = FailureRouter(config, state, artifacts).route(failure_id)

        repair = state.get_task(repair_id)
        assert repair is not None
        required = json.loads(str(repair["required_capabilities_json"]))
        assert "toolchain.container_builder" in required
        assert "toolchain.scanners" in required
        contract = json.loads(
            (config.evidence_dir / Path(str(repair["contract_ref"])).name).read_text(
                encoding="utf-8"
            )
        )
        assert contract["required_capabilities"] == required

        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE tasks SET required_capabilities_json=? WHERE task_id=?",
                (
                    stable_json(list(CAPABILITY_PROFILES["builder_workspace"])),
                    repair_id,
                ),
            )
        stripped_repair = state.get_task(repair_id)
        assert stripped_repair is not None
        recovered = FailureRouter(
            config,
            state,
            artifacts,
        )._lineage_required_capabilities(
            stripped_repair,
            "builder_workspace",
        )
        assert "toolchain.container_builder" in recovered
        assert "toolchain.scanners" in recovered
    finally:
        state.close()


@pytest.mark.parametrize(
    "reason_code",
    ["mandatory_gate_failed", "model_requested_repair"],
)
def test_actionable_failure_from_readonly_reviewer_routes_to_replanner(
    tmp_path: Path,
    reason_code: str,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(
        tmp_path,
        reason_code=reason_code,
    )
    try:
        failed = state.get_task("T-FAILNODEA")
        assert failed is not None
        contract_path = config.evidence_dir / Path(str(failed["contract_ref"])).name
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        contract.update(
            {
                "role": "security-reviewer",
                "output_schema": "security-review-result.schema.json",
                "capability_profile": "reviewer_readonly",
                "required_capabilities": list(CAPABILITY_PROFILES["reviewer_readonly"]),
                "quality_gates": ["target-tests", "target-lint"],
            }
        )
        contract_path.write_text(
            json.dumps(contract, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with state._lock, state._connection:
            state._connection.execute(
                """UPDATE tasks
                   SET role='security-reviewer',
                       output_schema='security-review-result.schema.json',
                       capability_profile='reviewer_readonly',
                       required_capabilities_json=?
                   WHERE task_id='T-FAILNODEA'""",
                (stable_json(list(CAPABILITY_PROFILES["reviewer_readonly"])),),
            )

        routed_id = FailureRouter(config, state, artifacts).route(failure_id)

        routed = state.get_task(routed_id)
        assert routed is not None
        assert routed["role"] == "path-arbiter"
        assert routed["output_schema"] == "path-decision-proposal.schema.json"
        assert routed["stage_key"] == "path-arbiter"
        assert routed["capability_profile"] == "planning_readonly"
        assert routed["repair_context_ref"] is None
        routed_contract = json.loads(
            (config.evidence_dir / Path(str(routed["contract_ref"])).name).read_text(
                encoding="utf-8"
            )
        )
        assert routed_contract["failure_id"] == failure_id
        assert routed_contract["quality_gates"] == []
        assert routed_contract["model_floor"] == "sol"
        assert routed["root_problem_signature"]
        budget = state._connection.execute(
            """SELECT arbiter_calls_used, execution_attempts_used, status
                 FROM problem_budgets
                WHERE product_id=? AND root_problem_signature=?""",
            ("product-autonomy", routed["root_problem_signature"]),
        ).fetchone()
        assert budget is not None
        assert tuple(budget) == (1, 0, "ACTIVE")
        decision = state._connection.execute(
            """SELECT action, status FROM path_decisions
                WHERE product_id=? AND root_problem_signature=?""",
            ("product-autonomy", routed["root_problem_signature"]),
        ).fetchone()
        assert decision is not None
        assert tuple(decision) == ("REPLAN_DELTA", "APPLIED")
    finally:
        state.close()


@pytest.mark.parametrize(
    ("second_reason", "failed_gate_id"),
    [
        ("mandatory_gate_failed", "target-dependency-audit"),
        ("model_requested_repair", "SECURITY-CONTAINER-SCAN-NOT-RUN"),
    ],
)
def test_reviewer_gate_failure_after_arbiter_uses_remaining_builder_slot(
    tmp_path: Path,
    second_reason: str,
    failed_gate_id: str,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(
        tmp_path,
        reason_code="mandatory_gate_failed",
    )
    try:
        failed = state.get_task("T-FAILNODEA")
        assert failed is not None
        contract_path = config.evidence_dir / Path(str(failed["contract_ref"])).name
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        contract.update(
            {
                "role": "security-reviewer",
                "output_schema": "security-review-result.schema.json",
                "capability_profile": "reviewer_readonly",
                "required_capabilities": list(CAPABILITY_PROFILES["reviewer_readonly"]),
                "allowed_paths": ["artifacts/**"],
                "quality_gates": ["target-dependency-audit"],
            }
        )
        contract_path.write_text(
            json.dumps(contract, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with state._lock, state._connection:
            state._connection.execute(
                """UPDATE tasks
                   SET role='security-reviewer',
                       output_schema='security-review-result.schema.json',
                       capability_profile='reviewer_readonly',
                       required_capabilities_json=?
                   WHERE task_id='T-FAILNODEA'""",
                (stable_json(list(CAPABILITY_PROFILES["reviewer_readonly"])),),
            )

        router = FailureRouter(config, state, artifacts)
        arbiter_id = router.route(failure_id)
        arbiter = state.get_task(arbiter_id)
        assert arbiter is not None and arbiter["role"] == "path-arbiter"
        signature = str(arbiter["root_problem_signature"])
        second_failure_id = f"failure-reviewer-after-arbiter-{second_reason}"
        safe_message = (
            "Build and scan the exact immutable image before security acceptance."
            if "CONTAINER" in failed_gate_id
            else "Target dependency audit requires a repository repair."
        )
        now = "2026-08-03T00:00:01Z"
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE failures SET status='RESOLVED' WHERE failure_id=?",
                (failure_id,),
            )
            state._connection.execute(
                """INSERT INTO failures
                   (failure_id, product_id, task_id, failure_class, reason_code,
                    fingerprint, safe_message, evidence_ref, status, retryable,
                    owner_action_eligible, expected_json, actual_json,
                   failed_gate_ids_json, parent_failure_id, first_seen_at, last_seen_at)
                   VALUES (?, 'product-autonomy', 'T-FAILNODEA', 'semantic',
                           ?, ?, ?,
                           'internal://reviewer-gate', 'OPEN', 0, 0, '{}', ?, ?, ?, ?, ?)""",
                (
                    second_failure_id,
                    second_reason,
                    sha256_text(second_failure_id),
                    safe_message,
                    stable_json(
                        {
                            "required_fixes": [
                                "Produce fresh subject-bound evidence for the reviewer."
                            ]
                        }
                    ),
                    stable_json([failed_gate_id]),
                    failure_id,
                    now,
                    now,
                ),
            )
            state._connection.execute(
                "UPDATE tasks SET failure_id=? WHERE task_id='T-FAILNODEA'",
                (second_failure_id,),
            )
            state._connection.execute(
                """UPDATE problem_budgets
                      SET execution_attempts_used=1, status='ACTIVE'
                    WHERE product_id='product-autonomy'
                      AND root_problem_signature=?""",
                (signature,),
            )

        repair_id = router.route(second_failure_id)
        repair = state.get_task(repair_id)
        assert repair is not None
        assert repair["role"] == "builder"
        assert repair["output_schema"] == "implementation-result.schema.json"
        assert repair["capability_profile"] == "builder_workspace"
        assert repair["stage_key"] == "repair"
        assert repair["repair_context_ref"]
        repair_contract = json.loads(
            (config.evidence_dir / Path(str(repair["contract_ref"])).name).read_text(
                encoding="utf-8"
            )
        )
        expected_paths = ["pyproject.toml", "src/**", "tests/**"]
        if "dependency" in failed_gate_id:
            expected_paths.insert(1, "requirements*.txt")
        if "CONTAINER" in failed_gate_id:
            expected_paths.extend(
                [
                    "Dockerfile",
                    "docker/**",
                    "compose*.yaml",
                    "compose*.yml",
                    "scripts/**",
                ]
            )
        assert repair_contract["allowed_paths"] == expected_paths
        assert repair_contract["quality_gates"] == ["target-dependency-audit"]
        assert repair_contract["acceptance"][0]["criterion_id"] == (
            "AC-REVIEWER-GATE-ROOT-CAUSE"
        )
        budget = state._connection.execute(
            """SELECT arbiter_calls_used, execution_attempts_used, status
                 FROM problem_budgets
                WHERE product_id='product-autonomy'
                  AND root_problem_signature=?""",
            (signature,),
        ).fetchone()
        assert tuple(budget) == (1, 2, "ACTIVE")
    finally:
        state.close()


def test_reviewer_builder_route_recovery_preserves_finding_and_budget(
    tmp_path: Path,
) -> None:
    config, state, artifacts, first_failure_id, _ = failed_two_node_graph(
        tmp_path,
        reason_code="mandatory_gate_failed",
    )
    try:
        failed = state.get_task("T-FAILNODEA")
        assert failed is not None
        contract_path = config.evidence_dir / Path(str(failed["contract_ref"])).name
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        contract.update(
            {
                "role": "security-reviewer",
                "output_schema": "security-review-result.schema.json",
                "capability_profile": "reviewer_readonly",
                "required_capabilities": [
                    *CAPABILITY_PROFILES["reviewer_readonly"],
                    "toolchain.container_builder",
                    "toolchain.scanners",
                ],
                "allowed_paths": ["artifacts/**"],
                "quality_gates": ["target-tests", "target-sast"],
            }
        )
        contract_path.write_text(
            json.dumps(contract, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with state._lock, state._connection:
            state._connection.execute(
                """UPDATE tasks
                   SET role='security-reviewer',
                       output_schema='security-review-result.schema.json',
                       capability_profile='reviewer_readonly',
                       required_capabilities_json=?
                   WHERE task_id='T-FAILNODEA'""",
                (stable_json(contract["required_capabilities"]),),
            )

        router = FailureRouter(config, state, artifacts)
        arbiter_id = router.route(first_failure_id)
        arbiter = state.get_task(arbiter_id)
        assert arbiter is not None and arbiter["role"] == "path-arbiter"
        signature = str(arbiter["root_problem_signature"])
        failure_id = "failure-production-container-scan-route"
        now = "2026-08-03T00:00:02Z"
        safe_message = (
            "blocking findings: SECURITY-CONTAINER-SCAN-NOT-RUN [high]: "
            "No subject-bound immutable image scan exists; build and scan the "
            "exact immutable image before security acceptance."
        )
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE failures SET status='RESOLVED' WHERE failure_id=?",
                (first_failure_id,),
            )
            state._connection.execute(
                """INSERT INTO failures
                   (failure_id, product_id, task_id, failure_class, reason_code,
                    fingerprint, safe_message, evidence_ref, status, retryable,
                    owner_action_eligible, expected_json, actual_json,
                    failed_gate_ids_json, parent_failure_id, first_seen_at, last_seen_at)
                   VALUES (?, 'product-autonomy', 'T-FAILNODEA', 'semantic',
                           'model_requested_repair', ?, ?,
                           'internal://container-scan-review', 'ROUTED', 0, 0,
                           '{}', ?, ?, ?, ?, ?)""",
                (
                    failure_id,
                    sha256_text(failure_id),
                    safe_message,
                    stable_json(
                        {
                            "required_fixes": [
                                "Build and scan the immutable candidate image."
                            ]
                        }
                    ),
                    stable_json(["SECURITY-CONTAINER-SCAN-NOT-RUN"]),
                    first_failure_id,
                    now,
                    now,
                ),
            )
            state._connection.execute(
                "UPDATE tasks SET failure_id=? WHERE task_id='T-FAILNODEA'",
                (failure_id,),
            )
            state._connection.execute(
                """UPDATE problem_budgets
                      SET deterministic_actions_used=1,
                          execution_attempts_used=1, status='EXHAUSTED'
                    WHERE product_id='product-autonomy'
                      AND root_problem_signature=?""",
                (signature,),
            )
            state._connection.execute(
                """UPDATE products SET status='FAILED_SAFE',
                          terminal_reason='path_governor_problem_budget_exhausted'
                    WHERE product_id='product-autonomy'"""
            )

        state.enter_maintenance("reviewer-builder-route-recovery")
        applied = resume_reviewer_builder_route_failure(
            config,
            state,
            product_id="product-autonomy",
            failure_id=failure_id,
            correction_evidence_digest="d" * 64,
        )
        assert applied["application_status"] == "APPLIED"
        repair = state.get_task(str(applied["recovery_task_id"]))
        assert repair is not None
        assert repair["role"] == "builder"
        assert repair["stage_key"] == "repair"
        required = json.loads(str(repair["required_capabilities_json"]))
        assert "toolchain.container_builder" in required
        assert "toolchain.scanners" in required
        repair_contract = json.loads(
            (config.evidence_dir / Path(str(repair["contract_ref"])).name).read_text(
                encoding="utf-8"
            )
        )
        assert "Dockerfile" in repair_contract["allowed_paths"]
        assert "docker/**" in repair_contract["allowed_paths"]
        assert repair_contract["quality_gates"] == ["target-tests", "target-sast"]
        finding = state._connection.execute(
            "SELECT failure_class,reason_code,status FROM failures WHERE failure_id=?",
            (failure_id,),
        ).fetchone()
        assert tuple(finding) == ("semantic", "model_requested_repair", "ROUTED")
        budget = state._connection.execute(
            """SELECT deterministic_actions_used,arbiter_calls_used,
                      execution_attempts_used,status
                 FROM problem_budgets
                WHERE product_id='product-autonomy'
                  AND root_problem_signature=?""",
            (signature,),
        ).fetchone()
        assert tuple(budget) == (1, 1, 2, "ACTIVE")
        assert state.get_product("product-autonomy")["status"] == "IMPLEMENTING"
        replay = resume_reviewer_builder_route_failure(
            config,
            state,
            product_id="product-autonomy",
            failure_id=failure_id,
            correction_evidence_digest="d" * 64,
        )
        assert replay["application_status"] == "REPLAYED"
        assert state._connection.execute(
            """SELECT COUNT(*) FROM tasks
                WHERE product_id='product-autonomy' AND failure_id=?
                  AND role='builder' AND stage_key='repair'""",
            (failure_id,),
        ).fetchone()[0] == 1
    finally:
        state.close()


def test_path_governor_live_router_enforces_one_arbiter_two_executions(
    tmp_path: Path,
) -> None:
    """Production routing cannot reset a structural budget with fresh task IDs."""

    config, state, artifacts, failure_id, _ = failed_two_node_graph(
        tmp_path,
        reason_code="mandatory_gate_failed",
    )
    try:
        failed = state.get_task("T-FAILNODEA")
        assert failed is not None
        contract_path = config.evidence_dir / Path(str(failed["contract_ref"])).name
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        contract.update(
            {
                "role": "security-reviewer",
                "output_schema": "security-review-result.schema.json",
                "capability_profile": "reviewer_readonly",
                "required_capabilities": list(CAPABILITY_PROFILES["reviewer_readonly"]),
                "quality_gates": ["target-tests", "target-lint"],
            }
        )
        contract_path.write_text(
            json.dumps(contract, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with state._lock, state._connection:
            state._connection.execute(
                """UPDATE tasks
                   SET role='security-reviewer',
                       output_schema='security-review-result.schema.json',
                       capability_profile='reviewer_readonly',
                       required_capabilities_json=?
                   WHERE task_id='T-FAILNODEA'""",
                (stable_json(list(CAPABILITY_PROFILES["reviewer_readonly"])),),
            )

        router = FailureRouter(config, state, artifacts)
        arbiter_id = router.route(failure_id)
        arbiter = state.get_task(arbiter_id)
        assert arbiter is not None and arbiter["role"] == "path-arbiter"
        signature = str(arbiter["root_problem_signature"])
        replanner_id = accept_path_arbiter_and_prepare_replanner(
            config,
            state,
            artifacts,
            arbiter_id,
        )
        product = state.get_product("product-autonomy")
        assert product is not None
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-PATH-LIVE-2",
            root_task_id=replanner_id,
            revision=2,
            parent_plan_id=str(product["active_plan_id"]),
            node_specs=[
                ("repair-a", "T-PATH-LIVE-A", "fresh-a"),
                ("repair-b", "T-PATH-LIVE-B", "fresh-b"),
            ],
            edges=[("repair-a", "repair-b")],
        )
        for node in plan["nodes"]:
            node["task_contract"]["lifecycle_stage"] = "implementation-slice"
        persist_and_ingest_plan(
            config,
            state,
            plan,
            created_by_task_id=replanner_id,
        )
        claimed = state.claim_task(worker_id="path-budget-exhaustion")
        assert claimed is not None and claimed["task_id"] == "T-PATH-LIVE-A"
        committed = state.commit_task_outcome(
            TaskOutcome(
                task_id="T-PATH-LIVE-A",
                worker_id="path-budget-exhaustion",
                lease_token=str(claimed["lease_token"]),
                expected_task_revision=int(claimed["task_revision"]),
                expected_plan_revision=2,
                idempotency_key=sha256_text("path-budget-exhaustion"),
                result_ref="internal://path-budget-exhaustion",
                result_digest=sha256_text("path-budget-exhaustion"),
                status="FAILED_SEMANTIC",
                failure=FailureData(
                    failure_class="semantic",
                    reason_code="model_requested_repair",
                    safe_message="Reserved evidence execution did not solve the gate.",
                    evidence_ref="internal://path-budget-exhaustion",
                    parent_failure_id=failure_id,
                    failed_gate_ids=("target-dependency-audit",),
                ),
            )
        )
        assert committed.failure_id is not None
        tasks_before = len(state.list_tasks("product-autonomy"))
        terminal_task_id = router.route(committed.failure_id)
        assert terminal_task_id == "T-PATH-LIVE-A"
        assert len(state.list_tasks("product-autonomy")) == tasks_before

        product = state.get_product("product-autonomy")
        assert product is not None
        assert product["status"] == "FAILED_SAFE"
        assert product["terminal_reason"] == "path_governor_problem_budget_exhausted"
        budget = state._connection.execute(
            """SELECT arbiter_calls_used, execution_attempts_used, status
                 FROM problem_budgets
                WHERE product_id=? AND root_problem_signature=?""",
            ("product-autonomy", signature),
        ).fetchone()
        assert budget is not None
        assert tuple(budget) == (1, 2, "EXHAUSTED")
        decisions = state._connection.execute(
            """SELECT action, status FROM path_decisions
                WHERE product_id=? AND root_problem_signature=?
                ORDER BY created_at, decision_id""",
            ("product-autonomy", signature),
        ).fetchall()
        decision_pairs = [tuple(row) for row in decisions]
        assert decision_pairs.count(("REPLAN_DELTA", "APPLIED")) == 1
        assert decision_pairs.count(("REPAIR_NODE", "FAILED_SAFE")) == 1
    finally:
        state.close()


def test_path_arbiter_worker_runs_readonly_and_creates_one_replanner(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(
        tmp_path,
        reason_code="needs_replan",
    )
    try:
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE products SET delivery_mode=NULL WHERE product_id=?",
                ("product-autonomy",),
            )
        arbiter_id = FailureRouter(config, state, artifacts).route(failure_id)
        arbiter = state.get_task(arbiter_id)
        assert arbiter is not None
        signature = str(arbiter["root_problem_signature"])
        runner = FakeRunner(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "status": "proposed",
                    "root_problem_signature": signature,
                    "root_cause_class": "product_semantic",
                    "recommended_action": "REPLAN_DELTA",
                    "affected_semantic_node_keys": ["a"],
                    "evidence_refs": ["internal://failure/evidence"],
                    "expected_progress_delta": {
                        "unresolved_root_problem_signatures": -1
                    },
                    "summary": "Create one bounded semantic delta with fresh evidence.",
                }
            )
        )
        result = AgentWorker(
            config,
            state,
            runner=runner,
            health_probe=lambda _: True,
            repository_root=Path(__file__).resolve().parents[1],
        ).run_once()

        assert result is not None and result.status == "completed"
        assert len(runner.calls) == 1
        durable_arbiter = state.get_task(arbiter_id)
        assert durable_arbiter is not None
        assert durable_arbiter["graph_status"] == "ACCEPTED"
        replanners = [
            task
            for task in state.list_tasks("product-autonomy")
            if task["role"] == "replanner" and task["graph_status"] == "READY"
        ]
        assert len(replanners) == 1
        assert replanners[0]["parent_task_id"] == arbiter_id
        assert replanners[0]["root_problem_signature"] == signature
        context = json.loads(
            (config.evidence_dir / f"context-{arbiter_id}.json").read_text(
                encoding="utf-8"
            )
        )
        snapshot = context["plan_summary"]["path_snapshot"]
        assert snapshot["root_problem_signature"] == signature
        assert snapshot["problem_budget"]["arbiter_calls_used"] == 1
        assert snapshot["problem_budget"]["execution_attempts_used"] == 0
    finally:
        state.close()


def test_exact_builder_repair_inherits_controller_quality_gates(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(tmp_path)
    try:
        failed = state.get_task("T-FAILNODEA")
        assert failed is not None
        contract_path = config.evidence_dir / Path(str(failed["contract_ref"])).name
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        contract["quality_gates"] = ["unit-tests", "lint"]
        contract_path.write_text(
            json.dumps(contract, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        repair_id = FailureRouter(config, state, artifacts).route(failure_id)

        repair = state.get_task(repair_id)
        assert repair is not None
        assert repair["role"] == "builder"
        repair_contract = json.loads(
            (config.evidence_dir / Path(str(repair["contract_ref"])).name).read_text(
                encoding="utf-8"
            )
        )
        assert repair_contract["quality_gates"] == ["unit-tests", "lint"]
    finally:
        state.close()


def test_scope_insufficient_builder_failure_routes_directly_to_replanner(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(tmp_path)
    try:
        with state._lock, state._connection:
            state._connection.execute(
                """UPDATE failures
                      SET actual_json=?
                    WHERE failure_id=?""",
                (
                    stable_json(
                        {
                            "required_fixes": ["Repair the Compose runtime root cause."],
                            "scope_reassessment_required": True,
                            "blocked_allowed_paths": ["tests/**"],
                            "provider_scope_findings": [
                                {
                                    "code": "FULL_SUITE_UNRELATED_FAILURE",
                                    "severity": "medium",
                                    "text": (
                                        "scripts/image_security_verify.py is outside "
                                        "allowed task scope."
                                    ),
                                }
                            ],
                        }
                    ),
                    failure_id,
                ),
            )

        arbiter_id = FailureRouter(config, state, artifacts).route(failure_id)
        routed_id = accept_path_arbiter_and_prepare_replanner(
            config, state, artifacts, arbiter_id
        )

        routed = state.get_task(routed_id)
        assert routed is not None
        assert routed["role"] == "replanner"
        assert routed["stage_key"] == "replan-after-arbiter"
        assert routed["repair_context_ref"] is None
        contract = json.loads(
            (config.evidence_dir / Path(str(routed["contract_ref"])).name).read_text(
                encoding="utf-8"
            )
        )
        assert "allowed_paths were too narrow" in contract["objective"]
        assert "Expand the bounded implementation scope" in contract["objective"]
        assert "scripts/image_security_verify.py" in contract["objective"]
        assert contract["allowed_paths"] == ["artifacts/**"]
    finally:
        state.close()


def test_exact_safe_scope_expansion_compiles_without_provider_call(
    tmp_path: Path,
) -> None:
    """LOOP-P1-002: one proven path expands the plan deterministically."""

    config, state, artifacts, root_failure_id, _ = failed_two_node_graph(tmp_path)
    runner = FakeRunner("{}")
    try:
        product = state.get_product("product-autonomy")
        assert product is not None
        active_plan_id = str(product["active_plan_id"])
        state.add_task(
            task_id="T-ACCEPTED-ARCHITECTURE",
            product_id="product-autonomy",
            title="Accepted architecture source",
            role="solution-architect",
            plan_id=active_plan_id,
            stage_key="architecture-source",
        )
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE products SET delivery_mode=NULL WHERE product_id=?",
                ("product-autonomy",),
            )
            state._connection.execute(
                """
                UPDATE tasks
                   SET status='SUCCEEDED', graph_status='ACCEPTED',
                       result_ref='internal://architecture-package',
                       result_digest=?
                 WHERE task_id='T-ACCEPTED-ARCHITECTURE'
                """,
                (sha256_text("architecture-package"),),
            )
            state._connection.execute(
                "UPDATE failures SET actual_json=? WHERE failure_id=?",
                (
                    stable_json(
                        {
                            "scope_reassessment_required": True,
                            "blocked_allowed_paths": ["src/a/**"],
                            "provider_scope_findings": [
                                {
                                    "code": "SCOPE_INSUFFICIENT",
                                    "severity": "high",
                                    "text": (
                                        "scripts/image_security_verify.py is outside "
                                        "allowed task scope."
                                    ),
                                }
                            ],
                        }
                    ),
                    root_failure_id,
                ),
            )
        failed = state.get_task("T-FAILNODEA")
        product = state.get_product("product-autonomy")
        assert failed is not None and product is not None
        for index in range(40):
            state.add_task(
                task_id=f"T-HISTORICAL-SUPERSEDED-{index:02d}",
                product_id="product-autonomy",
                title=f"Historical superseded Builder {index}",
                role="builder",
                output_schema="attempt-result.schema.json",
                contract_ref=str(failed["contract_ref"]),
                stage_key=f"historical-repair-{index:02d}",
                plan_id=str(product["active_plan_id"]),
                plan_node_id=f"historical-repair-{index:02d}",
                capability_profile="builder_workspace",
                graph_status="SUPERSEDED",
            )
        arbiter_id = FailureRouter(config, state, artifacts).route(root_failure_id)
        replanner_id = accept_path_arbiter_and_prepare_replanner(
            config, state, artifacts, arbiter_id
        )
        replanner = state.get_task(replanner_id)
        assert replanner is not None
        contract = json.loads(
            (
                config.evidence_dir / Path(str(replanner["contract_ref"])).name
            ).read_text(encoding="utf-8")
        )
        assert contract["allowed_paths"] == ["artifacts/**"]

        worker = AgentWorker(
            config,
            state,
            runner=runner,
            health_probe=lambda _: True,
            repository_root=Path(__file__).resolve().parents[1],
        )
        result = worker.run_once()

        assert result is not None
        assert result.status == "completed"
        assert runner.calls == []
        product = state.get_product("product-autonomy")
        assert product is not None
        assert int(product["active_plan_revision"]) == 2
        implementation = next(
            task
            for task in state.list_tasks("product-autonomy")
            if task["plan_id"] == product["active_plan_id"]
            and task["semantic_node_key"] == "a"
            and task["lifecycle_stage"] == "implementation-slice"
        )
        compiled_contract = json.loads(
            (
                config.evidence_dir / Path(str(implementation["contract_ref"])).name
            ).read_text(encoding="utf-8")
        )
        assert "scripts/image_security_verify.py" in compiled_contract["allowed_paths"]
        result_artifact = json.loads(
            Path(str(result.artifact_ref)).read_text(encoding="utf-8")
        )
        assert result_artifact["producer"]["provider"] == "controller"
        assert (
            result_artifact["commands"][0]["command_id"]
            == "controller-deterministic-scope-expansion"
        )
    finally:
        state.close()


def test_scope_recovery_signature_is_stable_across_reason_transitions(
    tmp_path: Path,
) -> None:
    """LOOP-P0-005: wording and control reason codes cannot reset the budget."""

    config, state, _, root_failure_id, _ = failed_two_node_graph(tmp_path)
    try:
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE failures SET actual_json=? WHERE failure_id=?",
                (
                    stable_json(
                        {
                            "scope_reassessment_required": True,
                            "blocked_allowed_paths": ["src/a/**"],
                            "provider_scope_findings": [
                                {
                                    "code": "SCOPE_INSUFFICIENT",
                                    "severity": "high",
                                    "text": (
                                        "scripts/image_security_verify.py is outside "
                                        "allowed task scope."
                                    ),
                                }
                            ],
                        }
                    ),
                    root_failure_id,
                ),
            )
        root_failure = state.list_failures("product-autonomy")[-1]
        signatures: set[str] = set()
        for index, reason_code in enumerate(
            (
                "mandatory_gate_failed",
                "plan_contract_violation",
                "model_requested_repair",
                "needs_replan",
            )
        ):
            child_id = f"failure-signature-{index}"
            child = {
                **root_failure,
                "failure_id": child_id,
                "parent_failure_id": root_failure_id,
                "reason_code": reason_code,
                "safe_message": f"different wording {index}",
                "failed_gate_ids_json": stable_json(
                    ["target-tests"]
                    if reason_code == "mandatory_gate_failed"
                    else [reason_code]
                ),
                "actual_json": "{}",
            }
            directive = build_scope_recovery_directive(
                config,
                state,
                [root_failure, child],
                product_id="product-autonomy",
                source_failure_id=child_id,
                forbidden_paths=["secrets/**", "production/**"],
            )
            signatures.add(str(directive["root_problem_signature"]))
            assert directive["root_failure_id"] == root_failure_id
            assert directive["required_scope_paths"] == [
                "scripts/image_security_verify.py"
            ]
            assert directive["failed_mandatory_gate_ids"] == [
                "target-tests",
                "target-lint",
            ]
            assert directive["forbidden_paths"] == [
                "secrets/**",
                "production/**",
            ]
        assert len(signatures) == 1
    finally:
        state.close()


def test_recovery_directive_targets_latest_builder_not_historical_root_role(
    tmp_path: Path,
) -> None:
    config, state, _, root_failure_id, _ = failed_two_node_graph(tmp_path)
    child_failure_id = "failure-replanner-child"
    now = "2026-07-31T00:00:00Z"
    try:
        state.add_task(
            task_id="T-REPLANNER-HISTORY",
            product_id="product-autonomy",
            title="Historical replanner failure",
            role="replanner",
            stage_key="diagnosis-reassessment",
            graph_status="FAILED_SEMANTIC",
        )
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE failures SET actual_json=? WHERE failure_id=?",
                (
                    stable_json(
                        {
                            "scope_reassessment_required": True,
                            "blocked_allowed_paths": ["src/a/**", "tests/**"],
                            "scope_required_paths": [
                                "scripts/image_security_verify.py"
                            ],
                        }
                    ),
                    root_failure_id,
                ),
            )
            state._connection.execute(
                """
                INSERT INTO failures
                    (failure_id, product_id, task_id, parent_failure_id,
                     failure_class, reason_code, fingerprint, safe_message,
                     evidence_ref, status, retryable,
                     owner_action_eligible, expected_json, actual_json,
                     failed_gate_ids_json, first_seen_at, last_seen_at)
                VALUES (?, 'product-autonomy', 'T-REPLANNER-HISTORY', ?,
                        'semantic', 'plan_contract_violation', ?,
                        'Historical Replanner retained the old scope.',
                        'internal://replanner-child', 'OPEN', 0, 0,
                        '{}', '{}', '["target-tests"]', ?, ?)
                """,
                (
                    child_failure_id,
                    root_failure_id,
                    sha256_text(child_failure_id),
                    now,
                    now,
                ),
            )
        directive = build_scope_recovery_directive(
            config,
            state,
            state.list_failures("product-autonomy"),
            product_id="product-autonomy",
            source_failure_id=child_failure_id,
            forbidden_paths=["secrets/**"],
        )

        assert directive["affected_semantic_node_keys"] == ["a"]
        assert directive["required_scope_paths"] == [
            "scripts/image_security_verify.py"
        ]
    finally:
        state.close()


def test_plan_contract_descendant_promotes_causal_required_scope_path(
    tmp_path: Path,
) -> None:
    config, state, artifacts, parent_failure_id, _ = failed_two_node_graph(tmp_path)
    child_failure_id = "failure-required-scope-descendant"
    now = "2026-07-31T00:00:00Z"
    try:
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE failures SET actual_json=? WHERE failure_id=?",
                (
                    stable_json(
                        {
                            "scope_reassessment_required": True,
                            "blocked_allowed_paths": ["src/**", "tests/**"],
                            "provider_scope_findings": [
                                {
                                    "code": "SCOPE_INSUFFICIENT",
                                    "severity": "high",
                                    "text": (
                                        "scripts/image_security_verify.py is outside "
                                        "allowed task scope."
                                    ),
                                }
                            ],
                        }
                    ),
                    parent_failure_id,
                ),
            )
            state._connection.execute(
                """
                INSERT INTO failures
                    (failure_id, product_id, task_id, parent_failure_id,
                     failure_class, reason_code, fingerprint, safe_message,
                     evidence_ref, status, retryable,
                     owner_action_eligible, expected_json, actual_json,
                     failed_gate_ids_json, first_seen_at, last_seen_at)
                VALUES (?, 'product-autonomy', 'T-FAILNODEA', ?,
                        'semantic', 'plan_contract_violation', ?,
                        'Fresh plan did not expand its scope.',
                        'internal://required-scope-descendant', 'OPEN', 0, 0,
                        '{}', '{}', '["target-tests"]', ?, ?)
                """,
                (
                    child_failure_id,
                    parent_failure_id,
                    sha256_text(child_failure_id),
                    now,
                    now,
                ),
            )
            state._connection.execute(
                "UPDATE tasks SET failure_id=? WHERE task_id='T-FAILNODEA'",
                (child_failure_id,),
            )

        arbiter_id = FailureRouter(config, state, artifacts).route(child_failure_id)
        routed_id = accept_path_arbiter_and_prepare_replanner(
            config, state, artifacts, arbiter_id
        )

        routed = state.get_task(routed_id)
        assert routed is not None
        contract = json.loads(
            (config.evidence_dir / Path(str(routed["contract_ref"])).name).read_text(
                encoding="utf-8"
            )
        )
        assert routed["role"] == "replanner"
        assert "allowed_paths were too narrow" in contract["objective"]
        assert "scripts/image_security_verify.py" in contract["objective"]
    finally:
        state.close()


def test_legacy_mandatory_gate_repair_without_gate_contract_fails_closed(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(
        tmp_path,
        reason_code="mandatory_gate_failed",
    )
    try:
        repair_id = FailureRouter(config, state, artifacts).route(failure_id)
        repair = state.get_task(repair_id)
        assert repair is not None
        contract_path = config.evidence_dir / Path(str(repair["contract_ref"])).name
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        assert contract["quality_gates"] == ["target-tests", "target-lint"]
        contract.pop("quality_gates")
        contract_path.write_text(
            json.dumps(contract, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        worker = AgentWorker(
            config,
            state,
            health_probe=lambda _: True,
            repository_root=tmp_path,
        )

        with pytest.raises(
            ExternalBlocker,
            match="omits fresh PASS requirements",
        ) as blocked:
            worker.default_spec(repair)

        assert blocked.value.reason_code == "invalid_quality_gate_contract"
    finally:
        state.close()


def test_legacy_readonly_reviewer_repair_requires_director_replan(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(tmp_path)
    try:
        repair_id = FailureRouter(config, state, artifacts).route(failure_id)
        with state._lock, state._connection:
            state._connection.execute(
                """UPDATE tasks
                   SET role='security-reviewer',
                       capability_profile='reviewer_readonly',
                       required_capabilities_json=?
                   WHERE task_id=?""",
                (
                    stable_json(list(CAPABILITY_PROFILES["reviewer_readonly"])),
                    repair_id,
                ),
            )
        repair = state.get_task(repair_id)
        assert repair is not None
        worker = AgentWorker(
            config,
            state,
            health_probe=lambda _: True,
            repository_root=tmp_path,
        )

        with pytest.raises(
            ExternalBlocker,
            match="Director replan is required",
        ) as blocked:
            worker.default_spec(repair)

        assert blocked.value.reason_code == "plan_contract_violation"
    finally:
        state.close()


def test_AUT_P0_005_failure_router_replays_partial_artifacts_idempotently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(tmp_path)
    router = FailureRouter(config, state, artifacts)
    original_add_task = state.add_task
    interrupted = True

    def interrupt_once(**values: Any) -> bool:
        nonlocal interrupted
        if interrupted:
            interrupted = False
            raise RuntimeError("injected failure after immutable route artifacts")
        return original_add_task(**values)

    try:
        monkeypatch.setattr(state, "add_task", interrupt_once)
        with pytest.raises(
            RuntimeError,
            match="injected failure after immutable route artifacts",
        ):
            router.route(failure_id)
        task_artifacts = sorted(config.evidence_dir.glob("task-T-*.json"))
        repair_artifacts = sorted(config.evidence_dir.glob("repair-brief-T-*.json"))
        monkeypatch.setattr(state, "add_task", original_add_task)

        repair_task_id = router.route(failure_id)

        assert state.get_task(repair_task_id) is not None
        assert sorted(config.evidence_dir.glob("task-T-*.json")) == task_artifacts
        assert sorted(config.evidence_dir.glob("repair-brief-T-*.json")) == repair_artifacts
    finally:
        state.close()


def test_AUT_P0_006_failed_dependency_routes_and_unblocks_after_repair(
    tmp_path: Path,
) -> None:
    config, state, artifacts, _, _ = failed_two_node_graph(tmp_path)
    try:
        assert state.runnable_tasks("product-autonomy") == []
        reconciled = PipelineReconciler(config, state, artifacts).reconcile_once()
        assert reconciled.repaired + reconciled.replanned + reconciled.incidents == 1
        assert state.has_bounded_progress_path("product-autonomy")
        repair = next(
            task
            for task in state.list_tasks("product-autonomy")
            if task["supersedes_task_id"] == "T-FAILNODEA"
        )
        sibling_failure_id = "failure-sibling-output"
        now = "2026-07-30T00:00:00Z"
        with state._lock, state._connection:
            state._connection.execute(
                """INSERT INTO failures
                   (failure_id, product_id, task_id, failure_class,
                    reason_code, fingerprint, safe_message, evidence_ref,
                    status, retryable, owner_action_eligible, expected_json,
                    actual_json, failed_gate_ids_json, first_seen_at,
                    last_seen_at)
                   VALUES (?, 'product-autonomy', 'T-FAILNODEA', 'semantic',
                           'schema_validation', ?, 'safe sibling failure',
                           'internal://sibling-failure', 'OPEN', 0, 0,
                           '{}', '{}', '[]', ?, ?)""",
                (
                    sibling_failure_id,
                    sha256_text(sibling_failure_id),
                    now,
                    now,
                ),
            )
        redundant_repair_id = "T-REDUNDANT-SIBLING-REPAIR"
        state.add_task(
            task_id=redundant_repair_id,
            product_id="product-autonomy",
            title="Repair a sibling failure for the same task",
            role=str(repair["role"]),
            output_schema=str(repair["output_schema"]),
            contract_ref=f"evidence/task-{redundant_repair_id}.json",
            stage_key="repair",
            root_task_id=str(repair["root_task_id"]),
            parent_task_id="T-FAILNODEA",
            source_task_id="T-FAILNODEA",
            plan_id=str(repair["plan_id"]),
            plan_node_id=f"{repair['plan_node_id']}-sibling",
            root_context_ref=str(repair["root_context_ref"]),
            active_context_ref=str(repair["active_context_ref"]),
            failure_id=sibling_failure_id,
            supersedes_task_id="T-FAILNODEA",
            graph_status="READY",
        )
        claimed = state.claim_task(worker_id="repair-worker")
        assert claimed is not None
        assert claimed["task_id"] == repair["task_id"]
        state.commit_task_outcome(
            TaskOutcome(
                task_id=str(repair["task_id"]),
                worker_id="repair-worker",
                lease_token=str(claimed["lease_token"]),
                expected_task_revision=int(repair["task_revision"]),
                expected_plan_revision=1,
                idempotency_key=sha256_text("accepted-repair"),
                result_ref="internal://accepted-repair",
                result_digest=sha256_text("accepted-repair"),
                status="ACCEPTED",
            )
        )
        assert state.get_task("T-FAILNODEA")["graph_status"] == "SUPERSEDED"
        assert state.get_task("T-FAILNODEB")["graph_status"] == "READY"
        sibling_failure = state._connection.execute(
            "SELECT status FROM failures WHERE failure_id=?",
            (sibling_failure_id,),
        ).fetchone()
        assert sibling_failure is not None
        assert sibling_failure["status"] == "RESOLVED"
        redundant_repair = state.get_task(redundant_repair_id)
        assert redundant_repair is not None
        assert redundant_repair["graph_status"] == "SUPERSEDED"
        assert redundant_repair["terminal_reason"] == "redundant_repair_suppressed"
        assert any(
            event["event_type"] == "redundant_repair_work_suppressed"
            for event in state.events("product-autonomy")
        )
    finally:
        state.close()


def test_AUT_P0_006_retryable_in_place_repair_is_not_double_routed(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        state.add_task(
            task_id="T-INPLACE-RETRY",
            product_id="product-autonomy",
            title="Retry schema-invalid planner output in place",
            role="replanner",
            priority=100,
        )
        claimed = state.claim_task(worker_id="planning-worker")
        assert claimed is not None
        assert claimed["task_id"] == "T-INPLACE-RETRY"
        task_id = str(claimed["task_id"])
        committed = state.commit_task_outcome(
            TaskOutcome(
                task_id=task_id,
                worker_id="planning-worker",
                lease_token=str(claimed["lease_token"]),
                expected_task_revision=int(claimed["task_revision"]),
                expected_plan_revision=0,
                idempotency_key=sha256_text("schema-repair-attempt-one"),
                result_ref="evidence/schema-diagnostic.json",
                result_digest=sha256_text("schema-diagnostic"),
                status="WAITING_TIME",
                next_tier="sol",
                next_attempt_kind="repair",
                repair_context_ref="evidence/schema-repair-brief.json",
                failure=FailureData(
                    failure_class="semantic",
                    reason_code="schema_validation",
                    safe_message="Planner output did not match the required schema.",
                    evidence_ref="evidence/schema-diagnostic.json",
                    retryable=True,
                ),
            )
        )
        assert committed.failure_id is not None
        task_count = len(state.list_tasks("product-autonomy"))

        routed = FailureRouter(config, state, ArtifactStore(config)).route_open_failures(
            "product-autonomy"
        )

        assert routed == []
        assert len(state.list_tasks("product-autonomy")) == task_count
        retry = state.get_task(task_id)
        assert retry is not None
        assert retry["graph_status"] == "READY"
        assert retry["next_attempt_kind"] == "repair"
        assert state.list_failures("product-autonomy")[0]["status"] == "OPEN"

        reclaimed = state.claim_task(worker_id="planning-worker")
        assert reclaimed is not None
        assert reclaimed["task_id"] == task_id
        state.commit_task_outcome(
            TaskOutcome(
                task_id=task_id,
                worker_id="planning-worker",
                lease_token=str(reclaimed["lease_token"]),
                expected_task_revision=int(reclaimed["task_revision"]),
                expected_plan_revision=0,
                idempotency_key=sha256_text("schema-repair-attempt-two"),
                result_ref="evidence/valid-plan.json",
                result_digest=sha256_text("valid-plan"),
                status="ACCEPTED",
            )
        )
        assert state.list_failures("product-autonomy")[0]["status"] == "RESOLVED"
    finally:
        state.close()


def test_inflight_outcome_cannot_cancel_a_newer_owner_pause(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        state.add_task(
            task_id="T-INFLIGHT-OWNER-PAUSE",
            product_id="product-autonomy",
            title="Finish work already claimed before an owner pause",
            role="replanner",
            priority=100,
        )
        claimed = state.claim_task(worker_id="inflight-worker")
        assert claimed is not None
        state.transition_product("product-autonomy", "PAUSED")

        state.commit_task_outcome(
            TaskOutcome(
                task_id="T-INFLIGHT-OWNER-PAUSE",
                worker_id="inflight-worker",
                lease_token=str(claimed["lease_token"]),
                expected_task_revision=int(claimed["task_revision"]),
                idempotency_key=sha256_text("inflight-owner-pause"),
                result_ref="evidence/inflight-owner-pause.json",
                result_digest=sha256_text("inflight-owner-pause"),
                status="ACCEPTED",
                product_status="IMPLEMENTING",
            )
        )

        product = state.get_product("product-autonomy")
        assert product is not None
        assert product["status"] == "PAUSED"
        task = state.get_task("T-INFLIGHT-OWNER-PAUSE")
        assert task is not None
        assert task["graph_status"] == "ACCEPTED"
        suppressed = [
            json.loads(str(event["payload_json"]))
            for event in state.events("product-autonomy")
            if event["event_type"] == "product_transition_suppressed"
        ]
        assert suppressed == [
            {
                "current_status": "PAUSED",
                "reason": "newer_owner_or_terminal_state",
                "requested_status": "IMPLEMENTING",
                "task_id": "T-INFLIGHT-OWNER-PAUSE",
            }
        ]
    finally:
        state.close()


def test_AUT_P0_006_only_causal_leaf_failure_creates_recovery_work(
    tmp_path: Path,
) -> None:
    config, state, artifacts, parent_failure_id, _ = failed_two_node_graph(tmp_path)
    child_failure_id = "failure-causal-leaf"
    now = "2026-07-29T00:00:01Z"
    try:
        with state._lock, state._connection:
            state._connection.execute(
                """
                INSERT INTO failures
                    (failure_id, product_id, task_id, parent_failure_id,
                     failure_class, reason_code, fingerprint, safe_message,
                     evidence_ref, status, retryable,
                     owner_action_eligible, expected_json, actual_json,
                     failed_gate_ids_json, first_seen_at, last_seen_at)
                VALUES (?, 'product-autonomy', 'T-FAILNODEA', ?,
                        'semantic', 'needs_replan', ?,
                        'The terminal repair needs a new executable plan.',
                        'internal://causal-leaf', 'OPEN', 0, 0,
                        '{}', '{}', '[]', ?, ?)
                """,
                (
                    child_failure_id,
                    parent_failure_id,
                    sha256_text(child_failure_id),
                    now,
                    now,
                ),
            )
            state._connection.execute(
                "UPDATE tasks SET failure_id=? WHERE task_id='T-FAILNODEA'",
                (child_failure_id,),
            )

        routed = FailureRouter(
            config,
            state,
            artifacts,
        ).route_open_failures("product-autonomy")

        assert len(routed) == 1
        recovery = state.get_task(routed[0])
        assert recovery is not None
        assert recovery["failure_id"] == child_failure_id
        assert recovery["role"] == "path-arbiter"
        failures = {
            failure["failure_id"]: failure["status"]
            for failure in state.list_failures("product-autonomy")
        }
        assert failures[parent_failure_id] == "OPEN"
        assert failures[child_failure_id] == "ROUTED"
        assert (
            len(
                [
                    task
                    for task in state.list_tasks("product-autonomy")
                    if task["failure_id"] in {parent_failure_id, child_failure_id}
                    and task["graph_status"] in {"READY", "CLAIMED"}
                ]
            )
            == 1
        )
    finally:
        state.close()


def test_AUT_P0_006_missing_plan_output_schema_routes_replanner(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(tmp_path)
    missing_schema = "recovery-test-validation-v2.schema.json"
    try:
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE tasks SET output_schema=? WHERE task_id='T-FAILNODEA'",
                (missing_schema,),
            )
            state._connection.execute(
                """
                UPDATE failures
                   SET failure_class='controller',
                       reason_code='controller_exception_file_not_found_error',
                       safe_message=?
                 WHERE failure_id=?
                """,
                (
                    f"/opt/hermes-factory/current/schemas/{missing_schema}",
                    failure_id,
                ),
            )
            state._connection.execute(
                """
                INSERT INTO controller_incidents
                    (incident_id, product_id, task_id, reason_code,
                     evidence_ref, status, created_at)
                VALUES ('incident-missing-plan-schema', 'product-autonomy',
                        'T-FAILNODEA',
                        'controller_exception_file_not_found_error',
                        'internal://missing-plan-schema', 'OPEN',
                        '2026-07-29T00:00:00Z')
                """
            )

        routed_id = FailureRouter(config, state, artifacts).route(failure_id)

        routed = state.get_task(routed_id)
        assert routed is not None
        assert routed["role"] == "replanner"
        assert routed["output_schema"] == "plan-proposal-v1.schema.json"
        assert routed["graph_status"] == "READY"
        incident = state._connection.execute(
            "SELECT status, resolved_at FROM controller_incidents WHERE product_id=?",
            ("product-autonomy",),
        ).fetchone()
        assert incident is not None
        assert incident["status"] == "RESOLVED"
        assert incident["resolved_at"]
    finally:
        state.close()


def test_AUT_P0_006_legacy_contract_ref_uses_canonical_evidence_coordinate(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(
        tmp_path,
        reason_code="needs_replan",
    )
    try:
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE tasks SET contract_ref=? WHERE task_id='T-FAILNODEA'",
                ("artifacts/task-contracts/T-FAILNODEA.json",),
            )

        arbiter_id = FailureRouter(config, state, artifacts).route(failure_id)
        routed_id = accept_path_arbiter_and_prepare_replanner(
            config, state, artifacts, arbiter_id
        )

        routed = state.get_task(routed_id)
        assert routed is not None
        assert routed["role"] == "replanner"
        reconstructed = [
            event
            for event in state.events("product-autonomy")
            if event["event_type"] == "task_contract_reconstructed"
        ]
        assert reconstructed == []
    finally:
        state.close()


def test_AUT_P0_006_missing_contract_reconstructs_safe_replan_coordinate(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(
        tmp_path,
        reason_code="needs_replan",
    )
    try:
        (config.evidence_dir / "task-T-FAILNODEA.json").unlink()
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE tasks SET contract_ref=? WHERE task_id='T-FAILNODEA'",
                ("artifacts/task-contracts/missing.json",),
            )

        arbiter_id = FailureRouter(config, state, artifacts).route(failure_id)
        routed_id = accept_path_arbiter_and_prepare_replanner(
            config, state, artifacts, arbiter_id
        )

        routed = state.get_task(routed_id)
        assert routed is not None
        assert routed["role"] == "replanner"
        routed_contract = json.loads(
            (config.evidence_dir / Path(str(routed["contract_ref"])).name).read_text(
                encoding="utf-8"
            )
        )
        assert routed_contract["allowed_paths"] == ["artifacts/**"]
        assert {item["criterion_id"] for item in routed_contract["acceptance"]} == {
            "AC-REPLAN-FAILURE-CHAIN",
            "AC-REPLAN-EXECUTABLE-HANDOFF",
            "AC-REPLAN-PRESERVE-ACCEPTED",
            "AC-REPLAN-SEMANTIC-ONLY",
        }
        incident = state._connection.execute(
            """
            SELECT reason_code, status, evidence_ref
              FROM controller_incidents
             WHERE product_id=?
               AND reason_code='artifact_task_contract_reconstructed'
            """,
            ("product-autonomy",),
        ).fetchone()
        assert incident is not None
        assert incident["status"] == "RESOLVED"
        assert str(incident["evidence_ref"]).startswith("state://task-contract/")
    finally:
        state.close()


def test_replanner_uses_planning_acceptance_not_failed_security_acceptance(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, root_id = failed_two_node_graph(
        tmp_path,
        reason_code="needs_replan",
    )
    failed_contract_path = config.evidence_dir / "task-T-FAILNODEA.json"
    failed_product_criterion = "No blocking security finding remains."
    try:
        failed_contract = json.loads(failed_contract_path.read_text(encoding="utf-8"))
        failed_contract["role"] = "security-reviewer"
        failed_contract["acceptance"] = [
            {
                "criterion_id": "AC-SECURITY-NO-BLOCKER",
                "verification": failed_product_criterion,
                "mandatory": True,
            }
        ]
        failed_contract_path.write_text(
            stable_json(failed_contract),
            encoding="utf-8",
        )
        with state._lock, state._connection:
            state._connection.execute(
                """
                UPDATE tasks
                   SET role='security-reviewer'
                 WHERE task_id='T-FAILNODEA'
                """
            )
            state._connection.execute(
                """
                UPDATE failures
                   SET expected_json=?,
                       failed_gate_ids_json=?
                 WHERE failure_id=?
                """,
                (
                    stable_json(
                        {
                            "acceptance": [
                                "AC-SECURITY-NO-BLOCKER",
                            ]
                        }
                    ),
                    stable_json(
                        [
                            "target-dependency-audit",
                            "target-license-check",
                        ]
                    ),
                    failure_id,
                ),
            )

        arbiter_id = FailureRouter(config, state, artifacts).route(failure_id)
        routed_id = accept_path_arbiter_and_prepare_replanner(
            config, state, artifacts, arbiter_id
        )

        routed = state.get_task(routed_id)
        assert routed is not None
        assert routed["role"] == "replanner"
        assert routed["parent_task_id"] == arbiter_id
        assert routed["source_task_id"] == arbiter_id
        assert routed["root_task_id"] == root_id
        assert routed["failure_id"] == failure_id
        assert routed["root_context_ref"] == ("evidence/intake-product-autonomy.json")
        routed_contract = json.loads(
            (config.evidence_dir / Path(str(routed["contract_ref"])).name).read_text(
                encoding="utf-8"
            )
        )
        criterion_ids = {str(item["criterion_id"]) for item in routed_contract["acceptance"]}
        assert criterion_ids == {
            "AC-REPLAN-FAILURE-CHAIN",
            "AC-REPLAN-EXECUTABLE-HANDOFF",
            "AC-REPLAN-PRESERVE-ACCEPTED",
            "AC-REPLAN-SEMANTIC-ONLY",
        }
        assert failed_product_criterion not in stable_json(routed_contract["acceptance"])
        assert (
            "failed acceptance criteria and mandatory gate IDs"
            in (routed_contract["acceptance"][0]["verification"])
        )
    finally:
        state.close()


def test_AUT_P0_006_one_product_reconcile_failure_does_not_stop_another(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = configured(tmp_path)
    state = StateStore(
        config.database_path,
        max_active_products=2,
    )
    try:
        create_v2_product(state, product_id="product-isolated-a")
        create_v2_product(state, product_id="product-progress-b")
        reconciler = PipelineReconciler(
            config,
            state,
            ArtifactStore(config),
        )
        seen: list[str] = []

        def isolate_first(product: dict[str, Any]) -> str:
            product_id = str(product["product_id"])
            seen.append(product_id)
            if product_id == "product-isolated-a":
                raise RuntimeError("sanitized injected reconcile failure")
            return "active"

        monkeypatch.setattr(
            reconciler,
            "reconcile_product",
            isolate_first,
        )
        result = reconciler.reconcile_once()

        assert seen == ["product-isolated-a", "product-progress-b"]
        assert result.inspected == 2
        assert result.incidents == 1
        incident = state._connection.execute(
            """
            SELECT status, evidence_ref
              FROM controller_incidents
             WHERE product_id='product-isolated-a'
               AND reason_code='controller_product_reconcile_isolated'
            """
        ).fetchone()
        assert incident is not None
        assert incident["status"] == "OPEN"
        assert str(incident["evidence_ref"]).startswith("state://product-reconcile/")

        monkeypatch.setattr(
            reconciler,
            "reconcile_product",
            lambda _product: "active",
        )
        reconciler.reconcile_once()
        resolved = state._connection.execute(
            """
            SELECT status, resolved_at
              FROM controller_incidents
             WHERE product_id='product-isolated-a'
               AND reason_code='controller_product_reconcile_isolated'
            """
        ).fetchone()
        assert resolved is not None
        assert resolved["status"] == "RESOLVED"
        assert resolved["resolved_at"]
    finally:
        state.close()


def test_AUT_P0_010_localized_repair_brief_keeps_exact_cause_and_scope(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(tmp_path)
    try:
        repair_id = FailureRouter(config, state, artifacts).route(failure_id)
        repair = state.get_task(repair_id)
        assert repair is not None
        brief = json.loads(
            (config.evidence_dir / Path(str(repair["repair_context_ref"])).name).read_text(
                encoding="utf-8"
            )
        )
        assert brief["failed_task_id"] == "T-FAILNODEA"
        assert brief["failure_id"] == failure_id
        assert brief["hypothesis_id"] == repair["hypothesis_id"]
        assert brief["inherited_goal_ref"] == repair["root_context_ref"]
        assert brief["allowed_paths"] == ["src/a/**"]
        assert "target-tests" in brief["failed_gate_ids"]
        assert any("transaction boundary" in fix for fix in brief["required_fixes"])
        assert (
            ArtifactStore(config).validate(
                "repair-brief-v2.schema.json",
                brief,
            )
            == []
        )
    finally:
        state.close()


def test_AUT_P0_010_repair_brief_maps_non_gate_failure_to_safe_reason_code(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(tmp_path)
    try:
        with state._lock, state._connection:
            state._connection.execute(
                """
                UPDATE failures
                   SET reason_code='scope_violation',
                       failed_gate_ids_json='[]',
                       actual_json=?
                 WHERE failure_id=?
                """,
                (
                    json.dumps(
                        {"required_fixes": ["Restrict changes to the task allowlisted paths."]}
                    ),
                    failure_id,
                ),
            )

        repair_id = FailureRouter(config, state, artifacts).route(failure_id)
        repair = state.get_task(repair_id)
        assert repair is not None
        brief = json.loads(
            (config.evidence_dir / Path(str(repair["repair_context_ref"])).name).read_text(
                encoding="utf-8"
            )
        )
        assert brief["failed_gate_ids"] == ["scope_violation"]
        assert "Restrict changes to the task allowlisted paths." in brief["required_fixes"]
        assert (
            ArtifactStore(config).validate(
                "repair-brief-v2.schema.json",
                brief,
            )
            == []
        )
    finally:
        state.close()


def test_AUT_P0_011_needs_replan_activates_real_plan_revision(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, root_id = failed_two_node_graph(
        tmp_path,
        reason_code="needs_replan",
    )
    try:
        result = PipelineReconciler(config, state, artifacts).reconcile_once()
        assert result.replanned == 1
        arbiter = next(
            task
            for task in state.list_tasks("product-autonomy")
            if task["role"] == "path-arbiter"
        )
        accept_path_arbiter_and_prepare_replanner(
            config, state, artifacts, str(arbiter["task_id"])
        )
        replanner = next(
            task for task in state.list_tasks("product-autonomy") if task["role"] == "replanner"
        )
        assert replanner["capability_profile"] == "planning_readonly"
        claimed = state.claim_task(worker_id="replanner-worker")
        assert claimed is not None
        assert claimed["task_id"] == replanner["task_id"]
        replacement_plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-FAILURE-2",
            root_task_id=root_id,
            revision=2,
            parent_plan_id="PLAN-FAILURE-1",
            source_failure_id=failure_id,
            node_specs=[
                ("A2", "T-REPLACEMENTA", "accept-a2"),
                ("B2", "T-REPLACEMENTB", "accept-b2"),
            ],
            edges=[("A2", "B2")],
            supersedes={"A2": "T-FAILNODEA"},
        )
        for node in replacement_plan["nodes"]:
            contract = node["task_contract"]
            contract["failure_id"] = failure_id
            contract["hypothesis_id"] = replanner["hypothesis_id"]
            artifacts.write(
                "task-contract-v2.schema.json",
                contract,
                filename=f"task-{contract['task_id']}.json",
            )
            node["task_contract_ref"] = f"evidence/task-{contract['task_id']}.json"
        plan_path = artifacts.write(
            "backlog-plan-v2.schema.json",
            replacement_plan,
            filename="backlog-plan-PLAN-FAILURE-2.json",
        )
        committed_plan = {
            **replacement_plan,
            "plan_artifact_ref": f"evidence/{plan_path.name}",
            "plan_digest": artifacts.digest(replacement_plan),
        }
        state.commit_task_outcome(
            TaskOutcome(
                task_id=str(replanner["task_id"]),
                worker_id="replanner-worker",
                lease_token=str(claimed["lease_token"]),
                expected_task_revision=int(replanner["task_revision"]),
                expected_plan_revision=1,
                idempotency_key=sha256_text("replan-outcome"),
                result_ref=f"evidence/{plan_path.name}",
                result_digest=sha256_file(plan_path),
                status="ACCEPTED",
                plan=committed_plan,
            )
        )
        plans = state.list_plans("product-autonomy")
        assert [(plan["revision"], plan["status"]) for plan in plans][-2:] == [
            (1, "SUPERSEDED"),
            (2, "ACTIVE"),
        ]
        assert state.get_task("T-REPLACEMENTA")["graph_status"] == "READY"
        assert all(
            task["graph_status"] != "READY"
            for task in state.list_tasks("product-autonomy")
            if task["plan_id"] == "PLAN-FAILURE-1"
        )
        replacement_edges = state.list_edges("PLAN-FAILURE-2")
        assert any(
            edge["edge_type"] == "supersedes"
            and edge["from_task_id"] == "T-FAILNODEA"
            and edge["to_task_id"] == "T-REPLACEMENTA"
            for edge in replacement_edges
        )
    finally:
        state.close()


def test_AUT_P0_012_hypothesis_budget_exhaustion_changes_hypothesis(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(tmp_path)
    try:
        router = FailureRouter(config, state, artifacts)
        initial_task_id = router.route(failure_id)
        failed = state.get_task("T-FAILNODEA")
        assert failed is not None
        old_hypothesis_id = str(failed["hypothesis_id"])
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE tasks SET status='DONE', graph_status='SUPERSEDED' WHERE task_id=?",
                (initial_task_id,),
            )
            state._connection.execute(
                "UPDATE hypotheses SET attempts_used=3 WHERE hypothesis_id=?",
                (old_hypothesis_id,),
            )
            state._connection.execute(
                "UPDATE failures SET status='OPEN' WHERE failure_id=?",
                (failure_id,),
            )
        arbiter_id = router.route(failure_id)
        reassessment_task_id = accept_path_arbiter_and_prepare_replanner(
            config, state, artifacts, arbiter_id
        )
        reassessment = state.get_task(reassessment_task_id)
        assert reassessment is not None
        assert reassessment["role"] == "replanner"
        hypotheses = state.list_hypotheses("product-autonomy")
        exhausted = next(item for item in hypotheses if item["hypothesis_id"] == old_hypothesis_id)
        replacement = next(
            item
            for item in hypotheses
            if item["parent_hypothesis_id"] == old_hypothesis_id
        )
        assert exhausted["status"] == "EXHAUSTED"
        assert replacement["status"] == "RESOLVED"
        assert replacement["signature"] != exhausted["signature"]
        assert reassessment["hypothesis_id"] == replacement["hypothesis_id"]
    finally:
        state.close()


def test_diagnosis_reassessment_uses_one_arbiter_then_fails_safe(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(tmp_path)
    try:
        router = FailureRouter(config, state, artifacts)
        initial_repair_id = router.route(failure_id)
        failed = state.get_task("T-FAILNODEA")
        assert failed is not None
        old_hypothesis_id = str(failed["hypothesis_id"])
        with state._lock, state._connection:
            state._connection.execute(
                """UPDATE tasks SET status='DONE', graph_status='SUPERSEDED'
                   WHERE task_id=?""",
                (initial_repair_id,),
            )
            state._connection.execute(
                "UPDATE hypotheses SET attempts_used=3 WHERE hypothesis_id=?",
                (old_hypothesis_id,),
            )
            state._connection.execute(
                "UPDATE failures SET status='OPEN' WHERE failure_id=?",
                (failure_id,),
            )
        diagnosis_task_id = router.route(failure_id)
        diagnosis = state.get_task(diagnosis_task_id)
        assert diagnosis is not None
        diagnosis_hypothesis_id = str(diagnosis["hypothesis_id"])
        assert diagnosis["role"] == "path-arbiter"
        assert diagnosis["stage_key"] == "path-arbiter"
        claimed = state.claim_task(worker_id="diagnosis-worker")
        assert claimed is not None and claimed["task_id"] == diagnosis_task_id
        committed = state.commit_task_outcome(
            TaskOutcome(
                task_id=diagnosis_task_id,
                worker_id="diagnosis-worker",
                lease_token=str(claimed["lease_token"]),
                expected_task_revision=int(claimed["task_revision"]),
                expected_plan_revision=1,
                idempotency_key=sha256_text("diagnosis-arbiter-failed"),
                result_ref="evidence/diagnosis-arbiter-failed.json",
                result_digest=sha256_text("diagnosis-arbiter-failed"),
                status="FAILED_SEMANTIC",
                failure=FailureData(
                    failure_class="semantic",
                    reason_code="needs_replan",
                    safe_message="The one-shot arbiter found no safe bounded path.",
                    evidence_ref="evidence/diagnosis-arbiter-failed.json",
                    parent_failure_id=failure_id,
                    failed_gate_ids=("target-tests",),
                ),
            )
        )
        assert committed.failure_id is not None
        tasks_before = len(state.list_tasks("product-autonomy"))
        assert router.route(committed.failure_id) == diagnosis_task_id
        assert len(state.list_tasks("product-autonomy")) == tasks_before
        assert state.get_product("product-autonomy")["status"] == "FAILED_SAFE"
        exhausted = next(
            item
            for item in state.list_hypotheses("product-autonomy")
            if item["hypothesis_id"] == diagnosis_hypothesis_id
        )
        assert exhausted["status"] == "EXHAUSTED"
    finally:
        state.close()


def test_AUT_P0_031_third_identical_same_role_failure_opens_replan_circuit(
    tmp_path: Path,
) -> None:
    config, state, artifacts, failure_id, _ = failed_two_node_graph(tmp_path)
    try:
        router = FailureRouter(config, state, artifacts)
        repair_id = router.route(failure_id)
        repair = state.claim_task(worker_id="repair-worker")
        assert repair is not None
        assert repair["task_id"] == repair_id
        original = next(
            item
            for item in state.list_failures("product-autonomy")
            if item["failure_id"] == failure_id
        )
        failed_gates = tuple(json.loads(original["failed_gate_ids_json"]))
        committed = state.commit_task_outcome(
            TaskOutcome(
                task_id=repair_id,
                worker_id="repair-worker",
                lease_token=str(repair["lease_token"]),
                expected_task_revision=int(repair["task_revision"]),
                expected_plan_revision=1,
                idempotency_key=sha256_text("second-identical-problem"),
                result_ref="internal://second-identical-problem",
                result_digest=sha256_text("second-identical-problem"),
                status="FAILED_SEMANTIC",
                failure=FailureData(
                    failure_class=str(original["failure_class"]),
                    reason_code=str(original["reason_code"]),
                    safe_message=str(original["safe_message"]),
                    evidence_ref="internal://second-identical-problem",
                    parent_failure_id=failure_id,
                    expected=json.loads(original["expected_json"]),
                    actual=json.loads(original["actual_json"]),
                    failed_gate_ids=failed_gates,
                ),
            )
        )
        assert committed.failure_id is not None
        second_repair_id = router.route(committed.failure_id)
        second_repair = state.get_task(second_repair_id)
        assert second_repair is not None
        assert second_repair["role"] == "builder"
        claimed_second = state.claim_task(worker_id="second-repair-worker")
        assert claimed_second is not None
        assert claimed_second["task_id"] == second_repair_id
        committed_second = state.commit_task_outcome(
            TaskOutcome(
                task_id=second_repair_id,
                worker_id="second-repair-worker",
                lease_token=str(claimed_second["lease_token"]),
                expected_task_revision=int(claimed_second["task_revision"]),
                expected_plan_revision=1,
                idempotency_key=sha256_text("third-identical-problem"),
                result_ref="internal://third-identical-problem",
                result_digest=sha256_text("third-identical-problem"),
                status="FAILED_SEMANTIC",
                failure=FailureData(
                    failure_class=str(original["failure_class"]),
                    reason_code=str(original["reason_code"]),
                    safe_message=str(original["safe_message"]),
                    evidence_ref="internal://third-identical-problem",
                    parent_failure_id=committed.failure_id,
                    expected=json.loads(original["expected_json"]),
                    actual=json.loads(original["actual_json"]),
                    failed_gate_ids=failed_gates,
                ),
            )
        )
        assert committed_second.failure_id is not None
        routed_id = router.route(committed_second.failure_id)
        routed = state.get_task(routed_id)
        assert routed is not None
        assert routed["role"] == "path-arbiter"
        assert routed["output_schema"] == "path-decision-proposal.schema.json"
        assert not any(
            task["role"] == "builder"
            and task["graph_status"] == "READY"
            and task["task_id"] not in {repair_id, second_repair_id}
            for task in state.list_tasks("product-autonomy")
        )
        events = [
            json.loads(event["payload_json"])
            for event in state.events("product-autonomy")
            if event["event_type"] == "failure_routed" and event["task_id"] == routed_id
        ]
        assert events[-1]["same_role_problem_count"] == 3
    finally:
        state.close()


def test_AUT_P0_013_context_pack_has_bounded_safe_file_excerpts(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    repository = tmp_path / "repository"
    repository.mkdir()
    token = "ghp_" + "B" * 24
    (repository / "large.py").write_text(
        f"token = '{token}'\n" + ("print('bounded')\n" * 500),
        encoding="utf-8",
    )
    (repository / "binary.bin").write_bytes(b"\x00\x01\x02secret")
    result = ContextBuilder(config, repository).build(
        product_id="context-product",
        task_id="T-CONTEXT001",
        subject_sha="c" * 64,
        objective="Inspect only bounded repository evidence",
        acceptance=["No secret crosses the planning boundary"],
        candidates=[
            ("large.py", "implementation evidence"),
            ("binary.bin", "binary metadata"),
        ],
        allowed_paths=["src/**"],
        forbidden_actions=["secret.read", "repository.write"],
        output_schema="backlog-plan-v2.schema.json",
        root_goal="Create a verified service without exposing credentials",
        root_task_id="T-CONTEXT001",
        plan_summary={"plan_id": "PLAN-CONTEXT", "revision": 1},
        capability_contract={
            "profile": "builder_workspace",
            "required": ["toolchain.container_builder"],
            "missing": [],
            "available": [
                {
                    "capability": "toolchain.container_builder",
                    "provider": "controller-toolchain",
                    "scope": {"runtime": "podman"},
                }
            ],
        },
        max_chars=800,
    )
    excerpts = {item["path"]: item for item in result.artifact["file_excerpts"]}
    assert excerpts["large.py"]["truncated"] is True
    assert token not in excerpts["large.py"]["content"]
    assert excerpts["large.py"]["redactions"][0]["location"].startswith("line ")
    assert excerpts["binary.bin"]["binary"] is True
    assert excerpts["binary.bin"]["content"] == ""
    assert result.artifact["capability_contract"]["available"][0]["scope"] == {"runtime": "podman"}
    assert (
        ArtifactStore(config).validate(
            "context-pack-v2.schema.json",
            result.artifact,
        )
        == []
    )


def test_replanner_context_preserves_exact_structural_coordinates_under_budget(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    repository = tmp_path / "repository"
    repository.mkdir()
    policy = "a" * 64
    result_digest = "b" * 64
    plan_summary = {
        "plan_id": "PLAN-STRUCTURAL-CONTEXT",
        "revision": 40,
        "status": "ACTIVE",
        "policy_digest": policy,
        "accepted_unaffected_node_keys": ["runtime-service-foundation"],
        "implementation_nodes": [
            {
                "node_key": "dependency-audit-runtime-inventory",
                "task_id": "T-STRUCTURAL-CONTEXT",
                "role": "builder",
                "capability_profile": "builder_workspace",
                "required_capabilities": ["toolchain.container_builder"],
                "allowed_paths": ["pyproject.toml", "scripts/dependency_audit.py"],
                "quality_gates": ["target-dependency-audit"],
                "objective": "bounded objective " * 500,
                "accepted_result": {
                    "result_ref": "evidence/result-structural-context.json",
                    "result_digest": result_digest,
                    "summary": "bounded accepted result " * 500,
                },
            }
        ],
        "unresolved_failure_inventory": [
            {
                "failure_id": "failure-structural-context",
                "reason_code": "target_dependency_audit_failed",
                "scope_required_paths": [
                    "scripts/image_security_verify.py",
                ],
                "safe_message": "bounded failure diagnostic " * 500,
            }
        ],
    }

    result = ContextBuilder(config, repository).build(
        product_id="context-product",
        task_id="T-STRUCTURAL-CONTEXT",
        subject_sha="c" * 64,
        objective="Repair the exact unresolved dependency audit coordinate",
        acceptance=["Return a schema-valid replan delta"],
        candidates=[],
        allowed_paths=["**"],
        forbidden_actions=["secret.read"],
        output_schema="backlog-plan-v2.schema.json",
        plan_summary=plan_summary,
        max_plan_summary_chars=512,
    )

    bounded = result.artifact["plan_summary"]
    node = bounded["implementation_nodes"][0]
    failure = bounded["unresolved_failure_inventory"][0]
    assert bounded["policy_digest"] == policy
    assert bounded["plan_id"] == "PLAN-STRUCTURAL-CONTEXT"
    assert bounded["accepted_unaffected_node_keys"] == ["runtime-service-foundation"]
    assert node["node_key"] == "dependency-audit-runtime-inventory"
    assert node["task_id"] == "T-STRUCTURAL-CONTEXT"
    assert node["capability_profile"] == "builder_workspace"
    assert node["required_capabilities"] == ["toolchain.container_builder"]
    assert node["allowed_paths"] == [
        "pyproject.toml",
        "scripts/dependency_audit.py",
    ]
    assert node["quality_gates"] == ["target-dependency-audit"]
    assert node["accepted_result"]["result_ref"] == ("evidence/result-structural-context.json")
    assert node["accepted_result"]["result_digest"] == result_digest
    assert failure["failure_id"] == "failure-structural-context"
    assert failure["reason_code"] == "target_dependency_audit_failed"
    assert failure["scope_required_paths"] == ["scripts/image_security_verify.py"]
    assert len(node["objective"]) < len(plan_summary["implementation_nodes"][0]["objective"])
    assert len(node["accepted_result"]["summary"]) < len(
        plan_summary["implementation_nodes"][0]["accepted_result"]["summary"]
    )
    assert len(failure["safe_message"]) < len(
        plan_summary["unresolved_failure_inventory"][0]["safe_message"]
    )
    assert (
        ArtifactStore(config).validate(
            "context-pack-v2.schema.json",
            result.artifact,
        )
        == []
    )


@pytest.mark.parametrize(
    "reason_code",
    [
        "plan_contract_violation",
        "missing_declared_predecessor",
        "evidence_profile_mismatch",
        "completion_unreachable",
    ],
)
def test_transport_diagnostic_accepts_plan_contract_reason_codes(
    tmp_path: Path,
    reason_code: str,
) -> None:
    config = configured(tmp_path)
    diagnostic = {
        "schema_version": "1.0",
        "artifact_id": "transport-diagnostic-test",
        "product_id": "context-product",
        "task_id": "T-TRANSPORT-CONTRACT",
        "attempt_id": "attempt-transport-contract",
        "reason_code": reason_code,
        "raw_sha256": "d" * 64,
        "raw_chars": 42,
        "safe_head": "safe coordinate",
        "safe_tail": "safe coordinate",
        "parser_error_type": "PlanContractViolation",
        "parser_error_safe_message": "safe plan contract coordinate",
        "redactions": [],
        "provider": "openai-codex",
        "model": "gpt-5.6-luna",
        "context_ref": "evidence/context-T-TRANSPORT-CONTRACT.json",
        "usage_ref": None,
    }

    assert (
        ArtifactStore(config).validate(
            "transport-diagnostic.schema.json",
            diagnostic,
        )
        == []
    )


def test_plan_contract_repair_findings_preserve_each_failed_gate_id() -> None:
    error = PlanContractViolation(
        "fresh implementation slices omitted two release gates",
        failed_gate_ids=(
            "RELEASE-EVIDENCE-SUBJECT-MISMATCH",
            "RELEASE-PREREQUISITES-MISSING",
        ),
    )

    findings = _plan_contract_repair_findings(error, str(error))

    assert [item["id"] for item in findings] == [
        "RELEASE-EVIDENCE-SUBJECT-MISMATCH",
        "RELEASE-PREREQUISITES-MISSING",
    ]
    assert all(item["id"] in item["required_fix"] for item in findings)


def test_plan_contract_repair_finding_prioritizes_exact_required_path() -> None:
    error = PlanContractViolation(
        "fresh implementation slices do not cover required scope paths: "
        "scripts/image_security_verify.py",
        failed_gate_ids=("target-tests", "target-lint"),
    )

    findings = _plan_contract_repair_findings(error, str(error))

    assert findings == [
        {
            "id": "REQUIRED-REPLAN-SCOPE-PATHS",
            "severity": "high",
            "description": (
                "fresh implementation slices do not cover required scope paths: "
                "scripts/image_security_verify.py"
            ),
            "required_fix": (
                "Add every exact controller-owned repository path named in "
                "the validator diagnostic to a fresh implementation slice "
                "scope while preserving mandatory gates and forbidden paths."
            ),
        }
    ]


def test_available_capability_inventory_selects_specific_runtime_scope(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        state.grant_capability(
            capability="toolchain.container_builder",
            provider="controller-toolchain",
            scope={"runtime": "docker"},
        )
        state.grant_capability(
            product_id="product-autonomy",
            capability="toolchain.container_builder",
            provider="controller-toolchain",
            scope={"runtime": "podman"},
        )

        available = state.available_capabilities(
            "product-autonomy",
            "T-CONTEXT001",
            ["toolchain.container_builder", "toolchain.python"],
        )

        assert available == [
            {
                "capability": "toolchain.container_builder",
                "provider": "controller-toolchain",
                "scope": {"runtime": "podman"},
            }
        ]
    finally:
        state.close()


def test_AUT_P0_014_capability_preflight_controls_ready_frontier(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        root_id = "T-ROOTCAPABILITY"
        state.add_task(
            task_id=root_id,
            product_id="product-autonomy",
            title="Capability planner",
        )
        product = state.get_product("product-autonomy")
        assert product is not None
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-CAPABILITY-1",
            root_task_id=root_id,
            parent_plan_id=str(product["active_plan_id"]),
            node_specs=[("release-staging", "T-RELEASECAP", "accept-release")],
            edges=[],
        )
        contract = plan["nodes"][0]["task_contract"]
        contract["role"] = "release-operator"
        contract["output_schema"] = "release-operation-result.schema.json"
        contract["capability_profile"] = "release_staging"
        contract["required_capabilities"] = list(CAPABILITY_PROFILES["release_staging"])
        for capability in CAPABILITY_PROFILES["release_staging"]:
            if capability == "github.pull_request.create":
                continue
            state.grant_capability(
                product_id="product-autonomy",
                task_id=None,
                capability=capability,
                provider="fake-controller",
                scope={"repository": "brullik/durable-task-service"},
                status="AVAILABLE",
            )
        persist_and_ingest_plan(
            config,
            state,
            plan,
            created_by_task_id=root_id,
        )
        assert state.get_task("T-RELEASECAP")["graph_status"] == "BLOCKED_CAPABILITY"
        assert state.claim_task(worker_id="worker") is None
        state.grant_capability(
            product_id="product-autonomy",
            task_id=None,
            capability="github.pull_request.create",
            provider="fake-github",
            scope={"repository": "brullik/durable-task-service"},
            status="AVAILABLE",
        )
        assert state.get_task("T-RELEASECAP")["graph_status"] == "READY"
        assert state.claim_task(worker_id="worker")["task_id"] == "T-RELEASECAP"
    finally:
        state.close()


class InternalGapProbe:
    def check(
        self,
        capability: str,
        *,
        product: dict[str, Any],
    ) -> CapabilityCheck:
        del product
        return CapabilityCheck(
            capability=capability,
            status="DENIED_POLICY",
            provider="fake-host",
            reason_code="controller_adapter_unconfigured",
        )


def test_AUT_P0_015_routine_technical_gaps_never_require_owner(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        checks = CapabilityBroker(
            config,
            state,
            probe=InternalGapProbe(),
        ).preflight_product("product-autonomy")
        assert checks
        events = state.events("product-autonomy")
        assert not any(event["event_type"] == "owner_action_required" for event in events)
        incidents = state._connection.execute(
            "SELECT * FROM controller_incidents WHERE product_id=?",
            ("product-autonomy",),
        ).fetchall()
        assert incidents
    finally:
        state.close()


def test_AUT_P0_016_observation_is_atomic_with_production_release(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    artifacts = ArtifactStore(config)
    try:
        create_v2_product(state)
        root_id = "T-ROOTRELEASE"
        state.add_task(
            task_id=root_id,
            product_id="product-autonomy",
            title="Release planner",
        )
        product = state.get_product("product-autonomy")
        assert product is not None
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-RELEASE-1",
            root_task_id=root_id,
            parent_plan_id=str(product["active_plan_id"]),
            node_specs=[
                (
                    "release-production",
                    "T-PRODUCTION01",
                    "accept-production",
                )
            ],
            edges=[],
        )
        contract = plan["nodes"][0]["task_contract"]
        contract["role"] = "release-operator"
        contract["output_schema"] = "release-operation-result.schema.json"
        contract["capability_profile"] = "release_production"
        contract["required_capabilities"] = list(CAPABILITY_PROFILES["release_production"])
        for capability in CAPABILITY_PROFILES["release_production"]:
            state.grant_capability(
                product_id="product-autonomy",
                task_id=None,
                capability=capability,
                provider="fake-controller",
                scope={"repository": "brullik/durable-task-service"},
                status="AVAILABLE",
            )
        persist_and_ingest_plan(
            config,
            state,
            plan,
            created_by_task_id=root_id,
        )
        claimed = state.claim_task(worker_id="release-worker")
        assert claimed is not None
        release_digest = "sha256:" + "d" * 64
        output = {
            "status": "completed",
            "release": {"image_digest": release_digest},
        }
        task = state.get_task("T-PRODUCTION01")
        assert task is not None
        prepared = PipelineCoordinator(
            config,
            state,
            artifacts,
        ).prepare_after(task, output, tmp_path / "release-result.json")
        outcome = TaskOutcome(
            task_id="T-PRODUCTION01",
            worker_id="release-worker",
            lease_token=str(claimed["lease_token"]),
            expected_plan_revision=1,
            idempotency_key=sha256_text("production-release-outcome"),
            result_ref="internal://production-release",
            result_digest=sha256_text("production-release"),
            status="ACCEPTED",
            product_status=prepared.product_status,
            successors=prepared.successors,
            edges=prepared.edges,
        )

        def crash(point: str) -> None:
            if point == "after_successor_write":
                raise RuntimeError(point)

        with pytest.raises(RuntimeError, match="after_successor_write"):
            state.commit_task_outcome(outcome, fault_injector=crash)
        assert not any(
            task["stage_key"] == "observation" for task in state.list_tasks("product-autonomy")
        )
        state.commit_task_outcome(outcome)
        observations = [
            task
            for task in state.list_tasks("product-autonomy")
            if task["stage_key"] == "observation"
        ]
        assert len(observations) == 1
        observation = observations[0]
        assert observation["graph_status"] == "WAITING_TIME"
        assert observation["required_predecessor_digest"] == release_digest
        edges = state.list_edges("PLAN-RELEASE-1")
        assert any(
            edge["from_task_id"] == "T-PRODUCTION01"
            and edge["to_task_id"] == observation["task_id"]
            for edge in edges
        )
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE tasks SET available_at='2000-01-01T00:00:00Z' WHERE task_id=?",
                (observation["task_id"],),
            )
        next_task = state.claim_task(worker_id="observer")
        assert next_task is not None
        assert next_task["task_id"] == observation["task_id"]
    finally:
        state.close()


def test_AUT_P0_017_completion_reducer_requires_all_evidence_and_is_idempotent(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    artifacts = ArtifactStore(config)
    try:
        create_v2_product(state)
        root_id = "T-ROOTCOMPLETE"
        state.add_task(
            task_id=root_id,
            product_id="product-autonomy",
            title="Completion planner",
        )
        product = state.get_product("product-autonomy")
        assert product is not None
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-COMPLETE-1",
            root_task_id=root_id,
            parent_plan_id=str(product["active_plan_id"]),
            node_specs=[("observation", "T-OBSERVATION1", "accept-observation")],
            edges=[],
        )
        persist_and_ingest_plan(
            config,
            state,
            plan,
            created_by_task_id=root_id,
        )
        claimed = state.claim_task(worker_id="observer")
        assert claimed is not None
        state.commit_task_outcome(
            TaskOutcome(
                task_id="T-OBSERVATION1",
                worker_id="observer",
                lease_token=str(claimed["lease_token"]),
                expected_plan_revision=1,
                idempotency_key=sha256_text("observation-accepted"),
                result_ref="internal://observation-result",
                result_digest=sha256_text("observation-result"),
                status="ACCEPTED",
            )
        )
        incomplete = state.reduce_completion(
            "product-autonomy",
            artifacts=artifacts,
        )
        assert not incomplete.completed
        assert any(
            condition.startswith("goal_without_pass_evidence")
            for condition in incomplete.unmet_conditions
        )
        release_digest = "e" * 64
        state.record_product_evidence(
            product_id="product-autonomy",
            evidence_type="goal",
            goal_id="root-goal",
            artifact_ref="internal://goal-proof",
            artifact_digest=sha256_text("goal-proof"),
        )
        for evidence_type in (
            "independent_review",
            "required_checks",
            "staging",
            "product_acceptance",
            "production",
            "rollback",
            "observation",
        ):
            state.record_product_evidence(
                product_id="product-autonomy",
                evidence_type=evidence_type,
                artifact_ref=f"internal://{evidence_type}",
                artifact_digest=(
                    release_digest
                    if evidence_type in {"staging", "production"}
                    else sha256_text(evidence_type)
                ),
            )
        with state._lock, state._connection:
            state._connection.execute(
                """
                INSERT INTO controller_incidents
                    (incident_id, product_id, task_id, reason_code,
                     evidence_ref, status, created_at)
                VALUES ('incident-completion-open', 'product-autonomy',
                        'T-OBSERVATION1', 'controller_completion_guard',
                        'internal://completion-guard', 'OPEN',
                        '2026-07-29T00:00:00Z')
                """
            )
        blocked_by_incident = state.reduce_completion(
            "product-autonomy",
            artifacts=artifacts,
        )
        assert not blocked_by_incident.completed
        assert (
            "open_controller_incident:incident-completion-open"
            in blocked_by_incident.unmet_conditions
        )
        with state._lock, state._connection:
            state._connection.execute(
                """
                UPDATE controller_incidents
                   SET status='RESOLVED', resolved_at='2026-07-29T00:01:00Z'
                 WHERE incident_id='incident-completion-open'
                """
            )
        completed = state.reduce_completion(
            "product-autonomy",
            artifacts=artifacts,
        )
        assert completed.completed
        assert completed.completion_evidence_ref is not None
        completion_path = config.evidence_dir / Path(completed.completion_evidence_ref).name
        completion = json.loads(completion_path.read_text(encoding="utf-8"))
        assert (
            artifacts.validate(
                "completion-evidence.schema.json",
                completion,
            )
            == []
        )
        replay = state.reduce_completion(
            "product-autonomy",
            artifacts=artifacts,
        )
        assert replay == completed
        completion_outbox = [
            row for row in state.list_outbox() if row["event_type"] == "product_completed"
        ]
        assert len(completion_outbox) == 1
    finally:
        state.close()


def test_AUT_P0_018_restart_and_lease_loss_preserve_graph_lineage(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    create_v2_product(state)
    root_id = "T-ROOTRESTART"
    state.add_task(
        task_id=root_id,
        product_id="product-autonomy",
        title="Restart planner",
    )
    product = state.get_product("product-autonomy")
    assert product is not None
    plan = executable_plan(
        config,
        product_id="product-autonomy",
        plan_id="PLAN-RESTART-1",
        root_task_id=root_id,
        parent_plan_id=str(product["active_plan_id"]),
        node_specs=[
            ("A", "T-RESTARTA1", "accept-a"),
            ("B", "T-RESTARTB1", "accept-b"),
        ],
        edges=[("A", "B")],
    )
    persist_and_ingest_plan(
        config,
        state,
        plan,
        created_by_task_id=root_id,
    )
    first = state.claim_task(worker_id="lost-worker", lease_seconds=1)
    assert first is not None
    lineage_before = tuple(
        first[key]
        for key in (
            "root_task_id",
            "parent_task_id",
            "source_task_id",
            "plan_id",
            "plan_node_id",
        )
    )
    with state._lock, state._connection:
        state._connection.execute(
            "UPDATE tasks SET lease_until='2000-01-01T00:00:00Z' WHERE task_id=?",
            (first["task_id"],),
        )
    state.close()
    restarted = StateStore(config.database_path)
    try:
        assert restarted.recover_expired_leases() == 1
        reclaimed = restarted.claim_task(worker_id="recovery-worker")
        assert reclaimed is not None
        lineage_after = tuple(
            reclaimed[key]
            for key in (
                "root_task_id",
                "parent_task_id",
                "source_task_id",
                "plan_id",
                "plan_node_id",
            )
        )
        assert lineage_after == lineage_before
        assert restarted.get_task("T-RESTARTB1")["graph_status"] == "BLOCKED_DEPENDENCY"
    finally:
        restarted.close()


def test_AUT_P0_019_legacy_migration_preserves_rows_and_builds_graph(
    tmp_path: Path,
) -> None:
    database = build_fixture(tmp_path / "legacy_2_0_19.db")
    state = StateStore(database)
    try:
        product = state.get_product("legacy-product")
        assert product is not None
        assert product["goal_text"] == "Build a sanitized legacy service"
        assert product["active_plan_revision"] == 0
        predecessor = state.get_task("legacy-predecessor")
        active = state.get_task("legacy-active-repair")
        assert predecessor is not None and active is not None
        assert predecessor["graph_status"] == "ACCEPTED"
        assert active["graph_status"] == "READY"
        assert active["root_task_id"] == predecessor["task_id"]
        assert state.list_edges(str(product["active_plan_id"]))
        assert state.attempts_for_task("legacy-active-repair")
        assert state.events("legacy-product")
        assert state.list_outbox()
        versions = [
            row[0]
            for row in state._connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        ]
        assert versions == [version for version, _, _ in MIGRATIONS]
        assert database.with_suffix(database.suffix + ".pre-autonomy-v2.bak").is_file()
    finally:
        state.close()

    repository_database = build_fixture(tmp_path / "legacy_2_0_19_repository.db")
    connection = sqlite3.connect(repository_database)
    try:
        connection.execute(
            "UPDATE products SET idea=? WHERE product_id='legacy-product'",
            ("https://github.com/example/legacy-product.git",),
        )
        connection.commit()
    finally:
        connection.close()
    repository_state = StateStore(repository_database)
    try:
        product = repository_state.get_product("legacy-product")
        assert product is not None
        assert product["delivery_mode"] == "existing_repository"
        assert product["repository_url"] == ("https://github.com/example/legacy-product")
        assert product["repository_name"] == "legacy-product"
        assert product["goal_text"] != product["idea"]
        plan = repository_state.list_plans("legacy-product")
        assert json.loads(plan[0]["goals_json"])[0]["statement"] == (product["goal_text"])
    finally:
        repository_state.close()


def test_AUT_P0_019_workspace_collision_migration_collapses_incident_tree(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        state.add_task(
            task_id="T-WORKSPACE-COLLISION-A",
            product_id="product-autonomy",
            title="Retry the first workspace collision",
            role="replanner",
            priority=100,
        )
        first_claim = state.claim_task(worker_id="worker-a")
        assert first_claim is not None
        assert first_claim["task_id"] == "T-WORKSPACE-COLLISION-A"
        first = state.commit_task_outcome(
            TaskOutcome(
                task_id="T-WORKSPACE-COLLISION-A",
                worker_id="worker-a",
                lease_token=str(first_claim["lease_token"]),
                expected_plan_revision=0,
                idempotency_key=sha256_text("workspace-collision-a"),
                result_ref="evidence/workspace-collision-a.json",
                result_digest=sha256_text("workspace-collision-a"),
                status="FAILED_SEMANTIC",
                failure=FailureData(
                    failure_class="controller",
                    reason_code="controller_exception_runtime_error",
                    safe_message="workspace already leased by another worker",
                    evidence_ref="evidence/workspace-collision-a.json",
                    exception_type="RuntimeError",
                    stack_fingerprint=sha256_text("workspace-acquire"),
                ),
            )
        )
        assert first.failure_id is not None
        state.add_task(
            task_id="T-WORKSPACE-COLLISION-E",
            product_id="product-autonomy",
            title="A second independent workspace collision",
            role="builder",
            priority=110,
        )
        independent_claim = state.claim_task(worker_id="worker-e")
        assert independent_claim is not None
        assert independent_claim["task_id"] == "T-WORKSPACE-COLLISION-E"
        independent = state.commit_task_outcome(
            TaskOutcome(
                task_id="T-WORKSPACE-COLLISION-E",
                worker_id="worker-e",
                lease_token=str(independent_claim["lease_token"]),
                expected_plan_revision=0,
                idempotency_key=sha256_text("workspace-collision-e"),
                result_ref="evidence/workspace-collision-e.json",
                result_digest=sha256_text("workspace-collision-e"),
                status="FAILED_SEMANTIC",
                failure=FailureData(
                    failure_class="controller",
                    reason_code="controller_exception_runtime_error",
                    safe_message="workspace already leased by another worker",
                    evidence_ref="evidence/workspace-collision-e.json",
                    exception_type="RuntimeError",
                    stack_fingerprint=sha256_text("workspace-acquire"),
                ),
            )
        )
        assert independent.failure_id is not None
        state.add_task(
            task_id="T-WORKSPACE-COLLISION-B",
            product_id="product-autonomy",
            title="Duplicate controller incident",
            role="incident-recovery",
            parent_task_id="T-WORKSPACE-COLLISION-A",
            source_task_id="T-WORKSPACE-COLLISION-A",
            failure_id=first.failure_id,
            priority=100,
        )
        second_claim = state.claim_task(worker_id="worker-b")
        assert second_claim is not None
        assert second_claim["task_id"] == "T-WORKSPACE-COLLISION-B"
        second = state.commit_task_outcome(
            TaskOutcome(
                task_id="T-WORKSPACE-COLLISION-B",
                worker_id="worker-b",
                lease_token=str(second_claim["lease_token"]),
                expected_plan_revision=0,
                idempotency_key=sha256_text("workspace-collision-b"),
                result_ref="evidence/workspace-collision-b.json",
                result_digest=sha256_text("workspace-collision-b"),
                status="FAILED_SEMANTIC",
                failure=FailureData(
                    failure_class="controller",
                    reason_code="controller_exception_runtime_error",
                    safe_message="workspace already leased by another worker",
                    evidence_ref="evidence/workspace-collision-b.json",
                    parent_failure_id=first.failure_id,
                    exception_type="RuntimeError",
                    stack_fingerprint=sha256_text("workspace-acquire"),
                ),
            )
        )
        assert second.failure_id is not None
        state.add_task(
            task_id="T-WORKSPACE-COLLISION-C",
            product_id="product-autonomy",
            title="Redundant collision descendant",
            role="incident-recovery",
            parent_task_id="T-WORKSPACE-COLLISION-B",
            source_task_id="T-WORKSPACE-COLLISION-B",
            failure_id=second.failure_id,
            priority=90,
        )
        state.add_task(
            task_id="T-WORKSPACE-UNRELATED-D",
            product_id="product-autonomy",
            title="Unrelated child sharing only a structural parent",
            role="builder",
            parent_task_id="T-WORKSPACE-COLLISION-A",
            priority=80,
        )
        with state._lock, state._connection:
            for index, (task_id, failure_id) in enumerate(
                (
                    ("T-WORKSPACE-COLLISION-A", first.failure_id),
                    ("T-WORKSPACE-COLLISION-B", second.failure_id),
                    ("T-WORKSPACE-COLLISION-E", independent.failure_id),
                ),
                1,
            ):
                state._connection.execute(
                    """
                    INSERT INTO controller_incidents
                        (incident_id, product_id, task_id, reason_code,
                         evidence_ref, status, created_at)
                    VALUES (?, 'product-autonomy', ?,
                            'controller_exception_runtime_error', ?,
                            'OPEN', '2026-07-29T00:00:00Z')
                    """,
                    (
                        f"incident-workspace-{index}",
                        task_id,
                        f"evidence/{failure_id}.json",
                    ),
                )
                state._connection.execute(
                    "DELETE FROM schema_migrations WHERE version=?",
                    (11,),
                )
    finally:
        state.close()

    restarted = StateStore(config.database_path)
    try:
        survivor = restarted.get_task("T-WORKSPACE-COLLISION-A")
        duplicate = restarted.get_task("T-WORKSPACE-COLLISION-B")
        descendant = restarted.get_task("T-WORKSPACE-COLLISION-C")
        independent = restarted.get_task("T-WORKSPACE-COLLISION-E")
        unrelated = restarted.get_task("T-WORKSPACE-UNRELATED-D")
        assert survivor is not None
        assert duplicate is not None
        assert descendant is not None
        assert independent is not None
        assert unrelated is not None
        assert survivor["graph_status"] == "READY"
        assert survivor["status"] == "PENDING"
        assert survivor["terminal_reason"] is None
        assert independent["graph_status"] == "READY"
        assert independent["status"] == "PENDING"
        assert duplicate["graph_status"] == "SUPERSEDED"
        assert descendant["graph_status"] == "SUPERSEDED"
        assert unrelated["graph_status"] == "READY"
        assert {failure["status"] for failure in restarted.list_failures("product-autonomy")} == {
            "RESOLVED"
        }
        incidents = restarted._connection.execute(
            "SELECT status, resolved_at FROM controller_incidents ORDER BY incident_id"
        ).fetchall()
        assert all(row["status"] == "RESOLVED" and row["resolved_at"] for row in incidents)
        event = next(
            event
            for event in restarted.events("product-autonomy")
            if event["event_type"] == "workspace_collision_recovered"
        )
        payload = json.loads(event["payload_json"])
        assert payload["survivor_task_ids"] == [
            "T-WORKSPACE-COLLISION-A",
            "T-WORKSPACE-COLLISION-E",
        ]
        assert payload["recovered_tasks"] == 2
        assert payload["superseded_tasks"] == 2
        versions = [
            row[0]
            for row in restarted._connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            )
        ]
        assert versions == [version for version, _, _ in MIGRATIONS]
    finally:
        restarted.close()


def test_AUT_P0_019_failure_lineage_migration_closes_proven_ancestors(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    product_id = "product-autonomy"
    now = "2026-07-29T00:00:00Z"
    try:
        create_v2_product(state)
        state.add_task(
            task_id="T-HISTORICAL-FAILED",
            product_id=product_id,
            title="Historical failed controller task",
            graph_status="FAILED_SEMANTIC",
        )
        state.add_task(
            task_id="T-HISTORICAL-RECOVERED",
            product_id=product_id,
            title="Historical accepted recovery",
            role="incident-recovery",
            failure_id="failure-historical-child",
            graph_status="SUPERSEDED",
        )
        with state._lock, state._connection:
            for values in (
                (
                    "failure-historical-parent",
                    "T-HISTORICAL-FAILED",
                    None,
                    "controller",
                    "controller_historical",
                ),
                (
                    "failure-historical-child",
                    "T-HISTORICAL-RECOVERED",
                    "failure-historical-parent",
                    "semantic",
                    "model_requested_repair",
                ),
            ):
                state._connection.execute(
                    """
                    INSERT INTO failures
                        (failure_id, product_id, task_id, parent_failure_id,
                         failure_class, reason_code, fingerprint, safe_message,
                         evidence_ref, status, retryable,
                         owner_action_eligible, expected_json, actual_json,
                         failed_gate_ids_json, first_seen_at, last_seen_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'historical safe diagnostic',
                            'internal://historical', 'ROUTED', 0, 0,
                            '{}', '{}', '[]', ?, ?)
                    """,
                    (
                        values[0],
                        product_id,
                        values[1],
                        values[2],
                        values[3],
                        values[4],
                        sha256_text(str(values)),
                        now,
                        now,
                    ),
                )
            state._connection.execute(
                """
                INSERT INTO controller_incidents
                    (incident_id, product_id, task_id, reason_code,
                     evidence_ref, status, created_at)
                VALUES ('incident-historical', ?, 'T-HISTORICAL-FAILED',
                        'controller_historical', 'internal://historical',
                        'OPEN', ?)
                """,
                (product_id, now),
            )
            state._connection.execute("DELETE FROM schema_migrations WHERE version=6")
    finally:
        state.close()

    restarted = StateStore(config.database_path)
    try:
        assert {failure["status"] for failure in restarted.list_failures(product_id)} == {
            "RESOLVED"
        }
        incident = restarted._connection.execute(
            """
            SELECT status, resolved_at
              FROM controller_incidents
             WHERE incident_id='incident-historical'
            """
        ).fetchone()
        assert incident is not None
        assert incident["status"] == "RESOLVED"
        assert incident["resolved_at"]
    finally:
        restarted.close()


def test_AUT_P0_019_causal_leaf_migration_supersedes_duplicate_recovery(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    product_id = "product-autonomy"
    now = "2026-07-29T00:00:00Z"
    try:
        create_v2_product(state)
        state.add_task(
            task_id="T-CAUSAL-PARENT-RECOVERY",
            product_id=product_id,
            title="Recovery for parent failure",
            role="replanner",
            failure_id="failure-causal-parent",
        )
        state.add_task(
            task_id="T-CAUSAL-LEAF-RECOVERY",
            product_id=product_id,
            title="Recovery for leaf failure",
            role="replanner",
            failure_id="failure-causal-leaf",
        )
        with state._lock, state._connection:
            for values in (
                (
                    "failure-causal-parent",
                    "T-CAUSAL-PARENT-RECOVERY",
                    None,
                ),
                (
                    "failure-causal-leaf",
                    "T-CAUSAL-LEAF-RECOVERY",
                    "failure-causal-parent",
                ),
            ):
                state._connection.execute(
                    """
                    INSERT INTO failures
                        (failure_id, product_id, task_id, parent_failure_id,
                         failure_class, reason_code, fingerprint, safe_message,
                         evidence_ref, status, retryable,
                         owner_action_eligible, expected_json, actual_json,
                         failed_gate_ids_json, first_seen_at, last_seen_at)
                    VALUES (?, ?, ?, ?, 'semantic', 'schema_validation', ?,
                            'safe causal diagnostic', 'internal://causal',
                            'ROUTED', 0, 0, '{}', '{}', '[]', ?, ?)
                    """,
                    (
                        values[0],
                        product_id,
                        values[1],
                        values[2],
                        sha256_text(str(values)),
                        now,
                        now,
                    ),
                )
            state._connection.execute("DELETE FROM schema_migrations WHERE version=7")
    finally:
        state.close()

    restarted = StateStore(config.database_path)
    try:
        parent = restarted.get_task("T-CAUSAL-PARENT-RECOVERY")
        leaf = restarted.get_task("T-CAUSAL-LEAF-RECOVERY")
        assert parent is not None and leaf is not None
        assert parent["graph_status"] == "SUPERSEDED"
        assert parent["blocked_reason"] == "causal_leaf_superseded"
        assert parent["blocked_ref"] == leaf["task_id"]
        assert leaf["graph_status"] == "READY"
        assert {failure["status"] for failure in restarted.list_failures(product_id)} == {"ROUTED"}
        event = next(
            event
            for event in restarted.events(product_id)
            if event["event_type"] == "causal_recovery_deduplicated"
        )
        payload = json.loads(event["payload_json"])
        assert payload["superseded_task_ids"] == ["T-CAUSAL-PARENT-RECOVERY"]
        assert payload["surviving_descendant_task_ids"] == ["T-CAUSAL-LEAF-RECOVERY"]
        versions = [
            int(row[0])
            for row in restarted._connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            )
        ]
        assert versions == [version for version, _, _ in MIGRATIONS]
    finally:
        restarted.close()


def test_AUT_P0_019_invalid_output_schema_migration_reopens_replan(
    tmp_path: Path,
) -> None:
    config, state, _, failure_id, root_id = failed_two_node_graph(tmp_path)
    missing_schema = "recovery-test-validation-v2.schema.json"
    recovery_id = "T-HISTORICAL-SCHEMA-INCIDENT"
    try:
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE tasks SET output_schema=? WHERE task_id='T-FAILNODEA'",
                (missing_schema,),
            )
            state._connection.execute(
                """
                UPDATE failures
                   SET failure_class='controller',
                       reason_code='controller_exception_file_not_found_error',
                       safe_message=?, status='ROUTED'
                 WHERE failure_id=?
                """,
                (
                    f"/opt/hermes-factory/current/schemas/{missing_schema}",
                    failure_id,
                ),
            )
            state._connection.execute(
                """
                INSERT INTO controller_incidents
                    (incident_id, product_id, task_id, reason_code,
                     evidence_ref, status, created_at)
                VALUES ('incident-historical-schema', 'product-autonomy',
                        'T-FAILNODEA',
                        'controller_exception_file_not_found_error',
                        'internal://historical-schema', 'OPEN',
                        '2026-07-29T00:00:00Z')
                """
            )
        state.add_task(
            task_id=recovery_id,
            product_id="product-autonomy",
            title="Historical incident recovery for an invalid plan schema",
            role="incident-recovery",
            output_schema="incident-result.schema.json",
            root_task_id=root_id,
            parent_task_id="T-FAILNODEA",
            source_task_id="T-FAILNODEA",
            failure_id=failure_id,
        )
        with state._lock, state._connection:
            state._connection.execute("DELETE FROM schema_migrations WHERE version IN (8,9)")
    finally:
        state.close()

    restarted = StateStore(config.database_path)
    try:
        failure = next(
            item
            for item in restarted.list_failures("product-autonomy")
            if item["failure_id"] == failure_id
        )
        recovery = restarted.get_task(recovery_id)
        assert failure["status"] == "OPEN"
        assert failure["owner_action_eligible"] == 0
        assert recovery is not None
        assert recovery["graph_status"] == "SUPERSEDED"
        assert recovery["blocked_reason"] == "invalid_output_schema_replan"
        incident = restarted._connection.execute(
            """
            SELECT status, resolved_at
              FROM controller_incidents
             WHERE incident_id='incident-historical-schema'
            """
        ).fetchone()
        assert incident is not None
        assert incident["status"] == "RESOLVED"
        assert incident["resolved_at"]
        assert any(
            event["event_type"] == "invalid_output_schema_replan_required"
            for event in restarted.events("product-autonomy")
        )
        routed_id = FailureRouter(
            config,
            restarted,
            ArtifactStore(config),
        ).route(failure_id)
        routed = restarted.get_task(routed_id)
        assert routed is not None
        assert routed["role"] == "replanner"
    finally:
        restarted.close()


def test_AUT_P0_019_concurrent_start_rechecks_migration_under_writer_lock(
    tmp_path: Path,
) -> None:
    database = tmp_path / "migration-race.db"
    owner = sqlite3.connect(database, timeout=5)
    owner.execute(
        """
        CREATE TABLE schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            checksum TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
        """
    )
    for version, name, _ in MIGRATIONS[:-1]:
        owner.execute(
            """
            INSERT INTO schema_migrations(version, name, checksum, applied_at)
            VALUES (?, ?, ?, '2026-07-29T00:00:00Z')
            """,
            (version, name, sha256_text(f"{version}:{name}")),
        )
    owner.commit()
    owner.execute("BEGIN IMMEDIATE")

    reached_writer_lock = threading.Event()
    errors: list[Exception] = []

    def concurrent_start() -> None:
        contender = sqlite3.connect(database, timeout=5)
        contender.set_trace_callback(
            lambda sql: (
                reached_writer_lock.set() if sql.strip().upper() == "BEGIN IMMEDIATE" else None
            )
        )
        try:
            apply_migrations(contender)
        except (sqlite3.Error, RuntimeError) as error:
            errors.append(error)
        finally:
            contender.close()

    thread = threading.Thread(target=concurrent_start)
    thread.start()
    assert reached_writer_lock.wait(timeout=2)
    version, name, _ = MIGRATIONS[-1]
    owner.execute(
        """
        INSERT INTO schema_migrations(version, name, checksum, applied_at)
        VALUES (?, ?, ?, '2026-07-29T00:00:01Z')
        """,
        (version, name, sha256_text(f"{version}:{name}")),
    )
    owner.commit()
    thread.join(timeout=5)
    owner.close()

    assert not thread.is_alive()
    assert errors == []
    verified = sqlite3.connect(database)
    try:
        versions = [
            int(row[0])
            for row in verified.execute("SELECT version FROM schema_migrations ORDER BY version")
        ]
    finally:
        verified.close()
    assert versions == [version for version, _, _ in MIGRATIONS]


def test_AUT_P0_019_plan_candidate_reports_existing_idempotency_coordinate(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        state.add_task(
            task_id="T-EXISTING-IDENTITY",
            product_id="product-autonomy",
            title="Existing task identity",
            idempotency_key=sha256_text("existing-plan-identity"),
        )
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-IDENTITY-COLLISION",
            root_task_id="T-EXISTING-IDENTITY",
            node_specs=[("A", "T-NEW-IDENTITY", "accept-identity")],
            edges=[],
        )
        plan["nodes"][0]["task_contract"]["idempotency_key"] = sha256_text("existing-plan-identity")

        with pytest.raises(
            ValueError,
            match=(r"nodes\[0\]\.task_contract\.idempotency_key already exists"),
        ):
            state.validate_plan_candidate(plan)

        assert state.list_plans("product-autonomy")[0]["revision"] == 0
        assert state.get_task("T-EXISTING-IDENTITY")["graph_status"] == "READY"
    finally:
        state.close()


def test_AUT_P0_019_plan_candidate_reports_existing_plan_digest_coordinate(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        root_task_id = "T-PLAN-DIGEST-ROOT"
        state.add_task(
            task_id=root_task_id,
            product_id="product-autonomy",
            title="Plan digest identity root",
            role="task-specifier",
        )
        original = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-DIGEST-IDENTITY",
            root_task_id=root_task_id,
            node_specs=[("A", "T-PLAN-DIGEST-OLD", "accept-plan-digest")],
            edges=[],
        )
        persist_and_ingest_plan(
            config,
            state,
            original,
            created_by_task_id=root_task_id,
        )
        plans_before = state.list_plans("product-autonomy")
        existing = next(item for item in plans_before if item["plan_id"] == "PLAN-DIGEST-IDENTITY")
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id=str(existing["plan_id"]),
            root_task_id=root_task_id,
            node_specs=[("A", "T-PLAN-DIGEST-NEW", "accept-plan-digest")],
            edges=[],
        )
        assert str(existing["plan_digest"]) != sha256_text(stable_json(plan))

        with pytest.raises(
            ValueError,
            match=("BacklogPlan plan_id already exists with a different immutable digest"),
        ):
            state.validate_plan_candidate(plan)

        assert state.list_plans("product-autonomy") == plans_before
        assert state.get_task("T-PLAN-DIGEST-NEW") is None
    finally:
        state.close()


def test_AUT_P0_019_plan_candidate_rejects_planning_only_graph(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-PLANNING-ONLY",
            root_task_id="T-PLANNING-ONLY-ROOT",
            node_specs=[("replan", "T-PLANNING-ONLY", "accept-replan")],
            edges=[],
        )
        contract = plan["nodes"][0]["task_contract"]
        contract["role"] = "replanner"
        contract["output_schema"] = "plan-proposal-v1.schema.json"
        contract["capability_profile"] = "planning_readonly"
        contract["required_capabilities"] = [
            "artifact.read",
            "artifact.write",
            "repository.read_bounded",
            "state.read",
            "plan.propose",
        ]

        with pytest.raises(
            ValueError,
            match="BacklogPlan nodes must include a non-planning execution task",
        ):
            state.validate_plan_candidate(plan)
    finally:
        state.close()


def test_AUT_P0_018_unregistered_output_schema_is_rejected(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-UNREGISTERED-SCHEMA",
            root_task_id="T-UNREGISTERED-SCHEMA-ROOT",
            node_specs=[("A", "T-UNREGISTERED-SCHEMA", "accept-schema")],
            edges=[],
        )
        plan["nodes"][0]["task_contract"]["output_schema"] = (
            "recovery-test-validation-v2.schema.json"
        )

        with pytest.raises(
            ValueError,
            match=(
                r"nodes\[0\]\.task_contract\.output_schema "
                r"is not registered: recovery-test-validation-v2\.schema\.json"
            ),
        ):
            state.validate_plan_candidate(plan)

        assert state.get_task("T-UNREGISTERED-SCHEMA") is None
    finally:
        state.close()


def test_AUT_P0_018_registered_but_noncanonical_output_schema_is_rejected(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-WRONG-REGISTERED-SCHEMA",
            root_task_id="T-WRONG-REGISTERED-SCHEMA-ROOT",
            node_specs=[("A", "T-WRONG-REGISTERED-SCHEMA", "accept-schema")],
            edges=[],
        )
        plan["nodes"][0]["task_contract"]["output_schema"] = "test-package-result.schema.json"

        with pytest.raises(
            ValueError,
            match=(
                r"nodes\[0\]\.task_contract\.output_schema must be "
                r"attempt-result\.schema\.json for role builder; "
                r"got test-package-result\.schema\.json"
            ),
        ):
            state.validate_plan_candidate(plan)

        assert state.get_task("T-WRONG-REGISTERED-SCHEMA") is None
    finally:
        state.close()


def test_AUT_P0_018_unregistered_quality_gate_is_rejected_before_plan_ingest(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-UNREGISTERED-QUALITY-GATE",
            root_task_id="T-UNREGISTERED-QUALITY-GATE-ROOT",
            node_specs=[("A", "T-UNREGISTERED-QUALITY-GATE", "accept-quality-gate")],
            edges=[],
        )
        plan["nodes"][0]["task_contract"]["quality_gates"] = ["package_integrity"]

        with pytest.raises(
            ValueError,
            match=(
                r"nodes\[0\]\.task_contract\.quality_gates\[0\] "
                r"is not registered: package_integrity"
            ),
        ):
            state.validate_plan_candidate(plan)

        assert state.get_task("T-UNREGISTERED-QUALITY-GATE") is None
    finally:
        state.close()


def test_AUT_P0_019_exhausted_graph_routes_real_liveness_replan(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        coordinator = PipelineCoordinator(config, state, ArtifactStore(config))
        root_path = coordinator.create_task(
            "product-autonomy",
            "task-specifier",
        )
        root_task_id = str(json.loads(root_path.read_text(encoding="utf-8"))["task_id"])
        with state._lock, state._connection:
            state._connection.execute(
                """
                UPDATE tasks
                   SET status='DONE', graph_status='ACCEPTED'
                 WHERE task_id=?
                """,
                (root_task_id,),
            )
        product = state.get_product("product-autonomy")
        assert product is not None
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-EXHAUSTED-GRAPH",
            root_task_id=root_task_id,
            parent_plan_id=str(product["active_plan_id"]),
            node_specs=[("build", "T-EXHAUSTED-BUILD", "accept-build")],
            edges=[],
        )
        persist_and_ingest_plan(
            config,
            state,
            plan,
            created_by_task_id=root_task_id,
        )
        claimed = state.claim_task(worker_id="liveness-builder")
        assert claimed is not None
        assert claimed["task_id"] == "T-EXHAUSTED-BUILD"
        state.commit_task_outcome(
            TaskOutcome(
                task_id="T-EXHAUSTED-BUILD",
                worker_id="liveness-builder",
                lease_token=str(claimed["lease_token"]),
                expected_task_revision=int(claimed["task_revision"]),
                expected_plan_revision=1,
                idempotency_key=sha256_text("accept-exhausted-build"),
                result_ref="internal://accepted/exhausted-build",
                result_digest=sha256_text("accepted-exhausted-build"),
                status="ACCEPTED",
            )
        )
        assert not state.has_bounded_progress_path("product-autonomy")

        first = PipelineReconciler(config, state).reconcile_once()
        second = PipelineReconciler(config, state).reconcile_once()

        assert first.replanned == 1
        assert second.replanned == 0
        active = [
            task
            for task in state.list_tasks("product-autonomy")
            if task["graph_status"] in {"READY", "CLAIMED"}
        ]
        assert len(active) == 1
        assert active[0]["role"] == "path-arbiter"
        assert active[0]["failure_id"]
        replanner_id = accept_path_arbiter_and_prepare_replanner(
            config,
            state,
            ArtifactStore(config),
            str(active[0]["task_id"]),
        )
        active = [state.get_task(replanner_id)]
        assert active[0] is not None and active[0]["role"] == "replanner"
        current_product = state.get_product("product-autonomy")
        assert current_product is not None
        assert active[0]["plan_id"] == current_product["active_plan_id"]
        claimed_replanner = state.claim_task(worker_id="liveness-replanner")
        assert claimed_replanner is not None
        assert claimed_replanner["task_id"] == active[0]["task_id"]

        stale_plan_id = str(plan["parent_plan_id"])
        with state._lock, state._connection:
            state._connection.execute(
                """
                UPDATE tasks
                   SET plan_id=?, status='PENDING', graph_status='READY',
                       lease_owner=NULL, lease_until=NULL, lease_token=NULL,
                       heartbeat_at=NULL
                 WHERE task_id=?
                """,
                (stale_plan_id, active[0]["task_id"]),
            )
        assert not state.has_bounded_progress_path("product-autonomy")
        third = PipelineReconciler(config, state).reconcile_once()
        fourth = PipelineReconciler(config, state).reconcile_once()
        assert third.replanned == 1
        assert fourth.replanned == 0
        terminal_product = state.get_product("product-autonomy")
        assert terminal_product is not None
        assert terminal_product["status"] == "FAILED_SAFE"
        assert terminal_product["terminal_reason"] == (
            "path_governor_problem_budget_exhausted"
        )
        assert not any(
            task["supersedes_task_id"] == active[0]["task_id"]
            for task in state.list_tasks("product-autonomy")
        )
        failures = state.list_failures("product-autonomy")
        assert len(failures) == 1
        assert failures[0]["reason_code"] == "liveness_invariant_violation"
        assert failures[0]["status"] == "ROUTED"
        incidents = state._connection.execute(
            """
            SELECT reason_code, status
              FROM controller_incidents
             WHERE product_id=?
            """,
            ("product-autonomy",),
        ).fetchall()
        assert [tuple(row) for row in incidents] == [
            ("liveness_invariant_violation", "RESOLVED"),
            ("path_governor_problem_budget_exhausted", "OPEN"),
        ]
    finally:
        state.close()


def test_AUT_P0_020_secret_never_enters_prompt_or_durable_evidence(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    artifacts = ArtifactStore(config)
    secret = "ghp_" + "C" * 24
    try:
        result = IntakeService(config, state, artifacts).submit(
            source="cli",
            owner_id="owner",
            goal_text=f"Build a safe service; accidental sample {secret}",
            delivery_mode="new_repository",
            repository_name="safe-service",
        )
        repository = tmp_path / "secret-repository"
        repository.mkdir()
        (repository / "settings.py").write_text(
            f"TOKEN = '{secret}'\n",
            encoding="utf-8",
        )
        context = ContextBuilder(config, repository, artifacts).build(
            product_id=result.product_id,
            task_id="T-SECRETBOUNDARY",
            subject_sha="f" * 64,
            objective="Inspect configuration without exposing credentials",
            acceptance=["Persist only redacted configuration evidence"],
            candidates=[("settings.py", "configuration")],
            allowed_paths=["settings.py"],
            forbidden_actions=["secret.read"],
            output_schema="attempt-result.schema.json",
        )
        assert secret not in json.dumps(context.artifact)
        assert secret not in config.database_path.read_bytes().decode(
            "utf-8",
            errors="ignore",
        )
        assert all(
            secret not in path.read_text(encoding="utf-8")
            for path in config.evidence_dir.glob("*.json")
        )
    finally:
        state.close()


def _atomic_state(tmp_path: Path) -> tuple[StateStore, dict[str, Any]]:
    state = StateStore(tmp_path / "controller.db")
    create_v2_product(state)
    state.add_task(
        task_id="T-ATOMIC-A",
        product_id="product-autonomy",
        title="Atomic predecessor",
    )
    claimed = state.claim_task(worker_id="worker")
    assert claimed is not None
    return state, claimed


def _outcome(claimed: dict[str, Any]) -> TaskOutcome:
    successor = {
        "task_id": "T-ATOMIC-B",
        "title": "Atomic successor",
        "contract_ref": "evidence/task-T-ATOMIC-B.json",
        "graph_status": "DRAFT",
        "dependencies": ["T-ATOMIC-A"],
    }
    return TaskOutcome(
        task_id="T-ATOMIC-A",
        worker_id="worker",
        lease_token=str(claimed["lease_token"]),
        idempotency_key=sha256_text("atomic-outcome"),
        result_ref="internal://accepted-result",
        result_digest=sha256_text("accepted-result"),
        status="ACCEPTED",
        successors=(successor,),
        edges=(
            {
                "from_task_id": "T-ATOMIC-A",
                "to_task_id": "T-ATOMIC-B",
                "edge_type": "depends_on",
                "required": True,
            },
        ),
    )


@pytest.mark.parametrize(
    "fault_point",
    [
        "before_transaction",
        "after_task_write",
        "after_failure_write",
        "after_successor_write",
        "after_frontier_recompute",
        "after_outbox_write",
        "after_commit_before_return",
    ],
)
def test_AUT_P0_007_atomic_outcome_survives_faults(
    tmp_path: Path,
    fault_point: str,
) -> None:
    state, claimed = _atomic_state(tmp_path)
    outcome = _outcome(claimed)

    def inject(point: str) -> None:
        if point == fault_point:
            raise RuntimeError(point)

    try:
        with pytest.raises(RuntimeError, match=fault_point):
            state.commit_task_outcome(outcome, fault_injector=inject)
    finally:
        state.close()
    restarted = StateStore(tmp_path / "controller.db")
    try:
        predecessor = restarted.get_task("T-ATOMIC-A")
        successor = restarted.get_task("T-ATOMIC-B")
        assert predecessor is not None
        if fault_point == "after_commit_before_return":
            assert predecessor["graph_status"] == "ACCEPTED"
            assert successor is not None
            replay = restarted.commit_task_outcome(outcome)
            assert replay.replayed
        else:
            assert predecessor["graph_status"] == "CLAIMED"
            assert successor is None
    finally:
        restarted.close()


def test_AUT_P0_008_outcome_replay_is_idempotent(tmp_path: Path) -> None:
    state, claimed = _atomic_state(tmp_path)
    try:
        outcome = _outcome(claimed)
        first = state.commit_task_outcome(outcome)
        second = state.commit_task_outcome(outcome)
        assert first.outcome_id == second.outcome_id
        assert second.replayed
        assert len([task for task in state.list_tasks() if task["task_id"] == "T-ATOMIC-B"]) == 1
        conflicting = TaskOutcome(
            **{
                **outcome.__dict__,
                "result_digest": sha256_text("different-result"),
            }
        )
        with pytest.raises(ValueError, match="digest conflict"):
            state.commit_task_outcome(conflicting)
    finally:
        state.close()


def test_AUT_P0_009_safe_internal_diagnostic_is_precise_and_redacted() -> None:
    token = "ghp_" + "A" * 24
    try:
        raise RuntimeError(f"database migration checksum mismatch; credential={token}")
    except RuntimeError as error:
        diagnostic = safe_exception_diagnostic(error)
    assert diagnostic["exception_type"] == "RuntimeError"
    assert "database migration checksum mismatch" in diagnostic["safe_message"]
    assert token not in json.dumps(diagnostic)
    assert len(str(diagnostic["stack_fingerprint"])) == 64


def test_legacy_replanner_scope_contract_gets_one_bounded_correction_then_stops(
    tmp_path: Path,
) -> None:
    """A historical Builder scope must not be inherited forever by Replanner."""

    config, state, artifacts, root_failure_id, _ = failed_two_node_graph(tmp_path)
    router = FailureRouter(config, state, artifacts)
    try:
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE failures SET actual_json=? WHERE failure_id=?",
                (
                    stable_json(
                        {
                            "scope_reassessment_required": True,
                            "blocked_allowed_paths": ["src/**", "tests/**"],
                            "provider_scope_findings": [
                                {
                                    "code": "SCOPE_INSUFFICIENT",
                                    "severity": "high",
                                    "text": (
                                        "scripts/image_security_verify.py is outside "
                                        "allowed task scope."
                                    ),
                                }
                            ],
                        }
                    ),
                    root_failure_id,
                ),
            )

        arbiter_id = router.route(root_failure_id)
        legacy_replanner_id = accept_path_arbiter_and_prepare_replanner(
            config, state, artifacts, arbiter_id
        )
        legacy_replanner = state.get_task(legacy_replanner_id)
        assert legacy_replanner is not None
        legacy_contract_path = (
            config.evidence_dir / Path(str(legacy_replanner["contract_ref"])).name
        )
        legacy_contract = json.loads(legacy_contract_path.read_text(encoding="utf-8"))
        # Reproduce the exact pre-fix production contract.
        legacy_contract["allowed_paths"] = ["src/**", "tests/**"]
        legacy_contract_path.write_text(
            json.dumps(legacy_contract, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )

        claimed = state.claim_task(worker_id="legacy-replanner")
        assert claimed is not None
        assert claimed["task_id"] == legacy_replanner_id
        state.commit_task_outcome(
            TaskOutcome(
                task_id=legacy_replanner_id,
                worker_id="legacy-replanner",
                lease_token=str(claimed["lease_token"]),
                expected_task_revision=int(claimed["task_revision"]),
                expected_plan_revision=1,
                idempotency_key=sha256_text("legacy-replanner-failed"),
                result_ref="internal://legacy-replanner-failed",
                result_digest=sha256_text("legacy-replanner-failed"),
                status="FAILED_SEMANTIC",
                failure=FailureData(
                    failure_class="semantic",
                    reason_code="needs_replan",
                    safe_message=(
                        "Required scripts/image_security_verify.py is outside "
                        "the inherited src/** and tests/** planning scope."
                    ),
                    evidence_ref="internal://legacy-replanner-failed",
                    parent_failure_id=root_failure_id,
                    failed_gate_ids=("needs_replan",),
                ),
            )
        )
        legacy_failure_id = str(state.get_task(legacy_replanner_id)["failure_id"])

        correction_id = router.route(legacy_failure_id)
        correction = state.get_task(correction_id)
        assert correction is not None
        assert correction["role"] == "replanner"
        assert correction["stage_key"] == "scope-contract-correction"
        correction_contract = json.loads(
            (
                config.evidence_dir / Path(str(correction["contract_ref"])).name
            ).read_text(encoding="utf-8")
        )
        assert correction_contract["allowed_paths"] == ["artifacts/**"]
        assert correction_contract["model_floor"] == "sol"
        assert "typed replan scope policy" in correction_contract["objective"]

        # The initial Sol arbitration and one deterministic contract correction
        # consume the complete non-execution budget for this structural cause.
        # A repeated correction failure terminates without another LLM task.
        claimed = state.claim_task(worker_id="scope-correction")
        assert claimed is not None and claimed["task_id"] == correction_id
        state.commit_task_outcome(
            TaskOutcome(
                task_id=correction_id,
                worker_id="scope-correction",
                lease_token=str(claimed["lease_token"]),
                expected_task_revision=int(claimed["task_revision"]),
                expected_plan_revision=1,
                idempotency_key=sha256_text("scope-correction-failed"),
                result_ref="internal://scope-correction-failed",
                result_digest=sha256_text("scope-correction-failed"),
                status="FAILED_SEMANTIC",
                failure=FailureData(
                    failure_class="semantic",
                    reason_code="needs_replan",
                    safe_message="The same required scope path remains unhandled.",
                    evidence_ref="internal://scope-correction-failed",
                    parent_failure_id=legacy_failure_id,
                    failed_gate_ids=("needs_replan",),
                ),
            )
        )
        correction_failure_id = str(state.get_task(correction_id)["failure_id"])
        tasks_before = len(state.list_tasks("product-autonomy"))

        terminal_task_id = router.route(correction_failure_id)

        assert terminal_task_id == correction_id
        assert len(state.list_tasks("product-autonomy")) == tasks_before
        product = state.get_product("product-autonomy")
        assert product is not None
        assert product["status"] == "FAILED_SAFE"
        assert product["terminal_reason"] == "path_governor_problem_budget_exhausted"
        budget = state._connection.execute(
            """SELECT deterministic_actions_used, arbiter_calls_used,
                      execution_attempts_used, status
                 FROM problem_budgets WHERE product_id=?""",
            ("product-autonomy",),
        ).fetchone()
        assert budget is not None
        assert tuple(budget) == (1, 1, 0, "EXHAUSTED")
        incident = state._connection.execute(
            """SELECT reason_code, status FROM controller_incidents
               WHERE product_id=? ORDER BY created_at DESC LIMIT 1""",
            ("product-autonomy",),
        ).fetchone()
        assert incident is not None
        assert incident["reason_code"] == "path_governor_problem_budget_exhausted"
        assert incident["status"] == "OPEN"
    finally:
        state.close()
