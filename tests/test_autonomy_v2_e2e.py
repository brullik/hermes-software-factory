from __future__ import annotations

import inspect
import json
import subprocess
import threading
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml
from test_autonomy_v2 import (
    FakePrivateRepositoryAdapter,
    FakeRepositoryAdapter,
    accept_path_arbiter_and_prepare_replanner,
    create_v2_product,
    executable_plan,
    persist_and_ingest_plan,
)
from test_worker import (
    make_config,
    product_contract,
    requirements_package,
    selected_registry,
)

from factory.artifacts import ArtifactStore, artifact_metadata
from factory.autonomy import (
    CAPABILITY_PROFILES,
    FailureData,
    HypothesisData,
    TaskOutcome,
)
from factory.capabilities import (
    CapabilityBroker,
    CapabilityCheck,
    CapabilityReconciler,
    ConfiguredCapabilityProbe,
    ProbeCommandResult,
)
from factory.common import sha256_text
from factory.failure_router import FailureRouter
from factory.gateway import TelegramGateway
from factory.intake import IntakeService
from factory.reconciler import PipelineReconciler
from factory.repository import RepositoryBootstrapper
from factory.state import StateStore
from factory.worker import AgentWorker, HermesRunResult, WorkerResult
from factory.workflow import WorkflowEngine


def configured(tmp_path: Path):
    return make_config(
        tmp_path,
        selected_registry(
            tmp_path / "registry.yaml",
            selected="gpt-5.6-luna",
        ),
    )


def plan_revision(
    state: StateStore,
    product_id: str,
    plan_id: str,
) -> int:
    return next(
        int(plan["revision"])
        for plan in state.list_plans(product_id)
        if str(plan["plan_id"]) == plan_id
    )


def accept_next(
    state: StateStore,
    *,
    worker_id: str,
    expected_task_id: str | None = None,
) -> dict[str, Any]:
    claimed = state.claim_task(worker_id=worker_id)
    assert claimed is not None
    if expected_task_id is not None:
        assert claimed["task_id"] == expected_task_id
    task_id = str(claimed["task_id"])
    result_digest = sha256_text(f"accepted:{task_id}")
    state.commit_task_outcome(
        TaskOutcome(
            task_id=task_id,
            worker_id=worker_id,
            lease_token=str(claimed["lease_token"]),
            expected_task_revision=int(claimed["task_revision"]),
            expected_plan_revision=plan_revision(
                state,
                str(claimed["product_id"]),
                str(claimed["plan_id"]),
            ),
            idempotency_key=sha256_text(f"accept-outcome:{task_id}"),
            result_ref=f"internal://accepted/{task_id}",
            result_digest=result_digest,
            status="ACCEPTED",
        )
    )
    accepted = state.get_task(task_id)
    assert accepted is not None
    return accepted


def write_plan_for_outcome(
    config,
    plan: dict[str, Any],
) -> dict[str, Any]:
    artifacts = ArtifactStore(config)
    for node in plan["nodes"]:
        contract = node["task_contract"]
        path = artifacts.write(
            "task-contract-v2.schema.json",
            contract,
            filename=f"task-{contract['task_id']}.json",
        )
        node["task_contract_ref"] = f"evidence/{path.name}"
    plan_path = artifacts.write(
        "backlog-plan-v2.schema.json",
        plan,
        filename=f"backlog-plan-{plan['plan_id']}.json",
    )
    enriched = dict(plan)
    enriched["plan_artifact_ref"] = f"evidence/{plan_path.name}"
    enriched["plan_digest"] = artifacts.digest(plan)
    return enriched


def bind_test_supersession_identities(
    state: StateStore,
    plan: dict[str, Any],
) -> None:
    """Make fixture replacements name the exact source semantic contract."""

    for node in plan["nodes"]:
        contract = node["task_contract"]
        source_id = contract.get("supersedes_task_id")
        if not source_id:
            continue
        source = state.get_task(str(source_id))
        assert source is not None
        contract["semantic_node_key"] = str(
            source.get("semantic_node_key") or source.get("semantic_node_id")
        )
        for field in ("lifecycle_stage", "review_kind", "evidence_profile"):
            value = source.get(field)
            if value is None or value == "":
                contract.pop(field, None)
            else:
                contract[field] = value


def record_completion_evidence(
    state: StateStore,
    *,
    product_id: str,
    release_digest: str,
) -> None:
    state.record_product_evidence(
        product_id=product_id,
        evidence_type="goal",
        goal_id="root-goal",
        artifact_ref="internal://goal/root-goal",
        artifact_digest=sha256_text(f"{product_id}:root-goal"),
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
            product_id=product_id,
            evidence_type=evidence_type,
            artifact_ref=f"internal://{evidence_type}/{release_digest[:12]}",
            artifact_digest=(
                release_digest
                if evidence_type in {"staging", "production"}
                else sha256_text(f"{product_id}:{evidence_type}")
            ),
        )


class IdempotentSideEffects:
    """Deterministic GitHub/deployment double keyed by immutable identity."""

    def __init__(self) -> None:
        self.results: dict[tuple[str, str], str] = {}
        self.calls: list[tuple[str, str]] = []

    def execute(self, operation: str, identity: str) -> str:
        key = (operation, identity)
        if key not in self.results:
            self.calls.append(key)
            self.results[key] = sha256_text(f"{operation}:{identity}")
        return self.results[key]


def test_AUT_P0_021_new_repository_full_e2e_without_owner(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    effects = IdempotentSideEffects()
    repository = FakeRepositoryAdapter()
    product_id = "new-product-e2e"
    try:
        create_v2_product(state, product_id=product_id)
        workspace = tmp_path / "new-product-workspace"
        RepositoryBootstrapper(config, state, repository).ensure(
            product_id,
            workspace,
        )
        root_id = "T-NEWROOT001"
        state.add_task(
            task_id=root_id,
            product_id=product_id,
            title="Create complete executable product plan",
            role="task-specifier",
        )
        product = state.get_product(product_id)
        assert product is not None
        specs = [
            ("functional", "T-NEWFUNC001", "accept-functional"),
            ("persistence", "T-NEWPERS001", "accept-persistence"),
            ("quality", "T-NEWQUAL001", "accept-quality"),
            ("review", "T-NEWREVW001", "accept-review"),
            ("operations", "T-NEWOPER001", "accept-operations"),
            ("observation", "T-NEWOBSV001", "accept-observation"),
        ]
        plan = executable_plan(
            config,
            product_id=product_id,
            plan_id="PLAN-NEW-E2E-1",
            root_task_id=root_id,
            parent_plan_id=str(product["active_plan_id"]),
            node_specs=specs,
            edges=[
                ("functional", "persistence"),
                ("persistence", "quality"),
                ("quality", "review"),
                ("review", "operations"),
                ("operations", "observation"),
            ],
        )
        persist_and_ingest_plan(
            config,
            state,
            plan,
            created_by_task_id=root_id,
        )
        accept_next(
            state,
            worker_id="e2e-new-1",
            expected_task_id="T-NEWFUNC001",
        )
        accept_next(
            state,
            worker_id="e2e-new-2",
            expected_task_id="T-NEWPERS001",
        )
    finally:
        state.close()

    # Mid-flow restart is part of the acceptance contract.
    state = StateStore(config.database_path)
    try:
        for index, task_id in enumerate(
            (
                "T-NEWQUAL001",
                "T-NEWREVW001",
                "T-NEWOPER001",
                "T-NEWOBSV001",
            ),
            start=3,
        ):
            accept_next(
                state,
                worker_id=f"e2e-new-{index}",
                expected_task_id=task_id,
            )
        candidate = effects.execute("pull_request", "PLAN-NEW-E2E-1")
        effects.execute("required_checks", candidate)
        release_digest = effects.execute("staging", candidate)
        effects.execute("production", release_digest)
        effects.execute("observation", release_digest)
        record_completion_evidence(
            state,
            product_id=product_id,
            release_digest=release_digest,
        )
        decision = state.reduce_completion(
            product_id,
            artifacts=ArtifactStore(config),
        )
        assert decision.completed
        assert len(
            [
                call
                for call in repository.calls
                if call[0] == "create"
            ]
        ) == 1
        assert all(
            task["graph_status"] in {"ACCEPTED", "SUPERSEDED"}
            for task in state.list_tasks(product_id)
            if task["plan_id"] == "PLAN-NEW-E2E-1"
        )
        assert not any(
            row["event_type"] == "owner_notification"
            for row in state.list_outbox()
        )
        assert list(config.evidence_dir.glob("owner-action-*.json")) == []
        product = state.get_product(product_id)
        assert product is not None
        assert product["status"] == "COMPLETED"
        assert product["repository_url"].endswith("durable-task-service")
        assert product["completion_evidence_ref"]
    finally:
        state.close()

    verified = StateStore(config.database_path)
    try:
        assert verified.get_product(product_id)["status"] == "COMPLETED"
        assert len(effects.calls) == 5
    finally:
        verified.close()


def test_AUT_P0_022_private_repository_repair_replan_full_e2e(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    product_id = "private-repair-replan-e2e"
    credential = "github_pat_" + "Z" * 24
    try:
        state.create_product_v2(
            product_id=product_id,
            owner_id="owner",
            source="cli",
            goal_text=(
                "Repair, replan, release, and observe the private service "
                "without owner intervention"
            ),
            delivery_mode="existing_repository",
            repository_url="https://github.com/brullik/private-repair-service",
            repository_name=None,
            repository_visibility="private",
            root_goal_ref=f"evidence/intake-{product_id}.json",
            constraints_ref=None,
            owner_defaults_ref=None,
            idempotency_key=sha256_text(product_id),
            rate_limit=None,
        )
        private_adapter = FakePrivateRepositoryAdapter(credential)
        RepositoryBootstrapper(config, state, private_adapter).ensure(
            product_id,
            tmp_path / "private-workspace",
        )
        for status in ("RISK_CLASSIFIED", "ARCHITECTED", "IMPLEMENTING"):
            state.transition_product(product_id, status)
        root_id = "T-PRIVROOT01"
        state.add_task(
            task_id=root_id,
            product_id=product_id,
            title="Plan private repository repair and release",
            role="task-specifier",
        )
        product = state.get_product(product_id)
        assert product is not None
        plan1 = executable_plan(
            config,
            product_id=product_id,
            plan_id="PLAN-PRIVATE-E2E-1",
            root_task_id=root_id,
            parent_plan_id=str(product["active_plan_id"]),
            node_specs=[
                ("A", "T-PRIVA001", "accept-a"),
                ("B", "T-PRIVB001", "accept-b"),
                ("C", "T-PRIVC001", "accept-c"),
            ],
            edges=[("A", "B"), ("B", "C")],
        )
        persist_and_ingest_plan(
            config,
            state,
            plan1,
            created_by_task_id=root_id,
        )
        transient = state.claim_task(worker_id="private-transient")
        assert transient is not None
        state.commit_task_outcome(
            TaskOutcome(
                task_id=str(transient["task_id"]),
                worker_id="private-transient",
                lease_token=str(transient["lease_token"]),
                expected_plan_revision=1,
                idempotency_key=sha256_text("private-transient"),
                result_ref="internal://transport/network-timeout",
                result_digest=sha256_text("private-transient"),
                status="WAITING_TIME",
                available_at="9999-12-31T23:59:59Z",
                next_tier="luna",
                next_attempt_kind="transient_retry",
                repair_context_ref="internal://repair-context/network-timeout",
                failure=FailureData(
                    failure_class="transient",
                    reason_code="network_timeout",
                    safe_message="Provider response timed out without semantic evidence",
                    evidence_ref="internal://transport/network-timeout",
                    retryable=True,
                ),
            )
        )
    finally:
        state.close()

    state = StateStore(config.database_path)
    try:
        assert state.claim_task(worker_id="too-early") is None
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE tasks SET available_at='2000-01-01T00:00:00Z' "
                "WHERE task_id='T-PRIVA001'",
            )
        accept_next(
            state,
            worker_id="private-retry",
            expected_task_id="T-PRIVA001",
        )

        failed_b = state.claim_task(worker_id="private-builder")
        assert failed_b is not None
        state.commit_task_outcome(
            TaskOutcome(
                task_id="T-PRIVB001",
                worker_id="private-builder",
                lease_token=str(failed_b["lease_token"]),
                expected_plan_revision=1,
                idempotency_key=sha256_text("private-builder-failure"),
                result_ref="internal://failure/private-builder",
                result_digest=sha256_text("private-builder-failure"),
                status="FAILED_SEMANTIC",
                failure=FailureData(
                    failure_class="semantic",
                    reason_code="model_requested_repair",
                    safe_message="Persistence retry violates idempotency acceptance",
                    evidence_ref="internal://failure/private-builder",
                    failed_gate_ids=("persistence-idempotency",),
                    actual={
                        "required_fixes": [
                            "Make persistence retry idempotent and rerun its gate"
                        ]
                    },
                ),
                hypothesis=HypothesisData(
                    statement="Persistence retry is not idempotent",
                    signature=sha256_text("private-persistence-hypothesis"),
                    required_evidence=("internal://gate/persistence-idempotency",),
                ),
            )
        )
        repaired = PipelineReconciler(config, state).reconcile_once()
        assert repaired.repaired == 1
        repair_task = next(
            task
            for task in state.list_tasks(product_id)
            if task["stage_key"] == "repair"
        )
        repair_id = str(repair_task["task_id"])
        assert repair_task["root_task_id"] == root_id
        assert repair_task["parent_task_id"] == "T-PRIVB001"
        assert repair_task["source_task_id"] == "T-PRIVB001"
        assert repair_task["failure_id"]
        assert repair_task["hypothesis_id"]
        accept_next(
            state,
            worker_id="private-repair",
            expected_task_id=repair_id,
        )
        assert state.get_task("T-PRIVB001")["graph_status"] == "SUPERSEDED"

        failed_c = state.claim_task(worker_id="private-scope-check")
        assert failed_c is not None
        state.commit_task_outcome(
            TaskOutcome(
                task_id="T-PRIVC001",
                worker_id="private-scope-check",
                lease_token=str(failed_c["lease_token"]),
                expected_plan_revision=1,
                idempotency_key=sha256_text("private-needs-replan"),
                result_ref="internal://failure/private-scope",
                result_digest=sha256_text("private-needs-replan"),
                status="FAILED_SEMANTIC",
                failure=FailureData(
                    failure_class="semantic",
                    reason_code="needs_replan",
                    safe_message=(
                        "Accepted architecture omits the required bounded "
                        "operations node"
                    ),
                    evidence_ref="internal://failure/private-scope",
                    failed_gate_ids=("architecture-operations-scope",),
                    actual={
                        "required_fixes": [
                            "Add a bounded operations node through plan revision 2"
                        ]
                    },
                ),
                hypothesis=HypothesisData(
                    statement="The active plan omits required operations scope",
                    signature=sha256_text("private-replan-hypothesis"),
                    required_evidence=("internal://architecture/scope",),
                ),
            )
        )
        replanned = PipelineReconciler(config, state).reconcile_once()
        assert replanned.replanned == 1
        arbiter = next(
            task
            for task in state.list_tasks(product_id)
            if task["role"] == "path-arbiter"
            and task["graph_status"] == "READY"
        )
        accept_path_arbiter_and_prepare_replanner(
            config,
            state,
            ArtifactStore(config),
            str(arbiter["task_id"]),
        )
        replanner = next(
            task
            for task in state.list_tasks(product_id)
            if task["role"] == "replanner"
            and task["graph_status"] == "READY"
        )
        assert replanner["capability_profile"] == "planning_readonly"
        source_failure_id = str(replanner["failure_id"])
        plan2 = executable_plan(
            config,
            product_id=product_id,
            plan_id="PLAN-PRIVATE-E2E-2",
            root_task_id=root_id,
            revision=2,
            parent_plan_id="PLAN-PRIVATE-E2E-1",
            source_failure_id=source_failure_id,
            node_specs=[
                ("A2", "T-PRIVA002", "accept-a"),
                ("B2", "T-PRIVB002", "accept-b"),
                ("C2", "T-PRIVC002", "accept-c2"),
                ("review", "T-PRIVREV02", "accept-review"),
                ("observation", "T-PRIVOBS02", "accept-observation"),
            ],
            edges=[
                ("A2", "B2"),
                ("B2", "C2"),
                ("C2", "review"),
                ("review", "observation"),
            ],
            supersedes={
                "A2": "T-PRIVA001",
                "B2": repair_id,
                "C2": "T-PRIVC001",
            },
        )
        bind_test_supersession_identities(state, plan2)
        enriched_plan2 = write_plan_for_outcome(config, plan2)
        claimed_replanner = state.claim_task(worker_id="private-replanner")
        assert claimed_replanner is not None
        assert claimed_replanner["task_id"] == replanner["task_id"]
        state.commit_task_outcome(
            TaskOutcome(
                task_id=str(replanner["task_id"]),
                worker_id="private-replanner",
                lease_token=str(claimed_replanner["lease_token"]),
                expected_task_revision=int(replanner["task_revision"]),
                expected_plan_revision=1,
                idempotency_key=sha256_text("private-replan-outcome"),
                result_ref="internal://plan/private-revision-2",
                result_digest=sha256_text("private-replan-outcome"),
                status="ACCEPTED",
                plan=enriched_plan2,
            )
        )
        reused_a = state.get_task("T-PRIVA002")
        reused_b = state.get_task("T-PRIVB002")
        assert reused_a is not None and reused_b is not None
        assert reused_a["graph_status"] == "ACCEPTED"
        assert reused_b["graph_status"] == "ACCEPTED"
        assert reused_a["result_ref"] == state.get_task("T-PRIVA001")["result_ref"]
        assert reused_b["result_ref"] == state.get_task(repair_id)["result_ref"]
        assert state.attempts_for_task("T-PRIVA002") == []
        assert state.attempts_for_task("T-PRIVB002") == []

        for index, task_id in enumerate(
            ("T-PRIVC002", "T-PRIVREV02", "T-PRIVOBS02"),
            start=1,
        ):
            accept_next(
                state,
                worker_id=f"private-final-{index}",
                expected_task_id=task_id,
            )
        release_digest = sha256_text("private-final-candidate")
        record_completion_evidence(
            state,
            product_id=product_id,
            release_digest=release_digest,
        )
        decision = state.reduce_completion(
            product_id,
            artifacts=ArtifactStore(config),
        )
        assert decision.completed
        assert all(
            failure["status"] == "RESOLVED"
            for failure in state.list_failures(product_id)
        )
        assert not any(
            row["event_type"] == "owner_notification"
            for row in state.list_outbox()
        )
        persisted = json.dumps(
            {
                "products": state.list_products(),
                "tasks": state.list_tasks(product_id),
                "failures": state.list_failures(product_id),
                "events": state.events(product_id),
                "outbox": state.list_outbox(),
            },
            ensure_ascii=False,
            default=str,
        )
        assert credential not in persisted
        assert state.get_product(product_id)["status"] == "COMPLETED"
    finally:
        state.close()


def test_AUT_P1_001_parallel_frontier_respects_conflict_keys(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(
        config.database_path,
        max_active_workers=2,
        max_active_products=2,
    )
    try:
        for product_id in ("parallel-product-a", "parallel-product-b"):
            create_v2_product(state, product_id=product_id)
        state.add_task(
            task_id="T-PARALLELA1",
            product_id="parallel-product-a",
            title="First conflicting write",
            conflict_keys=["shared-scope"],
            priority=30,
        )
        state.add_task(
            task_id="T-PARALLELA2",
            product_id="parallel-product-a",
            title="Second write in the same persistent workspace",
            conflict_keys=["independent-scope"],
            priority=20,
        )
        state.add_task(
            task_id="T-PARALLELB1",
            product_id="parallel-product-b",
            title="Independent write",
            conflict_keys=["shared-scope"],
            priority=10,
        )
        first = state.claim_task(worker_id="parallel-1")
        second = state.claim_task(worker_id="parallel-2")
        assert first is not None and second is not None
        assert first["task_id"] == "T-PARALLELA1"
        assert second["task_id"] == "T-PARALLELB1"
        state.complete_task("T-PARALLELA1", "parallel-1")
        third = state.claim_task(worker_id="parallel-3")
        assert third is not None
        assert third["task_id"] == "T-PARALLELA2"
    finally:
        state.close()


def test_AUT_P1_002_plan_supersession_removes_old_ready_tasks(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path, max_active_products=2)
    try:
        create_v2_product(state)
        state.add_task(
            task_id="T-SUPERROOT1",
            product_id="product-autonomy",
            title="Supersession planner",
        )
        product = state.get_product("product-autonomy")
        assert product is not None
        first = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-SUPER-1",
            root_task_id="T-SUPERROOT1",
            parent_plan_id=str(product["active_plan_id"]),
            node_specs=[
                ("A", "T-SUPEROLD1", "accept-old-a"),
                ("B", "T-SUPEROLD2", "accept-old-b"),
            ],
            edges=[],
        )
        persist_and_ingest_plan(
            config,
            state,
            first,
            created_by_task_id="T-SUPERROOT1",
        )
        second = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-SUPER-2",
            root_task_id="T-SUPERROOT1",
            revision=2,
            parent_plan_id="PLAN-SUPER-1",
            node_specs=[("A2", "T-SUPERNEW1", "accept-new-a")],
            edges=[],
            supersedes={"A2": "T-SUPEROLD1"},
        )
        bind_test_supersession_identities(state, second)
        persist_and_ingest_plan(
            config,
            state,
            second,
            created_by_task_id="T-SUPERROOT1",
        )
        assert state.get_task("T-SUPEROLD1")["graph_status"] == "SUPERSEDED"
        assert state.get_task("T-SUPEROLD2")["graph_status"] == "SUPERSEDED"
        claimed = state.claim_task(worker_id="new-plan-worker")
        assert claimed is not None
        assert claimed["task_id"] == "T-SUPERNEW1"
    finally:
        state.close()


def test_AUT_P1_003_replan_reuses_accepted_unaffected_node(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        state.add_task(
            task_id="T-REUSEROOT1",
            product_id="product-autonomy",
            title="Reuse planner",
        )
        product = state.get_product("product-autonomy")
        assert product is not None
        first = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-REUSE-1",
            root_task_id="T-REUSEROOT1",
            parent_plan_id=str(product["active_plan_id"]),
            node_specs=[("A", "T-REUSEOLD1", "accept-a")],
            edges=[],
        )
        persist_and_ingest_plan(
            config,
            state,
            first,
            created_by_task_id="T-REUSEROOT1",
        )
        old = accept_next(
            state,
            worker_id="reuse-old",
            expected_task_id="T-REUSEOLD1",
        )
        second = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-REUSE-2",
            root_task_id="T-REUSEROOT1",
            revision=2,
            parent_plan_id="PLAN-REUSE-1",
            node_specs=[("A2", "T-REUSENEW1", "accept-a")],
            edges=[],
            supersedes={"A2": "T-REUSEOLD1"},
        )
        bind_test_supersession_identities(state, second)
        persist_and_ingest_plan(
            config,
            state,
            second,
            created_by_task_id="T-REUSEROOT1",
        )
        reused = state.get_task("T-REUSENEW1")
        assert reused is not None
        assert reused["graph_status"] == "ACCEPTED"
        assert reused["result_digest"] == old["result_digest"]
        assert reused["result_ref"] == old["result_ref"]
        assert state.attempts_for_task("T-REUSENEW1") == []
    finally:
        state.close()


def test_AUT_P1_004_optional_gate_failure_remains_visible(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        state.add_task(
            task_id="T-OPTIONROOT",
            product_id="product-autonomy",
            title="Optional gate planner",
        )
        product = state.get_product("product-autonomy")
        assert product is not None
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-OPTIONAL-1",
            root_task_id="T-OPTIONROOT",
            parent_plan_id=str(product["active_plan_id"]),
            node_specs=[("observation", "T-OPTIONOBS1", "accept-observation")],
            edges=[],
        )
        persist_and_ingest_plan(
            config,
            state,
            plan,
            created_by_task_id="T-OPTIONROOT",
        )
        accept_next(
            state,
            worker_id="optional-observer",
            expected_task_id="T-OPTIONOBS1",
        )
        state.record_product_evidence(
            product_id="product-autonomy",
            evidence_type="optional_lint",
            artifact_ref="internal://optional/lint-failed",
            artifact_digest=sha256_text("optional-lint-failed"),
            status="FAIL",
        )
        release_digest = sha256_text("optional-candidate")
        record_completion_evidence(
            state,
            product_id="product-autonomy",
            release_digest=release_digest,
        )
        decision = state.reduce_completion(
            "product-autonomy",
            artifacts=ArtifactStore(config),
        )
        assert decision.completed
        with state._lock:
            row = state._connection.execute(
                "SELECT status, artifact_ref FROM product_evidence "
                "WHERE evidence_type='optional_lint'",
            ).fetchone()
        assert tuple(row) == ("FAIL", "internal://optional/lint-failed")
    finally:
        state.close()


def test_AUT_P1_005_waiting_timer_survives_restart(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    create_v2_product(state)
    state.add_task(
        task_id="T-TIMERWAIT1",
        product_id="product-autonomy",
        title="Wait for bounded backoff",
        available_at="9999-12-31T23:59:59Z",
    )
    state.close()

    restarted = StateStore(config.database_path)
    try:
        task = restarted.get_task("T-TIMERWAIT1")
        assert task is not None
        assert task["graph_status"] == "WAITING_TIME"
        assert restarted.claim_task(worker_id="too-early") is None
        with restarted._lock, restarted._connection:
            restarted._connection.execute(
                "UPDATE tasks SET available_at='2000-01-01T00:00:00Z' "
                "WHERE task_id='T-TIMERWAIT1'",
            )
        claimed = restarted.claim_task(worker_id="timer-ready")
        assert claimed is not None
        assert claimed["task_id"] == "T-TIMERWAIT1"
        assert restarted.claim_task(worker_id="timer-duplicate") is None
    finally:
        restarted.close()


def test_AUT_P1_006_outbox_is_logically_exactly_once(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        key = sha256_text("logical-notification")
        assert state.enqueue_outbox(
            outbox_id="outbox-logical-once",
            idempotency_key=key,
            event_type="owner_notification",
            payload={"message": "bounded test notification"},
        )
        assert not state.enqueue_outbox(
            outbox_id="outbox-logical-duplicate",
            idempotency_key=key,
            event_type="owner_notification",
            payload={"message": "bounded test notification"},
        )
        first = state.claim_outbox("transport-1")
        assert len(first) == 1
        state.mark_outbox_failed(
            "outbox-logical-once",
            "transport-1",
            "network timeout",
        )
        state.close()
        state = StateStore(config.database_path)
        second = state.claim_outbox("transport-2")
        assert len(second) == 1
        state.mark_outbox_done("outbox-logical-once", "transport-2")
        assert len(state.list_outbox()) == 1
        assert state.list_outbox()[0]["status"] == "DONE"
        assert int(state.list_outbox()[0]["attempts"]) == 1
    finally:
        state.close()


def test_AUT_P1_007_cancel_pause_resume_preserve_graph(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path, max_active_products=2)
    try:
        create_v2_product(state, product_id="pause-product")
        state.add_task(
            task_id="T-PAUSEA001",
            product_id="pause-product",
            title="Ready before pause",
        )
        state.add_task(
            task_id="T-PAUSEB001",
            product_id="pause-product",
            title="Blocked before pause",
            dependencies=["T-PAUSEA001"],
        )
        workflow = WorkflowEngine(state)
        workflow.pause("pause-product")
        before = {
            task["task_id"]: task["graph_status"]
            for task in state.list_tasks("pause-product")
        }
        assert state.claim_task(worker_id="paused-worker") is None
        workflow.resume("pause-product", "IDEA_RECEIVED")
        after = {
            task["task_id"]: task["graph_status"]
            for task in state.list_tasks("pause-product")
        }
        assert after == before
        assert state.claim_task(worker_id="resumed-worker")["task_id"] == "T-PAUSEA001"

        create_v2_product(state, product_id="cancel-product")
        state.add_task(
            task_id="T-CANCELA01",
            product_id="cancel-product",
            title="Ready before cancel",
        )
        state.add_task(
            task_id="T-CANCELB01",
            product_id="cancel-product",
            title="Blocked before cancel",
            dependencies=["T-CANCELA01"],
        )
        workflow.cancel("cancel-product")
        assert {
            task["graph_status"]
            for task in state.list_tasks("cancel-product")
        } == {"CANCELLED"}
    finally:
        state.close()


def test_AUT_P1_008_controller_incident_quarantines_without_model_recovery(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        state.add_task(
            task_id="T-CONTROOT1",
            product_id="product-autonomy",
            title="Controller incident planner",
        )
        product = state.get_product("product-autonomy")
        assert product is not None
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-CONTROLLER-1",
            root_task_id="T-CONTROOT1",
            parent_plan_id=str(product["active_plan_id"]),
            node_specs=[
                ("controller", "T-CONTROLLER1", "accept-controller")
            ],
            edges=[],
        )
        persist_and_ingest_plan(
            config,
            state,
            plan,
            created_by_task_id="T-CONTROOT1",
        )
        claimed = state.claim_task(worker_id="controller-fault")
        assert claimed is not None
        state.commit_task_outcome(
            TaskOutcome(
                task_id="T-CONTROLLER1",
                worker_id="controller-fault",
                lease_token=str(claimed["lease_token"]),
                expected_plan_revision=1,
                idempotency_key=sha256_text("controller-fault"),
                result_ref="internal://controller/schema-corruption",
                result_digest=sha256_text("controller-fault"),
                status="FAILED_SEMANTIC",
                failure=FailureData(
                    failure_class="controller",
                    reason_code="controller_schema_corruption",
                    safe_message="Controller schema checksum does not match migration",
                    evidence_ref="internal://controller/schema-corruption",
                    exception_type="RuntimeError",
                    stack_fingerprint=sha256_text("controller-stack"),
                ),
            )
        )
        routed = FailureRouter(config, state).route_open_failures(
            "product-autonomy"
        )
        assert routed == []
        assert not any(
            task["role"] == "incident-recovery"
            for task in state.list_tasks("product-autonomy")
        )
        assert state.list_hypotheses("product-autonomy") == []
        product = state.get_product("product-autonomy")
        assert product is not None
        assert product["status"] == "FAILED_SAFE"
        assert product["terminal_reason"] == "controller_schema_corruption"
        assert state._connection.execute(
            "SELECT COUNT(*) FROM problem_budgets WHERE product_id=?",
            ("product-autonomy",),
        ).fetchone()[0] == 0
        with state._lock:
            incidents = state._connection.execute(
                "SELECT reason_code, status FROM controller_incidents",
            ).fetchall()
        assert [tuple(row) for row in incidents] == [
            ("controller_schema_corruption", "OPEN")
        ]
    finally:
        state.close()


def test_AUT_P1_008_controller_defect_cannot_start_recovery_retry_loop(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        state.add_task(
            task_id="T-CONTROOT2",
            product_id="product-autonomy",
            title="Controller recovery depth planner",
        )
        product = state.get_product("product-autonomy")
        assert product is not None
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-CONTROLLER-2",
            root_task_id="T-CONTROOT2",
            parent_plan_id=str(product["active_plan_id"]),
            node_specs=[
                ("controller", "T-CONTROLLER2", "accept-controller-depth")
            ],
            edges=[],
        )
        persist_and_ingest_plan(
            config,
            state,
            plan,
            created_by_task_id="T-CONTROOT2",
        )
        claimed = state.claim_task(worker_id="controller-depth-fault")
        assert claimed is not None
        failed = state.commit_task_outcome(
            TaskOutcome(
                task_id="T-CONTROLLER2",
                worker_id="controller-depth-fault",
                lease_token=str(claimed["lease_token"]),
                expected_plan_revision=1,
                idempotency_key=sha256_text("controller-depth-fault"),
                result_ref="internal://controller/depth-fault",
                result_digest=sha256_text("controller-depth-fault"),
                status="FAILED_SEMANTIC",
                failure=FailureData(
                    failure_class="controller",
                    reason_code="controller_depth_fault",
                    safe_message="Controller recovery requires bounded reassessment",
                    evidence_ref="internal://controller/depth-fault",
                    exception_type="RuntimeError",
                    stack_fingerprint=sha256_text("controller-depth-stack"),
                ),
            )
        )
        assert failed.failure_id is not None
        routed = FailureRouter(config, state).route_open_failures(
            "product-autonomy"
        )
        assert routed == []
        assert FailureRouter(config, state).route_open_failures("product-autonomy") == []
        assert state.claim_task(worker_id="incident-depth-forbidden") is None
        assert not any(
            task["role"] in {"incident-recovery", "path-arbiter"}
            for task in state.list_tasks("product-autonomy")
        )
        assert state.get_product("product-autonomy")["status"] == "FAILED_SAFE"
    finally:
        state.close()


def test_AUT_P1_008_transient_transport_routes_product_retry_not_controller_recovery(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        state.add_task(
            task_id="T-CONTAINED-ROOT",
            product_id="product-autonomy",
            title="Contained controller incident planner",
        )
        product = state.get_product("product-autonomy")
        assert product is not None
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-CONTAINED-CONTROLLER",
            root_task_id="T-CONTAINED-ROOT",
            parent_plan_id=str(product["active_plan_id"]),
            node_specs=[
                (
                    "controller",
                    "T-CONTAINED-CONTROLLER",
                    "fresh-product-evidence",
                )
            ],
            edges=[],
        )
        persist_and_ingest_plan(
            config,
            state,
            plan,
            created_by_task_id="T-CONTAINED-ROOT",
        )
        claimed = state.claim_task(worker_id="controller-contained-fault")
        assert claimed is not None
        failed = state.commit_task_outcome(
            TaskOutcome(
                task_id="T-CONTAINED-CONTROLLER",
                worker_id="controller-contained-fault",
                lease_token=str(claimed["lease_token"]),
                expected_plan_revision=1,
                idempotency_key=sha256_text("controller-contained-fault"),
                result_ref="internal://controller/contained-fault",
                result_digest=sha256_text("controller-contained-fault"),
                status="FAILED_TRANSIENT",
                failure=FailureData(
                    failure_class="transient",
                    reason_code="malformed_transport",
                    safe_message="Provider response transport was invalid.",
                    evidence_ref="internal://controller/contained-fault",
                    retryable=True,
                ),
            )
        )
        assert failed.failure_id is not None
        routed = FailureRouter(config, state).route_open_failures(
            "product-autonomy"
        )
        assert len(routed) == 1
        recovery = state.claim_task(worker_id="incident-contained")
        assert recovery is not None
        assert recovery["task_id"] == routed[0]
        assert recovery["role"] == "builder"
        assert recovery["role"] != "incident-recovery"
        assert not any(
            task["role"] == "incident-recovery"
            for task in state.list_tasks("product-autonomy")
        )
    finally:
        state.close()


def test_AUT_P1_009_artifact_conflict_commits_controller_failure_only(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    artifacts = ArtifactStore(config)
    try:
        intake = IntakeService(config, state, artifacts).submit(
            source="cli",
            owner_id="owner",
            idea="Detect immutable artifact conflicts",
        )
        first = {
            "schema_version": "2.0",
            "artifact_id": "completion-conflict",
            "product_id": intake.product_id,
            "plan_id": "PLAN-CONFLICT",
            "completed_at": "2026-07-29T00:00:00Z",
            "goal_evidence": ["internal://goal"],
            "node_evidence": ["internal://node"],
            "release_digest": "a" * 64,
            "observation_ref": "internal://observation",
        }
        second = {
            **first,
            "release_digest": "b" * 64,
        }
        artifacts.write(
            "completion-evidence.schema.json",
            first,
            filename="immutable-conflict.json",
        )
        worker = AgentWorker(
            config,
            state,
            runner=None,
            health_probe=lambda _: True,
            repository_root=Path(__file__).resolve().parents[1],
        )

        def conflict(_: Any) -> Any:
            return artifacts.write(
                "completion-evidence.schema.json",
                second,
                filename="immutable-conflict.json",
            )

        with patch.object(worker, "execute", side_effect=conflict):
            result = worker.run_once()

        assert result is not None
        assert result.status == "failed_safe"
        assert result.reason_code == "artifact_immutable_conflict"
        source = state.list_tasks(intake.product_id)[0]
        assert source["graph_status"] == "FAILED_SEMANTIC"
        failures = state.list_failures(intake.product_id)
        assert len(failures) == 1
        assert failures[0]["failure_class"] == "controller"
        assert failures[0]["reason_code"] == "artifact_immutable_conflict"
        assert len(state.list_tasks(intake.product_id)) == 1
    finally:
        state.close()


class MutableCapabilityProbe:
    def __init__(
        self,
        *,
        missing: set[str] | None = None,
    ) -> None:
        self.missing = set(missing or ())
        self.calls: list[tuple[str, str]] = []

    def check(
        self,
        capability: str,
        *,
        product: dict[str, Any],
    ) -> CapabilityCheck:
        self.calls.append((str(product["product_id"]), capability))
        scope = {
            "owner": "brullik",
            "repository": str(
                product.get("repository_name") or product["product_id"]
            ),
            "allowed_operations": [capability],
        }
        if capability in self.missing:
            return CapabilityCheck(
                capability,
                "MISSING_EXTERNAL",
                "strict-fake",
                "missing_credential",
                scope,
            )
        return CapabilityCheck(
            capability,
            "AVAILABLE",
            "strict-fake",
            scope=scope,
        )


def release_staging_plan(
    config: Any,
    state: StateStore,
    *,
    product_id: str,
    root_task_id: str,
) -> dict[str, Any]:
    product = state.get_product(product_id)
    assert product is not None
    plan = executable_plan(
        config,
        product_id=product_id,
        plan_id=f"PLAN-RECONCILE-{sha256_text(product_id)[:12].upper()}",
        root_task_id=root_task_id,
        parent_plan_id=str(product["active_plan_id"]),
        node_specs=[
            (
                "release-staging",
                f"T-RELEASE-{sha256_text(product_id)[:10].upper()}",
                "accept-release",
            )
        ],
        edges=[],
    )
    contract = plan["nodes"][0]["task_contract"]
    contract["role"] = "release-operator"
    contract["output_schema"] = "release-operation-result.schema.json"
    contract["capability_profile"] = "release_staging"
    contract["required_capabilities"] = list(
        CAPABILITY_PROFILES["release_staging"]
    )
    return plan


def test_AUT_P0_023_intake_after_worker_start_resumes_capability_task(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    artifacts = ArtifactStore(config)
    probe = MutableCapabilityProbe(
        missing={"github.pull_request.create"},
    )
    broker = CapabilityBroker(config, state, probe=probe)
    worker = AgentWorker(
        config,
        state,
        runner=None,
        health_probe=lambda _: True,
        repository_root=Path(__file__).resolve().parents[1],
        repository_bootstrapper=RepositoryBootstrapper(
            config,
            state,
            FakeRepositoryAdapter(),
        ),
        worker_id="long-lived-worker",
    )
    try:
        intake = IntakeService(
            config,
            state,
            artifacts,
            capability_broker=broker,
        ).submit(
            source="cli",
            owner_id="owner",
            goal_text="Create a private release after worker startup",
            delivery_mode="new_repository",
            repository_name="aut-p0-023-private",
            repository_visibility="private",
            idempotency_key="aut-p0-023-intake",
        )
        root = state.list_tasks(intake.product_id)[0]
        plan = release_staging_plan(
            config,
            state,
            product_id=intake.product_id,
            root_task_id=str(root["task_id"]),
        )
        task_ids = persist_and_ingest_plan(
            config,
            state,
            plan,
            created_by_task_id=str(root["task_id"]),
        )
        release_task_id = task_ids[0]
        assert state.get_task(release_task_id)["graph_status"] == "BLOCKED_CAPABILITY"

        probe.missing.clear()
        reconcile = CapabilityReconciler(
            config,
            state,
            probe=probe,
            ttl_seconds=0,
            retry_seconds=0,
        ).reconcile_once()
        assert reconcile.resumed_tasks == 1
        assert state.get_task(release_task_id)["graph_status"] == "READY"

        claimed = threading.Event()
        finish = threading.Event()

        def execute(_: Any) -> WorkerResult:
            claimed.set()
            assert finish.wait(5)
            return WorkerResult(release_task_id, "completed", None)

        with patch.object(worker, "execute", side_effect=execute):
            thread = threading.Thread(target=worker.run_once, daemon=True)
            thread.start()
            assert claimed.wait(5)
            assert state.get_task(release_task_id)["graph_status"] == "CLAIMED"
            finish.set()
            thread.join(timeout=5)
            assert not thread.is_alive()
        assert not any(
            event["event_type"] == "worker_restarted"
            for event in state.events(intake.product_id)
        )
    finally:
        state.close()


def test_AUT_P0_024_credential_appearance_closes_old_owner_action(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    probe = MutableCapabilityProbe(
        missing={"github.pull_request.create"},
    )
    broker = CapabilityBroker(config, state, probe=probe)
    try:
        intake = IntakeService(
            config,
            state,
            ArtifactStore(config),
            capability_broker=broker,
        ).submit(
            source="cli",
            owner_id="owner",
            goal_text="Resume automatically when the credential appears",
            delivery_mode="new_repository",
            repository_name="aut-p0-024-private",
            repository_visibility="private",
            idempotency_key="aut-p0-024-intake",
        )
        root = state.list_tasks(intake.product_id)[0]
        plan = release_staging_plan(
            config,
            state,
            product_id=intake.product_id,
            root_task_id=str(root["task_id"]),
        )
        release_task_id = persist_and_ingest_plan(
            config,
            state,
            plan,
            created_by_task_id=str(root["task_id"]),
        )[0]
        reconciler = CapabilityReconciler(
            config,
            state,
            probe=probe,
            ttl_seconds=0,
            retry_seconds=0,
        )
        reconciler.reconcile_once()
        reconciler.reconcile_once()
        owner_events = [
            event
            for event in state.events(intake.product_id)
            if event["event_type"] == "owner_action_required"
        ]
        assert len(owner_events) == 1
        assert len(state.open_capability_blocks()) == 1
        assert len(
            [
                item
                for item in state.list_outbox()
                if json.loads(str(item["payload_json"])).get("kind")
                == "owner_action"
            ]
        ) == 1

        probe.missing.add("git.push_branch")
        reconciler.reconcile_once()
        assert len(state.open_capability_blocks()) == 2
        assert len(
            [
                event
                for event in state.events(intake.product_id)
                if event["event_type"] == "owner_action_required"
            ]
        ) == 1
        assert len(
            [
                item
                for item in state.list_outbox()
                if json.loads(str(item["payload_json"])).get("kind")
                == "owner_action"
            ]
        ) == 1

        probe.missing.remove("github.pull_request.create")
        reconciler.reconcile_once()
        assert state.get_task(release_task_id)["graph_status"] == "BLOCKED_CAPABILITY"
        assert [
            block["capability"] for block in state.open_capability_blocks()
        ] == ["git.push_branch"]

        probe.missing.clear()
        result = reconciler.reconcile_once()
        assert result.resumed_tasks == 1
        assert state.get_task(release_task_id)["graph_status"] == "READY"
        assert state.open_capability_blocks() == []
        block = state._connection.execute(
            """SELECT status, resolved_at, failure_ref
                 FROM capability_blocks
                WHERE product_id=? AND capability=?""",
            (intake.product_id, "github.pull_request.create"),
        ).fetchone()
        assert block is not None
        assert block["status"] == "RESOLVED"
        assert block["resolved_at"]
        assert str(block["failure_ref"]).startswith("capability://")
    finally:
        state.close()


def test_AUT_P0_025_production_profile_underdeclaration_is_atomic(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        root_id = "T-P0-025-ROOT"
        state.add_task(
            task_id=root_id,
            product_id="product-autonomy",
            title="Production release planner",
            role="task-specifier",
        )
        product = state.get_product("product-autonomy")
        assert product is not None
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-AUT-P0-025",
            root_task_id=root_id,
            parent_plan_id=str(product["active_plan_id"]),
            node_specs=[
                (
                    "release-production",
                    "T-AUT-P0-025-PRODUCTION",
                    "accept-production",
                )
            ],
            edges=[],
        )
        contract = plan["nodes"][0]["task_contract"]
        contract["role"] = "release-operator"
        contract["output_schema"] = "release-operation-result.schema.json"
        contract["capability_profile"] = "release_production"
        contract["required_capabilities"] = []
        before = {
            table: state._connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in (
                "plans",
                "tasks",
                "task_edges",
                "task_outcomes",
                "outbox",
            )
        }
        with pytest.raises(
            ValueError,
            match=(
                "required_capabilities omits canonical capability: "
                "backup.verify"
            ),
        ):
            state.ingest_plan(
                plan,
                plan_artifact_ref="evidence/aut-p0-025.json",
                plan_digest=sha256_text(json.dumps(plan, sort_keys=True)),
                created_by_task_id=root_id,
            )
        after = {
            table: state._connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in before
        }
        assert after == before
    finally:
        state.close()


def test_CAP_P0_004_unknown_capability_is_rejected_before_sqlite_mutation(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    try:
        create_v2_product(state)
        root_id = "T-CAP-P0-004-ROOT"
        state.add_task(
            task_id=root_id,
            product_id="product-autonomy",
            title="Unknown capability planner",
            role="task-specifier",
        )
        product = state.get_product("product-autonomy")
        assert product is not None
        plan = executable_plan(
            config,
            product_id="product-autonomy",
            plan_id="PLAN-CAP-P0-004",
            root_task_id=root_id,
            parent_plan_id=str(product["active_plan_id"]),
            node_specs=[("release-staging", "T-CAP-P0-004", "accept-release")],
            edges=[],
        )
        contract = plan["nodes"][0]["task_contract"]
        contract["role"] = "release-operator"
        contract["output_schema"] = "release-operation-result.schema.json"
        contract["capability_profile"] = "release_staging"
        contract["required_capabilities"] = [
            *CAPABILITY_PROFILES["release_staging"],
            "controller.unknown-capability",
        ]
        before = {
            table: state._connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in ("plans", "tasks", "task_edges", "task_outcomes", "outbox")
        }
        with pytest.raises(ValueError, match="contains unknown capability"):
            state.ingest_plan(
                plan,
                plan_artifact_ref="evidence/cap-p0-004.json",
                plan_digest=sha256_text(json.dumps(plan, sort_keys=True)),
                created_by_task_id=root_id,
            )
        after = {
            table: state._connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in before
        }
        assert after == before
    finally:
        state.close()


def test_AUT_P0_026_contents_read_never_implies_github_write(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    product = {
        "product_id": "aut-p0-026-product",
        "repository_url": "https://github.com/brullik/read-only-private",
        "repository_name": None,
        "repository_visibility": "private",
    }

    def runner(argv: list[str]) -> ProbeCommandResult:
        endpoint = argv[-1]
        if endpoint == "user":
            return ProbeCommandResult(
                0,
                'HTTP/2 200 OK\n\n{"login":"brullik"}',
            )
        if endpoint == "repos/brullik/read-only-private":
            return ProbeCommandResult(
                0,
                (
                    "HTTP/2 200 OK\n\n"
                    '{"default_branch":"main","permissions":'
                    '{"pull":true,"push":false,"maintain":false,"admin":false},'
                    '"allow_merge_commit":true}'
                ),
            )
        if endpoint.endswith("/rulesets"):
            return ProbeCommandResult(0, "HTTP/2 200 OK\n\n[]")
        if endpoint.endswith("/protection"):
            return ProbeCommandResult(1, "HTTP/2 404 Not Found\n\n{}")
        raise AssertionError(argv)

    with patch("factory.capabilities.shutil.which", return_value="/safe/tool"):
        probe = ConfiguredCapabilityProbe(
            config,
            command_runner=runner,
        )
        assert probe.check("repository.read", product=product).status == "AVAILABLE"
        for capability in (
            "git.push_branch",
            "github.pull_request.create",
            "github.pull_request.merge",
        ):
            assert probe.check(capability, product=product).status != "AVAILABLE"


def test_admin_permission_proves_configure_and_merge_when_governance_is_unreadable(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    product = {
        "product_id": "fine-grained-admin-product",
        "repository_url": "https://github.com/brullik/fine-grained-admin",
        "repository_name": None,
        "repository_visibility": "public",
    }

    def runner(argv: list[str]) -> ProbeCommandResult:
        endpoint = argv[-1]
        if endpoint == "user":
            return ProbeCommandResult(
                0,
                'HTTP/2 200 OK\n\n{"login":"brullik"}',
            )
        if endpoint == "repos/brullik/fine-grained-admin":
            return ProbeCommandResult(
                0,
                (
                    "HTTP/2 200 OK\n\n"
                    '{"default_branch":"main","permissions":'
                    '{"pull":true,"push":true,"maintain":true,"admin":true},'
                    '"allow_merge_commit":true}'
                ),
            )
        if endpoint.endswith("/rulesets"):
            return ProbeCommandResult(1, "HTTP/2 404 Not Found\n\n{}")
        if endpoint.endswith("/protection"):
            return ProbeCommandResult(1, "HTTP/2 404 Not Found\n\n{}")
        raise AssertionError(argv)

    with patch("factory.capabilities.shutil.which", return_value="/safe/tool"):
        probe = ConfiguredCapabilityProbe(
            config,
            command_runner=runner,
        )
        assert (
            probe.check("github.repository.configure", product=product).status
            == "AVAILABLE"
        )
        assert (
            probe.check("github.pull_request.merge", product=product).status
            == "AVAILABLE"
        )


def test_container_capability_requires_subject_runtime_ipam_and_network_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = configured(tmp_path)
    runtime = tmp_path / "runtime"
    runroot = runtime / "containers"
    networks = runroot / "networks"
    networks.mkdir(parents=True)
    ipam = networks / "ipam.db"
    ipam.write_bytes(b"controller-owned-ipam")
    ipam.chmod(0o600)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> ProbeCommandResult:
        calls.append(argv)
        if argv[:3] == ["podman", "info", "--format"]:
            return ProbeCommandResult(0, str(runroot) + "\n")
        if argv[:3] in (
            ["podman", "network", "create"],
            ["podman", "network", "rm"],
        ):
            return ProbeCommandResult(0)
        if argv == ["podman", "--version"]:
            return ProbeCommandResult(0, "podman version 5.6.0\n")
        raise AssertionError(argv)

    with patch("factory.capabilities.shutil.which", return_value="/safe/podman"):
        result = ConfiguredCapabilityProbe(config, command_runner=runner).check(
            "toolchain.container_builder",
            product={"product_id": "container-capability-product"},
        )

    assert result.status == "AVAILABLE"
    assert result.scope is not None
    assert result.scope["runtime"] == "podman"
    assert [call[:3] for call in calls] == [
        ["podman", "info", "--format"],
        ["podman", "network", "create"],
        ["podman", "network", "rm"],
        ["podman", "--version"],
    ]


def test_container_capability_rejects_runroot_outside_worker_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = configured(tmp_path)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "shadow-runtime"))

    def runner(argv: list[str]) -> ProbeCommandResult:
        if argv[:3] == ["podman", "info", "--format"]:
            return ProbeCommandResult(
                0,
                str(tmp_path / "production-runtime" / "containers") + "\n",
            )
        raise AssertionError(argv)

    with patch("factory.capabilities.shutil.which", return_value="/safe/podman"):
        result = ConfiguredCapabilityProbe(config, command_runner=runner).check(
            "toolchain.container_builder",
            product={"product_id": "mis-scoped-container-product"},
        )

    assert result.status == "DENIED_POLICY"
    assert result.reason_code == "controller_toolchain_container_storage_scope_mismatch"


class QueuedRuntimeRunner:
    def __init__(self) -> None:
        self.outputs: list[str] = []
        self.prompts: list[str] = []

    def run(
        self,
        *,
        selection: Any,
        prompt: str,
        cwd: Path,
        usage_path: Path | None = None,
    ) -> HermesRunResult:
        del selection, cwd
        self.prompts.append(prompt)
        if not self.outputs:
            raise AssertionError("runtime runner output queue is empty")
        return HermesRunResult(
            "PASS",
            self.outputs.pop(0),
            sha256_text("strict-runtime-output"),
            None,
            str(usage_path) if usage_path else None,
        )


class RecordingTelegramApi:
    def __init__(self) -> None:
        self.messages: list[tuple[str, str]] = []

    def send_message(self, chat_id: str, text: str) -> None:
        self.messages.append((chat_id, text))


class StrictLifecycleReleaseExecutor:
    def __init__(self, config: Any) -> None:
        self.config = config
        self.calls: list[str] = []
        self.candidate_sha = "c" * 40
        self.release_digest = "sha256:" + "d" * 64

    def execute(
        self,
        *,
        stage: str,
        proposed: Any,
        product_id: str,
        task_contract: Any,
        workspace: Path,
        expected_staging_digest: str | None,
    ) -> dict[str, Any]:
        del proposed, task_contract
        assert workspace.is_dir()
        if stage == "staging":
            self.calls.extend(["pull_request", "checks", "staging"])
            merge = {"performed": False, "merge_sha": None}
            production = "not_started"
            rollback = "not_tested"
        else:
            assert expected_staging_digest == self.release_digest
            self.calls.extend(["merge", "production"])
            merge = {
                "performed": True,
                "merge_sha": self.candidate_sha,
            }
            production = "deployed"
            rollback = "not_needed"
        return {
            **artifact_metadata(
                self.config,
                "release-operator",
                f"strict-release-{stage}-{product_id}",
                product_id,
            ),
            "status": "completed",
            "repository": "brullik/aut-p0-027-private",
            "candidate_sha": self.candidate_sha,
            "merge": merge,
            "release": {
                "version": "1.0.0",
                "image_digest": self.release_digest,
            },
            "staging": "deployed",
            "production": production,
            "rollback": rollback,
            "summary": f"Strict fake completed {stage}.",
            "findings": [],
            "evidence_refs": [
                f"strict://{stage}/immutable-candidate",
                f"strict://{stage}/health",
            ],
        }


class RuntimeRepositoryAdapter(FakeRepositoryAdapter):
    def clone(self, **values: Any) -> tuple[str, str]:
        self.calls.append(("clone", str(values["idempotency_key"])))
        destination = Path(values["destination"])
        destination.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "init", "--quiet", "--initial-branch=main", str(destination)],
            check=True,
        )
        return "main", ""

    def bootstrap_commit(self, **values: Any) -> str:
        self.calls.append(("bootstrap", str(values["idempotency_key"])))
        workspace = Path(values["workspace"])
        (workspace / "README.md").write_text(
            "# Runtime acceptance\n",
            encoding="utf-8",
        )
        (workspace / "src" / "runtime_service").mkdir(parents=True)
        (workspace / "src" / "runtime_service" / "__init__.py").write_text(
            '"""Runtime service fixture."""\n',
            encoding="utf-8",
        )
        (workspace / "tests").mkdir()
        (workspace / "tests" / "test_runtime_service.py").write_text(
            "def test_runtime_service() -> None:\n"
            "    assert True\n",
            encoding="utf-8",
        )
        (workspace / "pyproject.toml").write_text(
            "[project]\n"
            'name = "runtime-service-fixture"\n'
            'version = "1.0.0"\n'
            "dependencies = []\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["git", "-C", str(workspace), "add", "."],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(workspace),
                "-c",
                "user.name=Hermes Test",
                "-c",
                "user.email=hermes-test@localhost",
                "commit",
                "--quiet",
                "-m",
                "Bootstrap runtime fixture",
            ],
            check=True,
        )
        return subprocess.run(
            ["git", "-C", str(workspace), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()


def _architecture_output(config: Any, product_id: str) -> str:
    output = {
        **artifact_metadata(
            config,
            "solution-architect",
            "architecture-aut-p0-027",
            product_id,
        ),
        "status": "completed",
        "summary": "Small private service with transactional release.",
        "components": [
            {
                "id": "service",
                "responsibility": "Serve the verified product journey.",
                "technology": "Python",
                "data_owned": [],
            }
        ],
        "interfaces": [],
        "data_stores": [],
        "trust_boundaries": [],
        "adrs": [],
        "deployment": {
            "staging": "isolated",
            "production": "transactional",
            "image_promotion": "immutable digest",
            "https": True,
        },
        "observability": ["health probe"],
        "backup_restore": {
            "backup": "offsite restic",
            "restore_test": "controlled drill",
        },
        "rollback": {
            "strategy": "previous immutable release",
            "trigger": "health failure",
            "verification": "health probe",
        },
        "test_strategy": ["unit and end-to-end"],
        "capacity": {
            "fits_current_vps": True,
            "constraints": [],
        },
        "assumptions": [],
        "findings": [],
        "evidence_refs": ["strict://requirements/accepted"],
    }
    return json.dumps(output)


def _runtime_plan(
    config: Any,
    state: StateStore,
    *,
    product_id: str,
    root_task_id: str,
) -> dict[str, Any]:
    del state, root_task_id
    return {
        **artifact_metadata(
            config,
            "task-specifier",
            "plan-proposal-aut-p0-027",
            product_id,
        ),
        "schema_version": "1.0",
        "producer": {
            "role": "task-specifier",
            "tier": "luna",
            "provider": "strict-fake",
            "model": "strict-fake",
        },
        "status": "completed",
        "proposal_kind": "initial",
        "parent_plan_id": None,
        "source_failure_id": None,
        "goals": [
            {
                "goal_id": "runtime-service",
                "statement": (
                    "Build, release, and observe the complete private runtime "
                    "acceptance service."
                ),
                "mandatory": True,
            }
        ],
        "nodes": [
            {
                "node_key": "runtime-service",
                "stage_kind": "implementation_slice",
                "title": "Implement the private runtime service",
                "objective": (
                    "Implement the complete private service and its observable "
                    "critical journey."
                ),
                "depends_on": [],
                "scope": [
                    "src/**",
                    "tests/**",
                    "README.md",
                    "pyproject.toml",
                ],
                "acceptance_intents": [
                    "The critical private-service journey and its negative path pass."
                ],
                "goal_ids": ["runtime-service"],
            }
        ],
        "summary": (
            "Semantic implementation proposal for the complete private runtime "
            "acceptance service."
        ),
        "evidence_refs": ["strict://architecture/accepted"],
    }


def _attempt_output(
    config: Any,
    product_id: str,
    task_id: str,
) -> str:
    output = {
        **artifact_metadata(
            config,
            "builder",
            "attempt-output-aut-p0-027",
            product_id,
        ),
        "task_id": task_id,
        "attempt_id": "provider-attempt-aut-p0-027",
        "tier": "luna",
        "attempt_kind": "initial",
        "prompt_digest": "a" * 64,
        "subject_sha_before": "b" * 64,
        "status": "completed",
        "summary": "Core slice is complete.",
        "changed_files": [],
        "commands": [],
        "test_results": [],
        "assumptions": [],
        "findings": [],
        "evidence_refs": ["strict://builder/complete"],
    }
    return json.dumps(output)


def _test_output(config: Any, product_id: str, task_id: str) -> str:
    return json.dumps(
        {
            **artifact_metadata(
                config,
                "test-engineer",
                "test-output-aut-p0-027",
                product_id,
            ),
            "task_id": task_id,
            "status": "completed",
            "traceability": [
                {
                    "criterion_id": "accept-builder",
                    "test_ids": ["strict-e2e"],
                }
            ],
            "tests_added": [],
            "mutation_or_negative_check": "passed",
            "coverage_expectation": 100,
            "assumptions": [],
            "findings": [],
            "evidence_refs": ["strict://tests/pass"],
        }
    )


def _security_output(config: Any, product_id: str, task_id: str) -> str:
    return json.dumps(
        {
            **artifact_metadata(
                config,
                "security-reviewer",
                "security-output-aut-p0-027",
                product_id,
            ),
            "task_id": task_id,
            "subject_sha": "e" * 64,
            "status": "accepted",
            "changed_trust_boundaries": [],
            "findings": [],
            "release_blocked": False,
            "assumptions": [],
            "evidence_refs": ["strict://security/pass"],
        }
    )


def _review_output(config: Any, product_id: str, task_id: str) -> str:
    return json.dumps(
        {
            **artifact_metadata(
                config,
                "independent-reviewer",
                "review-output-aut-p0-027",
                product_id,
            ),
            "task_id": task_id,
            "subject_sha": "f" * 64,
            "status": "accepted",
            "acceptance_trace": [
                {
                    "criterion_id": "accept-review",
                    "result": "PASS",
                    "evidence_refs": ["strict://review/pass"],
                }
            ],
            "findings": [],
            "assumptions": [],
            "evidence_refs": ["strict://review/pass"],
        }
    )


def _release_proposal(config: Any, product_id: str, stage: str) -> str:
    return json.dumps(
        {
            **artifact_metadata(
                config,
                "release-operator",
                f"release-proposal-{stage}-aut-p0-027",
                product_id,
            ),
            "status": "completed",
            "repository": "brullik/aut-p0-027-private",
            "candidate_sha": "c" * 40,
            "merge": {"performed": False, "merge_sha": None},
            "release": {
                "version": "1.0.0",
                "image_digest": "sha256:" + "d" * 64,
            },
            "staging": "deployed",
            "production": "not_started",
            "rollback": "not_tested",
            "summary": f"Propose {stage}.",
            "findings": [],
            "evidence_refs": [f"strict://proposal/{stage}"],
        }
    )


def _product_test_output(
    config: Any,
    product_id: str,
    *,
    environment: str,
) -> str:
    return json.dumps(
        {
            **artifact_metadata(
                config,
                "product-tester",
                f"product-test-{environment}-aut-p0-027",
                product_id,
            ),
            "release_digest": "sha256:" + "d" * 64,
            "environment": environment,
            "status": "accepted",
            "journeys": [
                {
                    "journey_id": "critical-owner-journey",
                    "result": "PASS",
                    "evidence_refs": [
                        f"strict://journey/{environment}/pass"
                    ],
                }
            ],
            "defects": [],
            "improvements": [],
            "release_blocked": False,
            "summary": f"{environment} journey passed.",
            "evidence_refs": [f"strict://product-test/{environment}"],
        }
    )


def test_AUT_P0_027_real_service_path_completes_new_private_product(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    quality_catalog = yaml.safe_load(
        (
            Path(__file__).resolve().parents[1]
            / "config"
            / "quality-gates.yaml"
        ).read_text(encoding="utf-8")
    )
    dependency_gate = next(
        gate
        for gate in quality_catalog["gates"]
        if gate["id"] == "target-dependency-audit"
    )
    dependency_gate.clear()
    dependency_gate.update(
        {
            "id": "target-dependency-audit",
            "command": 'python3 -c "pass"',
            "allowlist_prefixes": ["python3 -c"],
            "timeout_seconds": 30,
            "mandatory": True,
        }
    )
    quality_path = tmp_path / "quality-gates-runtime-e2e.yaml"
    quality_path.write_text(
        yaml.safe_dump(quality_catalog, sort_keys=False),
        encoding="utf-8",
    )
    config.raw["paths"]["quality_gates"] = str(quality_path)
    config.raw["telegram"]["allowed_user_ids"] = ["42"]
    config.raw["controller"]["observation_seconds"] = 0
    state = StateStore(config.database_path)
    artifacts = ArtifactStore(config)
    probe = MutableCapabilityProbe()
    broker = CapabilityBroker(config, state, probe=probe)
    capability_reconciler = CapabilityReconciler(
        config,
        state,
        probe=probe,
        ttl_seconds=0,
        retry_seconds=0,
    )
    repository = RuntimeRepositoryAdapter()
    runner = QueuedRuntimeRunner()
    release = StrictLifecycleReleaseExecutor(config)
    worker = AgentWorker(
        config,
        state,
        runner=runner,
        health_probe=lambda _: True,
        repository_root=Path(__file__).resolve().parents[1],
        release_executor=release,
        repository_bootstrapper=RepositoryBootstrapper(
            config,
            state,
            repository,
        ),
        worker_id="long-lived-runtime-worker",
    )
    telegram = RecordingTelegramApi()
    gateway = TelegramGateway(
        config,
        state,
        artifacts,
        telegram,
        capability_broker=broker,
    )
    try:
        assert gateway.process_update(
            {
                "update_id": 27027,
                "message": {
                    "from": {"id": 42},
                    "chat": {"id": 42, "type": "private"},
                    "text": (
                        "/idea Build and release a complete private runtime "
                        "acceptance service"
                    ),
                },
            }
        )
        assert telegram.messages
        product = state.list_products()[0]
        product_id = str(product["product_id"])
        runner.outputs.extend(
            [
                product_contract(config, product_id),
                requirements_package(config, product_id),
                _architecture_output(config, product_id),
            ]
        )
        for _ in range(3):
            result = worker.run_once()
            assert result is not None
            assert result.status == "completed", (
                result.reason_code,
                result.detail,
            )
        task_specifier = next(
            task
            for task in state.list_tasks(product_id)
            if task["role"] == "task-specifier"
            and task["graph_status"] == "READY"
        )
        plan = _runtime_plan(
            config,
            state,
            product_id=product_id,
            root_task_id=str(task_specifier["task_id"]),
        )
        runner.outputs.append(json.dumps(plan))
        capability_reconciler.reconcile_once()
        compiled = worker.run_once()
        assert compiled is not None
        assert compiled.status == "completed", (
            compiled.reason_code,
            compiled.detail,
        )
        lifecycle_tasks = {
            str(task["lifecycle_stage"]): task
            for task in state.list_tasks(product_id)
            if task.get("lifecycle_stage")
        }
        assert set(lifecycle_tasks) == {
            "architecture-review",
            "implementation-slice",
            "candidate-snapshot",
            "test",
            "security-review",
            "release-readiness-review",
            "staging",
            "product-acceptance",
            "production",
            "observation",
        }
        runner.outputs.extend(
            [
                _review_output(
                    config,
                    product_id,
                    str(lifecycle_tasks["architecture-review"]["task_id"]),
                ),
                _attempt_output(
                    config,
                    product_id,
                    str(lifecycle_tasks["implementation-slice"]["task_id"]),
                ),
                _test_output(
                    config,
                    product_id,
                    str(lifecycle_tasks["test"]["task_id"]),
                ),
                _security_output(
                    config,
                    product_id,
                    str(lifecycle_tasks["security-review"]["task_id"]),
                ),
                _review_output(
                    config,
                    product_id,
                    str(lifecycle_tasks["release-readiness-review"]["task_id"]),
                ),
                _release_proposal(config, product_id, "staging"),
                _product_test_output(
                    config,
                    product_id,
                    environment="staging",
                ),
                _release_proposal(config, product_id, "production"),
                _product_test_output(
                    config,
                    product_id,
                    environment="production",
                ),
            ]
        )
        capability_reconciler.reconcile_once()
        reconciler = PipelineReconciler(config, state, artifacts)
        for _ in range(14):
            if str(state.get_product(product_id)["status"]) == "COMPLETED":
                break
            reconciler.reconcile_once()
            result = worker.run_once()
            assert result is not None, {
                str(task.get("lifecycle_stage")): (
                    task.get("graph_status"),
                    task.get("blocked_reason"),
                    task.get("blocked_ref"),
                )
                for task in state.list_tasks(product_id)
                if task.get("lifecycle_stage")
            }
            assert result.status == "completed", (
                result.reason_code,
                result.detail,
            )
        completed = state.get_product(product_id)
        assert completed is not None
        assert completed["status"] == "COMPLETED"
        assert completed["repository_visibility"] == "private"
        assert completed["completion_evidence_ref"]
        assert [call[0] for call in repository.calls] == [
            "create",
            "clone",
            "bootstrap",
        ]
        assert release.calls == [
            "pull_request",
            "checks",
            "staging",
            "merge",
            "production",
        ]
        assert any(
            task["stage_key"] == "observation"
            and task["graph_status"] == "ACCEPTED"
            for task in state.list_tasks(product_id)
        )
        assert not any(
            event["event_type"] == "worker_restarted"
            for event in state.events(product_id)
        )
    finally:
        state.close()


def test_AUT_P1_010_external_side_effects_are_idempotent(
    tmp_path: Path,
) -> None:
    config = configured(tmp_path)
    state = StateStore(config.database_path)
    repository = FakeRepositoryAdapter()
    effects = IdempotentSideEffects()
    try:
        create_v2_product(state, product_id="idempotent-effects-product")
        bootstrap = RepositoryBootstrapper(config, state, repository)
        first = bootstrap.ensure(
            "idempotent-effects-product",
            tmp_path / "effects-workspace",
        )
        second = bootstrap.ensure(
            "idempotent-effects-product",
            tmp_path / "effects-workspace",
        )
        assert first == second
        identity = str(first["bootstrap_sha"])
        for operation in (
            "push",
            "pull_request",
            "merge",
            "staging",
            "production",
        ):
            assert effects.execute(operation, identity) == effects.execute(
                operation,
                identity,
            )
        assert [call[0] for call in repository.calls].count("create") == 1
        assert [call[0] for call in repository.calls].count("bootstrap") == 1
        assert len(effects.calls) == 5
    finally:
        state.close()


def test_AUT_ARCH_001_canonical_v2_path_excludes_legacy_heuristics() -> None:
    from factory.autonomy import AutonomyStore
    from factory.pipeline import PipelineCoordinator
    from factory.repository import RepositoryBootstrapper

    worker_source = inspect.getsource(AgentWorker.run_once)
    outcome_source = inspect.getsource(AutonomyStore.commit_task_outcome)
    router_source = inspect.getsource(FailureRouter.route)
    prepare_source = inspect.getsource(PipelineCoordinator.prepare_after)
    bootstrap_source = inspect.getsource(RepositoryBootstrapper.ensure)

    assert "advance_after" not in worker_source
    assert "latest_task" not in outcome_source
    assert "latest_task" not in router_source
    assert "next_repair_cycle" not in router_source
    assert "task.get(\"title\")" not in prepare_source
    assert "copytree" not in bootstrap_source
    assert 'role = "replanner"' in router_source
    assert '"observation"' in prepare_source
    assert "commit_task_outcome" in inspect.getsource(AgentWorker.run_once)
    assert hasattr(PipelineCoordinator, "advance_after_legacy_v1")
    assert not hasattr(PipelineCoordinator, "advance_after")
