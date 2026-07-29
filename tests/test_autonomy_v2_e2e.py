from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

from test_autonomy_v2 import (
    FakePrivateRepositoryAdapter,
    FakeRepositoryAdapter,
    create_v2_product,
    executable_plan,
    persist_and_ingest_plan,
)
from test_worker import make_config, selected_registry

from factory.artifacts import ArtifactStore
from factory.autonomy import FailureData, HypothesisData, TaskOutcome
from factory.common import sha256_text
from factory.failure_router import FailureRouter
from factory.intake import IntakeService
from factory.reconciler import PipelineReconciler
from factory.repository import RepositoryBootstrapper
from factory.state import StateStore
from factory.worker import AgentWorker
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


def test_AUT_P1_008_controller_incident_does_not_consume_semantic_budget(
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
        assert len(routed) == 1
        incident_task = state.get_task(routed[0])
        assert incident_task is not None
        assert incident_task["role"] == "incident-recovery"
        assert incident_task["capability_profile"] == "controller_incident"
        assert state.list_hypotheses("product-autonomy") == []
        with state._lock:
            incidents = state._connection.execute(
                "SELECT reason_code, status FROM controller_incidents",
            ).fetchall()
        assert [tuple(row) for row in incidents] == [
            ("controller_schema_corruption", "OPEN")
        ]
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
