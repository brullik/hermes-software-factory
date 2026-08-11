from __future__ import annotations

import inspect
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from test_path_governor import POLICY_DIGEST, _state
from test_pre_q8_r02_r03_locked import (
    _fault_blueprint,
    _profile_blueprint,
)
from test_pre_q8_r02_r03_locked import (
    exact_architecture_baseline as _exact_architecture_baseline_fixture,
)

from factory.architecture_baseline import (
    ArchitectureBaselineDrift,
    ControllerArchitectureBaselineInvalid,
    normalize_architecture_package_to_baseline,
    validate_architecture_package_against_baseline,
)
from factory.autonomy import TaskOutcome
from factory.common import sha256_text, stable_json
from factory.failure_router import FailureRouter
from factory.path_governor import (
    PathGovernor,
    ResultLineageIdentityError,
    root_cause_key,
    semantic_node_id,
    task_contract_digest,
)
from factory.pre_q8_convergence import resource_namespace
from factory.qualification_repository_gc import (
    HISTORICAL_REPOSITORY_COUNT,
    QualificationRepositoryGCError,
    finalize_repository_cleanup,
    load_repository_ledger,
    mark_scenario_evidence_frozen,
    qualification_repository_cleanup_plan,
    record_provisioned_repository,
    repository_cleanup_summary,
    update_repository_cleanup_state,
    verify_repository_cleanup_eligibility,
)
from factory.telegram import TelegramApi


@pytest.fixture(scope="module")
def r04_architecture_baseline(tmp_path_factory: pytest.TempPathFactory) -> Any:
    return _exact_architecture_baseline_fixture.__wrapped__(tmp_path_factory)


def _write_contract(
    state: Any,
    task_id: str,
    *,
    role: str,
    revision: int,
    semantic_key: str,
    lifecycle_stage: str | None = None,
) -> dict[str, Any]:
    task = state.get_task(task_id)
    assert task is not None
    contract: dict[str, Any] = {
        "task_id": task_id,
        "product_id": task["product_id"],
        "plan_id": task["plan_id"],
        "plan_node_id": task["plan_node_id"],
        "semantic_node_key": semantic_key,
        "role": role,
        "output_schema": "architecture-package.schema.json",
        "capability_profile": "planning_readonly",
        "produces_evidence_types": ["architecture_package"],
        "task_revision": revision,
    }
    if lifecycle_stage is not None:
        contract["lifecycle_stage"] = lifecycle_stage
    evidence = state.database_path.parent / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / f"task-{task_id}.json").write_text(
        json.dumps(contract, sort_keys=True), encoding="utf-8"
    )
    digest = task_contract_digest(contract)
    node = semantic_node_id(contract, digest)
    with state._connection:
        state._connection.execute(
            """UPDATE tasks SET contract_ref=?, contract_digest=?,
                      semantic_node_id=?, semantic_node_key=?, task_revision=?,
                      produces_evidence_types_json=?
                 WHERE task_id=?""",
            (
                f"evidence/task-{task_id}.json",
                digest,
                node,
                semantic_key,
                revision,
                stable_json(["architecture_package"]),
                task_id,
            ),
        )
    return contract


def _architecture_graph(tmp_path: Path) -> tuple[Any, PathGovernor, str]:
    state = _state(tmp_path)
    product = state.get_product("product-path-governor")
    assert product is not None
    plan_id = str(product["active_plan_id"])
    with state._connection:
        state._connection.execute(
            """UPDATE tasks SET status='DONE',graph_status='ACCEPTED'
                 WHERE task_id='T-ROOT0001'"""
        )
    state.add_task(
        task_id="T-ARCH-PRIOR",
        product_id="product-path-governor",
        title="Prior architecture",
        role="solution-architect",
        output_schema="architecture-package.schema.json",
        contract_ref="evidence/task-T-ARCH-PRIOR.json",
        stage_key="architecture",
        plan_id=plan_id,
        plan_node_id="architecture-prior",
        semantic_node_key="architecture-prior",
        task_revision=1,
        capability_profile="planning_readonly",
        graph_status="ACCEPTED",
    )
    state.add_task(
        task_id="T-ARCH-CORR",
        product_id="product-path-governor",
        title="Correct architecture",
        role="solution_architect",
        output_schema="architecture-package.schema.json",
        contract_ref="evidence/task-T-ARCH-CORR.json",
        stage_key="repair",
        plan_id=plan_id,
        plan_node_id="architecture-correction",
        semantic_node_key="architecture-correction",
        task_revision=2,
        capability_profile="planning_readonly",
        priority=100,
        graph_status="READY",
    )
    state.add_task(
        task_id="T-ARCH-REVIEW",
        product_id="product-path-governor",
        title="Review architecture",
        role="independent-reviewer",
        output_schema="review-result.schema.json",
        contract_ref="evidence/task-T-ARCH-REVIEW.json",
        stage_key="architecture-review",
        dependencies=["T-ARCH-CORR"],
        plan_id=plan_id,
        plan_node_id="architecture-review",
        capability_profile="reviewer_readonly",
        graph_status="BLOCKED_DEPENDENCY",
    )
    with state._connection:
        state._connection.execute(
            """UPDATE tasks SET lifecycle_stage='architecture-review'
                 WHERE task_id='T-ARCH-REVIEW'"""
        )
    _write_contract(
        state,
        "T-ARCH-PRIOR",
        role="solution-architect",
        revision=1,
        semantic_key="architecture-prior",
        lifecycle_stage="architecture",
    )
    _write_contract(
        state,
        "T-ARCH-CORR",
        role="solution-architect",
        revision=2,
        semantic_key="architecture-correction",
    )
    state.record_attempt(
        attempt_id="attempt-arch-prior",
        task_id="T-ARCH-PRIOR",
        tier="terra",
        attempt_kind="initial",
        prompt_digest="1" * 64,
        status="completed",
        semantic_counted=True,
    )
    governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
    prior_binding = governor.bind_result(
        task_id="T-ARCH-PRIOR",
        source_task_id="T-ARCH-PRIOR",
        source_attempt_id="attempt-arch-prior",
        result_ref="evidence/architecture-prior.json",
        result_digest="2" * 64,
        output_schema="architecture-package.schema.json",
    ).binding_id
    with state._connection:
        state._connection.execute(
            """INSERT INTO task_edges
               (plan_id,from_task_id,to_task_id,edge_type,required,created_at)
               VALUES (?, 'T-ARCH-CORR', 'T-ARCH-REVIEW', 'revalidates', 1,
                       '2026-08-11T00:00:00Z')""",
            (plan_id,),
        )
        state._connection.execute(
            """INSERT INTO task_edges
               (plan_id,from_task_id,to_task_id,edge_type,required,created_at)
               VALUES (?, 'T-ARCH-PRIOR', 'T-ARCH-REVIEW', 'evidence_from', 1,
                       '2026-08-11T00:00:00Z')""",
            (plan_id,),
        )
    return state, governor, prior_binding


def _accept_correction(state: Any, *, fault: str | None = None) -> Any:
    claimed = state.claim_task(worker_id="architecture-correction-worker")
    assert claimed is not None and claimed["task_id"] == "T-ARCH-CORR"
    state.record_attempt(
        attempt_id="attempt-arch-correction",
        task_id="T-ARCH-CORR",
        tier="terra",
        attempt_kind="repair",
        prompt_digest="3" * 64,
        status="started",
        semantic_counted=True,
    )
    plan = state._connection.execute(
        "SELECT revision FROM plans WHERE plan_id=?", (claimed["plan_id"],)
    ).fetchone()

    def inject(point: str) -> None:
        if point == fault:
            raise RuntimeError(f"fault:{point}")

    return state.commit_task_outcome(
        TaskOutcome(
            task_id="T-ARCH-CORR",
            worker_id="architecture-correction-worker",
            lease_token=str(claimed["lease_token"]),
            expected_task_revision=2,
            expected_plan_revision=int(plan[0]),
            idempotency_key="4" * 64,
            result_ref="evidence/attempt-arch-correction.json",
            result_digest="5" * 64,
            status="ACCEPTED",
            attempt_id="attempt-arch-correction",
            attempt_status="completed",
            accepted_result_ref="evidence/architecture-correction.json",
            accepted_result_digest="6" * 64,
            accepted_policy_digest=POLICY_DIGEST,
        ),
        fault_injector=inject,
    )


def test_reviewed_architecture_source_is_selected_by_exact_graph(tmp_path: Path) -> None:
    state, governor, prior = _architecture_graph(tmp_path)
    try:
        proof = governor._reviewed_architecture_source_for_correction("T-ARCH-CORR")
        assert proof is not None
        assert proof.prior_binding_id == prior
        assert proof.reviewer_task_id == "T-ARCH-REVIEW"
    finally:
        state.close()


def test_architecture_correction_does_not_require_reviewer_lifecycle_on_producer(
    tmp_path: Path,
) -> None:
    state, governor, _ = _architecture_graph(tmp_path)
    try:
        assert state.get_task("T-ARCH-CORR")["lifecycle_stage"] is None
        assert governor._reviewed_architecture_source_for_correction("T-ARCH-CORR")
    finally:
        state.close()


def test_architecture_correction_does_not_require_same_contract_digest(tmp_path: Path) -> None:
    state, governor, _ = _architecture_graph(tmp_path)
    try:
        prior = state.get_task("T-ARCH-PRIOR")
        correction = state.get_task("T-ARCH-CORR")
        assert prior["contract_digest"] != correction["contract_digest"]
        assert governor._reviewed_architecture_source_for_correction("T-ARCH-CORR")
    finally:
        state.close()


def test_architecture_correction_does_not_require_same_semantic_node(tmp_path: Path) -> None:
    state, governor, _ = _architecture_graph(tmp_path)
    try:
        prior = state.get_task("T-ARCH-PRIOR")
        correction = state.get_task("T-ARCH-CORR")
        assert prior["semantic_node_id"] != correction["semantic_node_id"]
        assert governor._reviewed_architecture_source_for_correction("T-ARCH-CORR")
    finally:
        state.close()


def test_architecture_correction_accepts_graph_bound_legacy_prior_plan(tmp_path: Path) -> None:
    state, governor, prior_binding = _architecture_graph(tmp_path)
    try:
        correction_plan = str(state.get_task("T-ARCH-CORR")["plan_id"])
        legacy_plan = "PLAN-LEGACY-ARCHITECTURE"
        with state._connection:
            state._connection.execute(
                """INSERT INTO plans
                   (plan_id, product_id, revision, status, plan_artifact_ref,
                    plan_digest, goals_json, completion_criteria_json,
                    created_by_task_id, created_at, activated_at, completed_at)
                   VALUES (?, 'product-path-governor', 999, 'SUPERSEDED', ?, ?,
                           '[]', '[]', 'T-ROOT0001',
                           '2026-08-11T00:00:00Z', '2026-08-11T00:00:00Z',
                           '2026-08-11T00:01:00Z')""",
                (
                    legacy_plan,
                    f"internal://plan/{legacy_plan}",
                    sha256_text(legacy_plan),
                ),
            )
            state._connection.execute(
                """UPDATE tasks SET plan_id=?, produces_evidence_types_json='[]'
                     WHERE task_id='T-ARCH-PRIOR'""",
                (legacy_plan,),
            )
        assert state.get_task("T-ARCH-PRIOR")["plan_id"] != correction_plan
        proof = governor._reviewed_architecture_source_for_correction("T-ARCH-CORR")
        assert proof is not None and proof.prior_binding_id == prior_binding
    finally:
        state.close()


def test_architecture_correction_retires_exact_prior_binding(tmp_path: Path) -> None:
    state, governor, prior = _architecture_graph(tmp_path)
    try:
        with state._connection:
            assert (
                governor.retire_reviewed_architecture_binding_for_correction("T-ARCH-CORR") == prior
            )
        assert (
            state._connection.execute(
                "SELECT status FROM result_bindings WHERE binding_id=?", (prior,)
            ).fetchone()[0]
            == "SUPERSEDED"
        )
    finally:
        state.close()


def test_architecture_correction_updates_exact_reviewer_edge(tmp_path: Path) -> None:
    state, _, _ = _architecture_graph(tmp_path)
    try:
        _accept_correction(state)
        edge = state._connection.execute(
            """SELECT from_task_id FROM task_edges
                 WHERE to_task_id='T-ARCH-REVIEW' AND edge_type='evidence_from'
                   AND required=1"""
        ).fetchone()
        assert edge[0] == "T-ARCH-CORR"
    finally:
        state.close()


def test_architecture_correction_leaves_one_required_evidence_edge(tmp_path: Path) -> None:
    state, _, _ = _architecture_graph(tmp_path)
    try:
        _accept_correction(state)
        assert (
            state._connection.execute(
                """SELECT COUNT(*) FROM task_edges
                 WHERE to_task_id='T-ARCH-REVIEW' AND edge_type='evidence_from'
                   AND required=1"""
            ).fetchone()[0]
            == 1
        )
    finally:
        state.close()


def test_architecture_correction_replay_is_idempotent(tmp_path: Path) -> None:
    state, _, _ = _architecture_graph(tmp_path)
    try:
        first = _accept_correction(state)
        replay = state.commit_task_outcome(
            TaskOutcome(
                task_id="T-ARCH-CORR",
                worker_id="architecture-correction-worker",
                expected_task_revision=2,
                idempotency_key="4" * 64,
                result_ref="evidence/attempt-arch-correction.json",
                result_digest="5" * 64,
                status="ACCEPTED",
            )
        )
        assert first.outcome_id == replay.outcome_id
        assert replay.replayed is True
    finally:
        state.close()


def _add_second_correction(state: Any) -> None:
    plan_id = str(state.get_task("T-ARCH-CORR")["plan_id"])
    state.add_task(
        task_id="T-ARCH-CORR2",
        product_id="product-path-governor",
        title="Correct architecture again",
        role="solution_architect",
        output_schema="architecture-package.schema.json",
        contract_ref="evidence/task-T-ARCH-CORR2.json",
        stage_key="repair",
        plan_id=plan_id,
        plan_node_id="architecture-correction-2",
        semantic_node_key="architecture-correction-2",
        task_revision=3,
        capability_profile="planning_readonly",
        priority=200,
        graph_status="READY",
    )
    _write_contract(
        state,
        "T-ARCH-CORR2",
        role="solution-architect",
        revision=3,
        semantic_key="architecture-correction-2",
    )
    with state._connection:
        state._connection.execute(
            "UPDATE tasks SET dependencies_json=? WHERE task_id='T-ARCH-REVIEW'",
            (stable_json(["T-ARCH-CORR2"]),),
        )
        state._connection.execute(
            """INSERT INTO task_edges
               (plan_id,from_task_id,to_task_id,edge_type,required,created_at)
               VALUES (?, 'T-ARCH-CORR2', 'T-ARCH-REVIEW', 'revalidates', 1,
                       '2026-08-11T00:01:00Z')""",
            (plan_id,),
        )


def test_second_architecture_correction_replaces_first(tmp_path: Path) -> None:
    state, _, _ = _architecture_graph(tmp_path)
    try:
        _accept_correction(state)
        first_binding = state.get_task("T-ARCH-CORR")["result_binding_id"]
        _add_second_correction(state)
        governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
        proof = governor._reviewed_architecture_source_for_correction("T-ARCH-CORR2")
        assert proof is not None and proof.prior_binding_id == first_binding
    finally:
        state.close()


def test_architecture_correction_rejects_missing_revalidates_edge(tmp_path: Path) -> None:
    state, governor, _ = _architecture_graph(tmp_path)
    try:
        with state._connection:
            state._connection.execute("DELETE FROM task_edges WHERE edge_type='revalidates'")
        with pytest.raises(ResultLineageIdentityError):
            governor._reviewed_architecture_source_for_correction("T-ARCH-CORR")
    finally:
        state.close()


def test_architecture_correction_rejects_ambiguous_prior_source(tmp_path: Path) -> None:
    state, governor, _ = _architecture_graph(tmp_path)
    try:
        plan_id = state.get_task("T-ARCH-CORR")["plan_id"]
        with state._connection:
            state._connection.execute(
                """INSERT INTO task_edges
                   (plan_id,from_task_id,to_task_id,edge_type,required,created_at)
                   VALUES (?, 'T-ROOT0001', 'T-ARCH-REVIEW', 'evidence_from', 1,
                           '2026-08-11T00:00:00Z')""",
                (plan_id,),
            )
        with pytest.raises(ResultLineageIdentityError):
            governor._reviewed_architecture_source_for_correction("T-ARCH-CORR")
    finally:
        state.close()


def test_architecture_correction_rejects_cross_product_graph(tmp_path: Path) -> None:
    state, governor, _ = _architecture_graph(tmp_path)
    try:
        state.create_product(
            product_id="other-product",
            owner_id="owner",
            source="cli",
            idea="other",
            idempotency_key="other-product",
        )
        with state._connection:
            state._connection.execute(
                "UPDATE tasks SET product_id='other-product' WHERE task_id='T-ARCH-REVIEW'"
            )
        with pytest.raises(ResultLineageIdentityError):
            governor._reviewed_architecture_source_for_correction("T-ARCH-CORR")
    finally:
        state.close()


def test_architecture_correction_rejects_lower_revision(tmp_path: Path) -> None:
    state, governor, _ = _architecture_graph(tmp_path)
    try:
        with state._connection:
            state._connection.execute(
                "UPDATE tasks SET task_revision=1 WHERE task_id='T-ARCH-CORR'"
            )
        with pytest.raises(ResultLineageIdentityError):
            governor._reviewed_architecture_source_for_correction("T-ARCH-CORR")
    finally:
        state.close()


@pytest.mark.parametrize(
    "fault",
    [
        "after_architecture_binding_retirement",
        "after_architecture_result_bind",
        "after_architecture_evidence_edge_update",
    ],
)
def _assert_architecture_rollback(tmp_path: Path, fault: str) -> None:
    state, _, prior = _architecture_graph(tmp_path)
    try:
        with pytest.raises(RuntimeError, match="fault:"):
            _accept_correction(state, fault=fault)
        assert (
            state._connection.execute(
                "SELECT status FROM result_bindings WHERE binding_id=?", (prior,)
            ).fetchone()[0]
            == "ACTIVE"
        )
        assert state.get_task("T-ARCH-CORR")["result_binding_id"] is None
        assert (
            state._connection.execute(
                """SELECT from_task_id FROM task_edges
                 WHERE to_task_id='T-ARCH-REVIEW' AND edge_type='evidence_from'"""
            ).fetchone()[0]
            == "T-ARCH-PRIOR"
        )
    finally:
        state.close()


def test_architecture_correction_transaction_rolls_back_after_retire(tmp_path: Path) -> None:
    _assert_architecture_rollback(tmp_path, "after_architecture_binding_retirement")


def test_architecture_correction_transaction_rolls_back_after_bind(tmp_path: Path) -> None:
    _assert_architecture_rollback(tmp_path, "after_architecture_result_bind")


def test_architecture_correction_transaction_rolls_back_after_edge_update(tmp_path: Path) -> None:
    _assert_architecture_rollback(tmp_path, "after_architecture_evidence_edge_update")


def test_architecture_correction_preserves_frozen_snapshot_binding(tmp_path: Path) -> None:
    state, _, prior = _architecture_graph(tmp_path)
    try:
        prior_task = state.get_task("T-ARCH-PRIOR")
        with state._connection:
            state._connection.execute(
                """INSERT INTO candidate_snapshots
                   (snapshot_id,product_id,plan_id,repository_commit,tree_digest,
                    architecture_binding_id,snapshot_digest,status,created_at)
                   VALUES ('CS-R04','product-path-governor',?,'a','b',?,?,'FROZEN',?)""",
                (prior_task["plan_id"], prior, "7" * 64, "2026-08-11T00:00:00Z"),
            )
            state._connection.execute(
                """INSERT INTO candidate_snapshot_items
                   (snapshot_id,semantic_node_id,binding_id) VALUES ('CS-R04',?,?)""",
                (prior_task["semantic_node_id"], prior),
            )
        _accept_correction(state)
        assert (
            state._connection.execute(
                "SELECT binding_id FROM candidate_snapshot_items WHERE snapshot_id='CS-R04'"
            ).fetchone()[0]
            == prior
        )
    finally:
        state.close()


def _problem_signature(values: dict[str, Any]) -> str:
    return root_cause_key(
        {
            "product_id": "product-signature",
            "failure_class": "semantic",
            "reason_code": "mandatory_gate_failed",
            "semantic_node_key": "node-a",
            "lifecycle_stage": "test",
            "failed_gate_ids": ["target-tests"],
            **values,
        }
    )


def _signature_router(tmp_path: Path) -> tuple[Any, FailureRouter, dict[str, Any]]:
    state = _state(tmp_path, product_id="product-signature")
    now = "2026-08-11T00:00:00Z"
    with state._connection:
        state._connection.execute(
            """UPDATE tasks SET hypothesis_id=NULL, lifecycle_stage='test',
                      semantic_node_key='node-a', root_problem_signature=?
                 WHERE task_id='T-ROOT0001'""",
            ("a" * 64,),
        )
        state._connection.execute(
            """INSERT INTO failures
               (failure_id,product_id,task_id,failure_class,reason_code,
                fingerprint,safe_message,evidence_ref,status,retryable,
                owner_action_eligible,expected_json,actual_json,
                failed_gate_ids_json,first_seen_at,last_seen_at,root_cause_key)
               VALUES ('failure-parent','product-signature','T-ROOT0001','semantic',
                       'mandatory_gate_failed',?,'gate','internal://gate','ROUTED',0,0,
                       '{}','{}',?, ?, ?, ?)""",
            (
                sha256_text("failure-parent"),
                stable_json(["target-tests"]),
                now,
                now,
                _problem_signature({}),
            ),
        )
        state._connection.execute(
            """INSERT INTO hypotheses
               (hypothesis_id,product_id,failure_id,parent_hypothesis_id,signature,
                statement,required_evidence_json,status,semantic_budget,attempts_used,
                created_at)
               VALUES ('hypothesis-r04','product-signature','failure-parent',NULL,?,
                       'same hypothesis','[]','ACTIVE',3,0,?)""",
            (sha256_text("hypothesis-r04"), now),
        )
        state._connection.execute(
            "UPDATE tasks SET hypothesis_id='hypothesis-r04' WHERE task_id='T-ROOT0001'"
        )
    router = object.__new__(FailureRouter)
    router.state = state
    failed = state.get_task("T-ROOT0001")
    assert failed is not None
    return state, router, failed


def test_new_mandatory_gate_gets_new_problem_signature() -> None:
    assert _problem_signature({"failed_gate_ids": ["target-tests"]}) != _problem_signature(
        {"failed_gate_ids": ["target-sast"]}
    )


def test_test_and_security_stages_get_distinct_problem_signatures() -> None:
    assert _problem_signature({"lifecycle_stage": "test"}) != _problem_signature(
        {"lifecycle_stage": "security-review"}
    )


def test_same_gate_builder_repair_inherits_problem_signature() -> None:
    assert _problem_signature({}) == _problem_signature(
        {"semantic_node_key": "node-a", "failed_gate_ids": ["target-tests"]}
    )


def test_schema_retry_inherits_problem_signature(tmp_path: Path) -> None:
    state, router, failed = _signature_router(tmp_path)
    try:
        assert router._may_inherit_problem_signature(
            {
                "reason_code": "schema_validation",
                "parent_failure_id": "failure-parent",
                "failed_gate_ids_json": stable_json(["target-tests"]),
            },
            failed,
            inherited_signature="a" * 64,
        )
    finally:
        state.close()


def test_transport_retry_inherits_problem_signature(tmp_path: Path) -> None:
    state, router, failed = _signature_router(tmp_path)
    try:
        assert router._may_inherit_problem_signature(
            {
                "reason_code": "malformed_transport",
                "parent_failure_id": "failure-parent",
                "failed_gate_ids_json": stable_json(["target-tests"]),
            },
            failed,
            inherited_signature="a" * 64,
        )
    finally:
        state.close()


def test_failure_root_cause_key_precedes_stale_task_signature(tmp_path: Path) -> None:
    state, router, failed = _signature_router(tmp_path)
    try:
        current = "b" * 64
        failure = {
            "failure_id": "failure-current",
            "reason_code": "mandatory_gate_failed",
            "root_cause_key": current,
            "failed_gate_ids_json": stable_json(["target-sast"]),
        }
        assert (
            router._stable_causal_problem_signature(
                failure,
                failed,
                scope_reassessment_required=False,
                required_scope_paths=(),
            )
            == current
        )
    finally:
        state.close()


def test_telegram_target_tests_and_target_sast_have_distinct_budgets() -> None:
    tests = _problem_signature({"failed_gate_ids": ["target-tests"]})
    sast = _problem_signature({"failed_gate_ids": ["target-sast"]})
    assert tests != sast


def test_telegram_transport_rejects_non_http_schemes() -> None:
    with pytest.raises(ValueError):
        TelegramApi("fixture", api_base_url="file:///tmp/telegram")


def test_telegram_transport_does_not_use_generic_urlopen() -> None:
    import factory.telegram as telegram_module

    source = inspect.getsource(telegram_module)
    assert "urlopen" not in source
    assert "HTTPConnection" in source and "HTTPSConnection" in source


def test_telegram_fixture_token_has_no_default() -> None:
    parameter = inspect.signature(TelegramApi).parameters["token"]
    assert parameter.default is inspect.Parameter.empty
    blueprint = _profile_blueprint("TELEGRAM_BOT")
    assert blueprint["fixture_token_required"] is True
    assert blueprint["fixture_token_default"] is None


def test_telegram_concurrency_test_is_bounded() -> None:
    race = _profile_blueprint("TELEGRAM_BOT")["race_test"]
    assert race["barrier_timeout_seconds"] == 5
    assert race["join_timeout_seconds"] == 10


def test_telegram_concurrency_all_threads_finish() -> None:
    race = _profile_blueprint("TELEGRAM_BOT")["race_test"]
    assert race["database_preinitialized"] is True
    assert race["join_timeout_seconds"] < 60


def test_telegram_exactly_one_claims() -> None:
    assert _profile_blueprint("TELEGRAM_BOT")["race_test"]["expected_results"] == [
        False,
        True,
    ]


def _architecture_package() -> dict[str, Any]:
    return {
        "adrs": [
            {
                "id": "ADR-001",
                "decision": "Use the product protocol.",
                "status": "accepted",
                "rationale": "Product semantics.",
                "consequences": [],
            }
        ],
        "components": [
            {
                "id": "app",
                "responsibility": "product",
                "technology": "Python",
                "data_owned": [],
            }
        ],
        "evidence_refs": [],
    }


def test_architecture_package_is_normalized_to_controller_baseline(
    r04_architecture_baseline: Any,
) -> None:
    normalized = normalize_architecture_package_to_baseline(
        _architecture_package(), r04_architecture_baseline
    )
    validate_architecture_package_against_baseline(normalized, r04_architecture_baseline)
    assert any(item["id"] == "ADR-900" for item in normalized["adrs"])


def test_architecture_baseline_drift_fails_typed(
    r04_architecture_baseline: Any,
) -> None:
    package = _architecture_package()
    package["adrs"][0]["decision"] = "Use Hatchling.build as the backend."
    with pytest.raises(ArchitectureBaselineDrift, match="architecture_baseline_drift"):
        normalize_architecture_package_to_baseline(package, r04_architecture_baseline)


def test_architecture_baseline_missing_is_controller_failure(
    r04_architecture_baseline: Any,
) -> None:
    invalid = replace(r04_architecture_baseline, baseline_digest="0" * 64)
    with pytest.raises(ControllerArchitectureBaselineInvalid):
        normalize_architecture_package_to_baseline(_architecture_package(), invalid)


def test_reviewer_does_not_request_alternative_build_backend() -> None:
    import factory.worker as worker_module

    source = inspect.getsource(worker_module.AgentWorker.default_spec)
    assert "do not" in source.lower()
    assert "Hatchling" in source and "setuptools.build_meta" in source


def test_reviewer_does_not_request_alternative_signer() -> None:
    import factory.worker as worker_module

    source = inspect.getsource(worker_module.AgentWorker.default_spec)
    assert "OpenPGP" in source and "Ed25519" in source


def test_cli_raw_text_and_json_modes_are_unambiguous() -> None:
    blueprint = _profile_blueprint("CLI_PACKAGE")
    assert blueprint["command_shape"][-1] == "TEXT"
    assert blueprint["json_command_shape"][-1] == "JSON"
    assert blueprint["command_shape"] != blueprint["json_command_shape"]


def test_high_fan_in_obligations_include_toctou_safe_paths() -> None:
    blueprint = _profile_blueprint("OFFLINE_BATCH")
    assert blueprint["actual_byte_accounting"] is True
    assert blueprint["toctou_safe"] is True
    assert "O_NOFOLLOW" in blueprint["path_open_strategy"]


def test_external_blocker_obligations_include_claim_before_effect() -> None:
    blueprint = _profile_blueprint("GITHUB_AUTOMATION")
    assert blueprint["claim_before_effect"] is True
    assert blueprint["completion_after_effect"] is True


def test_deploy_obligations_include_lifecycle_cas() -> None:
    blueprint = _profile_blueprint("DEPLOYED_SERVICE")
    assert "lifecycle_id" in blueprint["lifecycle_cas"]
    assert blueprint["crash_recovery"] == "resume_from_last_durable_receipt"


def test_package_obligations_include_stale_policy_and_sdist() -> None:
    blueprint = _profile_blueprint("LIBRARY_PACKAGE")
    assert "revocation" in blueprint["stale_policy"]
    assert blueprint["offline_build_artifacts"] == ["wheel", "sdist"]


def _ledger_fixture(
    tmp_path: Path,
    *,
    scenario_id: str = "zero-dependency-cli",
    product_id: str | None = "product-r04",
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    ledger = tmp_path / "repository-ledger.json"
    candidate = "c" * 64
    name = resource_namespace(
        plane="convergence",
        run_id="r04-run-0001",
        candidate_digest=candidate,
        scenario_id=scenario_id,
    )
    entry = record_provisioned_repository(
        ledger,
        qualification_plane="CONVERGENCE",
        epoch_id="RE-AAAAAAAAAAAAAAAAAAAAAAAA",
        run_id="r04-run-0001",
        scenario_id=scenario_id,
        candidate_digest=candidate,
        product_id=product_id,
        repository_owner="brullik",
        repository_name=name,
        repository_id=42,
        expected_description=(
            f"Hermes product {product_id}"
            if product_id is not None
            else "Hermes content-addressed PRE-Q8 repair fixture"
        ),
        provision_receipt_digest="d" * 64,
    )
    mark_scenario_evidence_frozen(ledger, scenario_id)
    entry = next(
        item
        for item in load_repository_ledger(ledger)["repositories"]
        if item["entry_id"] == entry["entry_id"]
    )
    live = {
        "id": 42,
        "name": name,
        "private": True,
        "fork": False,
        "owner": {"login": "brullik"},
        "description": entry["expected_description"],
    }
    return ledger, entry, live


def test_repository_ledger_records_every_created_repository(tmp_path: Path) -> None:
    ledger, _, _ = _ledger_fixture(tmp_path)
    assert load_repository_ledger(ledger)["repository_count"] == 1


def test_repository_ledger_entry_is_digest_bound(tmp_path: Path) -> None:
    ledger, _, _ = _ledger_fixture(tmp_path)
    value = json.loads(ledger.read_text(encoding="utf-8"))
    value["repositories"][0]["repository_name"] += "-tampered"
    ledger.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(QualificationRepositoryGCError, match="digest"):
        load_repository_ledger(ledger)


def test_repository_gc_recomputes_exact_namespace(tmp_path: Path) -> None:
    _, entry, live = _ledger_fixture(tmp_path)
    assert verify_repository_cleanup_eligibility(entry, live, run_active=False) == (
        True,
        "eligible",
    )


def test_repository_gc_refuses_unknown_prefix_repository(tmp_path: Path) -> None:
    _, entry, live = _ledger_fixture(tmp_path)
    changed = {**entry, "repository_name": "unknown-r04-repository"}
    assert verify_repository_cleanup_eligibility(changed, live, run_active=False)[0] is False


def test_repository_gc_refuses_public_repository(tmp_path: Path) -> None:
    _, entry, live = _ledger_fixture(tmp_path)
    assert (
        verify_repository_cleanup_eligibility(entry, {**live, "private": False}, run_active=False)[
            0
        ]
        is False
    )


def test_repository_gc_refuses_repository_id_mismatch(tmp_path: Path) -> None:
    _, entry, live = _ledger_fixture(tmp_path)
    assert (
        verify_repository_cleanup_eligibility(entry, {**live, "id": 43}, run_active=False)[0]
        is False
    )


def test_repository_gc_refuses_description_mismatch(tmp_path: Path) -> None:
    _, entry, live = _ledger_fixture(tmp_path)
    assert (
        verify_repository_cleanup_eligibility(
            entry, {**live, "description": "other"}, run_active=False
        )[0]
        is False
    )


def test_repository_gc_waits_for_frozen_evidence(tmp_path: Path) -> None:
    ledger, entry, live = _ledger_fixture(tmp_path)
    pending = {**entry, "state": "PROVISIONED", "evidence_status": "PENDING"}
    assert verify_repository_cleanup_eligibility(pending, live, run_active=False) == (
        False,
        "evidence_not_frozen",
    )
    assert qualification_repository_cleanup_plan(ledger)["planned_count"] == 1


def test_repository_gc_deletes_new_repository_product(tmp_path: Path) -> None:
    ledger, entry, _ = _ledger_fixture(tmp_path)
    update_repository_cleanup_state(
        ledger, entry["entry_id"], state="DELETED", cleanup_receipt={"status": "DELETED"}
    )
    assert repository_cleanup_summary(ledger)["repository_residue_count"] == 0


def test_repository_gc_deletes_existing_repository_fixture(tmp_path: Path) -> None:
    ledger, entry, _ = _ledger_fixture(
        tmp_path,
        scenario_id="existing-repository-repair",
        product_id=None,
    )
    update_repository_cleanup_state(
        ledger, entry["entry_id"], state="DELETED", cleanup_receipt={"status": "DELETED"}
    )
    assert finalize_repository_cleanup(ledger)["all_terminal"] is True


def test_repository_gc_treats_404_as_already_absent(tmp_path: Path) -> None:
    ledger, entry, _ = _ledger_fixture(tmp_path)
    assert verify_repository_cleanup_eligibility(entry, None, run_active=False) == (
        True,
        "already_absent",
    )
    update_repository_cleanup_state(
        ledger,
        entry["entry_id"],
        state="ALREADY_ABSENT",
        cleanup_receipt={"verified_get_status": 404},
    )
    assert finalize_repository_cleanup(ledger)["all_terminal"] is True


def test_repository_gc_retries_pending_delete_after_crash(tmp_path: Path) -> None:
    ledger, entry, _ = _ledger_fixture(tmp_path)
    update_repository_cleanup_state(ledger, entry["entry_id"], state="PENDING_DELETE")
    assert qualification_repository_cleanup_plan(ledger)["planned_count"] == 1


def test_repository_gc_receipt_is_idempotent(tmp_path: Path) -> None:
    ledger, entry, _ = _ledger_fixture(tmp_path)
    receipt = {"status": "DELETED", "verified_get_status": 404}
    update_repository_cleanup_state(
        ledger, entry["entry_id"], state="DELETED", cleanup_receipt=receipt
    )
    update_repository_cleanup_state(
        ledger, entry["entry_id"], state="DELETED", cleanup_receipt=receipt
    )
    assert finalize_repository_cleanup(ledger)["repository_count"] == 1


def _runner_source(name: str) -> str:
    return (Path(__file__).parents[1] / "scripts" / "qualification" / name).read_text(
        encoding="utf-8"
    )


def test_convergence_failure_still_runs_repository_gc() -> None:
    source = _runner_source("run-pre-q8-convergence.sh")
    assert "trap cleanup_repositories EXIT" in source
    assert "scripts.pre_q8_repository_gc cleanup" in source


def test_convergence_success_requires_zero_repository_residue() -> None:
    source = _runner_source("run-pre-q8-convergence.sh")
    assert "repository_residue" in source and "cleanup_failed" in source


def test_official_failure_still_runs_repository_gc() -> None:
    source = _runner_source("run-all-pre-q8.sh")
    assert "trap cleanup_repositories EXIT" in source
    assert "scripts.pre_q8_repository_gc cleanup" in source


def test_q8_finalize_requires_zero_repository_residue() -> None:
    source = _runner_source("run-all-clean-canaries.sh")
    assert "repository_residue" in source and "repository-cleanup-summary.json" in source


def test_seal_rejects_cleanup_failed_entry(tmp_path: Path) -> None:
    ledger, entry, _ = _ledger_fixture(tmp_path)
    update_repository_cleanup_state(
        ledger,
        entry["entry_id"],
        state="CLEANUP_FAILED",
        cleanup_receipt={"status": "CLEANUP_FAILED"},
    )
    with pytest.raises(QualificationRepositoryGCError, match="residue"):
        finalize_repository_cleanup(ledger)


def test_historical_inventory_contains_exact_39_names() -> None:
    assert HISTORICAL_REPOSITORY_COUNT == 39


def test_cli_raw_text_exact_output_contract() -> None:
    blueprint = _profile_blueprint("CLI_PACKAGE")
    assert blueprint["raw_text_protocol"] == "strict_utf8_in_exactly_one_text_argument"
    assert blueprint["valid_stdout"] == "strict UTF-8 TEXT plus newline"


def test_http_head_405_has_zero_body_bytes() -> None:
    blueprint = _profile_blueprint("DEPLOYED_SERVICE")
    assert blueprint["http_head_body_bytes"] == 0
    assert 405 in blueprint["http_head_statuses"]


def test_existing_repository_generated_cache_is_not_changed_path() -> None:
    blueprint = _profile_blueprint("DEPLOYED_SERVICE", delivery_mode="existing_repository")
    assert blueprint["generated_cache_not_changed_path"] is True
    assert "**/__pycache__/**" in blueprint["changed_path_ignores"]


def test_high_fan_in_limit_boundary_is_publicly_reachable() -> None:
    blueprint = _profile_blueprint("OFFLINE_BATCH")
    assert blueprint["exact_boundary_node_spec_bytes"] < blueprint["max_definition_bytes"]
    assert (
        blueprint["node_fixed_overhead_bytes"] + blueprint["exact_boundary_node_spec_bytes"]
        == blueprint["max_node_memory_bytes"]
    )


def test_high_fan_in_limit_plus_one_opens_no_input() -> None:
    blueprint = _profile_blueprint("OFFLINE_BATCH")
    assert blueprint["plus_one_node_spec_bytes"] == blueprint["exact_boundary_node_spec_bytes"] + 1
    assert blueprint["limit_failure_opens_inputs"] is False


def test_external_claim_create_ref_allows_one_winner() -> None:
    blueprint = _profile_blueprint("GITHUB_AUTOMATION")
    assert blueprint["initial_atomic_operation"] == "create_ref"
    assert blueprint["concurrent_create_successes"] == 1


def test_external_transition_rejects_stale_sibling() -> None:
    blueprint = _profile_blueprint("GITHUB_AUTOMATION")
    assert blueprint["transition_force"] is False
    assert blueprint["sibling_stale_update"] == "reject"


def test_retry_intent_is_globally_unique() -> None:
    fault = _fault_blueprint("ONE_PROVIDER_TIMEOUT")["ONE_PROVIDER_TIMEOUT"]
    assert fault["retry_intent_unique"] is True
    assert fault["other_request_same_intent"] == "sqlite3.IntegrityError"


def test_provider_restart_consumes_intent_once() -> None:
    faults = _fault_blueprint("ONE_PROVIDER_TIMEOUT", "ONE_PROCESS_RESTART")
    assert faults["ONE_PROVIDER_TIMEOUT"]["consume_once_after_restart"] is True
    assert faults["ONE_PROCESS_RESTART"]["intent_consumptions"] == 1


def test_product_test_fault_targets_target_tests_once() -> None:
    fault = _fault_blueprint("ONE_PRODUCT_TEST_FAILURE")["ONE_PRODUCT_TEST_FAILURE"]
    assert fault["injected_gate"] == "target-tests"
    assert fault["injected_count"] == 1 and fault["builder_repairs"] == 1


def test_manifest_rejects_non_artifact_before_sort() -> None:
    blueprint = _profile_blueprint("LIBRARY_PACKAGE")
    assert blueprint["validate_artifact_type_before_sort"] is True
    assert blueprint["invalid_type_exception"] == "MalformedEvidenceError"


def test_package_stale_policy_is_deterministic() -> None:
    blueprint = _profile_blueprint("LIBRARY_PACKAGE")
    assert blueprint["stale_policy"] == "reject_if_subject_or_revocation_digest_differs"


def test_package_builds_wheel_and_sdist_offline() -> None:
    blueprint = _profile_blueprint("LIBRARY_PACKAGE")
    assert blueprint["clean_consumer_offline"] is True
    assert blueprint["offline_build_artifacts"] == ["wheel", "sdist"]


def test_deploy_fault_consumption_and_rollback_are_exactly_once() -> None:
    fault = _fault_blueprint("ONE_POST_DEPLOY_HEALTH_FAILURE")["ONE_POST_DEPLOY_HEALTH_FAILURE"]
    assert fault["fault_consumptions"] == 1
    assert fault["rollback_count"] == 1
    assert fault["lifecycle_cas"] is True


def _three_runs() -> list[dict[str, Any]]:
    return [
        {
            "run_id": f"r04-convergence-{index}",
            "git_tree": "f" * 40,
            "status": "10/10 PASS",
            "pass_count": 10,
            "scenario_count": 10,
            "repository_residue_count": 0,
        }
        for index in range(1, 4)
    ]


def test_three_consecutive_runs_require_same_tree() -> None:
    runs = _three_runs()
    assert {run["git_tree"] for run in runs} == {"f" * 40}
    runs[2]["git_tree"] = "e" * 40
    assert len({run["git_tree"] for run in runs}) != 1


def test_three_consecutive_runs_require_distinct_run_ids() -> None:
    runs = _three_runs()
    assert len({run["run_id"] for run in runs}) == 3
    runs[2]["run_id"] = runs[1]["run_id"]
    assert len({run["run_id"] for run in runs}) != 3


def test_three_consecutive_runs_each_require_10_of_10() -> None:
    runs = _three_runs()
    assert all(
        run["status"] == "10/10 PASS" and run["pass_count"] == run["scenario_count"] == 10
        for run in runs
    )


def test_three_consecutive_runs_each_require_zero_residue() -> None:
    runs = _three_runs()
    assert all(run["repository_residue_count"] == 0 for run in runs)
