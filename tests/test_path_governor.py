from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from test_worker import make_config

from factory.artifacts import ArtifactStore
from factory.autonomy import TaskOutcome
from factory.common import sha256_text
from factory.path_governor import (
    PathArbiterSandbox,
    PathDecisionError,
    PathGovernor,
    ProgressVector,
    ResultLineageCycleError,
    ResultLineageIdentityError,
    failure_owner,
    stable_root_problem_signature,
)
from factory.reconciler import PipelineReconciler
from factory.state import StateStore

POLICY_DIGEST = "a" * 64


def _state(tmp_path: Path, product_id: str = "product-path-governor") -> StateStore:
    state = StateStore(tmp_path / "controller.db")
    state.create_product(
        product_id=product_id,
        owner_id="owner",
        source="cli",
        idea="Exercise deterministic path governance",
        idempotency_key=f"intake-{product_id}",
    )
    state.add_task(
        task_id="T-ROOT0001",
        product_id=product_id,
        title="Root semantic node",
        role="builder",
        output_schema="attempt-result.schema.json",
        contract_ref="evidence/task-T-ROOT0001.json",
        stage_key="implementation-slice",
        plan_node_id="implementation-root",
        graph_status="READY",
    )
    with state._connection:
        state._connection.execute(
            """UPDATE tasks SET lifecycle_stage='implementation-slice',
                      semantic_node_key='root', result_ref='evidence/attempt-root.json',
                      result_digest=? WHERE task_id='T-ROOT0001'""",
            ("b" * 64,),
        )
    state.transition_product(product_id, "RISK_CLASSIFIED")
    state.transition_product(product_id, "ARCHITECTED")
    state.transition_product(product_id, "IMPLEMENTING")
    return state


def _clone_task(
    state: StateStore,
    source_id: str,
    task_id: str,
    *,
    supersedes_task_id: str | None,
    semantic_key: str = "root",
    lifecycle_stage: str = "implementation-slice",
    graph_status: str = "ACCEPTED",
) -> None:
    source = dict(
        state._connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (source_id,)
        ).fetchone()
    )
    columns = [
        str(row[1]) for row in state._connection.execute("PRAGMA table_info(tasks)")
    ]
    source.update(
        {
            "task_id": task_id,
            "idempotency_key": sha256_text(f"task:{task_id}"),
            "plan_node_id": semantic_key,
            "semantic_node_key": semantic_key,
            "lifecycle_stage": lifecycle_stage,
            "supersedes_task_id": supersedes_task_id,
            "status": "DONE" if graph_status in {"ACCEPTED", "SUPERSEDED"} else "PENDING",
            "graph_status": graph_status,
            "lease_owner": None,
            "lease_until": None,
            "lease_token": None,
            "heartbeat_at": None,
            "result_binding_id": None,
            "semantic_node_id": None,
            "contract_digest": None,
        }
    )
    placeholders = ",".join("?" for _ in columns)
    state._connection.execute(
        f"INSERT INTO tasks ({','.join(columns)}) VALUES ({placeholders})",
        tuple(source[column] for column in columns),
    )


def _accept_source(state: StateStore, task_id: str, attempt_id: str) -> None:
    state._connection.execute(
        """UPDATE tasks SET status='DONE', graph_status='ACCEPTED',
                  result_ref='evidence/attempt-root.json', result_digest=?
            WHERE task_id=?""",
        ("b" * 64, task_id),
    )
    state.record_attempt(
        attempt_id=attempt_id,
        task_id=task_id,
        tier="luna",
        attempt_kind="initial",
        prompt_digest=sha256_text(f"prompt:{attempt_id}"),
        status="completed",
        semantic_counted=True,
    )


def _binding(
    state: StateStore,
    task_id: str,
    attempt_id: str,
    *,
    result_digest: str,
) -> str:
    governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
    return governor.bind_result(
        task_id=task_id,
        source_task_id=task_id,
        source_attempt_id=attempt_id,
        result_ref=f"evidence/output-{task_id}.json",
        result_digest=result_digest,
        output_schema="attempt-result.schema.json",
    ).binding_id


def _progress(first: int, *, evidence_gap: int = 0) -> ProgressVector:
    return ProgressVector(first, 1, 1, 0, evidence_gap, 0, 0)


def test_LOOP_P0_001_ten_thousand_valid_legacy_nodes_materialize_direct_binding(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    try:
        _accept_source(state, "T-ROOT0001", "attempt-root")
        previous = "T-ROOT0001"
        with state._connection:
            for index in range(1, 10_000):
                task_id = f"T-L{index:05d}"
                _clone_task(
                    state,
                    "T-ROOT0001",
                    task_id,
                    supersedes_task_id=previous,
                )
                previous = task_id
        governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
        source = governor.resolve_legacy_source(previous)
        assert source.depth == 9_999
        binding = governor.bind_result(
            task_id=previous,
            source_task_id="T-ROOT0001",
            source_attempt_id="attempt-root",
            result_ref="evidence/output-root.json",
            result_digest="c" * 64,
            output_schema="attempt-result.schema.json",
        )
        assert governor.direct_binding(previous) == binding
    finally:
        state.close()


def test_LOOP_P0_002_literal_cycle_reports_controller_cycle(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        with state._connection:
            _clone_task(state, "T-ROOT0001", "T-CYCLEA", supersedes_task_id="T-CYCLEC")
            _clone_task(state, "T-ROOT0001", "T-CYCLEB", supersedes_task_id="T-CYCLEA")
            _clone_task(state, "T-ROOT0001", "T-CYCLEC", supersedes_task_id="T-CYCLEB")
        governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
        with pytest.raises(ResultLineageCycleError, match="cyclic"):
            governor.resolve_legacy_source("T-CYCLEA")
    finally:
        state.close()


def test_LOOP_P0_003_depth_147_is_not_a_cycle(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        _accept_source(state, "T-ROOT0001", "attempt-root")
        previous = "T-ROOT0001"
        with state._connection:
            for index in range(1, 148):
                task_id = f"T-D{index:04d}"
                _clone_task(state, "T-ROOT0001", task_id, supersedes_task_id=previous)
                previous = task_id
        source = PathGovernor(
            state._connection, policy_digest=POLICY_DIGEST
        ).resolve_legacy_source(previous)
        assert source.depth == 147
        assert source.task["task_id"] == "T-ROOT0001"
    finally:
        state.close()


def test_LOOP_P0_004_five_hundred_deltas_do_not_accrete_unchanged_tasks(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    try:
        _accept_source(state, "T-ROOT0001", "attempt-root")
        binding_id = _binding(
            state, "T-ROOT0001", "attempt-root", result_digest="c" * 64
        )
        with state._connection:
            _clone_task(
                state,
                "T-ROOT0001",
                "T-CHANGED1",
                supersedes_task_id=None,
                semantic_key="changed",
                graph_status="READY",
            )
        before = int(state._connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0])
        governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
        with state._connection:
            for revision in range(1, 501):
                governor.apply_plan_delta(
                    plan_id=f"PLAN-DELTA-{revision:04d}",
                    preserve_binding_ids=(binding_id,),
                    execution_task_ids=("T-CHANGED1",),
                )
        after = int(state._connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0])
        assert after == before
        assert state._connection.execute(
            "SELECT COUNT(*) FROM plan_memberships WHERE binding_id=?", (binding_id,)
        ).fetchone()[0] == 501
    finally:
        state.close()


def test_LOOP_P0_005_reviews_share_one_candidate_snapshot(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
        binding_ids: list[str] = []
        architecture_id = ""
        for index in range(81):
            task_id = "T-ROOT0001" if index == 0 else f"T-S{index:04d}"
            if index:
                with state._connection:
                    _clone_task(
                        state,
                        "T-ROOT0001",
                        task_id,
                        supersedes_task_id=None,
                        semantic_key=f"slice-{index:03d}",
                    )
            with state._connection:
                state._connection.execute(
                    """UPDATE tasks SET lifecycle_stage=?, semantic_node_key=?
                        WHERE task_id=?""",
                    (
                        "architecture-review" if index == 0 else "implementation-slice",
                        "architecture" if index == 0 else f"slice-{index:03d}",
                        task_id,
                    ),
                )
            attempt_id = f"attempt-snapshot-{index:03d}"
            _accept_source(state, task_id, attempt_id)
            binding_id = _binding(
                state,
                task_id,
                attempt_id,
                result_digest=f"{index + 1:064x}",
            )
            binding_ids.append(binding_id)
            if index == 0:
                architecture_id = binding_id
        with state._connection:
            snapshot_id = governor.create_candidate_snapshot(
                product_id="product-path-governor",
                plan_id=str(state.get_task("T-ROOT0001")["plan_id"]),
                repository_commit="d" * 40,
                tree_digest="sha256:" + "e" * 64,
                architecture_binding_id=architecture_id,
                result_binding_ids=binding_ids,
            )
            for role, task_id in (
                ("test-engineer", "T-REVIEW1"),
                ("security-reviewer", "T-REVIEW2"),
                ("independent-reviewer", "T-REVIEW3"),
            ):
                _clone_task(
                    state,
                    "T-ROOT0001",
                    task_id,
                    supersedes_task_id=None,
                    semantic_key=role,
                    graph_status="READY",
                )
                state._connection.execute(
                    "UPDATE tasks SET role=?, candidate_snapshot_id=?, dependencies_json='[]' "
                    "WHERE task_id=?",
                    (role, snapshot_id, task_id),
                )
        assert state._connection.execute(
            "SELECT COUNT(*) FROM candidate_snapshots"
        ).fetchone()[0] == 1
        assert state._connection.execute(
            "SELECT COUNT(*) FROM candidate_snapshot_items WHERE snapshot_id=?",
            (snapshot_id,),
        ).fetchone()[0] == 81
        assert state._connection.execute(
            "SELECT COUNT(DISTINCT candidate_snapshot_id) FROM tasks "
            "WHERE task_id IN ('T-REVIEW1','T-REVIEW2','T-REVIEW3')"
        ).fetchone()[0] == 1
    finally:
        state.close()


def test_ID_P0_007_missing_orphan_and_conflicting_artifacts_fail_closed(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    try:
        governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
        with pytest.raises(ResultLineageIdentityError, match="missing or cross-product"):
            governor.create_candidate_snapshot(
                product_id="product-path-governor",
                plan_id=str(state.get_task("T-ROOT0001")["plan_id"]),
                repository_commit="d" * 40,
                tree_digest="sha256:" + "e" * 64,
                architecture_binding_id="RB-MISSING",
                result_binding_ids=("RB-MISSING",),
            )

        _accept_source(state, "T-ROOT0001", "attempt-root")
        binding = governor.bind_result(
            task_id="T-ROOT0001",
            source_task_id="T-ROOT0001",
            source_attempt_id="attempt-root",
            result_ref="evidence/output-root.json",
            result_digest="c" * 64,
            output_schema="attempt-result.schema.json",
        )
        with pytest.raises(ResultLineageIdentityError, match="conflicts"):
            governor.bind_result(
                task_id="T-ROOT0001",
                source_task_id="T-ROOT0001",
                source_attempt_id="attempt-root",
                result_ref="evidence/output-conflict.json",
                result_digest="f" * 64,
                output_schema="attempt-result.schema.json",
            )
        assert governor.direct_binding("T-ROOT0001") == binding
        state._connection.commit()

        state.create_product(
            product_id="product-orphan-source",
            owner_id="owner",
            source="cli",
            idea="Create a cross-product artifact",
            idempotency_key="intake-product-orphan-source",
        )
        state.add_task(
            task_id="T-ORPHAN-SOURCE",
            product_id="product-orphan-source",
            title="Cross-product source",
            role="builder",
            output_schema="attempt-result.schema.json",
            contract_ref="evidence/task-T-ORPHAN-SOURCE.json",
            stage_key="implementation-slice",
            plan_node_id="orphan-source",
            graph_status="READY",
        )
        with state._connection:
            state._connection.execute(
                """UPDATE tasks SET lifecycle_stage='implementation-slice',
                          semantic_node_key='orphan-source'
                    WHERE task_id='T-ORPHAN-SOURCE'"""
            )
        _accept_source(state, "T-ORPHAN-SOURCE", "attempt-orphan-source")
        orphan = governor.bind_result(
            task_id="T-ORPHAN-SOURCE",
            source_task_id="T-ORPHAN-SOURCE",
            source_attempt_id="attempt-orphan-source",
            result_ref="evidence/output-orphan-source.json",
            result_digest="9" * 64,
            output_schema="attempt-result.schema.json",
        )
        with pytest.raises(ResultLineageIdentityError, match="missing or cross-product"):
            governor.create_candidate_snapshot(
                product_id="product-path-governor",
                plan_id=str(state.get_task("T-ROOT0001")["plan_id"]),
                repository_commit="d" * 40,
                tree_digest="sha256:" + "e" * 64,
                architecture_binding_id=orphan.binding_id,
                result_binding_ids=(orphan.binding_id,),
            )
    finally:
        state.close()


def test_candidate_snapshot_is_dependency_ancestry_cut(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        plan_id = str(state.get_task("T-ROOT0001")["plan_id"])
        implementation_ids = ["T-ROOT0001"]
        with state._connection:
            for index in range(1, 79):
                task_id = f"T-CUT{index:04d}"
                _clone_task(
                    state,
                    "T-ROOT0001",
                    task_id,
                    supersedes_task_id=None,
                    semantic_key=f"cut-{index:03d}",
                )
                implementation_ids.append(task_id)
            _clone_task(
                state,
                "T-ROOT0001",
                "T-SNAPSHOT-CUT",
                supersedes_task_id=None,
                semantic_key="candidate-snapshot-cut",
                lifecycle_stage="candidate-snapshot",
            )
            _clone_task(
                state,
                "T-ROOT0001",
                "T-TEST-CUT",
                supersedes_task_id=None,
                semantic_key="test-cut",
                lifecycle_stage="test",
                graph_status="READY",
            )
            for implementation_id in implementation_ids:
                state._connection.execute(
                    """INSERT INTO task_edges
                       (plan_id, from_task_id, to_task_id, edge_type,
                        required, created_at)
                       VALUES (?, ?, 'T-SNAPSHOT-CUT', 'evidence_from', 1,
                               '2026-08-03T00:00:00Z')""",
                    (plan_id, implementation_id),
                )
            state._connection.execute(
                """INSERT INTO task_edges
                   (plan_id, from_task_id, to_task_id, edge_type,
                    required, created_at)
                   VALUES (?, 'T-SNAPSHOT-CUT', 'T-TEST-CUT',
                           'depends_on', 1, '2026-08-03T00:00:00Z')""",
                (plan_id,),
            )

        ancestors = state.dependency_ancestors("T-TEST-CUT")

        assert [row["task_id"] for row in ancestors] == ["T-SNAPSHOT-CUT"]
    finally:
        state.close()


def test_candidate_memberships_ignore_historical_task_binding_fields(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    try:
        with state._connection:
            _clone_task(
                state,
                "T-ROOT0001",
                "T-ARCH0001",
                supersedes_task_id=None,
                semantic_key="architecture-review",
                lifecycle_stage="architecture-review",
            )
            _clone_task(
                state,
                "T-ROOT0001",
                "T-SNAPSHOT1",
                supersedes_task_id=None,
                semantic_key="candidate-snapshot",
                lifecycle_stage="candidate-snapshot",
                graph_status="READY",
            )
            state._connection.execute(
                "UPDATE tasks SET role='independent-reviewer' WHERE task_id='T-ARCH0001'"
            )
            state._connection.execute(
                "UPDATE tasks SET role='path-governor' WHERE task_id='T-SNAPSHOT1'"
            )
        _accept_source(state, "T-ARCH0001", "attempt-architecture")
        _accept_source(state, "T-ROOT0001", "attempt-implementation")
        architecture = _binding(
            state,
            "T-ARCH0001",
            "attempt-architecture",
            result_digest="d" * 64,
        )
        implementation = _binding(
            state,
            "T-ROOT0001",
            "attempt-implementation",
            result_digest="e" * 64,
        )
        governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
        with state._connection:
            governor.apply_plan_delta(
                plan_id="PLAN-DELTA-CANDIDATE",
                preserve_binding_ids=(architecture, implementation),
                execution_task_ids=("T-SNAPSHOT1",),
            )
            state._connection.execute(
                "UPDATE tasks SET result_binding_id=NULL "
                "WHERE task_id IN ('T-ARCH0001','T-ROOT0001')"
            )

        selected_architecture, bindings = governor.candidate_membership_bindings(
            product_id="product-path-governor",
            plan_id="PLAN-DELTA-CANDIDATE",
        )

        assert selected_architecture == architecture
        assert bindings == tuple(sorted((architecture, implementation)))
    finally:
        state.close()


def test_candidate_snapshot_execution_identity_is_scoped_to_plan_revision(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    try:
        with state._connection:
            for task_id, plan_id in (
                ("T-SNAPSHOT-REV1", "PLAN-SNAPSHOT-REV1"),
                ("T-SNAPSHOT-REV2", "PLAN-SNAPSHOT-REV2"),
            ):
                _clone_task(
                    state,
                    "T-ROOT0001",
                    task_id,
                    supersedes_task_id=None,
                    semantic_key="candidate-snapshot",
                    lifecycle_stage="candidate-snapshot",
                    graph_status="READY",
                )
                state._connection.execute(
                    """UPDATE tasks SET role='path-governor', plan_id=?,
                              output_schema='candidate-snapshot.schema.json'
                        WHERE task_id=?""",
                    (plan_id, task_id),
                )
        governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
        with state._connection:
            governor.apply_plan_delta(
                plan_id="PLAN-SNAPSHOT-REV1",
                preserve_binding_ids=(),
                execution_task_ids=("T-SNAPSHOT-REV1",),
            )
            governor.apply_plan_delta(
                plan_id="PLAN-SNAPSHOT-REV2",
                preserve_binding_ids=(),
                execution_task_ids=("T-SNAPSHOT-REV2",),
            )

        first = state.get_task("T-SNAPSHOT-REV1")
        second = state.get_task("T-SNAPSHOT-REV2")
        assert first is not None and second is not None
        assert first["semantic_node_key"] == (
            "candidate-snapshot@plan:PLAN-SNAPSHOT-REV1"
        )
        assert second["semantic_node_key"] == (
            "candidate-snapshot@plan:PLAN-SNAPSHOT-REV2"
        )
        assert first["semantic_node_id"] != second["semantic_node_id"]
        assert first["contract_digest"] != second["contract_digest"]
        for task_id, plan_id in (
            ("T-SNAPSHOT-REV1", "PLAN-SNAPSHOT-REV1"),
            ("T-SNAPSHOT-REV2", "PLAN-SNAPSHOT-REV2"),
        ):
            assert state._connection.execute(
                """SELECT COUNT(*) FROM plan_memberships
                    WHERE plan_id=? AND execution_task_id=?
                      AND membership_state='EXECUTION'""",
                (plan_id, task_id),
            ).fetchone()[0] == 1
    finally:
        state.close()


def test_candidate_materializer_uses_plan_delta_memberships(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = make_config(tmp_path)
    state = _state(tmp_path)
    try:
        with state._connection:
            _clone_task(
                state,
                "T-ROOT0001",
                "T-ARCH0002",
                supersedes_task_id=None,
                semantic_key="architecture-review",
                lifecycle_stage="architecture-review",
            )
            _clone_task(
                state,
                "T-ROOT0001",
                "T-SNAPSHOT2",
                supersedes_task_id=None,
                semantic_key="candidate-snapshot",
                lifecycle_stage="candidate-snapshot",
                graph_status="READY",
            )
            _clone_task(
                state,
                "T-ROOT0001",
                "T-TEST-LEGACY",
                supersedes_task_id=None,
                semantic_key="test",
                lifecycle_stage="test",
            )
            _clone_task(
                state,
                "T-ROOT0001",
                "T-TEST0002",
                supersedes_task_id=None,
                semantic_key="test",
                lifecycle_stage="test",
                graph_status="BLOCKED_DEPENDENCY",
            )
            state._connection.execute(
                """UPDATE tasks SET role='independent-reviewer'
                    WHERE task_id='T-ARCH0002'"""
            )
            state._connection.execute(
                """UPDATE tasks SET role='path-governor',
                          output_schema='candidate-snapshot.schema.json',
                          plan_id='PLAN-DELTA-MATERIALIZE',
                          dependencies_json='[\"T-ARCH0002\",\"T-ROOT0001\"]'
                    WHERE task_id='T-SNAPSHOT2'"""
            )
            state._connection.execute(
                """UPDATE tasks SET role='test-engineer',
                          plan_id='PLAN-DELTA-LEGACY'
                    WHERE task_id='T-TEST-LEGACY'"""
            )
            state._connection.execute(
                """UPDATE tasks SET role='test-engineer',
                          plan_id='PLAN-DELTA-MATERIALIZE',
                          dependencies_json='[\"T-SNAPSHOT2\"]'
                    WHERE task_id='T-TEST0002'"""
            )
            state._connection.execute(
                """UPDATE products SET active_plan_id='PLAN-DELTA-MATERIALIZE',
                          active_plan_revision=2
                    WHERE product_id='product-path-governor'"""
            )
            for source, target in (
                ("T-ARCH0002", "T-SNAPSHOT2"),
                ("T-ROOT0001", "T-SNAPSHOT2"),
                ("T-SNAPSHOT2", "T-TEST0002"),
            ):
                state._connection.execute(
                    """INSERT INTO task_edges
                       (plan_id, from_task_id, to_task_id, edge_type,
                        required, created_at)
                       VALUES ('PLAN-DELTA-MATERIALIZE', ?, ?,
                               'depends_on', 1, '2026-08-02T00:00:00Z')""",
                    (source, target),
                )
        _accept_source(state, "T-TEST-LEGACY", "attempt-test-legacy")
        legacy_test_binding = _binding(
            state,
            "T-TEST-LEGACY",
            "attempt-test-legacy",
            result_digest="9" * 64,
        )
        legacy_test = state.get_task("T-TEST-LEGACY")
        assert legacy_test is not None
        _accept_source(state, "T-ARCH0002", "attempt-architecture-2")
        _accept_source(state, "T-ROOT0001", "attempt-implementation-2")
        architecture = _binding(
            state,
            "T-ARCH0002",
            "attempt-architecture-2",
            result_digest="f" * 64,
        )
        implementation = _binding(
            state,
            "T-ROOT0001",
            "attempt-implementation-2",
            result_digest="1" * 64,
        )
        governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
        with state._connection:
            governor.apply_plan_delta(
                plan_id="PLAN-DELTA-MATERIALIZE",
                preserve_binding_ids=(architecture, implementation),
                execution_task_ids=("T-SNAPSHOT2", "T-TEST0002"),
            )
            state._connection.execute(
                "UPDATE tasks SET result_binding_id=NULL "
                "WHERE task_id IN ('T-ARCH0002','T-ROOT0001')"
            )
        monkeypatch.setattr(
            "factory.reconciler.git_candidate",
            lambda _config, _product_id: (
                "2" * 40,
                "sha256:" + "3" * 64,
            ),
        )

        original_bind_result = PathGovernor.bind_result
        injected_failure = False

        def fail_after_artifact_once(
            governor: PathGovernor, **kwargs: Any
        ) -> Any:
            nonlocal injected_failure
            if kwargs.get("task_id") == "T-SNAPSHOT2" and not injected_failure:
                injected_failure = True
                raise ResultLineageIdentityError("injected post-artifact rollback")
            return original_bind_result(governor, **kwargs)

        monkeypatch.setattr(PathGovernor, "bind_result", fail_after_artifact_once)

        with pytest.raises(
            ResultLineageIdentityError, match="injected post-artifact rollback"
        ):
            PipelineReconciler(
                config,
                state,
                ArtifactStore(config),
            )._materialize_candidate_snapshot("product-path-governor")
        assert state._connection.execute(
            "SELECT COUNT(*) FROM candidate_snapshots"
        ).fetchone()[0] == 0
        assert len(list(config.evidence_dir.glob("candidate-snapshot-*.json"))) == 1

        materialized = PipelineReconciler(
            config,
            state,
            ArtifactStore(config),
        )._materialize_candidate_snapshot("product-path-governor")

        candidate = state.get_task("T-SNAPSHOT2")
        downstream = state.get_task("T-TEST0002")
        assert materialized
        assert candidate is not None and candidate["graph_status"] == "ACCEPTED"
        assert candidate["result_binding_id"]
        assert candidate["candidate_snapshot_id"]
        assert downstream is not None
        assert downstream["candidate_snapshot_id"] == candidate["candidate_snapshot_id"]
        assert downstream["semantic_node_key"] == (
            f"test@candidate:{candidate['candidate_snapshot_id']}"
        )
        assert downstream["semantic_node_id"] != legacy_test["semantic_node_id"]
        # Candidate scope separates execution identity without mutating the
        # immutable semantic task contract.
        assert downstream["contract_digest"] == legacy_test["contract_digest"]
        assert state._connection.execute(
            """SELECT COUNT(*) FROM plan_memberships
                WHERE plan_id='PLAN-DELTA-MATERIALIZE'
                  AND semantic_node_id=? AND execution_task_id='T-TEST0002'
                  AND membership_state='EXECUTION'""",
            (downstream["semantic_node_id"],),
        ).fetchone()[0] == 1
        assert state._connection.execute(
            """SELECT binding_id FROM result_bindings
                WHERE semantic_node_id=? AND status='ACTIVE'""",
            (legacy_test["semantic_node_id"],),
        ).fetchone()[0] == legacy_test_binding
        assert state._connection.execute(
            "SELECT COUNT(*) FROM candidate_snapshot_items WHERE snapshot_id=?",
            (candidate["candidate_snapshot_id"],),
        ).fetchone()[0] == 2
    finally:
        state.close()


def test_replanner_result_identity_is_scoped_to_active_plan(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        plan_one = "PLAN-REPLANNER-ONE"
        plan_two = "PLAN-REPLANNER-TWO"
        with state._connection:
            for revision, plan_id in enumerate((plan_one, plan_two), start=1):
                state._connection.execute(
                    """INSERT INTO plans
                       (plan_id, product_id, revision, status, plan_artifact_ref,
                        plan_digest, goals_json, completion_criteria_json,
                        created_by_task_id, created_at, activated_at)
                       VALUES (?, 'product-path-governor', ?, 'ACTIVE', ?, ?,
                               '[]', '[]', 'T-ROOT0001',
                               '2026-08-03T00:00:00Z',
                               '2026-08-03T00:00:00Z')""",
                    (
                        plan_id,
                        revision,
                        f"internal://plan/{plan_id}",
                        sha256_text(plan_id),
                    ),
                )
        for task_id, plan_id in (
            ("T-REPLANNER-ONE", plan_one),
            ("T-REPLANNER-TWO", plan_two),
        ):
            state.add_task(
                task_id=task_id,
                product_id="product-path-governor",
                title="Replan controller recovery",
                role="replanner",
                output_schema="plan-proposal-v1.schema.json",
                contract_ref=f"evidence/task-{task_id}.json",
                stage_key="replan",
                plan_id=plan_id,
                plan_node_id="test:controller-incident:replan",
                graph_status="READY",
            )
            _accept_source(state, task_id, f"attempt-{task_id.lower()}")

        first = state.get_task("T-REPLANNER-ONE")
        second = state.get_task("T-REPLANNER-TWO")
        assert first is not None and second is not None
        assert first["semantic_node_key"] == (
            f"test:controller-incident:replan@plan:{plan_one}"
        )
        assert second["semantic_node_key"] == (
            f"test:controller-incident:replan@plan:{plan_two}"
        )

        governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
        bindings = []
        with state._connection:
            for index, (task_id, attempt_id) in enumerate(
                (
                    ("T-REPLANNER-ONE", "attempt-t-replanner-one"),
                    ("T-REPLANNER-TWO", "attempt-t-replanner-two"),
                ),
                start=1,
            ):
                bindings.append(
                    governor.bind_result(
                        task_id=task_id,
                        source_task_id=task_id,
                        source_attempt_id=attempt_id,
                        result_ref=f"evidence/output-{task_id}.json",
                        result_digest=f"{index + 20:064x}",
                        output_schema="plan-proposal-v1.schema.json",
                    )
                )
        assert bindings[0].semantic_node_id != bindings[1].semantic_node_id
        assert bindings[0].binding_id != bindings[1].binding_id
        assert governor.direct_binding("T-REPLANNER-ONE") == bindings[0]
        assert governor.direct_binding("T-REPLANNER-TWO") == bindings[1]
    finally:
        state.close()


def test_LOOP_P0_006_failure_owner_is_decided_before_role_selection() -> None:
    assert failure_owner(
        failure_class="semantic", reason_code="controller_result_lineage_cycle"
    ) == "controller"
    assert failure_owner(failure_class="policy", reason_code="scope_violation") == "product"
    assert failure_owner(
        failure_class="external", reason_code="missing_credential"
    ) == "external"


def test_LOOP_P0_007_root_signature_ignores_ids_and_reason_wording() -> None:
    baseline: dict[str, Any] = {
        "product_id": "product-path-governor",
        "failure_class": "controller",
        "reason_code": "controller_result_lineage_cycle",
        "semantic_node_key": "test",
        "lifecycle_stage": "test",
        "failed_gate_ids": ["provenance"],
        "task_id": "T-ONE",
        "hypothesis_id": "H-ONE",
        "safe_message": "first wording",
    }
    changed = {**baseline, "task_id": "T-TWO", "hypothesis_id": "H-TWO", "safe_message": "other"}
    assert stable_root_problem_signature(baseline) == stable_root_problem_signature(changed)
    product_problem = {
        "product_id": "product-path-governor",
        "failure_class": "semantic",
        "reason_code": "mandatory_gate_failed",
        "semantic_node_key": "security-review@candidate:CS-ONE",
        "lifecycle_stage": "security-review",
        "failed_gate_ids": ["target-dependency-audit"],
    }
    expected = stable_root_problem_signature(product_problem)
    for reason_code in (
        "mandatory_gate_failed",
        "needs_replan",
        "model_requested_repair",
    ):
        assert stable_root_problem_signature(
            {
                **product_problem,
                "reason_code": reason_code,
                "semantic_node_key": "security-review@candidate:CS-TWO",
            }
        ) == expected


def test_LOOP_P0_008_no_op_plan_delta_is_rejected_before_mutation(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    try:
        governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
        with pytest.raises(PathDecisionError, match="no-op"):
            governor.apply_plan_delta(
                plan_id="PLAN-NOOP",
                preserve_binding_ids=(),
                execution_task_ids=(),
            )
        assert state._connection.execute(
            "SELECT COUNT(*) FROM plan_memberships WHERE plan_id='PLAN-NOOP'"
        ).fetchone()[0] == 0
    finally:
        state.close()


def test_LOOP_P0_009_circuit_breaker_uses_exact_problem_budget(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
        signature = "f" * 64
        with state._connection:
            assert governor.consume_budget(
                product_id="product-path-governor",
                root_problem_signature=signature,
                action_kind="deterministic",
                progress=_progress(5),
                evidence_digest="1" * 64,
            ) == "CONTINUE"
            assert governor.consume_budget(
                product_id="product-path-governor",
                root_problem_signature=signature,
                action_kind="deterministic",
                progress=_progress(4),
                evidence_digest="2" * 64,
            ) == "FAIL_SAFE"
        assert state._connection.execute(
            "SELECT status FROM problem_budgets WHERE root_problem_signature=?",
            (signature,),
        ).fetchone()[0] == "EXHAUSTED"
    finally:
        state.close()


def test_failed_safe_reopens_only_through_unused_controller_correction(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    try:
        governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
        signature = "e" * 64
        progress = _progress(5)
        with state._connection:
            assert governor.consume_budget(
                product_id="product-path-governor",
                root_problem_signature=signature,
                action_kind="arbiter",
                progress=progress,
                evidence_digest="1" * 64,
            ) == "CONTINUE"
            assert governor.consume_budget(
                product_id="product-path-governor",
                root_problem_signature=signature,
                action_kind="arbiter",
                progress=progress,
                evidence_digest="2" * 64,
            ) == "FAIL_SAFE"
            assert governor.apply_controller_correction(
                product_id="product-path-governor",
                root_problem_signature=signature,
                progress=progress,
                evidence_digest="3" * 64,
            ) == "CONTINUE"
            assert governor.apply_controller_correction(
                product_id="product-path-governor",
                root_problem_signature=signature,
                progress=progress,
                evidence_digest="4" * 64,
            ) == "FAIL_SAFE"
            assert governor.reserve_execution_slots(
                product_id="product-path-governor",
                root_problem_signature=signature,
                count=2,
                progress=progress,
            ) == "CONTINUE"
        budget = state._connection.execute(
            """SELECT deterministic_actions_used, arbiter_calls_used,
                      execution_attempts_used, status
                 FROM problem_budgets WHERE root_problem_signature=?""",
            (signature,),
        ).fetchone()
        assert tuple(budget) == (1, 1, 2, "ACTIVE")
    finally:
        state.close()


def test_unused_reservation_reclaim_refuses_cross_signature_and_attempted_task(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    signature = "c" * 64
    try:
        with state._connection:
            state._connection.execute(
                """INSERT INTO plans
                   (plan_id, product_id, revision, status, plan_artifact_ref,
                    plan_digest, goals_json, completion_criteria_json,
                    created_by_task_id, created_at, activated_at)
                   VALUES ('PLAN-UNUSED-UNIT', 'product-path-governor', 1,
                           'SUPERSEDED', 'internal://plan/unused-unit', ?,
                           '[]', '[]', 'T-ROOT0001',
                           '2026-08-09T00:00:00Z',
                           '2026-08-09T00:00:00Z')""",
                (sha256_text("PLAN-UNUSED-UNIT"),),
            )
            _clone_task(
                state,
                "T-ROOT0001",
                "T-UNUSED-UNIT",
                supersedes_task_id=None,
                graph_status="SUPERSEDED",
            )
            state._connection.execute(
                """UPDATE tasks
                      SET plan_id='PLAN-UNUSED-UNIT',
                          root_problem_signature=?, result_ref=NULL,
                          result_digest=NULL, result_binding_id=NULL
                    WHERE task_id='T-UNUSED-UNIT'""",
                (signature,),
            )
            governor = PathGovernor(
                state._connection,
                policy_digest=POLICY_DIGEST,
            )
            governor.register_execution_membership("T-UNUSED-UNIT")
            assert governor.reserve_execution_slots(
                product_id="product-path-governor",
                root_problem_signature=signature,
                count=1,
                progress=governor.progress_vector("product-path-governor"),
            ) == "CONTINUE"
            assert governor.reclaim_unused_execution_reservations(
                product_id="product-path-governor",
                root_problem_signature="d" * 64,
            ) == 0
        assert state.record_attempt(
            attempt_id="attempt-unused-unit",
            task_id="T-UNUSED-UNIT",
            tier="luna",
            attempt_kind="initial",
            prompt_digest=sha256_text("prompt:unused-unit"),
            status="started",
            semantic_counted=True,
        )
        with state._connection:
            assert governor.reclaim_unused_execution_reservations(
                product_id="product-path-governor",
                root_problem_signature=signature,
            ) == 0
        budget = state._connection.execute(
            """SELECT execution_attempts_used,status FROM problem_budgets
                WHERE product_id='product-path-governor'
                  AND root_problem_signature=?""",
            (signature,),
        ).fetchone()
        assert tuple(budget) == (1, "ACTIVE")
        assert state._connection.execute(
            """SELECT membership_state FROM plan_memberships
                WHERE plan_id='PLAN-UNUSED-UNIT'
                  AND execution_task_id='T-UNUSED-UNIT'"""
        ).fetchone()[0] == "EXECUTION"
    finally:
        state.close()


def test_LOOP_P0_010_path_arbiter_is_read_only_and_one_shot() -> None:
    signature = "a" * 64
    sandbox = PathArbiterSandbox(
        lambda _snapshot: {
            "schema_version": "1.0",
            "status": "proposed",
            "root_problem_signature": signature,
            "root_cause_class": "controller_invariant",
            "recommended_action": "RECOMPILE_AFFECTED_SUBGRAPH",
            "affected_semantic_node_keys": ["test"],
            "evidence_refs": ["state://path-snapshot"],
            "expected_progress_delta": {"lineage_indirection_depth": -147},
            "summary": "Materialize direct accepted-result bindings.",
        }
    )
    assert sandbox.propose(
        root_problem_signature=signature,
        path_snapshot={"product": "safe", "progress": {"depth": 147}},
    )["recommended_action"] == "RECOMPILE_AFFECTED_SUBGRAPH"
    with pytest.raises(PathDecisionError, match="exhausted"):
        sandbox.propose(root_problem_signature=signature, path_snapshot={"product": "safe"})


def test_LOOP_P0_011_result_binding_and_outcome_replay_are_atomic(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        claim = state.claim_task(worker_id="worker", lease_seconds=300)
        assert claim is not None
        state.record_attempt(
            attempt_id="attempt-atomic",
            task_id="T-ROOT0001",
            tier="luna",
            attempt_kind="initial",
            prompt_digest="3" * 64,
            status="started",
            semantic_counted=True,
        )
        outcome = TaskOutcome(
            task_id="T-ROOT0001",
            worker_id="worker",
            lease_token=str(claim["lease_token"]),
            idempotency_key="4" * 64,
            result_ref="evidence/attempt-attempt-atomic.json",
            result_digest="5" * 64,
            status="ACCEPTED",
            attempt_id="attempt-atomic",
            attempt_status="completed",
            accepted_result_ref="evidence/output-root.json",
            accepted_result_digest="6" * 64,
            accepted_policy_digest=POLICY_DIGEST,
        )
        with pytest.raises(RuntimeError, match="crash"):
            state.commit_task_outcome(
                outcome,
                fault_injector=lambda point: (
                    (_ for _ in ()).throw(RuntimeError("crash"))
                    if point == "after_result_binding_write"
                    else None
                ),
            )
        assert state._connection.execute(
            "SELECT COUNT(*) FROM result_bindings"
        ).fetchone()[0] == 0
        committed = state.commit_task_outcome(outcome)
        replayed = state.commit_task_outcome(outcome)
        assert not committed.replayed
        assert replayed.replayed
        assert state._connection.execute(
            "SELECT COUNT(*) FROM result_bindings"
        ).fetchone()[0] == 1
    finally:
        state.close()


def test_LOOP_P0_012_production_shape_has_79_bindings_and_one_snapshot(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    try:
        governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
        bindings: list[str] = []
        architecture = ""
        for index in range(79):
            task_id = "T-ROOT0001" if index == 0 else f"T-P{index:04d}"
            if index:
                with state._connection:
                    _clone_task(
                        state,
                        "T-ROOT0001",
                        task_id,
                        supersedes_task_id=None,
                        semantic_key=f"production-{index:03d}",
                    )
            with state._connection:
                state._connection.execute(
                    "UPDATE tasks SET lifecycle_stage=?, semantic_node_key=? WHERE task_id=?",
                    (
                        "architecture-review" if index == 0 else "implementation-slice",
                        "architecture" if index == 0 else f"production-{index:03d}",
                        task_id,
                    ),
                )
            attempt_id = f"attempt-production-{index:03d}"
            _accept_source(state, task_id, attempt_id)
            binding_id = _binding(
                state, task_id, attempt_id, result_digest=f"{index + 100:064x}"
            )
            bindings.append(binding_id)
            architecture = architecture or binding_id
        with state._connection:
            snapshot_id = governor.create_candidate_snapshot(
                product_id="product-path-governor",
                plan_id=str(state.get_task("T-ROOT0001")["plan_id"]),
                repository_commit="7" * 40,
                tree_digest="sha256:" + "8" * 64,
                architecture_binding_id=architecture,
                result_binding_ids=bindings,
            )
        assert len(set(bindings)) == 79
        assert state._connection.execute(
            "SELECT COUNT(*) FROM candidate_snapshots WHERE snapshot_id=?", (snapshot_id,)
        ).fetchone()[0] == 1
    finally:
        state.close()


def test_LOOP_P0_013_service_outcome_uses_public_state_api(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        claim = state.claim_task(worker_id="service-worker", lease_seconds=300)
        assert claim is not None
        state.record_attempt(
            attempt_id="attempt-service",
            task_id="T-ROOT0001",
            tier="luna",
            attempt_kind="initial",
            prompt_digest="9" * 64,
            status="started",
            semantic_counted=True,
        )
        state.commit_task_outcome(
            TaskOutcome(
                task_id="T-ROOT0001",
                worker_id="service-worker",
                lease_token=str(claim["lease_token"]),
                idempotency_key="a" * 64,
                result_ref="evidence/attempt-service.json",
                result_digest="b" * 64,
                status="ACCEPTED",
                attempt_id="attempt-service",
                attempt_status="completed",
                accepted_result_ref="evidence/output-service.json",
                accepted_result_digest="c" * 64,
                accepted_policy_digest=POLICY_DIGEST,
            )
        )
        task = state.get_task("T-ROOT0001")
        assert task is not None and task["graph_status"] == "ACCEPTED"
        assert task["result_binding_id"]
    finally:
        state.close()


def test_LOOP_P0_014_completion_requires_real_production_evidence(tmp_path: Path) -> None:
    state = _state(tmp_path)
    try:
        decision = state.reduce_completion("product-path-governor")
        assert not decision.completed
        assert decision.unmet_conditions
        assert state.get_product("product-path-governor")["status"] != "COMPLETED"
    finally:
        state.close()


def test_LOOP_P1_001_decision_storage_is_append_only_after_one_thousand_writes(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    try:
        governor = PathGovernor(state._connection, policy_digest=POLICY_DIGEST)
        with state._connection:
            for index in range(1_000):
                governor.record_decision(
                    product_id="product-path-governor",
                    root_problem_signature=None,
                    action="CONTINUE",
                    path_snapshot_digest=f"{index + 1:064x}",
                    progress_before=_progress(2),
                    expected_progress_after=_progress(1),
                )
        assert state._connection.execute(
            "SELECT COUNT(*) FROM path_decisions WHERE product_id=?",
            ("product-path-governor",),
        ).fetchone()[0] == 1_000
    finally:
        state.close()


def test_LOOP_P1_002_progress_vector_is_monotonic_property() -> None:
    for unmet in range(1, 50):
        before = ProgressVector(unmet, 3, 2, 1, 1, 147, 1)
        after = ProgressVector(unmet - 1, 3, 2, 1, 1, 147, 1)
        regression = ProgressVector(unmet - 1, 4, 2, 1, 1, 147, 1)
        assert after.strictly_improves(before)
        assert not regression.strictly_improves(before)
