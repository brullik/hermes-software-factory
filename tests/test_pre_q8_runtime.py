from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from pathlib import Path

import pytest

from factory.canary_faults import CanaryFaultContract
from factory.common import sha256_text
from factory.config import FactoryConfig
from factory.functional_readiness import (
    MANDATORY_Q6_5_OPERATIONS,
    CapabilityHandshakeReport,
    CapabilityStatus,
    FunctionalQualificationGovernor,
)
from factory.pre_q8_runtime import (
    CrashReconciliationDecision,
    OfficialTimerDecision,
    UnitSnapshot,
    WorkerAssessment,
    WorkerState,
    classify_worker,
    crash_reconciliation_decision,
    official_timer_decision,
    progress_snapshot,
)
from scripts import pre_q8_runtime as runtime_control
from scripts.functional_qualification import _write_identity_evidence


def _snapshot(
    active: str,
    sub: str,
    *,
    result: str = "success",
    status: int = 0,
) -> UnitSnapshot:
    return UnitSnapshot(
        active_state=active,
        sub_state=sub,
        result=result,
        n_restarts=0,
        main_pid=100 if active == "active" else 0,
        exec_main_code=1,
        exec_main_status=status,
    )


def _classify(
    snapshot: UnitSnapshot,
    *,
    restart_job_pending: bool = False,
    active_lease: bool = False,
    frontier_statuses: Sequence[str] = (),
    no_progress_window_elapsed: bool = True,
    intentional_restart_expected: bool = False,
    intentional_restart_receipt_verified: bool = False,
) -> WorkerAssessment:
    return classify_worker(
        snapshot,
        restart_job_pending=restart_job_pending,
        active_lease=active_lease,
        frontier_statuses=frontier_statuses,
        no_progress_window_elapsed=no_progress_window_elapsed,
        intentional_restart_expected=intentional_restart_expected,
        intentional_restart_receipt_verified=intentional_restart_receipt_verified,
    )


def test_active_worker_is_not_idle() -> None:
    assessment = _classify(_snapshot("active", "running"))
    assert assessment.state == WorkerState.BUSY
    assert not assessment.worker_idle


def test_activating_worker_is_not_idle() -> None:
    assessment = _classify(_snapshot("activating", "start"))
    assert assessment.state == WorkerState.BUSY
    assert not assessment.worker_idle


def test_auto_restart_worker_is_not_idle() -> None:
    assessment = _classify(_snapshot("inactive", "auto-restart"))
    assert assessment.state == WorkerState.BUSY
    assert not assessment.worker_idle


def test_failed_worker_is_typed_unit_failure() -> None:
    assessment = _classify(_snapshot("failed", "failed", result="failed", status=1))
    assert assessment.state == WorkerState.FAILED
    assert assessment.failure_class == "WORKER_UNIT_FAILED"
    assert not assessment.worker_idle


def test_intentional_restart_requires_grace_and_receipt() -> None:
    stopped = _snapshot("inactive", "dead")
    grace = _classify(
        stopped,
        intentional_restart_expected=True,
        intentional_restart_receipt_verified=False,
    )
    assert grace.state == WorkerState.RESTART_GRACE
    assert not grace.worker_idle
    verified = _classify(
        stopped,
        intentional_restart_expected=True,
        intentional_restart_receipt_verified=True,
    )
    assert verified.state == WorkerState.IDLE
    assert verified.worker_idle


def test_inactive_worker_with_frontier_or_restart_job_is_not_idle() -> None:
    stopped = _snapshot("inactive", "dead")
    assert not _classify(stopped, frontier_statuses=("PENDING",)).worker_idle
    assert not _classify(stopped, restart_job_pending=True).worker_idle
    assert not _classify(stopped, active_lease=True).worker_idle


def test_progress_fingerprint_is_repeatable_and_changes_only_with_state(tmp_path: Path) -> None:
    database = (tmp_path / "controller.db").resolve()
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE products(product_id TEXT PRIMARY KEY,status TEXT);
        CREATE TABLE tasks(
          task_id TEXT PRIMARY KEY,status TEXT,lease_owner TEXT,lease_until TEXT
        );
        CREATE TABLE attempts(attempt_id TEXT);
        CREATE TABLE side_effect_intents(intent_id TEXT);
        CREATE TABLE side_effect_receipts(intent_id TEXT);
        CREATE TABLE completion_manifests(product_id TEXT);
        CREATE TABLE controller_incidents(incident_id TEXT);
        CREATE TABLE recovery_applications(recovery_id TEXT);
        CREATE TABLE failures(failure_id TEXT,reason_code TEXT,failure_action TEXT);
        INSERT INTO products VALUES ('product-1','BUILDING');
        INSERT INTO tasks VALUES ('task-1','PENDING',NULL,NULL);
        """
    )
    connection.commit()
    first = progress_snapshot(database)
    second = progress_snapshot(database)
    assert first == second
    connection.execute("UPDATE tasks SET status='DONE' WHERE task_id='task-1'")
    connection.commit()
    connection.close()
    third = progress_snapshot(database)
    assert third["progress_fingerprint"] != first["progress_fingerprint"]


def test_q8_uses_config_database_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = (tmp_path / "q8").resolve()
    epoch_id = "RE-" + "A" * 24
    run_id = "q8-run01"
    scenario_id = "zero-dependency-cli"
    scenario_root = root / epoch_id / run_id / scenario_id
    database = scenario_root / "controller.db"
    config = FactoryConfig(
        {"controller": {"database_url": f"sqlite:///{database.as_posix()}"}},
        tmp_path / "scenario.yaml",
    )
    contract = CanaryFaultContract(
        qualification_plane="Q8",
        run_id=run_id,
        epoch_id=epoch_id,
        fixture_seed_digest="f" * 64,
        scenario_id=scenario_id,
        scenario_digest="1" * 64,
        controller_release_digest="2" * 64,
        candidate_digest="3" * 64,
        faults=(),
        receipt_root=scenario_root / "fault-receipts",
        isolated_target_root=scenario_root / "isolated-target",
    )
    monkeypatch.setattr(runtime_control, "load_config", lambda _path: config)
    monkeypatch.setattr(
        CanaryFaultContract,
        "from_config",
        classmethod(lambda cls, _config: contract),
    )
    identity = runtime_control.config_identity(
        tmp_path / "scenario.yaml",
        expected_plane="Q8",
        expected_scenario=scenario_id,
        allowed_root=root,
    )
    assert identity["database_path"] == str(database)

    escaped = FactoryConfig(
        {"controller": {"database_url": f"sqlite:///{(tmp_path / 'hardcoded.db').as_posix()}"}},
        tmp_path / "scenario.yaml",
    )
    monkeypatch.setattr(runtime_control, "load_config", lambda _path: escaped)
    with pytest.raises(runtime_control.RuntimeControlError):
        runtime_control.config_identity(
            tmp_path / "scenario.yaml",
            expected_plane="Q8",
            expected_scenario=scenario_id,
            allowed_root=root,
        )


def test_release_epoch_is_read_from_exact_governor_identity(tmp_path: Path) -> None:
    database = (tmp_path / "qualification.db").resolve()
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE controller_release_epochs("
        "epoch_id TEXT,source_commit TEXT,candidate_digest TEXT)"
    )
    connection.execute(
        "INSERT INTO controller_release_epochs VALUES (?,?,?)",
        ("RE-" + "A" * 24, "1" * 40, "2" * 64),
    )
    connection.commit()
    connection.close()

    assert runtime_control.release_epoch_from_governor(
        database,
        source_commit="1" * 40,
        candidate_digest="2" * 64,
    ) == "RE-" + "A" * 24
    with pytest.raises(runtime_control.RuntimeControlError):
        runtime_control.release_epoch_from_governor(
            database,
            source_commit="3" * 40,
            candidate_digest="2" * 64,
        )


def test_timer_second_tick_does_not_retry_terminal_candidate() -> None:
    first_tick_after_failure = official_timer_decision("QUALIFICATION_FAILED")
    second_tick_after_failure = official_timer_decision("QUALIFICATION_FAILED")
    assert first_tick_after_failure == OfficialTimerDecision.TERMINAL
    assert second_tick_after_failure == OfficialTimerDecision.TERMINAL
    assert second_tick_after_failure not in {
        OfficialTimerDecision.ADMIT,
        OfficialTimerDecision.RESUME,
    }


def test_stale_database_terminalizes_without_retry() -> None:
    decision = crash_reconciliation_decision(
        durable_run_status=None,
        database_exists=True,
        product_completed=False,
    )
    assert decision == CrashReconciliationDecision.STALE_DATABASE


def test_pre_q8_crash_between_evidence_and_database_commit_is_reconciled(
    tmp_path: Path,
) -> None:
    candidate_digest = "a" * 64
    toolchain_digest = "b" * 64
    epoch_id = "RE-CRASHBOUNDARY000000000001"
    scenario_id = "zero-dependency-cli"
    governor = FunctionalQualificationGovernor(sqlite3.connect(":memory:"))
    governor.register_epoch(
        epoch_id=epoch_id,
        source_commit="1" * 40,
        candidate_digest=candidate_digest,
        toolchain_digest=toolchain_digest,
    )
    for operation in MANDATORY_Q6_5_OPERATIONS:
        governor.record_handshake(
            epoch_id,
            CapabilityHandshakeReport.create(
                candidate_digest=candidate_digest,
                capability=operation,
                operation=operation,
                scope={"test": "crash-boundary"},
                status=CapabilityStatus.AVAILABLE,
                credential_epoch_id="CE-CRASH-BOUNDARY",
                toolchain_digest=toolchain_digest,
                receipts=(sha256_text(f"q65:{operation}"),),
            ),
        )
    body = {
        "schema_version": "1.0",
        "evidence_type": "OFFICIAL_PRE_Q8_FAILURE",
        "epoch_id": epoch_id,
        "run_id": "run-crash-boundary",
        "scenario_id": scenario_id,
        "attempt": 1,
        "candidate_digest": candidate_digest,
        "failure_class": "INTERRUPTED_OFFICIAL_RUN",
        "candidate_database_ref": str(tmp_path / "controller.db"),
        "config_digest": "c" * 64,
        "support_source_digests": {},
    }
    evidence_root = tmp_path / "evidence"
    first_path, first_digest, first_observed = _write_identity_evidence(
        evidence_root, "failure", body
    )
    # The first process crashes here, after evidence fsync and before DB commit.
    second_path, second_digest, second_observed = _write_identity_evidence(
        evidence_root, "failure", body
    )
    assert (first_path, first_digest, first_observed) == (
        second_path,
        second_digest,
        second_observed,
    )
    created = governor.record_pre_q8_failure(
        epoch_id=epoch_id,
        scenario_id=scenario_id,
        attempt=1,
        failure_class="INTERRUPTED_OFFICIAL_RUN",
        failure_digest=first_digest,
        evidence_ref=f"artifact://failure/{first_digest}",
        evidence_digest=first_digest,
        candidate_database_ref=str(tmp_path / "controller.db"),
        config_digest="c" * 64,
        support_bundle_ref="artifact://support/crash-boundary",
        support_bundle_digest=sha256_text("support-bundle"),
    )
    assert created
    assert governor.epoch(epoch_id)["status"] == "QUALIFICATION_FAILED"
    assert not governor.record_pre_q8_failure(
        epoch_id=epoch_id,
        scenario_id=scenario_id,
        attempt=1,
        failure_class="INTERRUPTED_OFFICIAL_RUN",
        failure_digest=first_digest,
        evidence_ref=f"artifact://failure/{first_digest}",
        evidence_digest=first_digest,
        candidate_database_ref=str(tmp_path / "controller.db"),
        config_digest="c" * 64,
        support_bundle_ref="artifact://support/crash-boundary",
        support_bundle_digest=sha256_text("support-bundle"),
    )
    governor.connection.close()


def test_functional_database_forward_migration_preserves_existing_epoch(
    tmp_path: Path,
) -> None:
    database = tmp_path / "pre-v2-functional.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE functional_epochs (
          epoch_id TEXT PRIMARY KEY,
          source_commit TEXT NOT NULL,
          candidate_digest TEXT NOT NULL,
          toolchain_digest TEXT NOT NULL,
          status TEXT NOT NULL,
          q6_5_status TEXT NOT NULL DEFAULT 'PENDING',
          pre_q8_status TEXT NOT NULL DEFAULT 'PENDING',
          golden_product_status TEXT NOT NULL DEFAULT 'PENDING',
          internal_verifier_status TEXT NOT NULL DEFAULT 'PENDING',
          stable_health_status TEXT NOT NULL DEFAULT 'PENDING',
          stable_intake_status TEXT NOT NULL DEFAULT 'PENDING',
          q7_started_at TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        INSERT INTO functional_epochs VALUES (
          'RE-OLD123456789012345678901','1111111111111111111111111111111111111111',
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
          'PRE_Q8_PENDING','PASS','PENDING','PENDING','PASS','PASS','PASS',NULL,
          '2026-08-09T00:00:00+00:00','2026-08-09T00:00:00+00:00'
        );
        CREATE TABLE pre_q8_scenarios (
          epoch_id TEXT NOT NULL REFERENCES functional_epochs(epoch_id),
          scenario_id TEXT NOT NULL,
          attempt INTEGER NOT NULL CHECK(attempt=1),
          status TEXT NOT NULL,
          product_id TEXT NOT NULL,
          completion_manifest_ref TEXT NOT NULL,
          evidence_digest TEXT NOT NULL,
          created_at TEXT NOT NULL,
          PRIMARY KEY(epoch_id,scenario_id)
        );
        """
    )
    connection.commit()

    governor = FunctionalQualificationGovernor(connection)

    epoch = governor.connection.execute(
        "SELECT status,q6_5_status,pre_q8_status FROM functional_epochs"
    ).fetchone()
    tables = {
        str(row[0])
        for row in governor.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    migration = governor.connection.execute(
        "SELECT description FROM functional_schema_migrations WHERE version=2"
    ).fetchone()
    assert tuple(epoch) == ("PRE_Q8_PENDING", "PASS", "PENDING")
    assert {
        "pre_q8_admissions",
        "pre_q8_runs",
        "pre_q8_progress",
        "pre_q8_failures",
    } <= tables
    assert migration is not None
    assert governor.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    governor.connection.close()
