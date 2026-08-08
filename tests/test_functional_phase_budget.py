from __future__ import annotations

import sqlite3

import pytest

from factory.functional_readiness import (
    PRE_Q8_SCENARIOS,
    FunctionalQualificationGovernor,
    FunctionalReadinessError,
)


def _governor() -> FunctionalQualificationGovernor:
    governor = FunctionalQualificationGovernor(sqlite3.connect(":memory:"))
    governor.register_epoch(
        epoch_id="RE-PHASE-BUDGET",
        source_commit="a" * 40,
        candidate_digest="b" * 64,
        toolchain_digest="c" * 64,
    )
    return governor


def test_pre_q8_phase_has_one_attempt_and_one_original_budget() -> None:
    governor = _governor()
    governor.connection.execute(
        """UPDATE functional_epochs
              SET q6_5_status='PASS',product_github_status='PASS',
                  stable_provider_status='PASS',status='PRE_Q8_PENDING'
            WHERE epoch_id='RE-PHASE-BUDGET'"""
    )
    phase_id = f"pre-q8:{PRE_Q8_SCENARIOS[0]}"

    first = governor.start_phase(
        epoch_id="RE-PHASE-BUDGET",
        phase_id=phase_id,
        budget_seconds=172800,
    )
    resumed = governor.start_phase(
        epoch_id="RE-PHASE-BUDGET",
        phase_id=phase_id,
        budget_seconds=172800,
    )

    assert first == resumed
    assert first["attempt"] == 1
    assert first["status"] == "RUNNING"
    with pytest.raises(FunctionalReadinessError, match="budget conflicts"):
        governor.start_phase(
            epoch_id="RE-PHASE-BUDGET",
            phase_id=phase_id,
            budget_seconds=172801,
        )

    failed = governor.fail_phase(
        epoch_id="RE-PHASE-BUDGET",
        phase_id=phase_id,
        reason_code="pre_q8_timeout",
    )
    repeated = governor.fail_phase(
        epoch_id="RE-PHASE-BUDGET",
        phase_id=phase_id,
        reason_code="pre_q8_timeout",
    )
    assert failed == repeated
    assert governor.epoch("RE-PHASE-BUDGET")["status"] == "QUALIFICATION_FAILED"
    assert (
        governor.connection.execute("SELECT COUNT(*) FROM functional_phase_runs").fetchone()[0]
        == 1
    )


def test_golden_intake_and_execution_use_separate_finite_deadlines() -> None:
    governor = _governor()
    governor.connection.execute(
        """UPDATE functional_epochs
              SET q6_5_status='PASS',product_github_status='PASS',
                  stable_provider_status='PASS',pre_q8_status='10/10 PASS',
                  status='GOLDEN_PRODUCT_PENDING'
            WHERE epoch_id='RE-PHASE-BUDGET'"""
    )

    intake = governor.start_phase(
        epoch_id="RE-PHASE-BUDGET",
        phase_id="golden-intake",
        budget_seconds=86400,
    )
    governor.pass_phase(
        epoch_id="RE-PHASE-BUDGET",
        phase_id="golden-intake",
        evidence_digest="d" * 64,
    )
    execution = governor.start_phase(
        epoch_id="RE-PHASE-BUDGET",
        phase_id="golden-product",
        budget_seconds=259200,
    )

    assert intake["attempt"] == execution["attempt"] == 1
    assert intake["budget_seconds"] == 86400
    assert execution["budget_seconds"] == 259200
    with pytest.raises(FunctionalReadinessError, match="passed functional phase cannot fail"):
        governor.fail_phase(
            epoch_id="RE-PHASE-BUDGET",
            phase_id="golden-intake",
            reason_code="golden_intake_failed",
        )
