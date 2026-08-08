from __future__ import annotations

from pathlib import Path


def test_interrupted_pre_q8_resumes_the_same_durable_attempt() -> None:
    repository = Path(__file__).parents[1]
    runner = (repository / "scripts/qualification/run-pre-q8-scenario.sh").read_text(
        encoding="utf-8"
    )

    assert "PRE-Q8 refuses a non-fresh database" not in runner
    assert 'scripts.canary_candidate --config "${CANDIDATE_CONFIG}" status' in runner
    assert 'value.get("product_id") or ""' in runner
    assert runner.count('scripts.canary_candidate --config "${CANDIDATE_CONFIG}" submit') == 2
    assert "rm " not in runner
    assert "ATTEMPT=" not in runner

    status = runner.index('scripts.canary_candidate --config "${CANDIDATE_CONFIG}" status')
    controller = runner.index(
        'systemctl start "hermes-factory-pre-q8-controller@${SCENARIO_ID}.service"'
    )
    worker = runner.index('systemctl start "hermes-factory-pre-q8-worker@${SCENARIO_ID}.service"')
    assert status < controller < worker


def test_pre_q8_resume_keeps_the_first_run_governor_contract() -> None:
    repository = Path(__file__).parents[1]
    governor = (repository / "factory/functional_readiness.py").read_text(encoding="utf-8")
    orchestrator = (repository / "scripts/qualification/run-all-pre-q8.sh").read_text(
        encoding="utf-8"
    )

    assert "attempt INTEGER NOT NULL CHECK(attempt=1)" in governor
    assert "PRIMARY KEY(epoch_id,scenario_id)" in governor
    assert "CREATE TABLE IF NOT EXISTS functional_phase_runs" in governor
    assert "PRIMARY KEY(epoch_id,phase_id)" in governor
    assert 'if [[ "${EXISTING}" == PASS ]]' in orchestrator
    assert '"${EXISTING}" != MISSING && "${EXISTING}" != RUNNING' in orchestrator
    assert 'phase-start "${PHASE_ID}" "${TIMEOUT_SECONDS}"' in (
        repository / "scripts/qualification/run-pre-q8-scenario.sh"
    ).read_text(encoding="utf-8")


def test_pre_q8_and_golden_deadlines_survive_service_restart() -> None:
    repository = Path(__file__).parents[1]
    pre_q8 = (repository / "scripts/qualification/run-pre-q8-scenario.sh").read_text(
        encoding="utf-8"
    )
    golden = (repository / "scripts/qualification/run-golden-product.sh").read_text(
        encoding="utf-8"
    )
    intake = (repository / "scripts/golden_intake.py").read_text(encoding="utf-8")

    assert 'STARTED_AT="$(date +%s)"' not in pre_q8
    assert "DEADLINE_EPOCH" in pre_q8
    assert "pre_q8_timeout" in pre_q8
    assert "INTERRUPTED=1; exit 75" in pre_q8
    assert 'STARTED_AT="$(date +%s)"' not in golden
    assert "INTAKE_DEADLINE" in golden
    assert "PRODUCT_DEADLINE" in golden
    assert "golden_intake_timeout" in golden
    assert "golden_product_timeout" in golden
    assert "INTERRUPTED=1; exit 75" in golden
    assert "deadline_digest" in intake
    assert "durable deadline expired" in intake


def test_post_functional_reconciler_drives_every_durable_release_state() -> None:
    repository = Path(__file__).parents[1]
    reconciler = (repository / "scripts/qualification/reconcile-functional.sh").read_text(
        encoding="utf-8"
    )

    for state in ("SHADOW_RUNNING", "CLEAN_CANARY", "PROMOTION_READY", "PROMOTED"):
        assert f"{state})" in reconciler
    assert "hermes-factory-shadow-verify.timer" in reconciler
    assert "hermes-factory-shadow-finalize.timer" in reconciler
    assert "hermes-factory-clean-canaries.service" in reconciler
    assert "hermes-factory-qualification-promote.service" in reconciler
    assert "hermes-factory-production-observation.timer" in reconciler
    assert "hermes-factory-ready-result.service" in reconciler


def test_lts_ready_result_is_signed_dispatched_and_persisted() -> None:
    repository = Path(__file__).parents[1]
    runner = (repository / "scripts/qualification/run-lts-ready.sh").read_text(encoding="utf-8")
    service = (repository / "config/systemd/hermes-factory-ready-result.service").read_text(
        encoding="utf-8"
    )
    result = (repository / "scripts/ready_result.py").read_text(encoding="utf-8")
    readiness = (repository / "factory/functional_readiness.py").read_text(encoding="utf-8")

    assert runner.index("lts-request") < runner.index("\n  sign ") < runner.index("lts-dispatch")
    assert "User=root" in service
    assert "PrivateNetwork=true" in service
    assert "FACTORY_LTS_READY" in result
    assert "AUTONOMOUS_FACTORY_READY" in result
    assert "record_factory_ready" in result
    assert result.index("receipt_path") < result.index("record_factory_ready")
    assert "hermes-factory-owner-notifier.service" in runner
    assert "FINAL_NOTIFICATION_PENDING" in runner
    assert "ready_result_manifest_digest" in readiness
    assert "ready_result_manifest_ref" in readiness


def test_owner_notifications_exclude_intermediate_qualification_progress() -> None:
    repository = Path(__file__).parents[1]
    functional = (repository / "scripts/functional_qualification.py").read_text(encoding="utf-8")
    result = (repository / "scripts/ready_result.py").read_text(encoding="utf-8")

    for kind in ("PRE_Q8_STARTED", "PRE_Q8_PROGRESS", "FACTORY_FUNCTIONALLY_READY"):
        assert f'kind="{kind}"' not in functional
    assert 'kind="Q7_STARTED"' not in result
    assert 'kind="FACTORY_LTS_READY"' in result


def test_interrupted_q8_resumes_one_governor_run_with_original_budget() -> None:
    repository = Path(__file__).parents[1]
    sequence = (repository / "scripts/qualification/run-all-clean-canaries.sh").read_text(
        encoding="utf-8"
    )
    runner = (repository / "scripts/qualification/run-clean-canary.sh").read_text(encoding="utf-8")
    status = (repository / "scripts/qualification_control.py").read_text(encoding="utf-8")

    assert 'if [[ "${EXISTING_STATUS}" == RUNNING ]]' in sequence
    assert "INTERRUPTED=1; exit 75" in runner
    assert "exit_status != 0 && INTERRUPTED == 0" in runner
    assert 'matches[0]["status"] == "RUNNING"' in runner
    assert 'if [[ "${CANARY_COUNT}" == 0 ]]' in runner
    assert 'if [[ "${PRESTART_STATUS}" != EMPTY ]]' in runner
    assert "datetime.fromisoformat" in runner
    assert 'STARTED_AT="$(date +%s)"' not in runner
    assert "canary_id,scenario_id,status,product_id,started_at" in status


def test_missing_stable_credentials_resume_only_after_external_file_change() -> None:
    repository = Path(__file__).parents[1]
    reconcile = (repository / "scripts/qualification/reconcile-functional.sh").read_text(
        encoding="utf-8"
    )
    waiting = reconcile[
        reconcile.index('if [[ "${STATUS}" == WAITING_CAPABILITY ]]') : reconcile.index(
            'if [[ "${STATUS}" == Q6_5_PROBE_REQUIRED ]]'
        )
    ]
    assert "product-github-capability.service" not in waiting
    assert "stable-provider-capability.service" not in waiting

    expectations = {
        "hermes-factory-product-github-capability.path": (
            "PathChanged=/etc/hermes-factory/credentials.d/github-token",
            "Unit=hermes-factory-product-github-capability.service",
        ),
        "hermes-factory-stable-provider-capability.path": (
            "PathChanged=/var/lib/hermes-factory/.hermes/auth.json",
            "Unit=hermes-factory-stable-provider-capability.service",
        ),
    }
    for name, required in expectations.items():
        unit = (repository / "config" / "systemd" / name).read_text(encoding="utf-8")
        assert all(value in unit for value in required)
    for name in (
        "hermes-factory-product-github-capability.service",
        "hermes-factory-stable-provider-capability.service",
    ):
        unit = (repository / "config" / "systemd" / name).read_text(encoding="utf-8")
        assert "OnSuccess=hermes-factory-functional-qualification.service" in unit
