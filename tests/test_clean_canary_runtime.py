from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from test_worker import (
    FakeRunner,
    make_config,
    release_operation,
    selected_registry,
    staging_release_task,
)

from factory.artifacts import ArtifactStore
from factory.canary_faults import (
    CanaryFaultContract,
    CanaryFaultError,
    CanaryFaultJournal,
    FaultInjectingHermesRunner,
    FaultInjectingQualityGate,
)
from factory.canary_release import IsolatedCanaryReleaseExecutor
from factory.common import sha256_text, utc_now
from factory.quality import QualityGateRun
from factory.release import ReleaseOperationFailed
from factory.release_executor import _release_digest
from factory.state import StateStore
from factory.worker import AgentWorker

ROOT = Path(__file__).parents[1]


def contract(tmp_path: Path, *faults: str) -> CanaryFaultContract:
    return CanaryFaultContract(
        scenario_id="qualification-scenario",
        scenario_digest="1" * 64,
        controller_release_digest="2" * 64,
        candidate_digest="3" * 64,
        faults=tuple(faults),
        receipt_root=tmp_path / "fault-receipts",
        isolated_target_root=tmp_path / "state" / "isolated-target",
    )


class PassingRunner:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, **values: Any) -> SimpleNamespace:
        self.calls += 1
        return SimpleNamespace(status="PASS", reason_code=None, output="{}")


def test_fault_transport_is_one_shot_and_digest_bound(tmp_path: Path) -> None:
    journal = CanaryFaultJournal(
        contract(tmp_path, "BOUNDED_EXTERNAL_BLOCK", "ONE_PROVIDER_TIMEOUT")
    )
    delegate = PassingRunner()
    runner = FaultInjectingHermesRunner(delegate, journal)
    values = {
        "selection": SimpleNamespace(),
        "prompt": "execute product task",
        "cwd": tmp_path,
        "usage_path": None,
    }

    first = runner.run(**values)
    second = runner.run(**values)
    third = runner.run(**values)

    assert (first.status, first.reason_code) == ("FAIL", "network_timeout")
    assert (second.status, second.reason_code) == (
        "TIMEOUT",
        "agent_execution_timeout",
    )
    assert third.status == "PASS"
    assert delegate.calls == 1
    assert journal.load("BOUNDED_EXTERNAL_BLOCK")["point"] == "provider_preflight"
    assert journal.load("ONE_PROVIDER_TIMEOUT")["point"] == "provider_transport"
    with pytest.raises(CanaryFaultError, match="more than once"):
        journal.consume("ONE_PROVIDER_TIMEOUT", point="provider_transport")


class PassingQuality:
    def __init__(self, artifacts: ArtifactStore) -> None:
        self.artifacts = artifacts
        self.calls = 0

    def run(self, **values: Any) -> QualityGateRun:
        self.calls += 1
        return QualityGateRun((), (), True)


def test_product_test_fault_fails_exactly_one_mandatory_gate(tmp_path: Path) -> None:
    config = make_config(
        tmp_path,
        selected_registry(tmp_path / "registry.yaml", selected="gpt-5.6-luna"),
    )
    delegate = PassingQuality(ArtifactStore(config))
    journal = CanaryFaultJournal(contract(tmp_path, "ONE_PRODUCT_TEST_FAILURE"))
    gate = FaultInjectingQualityGate(
        delegate,  # type: ignore[arg-type]
        journal,
        task_lookup=lambda _task_id: {"lifecycle_stage": "test"},
    )
    values = {
        "cwd": tmp_path,
        "subject_sha": "a" * 64,
        "task_id": "task-product-test",
        "attempt_id": "attempt-product-test",
        "gate_ids": ["unit-tests"],
    }

    injected = gate.run(**values)
    normal = gate.run(**values)

    assert injected.mandatory_passed is False
    assert injected.results[0]["status"] == "FAIL"
    evidence = json.loads(injected.evidence_paths[0].read_text(encoding="utf-8"))
    assert evidence["status"] == "FAIL"
    assert normal.mandatory_passed is True
    assert delegate.calls == 1


def _git(workspace: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(workspace), *arguments],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def test_isolated_release_rolls_back_once_then_promotes_repair(tmp_path: Path) -> None:
    config = make_config(
        tmp_path / "state",
        selected_registry(tmp_path / "registry.yaml", selected="gpt-5.6-luna"),
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _git(workspace, "init", "-b", "main")
    (workspace / "VERSION").write_text("1.0.0\n", encoding="utf-8")
    (workspace / "app.py").write_text("print('ready')\n", encoding="utf-8")
    _git(workspace, "add", "--all", "--")
    _git(
        workspace,
        "-c",
        "user.name=Canary Test",
        "-c",
        "user.email=canary@example.invalid",
        "commit",
        "-m",
        "initial",
    )
    journal = CanaryFaultJournal(
        contract(tmp_path, "ONE_POST_DEPLOY_HEALTH_FAILURE")
    )
    executor = IsolatedCanaryReleaseExecutor(config, journal)
    proposed = {
        "schema_version": "1.0",
        "artifact_id": "artifact-release",
        "created_at": utc_now(),
        "producer": {"role": "release-operator", "tier": "deterministic"},
        "policy_digest": sha256_text("policy"),
        "repository": "qualification/repository",
    }
    digest = _release_digest(workspace)

    with pytest.raises(ReleaseOperationFailed) as captured:
        executor.execute(
            stage="production",
            proposed=proposed,
            product_id="product-release-canary",
            task_contract={"task_id": "task-release-1", "idempotency_key": "first"},
            workspace=workspace,
            expected_staging_digest=digest,
        )
    assert captured.value.receipt_result["rollback"] == "succeeded"
    assert journal.load("ONE_POST_DEPLOY_HEALTH_FAILURE")["observed"]["rollback"] is True

    completed = executor.execute(
        stage="production",
        proposed=proposed,
        product_id="product-release-canary",
        task_contract={"task_id": "task-release-2", "idempotency_key": "repair"},
        workspace=workspace,
        expected_staging_digest=digest,
    )
    assert completed["status"] == "completed"
    assert completed["production"] == "deployed"
    assert completed["release"]["image_digest"] == digest


class ProvenFailedRelease:
    def execute(self, **values: Any) -> Any:
        raise ReleaseOperationFailed(
            "isolated health failed and rollback succeeded",
            reason_code="deployment_health_failed",
            receipt_ref="evidence/isolated-rollback.json",
            receipt_result={
                "status": "FAILED_SAFE",
                "reason_code": "deployment_health_failed",
                "product_id": values["product_id"],
                "stage": values["stage"],
                "rollback": "succeeded",
                "evidence_ref": "evidence/isolated-rollback.json",
            },
        )

    def reconcile(self, **values: Any) -> Any:
        return self.execute(**values)


def test_worker_persists_failed_release_receipt_before_repair_handoff(
    tmp_path: Path,
) -> None:
    config = make_config(
        tmp_path,
        selected_registry(tmp_path / "registry.yaml", selected="gpt-5.6-luna"),
    )
    state = StateStore(config.database_path)
    try:
        product_id, _ = staging_release_task(config, state, ArtifactStore(config))
        proposed = release_operation(
            config,
            product_id,
            candidate_sha="a" * 40,
            image_digest="sha256:" + "b" * 64,
        )
        worker = AgentWorker(
            config,
            state,
            runner=FakeRunner(json.dumps(proposed)),
            health_probe=lambda _selection: True,
            repository_root=ROOT,
            release_executor=ProvenFailedRelease(),
        )

        result = worker.run_once()

        assert result is not None
        assert result.status == "repair_handoff"
        assert result.reason_code == "deployment_health_failed"
        row = state._connection.execute(
            """SELECT intent.status,receipt.receipt_ref
                 FROM side_effect_intents AS intent
                 JOIN side_effect_receipts AS receipt USING(intent_id)
                WHERE intent.product_id=?""",
            (product_id,),
        ).fetchone()
        assert row is not None
        assert tuple(row) == ("VERIFIED", "evidence/isolated-rollback.json")
    finally:
        state.close()
