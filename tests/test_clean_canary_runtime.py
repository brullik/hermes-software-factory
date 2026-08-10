from __future__ import annotations

import json
import os
import stat
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
from factory.autonomy import CAPABILITY_PROFILES
from factory.canary_faults import (
    CanaryFaultContract,
    CanaryFaultError,
    CanaryFaultJournal,
    FaultInjectingHermesRunner,
    FaultInjectingQualityGate,
)
from factory.canary_qualification import load_canary_catalog
from factory.canary_release import IsolatedCanaryReleaseExecutor
from factory.capabilities import (
    CapabilityBroker,
    CapabilityCheck,
    ConfiguredCapabilityProbe,
    ProbeCommandResult,
)
from factory.common import sha256_file, sha256_text, utc_now
from factory.config import validate_config
from factory.credential_broker import BrokerReceipt, BrokerRequest
from factory.functional_readiness import (
    MANDATORY_Q6_5_OPERATIONS,
    CapabilityHandshakeReport,
    CapabilityStatus,
)
from factory.intake import IntakeService
from factory.quality import QualityGateRun
from factory.release import ReleaseOperationFailed
from factory.release_executor import _release_digest
from factory.state import StateStore
from factory.worker import AgentWorker

ROOT = Path(__file__).parents[1]


def clean_canary_config(tmp_path: Path):
    state_root = tmp_path / "state"
    config = make_config(
        state_root,
        selected_registry(tmp_path / "registry.yaml", selected="gpt-5.6-luna"),
    )
    catalog_path = ROOT / "qualification" / "canaries" / "catalog.yaml"
    scenario = load_canary_catalog(catalog_path)["deploy-rollback"]
    attestation = tmp_path / "canary-capability-attestation.json"
    attestation.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "plane": "CLEAN_CANARY",
                "capabilities": {},
            }
        ),
        encoding="utf-8",
    )
    config.raw["paths"]["canary_catalog"] = str(catalog_path)
    config.raw["deployment"].update(
        {
            "current_vps_high_risk_production": False,
            "production_helper": "",
            "rollback_helper": "",
            "production_target": {
                "mode": "isolated_candidate",
                "host": "clean-canary.invalid",
                "install_root": str(state_root / "isolated-target"),
                "entrypoint": "disabled",
            },
        }
    )
    config.raw["backup"].update(
        {
            "offsite_configured": False,
            "proof_path": str(state_root / "qualification" / "backup-proof.json"),
        }
    )
    config.raw["qualification"] = {
        "plane": "CLEAN_CANARY",
        "release_adapter": "IsolatedCanaryReleaseExecutor",
        "capability_attestation_path": str(attestation),
        "capability_attestation_digest": sha256_file(attestation),
        "scenario_id": scenario.scenario_id,
        "scenario_digest": scenario.scenario_digest,
        "controller_release_digest": "2" * 64,
        "candidate_digest": "3" * 64,
        "faults": list(scenario.injected_faults),
        "fault_receipt_root": str(state_root / "fault-receipts"),
        "isolated_target_root": str(state_root / "isolated-target"),
        "existing_repository_url": "",
    }
    return config


def test_clean_canary_preflight_uses_only_bound_release_substitutes(
    tmp_path: Path,
) -> None:
    config = clean_canary_config(tmp_path)
    assert validate_config(config) == []
    probe = ConfiguredCapabilityProbe(config)

    for capability, expected_operation in {
        "backup.verify": "content-addressed-release-snapshot",
        "production.deploy_transactional": "transactional-isolated-copy",
        "rollback.execute": "transactional-isolated-copy",
    }.items():
        check = probe.check(capability, product={"product_id": "canary-product"})
        assert check.status == "AVAILABLE"
        assert check.provider == "clean-canary-release-adapter"
        assert check.scope is not None
        assert check.scope["adapter"] == "IsolatedCanaryReleaseExecutor"
        assert check.scope["isolated_operation"] == expected_operation
        assert check.scope["allowed_operations"] == [capability]
        assert check.scope["scenario_id"] == "deploy-rollback"

    state = StateStore(config.database_path)
    try:
        required = CapabilityBroker(config, state)._required_for_product(
            {
                "delivery_profile": "DEPLOYED_SERVICE",
                "delivery_mode": "new_repository",
            }
        )
    finally:
        state.close()
    assert "toolchain.container_builder" in required
    assert "toolchain.python" in required
    assert "toolchain.scanners" in required
    assert "production.deploy_transactional" in required
    assert "github.pull_request.merge" in required


def test_clean_canary_substitutes_fail_closed_outside_state_root(
    tmp_path: Path,
) -> None:
    config = clean_canary_config(tmp_path)
    outside = tmp_path / "outside-target"
    config.raw["qualification"]["isolated_target_root"] = str(outside)
    config.raw["deployment"]["production_target"]["install_root"] = str(outside)
    config.raw["deployment"]["health_probe_url"] = (
        "https://clean-canary.invalid/healthz"
    )

    assert "clean canary capability boundary is invalid" in validate_config(config)
    probe = ConfiguredCapabilityProbe(
        config,
        command_runner=lambda _argv: ProbeCommandResult(127),
    )
    denied = probe.check(
        "production.deploy_transactional",
        product={"product_id": "escaped-canary-product"},
    )
    assert denied.status == "DENIED_POLICY"
    assert denied.provider == "production-boundary"

    state = StateStore(config.database_path)
    try:
        required = CapabilityBroker(config, state)._required_for_product(
            {
                "delivery_profile": "DEPLOYED_SERVICE",
                "delivery_mode": "new_repository",
            }
        )
    finally:
        state.close()
    assert "toolchain.container_builder" in required


def q6_5_report_index(path: Path, *, credential_epoch: str) -> Path:
    reports: list[CapabilityHandshakeReport] = []
    for index, operation in enumerate(MANDATORY_Q6_5_OPERATIONS):
        scope: dict[str, Any] = {"proof": "operation-specific"}
        operation_credential: str | None = None
        if index < 8:
            scope.update(
                {
                    "owner": "brullik",
                    "repository": "hermes-canary-q65-boundary",
                    "private": True,
                }
            )
            operation_credential = credential_epoch
        if operation == "github.repository.read":
            scope["repository_configuration"] = "verified"
        if operation == "git.branch.push":
            scope["workflow_write"] = "verified"
        if operation == "toolchain.container_builder":
            scope.update({"runtime": "rootless-podman", "network": "isolated"})
        reports.append(
            CapabilityHandshakeReport.create(
                candidate_digest="3" * 64,
                capability=operation,
                operation=operation,
                scope=scope,
                status=CapabilityStatus.AVAILABLE,
                credential_epoch_id=operation_credential,
                toolchain_digest="4" * 64,
                receipts=(sha256_text(operation),),
            )
        )
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "candidate_digest": "3" * 64,
        "toolchain_digest": "4" * 64,
        "credential_epoch_id": credential_epoch,
        "reports": [report.as_dict() for report in reports],
    }
    payload["index_digest"] = sha256_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":"))
    )
    payload["receipt_digest"] = sha256_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":"))
    )
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class Q65IdentityBroker:
    def __init__(self, credential_epoch: str) -> None:
        self.credential_epoch = credential_epoch
        self.calls: list[BrokerRequest] = []

    def execute(self, request: BrokerRequest) -> BrokerReceipt:
        self.calls.append(request)
        return BrokerReceipt(
            request_id=request.request_id,
            operation=request.operation,
            target_slug=f"{request.owner}/{request.repository}",
            subject_identity=request.owner,
            result="PASS",
            object_ids=(f"login:{request.owner}",),
            credential_epoch_id=self.credential_epoch,
            timestamp="2026-08-07T00:00:00Z",
            request_digest=request.digest(),
            receipt_digest=sha256_text(request.digest()),
        )


def test_clean_canary_github_preflight_binds_q6_5_and_live_broker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = clean_canary_config(tmp_path)
    credential_epoch = "CE-" + "A" * 32
    report_index = q6_5_report_index(
        tmp_path / "report-index.json",
        credential_epoch=credential_epoch,
    )
    broker = Q65IdentityBroker(credential_epoch)
    monkeypatch.setattr("factory.capabilities.shutil.which", lambda _name: "/safe/tool")
    probe = ConfiguredCapabilityProbe(
        config,
        command_runner=lambda _argv: pytest.fail("direct gh probe crossed broker boundary"),
        broker_client=broker,
        q6_5_report_index=report_index,
    )
    product = {
        "product_id": "clean-canary-product",
        "repository_name": "hermes-canary-deploy-rollback-boundary",
        "repository_visibility": "private",
    }

    for capability in (
        "repository.read",
        "github.repository.create",
        "github.repository.configure",
        "github.workflow.write",
        "git.initial_commit",
        "git.push_branch",
        "github.pull_request.create",
        "github.checks.read",
        "github.pull_request.verify",
        "github.pull_request.merge",
    ):
        check = probe.check(capability, product=product)
        assert check.status == "AVAILABLE"
        assert check.provider == "candidate-github-broker"
        assert check.scope is not None
        assert check.scope["credential_epoch_id"] == credential_epoch
        assert check.scope["q6_5_index_digest"]
        assert check.scope["q6_5_report_digests"]
    assert {request.operation for request in broker.calls} == {"identity.read"}


def test_clean_canary_container_builder_binds_exact_q6_5_proof(
    tmp_path: Path,
) -> None:
    config = clean_canary_config(tmp_path)
    credential_epoch = "CE-" + "C" * 32
    report_index = q6_5_report_index(
        tmp_path / "report-index.json",
        credential_epoch=credential_epoch,
    )
    check = ConfiguredCapabilityProbe(
        config,
        command_runner=lambda _argv: pytest.fail(
            "clean canary container grant must use immutable Q6.5 evidence"
        ),
        q6_5_report_index=report_index,
    ).check(
        "toolchain.container_builder",
        product={"product_id": "clean-canary-product"},
    )

    assert check.status == "AVAILABLE"
    assert check.provider == "candidate-q6-5-proof"
    assert check.scope is not None
    assert check.scope["allowed_operations"] == ["toolchain.container_builder"]
    assert check.scope["runtime"] == "rootless-podman"
    assert check.scope["network"] == "isolated"
    assert check.scope["candidate_digest"] == "3" * 64
    assert check.scope["q6_5_index_digest"]
    assert check.scope["q6_5_report_digest"]


def test_clean_canary_q6_5_container_grant_resumes_builder_frontier(
    tmp_path: Path,
) -> None:
    config = clean_canary_config(tmp_path)
    credential_epoch = "CE-" + "E" * 32
    report_index = q6_5_report_index(
        tmp_path / "report-index.json",
        credential_epoch=credential_epoch,
    )
    exact_probe = ConfiguredCapabilityProbe(
        config,
        command_runner=lambda _argv: pytest.fail(
            "clean canary container grant must use immutable Q6.5 evidence"
        ),
        q6_5_report_index=report_index,
    )

    class ProductProbe:
        def check(
            self,
            capability: str,
            *,
            product: dict[str, Any],
        ) -> CapabilityCheck:
            if capability == "toolchain.container_builder":
                return exact_probe.check(capability, product=product)
            return CapabilityCheck(
                capability,
                "AVAILABLE",
                "bounded-test-provider",
                scope={"allowed_operations": [capability]},
            )

    state = StateStore(config.database_path)
    try:
        intake = IntakeService(config, state, ArtifactStore(config)).submit(
            source="cli",
            owner_id="owner",
            goal_text="Build the clean canary product",
            delivery_mode="new_repository",
            repository_name="hermes-canary-q65-container-grant",
            repository_visibility="private",
        )
        task_id = "T-CLEAN-CANARY-Q65-BUILDER"
        state.add_task(
            task_id=task_id,
            product_id=intake.product_id,
            title="Build the isolated product",
            role="builder",
            output_schema="attempt-result.schema.json",
            stage_key="implementation-slice",
            capability_profile="builder_workspace",
            required_capabilities=[
                *CAPABILITY_PROFILES["builder_workspace"],
                "toolchain.container_builder",
            ],
            graph_status="BLOCKED_CAPABILITY",
        )
        CapabilityBroker(config, state, probe=ProductProbe()).preflight_product(
            intake.product_id
        )

        task = state.get_task(task_id)
        assert task is not None
        assert task["graph_status"] == "READY"
        grants = state.available_capabilities(
            intake.product_id,
            task_id,
            ["toolchain.container_builder"],
        )
        assert len(grants) == 1
        assert grants[0]["provider"] == "candidate-q6-5-proof"
    finally:
        state.close()


def test_clean_canary_container_builder_rejects_unscoped_q6_5_proof(
    tmp_path: Path,
) -> None:
    config = clean_canary_config(tmp_path)
    credential_epoch = "CE-" + "D" * 32
    report_index = q6_5_report_index(
        tmp_path / "report-index.json",
        credential_epoch=credential_epoch,
    )
    payload = json.loads(report_index.read_text(encoding="utf-8"))
    for report in payload["reports"]:
        if report["operation"] == "toolchain.container_builder":
            report["scope"] = {"runtime": "unscoped", "network": "unknown"}
            report_without_digest = {
                key: value for key, value in report.items() if key != "report_digest"
            }
            report["report_digest"] = sha256_text(
                json.dumps(report_without_digest, sort_keys=True, separators=(",", ":"))
            )
            break
    index_without_digests = {
        key: value
        for key, value in payload.items()
        if key not in {"index_digest", "receipt_digest"}
    }
    payload["index_digest"] = sha256_text(
        json.dumps(index_without_digests, sort_keys=True, separators=(",", ":"))
    )
    receipt_payload = {
        key: value for key, value in payload.items() if key != "receipt_digest"
    }
    payload["receipt_digest"] = sha256_text(
        json.dumps(receipt_payload, sort_keys=True, separators=(",", ":"))
    )
    report_index.write_text(json.dumps(payload), encoding="utf-8")

    check = ConfiguredCapabilityProbe(
        config,
        q6_5_report_index=report_index,
    ).check(
        "toolchain.container_builder",
        product={"product_id": "unscoped-container-proof"},
    )
    assert check.status == "DENIED_POLICY"
    assert check.reason_code == "controller_q6_5_evidence_invalid"


def test_clean_canary_github_preflight_rejects_tampered_q6_5_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = clean_canary_config(tmp_path)
    credential_epoch = "CE-" + "B" * 32
    report_index = q6_5_report_index(
        tmp_path / "report-index.json",
        credential_epoch=credential_epoch,
    )
    payload = json.loads(report_index.read_text(encoding="utf-8"))
    payload["candidate_digest"] = "9" * 64
    report_index.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr("factory.capabilities.shutil.which", lambda _name: "/safe/tool")
    check = ConfiguredCapabilityProbe(
        config,
        broker_client=Q65IdentityBroker(credential_epoch),
        q6_5_report_index=report_index,
    ).check(
        "github.repository.create",
        product={
            "product_id": "tampered-proof",
            "repository_name": "hermes-canary-tampered-proof",
            "repository_visibility": "private",
        },
    )
    assert check.status == "DENIED_POLICY"
    assert check.reason_code == "controller_q6_5_evidence_invalid"


@pytest.mark.skipif(os.name != "posix", reason="POSIX group boundary is required")
def test_clean_canary_repository_initializer_opens_only_shared_broker_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = clean_canary_config(tmp_path)
    state = StateStore(config.database_path)
    intake = IntakeService(config, state, ArtifactStore(config)).submit(
        source="cli",
        owner_id="owner",
        goal_text="Build an isolated service",
        delivery_mode="new_repository",
        repository_name="hermes-canary-shared-workspace",
    )

    class Bootstrap:
        def ensure(self, product_id: str, destination: Path) -> dict[str, str]:
            assert product_id == intake.product_id
            assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o2770
            destination.mkdir(mode=0o770)
            destination.chmod(0o770)
            return {}

    worker = AgentWorker(
        config,
        state,
        runner=FakeRunner("{}"),
        health_probe=lambda _: True,
        repository_bootstrapper=Bootstrap(),  # type: ignore[arg-type]
    )
    worker.workspace.root.chmod(0o2775)
    monkeypatch.setenv(
        "HERMES_GITHUB_BROKER_SOCKET",
        "/run/hermes-factory-github-broker/broker.sock",
    )
    lease = worker.workspace.acquire(
        product_id=intake.product_id,
        task_id="T-CLEAN-CANARY-WORKSPACE",
        worker_id="worker-1",
    )
    assert stat.S_IMODE(lease.path.parent.stat().st_mode) == 0o2770
    assert stat.S_IMODE(lease.path.stat().st_mode) == 0o770
    state.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX group boundary is required")
def test_clean_canary_repository_initializer_keeps_prepared_setgid_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = clean_canary_config(tmp_path)
    state = StateStore(config.database_path)
    intake = IntakeService(config, state, ArtifactStore(config)).submit(
        source="cli",
        owner_id="owner",
        goal_text="Build an isolated service",
        delivery_mode="new_repository",
        repository_name="hermes-canary-prepared-workspace",
    )

    class Bootstrap:
        def ensure(self, product_id: str, destination: Path) -> dict[str, str]:
            assert product_id == intake.product_id
            destination.mkdir(mode=0o770)
            destination.chmod(0o770)
            return {}

    worker = AgentWorker(
        config,
        state,
        runner=FakeRunner("{}"),
        health_probe=lambda _: True,
        repository_bootstrapper=Bootstrap(),  # type: ignore[arg-type]
    )
    worker.workspace.root.chmod(0o2775)
    prepared_parent = worker.workspace.root / intake.product_id
    prepared_parent.mkdir(mode=0o770)
    prepared_parent.chmod(0o2770)
    original_chmod = os.chmod

    def guarded_chmod(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int,
        *,
        follow_symlinks: bool = True,
    ) -> None:
        if Path(os.fsdecode(path)).resolve() == prepared_parent.resolve():
            pytest.fail("prepared setgid parent must not be chmodded inside the worker sandbox")
        original_chmod(path, mode, follow_symlinks=follow_symlinks)

    monkeypatch.setattr("factory.worker.os.chmod", guarded_chmod)
    monkeypatch.setenv(
        "HERMES_GITHUB_BROKER_SOCKET",
        "/run/hermes-factory-github-broker/broker.sock",
    )
    lease = worker.workspace.acquire(
        product_id=intake.product_id,
        task_id="T-CLEAN-CANARY-PREPARED",
        worker_id="worker-1",
    )
    assert stat.S_IMODE(lease.path.parent.stat().st_mode) == 0o2770
    assert stat.S_IMODE(lease.path.stat().st_mode) == 0o770
    state.close()


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
        self.gate_calls: list[list[str]] = []

    def run(self, **values: Any) -> QualityGateRun:
        self.calls += 1
        gate_ids = [str(value) for value in values.get("gate_ids", [])]
        self.gate_calls.append(gate_ids)
        return QualityGateRun(
            tuple(
                {
                    "gate_id": gate_id,
                    "status": "PASS",
                    "evidence_ref": f"evidence/{gate_id}.json",
                }
                for gate_id in gate_ids
            ),
            (),
            True,
        )


def _product_test_fault_gate(
    tmp_path: Path,
) -> tuple[FaultInjectingQualityGate, PassingQuality, CanaryFaultJournal]:
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
    return gate, delegate, journal


def test_product_test_fault_injects_target_tests_only(tmp_path: Path) -> None:
    gate, _, journal = _product_test_fault_gate(tmp_path)
    values = {
        "cwd": tmp_path,
        "subject_sha": "a" * 64,
        "task_id": "task-product-test",
        "attempt_id": "attempt-product-test",
        "gate_ids": ["target-environment", "target-tests", "target-compile"],
    }

    injected = gate.run(**values)

    assert injected.mandatory_passed is False
    failed = [item for item in injected.results if item["status"] == "FAIL"]
    assert [item["gate_id"] for item in failed] == ["target-tests"]
    evidence = json.loads(injected.evidence_paths[-1].read_text(encoding="utf-8"))
    assert evidence["status"] == "FAIL"
    receipt = journal.load("ONE_PRODUCT_TEST_FAILURE")
    assert receipt["point"] == "mandatory_product_test"
    assert receipt["observed"]["gate_id"] == "target-tests"


def test_product_test_fault_runs_preceding_gates_first(tmp_path: Path) -> None:
    gate, delegate, _ = _product_test_fault_gate(tmp_path)

    injected = gate.run(
        cwd=tmp_path,
        subject_sha="b" * 64,
        task_id="task-product-test",
        attempt_id="attempt-product-test",
        gate_ids=["target-environment", "target-secret-scan", "target-tests"],
    )

    assert delegate.gate_calls == [["target-environment", "target-secret-scan"]]
    assert [item["gate_id"] for item in injected.results] == [
        "target-environment",
        "target-secret-scan",
        "target-tests",
    ]


def test_product_test_fault_is_consumed_once(tmp_path: Path) -> None:
    gate, delegate, journal = _product_test_fault_gate(tmp_path)
    first = {
        "cwd": tmp_path,
        "subject_sha": "c" * 64,
        "task_id": "task-product-test",
        "attempt_id": "attempt-product-test-first",
        "gate_ids": ["target-environment", "target-tests"],
    }

    injected = gate.run(**first)
    normal = gate.run(
        **{
            **first,
            "attempt_id": "attempt-product-test-second",
        }
    )

    assert injected.mandatory_passed is False
    assert normal.mandatory_passed is True
    assert delegate.gate_calls == [
        ["target-environment"],
        ["target-environment", "target-tests"],
    ]
    assert delegate.calls == 2
    assert journal.consumed("ONE_PRODUCT_TEST_FAILURE")


def test_product_test_fault_requires_canonical_target_gate(tmp_path: Path) -> None:
    gate, delegate, journal = _product_test_fault_gate(tmp_path)

    with pytest.raises(CanaryFaultError, match="canonical fault gate is missing"):
        gate.run(
            cwd=tmp_path,
            subject_sha="d" * 64,
            task_id="task-product-test",
            attempt_id="attempt-product-test",
            gate_ids=["target-environment", "target-compile"],
        )

    assert delegate.calls == 0
    assert not journal.consumed("ONE_PRODUCT_TEST_FAILURE")


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
