from __future__ import annotations

import ast
import base64
import hashlib
import json
import runpy
import sqlite3
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from factory.common import sha256_text
from factory.credential_broker import (
    BrokerPolicy,
    BrokerReceipt,
    BrokerRequest,
    CredentialBrokerError,
    GitHubCredentialBroker,
)
from factory.functional_readiness import (
    MANDATORY_Q6_5_OPERATIONS,
    PRE_Q8_SCENARIOS,
    CandidateDatabaseVerifier,
    CapabilityHandshakeReport,
    CapabilityStatus,
    FunctionalQualificationGovernor,
    FunctionalReadinessError,
    ReadyResultManifest,
    verify_ready_result_manifest,
)
from factory.notifications import NotificationOutbox, NotificationRequest, OwnerNotifier
from factory.providers import ModelSelection
from factory.q6_5 import (
    GitHubOperationHandshake,
    ProbeIdentity,
    ProviderOperationHandshake,
    external_operation_report,
)
from factory.recursive_improvement import (
    ComparativeEvaluation,
    ImprovementError,
    ImprovementProposal,
    RecursiveImprovementGovernor,
)
from factory.release_qualification import QualificationError, ReleaseQualificationGovernor
from factory.state import StateStore
from factory.support_bundle import build_support_bundle
from factory.telegram import TelegramApi
from factory.worker import HermesRunResult
from scripts import functional_qualification

DIGEST = "a" * 64
TOOLCHAIN = "b" * 64
COMMIT = "c" * 40


def _functional_governor() -> FunctionalQualificationGovernor:
    connection = sqlite3.connect(":memory:")
    governor = FunctionalQualificationGovernor(connection)
    governor.register_epoch(
        epoch_id="RE-FUNCTIONAL-1",
        source_commit=COMMIT,
        candidate_digest=DIGEST,
        toolchain_digest=TOOLCHAIN,
    )
    return governor


def test_functional_epoch_reader_uses_checkpointed_immutable_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "governor.db"
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "CREATE TABLE controller_release_epochs ("
            "epoch_id TEXT, source_commit TEXT, candidate_digest TEXT, status TEXT, "
            "created_at TEXT)"
        )
        connection.execute(
            "INSERT INTO controller_release_epochs VALUES (?,?,?,?,?)",
            ("RE-IMMUTABLE", COMMIT, DIGEST, "FUNCTIONAL_PENDING", "2026-08-06T00:00:00Z"),
        )
        connection.commit()
    finally:
        connection.close()
    observed: list[str] = []
    real_connect = sqlite3.connect

    def recording_connect(database_uri: str, *args: Any, **kwargs: Any) -> sqlite3.Connection:
        observed.append(str(database_uri))
        return real_connect(database_uri, *args, **kwargs)

    monkeypatch.setattr(functional_qualification.sqlite3, "connect", recording_connect)
    assert functional_qualification._release_epoch(
        {
            "governor_database": str(database),
            "source_commit": COMMIT,
            "candidate_digest": DIGEST,
        }
    ) == "RE-IMMUTABLE"
    assert observed == [f"file:{database.resolve().as_posix()}?mode=ro&immutable=1"]


def test_release_governor_functional_failure_is_state_scoped(tmp_path: Path) -> None:
    state = StateStore(tmp_path / "governor.db")
    governor = ReleaseQualificationGovernor(state._connection)
    epoch_id = governor.create_epoch(
        source_commit=COMMIT,
        stable_release_digest="1" * 64,
        controller_release_digest="2" * 64,
        candidate_digest=DIGEST,
        policy_digest="3" * 64,
        toolchain_manifest_digest=TOOLCHAIN,
    )
    with pytest.raises(QualificationError, match="FUNCTIONAL_PENDING"):
        governor.fail_functional_orchestration(
            epoch_id=epoch_id,
            evidence_ref="artifact://qualification/functional-orchestration-failure/" + "4" * 64,
        )
    state._connection.execute(
        "UPDATE controller_release_epochs SET status='FUNCTIONAL_PENDING' WHERE epoch_id=?",
        (epoch_id,),
    )
    governor.fail_functional_orchestration(
        epoch_id=epoch_id,
        evidence_ref="artifact://qualification/functional-orchestration-failure/" + "4" * 64,
    )
    assert governor.epoch(epoch_id)["status"] == "QUALIFICATION_FAILED"
    state.close()


def test_golden_builder_reads_single_owner_from_stable_environment(
    tmp_path: Path,
) -> None:
    root = Path(__file__).parents[1]
    namespace = runpy.run_path(
        str(root / "scripts" / "bootstrap" / "build-golden-config.py")
    )
    resolve = namespace["_resolve_owner_ids"]
    environment = tmp_path / "telegram.env"
    environment.write_text(
        "# Stable owner binding\nFACTORY_TELEGRAM_OWNER_ID='123456789'\n",
        encoding="utf-8",
    )
    environment.chmod(0o640)

    assert resolve({"telegram": {"allowed_user_ids": []}}, environment) == [
        "123456789"
    ]
    assert resolve(
        {"telegram": {"allowed_user_ids": [123456789]}}, environment
    ) == ["123456789"]
    with pytest.raises(ValueError, match="exactly one"):
        resolve({"telegram": {"allowed_user_ids": [987654321]}}, environment)


def _report(
    operation: str,
    *,
    status: CapabilityStatus = CapabilityStatus.AVAILABLE,
    credential_epoch: str | None = "CE-1",
) -> CapabilityHandshakeReport:
    return CapabilityHandshakeReport.create(
        candidate_digest=DIGEST,
        capability=operation,
        operation=operation,
        scope={"allowed_operations": [operation]},
        status=status,
        credential_epoch_id=credential_epoch,
        toolchain_digest=TOOLCHAIN,
        receipts=(sha256_text(operation),) if status == CapabilityStatus.AVAILABLE else (),
        safe_reason_code=(
            None if status == CapabilityStatus.AVAILABLE else "missing_credential"
        ),
    )


def _pass_q6_5(governor: FunctionalQualificationGovernor) -> None:
    for operation in MANDATORY_Q6_5_OPERATIONS:
        governor.record_handshake("RE-FUNCTIONAL-1", _report(operation))


def _pass_pre_q8(governor: FunctionalQualificationGovernor) -> None:
    for scenario in PRE_Q8_SCENARIOS:
        governor.record_pre_q8_pass(
            epoch_id="RE-FUNCTIONAL-1",
            scenario_id=scenario,
            attempt=1,
            product_id=f"product-{scenario}",
            completion_manifest_ref=f"artifact://completion/{scenario}",
            evidence_digest=sha256_text(scenario),
        )


def _pass_golden(governor: FunctionalQualificationGovernor) -> None:
    governor.record_golden_product(
        epoch_id="RE-FUNCTIONAL-1",
        product_id="hermes-golden-acceptance",
        repository_ref="github://brullik/hermes-golden-acceptance",
        merge_commit="d" * 40,
        artifact_digest="e" * 64,
        completion_manifest_ref="artifact://completion/golden",
        verifier_digest="f" * 64,
    )


def test_wf_p0_001_capability_reports_bind_exact_candidate_and_receipts() -> None:
    report = _report("github.identity.read")
    assert report.as_dict()["candidate_digest"] == DIGEST
    assert report.receipts == (sha256_text("github.identity.read"),)
    report.validate()


def test_wf_p0_004_expired_capability_does_not_pass_q6_5() -> None:
    governor = _functional_governor()
    governor.record_handshake(
        "RE-FUNCTIONAL-1",
        _report("github.identity.read", status=CapabilityStatus.EXPIRED),
    )
    assert governor.epoch("RE-FUNCTIONAL-1")["q6_5_status"] == "PENDING"


def test_wf_p0_005_missing_credential_owner_action_is_single_and_epoch_bound() -> None:
    governor = _functional_governor()
    governor.record_handshake(
        "RE-FUNCTIONAL-1",
        _report(
            "github.identity.read",
            status=CapabilityStatus.MISSING_EXTERNAL,
            credential_epoch=None,
        ),
    )
    first = governor.ensure_owner_action(
        epoch_id="RE-FUNCTIONAL-1",
        reason_code="missing_candidate_github_credential",
        capability="github.identity.read",
        capability_epoch=None,
    )
    second = governor.ensure_owner_action(
        epoch_id="RE-FUNCTIONAL-1",
        reason_code="missing_candidate_github_credential",
        capability="github.identity.read",
        capability_epoch=None,
    )
    assert first == second
    assert not governor.capability_epoch_changed(
        epoch_id="RE-FUNCTIONAL-1", old_epoch=None, new_epoch=None
    )
    assert governor.capability_epoch_changed(
        epoch_id="RE-FUNCTIONAL-1", old_epoch=None, new_epoch="CE-2"
    )


def test_wf_p0_002_003_broker_hides_token_and_enforces_allowlist(tmp_path: Path) -> None:
    credential = tmp_path / "github-token"
    token = "fixture-token-not-a-real-secret"
    credential.write_text(token, encoding="utf-8")
    credential.chmod(0o600)
    seen_environments: list[dict[str, str]] = []

    def runner(
        argv: list[str], environment: Any, cwd: Path | None
    ) -> subprocess.CompletedProcess[str]:
        seen_environments.append(dict(environment))
        if argv[-1] == "user":
            output = json.dumps({"login": "brullik", "id": 1})
        else:
            output = json.dumps({"full_name": "brullik/hermes-canary-one", "id": 2})
        return subprocess.CompletedProcess(argv, 0, output, "")

    broker = GitHubCredentialBroker(
        policy=BrokerPolicy(owner="brullik", repository_prefixes=("hermes-canary-",)),
        credential_path=credential,
        receipt_root=tmp_path / "receipts",
        credential_epoch_id="CE-1",
        command_runner=runner,
    )
    receipt = broker.execute(
        BrokerRequest(
            request_id="request-0001",
            operation="repository.create_private",
            owner="brullik",
            repository="hermes-canary-one",
            payload={"visibility": "private"},
        )
    )
    assert receipt.result == "PASS"
    assert token not in json.dumps(receipt.as_dict())
    assert all(environment["GH_TOKEN"] == token for environment in seen_environments)
    with pytest.raises(CredentialBrokerError, match="replay request conflicts"):
        broker.execute(
            BrokerRequest(
                request_id="request-0001",
                operation="repository.create_private",
                owner="brullik",
                repository="hermes-canary-one",
                payload={"visibility": "private", "description": "changed after receipt"},
            )
        )
    with pytest.raises(CredentialBrokerError, match="outside allowlist"):
        broker.execute(
            BrokerRequest(
                request_id="request-0002",
                operation="repository.read",
                owner="brullik",
                repository="hermes-software-factory",
                payload={},
            )
        )
    with pytest.raises(CredentialBrokerError, match="public"):
        broker.execute(
            BrokerRequest(
                request_id="request-0003",
                operation="repository.create_private",
                owner="brullik",
                repository="hermes-canary-public",
                payload={"visibility": "public"},
            )
        )


def test_wf_p0_014_015_016_q7_rejected_until_all_functional_gates() -> None:
    governor = _functional_governor()
    with pytest.raises(FunctionalReadinessError, match="Q7 start rejected"):
        governor.authorize_q7("RE-FUNCTIONAL-1")
    _pass_q6_5(governor)
    with pytest.raises(FunctionalReadinessError, match="Q7 start rejected"):
        governor.authorize_q7("RE-FUNCTIONAL-1")
    _pass_pre_q8(governor)
    with pytest.raises(FunctionalReadinessError, match="Q7 start rejected"):
        governor.authorize_q7("RE-FUNCTIONAL-1")
    _pass_golden(governor)
    with pytest.raises(FunctionalReadinessError, match="Q7 start rejected"):
        governor.authorize_q7("RE-FUNCTIONAL-1")
    governor.record_factory_checks(
        epoch_id="RE-FUNCTIONAL-1",
        internal_verifier_pass=True,
        stable_health_pass=True,
        stable_intake_pass=True,
    )
    first = governor.authorize_q7("RE-FUNCTIONAL-1")
    second = governor.authorize_q7("RE-FUNCTIONAL-1")
    assert first == second


def test_wf_p0_017_preq8_rejects_second_attempt() -> None:
    governor = _functional_governor()
    _pass_q6_5(governor)
    with pytest.raises(FunctionalReadinessError, match="first-run"):
        governor.record_pre_q8_pass(
            epoch_id="RE-FUNCTIONAL-1",
            scenario_id=PRE_Q8_SCENARIOS[0],
            attempt=2,
            product_id="product",
            completion_manifest_ref="artifact://completion/product",
            evidence_digest="a" * 64,
        )


def _candidate_database(tmp_path: Path, *, product_status: str, task_status: str) -> Path:
    path = tmp_path / "candidate.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE products(product_id TEXT,status TEXT,created_at TEXT);
        CREATE TABLE tasks(product_id TEXT,status TEXT,created_at TEXT);
        CREATE TABLE failures(product_id TEXT,reason_code TEXT,first_seen_at TEXT);
        CREATE TABLE controller_incidents(
          product_id TEXT,reason_code TEXT,status TEXT,created_at TEXT
        );
        CREATE TABLE completion_manifests(product_id TEXT);
        """
    )
    connection.execute("INSERT INTO products VALUES ('p',?,'1')", (product_status,))
    connection.execute("INSERT INTO tasks VALUES ('p',?,'1')", (task_status,))
    connection.commit()
    connection.close()
    return path


def test_wf_p0_009_failed_safe_is_terminal_even_if_worker_active(tmp_path: Path) -> None:
    truth = CandidateDatabaseVerifier.inspect(
        _candidate_database(tmp_path, product_status="FAILED_SAFE", task_status="BLOCKED_EXTERNAL")
    )
    assert truth.scenario_status == "TERMINAL_FAILURE"


def test_wf_p0_010_blocked_external_is_waiting_capability(tmp_path: Path) -> None:
    truth = CandidateDatabaseVerifier.inspect(
        _candidate_database(tmp_path, product_status="BUILDING", task_status="BLOCKED_EXTERNAL")
    )
    assert truth.scenario_status == "WAITING_CAPABILITY"


def test_wf_p0_011_idle_without_frontier_is_liveness_finding(tmp_path: Path) -> None:
    truth = CandidateDatabaseVerifier.inspect(
        _candidate_database(tmp_path, product_status="BUILDING", task_status="FAILED"),
        worker_idle=True,
    )
    assert truth.scenario_status == "LIVENESS_FINDING"
    assert truth.liveness_finding


def test_wf_p0_012_013_completed_requires_internal_manifest_and_verifier(
    tmp_path: Path,
) -> None:
    database = _candidate_database(
        tmp_path, product_status="COMPLETED", task_status="COMPLETED"
    )
    assert CandidateDatabaseVerifier.inspect(database).scenario_status == "VERIFY_FAILED"
    connection = sqlite3.connect(database)
    connection.execute("INSERT INTO completion_manifests VALUES ('p')")
    connection.commit()
    connection.close()
    truth = CandidateDatabaseVerifier.inspect(
        database,
        independent_completion_verifier=lambda _connection, product_id: product_id == "p",
    )
    assert truth.scenario_status == "PASS"


def _proposal(objective: str = "objective-1", root: str = "root-1") -> ImprovementProposal:
    return ImprovementProposal(
        objective_id=objective,
        root_cause_key=root,
        baseline_digest="1" * 64,
        observed_deficit={"completion_time": 100.0},
        proposal={"mechanism": "bounded deterministic cache"},
        affected_components=("context_builder",),
        expected_delta={"completion_time": -10.0},
        non_regression_obligations=("all safety metrics non-regressed",),
        risk_class="low",
        max_cycles=3,
        max_implementation_attempts=2,
        evidence_refs=("artifact://metrics/baseline",),
    )


def _evaluation(*, candidate_time: float, independent: bool = True) -> ComparativeEvaluation:
    baseline = {metric: 0.0 for metric in (
        "unknown_transitions",
        "privilege_expansion",
        "duplicate_side_effects",
        "manual_database_mutations",
        "controller_recovery_in_clean_run",
        "high_critical_security_findings",
    )}
    baseline["completion_time"] = 100.0
    candidate = dict(baseline)
    candidate["completion_time"] = candidate_time
    return ComparativeEvaluation(
        baseline_scorecard=baseline,
        candidate_scorecard=candidate,
        safety_regressions=(),
        target_metric="completion_time",
        minimum_delta=10.0,
        independent=independent,
        evidence_refs=("artifact://comparison/1",),
    )


def _improvement_governor(tmp_path: Path) -> RecursiveImprovementGovernor:
    stable = tmp_path / "stable"
    isolated = tmp_path / "candidate-lab"
    stable.mkdir()
    isolated.mkdir()
    return RecursiveImprovementGovernor(
        sqlite3.connect(":memory:"), stable_root=stable, isolated_root=isolated
    )


def test_wf_p0_027_028_improvement_is_isolated_and_single(tmp_path: Path) -> None:
    governor = _improvement_governor(tmp_path)
    governor.propose(_proposal(), target_metric="completion_time")
    candidate = tmp_path / "candidate-lab" / "cycle-1"
    candidate.mkdir()
    governor.start_cycle(
        objective_id="objective-1",
        branch_name="codex/improvement-1",
        candidate_digest="2" * 64,
        experiment_root=candidate,
    )
    assert governor.active_experiment_count() == 1
    with pytest.raises((ImprovementError, sqlite3.IntegrityError)):
        governor.propose(
            _proposal(objective="objective-2", root="root-2"),
            target_metric="completion_time",
        )
    with pytest.raises(ImprovementError, match="outside isolated"):
        governor.start_cycle(
            objective_id="objective-1",
            branch_name="codex/forbidden",
            candidate_digest="3" * 64,
            experiment_root=tmp_path / "stable",
        )


def test_wf_p0_029_032_accepted_cycle_creates_immutable_release_epoch(
    tmp_path: Path,
) -> None:
    governor = _improvement_governor(tmp_path)
    governor.propose(_proposal(), target_metric="completion_time")
    candidate = tmp_path / "candidate-lab" / "cycle-1"
    candidate.mkdir()
    cycle = governor.start_cycle(
        objective_id="objective-1",
        branch_name="codex/improvement-1",
        candidate_digest="2" * 64,
        experiment_root=candidate,
    )
    assert governor.record_implementation_attempt(cycle) == 1
    assert governor.evaluate(
        cycle_id=cycle,
        evaluation=_evaluation(candidate_time=80.0),
        request_next_cycle=False,
    ) == "ACCEPT"
    row = governor.connection.execute(
        "SELECT status FROM improvement_release_epochs"
    ).fetchone()
    assert row[0] == "FULL_QUALIFICATION_REQUIRED"


def test_wf_p0_030_031_034_no_progress_or_safety_regression_rejects(
    tmp_path: Path,
) -> None:
    governor = _improvement_governor(tmp_path)
    with pytest.raises(ImprovementError, match="non-zero"):
        proposal = _proposal()
        ImprovementProposal(
            **{**proposal.__dict__, "expected_delta": {"completion_time": 0.0}}
        ).validate()
    governor.propose(_proposal(), target_metric="completion_time")
    candidate = tmp_path / "candidate-lab" / "cycle-1"
    candidate.mkdir()
    cycle = governor.start_cycle(
        objective_id="objective-1",
        branch_name="codex/improvement-1",
        candidate_digest="2" * 64,
        experiment_root=candidate,
    )
    assert governor.evaluate(
        cycle_id=cycle,
        evaluation=_evaluation(candidate_time=95.0),
        request_next_cycle=True,
    ) == "REJECT"
    with pytest.raises(ImprovementError):
        governor.start_cycle(
            objective_id="objective-1",
            branch_name="codex/improvement-2",
            candidate_digest="3" * 64,
            experiment_root=candidate,
        )


def test_wf_p0_033_forbidden_gate_change_is_rejected() -> None:
    proposal = _proposal()
    forbidden = ImprovementProposal(
        **{**proposal.__dict__, "affected_components": ("mandatory_gates",)}
    )
    with pytest.raises(ImprovementError, match="forbidden"):
        forbidden.validate()


def test_wf_p0_040_041_042_ready_manifest_requires_evidence_and_exact_state() -> None:
    manifest = ReadyResultManifest.create(
        manifest_type="PRODUCT_READY_RESULT",
        subject={"product_id": "golden", "state": "COMPLETED"},
        version="2.5.0",
        commit=COMMIT,
        digest=DIGEST,
        mandatory_obligations=(
            {
                "obligation_id": "user_result_available",
                "status": "PASS",
                "evidence_ref": "artifact://golden/acceptance",
            },
        ),
        evidence_refs=("artifact://golden/acceptance",),
        verifier_digest=TOOLCHAIN,
        verifier_signature="test-signature",
    )
    assert manifest.as_dict()["status"] == "PASS"
    assert manifest.as_dict()["subject"]["state"] == "COMPLETED"
    with pytest.raises(FunctionalReadinessError, match="evidence|COMPLETED"):
        ReadyResultManifest.create(
            manifest_type="PRODUCT_READY_RESULT",
            subject={"product_id": "golden", "state": "DELIVERED"},
            version="2.5.0",
            commit=COMMIT,
            digest=DIGEST,
            mandatory_obligations=(),
            evidence_refs=(),
            verifier_digest=TOOLCHAIN,
            verifier_signature="model-text-is-not-proof",
        )


def test_wf_p0_043_ready_manifest_signature_and_digests_verify_independently() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes_raw()
    public = base64.b64encode(public_bytes).decode("ascii")
    trust_digest = hashlib.sha256(public_bytes).hexdigest()
    subject = {"product_id": "golden", "state": "COMPLETED"}
    obligations = (
        {
            "obligation_id": "product_acceptance",
            "status": "PASS",
            "evidence_ref": "artifact://golden/product-acceptance",
        },
    )
    unsigned = {
        "schema_version": "1.0",
        "manifest_type": "PRODUCT_READY_RESULT",
        "status": "PASS",
        "subject": subject,
        "release_identity": {"version": "2.5.0", "commit": COMMIT, "digest": DIGEST},
        "mandatory_obligations": list(obligations),
        "evidence_refs": ["artifact://golden/product-acceptance"],
        "open_blockers": [],
        "verifier": {"digest": TOOLCHAIN},
    }
    signature = base64.b64encode(
        private_key.sign(json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())
    ).decode("ascii")
    manifest = ReadyResultManifest.create(
        manifest_type="PRODUCT_READY_RESULT",
        subject=subject,
        version="2.5.0",
        commit=COMMIT,
        digest=DIGEST,
        mandatory_obligations=obligations,
        evidence_refs=("artifact://golden/product-acceptance",),
        verifier_digest=TOOLCHAIN,
        verifier_signature=signature,
    ).as_dict()
    assert verify_ready_result_manifest(
        manifest,
        verifier_public_key=public,
        trusted_public_key_digest=trust_digest,
    ) == manifest["manifest_digest"]
    tampered = {**manifest, "subject": {"product_id": "other", "state": "COMPLETED"}}
    with pytest.raises(FunctionalReadinessError, match="digest"):
        verify_ready_result_manifest(
            tampered,
            verifier_public_key=public,
            trusted_public_key_digest=trust_digest,
        )


class _FakeQ65Broker:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def execute(self, request: BrokerRequest) -> BrokerReceipt:
        self.calls.append(request.operation)
        if request.repository.startswith("outside-") or request.payload.get("visibility") == "public":
            raise CredentialBrokerError("denied_policy")
        if request.operation == "repository.read" and request.payload.get("workspace"):
            workspace = Path(str(request.payload["workspace"]))
            workspace.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
        object_ids: tuple[str, ...] = ()
        if request.operation == "pull_request.create":
            object_ids = ("number:1",)
        return BrokerReceipt(
            request_id=request.request_id,
            operation=request.operation,
            target_slug=f"{request.owner}/{request.repository}",
            subject_identity="brullik",
            result="PASS",
            object_ids=object_ids,
            credential_epoch_id="CE-1",
            timestamp="2026-08-06T00:00:00Z",
            request_digest=request.digest(),
            receipt_digest=sha256_text(request.request_id),
        )


def test_wf_p0_001_github_operation_handshake_runs_end_to_end_through_broker(
    tmp_path: Path,
) -> None:
    broker = _FakeQ65Broker()
    handshake = GitHubOperationHandshake(
        broker=broker,  # type: ignore[arg-type]
        identity=ProbeIdentity(DIGEST, TOOLCHAIN, "CE-1"),
        epoch_id="RE-Q65-TEST",
        owner="brullik",
        repository="hermes-canary-working-factory",
        workspace=tmp_path / "workspace",
    )
    reports = handshake.run()
    assert {report.operation for report in reports} == set(MANDATORY_Q6_5_OPERATIONS[:8])
    assert broker.calls[:8] == [
        "identity.read",
        "repository.create_private",
        "repository.read",
        "branch.push",
        "branch.push",
        "pull_request.create",
        "checks.read",
        "pull_request.merge_or_close",
    ]
    assert "repository.archive_or_delete" in broker.calls
    replayed = handshake.run()
    assert [report.operation for report in replayed] == [report.operation for report in reports]


class _ProviderRunner:
    def run(
        self,
        *,
        selection: ModelSelection,
        prompt: str,
        cwd: Path,
        usage_path: Path | None = None,
    ) -> HermesRunResult:
        del prompt, cwd
        semantic_id = sha256_text("q6.5-provider-no-side-effect-v1")
        output = json.dumps(
            {
                "schema_version": "1.0",
                "status": "PASS",
                "tier": selection.tier,
                "semantic_id": semantic_id,
            }
        )
        if usage_path is not None:
            usage_path.parent.mkdir(parents=True, exist_ok=True)
            usage_path.write_text("{}\n", encoding="utf-8")
        return HermesRunResult("PASS", output, sha256_text(output), None)


def test_wf_p0_006_007_provider_three_tier_schema_and_semantic_identity(
    tmp_path: Path,
) -> None:
    selections = {
        tier: ModelSelection("openai_codex_subscription", alias, f"model-{tier}", tier)
        for tier, alias in ProviderOperationHandshake.ROUTES
    }
    reports = ProviderOperationHandshake(
        identity=ProbeIdentity(DIGEST, TOOLCHAIN, None),
        runner=_ProviderRunner(),
        selections=selections,
        workspace=tmp_path,
        evidence_root=tmp_path / "evidence",
    ).run()
    assert [report.operation for report in reports] == [
        "provider.luna.invoke",
        "provider.terra.invoke",
        "provider.sol.invoke",
    ]
    assert len({str(report.scope["semantic_id"]) for report in reports}) == 1


def test_wf_p0_008_external_handshake_requires_real_immutable_receipt(tmp_path: Path) -> None:
    receipt = tmp_path / "container.json"
    receipt.write_text('{"status":"PASS"}\n', encoding="utf-8")
    report = external_operation_report(
        identity=ProbeIdentity(DIGEST, TOOLCHAIN, None),
        operation="toolchain.container_builder",
        scope={"runtime": "rootless-podman"},
        receipt_paths=(receipt,),
    )
    assert report.status == CapabilityStatus.AVAILABLE
    with pytest.raises(Exception, match="unavailable"):
        external_operation_report(
            identity=ProbeIdentity(DIGEST, TOOLCHAIN, None),
            operation="deployment.rollback",
            scope={},
            receipt_paths=(tmp_path / "missing",),
        )


def test_wf_p0_023_026_notification_reboot_idempotence_and_support_bundle(
    tmp_path: Path,
) -> None:
    source = tmp_path / "state.json"
    secret = "ghp_" + "x" * 30
    source.write_text(json.dumps({"status": "FAIL", "token": secret}), encoding="utf-8")
    bundle, digest = build_support_bundle(
        incident_id="INC-1",
        source_files=(source,),
        allowed_roots=(tmp_path,),
        output_root=tmp_path / "bundles",
        metadata={"reason_code": "controller_defect"},
    )
    assert len(digest) == 64
    with zipfile.ZipFile(bundle) as archive:
        assert secret not in archive.read("evidence/state.json").decode("utf-8")
    calls: list[str] = []

    def telegram(method: str, payload: dict[str, object]) -> dict[str, Any]:
        calls.append(method)
        return {"ok": True, "result": {"message_id": 1}}

    outbox = NotificationOutbox(tmp_path / "notifications", attachment_roots=(tmp_path,))
    outbox.enqueue(
        NotificationRequest(
            request_id="SUPPORT-REQUEST-1",
            kind="ASSISTANCE_REQUIRED_GPT_CODEX",
            text="Sanitized support evidence is ready.",
            document_path=str(bundle),
            document_digest=digest,
        )
    )
    notifier = OwnerNotifier(outbox, TelegramApi("fixture-token", request=telegram), chat_id="42")
    assert notifier.run_once() == 1
    assert notifier.run_once() == 0
    assert calls == ["sendDocument"]


def test_wf_p0_029_recursion_depth_three_is_durable(tmp_path: Path) -> None:
    governor = _improvement_governor(tmp_path)
    governor.propose(_proposal(), target_metric="completion_time")
    candidate = tmp_path / "candidate-lab" / "cycles"
    candidate.mkdir()
    for cycle_number in range(1, 4):
        cycle = governor.start_cycle(
            objective_id="objective-1",
            branch_name=f"codex/improvement-{cycle_number}",
            candidate_digest=str(cycle_number + 1) * 64,
            experiment_root=candidate,
        )
        decision = governor.evaluate(
            cycle_id=cycle,
            evaluation=_evaluation(candidate_time=80.0 - cycle_number),
            request_next_cycle=True,
        )
        assert decision == ("NEXT_BOUNDED_CYCLE" if cycle_number < 3 else "ACCEPT")
    with pytest.raises(ImprovementError, match="budget exhausted|another cycle"):
        governor.start_cycle(
            objective_id="objective-1",
            branch_name="codex/improvement-4",
            candidate_digest="5" * 64,
            experiment_root=candidate,
        )


def test_wf_p0_acceptance_matrix_is_exact_43_and_has_no_skip() -> None:
    root = Path(__file__).parents[1]
    matrix = yaml.safe_load(
        (root / "qualification" / "working-factory-p0.yaml").read_text(
            encoding="utf-8"
        )
    )
    cases = matrix["cases"]
    assert list(cases) == [f"WF-P0-{value:03d}" for value in range(1, 44)]
    assert all(case["status"] == "AUTOMATED_NO_SKIP" and case["test"] for case in cases.values())
    for case in cases.values():
        parts = str(case["test"]).split("::")
        path = root / parts[0]
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        nodes: list[ast.stmt] = list(tree.body)
        for name in parts[1:]:
            matches = [
                node
                for node in nodes
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == name
            ]
            assert len(matches) == 1, f"unresolved acceptance node: {case['test']}"
            nodes = list(matches[0].body) if isinstance(matches[0], ast.ClassDef) else []


def test_wf_p0_023_024_025_systemd_autonomy_has_no_codex_runtime() -> None:
    root = Path(__file__).parents[1]
    required = (
        "hermes-factory-capability-reconciler.service",
        "hermes-factory-functional-qualification.service",
        "hermes-factory-functional-qualification.timer",
        "hermes-factory-golden-product.service",
        "hermes-factory-recursive-improvement.service",
        "hermes-factory-recursive-improvement.timer",
        "hermes-factory-support-bundle@.service",
        "hermes-factory-owner-notifier.service",
    )
    combined = "\n".join(
        (root / "config" / "systemd" / name).read_text(encoding="utf-8")
        for name in required
    )
    assert "NoNewPrivileges=true" in combined
    assert "codex" not in combined.lower()
    initial = (root / "scripts/qualification/run-initial-qualification.sh").read_text(
        encoding="utf-8"
    )
    assert "shadow-verify.timer" not in initial


def test_candidate_epoch_switch_binds_terminal_status_to_old_commit() -> None:
    root = Path(__file__).parents[1]
    bootstrap = (
        root / "scripts" / "bootstrap" / "prepare-candidate-plane.sh"
    ).read_text(encoding="utf-8")
    assert 'OLD_EPOCH_SOURCE_COMMIT="$(OLD_STATUS_JSON=' in bootstrap
    assert '"${OLD_EPOCH_SOURCE_COMMIT}" != "${OLD_SOURCE_COMMIT}"' in bootstrap
    assert "Previous Candidate B epoch status identity differs" in bootstrap
