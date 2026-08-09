from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import runpy
import sqlite3
import stat
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace
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
    _is_private_systemd_credential_view,
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
    Q65ExternalCapabilityError,
    Q65ProbeError,
    Q65ProviderCapabilityError,
    external_operation_report,
)
from factory.recursive_improvement import (
    ComparativeEvaluation,
    ImprovementError,
    ImprovementProposal,
    RecursiveImprovementGovernor,
)
from factory.release_qualification import QualificationError, ReleaseQualificationGovernor
from factory.repository import ConfiguredRepositoryAdapter
from factory.state import StateStore
from factory.support_bundle import build_support_bundle
from factory.telegram import TelegramApi
from factory.worker import HermesRunResult, _workspace_snapshot
from scripts import functional_qualification, q6_5_live

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


def test_functional_reconcile_retires_checkpointed_failed_release_epoch(
    tmp_path: Path,
) -> None:
    old_epoch = "RE-OLD-FUNCTIONAL"
    current_epoch = "RE-CURRENT-FUNCTIONAL"
    old_commit = "d" * 40
    current_commit = "e" * 40
    old_digest = "1" * 64
    current_digest = "2" * 64
    release_database = tmp_path / "release.db"
    connection = sqlite3.connect(release_database)
    try:
        connection.execute(
            "CREATE TABLE controller_release_epochs ("
            "epoch_id TEXT PRIMARY KEY,source_commit TEXT,candidate_digest TEXT,"
            "status TEXT,created_at TEXT)"
        )
        connection.executemany(
            "INSERT INTO controller_release_epochs VALUES (?,?,?,?,?)",
            (
                (
                    old_epoch,
                    old_commit,
                    old_digest,
                    "QUALIFICATION_FAILED",
                    "2026-08-06T00:00:00Z",
                ),
                (
                    current_epoch,
                    current_commit,
                    current_digest,
                    "FUNCTIONAL_PENDING",
                    "2026-08-06T00:01:00Z",
                ),
            ),
        )
        connection.commit()
    finally:
        connection.close()

    state_root = tmp_path / "functional"
    state_root.mkdir()
    governor = FunctionalQualificationGovernor(
        sqlite3.connect(state_root / "functional.db")
    )
    governor.register_epoch(
        epoch_id=old_epoch,
        source_commit=old_commit,
        candidate_digest=old_digest,
        toolchain_digest=TOOLCHAIN,
    )
    governor.record_handshake(
        old_epoch,
        CapabilityHandshakeReport.create(
            candidate_digest=old_digest,
            capability="github.identity.read",
            operation="github.identity.read",
            scope={"owner": "brullik"},
            status=CapabilityStatus.MISSING_EXTERNAL,
            credential_epoch_id=None,
            toolchain_digest=TOOLCHAIN,
            safe_reason_code="missing_candidate_github_credential",
        ),
    )
    old_action = governor.ensure_owner_action(
        epoch_id=old_epoch,
        reason_code="missing_candidate_github_credential",
        capability="github.identity.read",
        capability_epoch=None,
    )
    functional_qualification._notify_waiting(
        state_root,
        epoch_id=old_epoch,
        action_id=old_action,
        text="Install the superseded Candidate capability.",
    )
    governor.connection.close()

    control = tmp_path / "qualification-control.yaml"
    control.write_text(
        yaml.safe_dump(
            {
                "governor_database": str(release_database),
                "source_commit": current_commit,
                "candidate_digest": current_digest,
                "toolchain_manifest_digest": TOOLCHAIN,
                "factory_repository": "brullik/hermes-software-factory",
            }
        ),
        encoding="utf-8",
    )
    result = functional_qualification.reconcile(
        control,
        state_root=state_root,
        credential_source=tmp_path / "missing-github-token",
        telegram_credential_source=tmp_path / "missing-telegram-token",
        report_index=state_root / "q6-5" / "report-index.json",
        failure_index=state_root / "q6-5" / "failure-index.json",
    )

    assert result["status"] == "WAITING_CAPABILITY"
    assert result["epoch_id"] == current_epoch
    readback = sqlite3.connect(state_root / "functional.db")
    try:
        old = readback.execute(
            "SELECT status,q6_5_status FROM functional_epochs WHERE epoch_id=?",
            (old_epoch,),
        ).fetchone()
        current = readback.execute(
            "SELECT status,q6_5_status FROM functional_epochs WHERE epoch_id=?",
            (current_epoch,),
        ).fetchone()
        action = readback.execute(
            "SELECT status,resolved_at FROM functional_owner_actions WHERE action_id=?",
            (old_action,),
        ).fetchone()
        retirement = readback.execute(
            "SELECT release_status,release_snapshot_digest "
            "FROM functional_epoch_retirements WHERE epoch_id=?",
            (old_epoch,),
        ).fetchone()
    finally:
        readback.close()
    assert old == ("QUALIFICATION_FAILED", "WAITING_CAPABILITY")
    assert current == ("WAITING_CAPABILITY", "WAITING_CAPABILITY")
    assert action is not None and action[0] == "RESOLVED" and action[1]
    assert retirement is not None
    assert retirement[0] == "QUALIFICATION_FAILED"
    assert len(str(retirement[1])) == 64
    old_notification_digest = sha256_text(old_action)[:32]
    assert sorted(path.name for path in (state_root / "notifications" / "retired").iterdir()) == [
        f"NOTIFY-{old_notification_digest}.json",
        f"WAITING-{old_notification_digest}.json",
    ]
    current_notification_digest = sha256_text(str(result["action_ref"]).rsplit("/", 1)[1])[:32]
    assert sorted(path.name for path in (state_root / "notifications" / "outbox").iterdir()) == [
        f"NOTIFY-{current_notification_digest}.json",
        f"WAITING-{current_notification_digest}.json",
    ]


@pytest.mark.parametrize(
    ("reason_code", "operation", "message"),
    (
        (
            "candidate_github_operation_denied",
            "github.repository.create_private",
            "github.repository.create_private was denied",
        ),
        (
            "candidate_github_workflow_permission_denied",
            "git.branch.push",
            "workflow-file write",
        ),
    ),
)
def test_functional_reconcile_durably_waits_on_authenticated_github_denial(
    tmp_path: Path,
    reason_code: str,
    operation: str,
    message: str,
) -> None:
    epoch_id = "RE-Q65-EXTERNAL"
    release_database = tmp_path / "release.db"
    connection = sqlite3.connect(release_database)
    try:
        connection.execute(
            "CREATE TABLE controller_release_epochs ("
            "epoch_id TEXT PRIMARY KEY,source_commit TEXT,candidate_digest TEXT,"
            "status TEXT,created_at TEXT)"
        )
        connection.execute(
            "INSERT INTO controller_release_epochs VALUES (?,?,?,?,?)",
            (epoch_id, COMMIT, DIGEST, "FUNCTIONAL_PENDING", "2026-08-06T00:00:00Z"),
        )
        connection.commit()
    finally:
        connection.close()
    control = tmp_path / "qualification-control.yaml"
    control.write_text(
        yaml.safe_dump(
            {
                "governor_database": str(release_database),
                "source_commit": COMMIT,
                "candidate_digest": DIGEST,
                "toolchain_manifest_digest": TOOLCHAIN,
                "factory_repository": "brullik/hermes-software-factory",
            }
        ),
        encoding="utf-8",
    )
    state_root = tmp_path / "functional"
    credential = tmp_path / "github-token"
    credential.write_text("fixture-token-not-a-real-secret", encoding="utf-8")
    credential.chmod(0o600)
    report_index = state_root / "q6-5" / "report-index.json"
    failure_index = state_root / "q6-5" / "failure-index.json"
    first = functional_qualification.reconcile(
        control,
        state_root=state_root,
        credential_source=credential,
        telegram_credential_source=tmp_path / "missing-telegram-token",
        report_index=report_index,
        failure_index=failure_index,
    )
    assert first["status"] == "Q6_5_PROBE_REQUIRED"
    credential_epoch = (state_root / "credential-epoch").read_text(encoding="ascii").strip()
    q6_5_live._write_once(
        failure_index,
        {
            "schema_version": "1.0",
            "candidate_digest": DIGEST,
            "toolchain_digest": TOOLCHAIN,
            "credential_epoch_id": credential_epoch,
            "capability": operation,
            "operation": operation,
            "scope": {
                "owner": "brullik",
                "repository": f"hermes-canary-q65-{DIGEST[:10]}",
                "private": True,
            },
            "safe_reason_code": reason_code,
            "observed_at": "2026-08-06T00:01:00Z",
        },
    )

    result = functional_qualification.reconcile(
        control,
        state_root=state_root,
        credential_source=credential,
        telegram_credential_source=tmp_path / "missing-telegram-token",
        report_index=report_index,
        failure_index=failure_index,
    )
    replay = functional_qualification.reconcile(
        control,
        state_root=state_root,
        credential_source=credential,
        telegram_credential_source=tmp_path / "missing-telegram-token",
        report_index=report_index,
        failure_index=failure_index,
    )

    assert result == replay
    assert result["status"] == "WAITING_CAPABILITY"
    assert result["reason_code"] == reason_code
    assert result["operation"] == operation
    database = sqlite3.connect(state_root / "functional.db")
    try:
        epoch = database.execute(
            "SELECT status,q6_5_status FROM functional_epochs WHERE epoch_id=?", (epoch_id,)
        ).fetchone()
        report = database.execute(
            "SELECT status FROM capability_handshake_reports "
            "WHERE epoch_id=? AND operation=?",
            (epoch_id, operation),
        ).fetchone()
        action = database.execute(
            "SELECT action_id,status,reason_code,capability,capability_epoch "
            "FROM functional_owner_actions WHERE epoch_id=?",
            (epoch_id,),
        ).fetchone()
    finally:
        database.close()
    assert epoch == ("WAITING_CAPABILITY", "WAITING_CAPABILITY")
    assert report == ("MISSING_EXTERNAL",)
    assert action is not None
    assert action[1:] == (
        "OPEN",
        reason_code,
        operation,
        credential_epoch,
    )
    notification = json.loads(
        (state_root / "notifications" / "outbox" / f"NOTIFY-{sha256_text(action[0])[:32]}.json")
        .read_text(encoding="utf-8")
    )
    assert notification["kind"] == "OWNER_ACTION_REQUIRED"
    assert message in notification["text"]
    assert "fixture-token" not in notification["text"]

    credential.write_text("replacement-fixture-token-not-a-real-secret", encoding="utf-8")
    credential.chmod(0o600)
    if os.name == "nt":
        (state_root / "credential-epoch").chmod(stat.S_IWRITE)
    resumed = functional_qualification.reconcile(
        control,
        state_root=state_root,
        credential_source=credential,
        telegram_credential_source=tmp_path / "missing-telegram-token",
        report_index=report_index,
        failure_index=failure_index,
    )
    assert resumed["status"] == "Q6_5_PROBE_REQUIRED"
    assert not failure_index.exists()
    assert len(list((failure_index.parent / "archive").glob("failure-index-*.json"))) == 1
    database = sqlite3.connect(state_root / "functional.db")
    try:
        resumed_epoch = database.execute(
            "SELECT status,q6_5_status FROM functional_epochs WHERE epoch_id=?", (epoch_id,)
        ).fetchone()
        resolved_action = database.execute(
            "SELECT status,resolved_at FROM functional_owner_actions WHERE action_id=?",
            (action[0],),
        ).fetchone()
    finally:
        database.close()
    assert resumed_epoch == ("Q6_5_PENDING", "PENDING")
    assert resolved_action is not None and resolved_action[0] == "RESOLVED"
    assert resolved_action[1]


def test_functional_reconcile_durably_waits_on_candidate_provider_oauth(
    tmp_path: Path,
) -> None:
    epoch_id = "RE-Q65-PROVIDER"
    release_database = tmp_path / "release.db"
    connection = sqlite3.connect(release_database)
    try:
        connection.execute(
            "CREATE TABLE controller_release_epochs ("
            "epoch_id TEXT PRIMARY KEY,source_commit TEXT,candidate_digest TEXT,"
            "status TEXT,created_at TEXT)"
        )
        connection.execute(
            "INSERT INTO controller_release_epochs VALUES (?,?,?,?,?)",
            (epoch_id, COMMIT, DIGEST, "FUNCTIONAL_PENDING", "2026-08-07T00:00:00Z"),
        )
        connection.commit()
    finally:
        connection.close()
    control = tmp_path / "qualification-control.yaml"
    control.write_text(
        yaml.safe_dump(
            {
                "governor_database": str(release_database),
                "source_commit": COMMIT,
                "candidate_digest": DIGEST,
                "toolchain_manifest_digest": TOOLCHAIN,
                "factory_repository": "brullik/hermes-software-factory",
            }
        ),
        encoding="utf-8",
    )
    state_root = tmp_path / "functional"
    credential = tmp_path / "github-token"
    credential.write_text("fixture-token-not-a-real-secret", encoding="utf-8")
    credential.chmod(0o600)
    report_index = state_root / "q6-5" / "report-index.json"
    failure_index = state_root / "q6-5" / "failure-index.json"
    first = functional_qualification.reconcile(
        control,
        state_root=state_root,
        credential_source=credential,
        telegram_credential_source=tmp_path / "missing-telegram-token",
        report_index=report_index,
        failure_index=failure_index,
    )
    credential_epoch = (state_root / "credential-epoch").read_text(encoding="ascii").strip()
    assert first["status"] == "Q6_5_PROBE_REQUIRED"
    q6_5_live._write_once(
        failure_index,
        {
            "schema_version": "1.0",
            "candidate_digest": DIGEST,
            "toolchain_digest": TOOLCHAIN,
            "credential_epoch_id": credential_epoch,
            "capability": "provider.luna.invoke",
            "operation": "provider.luna.invoke",
            "scope": {
                "alias": "economy",
                "provider": "openai_codex_subscription",
                "model": "gpt-5.6-luna",
                "credential_provider": "openai-codex",
                "semantic_id": sha256_text("q6.5-provider-no-side-effect-v1"),
                "stdout_contract": "json-only",
            },
            "safe_reason_code": "missing_candidate_provider_credential",
            "observed_at": "2026-08-07T00:01:00Z",
        },
    )

    result = functional_qualification.reconcile(
        control,
        state_root=state_root,
        credential_source=credential,
        telegram_credential_source=tmp_path / "missing-telegram-token",
        report_index=report_index,
        failure_index=failure_index,
    )
    replay = functional_qualification.reconcile(
        control,
        state_root=state_root,
        credential_source=credential,
        telegram_credential_source=tmp_path / "missing-telegram-token",
        report_index=report_index,
        failure_index=failure_index,
    )

    assert result == replay
    assert result["status"] == "WAITING_CAPABILITY"
    assert result["reason_code"] == "missing_candidate_provider_credential"
    assert result["operation"] == "provider.luna.invoke"
    database = sqlite3.connect(state_root / "functional.db")
    try:
        action = database.execute(
            "SELECT action_id,status,reason_code,capability,capability_epoch "
            "FROM functional_owner_actions WHERE epoch_id=?",
            (epoch_id,),
        ).fetchone()
    finally:
        database.close()
    assert action is not None
    assert action[1:] == (
        "OPEN",
        "missing_candidate_provider_credential",
        "provider.luna.invoke",
        None,
    )
    notification = json.loads(
        (state_root / "notifications" / "outbox" / f"NOTIFY-{sha256_text(action[0])[:32]}.json")
        .read_text(encoding="utf-8")
    )
    assert notification["kind"] == "OWNER_ACTION_REQUIRED"
    assert "openai-codex" in notification["text"]
    assert "fixture-token" not in notification["text"]

    governor = FunctionalQualificationGovernor(sqlite3.connect(state_root / "functional.db"))
    try:
        assert governor.recover_external_capability(
            epoch_id=epoch_id, capability="provider.luna.invoke"
        )
        governor.record_handshake(
            epoch_id,
            CapabilityHandshakeReport.create(
                candidate_digest=DIGEST,
                capability="provider.luna.invoke",
                operation="provider.luna.invoke",
                scope={"provider": "openai_codex_subscription"},
                status=CapabilityStatus.AVAILABLE,
                credential_epoch_id=None,
                toolchain_digest=TOOLCHAIN,
                receipts=("d" * 64,),
            ),
        )
        resolved = governor.connection.execute(
            "SELECT status,resolved_at FROM functional_owner_actions WHERE action_id=?",
            (action[0],),
        ).fetchone()
    finally:
        governor.connection.close()
    assert resolved is not None and resolved[0] == "RESOLVED" and resolved[1]


@pytest.mark.skipif(os.name == "nt", reason="POSIX shared workspace modes are required")
def test_q6_5_shared_workspace_is_group_writable_without_setgid_and_rejects_symlinks(
    tmp_path: Path,
) -> None:
    shared = q6_5_live._prepare_shared_workspace_root(tmp_path / "github-shared")

    assert shared == tmp_path / "github-shared"
    assert stat.S_IMODE(shared.stat().st_mode) == 0o0770
    target = tmp_path / "target"
    target.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    with pytest.raises(q6_5_live.LiveProbeError, match="symlink"):
        q6_5_live._prepare_shared_workspace_root(linked)


def test_github_broker_preserves_shared_group_write_umask() -> None:
    repository = Path(__file__).parents[1]
    unit = (
        repository / "config/systemd/hermes-factory-github-broker.service"
    ).read_text(encoding="utf-8")

    assert "Group=hermesfunctional" in unit
    assert "UMask=0007" in unit
    probe_unit = (
        repository / "config/systemd/hermes-factory-capability-probe.service"
    ).read_text(encoding="utf-8")
    assert "Group=hermesfunctional" in probe_unit
    assert "SupplementaryGroups=hermescandidate" in probe_unit
    assert "RestrictSUIDSGID=true" in probe_unit


def test_candidate_workspace_workers_create_group_writable_setgid_parents() -> None:
    repository = Path(__file__).parents[1]

    for name in (
        "hermes-factory-candidate-worker.service",
        "hermes-factory-canary-worker@.service",
        "hermes-factory-pre-q8-worker@.service",
        "hermes-factory-golden-worker.service",
    ):
        unit = (repository / "config/systemd" / name).read_text(encoding="utf-8")
        assert "UMask=0007" in unit
        assert "RestrictSUIDSGID=true" in unit


def test_candidate_functional_units_retain_candidate_config_group() -> None:
    repository = Path(__file__).parents[1]

    for name in (
        "hermes-factory-capability-probe.service",
        "hermes-factory-golden-controller.service",
        "hermes-factory-golden-intake.service",
        "hermes-factory-golden-worker.service",
    ):
        unit = (repository / "config/systemd" / name).read_text(encoding="utf-8")
        assert "User=hermescandidate" in unit
        assert "Group=hermesfunctional" in unit
        assert "SupplementaryGroups=hermescandidate" in unit
        assert "InaccessiblePaths=" in unit
        assert "/etc/hermes-factory/candidate-credentials.d" in unit


def test_functional_retirement_rejects_nonterminal_release_proof() -> None:
    governor = _functional_governor()
    with pytest.raises(FunctionalReadinessError, match="retirement proof"):
        governor.retire_after_release_failure(
            epoch_id="RE-FUNCTIONAL-1",
            source_commit=COMMIT,
            candidate_digest=DIGEST,
            release_status="FUNCTIONAL_PENDING",
            release_snapshot_digest="d" * 64,
        )


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


def test_candidate_broker_verifies_private_repository_configuration(
    tmp_path: Path,
) -> None:
    credential = tmp_path / "github-token"
    credential.write_text("fixture-token-not-a-real-secret", encoding="utf-8")
    credential.chmod(0o600)

    def runner(
        argv: list[str], environment: Any, cwd: Path | None
    ) -> subprocess.CompletedProcess[str]:
        del environment, cwd
        if argv == ["gh", "api", "user"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps({"login": "brullik", "id": 1}),
                "",
            )
        assert argv == ["gh", "api", "repos/brullik/hermes-canary-configured"]
        return subprocess.CompletedProcess(
            argv,
            0,
            json.dumps(
                {
                    "full_name": "brullik/hermes-canary-configured",
                    "private": True,
                    "has_issues": True,
                    "has_projects": False,
                    "has_wiki": False,
                    "delete_branch_on_merge": True,
                    "allow_merge_commit": True,
                    "allow_squash_merge": True,
                    "allow_rebase_merge": True,
                }
            ),
            "",
        )

    receipt = GitHubCredentialBroker(
        policy=BrokerPolicy(owner="brullik", repository_prefixes=("hermes-canary-",)),
        credential_path=credential,
        receipt_root=tmp_path / "receipts",
        credential_epoch_id="CE-1",
        command_runner=runner,
    ).execute(
        BrokerRequest(
            request_id="request-config-0001",
            operation="repository.read",
            owner="brullik",
            repository="hermes-canary-configured",
            payload={"query": "configuration"},
        )
    )
    assert "state:configuration_verified" in receipt.object_ids
    assert "private:true" in receipt.object_ids


def test_candidate_broker_types_missing_workflow_scope_without_exposing_output(
    tmp_path: Path,
) -> None:
    credential = tmp_path / "github-token"
    credential.write_text("fixture-token-not-a-real-secret", encoding="utf-8")
    credential.chmod(0o600)
    error = (
        "remote: refusing to allow a Personal Access Token to create or update workflow "
        "'.github/workflows/q6-5-proof.yml' without `workflow` scope"
    )

    broker = GitHubCredentialBroker(
        policy=BrokerPolicy(owner="brullik"),
        credential_path=credential,
        receipt_root=tmp_path / "receipts",
        credential_epoch_id="CE-1",
        command_runner=lambda argv, environment, cwd: subprocess.CompletedProcess(
            argv, 1, "", error
        ),
    )

    with pytest.raises(
        CredentialBrokerError,
        match="^candidate_github_workflow_permission_denied$",
    ):
        broker._run(
            ["git", "push"],
            environment={"GH_TOKEN": "fixture-token-not-a-real-secret"},
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX credential modes are required")
def test_broker_accepts_only_private_systemd_credential_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    credential_directory = tmp_path / "credentials"
    credential_directory.mkdir()
    credential = credential_directory / "github-token"
    credential.write_text("fixture-token-not-a-real-secret", encoding="utf-8")
    file_metadata = os.stat_result((stat.S_IFREG | 0o440, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    directory_metadata = os.stat_result(
        (stat.S_IFDIR | 0o550, 0, 0, 1, 0, 0, 0, 0, 0, 0)
    )
    monkeypatch.setattr(
        Path,
        "stat",
        lambda path, **_kwargs: (
            file_metadata if path == credential else directory_metadata
        ),
    )
    broker = GitHubCredentialBroker(
        policy=BrokerPolicy(owner="brullik"),
        credential_path=credential,
        receipt_root=tmp_path / "receipts",
        credential_epoch_id="CE-1",
    )

    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credential_directory))
    assert _is_private_systemd_credential_view(credential, file_metadata)
    assert not _is_private_systemd_credential_view(
        credential,
        os.stat_result((stat.S_IFREG | 0o640, 0, 0, 1, 0, 0, 0, 0, 0, 0)),
    )
    assert not _is_private_systemd_credential_view(
        credential,
        os.stat_result((stat.S_IFREG | 0o444, 0, 0, 1, 0, 0, 0, 0, 0, 0)),
    )
    assert broker._credential() == "fixture-token-not-a-real-secret"

    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path / "different"))
    with pytest.raises(CredentialBrokerError, match="credential_permissions"):
        broker._credential()


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
        self.requests: list[BrokerRequest] = []

    def execute(self, request: BrokerRequest) -> BrokerReceipt:
        self.calls.append(request.operation)
        self.requests.append(request)
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


def test_q6_5_local_git_runner_trusts_only_the_exact_shared_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed["argv"] = argv
        observed["cwd"] = kwargs["cwd"]
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("factory.q6_5.subprocess.run", fake_run)
    workspace = tmp_path / "broker-owned-checkout"
    result = GitHubOperationHandshake._default_git_runner(
        ["git", "status", "--short"], workspace
    )

    assert result.returncode == 0
    assert observed == {
        "argv": [
            "git",
            "-c",
            f"safe.directory={workspace.resolve()}",
            "status",
            "--short",
        ],
        "cwd": workspace.resolve(),
    }
    assert "safe.directory=*" not in observed["argv"]
    with pytest.raises(Q65ProbeError, match="command is invalid"):
        GitHubOperationHandshake._default_git_runner(["sh", "-c", "true"], workspace)


def test_repository_adapter_trusts_only_the_exact_broker_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed["argv"] = argv
        observed["cwd"] = kwargs["cwd"]
        return subprocess.CompletedProcess(argv, 0, stdout="main\n", stderr="")

    monkeypatch.setattr("factory.repository.subprocess.run", fake_run)
    workspace = tmp_path / "broker-owned-checkout"
    workspace.mkdir()
    result = ConfiguredRepositoryAdapter._git_run(
        workspace, "branch", "--show-current"
    )

    resolved = workspace.resolve()
    assert result == "main"
    assert observed == {
        "argv": [
            "git",
            "-c",
            f"safe.directory={resolved}",
            "-C",
            str(resolved),
            "branch",
            "--show-current",
        ],
        "cwd": None,
    }
    assert "safe.directory=*" not in observed["argv"]


def test_workspace_snapshot_trusts_only_the_exact_broker_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        observed["argv"] = argv
        observed["capture_output"] = kwargs["capture_output"]
        observed["check"] = kwargs["check"]
        observed["timeout"] = kwargs["timeout"]
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr("factory.worker.subprocess.run", fake_run)
    workspace = tmp_path / "broker-owned-snapshot"
    (workspace / ".git").mkdir(parents=True)

    assert _workspace_snapshot(workspace) == {}
    resolved = workspace.resolve()
    assert observed == {
        "argv": [
            "git",
            "-c",
            f"safe.directory={resolved}",
            "-C",
            str(resolved),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        "capture_output": True,
        "check": False,
        "timeout": 30,
    }
    assert "safe.directory=*" not in observed["argv"]


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
    assert broker.calls[:9] == [
        "identity.read",
        "repository.create_private",
        "repository.read",
        "repository.read",
        "branch.push",
        "branch.push",
        "pull_request.create",
        "checks.read",
        "pull_request.merge_or_close",
    ]
    assert "repository.archive_or_delete" in broker.calls
    cleanup = next(
        request
        for request in broker.requests
        if request.operation == "repository.archive_or_delete"
    )
    assert cleanup.payload == {"action": "archive"}
    by_operation = {report.operation: report for report in reports}
    assert (
        by_operation["github.repository.read"].scope["repository_configuration"]
        == "verified"
    )
    assert by_operation["git.branch.push"].scope["workflow_write"] == "verified"
    assert (
        tmp_path / "workspace" / ".github" / "workflows" / "q6-5-proof.yml"
    ).is_file()
    replayed = handshake.run()
    assert [report.operation for report in replayed] == [report.operation for report in reports]


def test_q6_5_github_denial_is_typed_and_written_as_immutable_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class DeniedBroker(_FakeQ65Broker):
        def execute(self, request: BrokerRequest) -> BrokerReceipt:
            if request.operation == "repository.create_private":
                raise CredentialBrokerError("candidate_github_operation_denied")
            return super().execute(request)

    handshake = GitHubOperationHandshake(
        broker=DeniedBroker(),  # type: ignore[arg-type]
        identity=ProbeIdentity(DIGEST, TOOLCHAIN, "CE-" + "A" * 32),
        epoch_id=COMMIT,
        owner="brullik",
        repository=f"hermes-canary-q65-{DIGEST[:10]}",
        workspace=tmp_path / "workspace",
    )
    with pytest.raises(Q65ExternalCapabilityError) as captured:
        handshake.run()
    assert captured.value.operation == "github.repository.create_private"
    assert captured.value.safe_reason_code == "candidate_github_operation_denied"

    class DeniedHandshake:
        def __init__(self, **_: Any) -> None:
            pass

        def run(self) -> tuple[CapabilityHandshakeReport, ...]:
            raise Q65ExternalCapabilityError(
                "repository.create_private", "candidate_github_operation_denied"
            )

    monkeypatch.setattr(q6_5_live, "GitHubOperationHandshake", DeniedHandshake)
    control = tmp_path / "qualification-control.yaml"
    control.write_text(
        yaml.safe_dump(
            {
                "source_commit": COMMIT,
                "candidate_digest": DIGEST,
                "toolchain_manifest_digest": TOOLCHAIN,
                "factory_repository": "brullik/hermes-software-factory",
            }
        ),
        encoding="utf-8",
    )
    failure_index = tmp_path / "failure-index.json"
    result = q6_5_live.run(
        SimpleNamespace(
            config=control,
            credential_epoch="CE-" + "A" * 32,
            credential_epoch_file=None,
            output=tmp_path / "report-index.json",
            failure_index=failure_index,
            broker_socket=tmp_path / "broker.sock",
            candidate_config=tmp_path / "candidate.yaml",
            notifications=tmp_path / "notifications",
        )
    )
    assert result["status"] == "WAITING_CAPABILITY"
    assert result["operation"] == "github.repository.create_private"
    failure = json.loads(failure_index.read_text(encoding="utf-8"))
    digest = failure.pop("receipt_digest")
    assert digest == sha256_text(json.dumps(failure, sort_keys=True, separators=(",", ":")))
    assert failure["safe_reason_code"] == "candidate_github_operation_denied"


def test_q6_5_workflow_permission_denial_is_typed_for_branch_push(tmp_path: Path) -> None:
    class DeniedBroker(_FakeQ65Broker):
        def execute(self, request: BrokerRequest) -> BrokerReceipt:
            if request.operation == "branch.push":
                raise CredentialBrokerError(
                    "candidate_github_workflow_permission_denied"
                )
            return super().execute(request)

    handshake = GitHubOperationHandshake(
        broker=DeniedBroker(),  # type: ignore[arg-type]
        identity=ProbeIdentity(DIGEST, TOOLCHAIN, "CE-" + "A" * 32),
        epoch_id=COMMIT,
        owner="brullik",
        repository=f"hermes-canary-q65-{DIGEST[:10]}",
        workspace=tmp_path / "workspace",
    )

    with pytest.raises(Q65ExternalCapabilityError) as captured:
        handshake.run()
    assert captured.value.operation == "git.branch.push"
    assert (
        captured.value.safe_reason_code
        == "candidate_github_workflow_permission_denied"
    )


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


class _MissingProviderRunner:
    def run(
        self,
        *,
        selection: ModelSelection,
        prompt: str,
        cwd: Path,
        usage_path: Path | None = None,
    ) -> HermesRunResult:
        del selection, prompt, cwd, usage_path
        return HermesRunResult(
            "FAIL", "authentication required", "d" * 64, "missing_credential"
        )


def test_q6_5_provider_missing_oauth_is_typed_without_raw_output(tmp_path: Path) -> None:
    selections = {
        tier: ModelSelection(
            "openai_codex_subscription", alias, f"model-{tier}", tier, "openai-codex"
        )
        for tier, alias in ProviderOperationHandshake.ROUTES
    }

    with pytest.raises(Q65ProviderCapabilityError) as captured:
        ProviderOperationHandshake(
            identity=ProbeIdentity(DIGEST, TOOLCHAIN, None),
            runner=_MissingProviderRunner(),
            selections=selections,
            workspace=tmp_path,
            evidence_root=tmp_path / "evidence",
        ).run()

    assert captured.value.operation == "provider.luna.invoke"
    assert captured.value.safe_reason_code == "missing_candidate_provider_credential"
    assert captured.value.scope["credential_provider"] == "openai-codex"
    assert "authentication required" not in str(captured.value)


def test_q6_5_provider_failure_index_resumes_only_after_safe_auth_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class EmptyGitHubHandshake:
        def __init__(self, **_: Any) -> None:
            pass

        def run(self) -> tuple[CapabilityHandshakeReport, ...]:
            return ()

    error = Q65ProviderCapabilityError(
        tier="luna",
        alias="economy",
        selection=ModelSelection(
            "openai_codex_subscription",
            "economy",
            "gpt-5.6-luna",
            "luna",
            "openai-codex",
        ),
        semantic_id=sha256_text("q6.5-provider-no-side-effect-v1"),
    )

    def missing_provider(*_: Any, **__: Any) -> tuple[CapabilityHandshakeReport, ...]:
        raise error

    monkeypatch.setattr(q6_5_live, "GitHubOperationHandshake", EmptyGitHubHandshake)
    monkeypatch.setattr(q6_5_live, "_provider_reports", missing_provider)
    control = tmp_path / "qualification-control.yaml"
    control.write_text(
        yaml.safe_dump(
            {
                "source_commit": COMMIT,
                "candidate_digest": DIGEST,
                "toolchain_manifest_digest": TOOLCHAIN,
                "factory_repository": "brullik/hermes-software-factory",
            }
        ),
        encoding="utf-8",
    )
    args = SimpleNamespace(
        config=control,
        credential_epoch="CE-" + "A" * 32,
        credential_epoch_file=None,
        output=tmp_path / "report-index.json",
        failure_index=tmp_path / "failure-index.json",
        broker_socket=tmp_path / "broker.sock",
        candidate_config=tmp_path / "candidate.yaml",
        notifications=tmp_path / "notifications",
    )
    first = q6_5_live.run(args)
    assert first["status"] == "WAITING_CAPABILITY"
    assert args.failure_index.is_file()

    monkeypatch.setattr(q6_5_live, "_provider_credential_available", lambda provider: False)
    assert q6_5_live.run(args) == first

    class ResumeReached(RuntimeError):
        pass

    class ResumeHandshake:
        def __init__(self, **_: Any) -> None:
            pass

        def run(self) -> tuple[CapabilityHandshakeReport, ...]:
            raise ResumeReached

    monkeypatch.setattr(q6_5_live, "_provider_credential_available", lambda provider: True)
    monkeypatch.setattr(q6_5_live, "GitHubOperationHandshake", ResumeHandshake)
    with pytest.raises(ResumeReached):
        q6_5_live.run(args)
    assert not args.failure_index.exists()
    assert len(list((tmp_path / "archive").glob("failure-index-*.json"))) == 1


def test_q6_5_canonicalizes_supported_podman_sha256_image_ids() -> None:
    raw = "a" * 64
    canonical = f"sha256:{raw}"

    assert q6_5_live._canonical_sha256_image_id(raw) == canonical
    assert q6_5_live._canonical_sha256_image_id(canonical) == canonical
    with pytest.raises(q6_5_live.LiveProbeError, match="SHA-256 image digest"):
        q6_5_live._canonical_sha256_image_id("a" * 63)
    with pytest.raises(q6_5_live.LiveProbeError, match="SHA-256 image digest"):
        q6_5_live._canonical_sha256_image_id(f"sha512:{raw}")


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
        "hermes-factory-functional-handoff.service",
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
    notifier = (
        root / "config/systemd/hermes-factory-owner-notifier.service"
    ).read_text(encoding="utf-8")
    assert "Group=hermesfactory" in notifier
    assert "SupplementaryGroups=hermesfunctional" in notifier
    reconciler = (
        root / "scripts/qualification/reconcile-functional.sh"
    ).read_text(encoding="utf-8")
    assert "systemctl start --no-block hermes-factory-owner-notifier.service" in reconciler
    assert reconciler.count(
        "systemctl start --no-block hermes-factory-owner-notifier.service"
    ) == 2


def test_candidate_epoch_switch_binds_terminal_status_to_old_commit() -> None:
    root = Path(__file__).parents[1]
    bootstrap = (
        root / "scripts" / "bootstrap" / "prepare-candidate-plane.sh"
    ).read_text(encoding="utf-8")
    assert 'OLD_EPOCH_SOURCE_COMMIT="$(OLD_STATUS_JSON=' in bootstrap
    assert '"${OLD_EPOCH_SOURCE_COMMIT}" != "${OLD_SOURCE_COMMIT}"' in bootstrap
    assert "Previous Candidate B epoch status identity differs" in bootstrap
    incomplete_path = bootstrap.index(
        'if ! incomplete_prequalification_epoch_is_restartable "${OLD_SOURCE_COMMIT}"'
    )
    normal_path = bootstrap.index("if (( INCOMPLETE_PREQUALIFICATION_EPOCH != 1 ))")
    status_path = bootstrap.index('OLD_STATUS_JSON="$(runuser', normal_path)
    terminal_path = bootstrap.index("Previous Candidate B epoch is not terminal")
    active_unit_path = bootstrap.index('ACTIVE_CANDIDATE_UNITS="$(')
    switch_path = bootstrap.index("ALLOW_EPOCH_SWITCH=1")
    assert incomplete_path < normal_path < status_path < terminal_path
    assert terminal_path < active_unit_path < switch_path
    incomplete_function = bootstrap[
        bootstrap.index("incomplete_prequalification_epoch_is_restartable()") :
        bootstrap.index("ALLOW_EPOCH_SWITCH=0")
    ]
    assert "rm -rf" not in incomplete_function
    assert "mv --" not in incomplete_function
    assert "ln -s" not in incomplete_function
    assert incomplete_function.count(".hermes-bootstrap-complete") == 6
    assert (
        'for release_root in "${candidate_release}" "${verifier_release}"'
        in incomplete_function
    )
    assert '[[ -z "${release_status}" ]] || return 1' in incomplete_function
