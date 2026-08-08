from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from factory.common import sha256_text, stable_json
from factory.functional_readiness import (
    MANDATORY_Q6_5_OPERATIONS,
    CapabilityHandshakeReport,
    CapabilityStatus,
    FunctionalQualificationGovernor,
)
from scripts.functional_qualification import (
    _reconcile_product_github,
    _reconcile_stable_provider,
)

DIGEST = "a" * 64
TOOLCHAIN = "b" * 64
EPOCH = "RE-PRODUCT-RUNTIME"
CREDENTIAL_EPOCH = "CE-" + "C" * 32
ROOT = Path(__file__).resolve().parents[1]


def _governor(path: Path) -> FunctionalQualificationGovernor:
    governor = FunctionalQualificationGovernor(sqlite3.connect(path))
    governor.register_epoch(
        epoch_id=EPOCH,
        source_commit="c" * 40,
        candidate_digest=DIGEST,
        toolchain_digest=TOOLCHAIN,
    )
    for operation in MANDATORY_Q6_5_OPERATIONS:
        governor.record_handshake(
            EPOCH,
            CapabilityHandshakeReport.create(
                candidate_digest=DIGEST,
                capability=operation,
                operation=operation,
                scope={"allowed_operations": [operation]},
                status=CapabilityStatus.AVAILABLE,
                credential_epoch_id="CE-" + "A" * 32,
                toolchain_digest=TOOLCHAIN,
                receipts=(sha256_text(operation),),
            ),
        )
    return governor


def _runtime_reports() -> tuple[CapabilityHandshakeReport, ...]:
    return tuple(
        CapabilityHandshakeReport.create(
            candidate_digest=DIGEST,
            capability=operation,
            operation=operation,
            scope={
                "owner": "brullik",
                "repository": "hermes-canary-runtime-fixture",
                "private": True,
            },
            status=CapabilityStatus.AVAILABLE,
            credential_epoch_id=CREDENTIAL_EPOCH,
            toolchain_digest=TOOLCHAIN,
            receipts=(sha256_text("runtime:" + operation),),
        )
        for operation in MANDATORY_Q6_5_OPERATIONS[:8]
    )


def test_permanent_product_broker_is_a_durable_pre_preq8_gate(tmp_path: Path) -> None:
    state_root = tmp_path / "functional"
    state_root.mkdir()
    governor = _governor(state_root / "functional.db")
    report = state_root / "product-github" / "report-index.json"
    failure = state_root / "product-github" / "failure-index.json"
    config = {
        "candidate_digest": DIGEST,
        "toolchain_manifest_digest": TOOLCHAIN,
    }
    assert _reconcile_product_github(
        governor,
        epoch_id=EPOCH,
        config=config,
        state_root=state_root,
        report_index=report,
        failure_index=failure,
    ) == {"status": "PRODUCT_GITHUB_PROBE_REQUIRED", "epoch_id": EPOCH}

    failure.parent.mkdir(parents=True)
    missing = {
        "schema_version": "1.0",
        "candidate_digest": DIGEST,
        "credential_epoch_id": None,
        "capability": "github.product.runtime",
        "status": "MISSING_EXTERNAL",
        "safe_reason_code": "missing_stable_product_github_credential",
        "observed_at": "2026-08-08T00:00:00Z",
    }
    failure.write_text(
        json.dumps(
            {**missing, "failure_digest": sha256_text(stable_json(missing))},
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    waiting = _reconcile_product_github(
        governor,
        epoch_id=EPOCH,
        config=config,
        state_root=state_root,
        report_index=report,
        failure_index=failure,
    )
    assert waiting is not None and waiting["status"] == "WAITING_CAPABILITY"
    assert len(list((state_root / "notifications" / "outbox").glob("*.json"))) == 1

    failure.unlink()
    reports = _runtime_reports()
    payload = {
        "schema_version": "1.0",
        "credential_epoch_id": CREDENTIAL_EPOCH,
        "reports": [item.as_dict() for item in sorted(reports, key=lambda item: item.operation)],
    }
    report.write_text(
        json.dumps(
            {**payload, "report_digest": sha256_text(stable_json(payload))},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    assert (
        _reconcile_product_github(
            governor,
            epoch_id=EPOCH,
            config=config,
            state_root=state_root,
            report_index=report,
            failure_index=failure,
        )
        is None
    )
    epoch = governor.epoch(EPOCH)
    assert (epoch["q6_5_status"], epoch["product_github_status"], epoch["status"]) == (
        "PASS",
        "PASS",
        "RUNTIME_CAPABILITY_PENDING",
    )
    action = governor.connection.execute("SELECT status FROM functional_owner_actions").fetchone()
    assert tuple(action) == ("RESOLVED",)


def test_product_github_technical_failure_is_terminal_not_owner_work(tmp_path: Path) -> None:
    state_root = tmp_path / "functional"
    state_root.mkdir()
    governor = _governor(state_root / "functional.db")
    failure = state_root / "product-github" / "failure-index.json"
    failure.parent.mkdir(parents=True)
    internal = {
        "schema_version": "1.0",
        "candidate_digest": DIGEST,
        "credential_epoch_id": CREDENTIAL_EPOCH,
        "capability": "github.product.runtime",
        "status": "BROKEN_INTERNAL",
        "safe_reason_code": "stable_product_github_operation_failed",
        "observed_at": "2026-08-08T00:00:00Z",
    }
    failure.write_text(
        json.dumps(
            {**internal, "failure_digest": sha256_text(stable_json(internal))},
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    result = _reconcile_product_github(
        governor,
        epoch_id=EPOCH,
        config={"candidate_digest": DIGEST, "toolchain_manifest_digest": TOOLCHAIN},
        state_root=state_root,
        report_index=state_root / "product-github" / "report-index.json",
        failure_index=failure,
    )

    assert result == {
        "status": "QUALIFICATION_FAILED",
        "reason_code": "stable_product_github_operation_failed",
        "epoch_id": EPOCH,
    }
    epoch = governor.epoch(EPOCH)
    assert (epoch["product_github_status"], epoch["status"]) == (
        "FAIL",
        "QUALIFICATION_FAILED",
    )
    assert (
        governor.connection.execute("SELECT COUNT(*) FROM functional_owner_actions").fetchone()[0]
        == 0
    )
    assert list((state_root / "notifications").glob("**/*.json")) == []


def test_stable_provider_invocation_is_a_durable_pre_preq8_gate(tmp_path: Path) -> None:
    state_root = tmp_path / "functional"
    state_root.mkdir()
    governor = _governor(state_root / "functional.db")
    github_reports = _runtime_reports()
    github_payload = {
        "schema_version": "1.0",
        "credential_epoch_id": CREDENTIAL_EPOCH,
        "reports": [
            item.as_dict() for item in sorted(github_reports, key=lambda item: item.operation)
        ],
    }
    governor.record_product_github_capability(
        epoch_id=EPOCH,
        credential_epoch_id=CREDENTIAL_EPOCH,
        report_digest=sha256_text(stable_json(github_payload)),
        reports=github_reports,
    )
    report = state_root / "stable-provider" / "report-index.json"
    failure = state_root / "stable-provider" / "failure-index.json"
    config = {"candidate_digest": DIGEST, "toolchain_manifest_digest": TOOLCHAIN}
    assert _reconcile_stable_provider(
        governor,
        epoch_id=EPOCH,
        config=config,
        state_root=state_root,
        report_index=report,
        failure_index=failure,
    ) == {"status": "STABLE_PROVIDER_PROBE_REQUIRED", "epoch_id": EPOCH}

    reports = tuple(
        CapabilityHandshakeReport.create(
            candidate_digest=DIGEST,
            capability=f"provider.{tier}.invoke",
            operation=f"provider.{tier}.invoke",
            scope={
                "alias": alias,
                "provider": "fixture",
                "model": f"fixture-{tier}",
                "semantic_id": sha256_text("stable-provider-fixture"),
                "stdout_contract": "json-only",
                "runtime_principal": "hermesfactory",
            },
            status=CapabilityStatus.AVAILABLE,
            credential_epoch_id=None,
            toolchain_digest=TOOLCHAIN,
            receipts=(sha256_text("provider:" + tier),),
        )
        for tier, alias in (("luna", "economy"), ("terra", "standard"), ("sol", "expert"))
    ) + (
        CapabilityHandshakeReport.create(
            candidate_digest=DIGEST,
            capability="provider.terminal.sandbox",
            operation="provider.terminal.sandbox",
            scope={
                "alias": "economy",
                "provider": "fixture",
                "model": "fixture-luna",
                "semantic_id": sha256_text("stable-provider-terminal-sandbox-v1"),
                "runtime_principal": "hermesfactory",
                "execution_boundary": "rootless_oci",
                "container_identity": "/run/.containerenv",
                "workspace_mount": True,
                "credential_forwarding": False,
                "toolsets": ["terminal"],
                "marker_digest": sha256_text("terminal-marker"),
            },
            status=CapabilityStatus.AVAILABLE,
            credential_epoch_id=None,
            toolchain_digest=TOOLCHAIN,
            receipts=(sha256_text("provider:terminal:sandbox"),),
        ),
    )
    payload = {
        "schema_version": "1.0",
        "observed_at": "2026-08-08T00:00:00+00:00",
        "reports": [item.as_dict() for item in sorted(reports, key=lambda item: item.operation)],
    }
    report.parent.mkdir(parents=True)
    report.write_text(
        json.dumps(
            {**payload, "report_digest": sha256_text(stable_json(payload))},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    assert (
        _reconcile_stable_provider(
            governor,
            epoch_id=EPOCH,
            config=config,
            state_root=state_root,
            report_index=report,
            failure_index=failure,
        )
        is None
    )
    epoch = governor.epoch(EPOCH)
    assert (
        epoch["product_github_status"],
        epoch["stable_provider_status"],
        epoch["status"],
    ) == ("PASS", "PASS", "PRE_Q8_PENDING")


def test_every_model_writing_worker_uses_credential_free_oci_tools() -> None:
    units = (
        "hermes-factory-worker.service",
        "hermes-factory-worker-2.service",
        "hermes-factory-candidate-worker.service",
        "hermes-factory-canary-worker@.service",
        "hermes-factory-pre-q8-worker@.service",
        "hermes-factory-golden-worker.service",
    )
    required = (
        "Environment=TERMINAL_ENV=docker",
        "Environment=HERMES_DOCKER_BINARY=/usr/bin/podman",
        "Environment=TERMINAL_DOCKER_FORWARD_ENV=[]",
        "Environment=TERMINAL_DOCKER_MOUNT_CWD_TO_WORKSPACE=true",
        "Environment=TERMINAL_DOCKER_PERSIST_ACROSS_PROCESSES=false",
        "Environment=TERMINAL_DOCKER_RUN_AS_HOST_USER=true",
        "InaccessiblePaths=",
        "/etc/hermes-factory/credentials.d",
        "/etc/hermes-factory/candidate-credentials.d",
    )
    for unit in units:
        text = (ROOT / "config" / "systemd" / unit).read_text(encoding="utf-8")
        assert all(item in text for item in required), unit
    worker = (ROOT / "factory" / "worker.py").read_text(encoding="utf-8")
    agent_worker = worker[worker.index("class AgentWorker") :]
    assert 'toolsets=("terminal",)' in agent_worker
    assert 'toolsets=("file", "terminal")' not in agent_worker

    provider_unit = (
        ROOT / "config" / "systemd" / "hermes-factory-stable-provider-capability.service"
    ).read_text(encoding="utf-8")
    assert all(item in provider_unit for item in required[:7])
    provider_probe = (ROOT / "scripts" / "stable_provider_capability.py").read_text(
        encoding="utf-8"
    )
    assert 'toolsets=("terminal",)' in provider_probe
    assert "test -f /run/.containerenv" in provider_probe
    assert '"credential_forwarding": False' in provider_probe


def test_product_broker_cannot_read_or_write_stable_controller_state() -> None:
    unit = (
        ROOT / "config" / "systemd" / "hermes-factory-product-github-broker.service"
    ).read_text(encoding="utf-8")
    assert "ReadWritePaths=/var/lib/hermes-factory " not in unit
    assert "ReadWritePaths=/var/lib/hermes-factory/product-github " in unit
    assert "/var/lib/hermes-factory/evidence/product-github-receipts" in unit
    assert "/var/lib/hermes-factory/worktrees" in unit
    inaccessible = next(
        line for line in unit.splitlines() if line.startswith("InaccessiblePaths=")
    )
    assert "/var/lib/hermes-factory/controller.db" in inaccessible
    assert "/etc/hermes-factory/credentials.d" in inaccessible
