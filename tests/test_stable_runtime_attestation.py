from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

import pytest
import yaml

from scripts.stable_runtime_attestation import StableAttestationError, run


def _fixture(tmp_path: Path) -> argparse.Namespace:
    database = tmp_path / "controller.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE products(product_id TEXT PRIMARY KEY,status TEXT NOT NULL);
        CREATE TABLE controller_incidents(
            incident_id TEXT PRIMARY KEY,status TEXT NOT NULL
        );
        CREATE TABLE side_effect_intents(
            intent_id TEXT PRIMARY KEY,idempotency_key TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL
        );
        CREATE TABLE side_effect_receipts(
            receipt_id TEXT PRIMARY KEY,intent_id TEXT NOT NULL UNIQUE
        );
        CREATE TABLE completion_manifests(
            manifest_id TEXT PRIMARY KEY,product_id TEXT NOT NULL UNIQUE
        );
        CREATE TABLE outbox(
            outbox_id TEXT PRIMARY KEY,event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,status TEXT NOT NULL
        );
        INSERT INTO products VALUES ('P-1','COMPLETED');
        INSERT INTO completion_manifests VALUES ('CM-1','P-1');
        INSERT INTO side_effect_intents VALUES ('SEI-1','effect-1','VERIFIED');
        INSERT INTO side_effect_receipts VALUES ('SER-1','SEI-1');
        """
    )
    connection.commit()
    connection.close()
    control = tmp_path / "control.yaml"
    control.write_text(yaml.safe_dump({"candidate_digest": "a" * 64}), encoding="utf-8")
    functional = tmp_path / "functional"
    return argparse.Namespace(
        control=control,
        database=database,
        functional_root=functional,
        output=None,
    )


def test_stable_attestation_matches_internal_completion_and_effect_truth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = _fixture(tmp_path)
    monkeypatch.setattr("scripts.stable_runtime_attestation._worker_sandbox_violations", lambda: 0)
    monkeypatch.setattr(
        "scripts.stable_runtime_attestation._codex_runtime_dependency_violations", lambda: 0
    )
    result = run(args)
    assert result["status"] == "PASS"
    output = args.functional_root / "ready" / f"stable-runtime-{'a' * 64}.json"
    value = json.loads(output.read_text(encoding="utf-8"))
    assert value["metrics"]["open_controller_incidents"] == 0
    assert value["metrics"]["duplicate_side_effects"] == 0


def test_stable_attestation_rejects_unresolved_controller_incident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = _fixture(tmp_path)
    monkeypatch.setattr("scripts.stable_runtime_attestation._worker_sandbox_violations", lambda: 0)
    monkeypatch.setattr(
        "scripts.stable_runtime_attestation._codex_runtime_dependency_violations", lambda: 0
    )
    connection = sqlite3.connect(args.database)
    connection.execute("INSERT INTO controller_incidents VALUES ('INC-1','OPEN')")
    connection.commit()
    connection.close()
    with pytest.raises(StableAttestationError, match="state differs"):
        run(args)


def test_stable_attestation_rejects_unsandboxed_provider_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = _fixture(tmp_path)
    monkeypatch.setattr("scripts.stable_runtime_attestation._worker_sandbox_violations", lambda: 1)
    monkeypatch.setattr(
        "scripts.stable_runtime_attestation._codex_runtime_dependency_violations", lambda: 0
    )
    with pytest.raises(StableAttestationError, match="state differs"):
        run(args)


def test_stable_attestation_rejects_codex_runtime_dependency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = _fixture(tmp_path)
    monkeypatch.setattr("scripts.stable_runtime_attestation._worker_sandbox_violations", lambda: 0)
    monkeypatch.setattr(
        "scripts.stable_runtime_attestation._codex_runtime_dependency_violations", lambda: 1
    )
    with pytest.raises(StableAttestationError, match="state differs"):
        run(args)
