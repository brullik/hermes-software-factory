from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

from factory.support_bundle import SupportBundleError, build_support_bundle
from scripts.support_bundle_reconciler import (
    confirmed_incidents,
    reconcile,
    write_reconcile_report,
)


def _stable_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE products(product_id TEXT PRIMARY KEY,status TEXT);
        CREATE TABLE controller_incidents(
            incident_id TEXT PRIMARY KEY,product_id TEXT,task_id TEXT,
            reason_code TEXT,evidence_ref TEXT,status TEXT,created_at TEXT,resolved_at TEXT
        );
        INSERT INTO products VALUES ('failed-product','FAILED_SAFE');
        INSERT INTO products VALUES ('recovering-product','IMPLEMENTING');
        INSERT INTO controller_incidents VALUES
          ('INC-FAILED','failed-product',NULL,'schema_invariant',
           'artifact://internal/path','OPEN','2026-08-08T00:00:00Z',NULL),
          ('INC-TRANSIENT','recovering-product',NULL,'temporary_worker_loss',
           'artifact://internal/path','OPEN','2026-08-08T00:00:01Z',NULL);
        """
    )
    connection.commit()
    connection.close()


def _functional_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE functional_epochs("
        "epoch_id TEXT,source_commit TEXT,status TEXT,created_at TEXT)"
    )
    connection.execute(
        "INSERT INTO functional_epochs VALUES (?,?,?,?)",
        ("RE-FAILED", "a" * 40, "QUALIFICATION_FAILED", "2026-08-08T00:00:00Z"),
    )
    connection.commit()
    connection.close()


def test_support_bundle_requires_evidence_and_is_incident_idempotent(tmp_path: Path) -> None:
    source = tmp_path / "diagnostic.json"
    source.write_text('{"status":"FAILED_SAFE"}\n', encoding="utf-8")
    output = tmp_path / "bundles"
    first, first_digest = build_support_bundle(
        incident_id="TECH-1",
        source_files=(source,),
        allowed_roots=(tmp_path,),
        output_root=output,
        metadata={"status": "CONFIRMED_TECHNICAL_PROBLEM"},
    )
    source.write_text('{"status":"CHANGED"}\n', encoding="utf-8")
    second, second_digest = build_support_bundle(
        incident_id="TECH-1",
        source_files=(source,),
        allowed_roots=(tmp_path,),
        output_root=output,
        metadata={"status": "CONFIRMED_TECHNICAL_PROBLEM"},
    )
    assert (second, second_digest) == (first, first_digest)
    with zipfile.ZipFile(first) as archive:
        assert json.loads(archive.read("manifest.json"))["incident_id"] == "TECH-1"
    with pytest.raises(SupportBundleError, match="requires diagnostic evidence"):
        build_support_bundle(
            incident_id="TECH-2",
            source_files=(),
            allowed_roots=(tmp_path,),
            output_root=output,
            metadata={"status": "CONFIRMED_TECHNICAL_PROBLEM"},
        )
    with pytest.raises(SupportBundleError, match="metadata"):
        build_support_bundle(
            incident_id="TECH-3",
            source_files=(source,),
            allowed_roots=(tmp_path,),
            output_root=output,
            metadata={"token": "ghp_" + "x" * 30},
        )


def test_reconciler_bundles_only_confirmed_terminal_incidents(tmp_path: Path) -> None:
    stable = tmp_path / "controller.db"
    functional = tmp_path / "functional"
    verifier = tmp_path / "verifier"
    functional.mkdir()
    verifier.mkdir()
    _stable_database(stable)
    _functional_database(functional / "functional.db")
    detected = confirmed_incidents(
        stable_database=stable,
        functional_database=functional / "functional.db",
    )
    assert [(item.source, item.incident_id) for item in detected] == [
        ("stable_controller", "INC-FAILED"),
        ("candidate_qualification", "RE-FAILED"),
    ]
    assert detected[0].evidence_ref is not None
    assert "artifact://" not in detected[0].evidence_ref
    first = reconcile(
        stable_database=stable,
        functional_root=functional,
        verifier_root=verifier,
    )
    second = reconcile(
        stable_database=stable,
        functional_root=functional,
        verifier_root=verifier,
    )
    assert first == second
    assert first["confirmed_incidents"] == 2
    assert len(list((functional / "support-bundles").glob("*.zip"))) == 2
    report = write_reconcile_report(functional, first)
    assert report["status"] == "PASS"
    assert len(report["bundle_receipts"]) == 2
    assert (
        json.loads(
            (functional / "support-reconciler" / "report-index.json").read_text(encoding="utf-8")
        )
        == report
    )
