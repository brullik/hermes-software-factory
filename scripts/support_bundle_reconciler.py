#!/usr/bin/env python3
"""Create one sanitized support bundle for every confirmed terminal incident."""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from factory.common import redact_text, sha256_file, sha256_text, stable_json, utc_now
from factory.support_bundle import SupportBundleError, build_support_bundle

_SAFE_CODE = re.compile(r"[A-Za-z0-9_.:-]{1,200}")


@dataclass(frozen=True)
class ConfirmedIncident:
    incident_id: str
    source: str
    status: str
    reason_code: str
    product_id: str | None
    evidence_ref: str | None

    @property
    def bundle_id(self) -> str:
        return f"TECH-{sha256_text(stable_json(self.__dict__))[:32]}"

    def snapshot(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "incident_id": self.incident_id,
            "source": self.source,
            "status": self.status,
            "reason_code": self.reason_code,
            "product_id": self.product_id,
            "evidence_ref": self.evidence_ref,
            "classification": "CONFIRMED_TERMINAL_TECHNICAL_PROBLEM",
        }


def _open_readonly(path: Path) -> sqlite3.Connection | None:
    if not path.is_file() or path.is_symlink():
        return None
    connection = sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    if str(connection.execute("PRAGMA quick_check").fetchone()[0]) != "ok":
        connection.close()
        raise SupportBundleError("incident source database failed integrity check")
    return connection


def _safe(value: object, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    text = str(value or "")
    if not _SAFE_CODE.fullmatch(text):
        raise SupportBundleError("incident identity contains unsafe data")
    return text


def _opaque_evidence_ref(value: object) -> str | None:
    if value is None or not str(value):
        return None
    return f"sha256:{sha256_text(str(value))}"


def confirmed_incidents(
    *, stable_database: Path, functional_database: Path
) -> tuple[ConfirmedIncident, ...]:
    incidents: list[ConfirmedIncident] = []
    stable = _open_readonly(stable_database)
    if stable is not None:
        try:
            tables = {
                str(row[0])
                for row in stable.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if {"controller_incidents", "products"} <= tables:
                rows = stable.execute(
                    """SELECT incident.incident_id,incident.reason_code,
                              incident.evidence_ref,incident.product_id
                         FROM controller_incidents AS incident
                         LEFT JOIN products AS product
                           ON product.product_id=incident.product_id
                        WHERE incident.status!='RESOLVED'
                          AND (product.status='FAILED_SAFE' OR incident.product_id IS NULL)
                        ORDER BY incident.created_at,incident.incident_id"""
                ).fetchall()
                incidents.extend(
                    ConfirmedIncident(
                        incident_id=str(_safe(row[0])),
                        source="stable_controller",
                        status="FAILED_SAFE",
                        reason_code=str(_safe(row[1])),
                        product_id=_safe(row[3], optional=True),
                        evidence_ref=_opaque_evidence_ref(row[2]),
                    )
                    for row in rows
                )
        finally:
            stable.close()

    functional = _open_readonly(functional_database)
    if functional is not None:
        try:
            tables = {
                str(row[0])
                for row in functional.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if "functional_epochs" in tables:
                rows = functional.execute(
                    """SELECT epoch_id,source_commit FROM functional_epochs
                        WHERE status='QUALIFICATION_FAILED'
                        ORDER BY created_at,epoch_id"""
                ).fetchall()
                incidents.extend(
                    ConfirmedIncident(
                        incident_id=str(_safe(row[0])),
                        source="candidate_qualification",
                        status="QUALIFICATION_FAILED",
                        reason_code="candidate_qualification_failed",
                        product_id=None,
                        evidence_ref=f"git:{_safe(row[1])!s}",
                    )
                    for row in rows
                )
        finally:
            functional.close()
    return tuple(incidents)


def _write_snapshot(root: Path, incident: ConfirmedIncident) -> Path:
    destination = root / "support-sources" / f"{incident.bundle_id}.json"
    encoded = json.dumps(incident.snapshot(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    safe, redactions = redact_text(encoded)
    if redactions or safe != encoded:
        raise SupportBundleError("incident snapshot contains secret-like data")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.is_symlink() or destination.read_text(encoding="utf-8") != encoded:
            raise SupportBundleError("immutable incident snapshot conflicts")
        return destination
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    return destination


def reconcile(
    *, stable_database: Path, functional_root: Path, verifier_root: Path
) -> dict[str, Any]:
    detected = confirmed_incidents(
        stable_database=stable_database,
        functional_database=functional_root / "functional.db",
    )
    bundles: list[dict[str, str]] = []
    for incident in detected:
        snapshot = _write_snapshot(functional_root, incident)
        bundle, digest = build_support_bundle(
            incident_id=incident.bundle_id,
            source_files=(snapshot,),
            allowed_roots=(functional_root, verifier_root),
            output_root=functional_root / "support-bundles",
            metadata={
                "status": "CONFIRMED_TECHNICAL_PROBLEM",
                "source": incident.source,
            },
        )
        bundles.append(
            {
                "incident_id": incident.bundle_id,
                "bundle": str(bundle),
                "digest": digest,
            }
        )
    return {"status": "PASS", "confirmed_incidents": len(detected), "bundles": bundles}


def write_reconcile_report(functional_root: Path, result: dict[str, Any]) -> dict[str, Any]:
    receipts: list[dict[str, str]] = []
    raw_bundles = result.get("bundles")
    if not isinstance(raw_bundles, list):
        raise SupportBundleError("support reconciliation result is invalid")
    bundle_root = (functional_root / "support-bundles").resolve()
    for item in raw_bundles:
        if not isinstance(item, dict):
            raise SupportBundleError("support bundle receipt is invalid")
        path = Path(str(item.get("bundle") or "")).resolve()
        if (
            bundle_root not in path.parents
            or not path.is_file()
            or path.is_symlink()
            or sha256_file(path) != str(item.get("digest") or "")
        ):
            raise SupportBundleError("support bundle receipt differs from immutable bundle")
        receipts.append(
            {
                "incident_id": str(item.get("incident_id") or ""),
                "filename": path.name,
                "digest": str(item["digest"]),
            }
        )
    report = {
        "schema_version": "1.0",
        "proof_type": "SUPPORT_BUNDLE_RECONCILIATION",
        "status": "PASS",
        "observed_at": utc_now(),
        "confirmed_incidents": int(result.get("confirmed_incidents", -1)),
        "bundle_receipts": receipts,
    }
    if report["confirmed_incidents"] != len(receipts):
        raise SupportBundleError("confirmed incidents and support receipts differ")
    proof_digest = sha256_text(stable_json(report))
    value = {**report, "proof_digest": proof_digest}
    encoded = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    report_root = functional_root / "support-reconciler"
    report_root.mkdir(parents=True, exist_ok=True)
    immutable = report_root / f"report-{proof_digest}.json"
    if immutable.exists():
        if immutable.is_symlink() or immutable.read_text(encoding="utf-8") != encoded:
            raise SupportBundleError("immutable support reconciliation report conflicts")
    else:
        descriptor = os.open(immutable, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    index = report_root / "report-index.json"
    temporary = report_root / f".report-index-{os.getpid()}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, index)
    finally:
        temporary.unlink(missing_ok=True)
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--stable-database",
        type=Path,
        default=Path("/var/lib/hermes-factory/controller.db"),
    )
    parser.add_argument(
        "--functional-root",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional"),
    )
    parser.add_argument(
        "--verifier-root",
        type=Path,
        default=Path("/var/lib/hermes-factory-verifier"),
    )
    args = parser.parse_args(argv)
    try:
        result = reconcile(
            stable_database=args.stable_database,
            functional_root=args.functional_root.resolve(),
            verifier_root=args.verifier_root.resolve(),
        )
        result["report"] = write_reconcile_report(args.functional_root.resolve(), result)[
            "proof_digest"
        ]
    except (OSError, ValueError, sqlite3.Error, SupportBundleError) as error:
        print(
            json.dumps({"status": "FAIL", "error_type": type(error).__name__}),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
