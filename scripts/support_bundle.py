#!/usr/bin/env python3
"""Generate and enqueue a sanitized support bundle for one incident."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

from factory.common import redact_text
from factory.support_bundle import SupportBundleError, build_support_bundle


def _database_summary(path: Path, *, kind: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        return {"status": "UNAVAILABLE"}
    connection = sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        result: dict[str, Any] = {
            "status": "AVAILABLE",
            "quick_check": str(connection.execute("PRAGMA quick_check").fetchone()[0]),
        }
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if kind == "functional" and "functional_epochs" in tables:
            result["functional_epochs"] = [
                {
                    "epoch_id": str(row[0]),
                    "status": str(row[1]),
                    "q6_5_status": str(row[2]),
                    "pre_q8_status": str(row[3]),
                    "golden_product_status": str(row[4]),
                    "internal_verifier_status": str(row[5]),
                    "stable_health_status": str(row[6]),
                    "stable_intake_status": str(row[7]),
                }
                for row in connection.execute(
                    """SELECT epoch_id,status,q6_5_status,pre_q8_status,
                              golden_product_status,internal_verifier_status,
                              stable_health_status,stable_intake_status
                         FROM functional_epochs ORDER BY created_at DESC LIMIT 3"""
                )
            ]
            result["open_owner_actions"] = (
                int(
                    connection.execute(
                        "SELECT COUNT(*) FROM functional_owner_actions WHERE status='OPEN'"
                    ).fetchone()[0]
                )
                if "functional_owner_actions" in tables
                else 0
            )
        if kind == "improvement" and "improvement_objectives" in tables:
            result["objectives_by_status"] = {
                str(row[0]): int(row[1])
                for row in connection.execute(
                    "SELECT status,COUNT(*) FROM improvement_objectives GROUP BY status"
                )
            }
        return result
    finally:
        connection.close()


def _service_summary(unit: str) -> dict[str, str]:
    result = subprocess.run(
        [
            "systemctl",
            "show",
            unit,
            "--property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus",
        ],
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {
            "ActiveState",
            "SubState",
            "Result",
            "ExecMainCode",
            "ExecMainStatus",
        }:
            values[key] = value[:120]
    return values or {"status": "UNAVAILABLE"}


def _write_runtime_snapshot(
    *, incident_id: str, functional_root: Path, verifier_root: Path
) -> Path:
    destination = functional_root / "support-sources" / f"{incident_id}.json"
    if destination.exists():
        if destination.is_symlink() or not destination.is_file():
            raise SupportBundleError("support snapshot path is unsafe")
        return destination
    payload = {
        "schema_version": "1.0",
        "incident_id": incident_id,
        "functional_state": _database_summary(functional_root / "functional.db", kind="functional"),
        "improvement_state": _database_summary(
            functional_root / "recursive-improvement.db", kind="improvement"
        ),
        "services": {
            unit: _service_summary(unit)
            for unit in (
                "hermes-factory-controller.service",
                "hermes-factory-gateway.service",
                "hermes-factory-worker.service",
                "hermes-factory-worker-2.service",
                "hermes-factory-functional-qualification.service",
            )
        },
        "verifier_root_available": verifier_root.is_dir() and not verifier_root.is_symlink(),
    }
    encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    safe, redactions = redact_text(encoded)
    if redactions or safe != encoded:
        raise SupportBundleError("support snapshot unexpectedly contains secret-like data")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("incident_id")
    parser.add_argument("--source", action="append", type=Path, default=[])
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
    functional_root = args.functional_root.resolve()
    verifier_root = args.verifier_root.resolve()
    try:
        sources = tuple(args.source)
        if not sources:
            sources = (
                _write_runtime_snapshot(
                    incident_id=args.incident_id,
                    functional_root=functional_root,
                    verifier_root=verifier_root,
                ),
            )
        bundle, digest = build_support_bundle(
            incident_id=args.incident_id,
            source_files=sources,
            allowed_roots=(functional_root, verifier_root),
            output_root=functional_root / "support-bundles",
            metadata={"status": "CONFIRMED_TECHNICAL_PROBLEM"},
        )
    except (
        OSError,
        ValueError,
        sqlite3.Error,
        subprocess.SubprocessError,
        SupportBundleError,
    ) as error:
        print(json.dumps({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    print(json.dumps({"status": "PASS", "bundle": str(bundle), "digest": digest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
