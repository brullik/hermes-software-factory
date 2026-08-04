#!/usr/bin/env python3
"""Run one root-owned production observation and reconcile LTS or rollback."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

from factory.common import stable_json
from factory.production_observation import (
    ProductionObservationError,
    observe_once,
    rollback_to_lts_a,
)
from scripts.qualification_control import _load_config


def _verifier(command: str) -> None:
    result = subprocess.run(
        [
            "runuser",
            "-u",
            "hermesverifier",
            "--",
            "/opt/hermes-factory-verifier/venv/bin/python",
            "-m",
            "scripts.qualification_control",
            "--config",
            "/etc/hermes-factory/qualification-control.yaml",
            command,
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=180,
    )
    if result.returncode != 0:
        raise ProductionObservationError("independent verifier reconciliation failed")


def run(config_path: Path) -> dict[str, Any]:
    if os.name != "nt" and getattr(os, "geteuid", lambda: -1)() != 0:
        raise ProductionObservationError("production observation requires root")
    config = _load_config(config_path)
    governor_database = Path(str(config["governor_database"])).resolve()
    connection = sqlite3.connect(
        f"file:{governor_database.as_posix()}?mode=ro", uri=True, timeout=30
    )
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        rows = connection.execute(
            """SELECT * FROM controller_release_epochs
                 WHERE source_commit=? ORDER BY created_at DESC""",
            (str(config["source_commit"]),),
        ).fetchall()
        if len(rows) != 1 or str(rows[0]["status"]) not in {"PROMOTED", "LTS"}:
            raise ProductionObservationError("production epoch is not observable")
        epoch = dict(rows[0])
    finally:
        connection.close()
    if str(epoch["status"]) == "LTS":
        return {"status": "LTS", "reconciliation": "existing"}
    promoted_at = str(epoch.get("promoted_at") or "")
    result = observe_once(
        candidate_digest=str(config["candidate_digest"]),
        promoted_at=promoted_at,
        output_path=Path(str(config["production_observation_path"])),
    )
    if result["status"] == "ROLLBACK_REQUIRED":
        rollback_path = Path(str(config["production_rollback_path"]))
        if not rollback_path.exists():
            rollback_to_lts_a(
                release_id=str(config["source_commit"]),
                expected_candidate_digest=str(config["candidate_digest"]),
                expected_stable_digest=str(config["stable_release_digest"]),
                rollback_path=rollback_path,
            )
        _verifier("production-fail")
        subprocess.run(
            ["systemctl", "disable", "hermes-factory-production-observation.timer"],
            capture_output=True,
            check=False,
            timeout=30,
        )
        return {"status": "ROLLED_BACK"}
    if result["status"] == "LTS_READY":
        _verifier("lts-observe")
        subprocess.run(
            ["systemctl", "disable", "hermes-factory-production-observation.timer"],
            capture_output=True,
            check=False,
            timeout=30,
        )
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/hermes-factory/qualification-control.yaml"),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = run(args.config)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, ProductionObservationError) as error:
        print(stable_json({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    print(stable_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
