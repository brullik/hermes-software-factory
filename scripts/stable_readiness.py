#!/usr/bin/env python3
"""Read-only Stable A health and intake readiness proof."""

from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import urllib.request
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=Path("/var/lib/hermes-factory/controller.db"))
    parser.add_argument("--health", default="http://127.0.0.1:8787/healthz")
    args = parser.parse_args()
    health = json.loads(urllib.request.urlopen(args.health, timeout=10).read().decode("utf-8"))
    gateway = subprocess.run(
        ["systemctl", "is-active", "--quiet", "hermes-factory-gateway.service"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=15,
    )
    connection = sqlite3.connect(f"file:{args.database.resolve().as_posix()}?mode=ro", uri=True)
    try:
        quick = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        intake_count = int(connection.execute("SELECT COUNT(*) FROM intake_requests").fetchone()[0])
        incidents = (
            int(connection.execute("SELECT COUNT(*) FROM controller_incidents WHERE status!='RESOLVED'").fetchone()[0])
            if "controller_incidents" in tables
            else 0
        )
    finally:
        connection.close()
    health_pass = (
        isinstance(health, dict)
        and str(health.get("status", "")).lower() in {"ok", "pass", "healthy"}
        and health.get("database") is True
    )
    intake_pass = quick == "ok" and intake_count > 0 and incidents == 0 and gateway.returncode == 0
    result = {
        "status": "PASS" if health_pass and intake_pass else "FAIL",
        "health": "PASS" if health_pass else "FAIL",
        "intake": "PASS" if intake_pass else "FAIL",
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
