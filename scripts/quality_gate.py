#!/usr/bin/env python3
"""Execute allowlisted quality commands without a shell and emit gate evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.policy_guard import command_allowed


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_catalog(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("Gate catalog must be a mapping")
    return data


def run_gate(
    gate: dict[str, Any],
    cwd: Path,
    subject_sha: str,
    *,
    python_executable: str | None = None,
) -> dict[str, Any]:
    command = str(gate["command"])
    prefixes = gate.get("allowlist_prefixes", [])
    allowed, reason = command_allowed(command, prefixes)
    started = utc_now()
    if not allowed:
        output = f"command rejected: {reason}"
        exit_code = None
        status = "ERROR"
    else:
        try:
            argv = shlex.split(command)
            if python_executable and argv and argv[0].lower() in {"python", "python3", "python.exe"}:
                argv[0] = python_executable
            completed = subprocess.run(
                argv,
                cwd=cwd,
                text=True,
                capture_output=True,
                timeout=int(gate.get("timeout_seconds", 600)),
                check=False,
            )
            output = (completed.stdout + "\n" + completed.stderr).strip()
            exit_code = completed.returncode
            success_exit_codes = gate.get("success_exit_codes", [0])
            if not isinstance(success_exit_codes, list) or not all(
                isinstance(item, int) for item in success_exit_codes
            ):
                raise TypeError("success_exit_codes must be a list of integers")
            status = "PASS" if completed.returncode in success_exit_codes else "FAIL"
        except subprocess.TimeoutExpired as error:
            output = f"gate timed out after {gate.get('timeout_seconds', 600)} seconds: {error}"
            exit_code = None
            status = "ERROR"
        except OSError as error:
            output = f"gate process could not start: {error}"
            exit_code = None
            status = "ERROR"
    finished = utc_now()
    return {
        "schema_version": "1.0",
        "gate_id": gate["id"],
        "status": status,
        "subject_sha": subject_sha,
        "command_digest": digest_text(command),
        "started_at": started,
        "finished_at": finished,
        "exit_code": exit_code,
        "artifact_digest": digest_text(output),
        "summary": output[:4000],
        "mandatory": bool(gate.get("mandatory", True)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--cwd", type=Path, required=True)
    parser.add_argument("--subject-sha", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    catalog = load_catalog(args.catalog)
    selected = next((gate for gate in catalog["gates"] if gate["id"] == args.gate), None)
    if selected is None:
        raise SystemExit(f"Unknown gate: {args.gate}")
    result = run_gate(selected, args.cwd, args.subject_sha, python_executable=sys.executable)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(result["status"])
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
