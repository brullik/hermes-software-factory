#!/usr/bin/env python3
"""Fail-closed Hermes version compatibility smoke test."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_RE = re.compile(r"Hermes Agent v(?P<version>\d+\.\d+\.\d+)")


def expected_version(report_path: Path) -> str:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    for component in report.get("components", []):
        if isinstance(component, dict) and component.get("name") == "Hermes Agent":
            version = component.get("version")
            if isinstance(version, str) and re.fullmatch(r"\d+\.\d+\.\d+", version):
                return version
    raise ValueError("Hermes Agent compatibility pin is missing")


def observed_version(binary: str) -> str:
    completed = subprocess.run(
        [binary, "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    output = completed.stdout + "\n" + completed.stderr
    match = VERSION_RE.search(output)
    if completed.returncode != 0 or match is None:
        raise RuntimeError("Hermes version probe did not return a parseable version")
    return match.group("version")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=ROOT / "evidence" / "compatibility-report.json")
    parser.add_argument("--binary", default="hermes")
    parser.add_argument(
        "--candidate-version",
        help="Use a deterministic negative-test fixture instead of invoking the Hermes binary.",
    )
    args = parser.parse_args(argv)
    try:
        expected = expected_version(args.report)
        actual = args.candidate_version or observed_version(args.binary)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "FAILED_SAFE", "reason": type(error).__name__}))
        return 78
    if actual != expected:
        print(json.dumps({
            "status": "REJECTED_INCOMPATIBLE",
            "expected_version": expected,
            "observed_version": actual,
        }))
        return 78
    print(json.dumps({"status": "PASS", "version": actual}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
