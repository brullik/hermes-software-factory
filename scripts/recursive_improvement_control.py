#!/usr/bin/env python3
"""Initialize and reconcile the bounded Candidate-only improvement lane."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

from factory.common import sha256_text, stable_json
from factory.recursive_improvement import ImprovementError, RecursiveImprovementGovernor


def _scan_observations(
    governor: RecursiveImprovementGovernor, observation_root: Path
) -> tuple[int, str | None]:
    scanned = 0
    latest_outcome: str | None = None
    if not observation_root.is_dir() or observation_root.is_symlink():
        return scanned, latest_outcome
    for path in sorted(observation_root.glob("*.json")):
        if path.name.endswith("-rollback.json") or path.is_symlink() or not path.is_file():
            continue
        value: Any = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("proof_type") != "PRODUCTION_OBSERVATION":
            continue
        digest = str(value.get("proof_digest") or "")
        unsigned = {key: item for key, item in value.items() if key != "proof_digest"}
        if digest != sha256_text(stable_json(unsigned)):
            raise ImprovementError("production observation proof digest differs")
        latest_outcome = governor.record_observation_scan(
            observation_digest=digest,
            candidate_digest=str(value.get("candidate_digest") or ""),
            source_ref=f"artifact://production-observation/{digest}",
            measured_deficits={
                "controller_incidents": float(value.get("controller_incidents", -1)),
                "digest_divergences": float(value.get("digest_divergences", -1)),
                "health_failures": float(value.get("health_failures", -1)),
            },
        )
        scanned += 1
    return scanned, latest_outcome


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional/recursive-improvement.db"),
    )
    parser.add_argument("--stable-root", type=Path, default=Path("/opt/hermes-factory/current"))
    parser.add_argument(
        "--isolated-root",
        type=Path,
        default=Path("/var/lib/hermes-factory-improvement-lab"),
    )
    parser.add_argument(
        "--observation-root",
        type=Path,
        default=Path("/var/lib/hermes-factory-verifier/production-observation"),
    )
    args = parser.parse_args(argv)
    try:
        args.database.parent.mkdir(parents=True, exist_ok=True)
        args.isolated_root.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(args.database)
        try:
            governor = RecursiveImprovementGovernor(
                connection,
                stable_root=args.stable_root,
                isolated_root=args.isolated_root,
            )
            scanned, latest_outcome = _scan_observations(governor, args.observation_root.resolve())
            latest = connection.execute(
                """SELECT observation_digest,candidate_digest
                     FROM improvement_scans
                    ORDER BY created_at DESC,scan_id DESC LIMIT 1"""
            ).fetchone()
            lane_proof_digest = None
            if latest is not None:
                lane_proof_digest = governor.qualify_isolated_lane(
                    observation_digest=str(latest[0]),
                    release_digest=str(latest[1]),
                )
            result = {
                "status": "ACTIVE",
                "active_experiments": governor.active_experiment_count(),
                "observations_scanned": scanned,
                "latest_detection_outcome": latest_outcome,
                "lane_proof_digest": lane_proof_digest,
                "max_recursion_depth": 3,
                "max_implementation_attempts": 2,
                "stable_self_write": False,
            }
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError, ImprovementError) as error:
        print(json.dumps({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
