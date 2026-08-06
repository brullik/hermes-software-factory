#!/usr/bin/env python3
"""Project one functional scenario from authoritative Candidate database truth."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from factory.common import stable_json
from factory.functional_readiness import CandidateDatabaseVerifier, FunctionalReadinessError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--worker-idle", action="store_true")
    args = parser.parse_args(argv)
    try:
        truth = CandidateDatabaseVerifier.inspect(
            args.database, worker_idle=args.worker_idle
        )
    except (OSError, ValueError, FunctionalReadinessError) as error:
        print(stable_json({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    print(
        stable_json(
            {
                "product_status": truth.product_status,
                "scenario_status": truth.scenario_status,
                "task_statuses": list(truth.task_statuses),
                "failure_reasons": list(truth.failure_reasons),
                "open_incidents": list(truth.open_incidents),
                "completion_manifest_count": truth.completion_manifest_count,
                "liveness_finding": truth.liveness_finding,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
