#!/usr/bin/env python3
"""Initialize and reconcile the bounded Candidate-only improvement lane."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from factory.recursive_improvement import ImprovementError, RecursiveImprovementGovernor


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional/recursive-improvement.db"),
    )
    parser.add_argument(
        "--stable-root", type=Path, default=Path("/opt/hermes-factory/current")
    )
    parser.add_argument(
        "--isolated-root",
        type=Path,
        default=Path("/var/lib/hermes-factory-improvement-lab"),
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
            result = {
                "status": "ACTIVE",
                "active_experiments": governor.active_experiment_count(),
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
