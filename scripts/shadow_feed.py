#!/usr/bin/env python3
"""Export Stable A events or evaluate them in the isolated Candidate B plane."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from factory.common import stable_json
from factory.shadow_feed import ShadowFeedError, evaluate_candidate_batches, export_stable_events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export")
    export.add_argument("--database", type=Path, required=True)
    export.add_argument("--feed-root", type=Path, required=True)
    export.add_argument("--limit", type=int, default=1000)
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("--feed-root", type=Path, required=True)
    evaluate.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "export":
            result = export_stable_events(
                args.database,
                args.feed_root,
                limit=args.limit,
            )
        else:
            result = evaluate_candidate_batches(args.feed_root, args.output_root)
    except (ShadowFeedError, OSError, ValueError, TypeError) as error:
        print(
            stable_json({"status": "FAIL", "error_type": type(error).__name__}),
            file=sys.stderr,
        )
        return 1
    print(stable_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
