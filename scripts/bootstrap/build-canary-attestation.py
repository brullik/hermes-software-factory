#!/usr/bin/env python3
"""Create the empty live-probe capability boundary for clean canaries."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.output.is_absolute():
        raise ValueError("clean canary attestation path must be absolute")
    encoded = json.dumps(
        {
            "schema_version": "1.0",
            "plane": "CLEAN_CANARY",
            # Empty is deliberate: GitHub/provider access must pass the live
            # Candidate B probes and cannot be asserted by this file.
            "capabilities": {},
        },
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    if args.output.exists():
        if args.output.is_symlink() or args.output.read_text(encoding="utf-8") != encoded:
            raise ValueError("clean canary capability attestation conflicts")
        return 0
    args.output.write_text(encoded, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
