#!/usr/bin/env python3
"""Promote an exact Golden staging digest only inside the isolated Candidate root."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from factory.config import load_config
from factory.deployment import TransactionalDeployer
from factory.release_executor import _release_digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--product-id", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--staging-digest", required=True)
    parser.add_argument(
        "--config", type=Path, default=Path("/etc/hermes-factory/golden.yaml")
    )
    args = parser.parse_args()
    if not re.fullmatch(r"brullik/hermes-golden-[A-Za-z0-9_.-]+", args.repository):
        raise ValueError("Golden repository is outside isolated allowlist")
    if not re.fullmatch(r"[a-f0-9]{40}", args.release_id) or not re.fullmatch(
        r"sha256:[a-f0-9]{64}", args.staging_digest
    ):
        raise ValueError("Golden release identity is invalid")
    config = load_config(args.config)
    state = Path(str(config.raw["paths"]["state"])).resolve()
    allowed_root = Path("/var/lib/hermes-factory-golden").resolve()
    if state.parent != allowed_root or not re.fullmatch(r"[a-f0-9]{40}", state.name):
        raise ValueError("Golden state root is not bound to one Candidate commit")
    source = state / "staging" / args.product_id / "current"
    if not source.is_dir() or source.is_symlink() or _release_digest(source) != args.staging_digest:
        raise ValueError("Golden staging source differs from accepted digest")
    install = state / "isolated-target" / args.product_id
    transaction = TransactionalDeployer(
        install,
        health_probe=lambda current: _release_digest(current) == args.staging_digest,
    ).promote(args.release_id, source)
    if transaction.status != "PROMOTED":
        raise RuntimeError("Golden isolated deployment did not promote")
    print(
        json.dumps(
            {
                "status": "PROMOTED",
                "release_id": args.release_id,
                "staging_digest": args.staging_digest,
                "target": "isolated_candidate",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
