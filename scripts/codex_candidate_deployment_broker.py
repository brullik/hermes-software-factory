#!/usr/bin/env python3
"""Run the root-owned, operation-specific Candidate deployment broker."""

from __future__ import annotations

import argparse
from pathlib import Path

from factory.codex_candidate_deployment import (
    CANONICAL_REMOTE,
    CandidateDeploymentBroker,
    resolve_user,
    serve_candidate_deployment_broker,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--socket",
        type=Path,
        default=Path("/run/hermes-codex-candidate-deployment-broker/broker.sock"),
    )
    parser.add_argument(
        "--state-root",
        type=Path,
        default=Path("/var/lib/hermes-codex-candidate-deployment"),
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path("/var/lib/hermes-codex-candidate-deployment/source"),
    )
    parser.add_argument(
        "--merge-receipt-root",
        type=Path,
        default=Path("/var/lib/hermes-codex-github-broker/receipts"),
    )
    parser.add_argument("--allowed-requester", default="hermescodex")
    parser.add_argument("--merge-receipt-owner", default="hermescodexgithubbroker")
    args = parser.parse_args()

    allowed_uid, allowed_gid = resolve_user(args.allowed_requester)
    receipt_uid, _receipt_gid = resolve_user(args.merge_receipt_owner)
    broker = CandidateDeploymentBroker(
        source_root=args.source_root,
        state_root=args.state_root,
        merge_receipt_root=args.merge_receipt_root,
        expected_source_uid=0,
        expected_merge_receipt_uid=receipt_uid,
        expected_remote_url=CANONICAL_REMOTE,
    )
    serve_candidate_deployment_broker(
        socket_path=args.socket,
        broker=broker,
        allowed_uid=allowed_uid,
        allowed_gid=allowed_gid,
        socket_uid=0,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
