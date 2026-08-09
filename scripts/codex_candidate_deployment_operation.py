#!/usr/bin/env python3
"""Submit one secret-free, typed Candidate deployment request."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from factory.codex_candidate_deployment import (
    CANONICAL_REPOSITORY,
    DEPLOY_OPERATION,
    CandidateDeploymentClient,
    CandidateDeploymentRequest,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--socket",
        type=Path,
        default=Path("/run/hermes-codex-candidate-deployment-broker/broker.sock"),
    )
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--tree-sha", required=True)
    parser.add_argument("--merge-receipt-id", required=True)
    parser.add_argument("--merge-receipt-digest", required=True)
    args = parser.parse_args()

    request = CandidateDeploymentRequest.from_mapping(
        {
            "schema_version": "1.0",
            "request_id": args.request_id,
            "operation": DEPLOY_OPERATION,
            "repository": CANONICAL_REPOSITORY,
            "commit_sha": args.commit_sha,
            "tree_sha": args.tree_sha,
            "merge_receipt_id": args.merge_receipt_id,
            "merge_receipt_digest": args.merge_receipt_digest,
        }
    )
    response = CandidateDeploymentClient(args.socket).execute(request)
    print(json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if response["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
