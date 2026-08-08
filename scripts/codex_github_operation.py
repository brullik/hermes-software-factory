#!/usr/bin/env python3
"""Typed, secret-free client for the Hermes Codex GitHub broker."""

from __future__ import annotations

import argparse
import json
import secrets
from hashlib import sha256
from pathlib import Path

from factory.credential_broker import BrokerClient, BrokerRequest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--socket",
        type=Path,
        default=Path("/run/hermes-codex-github-broker/broker.sock"),
    )
    parser.add_argument("--owner", default="brullik")
    parser.add_argument("--repository", default="hermes-software-factory")
    parser.add_argument("--request-id")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("identity")
    commands.add_parser("repository-read")

    branch = commands.add_parser("branch")
    branch.add_argument("action", choices=("push", "delete"))
    branch.add_argument("--workspace", type=Path, required=True)
    branch.add_argument("--branch", required=True)

    create = commands.add_parser("pr-create")
    create.add_argument("--head", required=True)
    create.add_argument("--base", default="main")
    create.add_argument("--title", required=True)
    create.add_argument("--body-file", type=Path)
    create.add_argument("--draft", action="store_true")

    for name in ("pr-read", "pr-close", "threads"):
        subparser = commands.add_parser(name)
        subparser.add_argument("--number", type=int, required=True)

    mark_draft = commands.add_parser("pr-mark-draft")
    mark_draft.add_argument("--number", type=int, required=True)
    mark_draft.add_argument("--expected-head-sha", required=True)

    comment = commands.add_parser("pr-comment")
    comment.add_argument("--number", type=int, required=True)
    comment.add_argument("--expected-head-sha", required=True)
    comment.add_argument("--body-file", type=Path, required=True)

    checks = commands.add_parser("checks")
    checks.add_argument("--sha", required=True)

    merge = commands.add_parser("pr-merge")
    merge.add_argument("--number", type=int, required=True)
    merge.add_argument("--expected-head-sha", required=True)
    merge.add_argument("--workspace", type=Path, required=True)
    merge.add_argument("--evidence-manifest", type=Path, required=True)
    merge.add_argument("--policy-file", type=Path, required=True)
    return parser


def _request(args: argparse.Namespace) -> tuple[str, dict[str, object]]:
    if args.command == "identity":
        return "identity.read", {}
    if args.command == "repository-read":
        return "repository.read", {}
    if args.command == "branch":
        return "branch.push", {
            "action": args.action,
            "workspace": str(args.workspace.resolve()),
            "branch": args.branch,
        }
    if args.command == "pr-create":
        body = (
            args.body_file.resolve().read_text(encoding="utf-8")
            if args.body_file is not None
            else "Operation-specific Hermes Q6.5 canary"
        )
        return "pull_request.create", {
            "head": args.head,
            "base": args.base,
            "title": args.title,
            "body": body,
            "draft": args.draft,
        }
    if args.command == "pr-mark-draft":
        return "pull_request.update", {
            "number": args.number,
            "action": "mark_draft",
            "expected_head_sha": args.expected_head_sha,
        }
    if args.command == "pr-comment":
        return "pull_request.update", {
            "number": args.number,
            "action": "comment",
            "expected_head_sha": args.expected_head_sha,
            "body": args.body_file.resolve().read_text(encoding="utf-8"),
        }
    if args.command == "pr-read":
        return "pull_request.read", {"number": args.number}
    if args.command == "checks":
        return "checks.read", {"sha": args.sha}
    if args.command == "threads":
        return "review_threads.read", {"number": args.number}
    if args.command == "pr-close":
        return "pull_request.merge_or_close", {
            "number": args.number,
            "action": "close",
        }
    if args.command == "pr-merge":
        workspace = args.workspace.resolve()
        manifest = args.evidence_manifest.resolve()
        policy_file = args.policy_file.resolve()
        relative = manifest.relative_to(workspace)
        return "pull_request.merge_or_close", {
            "number": args.number,
            "action": "merge",
            "expected_head_sha": args.expected_head_sha,
            "merge_method": "squash",
            "workspace": str(workspace),
            "evidence_manifest": relative.as_posix(),
            "evidence_manifest_digest": sha256(manifest.read_bytes()).hexdigest(),
            "policy_digest": sha256(policy_file.read_bytes()).hexdigest(),
        }
    raise ValueError("unsupported typed operation")


def main() -> int:
    args = _parser().parse_args()
    operation, payload = _request(args)
    request_id = args.request_id or f"CODEX-{secrets.token_hex(20)}"
    receipt = BrokerClient(args.socket).execute(
        BrokerRequest(
            request_id=request_id,
            operation=operation,
            owner=args.owner,
            repository=args.repository,
            payload=payload,
        )
    )
    print(json.dumps(receipt.as_dict(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
