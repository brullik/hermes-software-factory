#!/usr/bin/env python3
"""Run the Candidate-scoped GitHub credential broker."""

from __future__ import annotations

import argparse
import os
from hashlib import sha256
from pathlib import Path

from factory.credential_broker import (
    CORE_TASK_BRANCH_PATTERN,
    GITHUB_BROKER_OPERATIONS,
    BrokerPolicy,
    BrokerServer,
    GitHubCredentialBroker,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--repository-prefix", action="append", default=[])
    parser.add_argument("--repository", action="append", default=[])
    parser.add_argument("--operation", action="append", default=[])
    parser.add_argument("--workspace-root", action="append", type=Path, required=True)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--receipt-root", type=Path, required=True)
    parser.add_argument("--credential-epoch")
    parser.add_argument("--credential-epoch-file", type=Path)
    parser.add_argument("--credential", type=Path)
    parser.add_argument("--askpass", type=Path, required=True)
    parser.add_argument("--strict-merge-contract", action="store_true")
    parser.add_argument("--base-branch", default="main")
    parser.add_argument("--task-branch-pattern")
    parser.add_argument("--required-check", action="append", default=[])
    parser.add_argument("--policy-file", type=Path)
    parser.add_argument("--deny-delete", action="store_true")
    parser.add_argument("--deny-archive", action="store_true")
    parser.add_argument("--deny-merge", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    credential_directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
    credential = args.credential or Path(credential_directory) / "github-token"
    credential_epoch = args.credential_epoch
    if args.credential_epoch_file is not None:
        credential_epoch = args.credential_epoch_file.read_text(encoding="ascii").strip()
    if not credential_epoch:
        raise ValueError("credential epoch is required")
    policy_digest = None
    if args.policy_file is not None:
        if not args.policy_file.is_file() or args.policy_file.is_symlink():
            raise ValueError("policy file must be a regular non-symlink file")
        policy_digest = sha256(args.policy_file.read_bytes()).hexdigest()
    broker = GitHubCredentialBroker(
        policy=BrokerPolicy(
            owner=args.owner,
            repository_prefixes=tuple(args.repository_prefix),
            repository_names=tuple(args.repository),
            workspace_roots=tuple(args.workspace_root),
            allow_delete=not args.deny_delete,
            allow_archive=not args.deny_archive,
            allow_merge=not args.deny_merge,
            allowed_operations=(
                frozenset(args.operation)
                if args.operation
                else GITHUB_BROKER_OPERATIONS
            ),
            strict_merge_contract=args.strict_merge_contract,
            base_branch=args.base_branch,
            task_branch_pattern=(
                args.task_branch_pattern or CORE_TASK_BRANCH_PATTERN
            ),
            required_checks=tuple(args.required_check),
            policy_digest=policy_digest,
        ),
        credential_path=credential,
        receipt_root=args.receipt_root,
        credential_epoch_id=credential_epoch,
        askpass_path=args.askpass,
    )
    BrokerServer(socket_path=args.socket, broker=broker).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
