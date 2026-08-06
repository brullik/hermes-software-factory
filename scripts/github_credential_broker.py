#!/usr/bin/env python3
"""Run the Candidate-scoped GitHub credential broker."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from factory.credential_broker import (
    BrokerPolicy,
    BrokerServer,
    GitHubCredentialBroker,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--repository-prefix", action="append", required=True)
    parser.add_argument("--repository", action="append", default=[])
    parser.add_argument("--workspace-root", action="append", type=Path, required=True)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--receipt-root", type=Path, required=True)
    parser.add_argument("--credential-epoch")
    parser.add_argument("--credential-epoch-file", type=Path)
    parser.add_argument("--credential", type=Path)
    parser.add_argument("--askpass", type=Path, required=True)
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
    broker = GitHubCredentialBroker(
        policy=BrokerPolicy(
            owner=args.owner,
            repository_prefixes=tuple(args.repository_prefix),
            repository_names=tuple(args.repository),
            workspace_roots=tuple(args.workspace_root),
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
