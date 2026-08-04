#!/usr/bin/env python3
"""Create the root-owned signing/install contract for one release epoch."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SHA40 = re.compile(r"^[a-f0-9]{40}$")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--request-path", type=Path, required=True)
    parser.add_argument("--signed-output-path", type=Path, required=True)
    parser.add_argument("--private-key-path", type=Path, required=True)
    parser.add_argument("--manifest-install-root", type=Path, required=True)
    parser.add_argument("--trusted-public-key-digest", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-candidate-digest", required=True)
    parser.add_argument("--verifier-digest", required=True)
    args = parser.parse_args()
    paths = (
        args.output,
        args.request_path,
        args.signed_output_path,
        args.private_key_path,
        args.manifest_install_root,
    )
    if not all(path.is_absolute() for path in paths):
        raise ValueError("verifier config paths must be absolute")
    if not _SHA40.fullmatch(args.expected_source_commit):
        raise ValueError("verifier source commit is invalid")
    if any(
        _SHA256.fullmatch(value) is None
        for value in (
            args.trusted_public_key_digest,
            args.expected_candidate_digest,
            args.verifier_digest,
        )
    ):
        raise ValueError("verifier digest is invalid")
    payload = {
        "schema_version": "1.0",
        "request_path": str(args.request_path),
        "output_path": str(args.signed_output_path),
        "private_key_path": str(args.private_key_path),
        "trusted_public_key_digest": args.trusted_public_key_digest,
        "expected_source_commit": args.expected_source_commit,
        "expected_candidate_digest": args.expected_candidate_digest,
        "verifier_digest": args.verifier_digest,
        "manifest_install_root": str(args.manifest_install_root),
    }
    encoded = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    if args.output.exists():
        if args.output.is_symlink() or args.output.read_text(encoding="utf-8") != encoded:
            raise ValueError("verifier config already exists with different content")
        return 0
    args.output.write_text(encoded, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
