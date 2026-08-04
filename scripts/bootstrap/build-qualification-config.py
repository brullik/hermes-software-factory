#!/usr/bin/env python3
"""Create the root-owned path/digest contract for the independent verifier."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SHA40 = re.compile(r"^[a-f0-9]{40}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--governor-database", type=Path, required=True)
    parser.add_argument("--candidate-repository-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--shadow-journal-root", type=Path, required=True)
    parser.add_argument("--shadow-feed-root", type=Path, required=True)
    parser.add_argument("--candidate-shadow-output-root", type=Path, required=True)
    parser.add_argument("--stable-release-root", type=Path, required=True)
    parser.add_argument("--candidate-database", type=Path, required=True)
    parser.add_argument("--q6-capability-attestation-path", type=Path, required=True)
    parser.add_argument("--q6-capability-attestation-digest", required=True)
    parser.add_argument("--manifest-request-path", type=Path, required=True)
    parser.add_argument("--signed-manifest-path", type=Path, required=True)
    parser.add_argument("--verifier-private-key-path", type=Path, required=True)
    parser.add_argument("--manifest-install-root", type=Path, required=True)
    parser.add_argument("--canary-catalog-path", type=Path, required=True)
    parser.add_argument("--canary-config-index", type=Path, required=True)
    parser.add_argument("--resilience-proof-index", type=Path, required=True)
    parser.add_argument("--promotion-receipt-path", type=Path, required=True)
    parser.add_argument("--production-observation-path", type=Path, required=True)
    parser.add_argument("--production-rollback-path", type=Path, required=True)
    parser.add_argument("--factory-repository", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--stable-release-digest", required=True)
    parser.add_argument("--controller-release-digest", required=True)
    parser.add_argument("--candidate-digest", required=True)
    parser.add_argument("--policy-digest", required=True)
    parser.add_argument("--toolchain-manifest-digest", required=True)
    parser.add_argument("--trusted-verifier-public-key-digest", required=True)
    parser.add_argument("--verifier-digest", required=True)
    parser.add_argument("--verifier-public-key", required=True)
    args = parser.parse_args()
    paths = (
        args.output,
        args.governor_database,
        args.candidate_repository_root,
        args.evidence_root,
        args.shadow_journal_root,
        args.shadow_feed_root,
        args.candidate_shadow_output_root,
        args.stable_release_root,
        args.candidate_database,
        args.q6_capability_attestation_path,
        args.manifest_request_path,
        args.signed_manifest_path,
        args.verifier_private_key_path,
        args.manifest_install_root,
        args.canary_catalog_path,
        args.canary_config_index,
        args.resilience_proof_index,
        args.promotion_receipt_path,
        args.production_observation_path,
        args.production_rollback_path,
    )
    if not all(path.is_absolute() for path in paths):
        raise ValueError("qualification config paths must be absolute")
    if not _SHA40.fullmatch(args.source_commit):
        raise ValueError("source commit is invalid")
    if not _REPOSITORY.fullmatch(args.factory_repository):
        raise ValueError("factory repository is invalid")
    digests = {
        "stable_release_digest": args.stable_release_digest,
        "controller_release_digest": args.controller_release_digest,
        "candidate_digest": args.candidate_digest,
        "policy_digest": args.policy_digest,
        "toolchain_manifest_digest": args.toolchain_manifest_digest,
        "trusted_verifier_public_key_digest": args.trusted_verifier_public_key_digest,
        "verifier_digest": args.verifier_digest,
        "q6_capability_attestation_digest": args.q6_capability_attestation_digest,
    }
    if any(_SHA256.fullmatch(value) is None for value in digests.values()):
        raise ValueError("qualification digest is invalid")
    payload = {
        "schema_version": "1.0",
        "governor_database": str(args.governor_database),
        "candidate_repository_root": str(args.candidate_repository_root),
        "evidence_root": str(args.evidence_root),
        "shadow_journal_root": str(args.shadow_journal_root),
        "shadow_feed_root": str(args.shadow_feed_root),
        "candidate_shadow_output_root": str(args.candidate_shadow_output_root),
        "stable_release_root": str(args.stable_release_root),
        "candidate_database": str(args.candidate_database),
        "q6_capability_attestation_path": str(args.q6_capability_attestation_path),
        "manifest_request_path": str(args.manifest_request_path),
        "signed_manifest_path": str(args.signed_manifest_path),
        "verifier_private_key_path": str(args.verifier_private_key_path),
        "manifest_install_root": str(args.manifest_install_root),
        "canary_catalog_path": str(args.canary_catalog_path),
        "canary_config_index": str(args.canary_config_index),
        "resilience_proof_index": str(args.resilience_proof_index),
        "promotion_receipt_path": str(args.promotion_receipt_path),
        "production_observation_path": str(args.production_observation_path),
        "production_rollback_path": str(args.production_rollback_path),
        "factory_repository": args.factory_repository,
        "source_commit": args.source_commit,
        **digests,
        "verifier_public_key": args.verifier_public_key,
    }
    encoded = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    if args.output.exists():
        if args.output.is_symlink() or args.output.read_text(encoding="utf-8") != encoded:
            raise ValueError("qualification config already exists with different content")
        return 0
    args.output.write_text(encoded, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
