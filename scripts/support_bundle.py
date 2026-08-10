#!/usr/bin/env python3
"""Generate and enqueue a sanitized support bundle for one incident."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from factory.common import sha256_file, sha256_text
from factory.notifications import NotificationOutbox, NotificationRequest
from factory.support_bundle import SupportBundleError, build_support_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("incident_id")
    parser.add_argument("--source", action="append", type=Path, default=[])
    args = parser.parse_args(argv)
    functional_root = Path("/var/lib/hermes-factory-functional")
    verifier_root = Path("/var/lib/hermes-factory-verifier")
    pre_q8_state_root = Path("/var/lib/hermes-factory-pre-q8")
    pre_q8_log_root = Path("/var/log/hermes-factory-pre-q8")
    try:
        bundle, digest = build_support_bundle(
            incident_id=args.incident_id,
            source_files=tuple(args.source),
            allowed_roots=(
                functional_root,
                verifier_root,
                pre_q8_state_root,
                pre_q8_log_root,
            ),
            output_root=functional_root / "support-bundles",
            metadata={"status": "ASSISTANCE_REQUIRED_GPT_CODEX"},
        )
        request_id = "SUPPORT-" + sha256_text(args.incident_id)[:32]
        NotificationOutbox(
            functional_root / "notifications",
            attachment_roots=(functional_root, verifier_root),
        ).enqueue(
            NotificationRequest(
                request_id=request_id,
                kind="ASSISTANCE_REQUIRED_GPT_CODEX",
                text=f"Sanitized support bundle is ready for incident {args.incident_id}.",
                document_path=str(bundle),
                document_digest=sha256_file(bundle),
            )
        )
    except (OSError, ValueError, SupportBundleError) as error:
        print(json.dumps({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    print(json.dumps({"status": "PASS", "bundle": str(bundle), "digest": digest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
