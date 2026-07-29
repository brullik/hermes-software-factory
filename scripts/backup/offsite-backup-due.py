#!/usr/bin/env python3
"""Return whether the fail-closed offsite backup proof needs refresh."""

from __future__ import annotations

import argparse
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def _timestamp(value: Any) -> datetime:
    parsed = datetime.fromisoformat(str(value))
    if parsed.tzinfo is None:
        raise ValueError("proof timestamp must include a timezone")
    return parsed.astimezone(UTC)


def proof_is_fresh(
    path: Path,
    *,
    max_age_seconds: int,
    now: datetime | None = None,
) -> bool:
    if max_age_seconds < 1:
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return False
        snapshot_id = str(payload.get("snapshot_id") or "")
        completed_at = _timestamp(payload["completed_at"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False
    current = (now or datetime.now(UTC)).astimezone(UTC)
    return bool(
        payload.get("status") == "PASS"
        and payload.get("restic_check") == "PASS"
        and payload.get("repository_kind") == "offsite"
        and re.fullmatch(r"[a-f0-9]{8,64}", snapshot_id)
        and timedelta(0) <= current - completed_at <= timedelta(seconds=max_age_seconds)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--max-age-seconds", type=int, required=True)
    args = parser.parse_args()
    if proof_is_fresh(args.proof, max_age_seconds=args.max_age_seconds):
        print("OFFSITE BACKUP FRESH: retry skipped.")
        return 10
    print("OFFSITE BACKUP DUE: starting refresh.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
