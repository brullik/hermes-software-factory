#!/usr/bin/env python3
"""Write a sanitized, atomic proof for a successful offsite restic run."""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def repository_kind(value: str) -> str:
    normalized = value.strip().lower()
    if re.match(r"^(s3|b2|azure|gs|rest|rclone|swift):", normalized):
        return "offsite"
    return "local"


def latest_snapshot(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, list) or not payload:
        raise ValueError("restic snapshot proof is empty")
    snapshots = [item for item in payload if isinstance(item, dict)]
    if not snapshots:
        raise ValueError("restic snapshot proof is invalid")
    return max(snapshots, key=lambda item: str(item.get("time") or ""))


def write_proof(snapshots_path: Path, proof_path: Path) -> None:
    snapshots = json.loads(snapshots_path.read_text(encoding="utf-8"))
    snapshot = latest_snapshot(snapshots)
    snapshot_id = str(snapshot.get("id") or snapshot.get("short_id") or "")
    if not re.fullmatch(r"[a-f0-9]{8,64}", snapshot_id):
        raise ValueError("restic snapshot identity is invalid")
    proof = {
        "schema_version": "1.0",
        "status": "PASS",
        "restic_check": "PASS",
        "repository_kind": repository_kind(
            os.environ.get("RESTIC_REPOSITORY", "")
        ),
        "snapshot_id": snapshot_id,
        "snapshot_time": str(snapshot.get("time") or ""),
        "completed_at": datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }
    proof_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = proof_path.with_suffix(proof_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(proof, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.chmod(temporary, 0o644)
    os.replace(temporary, proof_path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshots-json", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    args = parser.parse_args()
    write_proof(args.snapshots_json, args.proof)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
