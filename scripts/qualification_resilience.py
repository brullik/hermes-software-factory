#!/usr/bin/env python3
"""Create the real local-Restic backup/restore and rollback qualification proofs."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from factory.common import stable_json
from factory.resilience_qualification import (
    ResilienceQualificationError,
    build_resilience_proofs,
    online_sqlite_backup,
)
from scripts.qualification_control import _load_config

_SNAPSHOT_ID = re.compile(r"^[A-Fa-f0-9]{8,64}$")


def _run_restic(arguments: list[str], *, repository: Path, password_file: Path) -> str:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"),
        "RESTIC_REPOSITORY": str(repository),
        "RESTIC_PASSWORD_FILE": str(password_file),
    }
    result = subprocess.run(
        ["restic", *arguments],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=1800,
    )
    if result.returncode != 0:
        raise ResilienceQualificationError(f"Restic command failed: {arguments[0]}")
    return result.stdout


def _snapshot_id(value: str) -> str:
    try:
        rows: Any = json.loads(value)
    except json.JSONDecodeError as error:
        raise ResilienceQualificationError("Restic snapshot result is unreadable") from error
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise ResilienceQualificationError("Restic snapshot result is ambiguous")
    snapshot = str(rows[0].get("short_id") or rows[0].get("id") or "")
    if not _SNAPSHOT_ID.fullmatch(snapshot):
        raise ResilienceQualificationError("Restic snapshot identity is invalid")
    return snapshot


def run(config_path: Path, repository: Path, password_file: Path) -> dict[str, Any]:
    if os.name != "nt" and getattr(os, "geteuid", lambda: -1)() != 0:
        raise ResilienceQualificationError("resilience qualification requires root")
    config = _load_config(config_path)
    if not repository.is_absolute() or repository.is_symlink():
        raise ResilienceQualificationError("Restic repository path is unsafe")
    if not password_file.is_absolute() or not password_file.is_file() or password_file.is_symlink():
        raise ResilienceQualificationError("Restic password file is unsafe")
    if os.name != "nt":
        metadata = password_file.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise ResilienceQualificationError("Restic password file is not root-private")
    index_path = Path(str(config["resilience_proof_index"]))
    if index_path.exists():
        payload = json.loads(index_path.read_text(encoding="utf-8"))
        return {"status": "PASS", "reconciliation": "existing", **payload}
    attempt_root = index_path.parent / f"attempt-{uuid.uuid4().hex}"
    input_root = attempt_root / "input"
    restore_root = attempt_root / "restore"
    input_root.mkdir(parents=True, exist_ok=False)
    source_observation = online_sqlite_backup(
        Path("/var/lib/hermes-factory/controller.db"),
        input_root / "controller.db",
    )
    tag = f"hermes-qualification-{config['source_commit']}"
    _run_restic(["backup", str(input_root), "--tag", tag], repository=repository, password_file=password_file)
    _run_restic(["check", "--read-data"], repository=repository, password_file=password_file)
    snapshot = _snapshot_id(
        _run_restic(
            ["snapshots", "--latest", "1", "--tag", tag, "--json"],
            repository=repository,
            password_file=password_file,
        )
    )
    _run_restic(["restore", snapshot, "--target", str(restore_root)], repository=repository, password_file=password_file)
    restored_input = restore_root / input_root.resolve().relative_to(input_root.anchor)
    bundle = build_resilience_proofs(
        source_observation=source_observation,
        restored_database=restored_input / "controller.db",
        stable_root=Path(str(config["stable_release_root"])),
        candidate_root=Path(str(config["candidate_repository_root"])),
        expected_stable_digest=str(config["stable_release_digest"]),
        expected_candidate_digest=str(config["candidate_digest"]),
        source_commit=str(config["source_commit"]),
        restic_snapshot_id=snapshot,
        evidence_root=index_path.parent / "evidence",
        index_path=index_path,
    )
    return {"status": "PASS", "reconciliation": "executed", **bundle.__dict__}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/hermes-factory/qualification-control.yaml"),
    )
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path("/var/lib/hermes-factory-qualification-backup/repository"),
    )
    parser.add_argument(
        "--password-file",
        type=Path,
        default=Path("/etc/hermes-factory/qualification-backup-password"),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = run(args.config, args.repository, args.password_file)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, ResilienceQualificationError) as error:
        print(stable_json({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    print(stable_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
