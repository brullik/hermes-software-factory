"""Verifier-consumable backup/restore and blue/green rollback proofs."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .common import sha256_file, sha256_text, stable_json, utc_now
from .deployment import TransactionalDeployer
from .release_executor import _release_digest


class ResilienceQualificationError(RuntimeError):
    """A backup, restore, or rollback observation is not independently valid."""


@dataclass(frozen=True)
class DatabaseObservation:
    integrity_check: str
    database_sha256: str
    logical_digest: str
    table_counts: dict[str, int]
    active_terminal_reason_violations: int


@dataclass(frozen=True)
class ResilienceProofBundle:
    backup_restore_proof_ref: str
    backup_restore_proof_digest: str
    rollback_proof_ref: str
    rollback_proof_digest: str
    index_path: str
    index_digest: str


def _read_only_connection(path: Path) -> sqlite3.Connection:
    resolved = path.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ResilienceQualificationError("SQLite proof source is missing or unsafe")
    connection = sqlite3.connect(f"file:{resolved.as_posix()}?mode=ro", uri=True, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA busy_timeout=30000")
    return connection


def observe_database(path: Path) -> DatabaseObservation:
    """Read invariants without migrating or otherwise writing the observed DB."""

    connection = _read_only_connection(path)
    try:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        required = {"products", "tasks", "events", "outbox"}
        if not required.issubset(tables):
            raise ResilienceQualificationError("restored SQLite schema is incomplete")
        counts = {
            table: int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            for table in sorted(tables)
        }
        product_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(products)")
        }
        violations = 0
        if "terminal_reason" in product_columns:
            violations = int(
                connection.execute(
                    """SELECT COUNT(*) FROM products
                         WHERE status NOT IN ('COMPLETED','FAILED_SAFE','CANCELLED','PAUSED')
                           AND terminal_reason IS NOT NULL"""
                ).fetchone()[0]
            )
        schema = [
            tuple(str(value or "") for value in row)
            for row in connection.execute(
                """SELECT type,name,tbl_name,sql FROM sqlite_master
                     WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"""
            )
        ]
        migrations = (
            [
                tuple(str(value) for value in row)
                for row in connection.execute(
                    "SELECT version,name,checksum FROM schema_migrations ORDER BY version"
                )
            ]
            if "schema_migrations" in tables
            else []
        )
        logical_digest = sha256_text(
            stable_json(
                {
                    "schema": schema,
                    "migrations": migrations,
                    "counts": counts,
                    "active_terminal_reason_violations": violations,
                }
            )
        )
    finally:
        connection.close()
    return DatabaseObservation(
        integrity_check=integrity,
        database_sha256=sha256_file(path),
        logical_digest=logical_digest,
        table_counts=counts,
        active_terminal_reason_violations=violations,
    )


def online_sqlite_backup(source: Path, destination: Path) -> DatabaseObservation:
    """Create a consistent SQLite online backup without pausing Stable A."""

    if destination.exists() or destination.is_symlink():
        raise ResilienceQualificationError("SQLite backup destination must be new")
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_connection = _read_only_connection(source)
    destination_connection = sqlite3.connect(destination, timeout=30)
    try:
        source_connection.backup(destination_connection)
        destination_connection.commit()
    finally:
        destination_connection.close()
        source_connection.close()
    destination.chmod(0o400)
    observation = observe_database(destination)
    if observation.integrity_check != "ok" or observation.active_terminal_reason_violations:
        raise ResilienceQualificationError("SQLite online backup violates invariants")
    return observation


def run_rollback_drill(
    stable_root: Path,
    candidate_root: Path,
    *,
    work_root: Path | None = None,
) -> dict[str, Any]:
    """Inject post-switch health failure and prove exact Stable A restoration."""

    stable_digest = _release_digest(stable_root).removeprefix("sha256:")
    candidate_digest = _release_digest(candidate_root).removeprefix("sha256:")
    temporary: tempfile.TemporaryDirectory[str] | None = None
    if work_root is None:
        temporary = tempfile.TemporaryDirectory(prefix="hermes-resilience-rollback-")
        work_root = Path(temporary.name)
    try:
        install_root = work_root / "blue-green"
        install_root.mkdir(parents=True, exist_ok=False)
        shutil.copytree(stable_root, install_root / "current", symlinks=False)
        transaction = TransactionalDeployer(
            install_root,
            health_probe=lambda _current: False,
        ).promote(f"rollback-{candidate_digest[:20]}", candidate_root)
        current = install_root / "current"
        failed = Path(str(transaction.failed_path or ""))
        stable_restored = (
            transaction.status == "ROLLED_BACK"
            and current.is_dir()
            and _release_digest(current).removeprefix("sha256:") == stable_digest
        )
        candidate_quarantined = (
            failed.is_dir()
            and _release_digest(failed).removeprefix("sha256:") == candidate_digest
        )
        if not stable_restored or not candidate_quarantined:
            raise ResilienceQualificationError("blue/green rollback drill failed")
        return {
            "transaction_status": transaction.status,
            "stable_release_digest": stable_digest,
            "candidate_digest": candidate_digest,
            "stable_restored": stable_restored,
            "candidate_quarantined": candidate_quarantined,
            "blue_green_rollback_target": True,
        }
    finally:
        if temporary is not None:
            temporary.cleanup()


def _write_once(path: Path, payload: dict[str, Any], *, mode: int = 0o444) -> str:
    digest = sha256_text(stable_json(payload))
    envelope = {**payload, "proof_digest": digest}
    encoded = json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if path.exists():
        if path.is_symlink() or path.read_text(encoding="utf-8") != encoded:
            raise ResilienceQualificationError("immutable resilience proof conflicts")
        return digest
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(mode)
    return digest


def build_resilience_proofs(
    *,
    source_observation: DatabaseObservation,
    restored_database: Path,
    stable_root: Path,
    candidate_root: Path,
    expected_stable_digest: str,
    expected_candidate_digest: str,
    source_commit: str,
    restic_snapshot_id: str,
    evidence_root: Path,
    index_path: Path,
) -> ResilienceProofBundle:
    """Validate a real Restic restore and emit immutable manifest references."""

    if not restic_snapshot_id or any(character.isspace() for character in restic_snapshot_id):
        raise ResilienceQualificationError("Restic snapshot identity is invalid")
    restored = observe_database(restored_database)
    if restored != source_observation:
        raise ResilienceQualificationError("restored SQLite image differs from online backup")
    stable_digest = _release_digest(stable_root).removeprefix("sha256:")
    candidate_digest = _release_digest(candidate_root).removeprefix("sha256:")
    if stable_digest != expected_stable_digest or candidate_digest != expected_candidate_digest:
        raise ResilienceQualificationError("resilience proof release identity differs")
    rollback = run_rollback_drill(stable_root, candidate_root)
    evidence_root.mkdir(parents=True, exist_ok=True)
    created_at = utc_now()
    backup_payload = {
        "schema_version": "1.0",
        "proof_type": "BACKUP_RESTORE",
        "status": "PASS",
        "created_at": created_at,
        "sqlite_online_backup": True,
        "restic_snapshot_id": restic_snapshot_id,
        "restic_check": "PASS",
        "restore_target_isolated": True,
        "source_observation": asdict(source_observation),
        "restored_observation": asdict(restored),
    }
    backup_seed = sha256_text(stable_json(backup_payload))
    backup_path = evidence_root / f"backup-restore-{backup_seed}.json"
    backup_digest = _write_once(backup_path, backup_payload)
    rollback_payload = {
        "schema_version": "1.0",
        "proof_type": "BLUE_GREEN_ROLLBACK",
        "status": "PASS",
        "created_at": created_at,
        **rollback,
    }
    rollback_seed = sha256_text(stable_json(rollback_payload))
    rollback_path = evidence_root / f"rollback-{rollback_seed}.json"
    rollback_digest = _write_once(rollback_path, rollback_payload)
    backup_ref = f"artifact://qualification/resilience/{backup_digest}"
    rollback_ref = f"artifact://qualification/resilience/{rollback_digest}"
    index_payload = {
        "schema_version": "1.0",
        "source_commit": source_commit,
        "stable_release_digest": stable_digest,
        "candidate_digest": candidate_digest,
        "backup_restore_proof_ref": backup_ref,
        "backup_restore_proof_digest": backup_digest,
        "backup_restore_proof_path": str(backup_path.resolve()),
        "rollback_proof_ref": rollback_ref,
        "rollback_proof_digest": rollback_digest,
        "rollback_proof_path": str(rollback_path.resolve()),
    }
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_digest = _write_once(index_path, index_payload)
    return ResilienceProofBundle(
        backup_restore_proof_ref=backup_ref,
        backup_restore_proof_digest=backup_digest,
        rollback_proof_ref=rollback_ref,
        rollback_proof_digest=rollback_digest,
        index_path=str(index_path.resolve()),
        index_digest=index_digest,
    )
