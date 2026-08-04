"""Acceptance tests for manifest-bound resilience evidence."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from factory.release_executor import _release_digest
from factory.resilience_qualification import (
    ResilienceQualificationError,
    build_resilience_proofs,
    online_sqlite_backup,
    run_rollback_drill,
)
from factory.state import StateStore


def _release(path: Path, version: str) -> Path:
    path.mkdir()
    (path / "VERSION").write_text(version + "\n", encoding="utf-8")
    (path / "factory.py").write_text(f"VERSION = {version!r}\n", encoding="utf-8")
    return path


def test_online_backup_restore_and_blue_green_rollback_are_digest_bound(
    tmp_path: Path,
) -> None:
    database = tmp_path / "controller.db"
    state = StateStore(database)
    try:
        state.create_product(
            product_id="resilience-product",
            owner_id="qualification",
            source="test",
            idea="prove exact backup and restore",
            idempotency_key="resilience-product",
        )
    finally:
        state.close()
    stable = _release(tmp_path / "stable", "2.3.10")
    candidate = _release(tmp_path / "candidate", "2.4.0")
    backup = tmp_path / "snapshot" / "controller.db"
    source_observation = online_sqlite_backup(database, backup)
    restored = tmp_path / "restore" / "controller.db"
    restored.parent.mkdir()
    shutil.copy2(backup, restored)

    rollback = run_rollback_drill(stable, candidate)
    assert rollback["transaction_status"] == "ROLLED_BACK"
    bundle = build_resilience_proofs(
        source_observation=source_observation,
        restored_database=restored,
        stable_root=stable,
        candidate_root=candidate,
        expected_stable_digest=_release_digest(stable).removeprefix("sha256:"),
        expected_candidate_digest=_release_digest(candidate).removeprefix("sha256:"),
        source_commit="a" * 40,
        restic_snapshot_id="abcdef1234567890",
        evidence_root=tmp_path / "evidence",
        index_path=tmp_path / "proof-index.json",
    )
    index = json.loads(Path(bundle.index_path).read_text(encoding="utf-8"))
    assert index["source_commit"] == "a" * 40
    assert index["backup_restore_proof_ref"].endswith(
        bundle.backup_restore_proof_digest
    )
    assert index["rollback_proof_ref"].endswith(bundle.rollback_proof_digest)


def test_restore_proof_rejects_changed_database(tmp_path: Path) -> None:
    database = tmp_path / "controller.db"
    state = StateStore(database)
    state.close()
    stable = _release(tmp_path / "stable", "stable")
    candidate = _release(tmp_path / "candidate", "candidate")
    backup = tmp_path / "backup.db"
    source_observation = online_sqlite_backup(database, backup)
    restored = tmp_path / "restored.db"
    shutil.copy2(backup, restored)
    restored.chmod(0o600)
    restored.write_bytes(restored.read_bytes() + b"tamper")

    with pytest.raises(ResilienceQualificationError, match="differs"):
        build_resilience_proofs(
            source_observation=source_observation,
            restored_database=restored,
            stable_root=stable,
            candidate_root=candidate,
            expected_stable_digest=_release_digest(stable).removeprefix("sha256:"),
            expected_candidate_digest=_release_digest(candidate).removeprefix("sha256:"),
            source_commit="b" * 40,
            restic_snapshot_id="abcdef1234567890",
            evidence_root=tmp_path / "evidence",
            index_path=tmp_path / "proof-index.json",
        )
