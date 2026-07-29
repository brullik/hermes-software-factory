from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def load_due_module() -> ModuleType:
    path = ROOT / "scripts" / "backup" / "offsite-backup-due.py"
    spec = importlib.util.spec_from_file_location("offsite_backup_due", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_proof(path: Path, *, completed_at: datetime, kind: str = "offsite") -> None:
    path.write_text(
        json.dumps(
            {
                "status": "PASS",
                "restic_check": "PASS",
                "repository_kind": kind,
                "snapshot_id": "a" * 64,
                "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            }
        ),
        encoding="utf-8",
    )


def test_offsite_retry_skips_only_fresh_valid_offsite_proof(tmp_path: Path) -> None:
    module = load_due_module()
    proof = tmp_path / "proof.json"
    now = datetime(2026, 7, 29, 15, 0, tzinfo=UTC)

    write_proof(proof, completed_at=now - timedelta(hours=1))
    assert module.proof_is_fresh(proof, max_age_seconds=18 * 60 * 60, now=now)

    write_proof(proof, completed_at=now - timedelta(hours=19))
    assert not module.proof_is_fresh(proof, max_age_seconds=18 * 60 * 60, now=now)

    write_proof(proof, completed_at=now - timedelta(hours=1), kind="local")
    assert not module.proof_is_fresh(proof, max_age_seconds=18 * 60 * 60, now=now)

    write_proof(proof, completed_at=now + timedelta(minutes=1))
    assert not module.proof_is_fresh(proof, max_age_seconds=18 * 60 * 60, now=now)


def test_backup_runner_serializes_and_uses_stable_input_and_configurable_proof() -> None:
    runner = (ROOT / "scripts" / "backup" / "run-backup.sh").read_text(
        encoding="utf-8"
    )
    assert 'exec 9>"$LOCK_FILE"' in runner
    assert "flock -n 9" in runner
    assert "restic unlock" in runner
    assert '"$INPUT_DIR/controller.db.next"' in runner
    assert '"$INPUT_DIR"' in runner
    assert '--proof "$PROOF_PATH"' in runner
    assert '"$TMP_DIR"\n  "$STATE_DIR/evidence"' not in runner


def test_local_and_offsite_services_keep_proofs_and_credentials_separate() -> None:
    local_unit = (
        ROOT / "config" / "systemd" / "hermes-factory-backup.service"
    ).read_text(encoding="utf-8")
    offsite_unit = (
        ROOT / "config" / "systemd" / "hermes-factory-backup-offsite.service"
    ).read_text(encoding="utf-8")
    offsite_timer = (
        ROOT / "config" / "systemd" / "hermes-factory-backup-offsite.timer"
    ).read_text(encoding="utf-8")

    assert "backup-local-latest.json" in local_unit
    assert "/etc/hermes-factory/backup.env" in local_unit
    assert "backup-latest.json" in offsite_unit
    assert "/etc/hermes-factory/credentials.d/backup-offsite.env" in offsite_unit
    assert "run-offsite-backup.sh" in offsite_unit
    assert "OnUnitInactiveSec=2h" in offsite_timer
