"""Root-observed 24-hour production health journal and automatic LTS rollback."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

from .common import sha256_text, stable_json, utc_now
from .release_executor import _release_digest


class ProductionObservationError(RuntimeError):
    """Production observation cannot prove a safe continuation."""


SERVICES = (
    "hermes-factory-controller.service",
    "hermes-factory-gateway.service",
    "hermes-factory-worker.service",
)
OPTIONAL_SERVICES = ("hermes-factory-worker-2.service",)


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ProductionObservationError("observation timestamp is invalid") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _run(arguments: list[str]) -> None:
    result = subprocess.run(
        arguments,
        text=True,
        capture_output=True,
        check=False,
        timeout=180,
    )
    if result.returncode != 0:
        raise ProductionObservationError(f"allowlisted command failed: {arguments[0]}")


def _health() -> bool:
    try:
        with urlopen("http://127.0.0.1:8787/healthz", timeout=5) as response:
            status = getattr(response, "status", None)
            return isinstance(status, int) and 200 <= status < 400
    except (OSError, URLError, TimeoutError):
        return False


def _active_services() -> tuple[bool, list[str]]:
    observed: list[str] = []
    required = list(SERVICES)
    required.extend(
        service
        for service in OPTIONAL_SERVICES
        if (Path("/etc/systemd/system") / service).is_file()
    )
    for service in required:
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", service],
            capture_output=True,
            check=False,
            timeout=30,
        )
        if result.returncode == 0:
            observed.append(service)
    return len(observed) == len(required), observed


def _database_metrics(database: Path, promoted_at: str) -> tuple[str, int]:
    connection = sqlite3.connect(
        f"file:{database.resolve().as_posix()}?mode=ro", uri=True, timeout=30
    )
    try:
        connection.execute("PRAGMA query_only=ON")
        integrity = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        incidents = int(
            connection.execute(
                "SELECT COUNT(*) FROM controller_incidents WHERE created_at>=?",
                (promoted_at,),
            ).fetchone()[0]
        )
    finally:
        connection.close()
    return integrity, incidents


def _journal_entries(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if not path.is_file() or path.is_symlink():
        raise ProductionObservationError("production observation journal is unsafe")
    entries: list[dict[str, Any]] = []
    prior = "0" * 64
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as error:
            raise ProductionObservationError("production journal is unreadable") from error
        if not isinstance(entry, dict):
            raise ProductionObservationError("production journal entry is invalid")
        digest = str(entry.pop("entry_digest", ""))
        if (
            entry.get("sequence") != line_number
            or entry.get("previous_digest") != prior
            or sha256_text(stable_json(entry)) != digest
        ):
            raise ProductionObservationError("production journal hash chain differs")
        entries.append({**entry, "entry_digest": digest})
        prior = digest
    return entries


def _append_entry(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    entries = _journal_entries(path)
    prior = str(entries[-1]["entry_digest"]) if entries else "0" * 64
    entry = {
        "schema_version": "1.0",
        "sequence": len(entries) + 1,
        "previous_digest": prior,
        **payload,
    }
    digest = sha256_text(stable_json(entry))
    envelope = {**entry, "entry_digest": digest}
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o400)
    with os.fdopen(descriptor, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(stable_json(envelope) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(0o400)
    return envelope


def observe_once(
    *,
    candidate_digest: str,
    promoted_at: str,
    output_path: Path,
    minimum_hours: float = 24.0,
    minimum_entries: int = 720,
    current_root: Path = Path("/opt/hermes-factory/current"),
    database: Path = Path("/var/lib/hermes-factory/controller.db"),
    health_probe: Callable[[], bool] = _health,
    services_probe: Callable[[], tuple[bool, list[str]]] = _active_services,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Append one verifier-readable observation and finalize only after 24 hours."""

    current_digest = _release_digest(current_root).removeprefix("sha256:")
    services_ok, active_services = services_probe()
    integrity, incidents = _database_metrics(database, promoted_at)
    observed_at = observed_at or utc_now()
    healthy = health_probe()
    passed = all(
        (
            current_digest == candidate_digest,
            services_ok,
            healthy,
            integrity == "ok",
            incidents == 0,
        )
    )
    journal_path = output_path.with_suffix(".journal.jsonl")
    entry = _append_entry(
        journal_path,
        {
            "observed_at": observed_at,
            "promoted_at": promoted_at,
            "candidate_digest": candidate_digest,
            "production_digest": current_digest,
            "health": "PASS" if healthy else "FAIL",
            "services_active": services_ok,
            "active_services": active_services,
            "database_quick_check": integrity,
            "controller_incidents_since_promotion": incidents,
            "status": "PASS" if passed else "FAIL",
        },
    )
    entries = _journal_entries(journal_path)
    if not passed:
        return {"status": "ROLLBACK_REQUIRED", "entry_digest": entry["entry_digest"]}
    if any(item["status"] != "PASS" for item in entries):
        raise ProductionObservationError("production journal contains a failed observation")
    observed_times = [_parse_time(str(item["observed_at"])) for item in entries]
    if any(
        (later - earlier).total_seconds() > 180
        for earlier, later in pairwise(observed_times)
    ):
        return {"status": "ROLLBACK_REQUIRED", "entry_digest": entry["entry_digest"]}
    elapsed_hours = (
        _parse_time(observed_at) - _parse_time(promoted_at)
    ).total_seconds() / 3600
    if elapsed_hours < minimum_hours or len(entries) < minimum_entries:
        return {
            "status": "OBSERVING",
            "elapsed_hours": elapsed_hours,
            "entry_count": len(entries),
        }
    payload = {
        "schema_version": "1.0",
        "proof_type": "PRODUCTION_OBSERVATION",
        "status": "PASS",
        "candidate_digest": candidate_digest,
        "promoted_at": promoted_at,
        "completed_at": observed_at,
        "elapsed_hours": elapsed_hours,
        "entry_count": len(entries),
        "journal_head_digest": str(entries[-1]["entry_digest"]),
        "controller_incidents": 0,
        "digest_divergences": 0,
        "health_failures": 0,
    }
    digest = sha256_text(stable_json(payload))
    envelope = {**payload, "proof_digest": digest}
    encoded = json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output_path.exists():
        if output_path.is_symlink() or output_path.read_text(encoding="utf-8") != encoded:
            raise ProductionObservationError("immutable production observation conflicts")
    else:
        descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    return {
        "status": "LTS_READY",
        "evidence_ref": f"artifact://production-observation/{digest}",
    }


def rollback_to_lts_a(
    *,
    release_id: str,
    expected_candidate_digest: str,
    expected_stable_digest: str,
    rollback_path: Path,
) -> str:
    """Restore source and runtime rollback targets left by the root promotion."""

    if rollback_path.is_file() and not rollback_path.is_symlink():
        try:
            existing = json.loads(rollback_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ProductionObservationError("production rollback proof is unreadable") from error
        if not isinstance(existing, dict) or not isinstance(existing.get("proof_digest"), str):
            raise ProductionObservationError("production rollback proof is invalid")
        return f"artifact://production-rollback/{existing['proof_digest']}"
    install_root = Path("/opt/hermes-factory")
    current = install_root / "current"
    previous = install_root / f"backup-{release_id}-previous"
    failed = install_root / f"failed-post-promotion-{release_id}"
    runtime_link = install_root / "venv"
    preserved_runtime = install_root / f"venv-lts-before-{release_id[:12]}"
    preserved_resolved = preserved_runtime.resolve()
    candidate_venv_root = Path("/opt/hermes-factory-candidate/venvs").resolve()
    if (
        not current.exists()
        and not current.is_symlink()
        and previous.is_dir()
        and not previous.is_symlink()
        and failed.is_dir()
        and not failed.is_symlink()
        and _release_digest(previous).removeprefix("sha256:")
        == expected_stable_digest
        and _release_digest(failed).removeprefix("sha256:")
        == expected_candidate_digest
    ):
        previous.replace(current)
    current_digest = _release_digest(current).removeprefix("sha256:")
    if (
        not preserved_runtime.is_dir()
        or (
            preserved_runtime.is_symlink()
            and preserved_resolved.parent != candidate_venv_root
        )
    ):
        raise ProductionObservationError("rollback target is unavailable or ambiguous")
    installed_optional = [
        service
        for service in OPTIONAL_SERVICES
        if (Path("/etc/systemd/system") / service).is_file()
    ]
    reconciliation = "executed"
    if current_digest == expected_candidate_digest:
        if (
            not previous.is_dir()
            or previous.is_symlink()
            or _release_digest(previous).removeprefix("sha256:")
            != expected_stable_digest
            or failed.exists()
            or failed.is_symlink()
        ):
            raise ProductionObservationError("rollback source target is unavailable")
    elif current_digest == expected_stable_digest:
        if (
            not failed.is_dir()
            or failed.is_symlink()
            or _release_digest(failed).removeprefix("sha256:")
            != expected_candidate_digest
        ):
            raise ProductionObservationError("interrupted rollback cannot be reconciled")
        reconciliation = "verified_postcondition"
    else:
        raise ProductionObservationError("rollback current tree differs from both releases")
    _run(["systemctl", "stop", *SERVICES, *installed_optional])
    if current_digest == expected_candidate_digest:
        current.replace(failed)
        previous.replace(current)
    temporary_link = install_root / f".venv-rollback-{release_id[:12]}"
    if temporary_link.exists() or temporary_link.is_symlink():
        if not temporary_link.is_symlink() or temporary_link.resolve() != preserved_resolved:
            raise ProductionObservationError("rollback runtime temporary link conflicts")
    else:
        temporary_link.symlink_to(preserved_runtime, target_is_directory=True)
    temporary_link.replace(runtime_link)
    _run(["systemctl", "restart", *SERVICES, *installed_optional])
    restored_digest = _release_digest(current).removeprefix("sha256:")
    restored_health = _health()
    if restored_digest != expected_stable_digest or not restored_health:
        raise ProductionObservationError("Stable A rollback postcondition failed")
    payload = {
        "schema_version": "1.0",
        "proof_type": "PRODUCTION_ROLLBACK",
        "status": "PASS",
        "release_id": release_id,
        "candidate_digest": expected_candidate_digest,
        "stable_release_digest": expected_stable_digest,
        "restored_release_digest": restored_digest,
        "stable_health": "PASS",
        "failed_candidate_path": str(failed),
        "reconciliation": reconciliation,
        "created_at": utc_now(),
    }
    digest = sha256_text(stable_json(payload))
    envelope = {**payload, "proof_digest": digest}
    rollback_path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    descriptor = os.open(rollback_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    return f"artifact://production-rollback/{digest}"
