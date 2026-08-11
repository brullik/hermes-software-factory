"""Fail-closed run ledger and DELETE lifecycle for qualification repositories."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from .common import sha256_text, stable_json, utc_now
from .pre_q8_convergence import resource_namespace

LEDGER_STATES: Final = frozenset(
    {
        "PROVISIONED",
        "EVIDENCE_FROZEN",
        "PENDING_DELETE",
        "DELETE_REQUESTED",
        "DELETED",
        "ALREADY_ABSENT",
        "CLEANUP_FAILED",
    }
)
TERMINAL_STATES: Final = frozenset({"DELETED", "ALREADY_ABSENT"})
HISTORICAL_REPOSITORY_COUNT: Final = 39
_NAMESPACE = re.compile(r"hermes-canary-(?:convergence|preq8|q8)-[a-z0-9]+-[a-f0-9]{20}")


class QualificationRepositoryGCError(RuntimeError):
    """Repository cleanup cannot be proven safe or terminal."""


def _entry_digest(entry: Mapping[str, Any]) -> str:
    return sha256_text(
        stable_json({key: value for key, value in entry.items() if key != "entry_digest"})
    )


def _ledger_digest(ledger: Mapping[str, Any]) -> str:
    return sha256_text(
        stable_json({key: value for key, value in ledger.items() if key != "ledger_digest"})
    )


def _validate_ledger(ledger: Mapping[str, Any]) -> dict[str, Any]:
    value = {str(key): item for key, item in ledger.items()}
    entries = value.get("repositories")
    if (
        value.get("schema_version") != "1.0"
        or not isinstance(entries, list)
        or value.get("repository_count") != len(entries)
    ):
        raise QualificationRepositoryGCError("repository ledger is invalid")
    for raw in entries:
        if not isinstance(raw, Mapping):
            raise QualificationRepositoryGCError("repository ledger entry is invalid")
        entry = {str(key): item for key, item in raw.items()}
        if str(entry.get("state") or "") not in LEDGER_STATES or str(
            entry.get("entry_digest") or ""
        ) != _entry_digest(entry):
            raise QualificationRepositoryGCError("repository ledger entry digest differs")
    if str(value.get("ledger_digest") or "") != _ledger_digest(value):
        raise QualificationRepositoryGCError("repository ledger digest differs")
    return value


def load_repository_ledger(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise QualificationRepositoryGCError("repository ledger is unavailable")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QualificationRepositoryGCError("repository ledger is unreadable") from error
    if not isinstance(value, Mapping):
        raise QualificationRepositoryGCError("repository ledger is not an object")
    return _validate_ledger(value)


def _write_repository_ledger(path: Path, ledger: Mapping[str, Any]) -> dict[str, Any]:
    body = {str(key): value for key, value in ledger.items() if key != "ledger_digest"}
    body["repository_count"] = len(body.get("repositories", []))
    envelope = {**body, "ledger_digest": _ledger_digest(body)}
    _validate_ledger(envelope)
    encoded = json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return envelope


def initialize_repository_ledger(
    path: Path,
    *,
    qualification_plane: str,
    epoch_id: str,
    run_id: str,
    candidate_digest: str,
) -> dict[str, Any]:
    identity = {
        "schema_version": "1.0",
        "qualification_plane": qualification_plane.upper().replace("-", "_"),
        "epoch_id": epoch_id,
        "run_id": run_id,
        "candidate_digest": candidate_digest,
        "repositories": [],
        "repository_count": 0,
    }
    if path.exists():
        current = load_repository_ledger(path)
        for key, expected in identity.items():
            if key not in {"repositories", "repository_count"} and current.get(key) != expected:
                raise QualificationRepositoryGCError("repository ledger identity differs")
        return current
    return _write_repository_ledger(path, identity)


def record_provisioned_repository(
    path: Path,
    *,
    qualification_plane: str,
    epoch_id: str,
    run_id: str,
    scenario_id: str,
    candidate_digest: str,
    product_id: str | None,
    repository_owner: str,
    repository_name: str,
    repository_id: int | None,
    expected_description: str,
    provision_receipt_digest: str,
    database_path: str | None = None,
) -> dict[str, Any]:
    ledger = initialize_repository_ledger(
        path,
        qualification_plane=qualification_plane,
        epoch_id=epoch_id,
        run_id=run_id,
        candidate_digest=candidate_digest,
    )
    entry_id = (
        "QRG-"
        + sha256_text(
            stable_json(
                [
                    qualification_plane.upper().replace("-", "_"),
                    epoch_id,
                    run_id,
                    scenario_id,
                    candidate_digest,
                    product_id,
                    repository_owner,
                    repository_name,
                ]
            )
        )[:24].upper()
    )
    entry: dict[str, Any] = {
        "entry_id": entry_id,
        "qualification_plane": qualification_plane.upper().replace("-", "_"),
        "epoch_id": epoch_id,
        "run_id": run_id,
        "scenario_id": scenario_id,
        "candidate_digest": candidate_digest,
        "product_id": product_id,
        "repository_owner": repository_owner,
        "repository_name": repository_name,
        "repository_id": repository_id,
        "expected_description": expected_description,
        "repository_visibility": "private",
        "provision_receipt_digest": provision_receipt_digest,
        "database_path": database_path,
        "evidence_status": "PENDING",
        "state": "PROVISIONED",
        "cleanup_receipt": None,
        "updated_at": utc_now(),
    }
    entry["entry_digest"] = _entry_digest(entry)
    entries = [dict(item) for item in ledger["repositories"]]
    existing = next((item for item in entries if item.get("entry_id") == entry_id), None)
    if existing is not None:
        immutable = {
            key: value
            for key, value in entry.items()
            if key
            not in {"state", "evidence_status", "cleanup_receipt", "updated_at", "entry_digest"}
        }
        if any(existing.get(key) != value for key, value in immutable.items()):
            raise QualificationRepositoryGCError("repository ledger replay conflicts")
        return existing
    entries.append(entry)
    ledger["repositories"] = sorted(entries, key=lambda item: str(item["entry_id"]))
    return next(
        item
        for item in _write_repository_ledger(path, ledger)["repositories"]
        if item["entry_id"] == entry_id
    )


def mark_scenario_evidence_frozen(path: Path, scenario_id: str) -> int:
    ledger = load_repository_ledger(path)
    changed = 0
    entries = []
    for raw in ledger["repositories"]:
        entry = dict(raw)
        if entry.get("scenario_id") == scenario_id and entry.get("state") == "PROVISIONED":
            entry["evidence_status"] = "FROZEN"
            entry["state"] = "EVIDENCE_FROZEN"
            entry["updated_at"] = utc_now()
            entry["entry_digest"] = _entry_digest(entry)
            changed += 1
        entries.append(entry)
    ledger["repositories"] = entries
    _write_repository_ledger(path, ledger)
    return changed


def verify_repository_cleanup_eligibility(
    entry: Mapping[str, Any],
    live_repository: Mapping[str, Any] | None,
    *,
    run_active: bool,
    permanent_allowlist: Sequence[str] = (),
) -> tuple[bool, str]:
    """Verify every exact DELETE precondition; unknown repositories are report-only."""

    name = str(entry.get("repository_name") or "")
    owner = str(entry.get("repository_owner") or "")
    plane = str(entry.get("qualification_plane") or "").lower().replace("_", "-")
    expected = resource_namespace(
        plane=plane,
        run_id=str(entry.get("run_id") or ""),
        candidate_digest=str(entry.get("candidate_digest") or ""),
        scenario_id=str(entry.get("scenario_id") or ""),
    )
    if run_active:
        return False, "run_is_active"
    if entry.get("evidence_status") != "FROZEN" or entry.get("state") not in {
        "EVIDENCE_FROZEN",
        "PENDING_DELETE",
        "DELETE_REQUESTED",
    }:
        return False, "evidence_not_frozen"
    if not owner or name in set(permanent_allowlist):
        return False, "repository_is_permanent_or_owner_missing"
    if _NAMESPACE.fullmatch(name) is None or name != expected:
        return False, "namespace_recomputation_differs"
    if live_repository is None:
        return True, "already_absent"
    live_owner = live_repository.get("owner")
    if (
        live_repository.get("name") != name
        or live_repository.get("private") is not True
        or live_repository.get("fork") is True
        or not isinstance(live_owner, Mapping)
        or str(live_owner.get("login") or "") != owner
    ):
        return False, "live_repository_identity_differs"
    expected_id = entry.get("repository_id")
    if expected_id is not None and live_repository.get("id") != expected_id:
        return False, "repository_id_differs"
    if str(live_repository.get("description") or "") != str(
        entry.get("expected_description") or ""
    ):
        return False, "repository_description_differs"
    return True, "eligible"


def update_repository_cleanup_state(
    path: Path,
    entry_id: str,
    *,
    state: str,
    cleanup_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if state not in LEDGER_STATES:
        raise QualificationRepositoryGCError("repository cleanup state is invalid")
    ledger = load_repository_ledger(path)
    found = False
    result: dict[str, Any] | None = None
    entries = []
    for raw in ledger["repositories"]:
        entry = dict(raw)
        if entry.get("entry_id") == entry_id:
            found = True
            if entry.get("state") in TERMINAL_STATES and entry.get("state") != state:
                raise QualificationRepositoryGCError(
                    "terminal repository cleanup receipt conflicts"
                )
            entry["state"] = state
            entry["cleanup_receipt"] = (
                dict(cleanup_receipt) if cleanup_receipt is not None else None
            )
            entry["updated_at"] = utc_now()
            entry["entry_digest"] = _entry_digest(entry)
            result = entry
        entries.append(entry)
    if not found or result is None:
        raise QualificationRepositoryGCError("repository ledger entry is missing")
    ledger["repositories"] = entries
    _write_repository_ledger(path, ledger)
    return result


def qualification_repository_cleanup_plan(
    ledger: Path | Mapping[str, Any], *, run_active: bool = False
) -> dict[str, Any]:
    value = load_repository_ledger(ledger) if isinstance(ledger, Path) else _validate_ledger(ledger)
    planned = [
        dict(entry)
        for entry in value["repositories"]
        if not run_active
        and entry.get("state") in {"EVIDENCE_FROZEN", "PENDING_DELETE", "DELETE_REQUESTED"}
    ]
    return {
        "schema_version": "1.0",
        "run_id": value["run_id"],
        "planned_count": len(planned),
        "entries": planned,
    }


def repository_cleanup_summary(ledger: Path | Mapping[str, Any]) -> dict[str, Any]:
    value = load_repository_ledger(ledger) if isinstance(ledger, Path) else _validate_ledger(ledger)
    entries = [dict(item) for item in value["repositories"]]
    residue = [item for item in entries if item.get("state") not in TERMINAL_STATES]
    failed = [item for item in entries if item.get("state") == "CLEANUP_FAILED"]
    return {
        "schema_version": "1.0",
        "run_id": value["run_id"],
        "repository_count": len(entries),
        "repository_residue_count": len(residue),
        "cleanup_failed_count": len(failed),
        "all_terminal": not residue,
        "terminal_entry_ids": sorted(
            str(item["entry_id"]) for item in entries if item.get("state") in TERMINAL_STATES
        ),
    }


def finalize_repository_cleanup(
    ledger: Path | Mapping[str, Any],
    *,
    output: Path | None = None,
) -> dict[str, Any]:
    """Persist and enforce the zero-residue seal/finalize precondition."""

    summary = repository_cleanup_summary(ledger)
    if output is not None:
        encoded = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists() and output.read_text(encoding="utf-8") != encoded:
            raise QualificationRepositoryGCError("repository cleanup summary conflicts")
        if not output.exists():
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
    if (
        summary["repository_residue_count"] != 0
        or summary["cleanup_failed_count"] != 0
        or summary["all_terminal"] is not True
    ):
        raise QualificationRepositoryGCError("repository_residue_nonzero")
    return summary
