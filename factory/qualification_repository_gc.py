"""Fail-closed identity attestation and DELETE lifecycle for qualification repos."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from .common import sha256_text, stable_json, utc_now
from .pre_q8_convergence import resource_namespace

LEDGER_STATES: Final[frozenset[str]] = frozenset(
    {
        "PROVISIONED",
        "IDENTITY_ATTESTED",
        "EVIDENCE_FROZEN",
        "PENDING_DELETE",
        "DELETE_REQUESTED",
        "DELETED",
        "ALREADY_ABSENT",
        "CLEANUP_FAILED",
    }
)
TERMINAL_STATES: Final[frozenset[str]] = frozenset(
    {"DELETED", "ALREADY_ABSENT"}
)
HISTORICAL_REPOSITORY_COUNT: Final[int] = 40
_NAMESPACE: Final[re.Pattern[str]] = re.compile(
    r"hermes-canary-(?:convergence|preq8|q8)-[a-z0-9]+-[a-f0-9]{20}"
)
_SHA40: Final[re.Pattern[str]] = re.compile(r"[a-f0-9]{40}")


class QualificationRepositoryGCError(RuntimeError):
    """Repository cleanup cannot be proven safe or terminal."""


def _without(value: Mapping[str, Any], excluded: str) -> dict[str, Any]:
    return {str(key): item for key, item in value.items() if key != excluded}


def _entry_digest(entry: Mapping[str, Any]) -> str:
    return sha256_text(stable_json(_without(entry, "entry_digest")))


def _ledger_digest(ledger: Mapping[str, Any]) -> str:
    return sha256_text(stable_json(_without(ledger, "ledger_digest")))


def _attestation_digest(attestation: Mapping[str, Any]) -> str:
    return sha256_text(stable_json(_without(attestation, "attestation_digest")))


def _validate_attestation(value: object) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise QualificationRepositoryGCError(
            "repository identity attestation is invalid"
        )
    attestation = {str(key): item for key, item in value.items()}
    if (
        attestation.get("schema_version") != "1.0"
        or str(attestation.get("attestation_digest") or "")
        != _attestation_digest(attestation)
    ):
        raise QualificationRepositoryGCError(
            "repository identity attestation digest differs"
        )
    return attestation


def _validate_ledger(ledger: Mapping[str, Any]) -> dict[str, Any]:
    value = {str(key): item for key, item in ledger.items()}
    entries = value.get("repositories")
    if (
        value.get("schema_version") != "2.0"
        or not isinstance(entries, list)
        or value.get("repository_count") != len(entries)
    ):
        raise QualificationRepositoryGCError("repository ledger is invalid")
    for raw in entries:
        if not isinstance(raw, Mapping):
            raise QualificationRepositoryGCError(
                "repository ledger entry is invalid"
            )
        entry = {str(key): item for key, item in raw.items()}
        if (
            str(entry.get("state") or "") not in LEDGER_STATES
            or str(entry.get("entry_digest") or "") != _entry_digest(entry)
        ):
            raise QualificationRepositoryGCError(
                "repository ledger entry digest differs"
            )
        _validate_attestation(entry.get("identity_attestation"))
    if str(value.get("ledger_digest") or "") != _ledger_digest(value):
        raise QualificationRepositoryGCError("repository ledger digest differs")
    return value


def load_repository_ledger(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise QualificationRepositoryGCError("repository ledger is unavailable")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QualificationRepositoryGCError(
            "repository ledger is unreadable"
        ) from error
    if not isinstance(value, Mapping):
        raise QualificationRepositoryGCError(
            "repository ledger is not an object"
        )
    return _validate_ledger(value)


def _write_repository_ledger(
    path: Path,
    ledger: Mapping[str, Any],
) -> dict[str, Any]:
    body = _without(ledger, "ledger_digest")
    raw_entries = body.get("repositories", [])
    if not isinstance(raw_entries, list):
        raise QualificationRepositoryGCError(
            "repository ledger entries are invalid"
        )
    body["repository_count"] = len(raw_entries)
    envelope = {**body, "ledger_digest": _ledger_digest(body)}
    _validate_ledger(envelope)
    encoded = json.dumps(
        envelope,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o640,
    )
    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
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
    identity: dict[str, Any] = {
        "schema_version": "2.0",
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
            if key in {"repositories", "repository_count"}:
                continue
            if current.get(key) != expected:
                raise QualificationRepositoryGCError(
                    "repository ledger identity differs"
                )
        return current
    return _write_repository_ledger(path, identity)


def _provided_attestation(
    *,
    repository_id: int | None,
    repository_node_id: str | None,
    expected_default_branch: str,
    expected_head_sha: str | None,
    identity_proof_mode: str,
) -> dict[str, Any] | None:
    if not (
        isinstance(repository_id, int)
        and repository_id > 0
        and isinstance(repository_node_id, str)
        and bool(repository_node_id)
        and isinstance(expected_head_sha, str)
        and _SHA40.fullmatch(expected_head_sha) is not None
        and identity_proof_mode
        in {
            "LIVE_REPOSITORY_ID_AND_HEAD_V1",
            "FIXTURE_RECEIPT_ID_AND_HEAD_V1",
        }
    ):
        return None
    body: dict[str, Any] = {
        "schema_version": "1.0",
        "source": "record_provided_identity",
        "verified_absent": False,
        "repository_id": repository_id,
        "repository_node_id": repository_node_id,
        "default_branch": expected_default_branch,
        "head_sha": expected_head_sha,
        "description_status": "PRE_ATTESTED",
        "observed_metadata_digest": None,
        "observed_at": utc_now(),
    }
    return {**body, "attestation_digest": _attestation_digest(body)}


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
    repository_node_id: str | None = None,
    expected_head_sha: str | None = None,
    expected_default_branch: str = "main",
    identity_proof_mode: str = "PENDING_LIVE_ATTESTATION",
) -> dict[str, Any]:
    ledger = initialize_repository_ledger(
        path,
        qualification_plane=qualification_plane,
        epoch_id=epoch_id,
        run_id=run_id,
        candidate_digest=candidate_digest,
    )
    entry_id = "QRG-" + sha256_text(
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
    attestation = _provided_attestation(
        repository_id=repository_id,
        repository_node_id=repository_node_id,
        expected_default_branch=expected_default_branch,
        expected_head_sha=expected_head_sha,
        identity_proof_mode=identity_proof_mode,
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
        "repository_node_id": repository_node_id,
        "expected_description": expected_description,
        "description_policy": (
            "EXACT_REQUIRED"
            if product_id is None
            else "NULL_OR_EXACT_WITH_ID_HEAD"
        ),
        "repository_visibility": "private",
        "expected_default_branch": expected_default_branch,
        "expected_head_sha": expected_head_sha,
        "identity_proof_mode": identity_proof_mode,
        "identity_attestation": attestation,
        "provision_receipt_digest": provision_receipt_digest,
        "database_path": database_path,
        "evidence_status": "PENDING",
        "state": "IDENTITY_ATTESTED" if attestation is not None else "PROVISIONED",
        "cleanup_receipt": None,
        "updated_at": utc_now(),
    }
    entry["entry_digest"] = _entry_digest(entry)
    entries = [dict(item) for item in ledger["repositories"]]
    existing = next(
        (item for item in entries if item.get("entry_id") == entry_id),
        None,
    )
    if existing is not None:
        immutable_keys = {
            "entry_id",
            "qualification_plane",
            "epoch_id",
            "run_id",
            "scenario_id",
            "candidate_digest",
            "product_id",
            "repository_owner",
            "repository_name",
            "expected_description",
            "description_policy",
            "repository_visibility",
            "expected_default_branch",
            "provision_receipt_digest",
            "database_path",
        }
        if any(existing.get(key) != entry.get(key) for key in immutable_keys):
            raise QualificationRepositoryGCError(
                "repository ledger replay conflicts"
            )
        return existing
    entries.append(entry)
    ledger["repositories"] = sorted(
        entries,
        key=lambda item: str(item["entry_id"]),
    )
    written = _write_repository_ledger(path, ledger)
    return next(
        dict(item)
        for item in written["repositories"]
        if item["entry_id"] == entry_id
    )


def _comparable_attestation(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): item
        for key, item in value.items()
        if key not in {"observed_at", "attestation_digest"}
    }


def attest_repository_identity(
    path: Path,
    entry_id: str,
    *,
    live_repository: Mapping[str, Any] | None,
    live_head_sha: str | None,
    expected_head_sha: str | None,
) -> dict[str, Any]:
    """Bind one ledger entry to live GitHub ID, node ID and exact branch head."""

    ledger = load_repository_ledger(path)
    result: dict[str, Any] | None = None
    entries: list[dict[str, Any]] = []
    for raw in ledger["repositories"]:
        entry = dict(raw)
        if entry.get("entry_id") != entry_id:
            entries.append(entry)
            continue
        if entry.get("state") in TERMINAL_STATES:
            result = entry
            entries.append(entry)
            continue
        if entry.get("state") not in {"PROVISIONED", "IDENTITY_ATTESTED"}:
            raise QualificationRepositoryGCError(
                "repository identity cannot be attested from current state"
            )
        owner = str(entry.get("repository_owner") or "")
        name = str(entry.get("repository_name") or "")
        expected_description = str(entry.get("expected_description") or "")
        if live_repository is None:
            body: dict[str, Any] = {
                "schema_version": "1.0",
                "source": "live_github_metadata",
                "verified_absent": True,
                "repository_id": None,
                "repository_node_id": None,
                "default_branch": entry.get("expected_default_branch"),
                "head_sha": None,
                "expected_head_sha": expected_head_sha,
                "description_status": "ABSENT",
                "observed_metadata_digest": None,
                "observed_at": utc_now(),
            }
            repository_id: int | None = None
            repository_node_id: str | None = None
            identity_mode = "VERIFIED_ABSENT_AT_ATTESTATION_V1"
            stored_head_sha = expected_head_sha
        else:
            if (
                not isinstance(expected_head_sha, str)
                or _SHA40.fullmatch(expected_head_sha) is None
                or live_head_sha != expected_head_sha
            ):
                raise QualificationRepositoryGCError(
                    "live repository head SHA differs"
                )
            live_owner = live_repository.get("owner")
            raw_id = live_repository.get("id")
            raw_node_id = live_repository.get("node_id")
            if (
                live_repository.get("name") != name
                or live_repository.get("private") is not True
                or live_repository.get("fork") is True
                or not isinstance(live_owner, Mapping)
                or str(live_owner.get("login") or "") != owner
                or not isinstance(raw_id, int)
                or raw_id < 1
                or not isinstance(raw_node_id, str)
                or not raw_node_id
                or str(live_repository.get("default_branch") or "")
                != str(entry.get("expected_default_branch") or "")
            ):
                raise QualificationRepositoryGCError(
                    "live repository identity differs"
                )
            observed_description = live_repository.get("description")
            if entry.get("description_policy") == "EXACT_REQUIRED":
                if observed_description != expected_description:
                    raise QualificationRepositoryGCError(
                        "repository description differs"
                    )
                description_status = "EXACT"
            else:
                if (
                    observed_description is not None
                    and observed_description != expected_description
                ):
                    raise QualificationRepositoryGCError(
                        "repository description differs"
                    )
                description_status = (
                    "NULL_BROKER_OMISSION"
                    if observed_description is None
                    else "EXACT"
                )
            repository_id = raw_id
            repository_node_id = raw_node_id
            body = {
                "schema_version": "1.0",
                "source": "live_github_metadata",
                "verified_absent": False,
                "repository_id": repository_id,
                "repository_node_id": repository_node_id,
                "default_branch": live_repository.get("default_branch"),
                "head_sha": live_head_sha,
                "expected_head_sha": expected_head_sha,
                "description_status": description_status,
                "observed_metadata_digest": sha256_text(
                    stable_json(dict(live_repository))
                ),
                "observed_at": utc_now(),
            }
            identity_mode = (
                "FIXTURE_RECEIPT_ID_AND_HEAD_V1"
                if entry.get("product_id") is None
                else "LIVE_REPOSITORY_ID_AND_HEAD_V1"
            )
            stored_head_sha = live_head_sha
        attestation = {
            **body,
            "attestation_digest": _attestation_digest(body),
        }
        current = _validate_attestation(entry.get("identity_attestation"))
        if current is not None and current.get("source") == "live_github_metadata":
            if _comparable_attestation(current) != _comparable_attestation(attestation):
                raise QualificationRepositoryGCError(
                    "repository identity attestation conflicts"
                )
            result = entry
            entries.append(entry)
            continue
        if current is not None and current.get("source") == "record_provided_identity":
            if live_repository is None:
                raise QualificationRepositoryGCError(
                    "pre-attested repository unexpectedly disappeared"
                )
            if (
                current.get("repository_id") != repository_id
                or current.get("repository_node_id") != repository_node_id
                or current.get("head_sha") != stored_head_sha
            ):
                raise QualificationRepositoryGCError(
                    "pre-attested repository identity conflicts"
                )
        entry["repository_id"] = repository_id
        entry["repository_node_id"] = repository_node_id
        entry["expected_head_sha"] = stored_head_sha
        entry["identity_proof_mode"] = identity_mode
        entry["identity_attestation"] = attestation
        entry["state"] = "IDENTITY_ATTESTED"
        entry["updated_at"] = utc_now()
        entry["entry_digest"] = _entry_digest(entry)
        result = entry
        entries.append(entry)
    if result is None:
        raise QualificationRepositoryGCError(
            "repository ledger entry is missing"
        )
    ledger["repositories"] = entries
    written = _write_repository_ledger(path, ledger)
    return next(
        dict(item)
        for item in written["repositories"]
        if item.get("entry_id") == entry_id
    )


def mark_scenario_evidence_frozen(path: Path, scenario_id: str) -> int:
    ledger = load_repository_ledger(path)
    matching = [
        dict(entry)
        for entry in ledger["repositories"]
        if entry.get("scenario_id") == scenario_id
    ]
    if any(entry.get("state") == "PROVISIONED" for entry in matching):
        raise QualificationRepositoryGCError(
            "repository identity is not attested"
        )
    changed = 0
    entries: list[dict[str, Any]] = []
    for raw in ledger["repositories"]:
        entry = dict(raw)
        if (
            entry.get("scenario_id") == scenario_id
            and entry.get("state") == "IDENTITY_ATTESTED"
        ):
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
    live_head_sha: str | None = None,
) -> tuple[bool, str]:
    """Verify exact DELETE preconditions; unknown repositories are report-only."""

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
    if (
        entry.get("evidence_status") != "FROZEN"
        or entry.get("state")
        not in {
            "EVIDENCE_FROZEN",
            "PENDING_DELETE",
            "DELETE_REQUESTED",
            "CLEANUP_FAILED",
        }
    ):
        return False, "evidence_not_frozen"
    if not owner or name in set(permanent_allowlist):
        return False, "repository_is_permanent_or_owner_missing"
    if _NAMESPACE.fullmatch(name) is None or name != expected:
        return False, "namespace_recomputation_differs"
    try:
        attestation = _validate_attestation(entry.get("identity_attestation"))
    except QualificationRepositoryGCError:
        return False, "identity_attestation_invalid"
    if attestation is None:
        return False, "identity_attestation_missing"
    if live_repository is None:
        return True, "already_absent"
    if entry.get("identity_proof_mode") == "VERIFIED_ABSENT_AT_ATTESTATION_V1":
        return False, "repository_appeared_after_absent_attestation"
    live_owner = live_repository.get("owner")
    if live_head_sha is None:
        candidate = live_repository.get("_hermes_head_sha")
        live_head_sha = str(candidate) if isinstance(candidate, str) else None
    if (
        live_repository.get("name") != name
        or live_repository.get("private") is not True
        or live_repository.get("fork") is True
        or not isinstance(live_owner, Mapping)
        or str(live_owner.get("login") or "") != owner
        or live_repository.get("id") != entry.get("repository_id")
        or live_repository.get("node_id") != entry.get("repository_node_id")
        or str(live_repository.get("default_branch") or "")
        != str(entry.get("expected_default_branch") or "")
        or live_head_sha != entry.get("expected_head_sha")
    ):
        return False, "live_repository_identity_differs"
    expected_description = str(entry.get("expected_description") or "")
    observed_description = live_repository.get("description")
    if entry.get("description_policy") == "EXACT_REQUIRED":
        if observed_description != expected_description:
            return False, "repository_description_differs"
    elif observed_description is not None and observed_description != expected_description:
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
        raise QualificationRepositoryGCError(
            "repository cleanup state is invalid"
        )
    ledger = load_repository_ledger(path)
    found = False
    result: dict[str, Any] | None = None
    entries: list[dict[str, Any]] = []
    for raw in ledger["repositories"]:
        entry = dict(raw)
        if entry.get("entry_id") == entry_id:
            found = True
            existing_state = str(entry.get("state") or "")
            existing_receipt = entry.get("cleanup_receipt")
            next_receipt = (
                dict(cleanup_receipt) if cleanup_receipt is not None else None
            )
            if existing_state in TERMINAL_STATES:
                if existing_state != state or existing_receipt != next_receipt:
                    raise QualificationRepositoryGCError(
                        "terminal repository cleanup receipt conflicts"
                    )
                result = entry
                entries.append(entry)
                continue
            entry["state"] = state
            entry["cleanup_receipt"] = next_receipt
            entry["updated_at"] = utc_now()
            entry["entry_digest"] = _entry_digest(entry)
            result = entry
        entries.append(entry)
    if not found or result is None:
        raise QualificationRepositoryGCError(
            "repository ledger entry is missing"
        )
    ledger["repositories"] = entries
    _write_repository_ledger(path, ledger)
    return result


def qualification_repository_cleanup_plan(
    ledger: Path | Mapping[str, Any],
    *,
    run_active: bool = False,
) -> dict[str, Any]:
    value = (
        load_repository_ledger(ledger)
        if isinstance(ledger, Path)
        else _validate_ledger(ledger)
    )
    planned = [
        dict(entry)
        for entry in value["repositories"]
        if not run_active
        and entry.get("state")
        in {
            "EVIDENCE_FROZEN",
            "PENDING_DELETE",
            "DELETE_REQUESTED",
            "CLEANUP_FAILED",
        }
    ]
    return {
        "schema_version": "2.0",
        "run_id": value["run_id"],
        "planned_count": len(planned),
        "entries": planned,
    }


def repository_cleanup_summary(
    ledger: Path | Mapping[str, Any],
) -> dict[str, Any]:
    value = (
        load_repository_ledger(ledger)
        if isinstance(ledger, Path)
        else _validate_ledger(ledger)
    )
    entries = [dict(item) for item in value["repositories"]]
    residue = [
        item for item in entries if item.get("state") not in TERMINAL_STATES
    ]
    failed = [
        item for item in entries if item.get("state") == "CLEANUP_FAILED"
    ]
    return {
        "schema_version": "2.0",
        "run_id": value["run_id"],
        "repository_count": len(entries),
        "repository_residue_count": len(residue),
        "cleanup_failed_count": len(failed),
        "all_terminal": not residue,
        "terminal_entry_ids": sorted(
            str(item["entry_id"])
            for item in entries
            if item.get("state") in TERMINAL_STATES
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
        encoded = json.dumps(
            summary,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ) + "\n"
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists() and output.read_text(encoding="utf-8") != encoded:
            raise QualificationRepositoryGCError(
                "repository cleanup summary conflicts"
            )
        if not output.exists():
            descriptor = os.open(
                output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o640,
            )
            with os.fdopen(
                descriptor,
                "w",
                encoding="utf-8",
                newline="\n",
            ) as handle:
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
