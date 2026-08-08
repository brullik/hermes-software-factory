"""Fail-closed repository ownership, quota, and cleanup planning controls."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

PERMANENT_CLASSES = frozenset(
    {"permanent_factory", "permanent_pilot", "permanent_product"}
)
TEMPORARY_CLASSES = frozenset(
    {"temporary_canary", "temporary_golden_qualification", "temporary_shadow"}
)
PROTECTED_CLASSES = PERMANENT_CLASSES | {"unknown", "non_hermes"}
ACTIVE_STATES = frozenset({None, "active", "pending", "running"})
TERMINAL_STATES = frozenset({"passed", "failed", "cancelled", "expired", "closed"})
MAX_ACTIVE_TEMPORARY = 3


class RegistryViolation(RuntimeError):
    """The registry cannot prove that the requested operation is safe."""


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def registry_digest(registry: Mapping[str, Any]) -> str:
    """Return the digest of the registry with its self-digest field omitted."""
    unsigned = {key: value for key, value in registry.items() if key != "registry_digest"}
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _timestamp(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise RegistryViolation(f"{field} is not a valid date-time") from error
    if parsed.tzinfo is None:
        raise RegistryViolation(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def _entry_key(entry: Mapping[str, Any]) -> str:
    return str(entry["full_name"])


def _is_active(entry: Mapping[str, Any]) -> bool:
    return entry["terminal_state"] in ACTIVE_STATES


def _validate_semantics(entries: Sequence[Mapping[str, Any]]) -> None:
    names: set[str] = set()
    repository_ids: set[int] = set()
    idempotency: dict[str, str] = {}
    permanent_products: dict[str, str] = {}
    active_golden_runs: dict[str, str] = {}
    active_intents: dict[tuple[str, str, str], str] = {}
    active_temporary = 0

    for entry in entries:
        name = _entry_key(entry)
        if name in names:
            raise RegistryViolation(f"duplicate repository name: {name}")
        names.add(name)
        repository_id = entry["repository_id"]
        if repository_id is not None:
            if repository_id in repository_ids:
                raise RegistryViolation(f"duplicate repository id: {repository_id}")
            repository_ids.add(repository_id)

        entry_class = entry["class"]
        key = entry["idempotency_key"]
        if key is not None:
            previous = idempotency.setdefault(key, name)
            if previous != name:
                raise RegistryViolation(f"idempotency key maps to multiple repositories: {key}")

        if entry_class in PROTECTED_CLASSES:
            if entry["expires_at"] is not None or entry["cleanup_action"] != "none":
                raise RegistryViolation(f"protected repository has cleanup metadata: {name}")
            if entry["cleanup_receipt"] is not None:
                raise RegistryViolation(f"protected repository has cleanup receipt: {name}")

        if entry_class == "permanent_product":
            product = entry["product_id"]
            if not product:
                raise RegistryViolation(f"permanent product lacks product_id: {name}")
            previous = permanent_products.setdefault(product, name)
            if previous != name:
                raise RegistryViolation(f"more than one permanent repository for product: {product}")

        if entry_class not in TEMPORARY_CLASSES:
            continue
        required = (
            "product_id",
            "qualification_run_id",
            "candidate_epoch",
            "idempotency_key",
            "creator_intent",
            "creator_receipt",
            "expires_at",
        )
        if any(not entry[field] for field in required):
            raise RegistryViolation(f"temporary repository lacks ownership evidence: {name}")
        if entry["cleanup_action"] not in {"pending", "archive", "delete"}:
            raise RegistryViolation(f"temporary repository lacks cleanup policy: {name}")
        if _timestamp(entry["expires_at"], f"{name}.expires_at") <= _timestamp(
            entry["created_at"], f"{name}.created_at"
        ):
            raise RegistryViolation(f"temporary repository expiry is not after creation: {name}")
        if _is_active(entry):
            active_temporary += 1
            product = str(entry["product_id"])
            run = str(entry["qualification_run_id"])
            idem = str(entry["idempotency_key"])
            intent_key = (product, run, idem)
            previous = active_intents.setdefault(intent_key, name)
            if previous != name:
                raise RegistryViolation("more than one active creation intent for product/run/key")
            if entry_class == "temporary_golden_qualification":
                previous = active_golden_runs.setdefault(run, name)
                if previous != name:
                    raise RegistryViolation(
                        f"more than one active golden qualification repository for run: {run}"
                    )
    if active_temporary > MAX_ACTIVE_TEMPORARY:
        raise RegistryViolation(
            f"active temporary repository quota exceeded: {active_temporary} > {MAX_ACTIVE_TEMPORARY}"
        )


def validate_registry(
    registry: Mapping[str, Any], schema: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate schema, digest, ownership invariants, and global quotas."""
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(registry), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "$"
        raise RegistryViolation(f"schema violation at {location}: {first.message}")
    expected = registry_digest(registry)
    if registry["registry_digest"] != expected:
        raise RegistryViolation("registry digest differs from canonical content")
    entries = registry["entries"]
    _validate_semantics(entries)
    return {
        "status": "PASS",
        "registry_digest": expected,
        "entries": len(entries),
        "active_temporary": sum(
            1 for entry in entries if entry["class"] in TEMPORARY_CLASSES and _is_active(entry)
        ),
    }


def resolve_creation_retry(
    entries: Sequence[Mapping[str, Any]],
    *,
    idempotency_key: str,
    full_name: str,
    product_id: str,
    qualification_run_id: str,
    candidate_epoch: str,
) -> Mapping[str, Any] | None:
    """Resolve a retry to the existing immutable intent; never allocate a second name."""
    matches = [entry for entry in entries if entry["idempotency_key"] == idempotency_key]
    if not matches:
        return None
    if len(matches) != 1:
        raise RegistryViolation("idempotency key is ambiguous")
    entry = matches[0]
    identity = (
        entry["full_name"],
        entry["product_id"],
        entry["qualification_run_id"],
        entry["candidate_epoch"],
    )
    if identity != (full_name, product_id, qualification_run_id, candidate_epoch):
        raise RegistryViolation("idempotency retry differs from the recorded immutable intent")
    return entry


def cleanup_plan(
    registry: Mapping[str, Any],
    *,
    repository_state: Mapping[str, Mapping[str, Any]],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build an evidence-bound plan. This function never calls a repository API."""
    current = (now or datetime.now(UTC)).astimezone(UTC)
    plans: list[dict[str, Any]] = []
    for entry in registry["entries"]:
        name = _entry_key(entry)
        if entry["class"] in PROTECTED_CLASSES:
            continue
        if entry["class"] not in TEMPORARY_CLASSES:
            raise RegistryViolation(f"unrecognized cleanup class: {name}")
        if entry["repository_id"] is None:
            raise RegistryViolation(f"temporary repository lacks a durable repository id: {name}")
        terminal = entry["terminal_state"]
        expired = current >= _timestamp(entry["expires_at"], f"{name}.expires_at")
        if terminal not in TERMINAL_STATES or not expired:
            continue
        facts = repository_state.get(name)
        if facts is None:
            raise RegistryViolation(f"missing live reference evidence for cleanup candidate: {name}")
        required = {"open_prs", "active_releases", "active_deployments", "references"}
        if set(facts) != required or any(
            not isinstance(facts[field], int) or isinstance(facts[field], bool) or facts[field] < 0
            for field in required
        ):
            raise RegistryViolation(f"invalid live reference evidence for cleanup candidate: {name}")
        if any(facts[field] for field in required):
            raise RegistryViolation(f"cleanup candidate still has live references: {name}")
        final_action = entry["cleanup_action"]
        if final_action == "pending":
            raise RegistryViolation(f"cleanup policy is unresolved: {name}")
        plans.append(
            {
                "full_name": name,
                "repository_id": entry["repository_id"],
                "ownership": "registry_proven",
                "evidence": dict(facts),
                "steps": ["close_pull_requests", "delete_task_branches", final_action],
            }
        )
    return {
        "status": "PLAN_ONLY",
        "registry_digest": registry["registry_digest"],
        "generated_at": current.isoformat().replace("+00:00", "Z"),
        "repositories": plans,
    }


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RegistryViolation(f"JSON root must be an object: {path}")
    return value
