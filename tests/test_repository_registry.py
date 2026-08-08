from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from factory.repository_registry import (
    RegistryViolation,
    cleanup_plan,
    registry_digest,
    resolve_creation_retry,
    validate_registry,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/repository-registry.schema.json").read_text())


def entry(name: str, entry_class: str, **overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "full_name": f"brullik/{name}",
        "repository_id": abs(hash(name)) % 1_000_000 + 1,
        "class": entry_class,
        "product_id": None,
        "qualification_run_id": None,
        "candidate_epoch": None,
        "purpose": "A registry test fixture with explicit lifecycle ownership.",
        "idempotency_key": None,
        "creator_intent": None,
        "creator_receipt": None,
        "created_at": "2026-08-01T00:00:00Z",
        "expires_at": None,
        "terminal_state": None,
        "cleanup_action": "none",
        "cleanup_receipt": None,
    }
    value.update(overrides)
    return value


def temporary(name: str, *, run: str, terminal: str | None = None) -> dict[str, Any]:
    return entry(
        name,
        "temporary_golden_qualification",
        product_id=f"product-{name}",
        qualification_run_id=run,
        candidate_epoch="epoch-1",
        idempotency_key=hashlib.sha256(name.encode()).hexdigest(),
        creator_intent=f"intent:{name}",
        creator_receipt=f"receipt:{name}",
        expires_at="2026-08-07T00:00:00Z",
        terminal_state=terminal,
        cleanup_action="delete",
    )


def registry(entries: list[dict[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": "1.0",
        "captured_at": "2026-08-08T00:00:00Z",
        "entries": entries,
        "registry_digest": "",
    }
    value["registry_digest"] = registry_digest(value)
    return value


def test_current_style_registry_validates() -> None:
    value = registry(
        [
            entry("factory", "permanent_factory"),
            entry("personal", "non_hermes"),
            entry(
                "product",
                "permanent_product",
                product_id="product-1",
                idempotency_key="1" * 64,
                creator_intent="intent:product",
                creator_receipt="receipt:product",
            ),
        ]
    )
    assert validate_registry(value, SCHEMA) == {
        "status": "PASS",
        "registry_digest": value["registry_digest"],
        "entries": 3,
        "active_temporary": 0,
    }


def test_global_temporary_quota_fails_closed() -> None:
    value = registry([temporary(f"temp-{index}", run=f"run-{index}") for index in range(4)])
    with pytest.raises(RegistryViolation, match="quota exceeded"):
        validate_registry(value, SCHEMA)


def test_retry_resolves_existing_repository_and_rejects_drift() -> None:
    existing = temporary("temp", run="run-1")
    result = resolve_creation_retry(
        [existing],
        idempotency_key=existing["idempotency_key"],
        full_name=existing["full_name"],
        product_id=existing["product_id"],
        qualification_run_id=existing["qualification_run_id"],
        candidate_epoch=existing["candidate_epoch"],
    )
    assert result is existing
    with pytest.raises(RegistryViolation, match="differs"):
        resolve_creation_retry(
            [existing],
            idempotency_key=existing["idempotency_key"],
            full_name="brullik/a-second-repository",
            product_id=existing["product_id"],
            qualification_run_id=existing["qualification_run_id"],
            candidate_epoch=existing["candidate_epoch"],
        )


@pytest.mark.parametrize("entry_class", ["permanent_product", "unknown", "non_hermes"])
def test_protected_classes_cannot_acquire_cleanup_policy(entry_class: str) -> None:
    protected = entry(
        "protected",
        entry_class,
        product_id="product-1" if entry_class == "permanent_product" else None,
        expires_at="2026-08-09T00:00:00Z",
        cleanup_action="delete",
    )
    value = registry([protected])
    with pytest.raises(RegistryViolation, match="protected repository"):
        validate_registry(value, SCHEMA)


def test_eligible_cleanup_is_ordered_and_plan_only() -> None:
    candidate = temporary("expired", run="run-expired", terminal="passed")
    value = registry([candidate])
    validate_registry(value, SCHEMA)
    facts = {
        candidate["full_name"]: {
            "open_prs": 0,
            "active_releases": 0,
            "active_deployments": 0,
            "references": 0,
        }
    }
    plan = cleanup_plan(value, repository_state=facts, now=datetime(2026, 8, 8, tzinfo=UTC))
    assert plan["status"] == "PLAN_ONLY"
    assert plan["repositories"][0]["steps"] == [
        "close_pull_requests",
        "delete_task_branches",
        "delete",
    ]


def test_cleanup_requires_live_reference_evidence() -> None:
    candidate = temporary("expired", run="run-expired", terminal="failed")
    value = registry([candidate])
    with pytest.raises(RegistryViolation, match="missing live reference evidence"):
        cleanup_plan(value, repository_state={}, now=datetime(2026, 8, 8, tzinfo=UTC))


def test_digest_change_is_detected() -> None:
    value = registry([entry("factory", "permanent_factory")])
    mutated = copy.deepcopy(value)
    mutated["entries"][0]["purpose"] = "mutated"
    with pytest.raises(RegistryViolation, match="digest differs"):
        validate_registry(mutated, SCHEMA)
