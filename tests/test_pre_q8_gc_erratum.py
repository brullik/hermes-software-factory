from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from factory.pre_q8_convergence import resource_namespace
from factory.qualification_repository_gc import (
    QualificationRepositoryGCError,
    attest_repository_identity,
    load_repository_ledger,
    mark_scenario_evidence_frozen,
    record_provisioned_repository,
    verify_repository_cleanup_eligibility,
)

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "tools" / "qualification_repository_inventory_v2.json"
HISTORICAL_TOOL = ROOT / "tools" / "qualification_repository_gc_v2.py"
BROKER_SHA256 = (
    "14153c7c2bacaf102612327238220b89b3ae253c9c39014ddece9eb4bb5d4688"
)
SCOPE_DIGEST = (
    "4aa10c32e3a4e3b92bef99f154e7373c8527c547ddc0bed34bc93d4c93358faf"
)


def _historical() -> Any:
    spec = importlib.util.spec_from_file_location(
        "qualification_repository_gc_v2",
        HISTORICAL_TOOL,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _record_pending(
    tmp_path: Path,
    *,
    fixture: bool = False,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    ledger = tmp_path / "repository-ledger.json"
    candidate = "c" * 64
    scenario = "existing-repository-repair" if fixture else "zero-dependency-cli"
    name = resource_namespace(
        plane="convergence",
        run_id="r04-run-0001",
        candidate_digest=candidate,
        scenario_id=scenario,
    )
    expected_description = (
        "Hermes content-addressed PRE-Q8 repair fixture"
        if fixture
        else "Hermes product product-r04"
    )
    entry = record_provisioned_repository(
        ledger,
        qualification_plane="CONVERGENCE",
        epoch_id="RE-AAAAAAAAAAAAAAAAAAAAAAAA",
        run_id="r04-run-0001",
        scenario_id=scenario,
        candidate_digest=candidate,
        product_id=None if fixture else "product-r04",
        repository_owner="brullik",
        repository_name=name,
        repository_id=None,
        expected_description=expected_description,
        provision_receipt_digest="d" * 64,
    )
    live = {
        "id": 42,
        "node_id": "R_fixture",
        "name": name,
        "full_name": f"brullik/{name}",
        "private": True,
        "fork": False,
        "owner": {"login": "brullik"},
        "default_branch": "main",
        "description": expected_description if fixture else None,
        "_hermes_head_sha": "a" * 40,
    }
    return ledger, entry, live


def _attested(
    tmp_path: Path,
    *,
    fixture: bool = False,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    ledger, entry, live = _record_pending(tmp_path, fixture=fixture)
    entry = attest_repository_identity(
        ledger,
        str(entry["entry_id"]),
        live_repository=live,
        live_head_sha="a" * 40,
        expected_head_sha="a" * 40,
    )
    return ledger, entry, live


def test_historical_inventory_includes_r02_zero_dependency_cli() -> None:
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    names = {
        entry["repository_name"]
        for entry in inventory["repositories"]
    }
    assert inventory["repository_count"] == 40
    assert (
        "hermes-canary-convergence-"
        "zerodependencycli-190868183e2427161b5a"
        in names
    )


def test_product_repository_requires_live_id_and_head_attestation(
    tmp_path: Path,
) -> None:
    ledger, _, _ = _record_pending(tmp_path)
    with pytest.raises(
        QualificationRepositoryGCError,
        match="not attested",
    ):
        mark_scenario_evidence_frozen(ledger, "zero-dependency-cli")


def test_product_repository_accepts_null_description_only_with_id_head_proof(
    tmp_path: Path,
) -> None:
    ledger, _, live = _attested(tmp_path)
    mark_scenario_evidence_frozen(ledger, "zero-dependency-cli")
    frozen = load_repository_ledger(ledger)["repositories"][0]
    assert live["description"] is None
    assert verify_repository_cleanup_eligibility(
        frozen,
        live,
        run_active=False,
    ) == (True, "eligible")


def test_product_repository_rejects_non_null_wrong_description(
    tmp_path: Path,
) -> None:
    ledger, _, live = _attested(tmp_path)
    mark_scenario_evidence_frozen(ledger, "zero-dependency-cli")
    frozen = load_repository_ledger(ledger)["repositories"][0]
    assert verify_repository_cleanup_eligibility(
        frozen,
        {**live, "description": "unrelated repository"},
        run_active=False,
    ) == (False, "repository_description_differs")


def _assert_live_identity_rejected(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    ledger, _, live = _attested(tmp_path)
    mark_scenario_evidence_frozen(ledger, "zero-dependency-cli")
    frozen = load_repository_ledger(ledger)["repositories"][0]
    assert verify_repository_cleanup_eligibility(
        frozen,
        {**live, field: value},
        run_active=False,
    ) == (False, "live_repository_identity_differs")


def test_product_repository_rejects_live_id_mismatch(tmp_path: Path) -> None:
    _assert_live_identity_rejected(tmp_path, "id", 43)


def test_product_repository_rejects_node_id_mismatch(tmp_path: Path) -> None:
    _assert_live_identity_rejected(tmp_path, "node_id", "R_other")


def test_product_repository_rejects_head_sha_mismatch(tmp_path: Path) -> None:
    _assert_live_identity_rejected(tmp_path, "_hermes_head_sha", "b" * 40)


def test_fixture_repository_still_requires_exact_description(
    tmp_path: Path,
) -> None:
    ledger, _, live = _attested(tmp_path, fixture=True)
    mark_scenario_evidence_frozen(ledger, "existing-repository-repair")
    frozen = load_repository_ledger(ledger)["repositories"][0]
    assert verify_repository_cleanup_eligibility(
        frozen,
        {**live, "description": None},
        run_active=False,
    ) == (False, "repository_description_differs")


def test_freeze_refuses_unattested_repository(tmp_path: Path) -> None:
    ledger, _, _ = _record_pending(tmp_path)
    with pytest.raises(
        QualificationRepositoryGCError,
        match="not attested",
    ):
        mark_scenario_evidence_frozen(ledger, "zero-dependency-cli")


def test_freeze_accepts_attested_repository(tmp_path: Path) -> None:
    ledger, _, _ = _attested(tmp_path)
    assert mark_scenario_evidence_frozen(ledger, "zero-dependency-cli") == 1


def test_identity_attestation_is_digest_bound(tmp_path: Path) -> None:
    ledger, _, _ = _attested(tmp_path)
    value = json.loads(ledger.read_text(encoding="utf-8"))
    value["repositories"][0]["identity_attestation"]["repository_id"] = 99
    entry = value["repositories"][0]
    entry["entry_digest"] = hashlib.sha256(
        json.dumps(
            {key: item for key, item in entry.items() if key != "entry_digest"},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    body = {
        key: item
        for key, item in value.items()
        if key != "ledger_digest"
    }
    value["ledger_digest"] = hashlib.sha256(
        json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    ledger.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(
        QualificationRepositoryGCError,
        match="attestation",
    ):
        load_repository_ledger(ledger)


def test_identity_attestation_replay_is_idempotent(tmp_path: Path) -> None:
    ledger, entry, live = _attested(tmp_path)
    first = attest_repository_identity(
        ledger,
        str(entry["entry_id"]),
        live_repository=live,
        live_head_sha="a" * 40,
        expected_head_sha="a" * 40,
    )
    second = attest_repository_identity(
        ledger,
        str(entry["entry_id"]),
        live_repository=live,
        live_head_sha="a" * 40,
        expected_head_sha="a" * 40,
    )
    assert (
        first["identity_attestation"]["attestation_digest"]
        == second["identity_attestation"]["attestation_digest"]
    )


def _historical_entry() -> dict[str, Any]:
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    return next(
        entry
        for entry in inventory["repositories"]
        if entry["identity_proof_mode"] == "LEGACY_AUDIT_GIT_HEAD_V1"
    )


def _historical_live(
    entry: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    live = {
        "id": 123,
        "node_id": "R_live",
        "name": entry["repository_name"],
        "full_name": (
            f"{entry['repository_owner']}/{entry['repository_name']}"
        ),
        "private": True,
        "fork": False,
        "owner": {"login": entry["repository_owner"]},
        "default_branch": entry["expected_default_branch"],
        "description": None,
        "archived": False,
    }
    reference = {
        "ref": "refs/heads/main",
        "node_id": "REF_live",
        "object": {
            "type": "commit",
            "sha": entry["expected_head_sha"],
        },
    }
    commit = {
        "sha": entry["expected_bootstrap_sha"],
        "message": entry["expected_commit_message"],
        "tree": {"sha": "e" * 40},
        "parents": [],
    }
    return live, reference, commit


def test_historical_gc_attest_binds_live_repository_id() -> None:
    module = _historical()
    entry = _historical_entry()
    live, reference, commit = _historical_live(entry)
    result = module.verify_live_identity(entry, live, reference, commit)
    assert result["repository_id"] == 123
    assert result["repository_node_id"] == "R_live"
    assert result["head_sha"] == entry["expected_head_sha"]


def test_historical_gc_apply_revalidates_head_before_delete() -> None:
    module = _historical()
    entry = _historical_entry()
    live, reference, commit = _historical_live(entry)
    reference["object"]["sha"] = "f" * 40
    with pytest.raises(module.HistoricalGCError, match="Git identity"):
        module.verify_live_identity(entry, live, reference, commit)


def test_historical_gc_already_absent_is_terminal() -> None:
    module = _historical()
    result = module.verify_live_identity(
        _historical_entry(),
        None,
        None,
        None,
    )
    assert result["status"] == "ALREADY_ABSENT"


def test_historical_gc_unknown_prefix_is_report_only() -> None:
    module = _historical()
    inventory = module.validate_inventory(
        json.loads(INVENTORY.read_text(encoding="utf-8"))
    )
    unknown = "hermes-canary-convergence-unknown-aaaaaaaaaaaaaaaaaaaa"
    assert module.unknown_repository_names(
        inventory,
        {
            inventory["repositories"][0]["repository_name"],
            unknown,
        },
    ) == [unknown]


def test_historical_gc_inventory_digest_detects_tampering() -> None:
    module = _historical()
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    inventory["repositories"][0]["expected_head_sha"] = "0" * 40
    with pytest.raises(module.HistoricalGCError, match="digest"):
        module.validate_inventory(inventory)


def test_future_repository_gc_uses_id_head_as_primary_identity(
    tmp_path: Path,
) -> None:
    ledger, _, live = _attested(tmp_path)
    mark_scenario_evidence_frozen(ledger, "zero-dependency-cli")
    frozen = load_repository_ledger(ledger)["repositories"][0]
    assert live["description"] is None
    assert frozen["repository_id"] == 42
    assert frozen["repository_node_id"] == "R_fixture"
    assert frozen["expected_head_sha"] == "a" * 40
    assert verify_repository_cleanup_eligibility(
        frozen,
        live,
        run_active=False,
    )[0] is True


def test_credential_broker_remains_frozen() -> None:
    assert hashlib.sha256(
        (ROOT / "factory" / "credential_broker.py").read_bytes()
    ).hexdigest() == BROKER_SHA256


def test_scope_contract_remains_frozen() -> None:
    contract = json.loads(
        (ROOT / ".hermes" / "task-scope-contract.json").read_text(
            encoding="utf-8"
        )
    )
    assert contract["contract_digest"] == SCOPE_DIGEST
    assert "factory/credential_broker.py" in contract["forbidden_paths"]
