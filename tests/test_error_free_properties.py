"""Generative safety properties required by the Hermes 2.4 audit."""

from __future__ import annotations

import string

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from factory.common import sha256_text
from factory.failure_catalog import FAILURE_CATALOG, FailureAction, failure_disposition
from factory.path_governor import occurrence_epoch_key, root_cause_key
from factory.proof_obligations import ProofObligationError, compile_capability_proof
from factory.transition_catalog import (
    TRANSITION_CATALOG,
    ProductState,
    TransitionSpec,
    build_transition_index,
)
from factory.transition_kernel import TransitionKernel, TransitionProofError

PROPERTY_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    deadline=None,
    database=None,
    suppress_health_check=(HealthCheck.filter_too_much,),
)
CARDINALITIES = (0, 1, 2, 32, 99, 100, 101, 500, 10_000)


def test_locked_controller_reason_codes_are_registered_exactly() -> None:
    reason_codes = {
        "controller_result_provenance_invalid",
        "cross_role_supersession_invalid",
        "active_result_binding_conflict",
        "controller_envelope_conflict",
        "canonical_fault_gate_missing",
    }

    for reason_code in reason_codes:
        disposition = failure_disposition(reason_code)
        assert disposition.reason_code == reason_code
        assert disposition.registered
        assert disposition.action is FailureAction.CONTROLLER_QUARANTINE


@PROPERTY_SETTINGS
@given(
    task_id=st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=32),
    attempt_id=st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=32),
    hypothesis_id=st.text(
        alphabet=string.ascii_letters + string.digits,
        min_size=1,
        max_size=32,
    ),
    wording=st.text(alphabet=string.printable, max_size=80),
)
def test_root_cause_identity_excludes_all_ephemeral_coordinates(
    task_id: str,
    attempt_id: str,
    hypothesis_id: str,
    wording: str,
) -> None:
    stable = {
        "product_id": "P-PROPERTY",
        "failure_class": "semantic",
        "reason_code": "mandatory_gate_failed",
        "semantic_node_key": "build-core@plan:PLAN-STABLE",
        "lifecycle_stage": "implementation-slice",
        "failed_gate_ids": ["unit-tests"],
    }
    baseline = root_cause_key(stable)
    changed = {
        **stable,
        "task_id": task_id,
        "attempt_id": attempt_id,
        "plan_id": task_id,
        "hypothesis_id": hypothesis_id,
        "timestamp": attempt_id,
        "provider_wording": wording,
    }
    assert root_cause_key(changed) == baseline


@PROPERTY_SETTINGS
@given(
    digests=st.lists(
        st.binary(min_size=32, max_size=32).map(bytes.hex),
        min_size=6,
        max_size=6,
        unique=True,
    ),
    changed_index=st.integers(min_value=0, max_value=5),
    replacement=st.binary(min_size=32, max_size=32).map(bytes.hex),
)
def test_occurrence_identity_changes_when_any_epoch_coordinate_changes(
    digests: list[str],
    changed_index: int,
    replacement: str,
) -> None:
    keys = (
        "root_cause_key",
        "controller_release_digest",
        "candidate_snapshot_digest",
        "policy_digest",
        "contract_digest",
        "toolchain_manifest_digest",
    )
    baseline_values = dict(zip(keys, digests, strict=True))
    if replacement == digests[changed_index]:
        replacement = sha256_text(replacement)
    changed = dict(baseline_values)
    changed[keys[changed_index]] = replacement
    assert occurrence_epoch_key(changed) != occurrence_epoch_key(baseline_values)


@PROPERTY_SETTINGS
@given(
    suffix=st.text(
        alphabet=string.ascii_lowercase + string.digits + "_",
        min_size=1,
        max_size=40,
    )
)
def test_every_unregistered_failure_is_controller_quarantine(suffix: str) -> None:
    reason = f"unknown_property_{suffix}"
    if reason in FAILURE_CATALOG:
        return
    disposition = failure_disposition(reason)
    assert not disposition.registered
    assert disposition.owner == "controller"
    assert disposition.action is FailureAction.CONTROLLER_QUARANTINE
    assert not disposition.model_allowed


@PROPERTY_SETTINGS
@given(
    canonical=st.lists(
        st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=12).map(
            lambda value: f"capability.{value}"
        ),
        min_size=0,
        max_size=40,
        unique=True,
    ),
    parent_only=st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=12),
)
def test_capability_proof_never_unions_parent_or_model_capabilities(
    canonical: list[str],
    parent_only: str,
) -> None:
    extra = f"parent.{parent_only}"
    grants = [
        {
            "grant_id": f"G-{index}",
            "grant_epoch_id": "GE-1",
            "capability": capability,
            "provider": "property",
            "status": "AVAILABLE",
            "scope": {"allowed_operations": [capability]},
        }
        for index, capability in enumerate(canonical)
    ]
    grants.append(
        {
            "grant_id": "G-PARENT",
            "grant_epoch_id": "GE-PARENT",
            "capability": extra,
            "provider": "parent-lineage",
            "status": "AVAILABLE",
            "scope": {"allowed_operations": [extra]},
        }
    )
    proof = compile_capability_proof(
        task_id="T-PROPERTY",
        task_contract_digest="1" * 64,
        canonical_profile="property",
        canonical_capabilities=canonical,
        toolchain_manifest_digest="2" * 64,
        grants=grants,
        now="2026-08-03T00:00:00Z",
    )
    assert {grant.capability for grant in proof.grants} == set(canonical)
    assert extra not in {grant.capability for grant in proof.grants}


@pytest.mark.parametrize("wildcard", ("*", "**", "**/*"))
def test_every_unbounded_capability_scope_is_rejected(wildcard: str) -> None:
    with pytest.raises(ProofObligationError, match="unbounded"):
        compile_capability_proof(
            task_id="T-WILDCARD",
            task_contract_digest="1" * 64,
            canonical_profile="builder",
            canonical_capabilities=["repository.write"],
            toolchain_manifest_digest="2" * 64,
            grants=[
                {
                    "grant_id": "G-WILDCARD",
                    "grant_epoch_id": "GE-1",
                    "capability": "repository.write",
                    "provider": "property",
                    "status": "AVAILABLE",
                    "scope": {"allowed_paths": [wildcard]},
                }
            ],
            now="2026-08-03T00:00:00Z",
        )


@pytest.mark.parametrize("cardinality", CARDINALITIES)
def test_capability_resolver_has_no_cardinality_boundary(cardinality: int) -> None:
    capabilities = [f"property.capability.{index}" for index in range(cardinality)]
    proof = compile_capability_proof(
        task_id=f"T-CARDINALITY-{cardinality}",
        task_contract_digest="1" * 64,
        canonical_profile="property",
        canonical_capabilities=capabilities,
        toolchain_manifest_digest="2" * 64,
        grants=[
            {
                "grant_id": f"G-{index}",
                "grant_epoch_id": "GE-CARDINALITY",
                "capability": capability,
                "provider": "property",
                "status": "AVAILABLE",
                "scope": {"allowed_operations": [capability]},
            }
            for index, capability in enumerate(capabilities)
        ],
        now="2026-08-03T00:00:00Z",
    )
    assert len(proof.grants) == cardinality


@pytest.mark.parametrize("cardinality", CARDINALITIES)
def test_CARD_P0_transition_catalog_has_no_cardinality_boundary(
    cardinality: int,
) -> None:
    transitions = tuple(
        TransitionSpec(
            transition_id=f"cardinality-{index}",
            source=ProductState.IDEA_RECEIVED,
            event=f"CARDINALITY-{index}",
            target=ProductState.CONTRACT_DRAFTED,
            action=FailureAction.CONTINUE,
        )
        for index in range(cardinality)
    )
    index = build_transition_index(transitions)
    assert len(index) == cardinality
    assert all(
        index[(item.source, item.event, item.target)] is item
        for item in transitions
    )


@pytest.mark.parametrize("cardinality", CARDINALITIES)
def test_CARD_P0_transition_evidence_resolver_has_no_cardinality_boundary(
    cardinality: int,
) -> None:
    names = tuple(f"evidence-{index}" for index in range(cardinality))
    spec = TransitionSpec(
        transition_id=f"evidence-cardinality-{cardinality}",
        source=ProductState.IDEA_RECEIVED,
        event="CARDINALITY-EVIDENCE",
        target=ProductState.CONTRACT_DRAFTED,
        action=FailureAction.CONTINUE,
        required_evidence=names,
    )
    evidence = {name: f"evidence://{name}" for name in names}
    digest = TransitionKernel._validate_evidence(spec, evidence)
    assert len(digest) == 64
    if names:
        with pytest.raises(TransitionProofError, match=names[-1]):
            TransitionKernel._validate_evidence(
                spec,
                {name: evidence[name] for name in names[:-1]},
            )


def test_CARD_P0_duplicate_capability_sets_normalize_to_one_grant() -> None:
    proof = compile_capability_proof(
        task_id="T-DUPLICATE-CAPABILITY",
        task_contract_digest="1" * 64,
        canonical_profile="property",
        canonical_capabilities=["artifact.read", "artifact.read"],
        toolchain_manifest_digest="2" * 64,
        grants=[
            {
                "grant_id": "G-DUPLICATE-1",
                "grant_epoch_id": "GE-DUPLICATE",
                "capability": "artifact.read",
                "provider": "property",
                "status": "AVAILABLE",
                "scope": {"allowed_operations": ["artifact.read"]},
            },
            {
                "grant_id": "G-DUPLICATE-2",
                "grant_epoch_id": "GE-DUPLICATE",
                "capability": "artifact.read",
                "provider": "property",
                "status": "AVAILABLE",
                "scope": {"allowed_operations": ["artifact.read"]},
            },
        ],
        now="2026-08-03T00:00:00Z",
    )
    assert len(proof.grants) == 1
    assert proof.grants[0].grant_id == "G-DUPLICATE-1"


def test_every_side_effect_transition_has_explicit_evidence() -> None:
    assert all(
        item.required_evidence
        for item in TRANSITION_CATALOG
        if item.side_effect_allowed
    )
