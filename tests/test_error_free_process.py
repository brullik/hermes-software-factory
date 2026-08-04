"""P0 acceptance tests from the Hermes 2.4.0 error-free-process audit."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import sqlite3
import tarfile
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from factory import model_check, qualification_runner
from factory.autonomy import CAPABILITY_PROFILES
from factory.canary_qualification import (
    CanaryObservationError,
    load_canary_catalog,
    observe_completion,
    prove_fresh_state,
)
from factory.common import sha256_file, sha256_text, stable_json
from factory.delivery_profiles import DELIVERY_PROFILES
from factory.failure_catalog import (
    FAILURE_CATALOG,
    FailureAction,
    assert_catalog_total,
    discover_runtime_reason_literals,
)
from factory.failure_router import ContractIntegrityError, FailureRouter
from factory.migration_qualification import run_migration_matrix
from factory.model_check import check_transition_catalog
from factory.mutation_qualification import run_mutation_suite
from factory.path_governor import (
    PathGovernor,
    ProgressVector,
    failure_owner,
    occurrence_epoch_key,
    root_cause_key,
)
from factory.plan_compiler import CompileContext, PlanCompiler
from factory.plan_semantics import validate_compiled_plan
from factory.proof_obligations import (
    DecisionArchiveService,
    ProofObligationError,
    SideEffectProtocol,
    build_completion_manifest,
    profile_not_applicable_proof,
)
from factory.qualification_runner import (
    QualificationRunError,
    _immutable_release_tree_digest,
    _reproducible_wheel,
)
from factory.release_qualification import (
    REQUIRED_CANARY_SCENARIOS,
    QualificationError,
    QualificationThresholds,
    ReleaseQualificationGovernor,
    verify_qualification_manifest_envelope,
)
from factory.scenario_corpus import ScenarioError, load_scenario, replay_corpus
from factory.service_qualification import (
    ServiceQualificationError,
    _load_q6_container_attestation,
)
from factory.shadow_feed import evaluate_candidate_batches, export_stable_events
from factory.shadow_qualification import ShadowEvidenceJournal, ShadowJournalError
from factory.state import StateStore
from factory.transition_catalog import ProductState, TransitionSpec
from factory.transition_kernel import TransitionKernel, TransitionProofError
from factory.two_plane import (
    PlaneBoundary,
    PlaneIsolationError,
    ShadowDifferentialLab,
    TwoPlaneLayout,
)
from scripts import qualification_control
from scripts.qualification_control import initialize_epoch, verify_shadow_batches
from scripts.qualification_control import status as qualification_status
from scripts.release_qualify import VerifierConfigurationError, sign_qualification

_TEST_VERIFIER_PUBLIC_BYTES = b"v" * 32
_TEST_VERIFIER_PUBLIC_KEY = base64.b64encode(_TEST_VERIFIER_PUBLIC_BYTES).decode("ascii")
_TEST_VERIFIER_KEY_DIGEST = hashlib.sha256(_TEST_VERIFIER_PUBLIC_BYTES).hexdigest()


def _progress(seed: int = 0) -> ProgressVector:
    return ProgressVector(1, 1, 1, 0, 1, seed, seed)


def _qualify_to_clean_canary(
    governor: ReleaseQualificationGovernor,
    epoch_id: str,
    *,
    include_q7: bool = True,
) -> None:
    metrics = {
        "Q0_SOURCE_INTEGRITY": {
            "unknown_transitions": 0,
            "clean_commit": True,
            "version_manifest_sbom_consistent": True,
            "dependency_lock_present": True,
            "secret_scan_findings": 0,
            "reproducible_artifact_digest": "a" * 64,
        },
        "Q1_STATIC_CONTRACTS": {
            "unknown_transitions": 0,
            "transition_coverage_percent": 100,
            "schemas_valid": True,
            "capability_catalog_total": True,
            "failure_catalog_total": True,
            "lifecycle_profile_total": True,
            "mypy_errors": 0,
            "ruff_errors": 0,
            "permissive_fallbacks": 0,
        },
        "Q2_MODEL_CHECKING": {
            "unknown_transitions": 0,
            "model_checked": True,
            "bounded_model_states": 1,
            "unsafe_terminal_states": 0,
            "unranked_cycles": 0,
            "duplicate_side_effect_paths": 0,
        },
        "Q3_PROPERTY_AND_MUTATION": {
            "unknown_transitions": 0,
            "mutation_score_percent": 90,
            "property_examples": 1,
            "property_failures": 0,
        },
        "Q4_HISTORICAL_REPLAY": {
            "unknown_transitions": 0,
            "historical_replay_percent": 100,
            "historical_fixture_count": 1,
            "historical_replay_failures": 0,
        },
        "Q5_MIGRATION_MATRIX": {
            "unknown_transitions": 0,
            "migration_matrix_percent": 100,
            "migration_fixture_count": 1,
            "migration_fixup_count": 0,
            "backup_restore_verified": True,
        },
        "Q6_SERVICE_E2E": {
            "unknown_transitions": 0,
            "manual_database_mutations": 0,
            "duplicate_side_effects": 0,
            "controller_defects": 0,
            "candidate_production_credentials": 0,
            "candidate_writes_to_stable_db": 0,
            "service_scenarios": 1,
            "controller_processes": 1,
            "worker_processes": 1,
        },
        "Q7_SHADOW_DIFFERENTIAL": {
            "unknown_transitions": 0,
            "shadow_hours": 72,
            "shadow_incidents": 0,
            "unknown_controller_failures": 0,
            "duplicate_side_effects": 0,
            "candidate_side_effect_executions": 0,
            "candidate_production_credentials": 0,
            "candidate_writes_to_stable_db": 0,
            "candidate_shadow_state_writes": 0,
            "historical_products_total": 12,
            "historical_products_replayed": 12,
            "shadow_event_count": 1,
            "shadow_batch_count": 1,
            "task_amplification_ratio": 1.0,
            "max_evidence_indirection": 1,
        },
    }
    for stage, stage_metrics in metrics.items():
        if stage == "Q7_SHADOW_DIFFERENTIAL" and not include_q7:
            break
        if stage == "Q7_SHADOW_DIFFERENTIAL":
            governor.connection.execute(
                """UPDATE controller_release_epochs
                      SET shadow_started_at='2020-01-01T00:00:00Z'
                    WHERE epoch_id=?""",
                (epoch_id,),
            )
            governor.compare_shadow_decision(
                epoch_id=epoch_id,
                event_digest="9" * 64,
                stable_decision={"action": "CONTINUE"},
                candidate_decision={"action": "CONTINUE"},
            )
        governor.record_qualification(
            epoch_id=epoch_id,
            stage=stage,
            evidence_ref=f"evidence://qualification/{stage.lower()}",
            metrics=stage_metrics,
            passed=True,
        )


def test_p0_unknown_reason_is_controller_quarantine() -> None:
    assert (
        failure_owner(
            failure_class="semantic",
            reason_code="not_registered_anywhere",
        )
        == "controller"
    )


def test_p0_repair_capabilities_do_not_union_parent_lineage() -> None:
    assert not hasattr(FailureRouter, "_lineage_required_capabilities")
    assert sorted(CAPABILITY_PROFILES["test_workspace"]) == sorted(
        {
            "artifact.read",
            "artifact.write",
            "command.execute_allowlisted",
            "repository.read",
            "repository.write_tests_scoped",
            "test.execute",
        }
    )


def test_p0_missing_write_contract_never_reconstructs_wildcard(tmp_path: Path) -> None:
    router = object.__new__(FailureRouter)
    router.config = SimpleNamespace(evidence_dir=tmp_path)
    task = {
        "task_id": "T-MISSING",
        "product_id": "P-1",
        "contract_ref": "evidence/task-T-MISSING.json",
        "capability_profile": "builder_workspace",
    }

    with pytest.raises(ContractIntegrityError):
        router._contract(task)


def test_p0_root_cause_is_stable_but_occurrence_changes_by_epoch() -> None:
    first = {
        "product_id": "P-1",
        "failure_class": "semantic",
        "reason_code": "mandatory_gate_failed",
        "semantic_node_key": "build-core@plan:PLAN-A",
        "lifecycle_stage": "implementation-slice",
        "failed_gate_ids": ["unit-tests"],
        "task_id": "T-1",
        "attempt_id": "A-1",
        "hypothesis_id": "H-1",
        "provider_wording": "first wording",
    }
    second = {
        **first,
        "semantic_node_key": "build-core@plan:PLAN-B",
        "task_id": "T-2",
        "attempt_id": "A-2",
        "hypothesis_id": "H-2",
        "provider_wording": "different wording",
    }
    cause_a = root_cause_key(first)
    cause_b = root_cause_key(second)
    assert cause_a == cause_b

    shared = {
        "root_cause_key": cause_a,
        "candidate_snapshot_digest": "1" * 64,
        "policy_digest": "2" * 64,
        "contract_digest": "3" * 64,
        "toolchain_manifest_digest": "4" * 64,
    }
    assert occurrence_epoch_key(
        {**shared, "controller_release_digest": "5" * 64}
    ) != occurrence_epoch_key(
        {**shared, "controller_release_digest": "6" * 64}
    )


def test_p0_first_controller_defect_fails_release_epoch(tmp_path: Path) -> None:
    state = StateStore(tmp_path / "controller.db")
    try:
        governor = ReleaseQualificationGovernor(state._connection)
        epoch_id = governor.create_epoch(
            source_commit="0" * 40,
            controller_release_digest="1" * 64,
            candidate_digest="2" * 64,
            policy_digest="3" * 64,
            toolchain_manifest_digest="4" * 64,
            stable_release_digest="5" * 64,
        )
        _qualify_to_clean_canary(governor, epoch_id)
        canary_id = governor.start_clean_canary(
            epoch_id=epoch_id,
            scenario_id="zero-dependency-cli",
            state_fresh_proof_ref="evidence://canary/fresh/cli",
            initial_state_digest="6" * 64,
        )

        governor.record_controller_defect(
            epoch_id=epoch_id,
            canary_id=canary_id,
            reason_code="unknown_transition",
            evidence_ref="evidence://controller-defect/1",
        )

        assert governor.epoch(epoch_id)["status"] == "QUALIFICATION_FAILED"
        assert governor.clean_canary(canary_id)["status"] == "REJECTED"
    finally:
        state.close()


def test_p0_active_product_with_terminal_reason_is_rejected(tmp_path: Path) -> None:
    state = StateStore(tmp_path / "controller.db")
    try:
        state.create_product(
            product_id="P-1",
            owner_id="owner",
            source="test",
            idea="test",
            idempotency_key="p0-terminal-invariant",
        )
        with pytest.raises(sqlite3.IntegrityError), state._connection:
            state._connection.execute(
                "UPDATE products SET terminal_reason='stale' WHERE product_id='P-1'"
            )
    finally:
        state.close()


def test_catalog_transition_without_required_evidence_is_rejected(
    tmp_path: Path,
) -> None:
    state = StateStore(tmp_path / "controller.db")
    try:
        state.create_product(
            product_id="P-MISSING-EVIDENCE",
            owner_id="owner",
            source="test",
            idea="proof",
            idempotency_key="missing-transition-evidence",
        )
        with pytest.raises(TransitionProofError, match="lacks evidence"), state._connection:
            TransitionKernel(state._connection).apply_product(
                product_id="P-MISSING-EVIDENCE",
                target="RISK_CLASSIFIED",
                event="CONTRACT_AND_RISK_PROVEN",
                evidence={},
            )
    finally:
        state.close()


def test_p0_decision_history_is_append_only_without_archive_receipt(
    tmp_path: Path,
) -> None:
    state = StateStore(tmp_path / "controller.db")
    try:
        state.create_product(
            product_id="P-1",
            owner_id="owner",
            source="test",
            idea="test",
            idempotency_key="p0-history",
        )
        governor = PathGovernor(state._connection, policy_digest="a" * 64)
        for index in range(260):
            governor.record_decision(
                product_id="P-1",
                root_problem_signature=None,
                action="CONTINUE",
                path_snapshot_digest=sha256_text(f"snapshot-{index}"),
                progress_before=_progress(index),
                expected_progress_after=_progress(index),
                evidence_digest=sha256_text(f"evidence-{index}"),
                max_history=256,
            )
        count = state._connection.execute(
            "SELECT COUNT(*) FROM path_decisions WHERE product_id='P-1'"
        ).fetchone()[0]
        assert count == 260
    finally:
        state.close()


def test_p0_clean_canary_rejects_any_recovery_application(tmp_path: Path) -> None:
    state = StateStore(tmp_path / "controller.db")
    try:
        governor = ReleaseQualificationGovernor(state._connection)
        epoch_id = governor.create_epoch(
            source_commit="0" * 40,
            controller_release_digest="1" * 64,
            candidate_digest="2" * 64,
            policy_digest="3" * 64,
            toolchain_manifest_digest="4" * 64,
            stable_release_digest="5" * 64,
        )
        _qualify_to_clean_canary(governor, epoch_id)
        canary_id = governor.start_clean_canary(
            epoch_id=epoch_id,
            scenario_id="small-python-service",
            state_fresh_proof_ref="evidence://canary/fresh/service",
            initial_state_digest="6" * 64,
        )
        governor.record_recovery_application(
            epoch_id=epoch_id,
            canary_id=canary_id,
            recovery_ref="evidence://recovery/1",
        )
        with pytest.raises(QualificationError):
            governor.complete_clean_canary(
                epoch_id=epoch_id,
                canary_id=canary_id,
                terminal_status="COMPLETED",
                completion_manifest_ref="evidence://completion/1",
                product_id="rejected-canary",
                observation_evidence_ref="evidence://canary/observation/rejected",
                observation_digest="7" * 64,
            )
    finally:
        state.close()


@pytest.mark.parametrize("profile", sorted(item.value for item in DELIVERY_PROFILES))
def test_all_delivery_profiles_compile_to_exact_closed_lifecycle(
    profile: str,
) -> None:
    proposal = {
        "schema_version": "1.0",
        "artifact_id": "proposal-profile",
        "product_id": f"P-{profile}",
        "policy_digest": "a" * 64,
        "status": "completed",
        "proposal_kind": "initial",
        "parent_plan_id": None,
        "source_failure_id": None,
        "created_at": "2026-08-03T00:00:00Z",
        "producer": {"role": "task-specifier", "tier": "luna"},
        "goals": [
            {"goal_id": "root-goal", "statement": "Deliver", "mandatory": True}
        ],
        "nodes": [
            {
                "node_key": "core",
                "stage_kind": "implementation_slice",
                "title": "Implement core",
                "objective": "Implement the bounded product core",
                "depends_on": [],
                "scope": ["src/**", "tests/**"],
                "acceptance_intents": ["The product core is proven."],
                "goal_ids": ["root-goal"],
            }
        ],
        "summary": "Bounded profile plan",
        "evidence_refs": ["evidence/architecture.json"],
    }
    compiled = PlanCompiler(policy_digest="a" * 64).compile(
        proposal,
        CompileContext(
            product_id=f"P-{profile}",
            revision=1,
            parent_plan_id=None,
            source_failure_id=None,
            created_by_task_id="T-SPEC",
            root_task_id="T-ROOT",
            root_context_ref="evidence/intake.json",
            external_repository=False,
            proposal_artifact_ref="evidence/proposal.json",
            delivery_profile=profile,
        ),
    )
    validate_compiled_plan(compiled)
    expected = next(
        value for key, value in DELIVERY_PROFILES.items() if key.value == profile
    )
    assert compiled["delivery_profile"] == profile
    assert tuple(
        node["task_contract"]["lifecycle_stage"] for node in compiled["nodes"]
    ) == expected.lifecycle
    assert expected.required_capabilities
    assert expected.evidence_types
    if not expected.production_authority_required:
        assert "production.deploy_transactional" not in expected.required_capabilities
        assert "backup.verify" not in expected.required_capabilities


def test_staging_only_profile_never_preflights_production_authority() -> None:
    from factory.capabilities import CapabilityBroker

    capabilities = CapabilityBroker.required_for_product(
        {
            "delivery_profile": "STAGING_ONLY_PROTOTYPE",
            "delivery_mode": "new_repository",
        }
    )
    assert "staging.deploy" in capabilities
    assert "production.deploy_transactional" not in capabilities
    assert "rollback.execute" not in capabilities
    assert "backup.verify" not in capabilities


def test_decision_compaction_requires_verified_worm_readback(tmp_path: Path) -> None:
    state = StateStore(tmp_path / "controller.db")
    try:
        state.create_product(
            product_id="P-ARCHIVE",
            owner_id="owner",
            source="test",
            idea="archive",
            idempotency_key="archive",
        )
        governor = PathGovernor(state._connection, policy_digest="a" * 64)
        for index in range(2):
            governor.record_decision(
                product_id="P-ARCHIVE",
                root_problem_signature=None,
                action="CONTINUE",
                path_snapshot_digest=sha256_text(f"snapshot-{index}"),
                progress_before=_progress(index),
                expected_progress_after=_progress(index),
                evidence_digest=sha256_text(f"evidence-{index}"),
            )
        service = DecisionArchiveService(state._connection)
        manifest = service.build(product_id="P-ARCHIVE")
        tampered = manifest.payload()
        tampered["product_id"] = "P-OTHER"
        with pytest.raises(ProofObligationError, match="readback"):
            service.confirm_export(
                manifest=manifest,
                readback_payload=tampered,
                archive_ref="b2://bucket/path/archive.json",
                export_checkpoint="a" * 64,
                archive_receipt_ref="b2://bucket/path/archive.receipt",
            )
        archive_id = service.confirm_export(
            manifest=manifest,
            readback_payload=manifest.payload(),
            archive_ref="b2://bucket/path/archive.json",
            export_checkpoint="a" * 64,
            archive_receipt_ref="b2://bucket/path/archive.receipt",
        )
        assert service.compact(archive_id=archive_id) == 2
    finally:
        state.close()


def test_side_effect_intent_receipt_is_replay_safe_and_conflict_closed(
    tmp_path: Path,
) -> None:
    state = StateStore(tmp_path / "controller.db")
    try:
        protocol = SideEffectProtocol(state._connection)
        expected = {"product_id": "P-1", "stage": "staging"}
        intent_id = protocol.prepare(
            product_id="P-1",
            operation="release:staging",
            adapter="fixture",
            idempotency_key="effect-once",
            expected_postcondition=expected,
        )
        protocol.mark_executing(intent_id)
        result = {"status": "completed", "effect_id": "external-1"}
        digest = sha256_text(stable_json(result))
        protocol.verify(
            intent_id=intent_id,
            receipt_ref="evidence/receipt.json",
            receipt_digest=digest,
            observed_postcondition=expected,
            result=result,
        )
        assert protocol.verified_result(intent_id) == result
        protocol.mark_executing(intent_id)
        protocol.verify(
            intent_id=intent_id,
            receipt_ref="evidence/receipt.json",
            receipt_digest=digest,
            observed_postcondition=expected,
            result=result,
        )
        with pytest.raises(ProofObligationError, match="conflicts"):
            protocol.verify(
                intent_id=intent_id,
                receipt_ref="evidence/other.json",
                receipt_digest=sha256_text("different"),
                observed_postcondition=expected,
                result={"status": "completed", "effect_id": "external-2"},
            )
    finally:
        state.close()


def test_completion_not_applicable_reference_is_profile_bound_and_verified() -> None:
    profile = DELIVERY_PROFILES[next(iter(sorted(DELIVERY_PROFILES, key=lambda item: item.value)))]
    proof = profile_not_applicable_proof(
        product_id="P-PROFILE",
        delivery_profile=profile.name.value,
        delivery_profile_digest=profile.digest,
        obligation="rollback_restore_ref",
        acceptable_substitutes=("rollback",),
    )
    arguments = {
        "product_id": "P-PROFILE",
        "delivery_profile": profile.name.value,
        "delivery_profile_digest": profile.digest,
        "product_contract_digest": "1" * 64,
        "semantic_graph_digest": "2" * 64,
        "candidate_snapshot_digest": "3" * 64,
        "pr_checks_ref": "evidence://checks/1",
        "staging_ref": "evidence://staging/1",
        "acceptance_ref": "evidence://acceptance/1",
        "production_ref": "evidence://production/1",
        "rollback_restore_ref": proof["evidence_ref"],
        "observation_ref": "evidence://observation/1",
        "controller_release_digest": "4" * 64,
        "policy_digest": "5" * 64,
        "open_problem_count": 0,
        "open_controller_incident_count": 0,
        "not_applicable_proofs": [proof],
        "created_at": "2026-08-03T00:00:00Z",
    }
    manifest = build_completion_manifest(**arguments)
    assert manifest.rollback_restore_ref == proof["evidence_ref"]
    tampered = dict(proof)
    tampered["delivery_profile"] = "DEPLOYED_SERVICE"
    with pytest.raises(ProofObligationError, match="identity"):
        build_completion_manifest(**{**arguments, "not_applicable_proofs": [tampered]})


def test_closed_transition_model_is_deterministic_bounded_and_terminal_reachable() -> None:
    report = check_transition_catalog()
    assert report.state_event_coverage_percent == 100
    assert report.terminal_reachable_states > 0
    assert report.cyclic_components > 0
    assert report.side_effect_transitions > 0
    assert report.bounded_state_count > 0
    assert report.composed_state_count > report.bounded_state_count
    assert report.product_bounds == (1, 2)
    assert report.worker_bounds == (1, 2)
    assert report.node_bounds == (0, 1, 2, 3, 4)
    assert report.retry_bound == 2
    assert report.crash_bound == 1
    assert report.deadlock_count == 0
    assert report.livelock_count == 0
    assert report.duplicate_side_effect_count == 0
    assert report.evidence_free_pass_count == 0


def test_model_checker_rejects_a_cycle_without_ranking_function(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mutant = TransitionSpec(
        transition_id="mutant_unranked_terminal_cycle",
        source=ProductState.COMPLETED,
        event="MUTANT_LOOP",
        target=ProductState.COMPLETED,
        action=FailureAction.CONTINUE,
    )
    monkeypatch.setattr(
        model_check,
        "TRANSITION_CATALOG",
        (*model_check.TRANSITION_CATALOG, mutant),
    )
    with pytest.raises(model_check.ModelCheckError, match="ranking"):
        model_check.check_transition_catalog()


def test_historical_incident_corpus_replays_all_audited_failures() -> None:
    root = Path(__file__).parents[1] / "qualification" / "historical"
    report = replay_corpus(root)

    assert report.fixture_count == 11
    assert report.represented_incident_count == 1814
    assert report.passed_count == report.fixture_count
    assert report.failed_count == 0
    assert report.replay_percent == 100
    assert report.decision_count == report.fixture_count
    assert report.unknown_transition_count == 0
    assert report.unregistered_reason_count == 1
    assert len(report.corpus_digest) == 64


def test_historical_scenario_dsl_rejects_filename_identity_mismatch(
    tmp_path: Path,
) -> None:
    source = (
        Path(__file__).parents[1]
        / "qualification"
        / "historical"
        / "schema-validation-2.2.x.yaml"
    )
    mismatched = tmp_path / "different-id.yaml"
    mismatched.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    with pytest.raises(ScenarioError, match="filename"):
        load_scenario(mismatched)


def test_all_schema_versions_upgrade_crash_replay_and_restore(tmp_path: Path) -> None:
    report = run_migration_matrix(
        tmp_path / "migration-matrix",
        include_production_shape=False,
    )

    assert report.fixture_count == 18
    assert report.passed_count == 18
    assert report.failed_count == 0
    assert report.migration_matrix_percent == 100
    assert report.migration_fixup_count == 0
    assert report.backup_restore_passed
    assert all(item.crash_rollback_passed for item in report.fixtures)
    assert all(item.idempotent_restart_passed for item in report.fixtures)
    assert all(item.identity_digest_preserved for item in report.fixtures)
    assert all(item.no_scope_expansion for item in report.fixtures)


def test_audited_production_shape_migrates_with_exact_cardinality(
    tmp_path: Path,
) -> None:
    report = run_migration_matrix(
        tmp_path / "production-migration-matrix",
        include_production_shape=True,
    )

    assert report.fixture_count == 19
    assert report.passed_count == 19
    assert report.production_shape_passed
    assert report.production_shape_counts == {
        "products": 12,
        "tasks": 10536,
        "attempts": 1777,
        "events": 20700,
        "outbox": 4929,
    }


def test_required_kernel_mutations_score_at_least_ninety_percent(
    tmp_path: Path,
) -> None:
    report = run_mutation_suite(
        Path(__file__).parents[1],
        tmp_path / "mutations",
    )

    assert report.baseline_passed
    assert report.mutation_count == 9
    assert report.killed_count >= 9
    assert report.survived_count == 0
    assert report.mutation_score_percent >= 90


def test_shadow_decisions_are_append_only_and_conflict_fails_epoch(tmp_path: Path) -> None:
    state = StateStore(tmp_path / "controller.db")
    try:
        governor = ReleaseQualificationGovernor(state._connection)
        epoch_id = governor.create_epoch(
            source_commit="0" * 40,
            controller_release_digest="1" * 64,
            candidate_digest="2" * 64,
            policy_digest="3" * 64,
            toolchain_manifest_digest="4" * 64,
            stable_release_digest="5" * 64,
        )
        event_digest = "9" * 64
        stable = {"action": "CONTINUE"}
        assert governor.compare_shadow_decision(
            epoch_id=epoch_id,
            event_digest=event_digest,
            stable_decision=stable,
            candidate_decision=stable,
        ) == "MATCH"
        assert governor.compare_shadow_decision(
            epoch_id=epoch_id,
            event_digest=event_digest,
            stable_decision=stable,
            candidate_decision=stable,
        ) == "MATCH"
        with pytest.raises(QualificationError, match="append-only"):
            governor.compare_shadow_decision(
                epoch_id=epoch_id,
                event_digest=event_digest,
                stable_decision=stable,
                candidate_decision={"action": "FAIL_SAFE"},
            )
        assert governor.epoch(epoch_id)["status"] == "QUALIFICATION_FAILED"
    finally:
        state.close()


def test_promotion_rejects_digest_other_than_exact_candidate(tmp_path: Path) -> None:
    state = StateStore(tmp_path / "controller.db")
    try:
        governor = ReleaseQualificationGovernor(state._connection)
        epoch_id = governor.create_epoch(
            source_commit="0" * 40,
            controller_release_digest="1" * 64,
            candidate_digest="2" * 64,
            policy_digest="3" * 64,
            toolchain_manifest_digest="4" * 64,
            stable_release_digest="5" * 64,
        )
        _qualify_to_clean_canary(governor, epoch_id)
        for scenario_id in sorted(REQUIRED_CANARY_SCENARIOS):
            canary_id = governor.start_clean_canary(
                epoch_id=epoch_id,
                scenario_id=scenario_id,
                state_fresh_proof_ref=f"evidence://canary/fresh/{scenario_id}",
                initial_state_digest="6" * 64,
            )
            governor.complete_clean_canary(
                epoch_id=epoch_id,
                canary_id=canary_id,
                terminal_status="COMPLETED",
                completion_manifest_ref=f"evidence://canary/{scenario_id}",
                product_id=f"product-{scenario_id}",
                observation_evidence_ref=f"evidence://canary/observation/{scenario_id}",
                observation_digest="7" * 64,
                task_count=1,
                baseline_task_count=1,
            )
        with pytest.raises(QualificationError, match="does not match candidate"):
            governor.promote(
                epoch_id=epoch_id,
                manifest_id="RQM-NOT-REACHED",
                caller_plane="LTS_A",
                root_helper_receipt_ref="evidence://root-helper/receipt",
                exact_staging_production_digest="9" * 64,
            )
    finally:
        state.close()


def test_independent_manifest_requires_trusted_ed25519_signature(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_key = base64.b64encode(public_key_bytes).decode("ascii")
    trust_digest = hashlib.sha256(public_key_bytes).hexdigest()
    state = StateStore(tmp_path / "controller.db")
    try:
        governor = ReleaseQualificationGovernor(
            state._connection,
            trusted_verifier_public_key_digest=trust_digest,
        )
        epoch_id = governor.create_epoch(
            source_commit="0" * 40,
            controller_release_digest="1" * 64,
            candidate_digest="2" * 64,
            policy_digest="3" * 64,
            toolchain_manifest_digest="4" * 64,
            stable_release_digest="5" * 64,
        )
        _qualify_to_clean_canary(governor, epoch_id)
        for scenario_id in sorted(REQUIRED_CANARY_SCENARIOS):
            canary_id = governor.start_clean_canary(
                epoch_id=epoch_id,
                scenario_id=scenario_id,
                state_fresh_proof_ref=f"evidence://canary/fresh/{scenario_id}",
                initial_state_digest="6" * 64,
            )
            governor.complete_clean_canary(
                epoch_id=epoch_id,
                canary_id=canary_id,
                terminal_status="COMPLETED",
                completion_manifest_ref=f"evidence://canary/{scenario_id}",
                product_id=f"product-{scenario_id}",
                observation_evidence_ref=f"evidence://canary/observation/{scenario_id}",
                observation_digest="7" * 64,
                task_count=1,
                baseline_task_count=1,
            )
        arguments = {
            "epoch_id": epoch_id,
            "verifier_digest": "6" * 64,
            "verifier_public_key": public_key,
            "transition_model_digest": "7" * 64,
            "historical_corpus_digest": "8" * 64,
            "migration_matrix_digest": "9" * 64,
            "manifest_ref": "worm://qualification/manifest.json",
            "backup_restore_proof_ref": "b2://proofs/backup-restore.json",
            "rollback_proof_ref": "evidence://proofs/rollback.json",
            "shadow_report_ref": "evidence://proofs/shadow.json",
        }
        payload = governor.qualification_manifest_payload(**arguments)
        signature = base64.b64encode(
            private_key.sign(stable_json(payload).encode("utf-8"))
        ).decode("ascii")
        with pytest.raises(QualificationError, match="signature is invalid"):
            governor.create_qualification_manifest(
                **arguments,
                verifier_signature=base64.b64encode(b"x" * 64).decode("ascii"),
            )
        manifest_id = governor.create_qualification_manifest(
            **arguments,
            verifier_signature=signature,
        )
        envelope = {**payload, "verifier_signature": signature}
        assert len(
            verify_qualification_manifest_envelope(
                envelope,
                trusted_verifier_public_key_digest=trust_digest,
                expected_source_commit="0" * 40,
                expected_candidate_digest="2" * 64,
            )
        ) == 64
        private_path = tmp_path / "verifier.key"
        private_path.write_text(
            base64.b64encode(
                private_key.private_bytes(
                    Encoding.Raw,
                    PrivateFormat.Raw,
                    NoEncryption(),
                )
            ).decode("ascii")
            + "\n",
            encoding="ascii",
        )
        private_path.chmod(0o600)
        request_path = tmp_path / "unsigned-manifest.json"
        request_path.write_text(
            json.dumps(payload, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        output_path = tmp_path / "signed-manifest.json"
        config_path = tmp_path / "verifier.yaml"
        config_path.write_text(
            yaml.safe_dump(
                {
                    "schema_version": "1.0",
                    "request_path": str(request_path),
                    "output_path": str(output_path),
                    "private_key_path": str(private_path),
                    "trusted_public_key_digest": trust_digest,
                    "expected_source_commit": "0" * 40,
                    "expected_candidate_digest": "2" * 64,
                    "verifier_digest": "6" * 64,
                    "manifest_install_root": str(tmp_path / "installed"),
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        config_path.chmod(0o600)
        with pytest.raises(
            VerifierConfigurationError,
            match="verifier config is not root-owned read-only",
        ):
            sign_qualification(config_path, config_trust_policy=lambda _path: False)
        signed_path, independent_digest = sign_qualification(
            config_path,
            config_trust_policy=lambda _path: True,
        )
        assert signed_path == output_path
        assert len(independent_digest) == 64
        assert json.loads(output_path.read_text(encoding="utf-8")) == envelope
        with pytest.raises(QualificationError, match="candidate digest differs"):
            verify_qualification_manifest_envelope(
                envelope,
                trusted_verifier_public_key_digest=trust_digest,
                expected_source_commit="0" * 40,
                expected_candidate_digest="a" * 64,
            )
        row = state._connection.execute(
            "SELECT * FROM release_qualification_manifests WHERE manifest_id=?",
            (manifest_id,),
        ).fetchone()
        assert row is not None
        assert row["signature_algorithm"] == "Ed25519"
        assert row["verifier_public_key_digest"] == trust_digest
    finally:
        state.close()


def test_runtime_failure_reason_catalog_is_total() -> None:
    emitted = discover_runtime_reason_literals(Path(__file__).parents[1] / "factory")
    assert emitted <= set(FAILURE_CATALOG)
    assert_catalog_total(emitted)


def test_candidate_shadow_has_distinct_state_credentials_and_zero_authority(
    tmp_path: Path,
) -> None:
    layout = TwoPlaneLayout(
        stable_a=PlaneBoundary(
            "LTS_A",
            tmp_path / "stable",
            tmp_path / "stable" / "controller.db",
            frozenset({"stable-production-credential"}),
            True,
            True,
        ),
        candidate_b=PlaneBoundary(
            "CANDIDATE_B",
            tmp_path / "candidate",
            tmp_path / "candidate" / "controller.db",
            frozenset({"candidate-readonly-credential"}),
            False,
            False,
        ),
        verifier=PlaneBoundary(
            "INDEPENDENT_VERIFIER",
            tmp_path / "verifier",
            tmp_path / "verifier" / "verifier.db",
            frozenset(),
            False,
            False,
        ),
    )
    layout.validate()
    state = StateStore(tmp_path / "governor.db")
    try:
        governor = ReleaseQualificationGovernor(state._connection)
        epoch_id = governor.create_epoch(
            source_commit="0" * 40,
            controller_release_digest="1" * 64,
            candidate_digest="2" * 64,
            policy_digest="3" * 64,
            toolchain_manifest_digest="4" * 64,
            stable_release_digest="5" * 64,
        )

        def decide(event: Mapping[str, object]) -> Mapping[str, object]:
            digest = sha256_text(stable_json(event))
            return {
                "chosen_transition": "CONTROLLER_QUARANTINE",
                "failure_owner": "controller",
                "capability_proof_digest": digest,
                "root_cause_key": sha256_text("root:" + digest),
                "task_count": 0,
                "side_effect_intent": None,
                "terminal_result": "FAILED_SAFE",
            }

        report = ShadowDifferentialLab(
            layout=layout,
            governor=governor,
            epoch_id=epoch_id,
            stable_decide=decide,
            candidate_decide=decide,
        ).replay(
            [
                {
                    "event": "unknown",
                    "diagnostic": "ghp_" + ("1" * 30),
                }
            ]
        )
        assert report.event_count == 1
        assert report.matched_count == 1
        assert report.diverged_count == 0
        assert report.redaction_count == 1
        assert report.candidate_side_effect_count == 0
        assert report.stable_write_count == 0
        assert report.candidate_write_count == 0
    finally:
        state.close()


def test_two_plane_layout_rejects_shared_credential_fingerprint(
    tmp_path: Path,
) -> None:
    shared = frozenset({"shared"})
    layout = TwoPlaneLayout(
        PlaneBoundary("LTS_A", tmp_path / "a", tmp_path / "a.db", shared, True, True),
        PlaneBoundary("CANDIDATE_B", tmp_path / "b", tmp_path / "b.db", shared, False, False),
        PlaneBoundary(
            "INDEPENDENT_VERIFIER",
            tmp_path / "v",
            tmp_path / "v.db",
            frozenset(),
            False,
            False,
        ),
    )
    with pytest.raises(PlaneIsolationError, match="share a credential"):
        layout.validate()


def test_shadow_journal_derives_q7_metrics_and_rejects_tampering(tmp_path: Path) -> None:
    layout = TwoPlaneLayout(
        PlaneBoundary("LTS_A", tmp_path / "a", tmp_path / "a.db", frozenset(), True, True),
        PlaneBoundary(
            "CANDIDATE_B", tmp_path / "b", tmp_path / "b.db", frozenset(), False, False
        ),
        PlaneBoundary(
            "INDEPENDENT_VERIFIER",
            tmp_path / "v",
            tmp_path / "v.db",
            frozenset(),
            False,
            False,
        ),
    )
    state = StateStore(tmp_path / "governor.db")
    try:
        governor = ReleaseQualificationGovernor(
            state._connection,
            thresholds=QualificationThresholds(minimum_shadow_hours=0),
        )
        epoch_id = governor.create_epoch(
            source_commit="0" * 40,
            controller_release_digest="1" * 64,
            candidate_digest="2" * 64,
            policy_digest="3" * 64,
            toolchain_manifest_digest="4" * 64,
            stable_release_digest="5" * 64,
        )
        _qualify_to_clean_canary(governor, epoch_id, include_q7=False)

        def decide(event: Mapping[str, object]) -> Mapping[str, object]:
            digest = sha256_text(stable_json(event))
            return {
                "chosen_transition": "CONTINUE",
                "failure_owner": "product",
                "capability_proof_digest": digest,
                "root_cause_key": sha256_text("root:" + digest),
                "task_count": 1,
                "side_effect_intent": None,
                "terminal_result": "IMPLEMENTING",
            }

        report = ShadowDifferentialLab(
            layout=layout,
            governor=governor,
            epoch_id=epoch_id,
            stable_decide=decide,
            candidate_decide=decide,
        ).replay([{"event": "task_created"}])
        journal = ShadowEvidenceJournal(tmp_path / "journal", epoch_id=epoch_id)
        journal.append(report)
        run_id = journal.finalize_q7(
            governor,
            evidence_ref="evidence://qualification/shadow/1",
            historical_products_total=1,
            historical_products_replayed=1,
        )
        assert run_id.startswith("QR-")
        assert governor.epoch(epoch_id)["status"] == "CLEAN_CANARY"

        entry = next((tmp_path / "journal").glob("*.json"))
        entry.chmod(0o644)
        tampered = json.loads(entry.read_text(encoding="utf-8"))
        tampered["report"]["matched_count"] = 0
        entry.write_text(json.dumps(tampered), encoding="utf-8")
        with pytest.raises(ShadowJournalError, match="digest"):
            journal.summarize()
    finally:
        state.close()


def test_clean_canary_catalog_is_exact_and_fresh_state_is_observed(tmp_path: Path) -> None:
    catalog = load_canary_catalog(
        Path(__file__).parents[1] / "qualification" / "canaries" / "catalog.yaml"
    )
    assert set(catalog) == set(REQUIRED_CANARY_SCENARIOS)
    assert all(len(item.scenario_digest) == 64 for item in catalog.values())

    database = tmp_path / "fresh.db"
    state = StateStore(database)
    state.close()
    proof = prove_fresh_state(database, tmp_path / "evidence")
    assert proof.schema_version == 18
    assert not any(proof.row_counts.values())
    assert len(proof.initial_state_digest) == 64

    state = StateStore(database)
    try:
        state.create_product(
            product_id="canary-product",
            owner_id="qualification",
            source="cli",
            idea="A clean canary fixture",
            idempotency_key="canary-product",
        )
    finally:
        state.close()
    with pytest.raises(CanaryObservationError, match="not fresh"):
        prove_fresh_state(database, tmp_path / "second-evidence")


def test_completed_canary_observation_derives_zero_intervention_counts(
    tmp_path: Path,
) -> None:
    database = tmp_path / "canary.db"
    controller_digest = "8" * 64
    state = StateStore(database)
    try:
        state.create_product(
            product_id="product-clean",
            owner_id="qualification",
            source="cli",
            idea="A clean observed canary",
            idempotency_key="product-clean",
        )
        state.add_task(task_id="task-clean", product_id="product-clean", title="Build")
        claimed = state.claim_task(worker_id="worker-clean")
        assert claimed is not None
        state.complete_task("task-clean", "worker-clean")
        completion_ref = "evidence://canary/completion/product-clean"
        with state._connection:
            state._connection.execute(
                """INSERT INTO completion_manifests
                   (manifest_id,product_id,manifest_ref,manifest_json,manifest_digest,
                    controller_release_digest,policy_digest,created_at)
                   VALUES ('CM-CLEAN','product-clean',?,'{}',?,?,?,?)""",
                (completion_ref, "9" * 64, controller_digest, "7" * 64, "2026-08-03T00:00:00Z"),
            )
        state.transition_product(
            "product-clean",
            "COMPLETED",
            completion_evidence_ref=completion_ref,
        )
    finally:
        state.close()

    observation = observe_completion(
        database,
        tmp_path / "evidence",
        product_id="product-clean",
        expected_controller_release_digest=controller_digest,
    )
    assert observation.terminal_status == "COMPLETED"
    assert observation.task_count == observation.baseline_task_count == 1
    assert observation.controller_incidents == 0
    assert observation.recovery_applications == 0
    assert observation.routine_owner_actions == 0
    assert observation.duplicate_side_effects == 0


def test_qualification_control_initializes_one_idempotent_epoch(tmp_path: Path) -> None:
    repository = Path(__file__).parents[1]
    config = {
        "schema_version": "1.0",
        "governor_database": str((tmp_path / "verifier" / "governor.db").resolve()),
        "candidate_repository_root": str(repository.resolve()),
        "evidence_root": str((tmp_path / "evidence").resolve()),
        "shadow_journal_root": str((tmp_path / "shadow").resolve()),
        "shadow_feed_root": str((tmp_path / "feed").resolve()),
        "candidate_shadow_output_root": str((tmp_path / "shadow-output").resolve()),
        "stable_release_root": str((tmp_path / "stable-release").resolve()),
        "candidate_database": str((tmp_path / "candidate.db").resolve()),
        "canary_catalog_path": str(
            (repository / "qualification" / "canaries" / "catalog.yaml").resolve()
        ),
        "canary_config_index": str((tmp_path / "canaries" / "index.json").resolve()),
        "resilience_proof_index": str(
            (tmp_path / "resilience" / "proof-index.json").resolve()
        ),
        "promotion_receipt_path": str((tmp_path / "promotion.json").resolve()),
        "production_observation_path": str((tmp_path / "observation.json").resolve()),
        "production_rollback_path": str((tmp_path / "rollback.json").resolve()),
        "factory_repository": "brullik/hermes-software-factory",
        "source_commit": "0" * 40,
        "stable_release_digest": "1" * 64,
        "controller_release_digest": "2" * 64,
        "candidate_digest": "3" * 64,
        "policy_digest": "4" * 64,
        "toolchain_manifest_digest": "5" * 64,
        "trusted_verifier_public_key_digest": _TEST_VERIFIER_KEY_DIGEST,
        "verifier_digest": "6" * 64,
        "verifier_public_key": _TEST_VERIFIER_PUBLIC_KEY,
        "manifest_request_path": str((tmp_path / "verifier" / "request.json").resolve()),
        "signed_manifest_path": str((tmp_path / "verifier" / "signed.json").resolve()),
        "verifier_private_key_path": str((tmp_path / "verifier" / "key").resolve()),
        "manifest_install_root": str((tmp_path / "installed").resolve()),
    }
    epoch_id = initialize_epoch(config)
    assert initialize_epoch(config) == epoch_id
    result = qualification_status(config)
    assert result["epoch_id"] == epoch_id
    assert result["status"] == "CANDIDATE_BUILT"
    assert result["qualification_stages"] == []


def test_candidate_snapshot_digest_uses_manifest_canonical_shape() -> None:
    digest = _immutable_release_tree_digest(Path(__file__).parents[1])
    assert len(digest) == 64
    assert all(character in "0123456789abcdef" for character in digest)


def test_q0_git_trust_is_scoped_to_the_exact_candidate_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: list[object] = []

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        observed.extend((command, kwargs.get("cwd")))
        return SimpleNamespace(returncode=0, stdout="commit\n", stderr="")

    monkeypatch.setattr(qualification_runner.subprocess, "run", fake_run)
    assert qualification_runner._git(tmp_path, "rev-parse", "HEAD") == "commit"
    assert observed == [
        [
            "git",
            "-c",
            f"safe.directory={tmp_path.resolve()}",
            "rev-parse",
            "HEAD",
        ],
        tmp_path.resolve(),
    ]


def test_q0_reproducible_wheel_builds_in_two_archive_copies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
        payload = b"immutable source\n"
        member = tarfile.TarInfo("source.txt")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))

    monkeypatch.setattr(qualification_runner, "_git", lambda *_args: "0")
    monkeypatch.setattr(
        qualification_runner,
        "_immutable_source_archive",
        lambda _repository: archive_buffer.getvalue(),
    )
    build_roots: list[Path] = []

    def fake_run(
        command: list[str],
        *,
        cwd: Path,
        timeout: int,
        environment: dict[str, str] | None = None,
    ) -> tuple[int, str]:
        del timeout, environment
        build_roots.append(cwd)
        assert (cwd / "source.txt").read_text(encoding="utf-8") == "immutable source\n"
        wheel_root = Path(command[command.index("--wheel-dir") + 1])
        (wheel_root / "candidate.whl").write_bytes(b"reproducible wheel")
        return 0, "transcript"

    monkeypatch.setattr(qualification_runner, "_run", fake_run)
    wheel_digest, transcript_digest = _reproducible_wheel(tmp_path / "candidate")
    assert len(wheel_digest) == 64
    assert len(transcript_digest) == 64
    assert len(build_roots) == 2
    assert build_roots[0] != build_roots[1]
    assert all(root != (tmp_path / "candidate").resolve() for root in build_roots)


def test_qualification_run_error_exposes_only_a_machine_safe_coordinate() -> None:
    error = QualificationRunError("reproducible wheel build failed")
    assert error.safe_coordinate == "reproducible-wheel-build-failed"


def test_q1_static_tools_do_not_write_to_the_immutable_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[list[str]] = []

    def fake_run(
        command: list[str],
        *,
        cwd: Path,
        timeout: int,
        environment: dict[str, str] | None = None,
    ) -> tuple[int, str]:
        del cwd, timeout, environment
        commands.append(command)
        return 0, "transcript"

    monkeypatch.setattr(qualification_runner, "_run", fake_run)
    report = qualification_runner.run_q1(Path(__file__).parents[1], tmp_path)
    assert report.status == "PASS"
    assert "--no-cache" in commands[0]
    assert "--cache-dir=/dev/null" in commands[1]


def test_q6_container_attestation_is_digest_and_source_bound(tmp_path: Path) -> None:
    source_commit = "a" * 40
    capability = "toolchain.container_builder"
    payload = {
        "schema_version": "1.0",
        "plane": "ISOLATED_Q6",
        "capabilities": {
            capability: {
                "status": "AVAILABLE",
                "scope": {
                    "allowed_operations": [capability],
                    "runtime": "podman",
                    "runroot": "/run/hermes-factory-candidate/containers",
                    "network_preflight": "passed",
                    "exact_version": "podman version 5.4.2",
                    "subject_user": "hermescandidate",
                    "source_commit": source_commit,
                },
            }
        },
    }
    path = tmp_path / "q6-attestation.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    loaded = _load_q6_container_attestation(
        path,
        expected_digest=sha256_file(path),
        expected_source_commit=source_commit,
        trust_policy=lambda _path: True,
    )
    assert loaded == payload["capabilities"][capability]

    payload["capabilities"][capability]["scope"]["source_commit"] = "b" * 40
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ServiceQualificationError, match="scope"):
        _load_q6_container_attestation(
            path,
            expected_digest=sha256_file(path),
            expected_source_commit=source_commit,
            trust_policy=lambda _path: True,
        )


def test_qualification_stage_crash_fails_release_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = Path(__file__).parents[1]
    config = {
        "governor_database": str((tmp_path / "verifier" / "governor.db").resolve()),
        "candidate_repository_root": str(repository.resolve()),
        "evidence_root": str((tmp_path / "evidence").resolve()),
        "source_commit": "0" * 40,
        "stable_release_digest": "1" * 64,
        "controller_release_digest": "2" * 64,
        "candidate_digest": "3" * 64,
        "policy_digest": "4" * 64,
        "toolchain_manifest_digest": "5" * 64,
        "trusted_verifier_public_key_digest": _TEST_VERIFIER_KEY_DIGEST,
        "q6_capability_attestation_path": str(
            (tmp_path / "q6-attestation.json").resolve()
        ),
        "q6_capability_attestation_digest": "7" * 64,
    }

    def fail_stage(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("sensitive diagnostic must not be persisted")

    monkeypatch.setattr(qualification_control, "_run_stage", fail_stage)
    with pytest.raises(RuntimeError):
        qualification_control.run_and_record_stage(config, "Q0_SOURCE_INTEGRITY")

    state = StateStore(Path(str(config["governor_database"])))
    try:
        epoch = state._connection.execute(
            "SELECT status,failure_reason,failure_evidence_ref FROM controller_release_epochs"
        ).fetchone()
        run = state._connection.execute(
            "SELECT status,evidence_ref FROM qualification_runs"
        ).fetchone()
        assert tuple(epoch)[:2] == (
            "QUALIFICATION_FAILED",
            "qualification_failed:Q0_SOURCE_INTEGRITY",
        )
        assert run["status"] == "FAIL"
        evidence_file = next((tmp_path / "evidence").glob("*.json"))
        text = evidence_file.read_text(encoding="utf-8")
        assert "sensitive diagnostic" not in text
        assert (
            json.loads(text)["failure_coordinate"]
            == "q0_source_integrity-runtimeerror"
        )
        assert str(tuple(epoch)[2]) == str(tuple(run)[1])
    finally:
        state.close()


def test_qualification_orchestration_failure_is_terminal_and_idempotent(
    tmp_path: Path,
) -> None:
    repository = Path(__file__).parents[1]
    config = {
        "governor_database": str((tmp_path / "verifier" / "governor.db").resolve()),
        "candidate_repository_root": str(repository.resolve()),
        "evidence_root": str((tmp_path / "evidence").resolve()),
        "source_commit": "0" * 40,
        "stable_release_digest": "1" * 64,
        "controller_release_digest": "2" * 64,
        "candidate_digest": "3" * 64,
        "policy_digest": "4" * 64,
        "toolchain_manifest_digest": "5" * 64,
        "trusted_verifier_public_key_digest": _TEST_VERIFIER_KEY_DIGEST,
    }
    epoch_id = initialize_epoch(config)
    first = qualification_control.fail_qualification_orchestration(config)
    second = qualification_control.fail_qualification_orchestration(config)
    assert first == second
    assert first[0] == epoch_id

    evidence_files = list((tmp_path / "evidence").glob("orchestration-failure-*.json"))
    assert len(evidence_files) == 1
    evidence = json.loads(evidence_files[0].read_text(encoding="utf-8"))
    assert evidence["reason_code"] == "qualification_orchestrator_start_failed"
    assert evidence["candidate_digest"] == "3" * 64
    state = StateStore(Path(str(config["governor_database"])))
    try:
        epoch = state._connection.execute(
            "SELECT status,failure_reason,failure_evidence_ref "
            "FROM controller_release_epochs WHERE epoch_id=?",
            (epoch_id,),
        ).fetchone()
        assert tuple(epoch) == (
            "QUALIFICATION_FAILED",
            "qualification_orchestrator_start_failed",
            first[1],
        )
    finally:
        state.close()


def test_candidate_bootstrap_closes_dependency_and_namespace_failures() -> None:
    repository = Path(__file__).parents[1]
    bootstrap = (repository / "scripts/bootstrap/prepare-candidate-plane.sh").read_text(
        encoding="utf-8"
    )
    hermes_install = bootstrap.index('"${HERMES_WHEEL}"')
    lock_reassertion = bootstrap.index(
        '--requirement "${CANDIDATE_RELEASE}/requirements.lock"',
        hermes_install,
    )
    pip_check = bootstrap.index("-m pip check", lock_reassertion)
    assert hermes_install < lock_reassertion < pip_check
    assert "systemctl enable hermes-factory-qualification.service" in bootstrap
    assert (
        "if ! systemctl start --wait hermes-factory-qualification.service" in bootstrap
    )
    assert "orchestration-fail" in bootstrap
    assert "umask 022" in bootstrap
    assert 'find "${release_root}" -type f -exec chmod 0644' not in bootstrap
    assert "Immutable release mode/content differs from Git" in bootstrap
    assert 'SERVICE_USER="${CANDIDATE_USER}"' in bootstrap
    assert "q6-capability-attestation.json" in bootstrap
    assert "--q6-capability-attestation-digest" in bootstrap
    assert "--add-subuids 1200000" not in bootstrap
    attestation_builder = (
        repository / "scripts/bootstrap/build-canary-attestation.py"
    ).read_text(encoding="utf-8")
    assert 'scoped_argv[1:1] = ["--cgroup-manager=cgroupfs"]' in attestation_builder

    optional_candidate_database = "-/var/lib/hermes-factory-candidate/controller.db"
    for unit in (
        "hermes-factory-qualification.service",
        "hermes-factory-qualification-stage@.service",
        "hermes-factory-shadow-verify.service",
    ):
        text = (repository / "config/systemd" / unit).read_text(encoding="utf-8")
        assert optional_candidate_database in text


def test_live_shadow_feed_is_redacted_evaluated_and_verified_once(tmp_path: Path) -> None:
    stable_database = (tmp_path / "stable.db").resolve()
    stable_state = StateStore(stable_database)
    try:
        stable_state.create_product(
            product_id="stable-product",
            owner_id="owner",
            source="telegram",
            idea="A stable product",
            idempotency_key="stable-product",
        )
        stable_state.record_event(
            product_id="stable-product",
            task_id=None,
            event_type="diagnostic",
            payload={"credential": "ghp_" + ("x" * 30)},
        )
    finally:
        stable_state.close()
    feed_root = (tmp_path / "feed").resolve()
    output_root = (tmp_path / "candidate-output").resolve()
    exported = export_stable_events(stable_database, feed_root)
    assert exported["event_count"] == 2
    evaluated = evaluate_candidate_batches(feed_root, output_root)
    assert evaluated["new_batch_count"] == 1
    assert evaluate_candidate_batches(feed_root, output_root)["new_batch_count"] == 0
    feed_text = next(feed_root.glob("*.json")).read_text(encoding="utf-8")
    assert "ghp_" + ("x" * 30) not in feed_text

    repository = Path(__file__).parents[1]
    stable_release = (tmp_path / "stable-release").resolve()
    stable_release.mkdir()
    config = {
        "schema_version": "1.0",
        "governor_database": str((tmp_path / "verifier" / "governor.db").resolve()),
        "candidate_repository_root": str(repository.resolve()),
        "evidence_root": str((tmp_path / "verifier" / "evidence").resolve()),
        "shadow_journal_root": str((tmp_path / "verifier" / "journal").resolve()),
        "shadow_feed_root": str(feed_root),
        "candidate_shadow_output_root": str(output_root),
        "stable_release_root": str(stable_release),
        "candidate_database": str((tmp_path / "candidate.db").resolve()),
        "canary_catalog_path": str(
            (repository / "qualification" / "canaries" / "catalog.yaml").resolve()
        ),
        "canary_config_index": str((tmp_path / "canaries" / "index.json").resolve()),
        "resilience_proof_index": str(
            (tmp_path / "resilience" / "proof-index.json").resolve()
        ),
        "promotion_receipt_path": str((tmp_path / "promotion.json").resolve()),
        "production_observation_path": str((tmp_path / "observation.json").resolve()),
        "production_rollback_path": str((tmp_path / "rollback.json").resolve()),
        "factory_repository": "brullik/hermes-software-factory",
        "source_commit": "0" * 40,
        "stable_release_digest": "1" * 64,
        "controller_release_digest": "2" * 64,
        "candidate_digest": "3" * 64,
        "policy_digest": "4" * 64,
        "toolchain_manifest_digest": "5" * 64,
        "trusted_verifier_public_key_digest": _TEST_VERIFIER_KEY_DIGEST,
        "verifier_digest": "6" * 64,
        "verifier_public_key": _TEST_VERIFIER_PUBLIC_KEY,
        "manifest_request_path": str((tmp_path / "verifier" / "request.json").resolve()),
        "signed_manifest_path": str((tmp_path / "verifier" / "signed.json").resolve()),
        "verifier_private_key_path": str((tmp_path / "verifier" / "key").resolve()),
        "manifest_install_root": str((tmp_path / "installed").resolve()),
    }
    epoch_id = initialize_epoch(config)
    verifier_state = StateStore(Path(str(config["governor_database"])))
    try:
        governor = ReleaseQualificationGovernor(verifier_state._connection)
        _qualify_to_clean_canary(governor, epoch_id, include_q7=False)
        verifier_state._connection.commit()
    finally:
        verifier_state.close()
    observed_epoch, batch_count, event_count = verify_shadow_batches(config)
    assert observed_epoch == epoch_id
    assert batch_count == 1
    assert event_count == 2
    assert verify_shadow_batches(config)[1:] == (0, 0)
