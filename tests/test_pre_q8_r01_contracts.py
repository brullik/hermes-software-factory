"""Locked PRE-Q8 r01 controller-contract regressions."""

from __future__ import annotations

from factory.controller_envelope import bind_controller_envelope
from factory.path_governor import supersession_is_compatible
from factory.plan_compiler import CompileContext, PlanCompiler


def _identity_schema(*semantic_fields: str) -> dict[str, object]:
    properties = {
        "schema_version": {"const": "1.0"},
        "artifact_id": {"type": "string"},
        "product_id": {"type": "string"},
        "policy_digest": {"type": "string"},
        "source_failure_id": {"type": ["string", "null"]},
        **{field: {} for field in semantic_fields},
    }
    return {"type": "object", "properties": properties}


def test_model_policy_digest_is_replaced_by_controller_truth() -> None:
    invalid_model_digest = "a" * 65
    controller_digest = "b" * 64
    result = bind_controller_envelope(
        {
            "policy_digest": invalid_model_digest,
            "status": "completed",
            "summary": "provider semantics remain intact",
        },
        schema=_identity_schema("status", "summary"),
        controller_fields={
            "schema_version": "1.0",
            "artifact_id": "artifact-controller",
            "product_id": "product-controller",
            "policy_digest": controller_digest,
            "source_failure_id": None,
        },
    )

    assert result["policy_digest"] == controller_digest
    assert invalid_model_digest not in result.values()
    assert result["status"] == "completed"
    assert result["summary"] == "provider semantics remain intact"


def test_replanner_source_failure_id_is_bound_to_task_contract() -> None:
    result = bind_controller_envelope(
        {
            "source_failure_id": "failure-model-selected",
            "status": "completed",
        },
        schema=_identity_schema("status"),
        controller_fields={
            "schema_version": "1.0",
            "artifact_id": "artifact-controller",
            "product_id": "product-controller",
            "policy_digest": "c" * 64,
            "source_failure_id": "failure-task-contract",
        },
    )

    assert result["source_failure_id"] == "failure-task-contract"


def test_schema_retry_does_not_consume_execution_budget() -> None:
    schema = _identity_schema("status")
    controller_fields = {
        "schema_version": "1.0",
        "artifact_id": "artifact-controller",
        "product_id": "product-controller",
        "policy_digest": "d" * 64,
        "source_failure_id": None,
    }
    first = bind_controller_envelope(
        {"policy_digest": "e" * 65, "status": "invalid-enum"},
        schema=schema,
        controller_fields=controller_fields,
    )
    second = bind_controller_envelope(
        {"policy_digest": "f" * 66, "status": "completed"},
        schema=schema,
        controller_fields=controller_fields,
    )

    assert first["policy_digest"] == "d" * 64
    assert second["policy_digest"] == "d" * 64


def test_supersession_predicate_requires_full_contract_identity() -> None:
    source = {
        "product_id": "product-controller",
        "role": "builder",
        "output_schema": "attempt-result.schema.json",
        "lifecycle_stage": "implementation-slice",
        "review_kind": None,
        "evidence_profile": "repository-change",
        "semantic_node_key": "implementation",
    }

    assert supersession_is_compatible(source, dict(source))
    for field, value in (
        ("product_id", "different-product"),
        ("role", "replanner"),
        ("output_schema", "plan-proposal-v1.schema.json"),
        ("lifecycle_stage", "test"),
        ("review_kind", "security"),
        ("evidence_profile", "review"),
        ("semantic_node_key", "different-node"),
    ):
        replacement = {**source, field: value}
        assert not supersession_is_compatible(source, replacement)


def _compiled_profile_plan(
    delivery_profile: str,
    *,
    declared_faults: tuple[str, ...] = (),
) -> dict[str, object]:
    product_id = f"P-{delivery_profile}"
    proposal = {
        "schema_version": "1.0",
        "proposal_kind": "initial",
        "product_id": product_id,
        "parent_plan_id": None,
        "source_failure_id": None,
        "created_at": "2026-08-10T00:00:00Z",
        "goals": [
            {
                "goal_id": "root-goal",
                "statement": "Deliver the exact profile behavior.",
                "mandatory": True,
            }
        ],
        "nodes": [
            {
                "node_key": "product-runtime",
                "stage_kind": "implementation_slice",
                "title": "Implement product runtime",
                "objective": "Implement and prove the exact product behavior.",
                "scope": ["src/**", "tests/**"],
                "depends_on": [],
                "goal_ids": ["root-goal"],
                "acceptance_intents": ["The observable product behavior passes."],
            }
        ],
        "summary": "Exact profile plan.",
    }
    return PlanCompiler(policy_digest="e" * 64).compile(
        proposal,
        CompileContext(
            product_id=product_id,
            revision=1,
            parent_plan_id=None,
            source_failure_id=None,
            created_by_task_id="T-SPECIFIER",
            root_task_id="T-ROOT",
            root_context_ref=f"evidence/intake-{product_id}.json",
            external_repository=False,
            proposal_artifact_ref="evidence/proposal.json",
            delivery_profile=delivery_profile,
            delivery_mode="new_repository",
            declared_faults=declared_faults,
        ),
    )


def _acceptance_text(plan: dict[str, object], stage: str) -> str:
    nodes = plan["nodes"]
    assert isinstance(nodes, list)
    contract = next(
        node["task_contract"]
        for node in nodes
        if node["task_contract"]["lifecycle_stage"] == stage
    )
    return "\n".join(item["verification"] for item in contract["acceptance"])


def test_first_python_implementation_requires_project_metadata() -> None:
    plan = _compiled_profile_plan("CLI_PACKAGE")
    nodes = plan["nodes"]
    assert isinstance(nodes, list)
    contract = next(
        node["task_contract"]
        for node in nodes
        if node["task_contract"]["lifecycle_stage"] == "implementation-slice"
    )

    assert {"pyproject.toml", "README.md", "LICENSE", "tests/**"}.issubset(
        contract["allowed_paths"]
    )
    acceptance = _acceptance_text(plan, "implementation-slice")
    assert "PY-PACKAGE-001" in acceptance
    assert "PY-DEPS-001" in acceptance
    assert "PY-LICENSE-001" in acceptance
    assert "PY-DOCS-001" in acceptance
    assert "PY-TOOLCHAIN-001" in acceptance


def test_http_head_405_has_zero_body() -> None:
    plan = _compiled_profile_plan("DEPLOYED_SERVICE")

    for stage in ("implementation-slice", "release-readiness-review"):
        acceptance = _acceptance_text(plan, stage)
        assert "HTTP-HEAD-001" in acceptance
        assert "HEAD responses transmit no message body" in acceptance
        assert "including 405" in acceptance


def test_batch_rejects_absolute_and_parent_paths() -> None:
    plan = _compiled_profile_plan("OFFLINE_BATCH")
    acceptance = _acceptance_text(plan, "implementation-slice")

    assert "BATCH-PATH-001" in acceptance
    assert "Reject absolute input paths" in acceptance
    assert "any .. component" in acceptance
    assert "symlink escape" in acceptance
    assert "outside workspace" in acceptance


def test_timeout_recovery_does_not_complete_non_timeout_state() -> None:
    plan = _compiled_profile_plan(
        "GITHUB_AUTOMATION",
        declared_faults=("ONE_PROVIDER_TIMEOUT",),
    )

    for stage in ("implementation-slice", "release-readiness-review"):
        acceptance = _acceptance_text(plan, stage)
        assert "FAULT-TIMEOUT-001" in acceptance
        assert "Only durable TIMED_OUT transitions to RETRY" in acceptance
        assert "cannot complete a non-timeout state" in acceptance
