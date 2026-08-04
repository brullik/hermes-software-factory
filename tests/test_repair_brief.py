from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from factory.repair_brief import (
    builder_result_is_controller_complete,
    builder_result_is_locally_complete,
    controller_runtime_repair_findings,
    normalized_repair_findings,
    product_goals_are_proven,
    repair_finding_detail,
    repair_requirements,
)

ROOT = Path(__file__).resolve().parents[1]


def test_attempt_result_findings_preserve_code_and_text_as_actionable_fix() -> None:
    output = {
        "status": "repair_required",
        "findings": [
            {
                "code": "BOUNDARY-CHECK",
                "severity": "medium",
                "text": "Validate the assigned row against its own role boundary.",
            },
            {
                "code": "SCANNERS-PASS",
                "severity": "info",
                "text": "No scanner regression.",
            },
        ],
    }

    findings = normalized_repair_findings(output)
    blocker_ids, required_fixes = repair_requirements(
        output=output,
        reason_code="model_requested_repair",
        detail="repair requested",
    )

    assert [item.finding_id for item in findings] == ["BOUNDARY-CHECK"]
    assert blocker_ids == ["BOUNDARY-CHECK"]
    assert required_fixes == [
        "Validate the assigned row against its own role boundary."
    ]


def test_plan_proposal_failed_safe_summary_remains_actionable() -> None:
    detail = repair_finding_detail(
        {
            "status": "failed_safe",
            "summary": (
                "The active implementation inventory and exhausted hypothesis "
                "chain are missing from the supplied context."
            ),
        }
    )

    assert "status=failed_safe" in detail
    assert "implementation inventory" in detail
    assert "hypothesis chain" in detail


def test_controller_runtime_findings_require_exclusive_controller_ownership() -> None:
    output = {
        "status": "repair_required",
        "findings": [
            {
                "code": "CONTROLLER_PODMAN_IPAM_DATABASE_MISSING",
                "severity": "high",
                "text": "The controller RunRoot has no initialized IPAM database.",
            },
            {
                "code": "FULL_PYTEST_BLOCKED_BY_CONTROLLER_RUNTIME",
                "severity": "medium",
                "text": "The suite reached one controller-runtime-dependent test.",
            },
        ],
    }

    assert [
        item.finding_id for item in controller_runtime_repair_findings(output)
    ] == [
        "CONTROLLER_PODMAN_IPAM_DATABASE_MISSING",
        "FULL_PYTEST_BLOCKED_BY_CONTROLLER_RUNTIME",
    ]

    mixed = {
        **output,
        "findings": [
            *output["findings"],
            {
                "code": "PRODUCT_COMPOSE_DEFECT",
                "severity": "high",
                "text": "A repository defect also remains.",
            },
        ],
    }
    assert controller_runtime_repair_findings(mixed) == ()


def test_repair_brief_schema_requires_every_actionable_field() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "repair-brief.schema.json").read_text(encoding="utf-8")
    )
    base = {
        "schema_version": "1.0",
        "artifact_id": "repair-brief-test",
        "product_id": "product-test",
        "created_at": "2026-01-01T00:00:00Z",
        "producer": {"role": "repair-coordinator", "tier": "deterministic"},
        "policy_digest": "a" * 64,
        "task_id": "T-REPAIR",
        "attempt_id": "attempt-repair",
        "failure_class": "mandatory_gate_failed",
        "failed_gate_ids": ["target-tests"],
        "required_fixes": ["Make the failing target test pass without weakening it."],
        "allowed_paths": ["src/**", "tests/**"],
        "relevant_log_fragment": "target-tests failed with assertion mismatch",
        "expected_vs_actual": {
            "expected": "target-tests PASS",
            "actual": "target-tests FAIL",
        },
        "changed_files": [],
        "forbidden_actions": ["tests may not be weakened"],
        "previous_attempt_summary": "The target test failed.",
        "definition_of_done": ["target-tests reports PASS"],
        "evidence_refs": ["evidence/attempt.json"],
    }
    validator = Draft202012Validator(schema)

    assert list(validator.iter_errors(base)) == []
    for field in ("failed_gate_ids", "required_fixes", "allowed_paths"):
        missing = dict(base)
        missing.pop(field)
        assert list(validator.iter_errors(missing))
        empty = dict(base)
        empty[field] = []
        assert list(validator.iter_errors(empty))


def test_builder_can_finish_when_only_immutable_candidate_gate_is_deferred() -> None:
    output = {
        "status": "blocked_external",
        "changed_files": [{"path": "src/core.py", "change": "Applied repair."}],
        "test_results": [
            {"gate_id": "local-pm-acceptance", "status": "PASS"},
            {"gate_id": "AC-PM-SCOPE-GITHUB", "status": "NOT_RUN"},
        ],
        "findings": [
            {
                "code": "GITHUB_REQUIRED_CHECK_NOT_RUN",
                "severity": "medium",
                "text": "Run after immutable candidate creation.",
            },
            {
                "code": "OUT_OF_SCOPE_RUFF_BASELINE",
                "severity": "low",
                "text": "Unrelated baseline.",
            },
        ],
    }

    assert builder_result_is_locally_complete(output)
    output["findings"].append(
        {
            "code": "IMPLEMENTATION_DEFECT",
            "severity": "medium",
            "text": "A product defect remains.",
        }
    )
    assert not builder_result_is_locally_complete(output)


def test_builder_controller_complete_result_rejects_only_detector_scope_conflict() -> None:
    output = {
        "status": "needs_replan",
        "changed_files": [
            {"path": "src/grid_bot/core.py", "change": "Implemented the grid simulation."}
        ],
        "test_results": [
            {"gate_id": "target-environment", "status": "PASS"},
            {"gate_id": "target-tests", "status": "PASS"},
            {"gate_id": "target-compile", "status": "PASS"},
            {"gate_id": "target-lint", "status": "PASS"},
            {"gate_id": "target-secret-scan", "status": "PASS"},
            {"gate_id": "canonical-command-detector", "status": "NOT_RUN"},
        ],
        "findings": [
            {
                "code": "CANONICAL_DETECTOR_SCOPE_CONFLICT",
                "severity": "medium",
                "text": "A root manifest is outside the exact Builder write scope.",
            },
            {
                "code": "UNTRACKED_BYTECODE_PRESENT",
                "severity": "low",
                "text": "Runtime bytecode is excluded from the release candidate.",
            },
        ],
    }

    assert builder_result_is_controller_complete(output)

    unknown_finding = {**output, "findings": [*output["findings"], {
        "code": "IMPLEMENTATION_DEFECT",
        "severity": "medium",
        "text": "A product defect remains.",
    }]}
    assert not builder_result_is_controller_complete(unknown_finding)

    failed_gate = {**output, "test_results": [
        *output["test_results"],
        {"gate_id": "extra-check", "status": "FAIL"},
    ]}
    assert not builder_result_is_controller_complete(failed_gate)

    assert not builder_result_is_controller_complete({**output, "changed_files": []})


def test_product_goals_require_passing_journeys_with_evidence() -> None:
    output = {
        "status": "accepted",
        "release_blocked": False,
        "journeys": [
            {
                "journey_id": "J-001",
                "result": "PASS",
                "evidence_refs": ["evidence/journey-J-001.json"],
            }
        ],
    }

    assert product_goals_are_proven(output)
    output["journeys"][0]["evidence_refs"] = []
    assert not product_goals_are_proven(output)
