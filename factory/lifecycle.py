"""Controller-owned semantic lifecycle contracts.

The model may describe product work, but it must never choose executable
roles, schemas, capabilities, evidence identities, or release ordering.  This
module is deliberately free of provider-specific code so it can be used by the
plan compiler, validator, recovery tooling, and tests as the single lifecycle
authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

LIFECYCLE_VERSION: Final = "5.0"
PLAN_COMPILER_VERSION: Final = "3.0"


@dataclass(frozen=True)
class LifecycleStage:
    key: str
    role: str
    output_schema: str
    capability_profile: str
    review_kind: str | None
    evidence_profile: str
    consumes: tuple[str, ...]
    produces: tuple[str, ...]
    obligations: tuple[str, ...] = ()
    production_side_effects: bool = False


STAGES: Final[dict[str, LifecycleStage]] = {
    "architecture-review": LifecycleStage(
        "architecture-review",
        "independent-reviewer",
        "review-result.schema.json",
        "reviewer_readonly",
        "architecture",
        "architecture-review-v1",
        ("architecture_package",),
        ("architecture_review",),
    ),
    "implementation-slice": LifecycleStage(
        "implementation-slice",
        "builder",
        "attempt-result.schema.json",
        "builder_workspace",
        None,
        "implementation-candidate-v1",
        ("architecture_review",),
        ("implementation_candidate",),
    ),
    "candidate-snapshot": LifecycleStage(
        "candidate-snapshot",
        "path-governor",
        "candidate-snapshot.schema.json",
        "planning_readonly",
        None,
        "candidate-snapshot-v1",
        ("architecture_review", "implementation_candidate"),
        ("candidate_snapshot",),
    ),
    "test": LifecycleStage(
        "test",
        "test-engineer",
        "test-package-result.schema.json",
        "test_workspace",
        None,
        "test-evidence-v1",
        ("candidate_snapshot",),
        ("test_results",),
    ),
    "security-review": LifecycleStage(
        "security-review",
        "security-reviewer",
        "security-review-result.schema.json",
        "reviewer_readonly",
        "security",
        "security-review-v1",
        ("candidate_snapshot", "test_results"),
        ("security_review",),
    ),
    "release-readiness-review": LifecycleStage(
        "release-readiness-review",
        "independent-reviewer",
        "review-result.schema.json",
        "reviewer_readonly",
        "release_readiness",
        "release-readiness-review-v1",
        ("candidate_snapshot", "test_results", "security_review"),
        ("independent_review",),
        ("independent_review",),
    ),
    "staging": LifecycleStage(
        "staging",
        "release-operator",
        "release-operation-result.schema.json",
        "release_staging",
        None,
        "staging-release-v1",
        ("candidate_snapshot", "independent_review"),
        ("required_checks", "staging", "rollback"),
        ("required_checks", "staging", "rollback"),
    ),
    "product-acceptance": LifecycleStage(
        "product-acceptance",
        "product-tester",
        "product-test-result.schema.json",
        "test_workspace",
        None,
        "product-acceptance-v1",
        ("staging",),
        ("product_acceptance", "goal_evidence"),
        ("product_acceptance", "goal_evidence"),
    ),
    "production": LifecycleStage(
        "production",
        "release-operator",
        "release-operation-result.schema.json",
        "release_production",
        None,
        "production-release-v1",
        ("staging", "product_acceptance", "independent_review"),
        ("production", "rollback"),
        ("production", "rollback"),
        production_side_effects=True,
    ),
    "observation": LifecycleStage(
        "observation",
        "product-tester",
        "product-test-result.schema.json",
        "test_workspace",
        None,
        "production-observation-v1",
        ("production",),
        ("observation",),
        ("observation", "completion"),
    ),
    "telegram-contract-smoke": LifecycleStage(
        "telegram-contract-smoke",
        "product-tester",
        "product-test-result.schema.json",
        "test_workspace",
        None,
        "telegram-contract-smoke-v1",
        ("staging",),
        ("telegram_contract",),
        ("telegram_contract",),
    ),
    "browser-acceptance": LifecycleStage(
        "browser-acceptance",
        "product-tester",
        "product-test-result.schema.json",
        "test_workspace",
        None,
        "browser-acceptance-v1",
        ("staging",),
        ("browser_acceptance",),
        ("browser_acceptance",),
    ),
    "package-build": LifecycleStage(
        "package-build",
        "builder",
        "attempt-result.schema.json",
        "builder_workspace",
        None,
        "package-build-v1",
        ("candidate_snapshot", "independent_review"),
        ("package",),
        ("package",),
    ),
    "install-smoke": LifecycleStage(
        "install-smoke",
        "test-engineer",
        "test-package-result.schema.json",
        "test_workspace",
        None,
        "install-smoke-v1",
        ("package",),
        ("install_smoke",),
        ("install_smoke",),
    ),
    "signed-release": LifecycleStage(
        "signed-release",
        "release-operator",
        "release-operation-result.schema.json",
        "release_distribution",
        None,
        "signed-release-v1",
        ("package", "independent_review"),
        ("signed_release", "required_checks"),
        ("signed_release", "required_checks"),
        production_side_effects=True,
    ),
    "distribution-smoke": LifecycleStage(
        "distribution-smoke",
        "product-tester",
        "product-test-result.schema.json",
        "test_workspace",
        None,
        "distribution-smoke-v1",
        ("signed_release",),
        ("distribution_smoke", "goal_evidence"),
        ("distribution_smoke", "goal_evidence", "completion"),
    ),
    "observation-policy": LifecycleStage(
        "observation-policy",
        "product-tester",
        "product-test-result.schema.json",
        "test_workspace",
        None,
        "observation-policy-v1",
        ("distribution_smoke",),
        ("observation",),
        ("completion",),
    ),
    "compatibility-matrix": LifecycleStage(
        "compatibility-matrix",
        "test-engineer",
        "test-package-result.schema.json",
        "test_workspace",
        None,
        "compatibility-matrix-v1",
        ("package",),
        ("compatibility_matrix",),
        ("compatibility_matrix",),
    ),
    "publish-dry-run": LifecycleStage(
        "publish-dry-run",
        "release-operator",
        "release-operation-result.schema.json",
        "release_staging",
        None,
        "publish-dry-run-v1",
        ("package", "compatibility_matrix", "independent_review"),
        ("publish_dry_run", "required_checks"),
        ("publish_dry_run", "required_checks"),
    ),
    "signed-publish": LifecycleStage(
        "signed-publish",
        "release-operator",
        "release-operation-result.schema.json",
        "release_distribution",
        None,
        "signed-publish-v1",
        ("publish_dry_run", "independent_review"),
        ("signed_publish",),
        ("signed_publish",),
        production_side_effects=True,
    ),
    "consumer-smoke": LifecycleStage(
        "consumer-smoke",
        "product-tester",
        "product-test-result.schema.json",
        "test_workspace",
        None,
        "consumer-smoke-v1",
        ("signed_publish",),
        ("consumer_smoke", "goal_evidence"),
        ("consumer_smoke", "goal_evidence", "completion"),
    ),
    "workflow-dry-run": LifecycleStage(
        "workflow-dry-run",
        "test-engineer",
        "test-package-result.schema.json",
        "test_workspace",
        None,
        "workflow-dry-run-v1",
        ("candidate_snapshot", "independent_review"),
        ("workflow_dry_run", "required_checks"),
        ("workflow_dry_run", "required_checks"),
    ),
    "permission-contract": LifecycleStage(
        "permission-contract",
        "security-reviewer",
        "security-review-result.schema.json",
        "reviewer_readonly",
        "security",
        "permission-contract-v1",
        ("workflow_dry_run",),
        ("permission_contract",),
        ("permission_contract",),
    ),
    "repository-acceptance": LifecycleStage(
        "repository-acceptance",
        "product-tester",
        "product-test-result.schema.json",
        "test_workspace",
        None,
        "repository-acceptance-v1",
        ("workflow_dry_run", "permission_contract"),
        ("repository_acceptance", "package"),
        ("repository_acceptance",),
    ),
    "fixture-replay": LifecycleStage(
        "fixture-replay",
        "test-engineer",
        "test-package-result.schema.json",
        "test_workspace",
        None,
        "fixture-replay-v1",
        ("package",),
        ("fixture_replay", "required_checks"),
        ("fixture_replay", "required_checks"),
    ),
    "schedule-dry-run": LifecycleStage(
        "schedule-dry-run",
        "product-tester",
        "product-test-result.schema.json",
        "test_workspace",
        None,
        "schedule-dry-run-v1",
        ("fixture_replay",),
        ("schedule_dry_run", "signed_release"),
        ("schedule_dry_run",),
    ),
    "policy-approved-delivery": LifecycleStage(
        "policy-approved-delivery",
        "independent-reviewer",
        "review-result.schema.json",
        "reviewer_readonly",
        "release_readiness",
        "policy-approved-delivery-v1",
        ("staging", "product_acceptance", "independent_review"),
        ("policy_approved_delivery", "goal_evidence"),
        ("policy_approved_delivery", "goal_evidence", "completion"),
    ),
}


MANDATORY_STAGE_ORDER: Final[tuple[str, ...]] = (
    "architecture-review",
    "implementation-slice",
    "candidate-snapshot",
    "test",
    "security-review",
    "release-readiness-review",
    "staging",
    "product-acceptance",
    "production",
    "observation",
)

REQUIRED_COMPLETION_OBLIGATIONS: Final[frozenset[str]] = frozenset(
    {
        "independent_review",
        "required_checks",
        "staging",
        "product_acceptance",
        "production",
        "rollback",
        "observation",
        "goal_evidence",
        "completion",
    }
)

REVIEW_KINDS: Final[frozenset[str]] = frozenset({"architecture", "security", "release_readiness"})


def stage_contract(stage_key: str) -> LifecycleStage:
    try:
        return STAGES[stage_key]
    except KeyError as error:
        raise ValueError(f"unknown lifecycle stage: {stage_key}") from error
