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

LIFECYCLE_VERSION: Final = "3.0"
PLAN_COMPILER_VERSION: Final = "1.0"


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
    "test": LifecycleStage(
        "test",
        "test-engineer",
        "test-package-result.schema.json",
        "test_workspace",
        None,
        "test-evidence-v1",
        ("implementation_candidate",),
        ("test_results",),
    ),
    "security-review": LifecycleStage(
        "security-review",
        "security-reviewer",
        "security-review-result.schema.json",
        "reviewer_readonly",
        "security",
        "security-review-v1",
        ("implementation_candidate", "test_results"),
        ("security_review",),
    ),
    "release-readiness-review": LifecycleStage(
        "release-readiness-review",
        "independent-reviewer",
        "review-result.schema.json",
        "reviewer_readonly",
        "release_readiness",
        "release-readiness-review-v1",
        ("implementation_candidate", "test_results", "security_review"),
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
        ("implementation_candidate", "independent_review"),
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
}


MANDATORY_STAGE_ORDER: Final[tuple[str, ...]] = (
    "architecture-review",
    "implementation-slice",
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
