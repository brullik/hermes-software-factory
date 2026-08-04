"""Controller-owned delivery lifecycles; models cannot invent release semantics."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from .common import sha256_text, stable_json


class DeliveryProfileName(StrEnum):
    DEPLOYED_SERVICE = "DEPLOYED_SERVICE"
    TELEGRAM_BOT = "TELEGRAM_BOT"
    WEB_APPLICATION = "WEB_APPLICATION"
    CLI_PACKAGE = "CLI_PACKAGE"
    LIBRARY_PACKAGE = "LIBRARY_PACKAGE"
    GITHUB_AUTOMATION = "GITHUB_AUTOMATION"
    OFFLINE_BATCH = "OFFLINE_BATCH"
    STAGING_ONLY_PROTOTYPE = "STAGING_ONLY_PROTOTYPE"


@dataclass(frozen=True)
class DeliveryProfile:
    name: DeliveryProfileName
    lifecycle: tuple[str, ...]
    completion_obligations: tuple[str, ...]
    production_authority_required: bool
    observation_required: bool

    @property
    def required_capability_profiles(self) -> tuple[str, ...]:
        from .lifecycle import stage_contract

        return tuple(
            dict.fromkeys(
                stage_contract(stage).capability_profile for stage in self.lifecycle
            )
        )

    @property
    def required_capabilities(self) -> tuple[str, ...]:
        from .autonomy import CAPABILITY_PROFILES

        return tuple(
            dict.fromkeys(
                capability
                for profile in self.required_capability_profiles
                for capability in CAPABILITY_PROFILES[profile]
            )
        )

    @property
    def evidence_types(self) -> tuple[str, ...]:
        from .lifecycle import stage_contract

        return tuple(
            dict.fromkeys(
                evidence
                for stage in self.lifecycle
                for evidence in stage_contract(stage).produces
            )
        )

    @property
    def deployment_semantics(self) -> str:
        if self.production_authority_required:
            return "transactional_service_promotion"
        if any(stage in {"signed-release", "signed-publish"} for stage in self.lifecycle):
            return "signed_non_service_distribution"
        if self.name is DeliveryProfileName.STAGING_ONLY_PROTOTYPE:
            return "staging_only_policy_delivery"
        return "verified_non_service_delivery"

    @property
    def rollback_required(self) -> bool:
        return "rollback" in self.completion_obligations

    @property
    def digest(self) -> str:
        return sha256_text(
            stable_json(
                {
                    "name": self.name.value,
                    "lifecycle": self.lifecycle,
                    "completion_obligations": self.completion_obligations,
                    "required_capability_profiles": self.required_capability_profiles,
                    "required_capabilities": self.required_capabilities,
                    "evidence_types": self.evidence_types,
                    "deployment_semantics": self.deployment_semantics,
                    "rollback_required": self.rollback_required,
                    "production_authority_required": self.production_authority_required,
                    "observation_required": self.observation_required,
                }
            )
        )


_COMMON = (
    "architecture-review",
    "implementation-slice",
    "candidate-snapshot",
    "test",
    "security-review",
    "release-readiness-review",
)


DELIVERY_PROFILES: Final[dict[DeliveryProfileName, DeliveryProfile]] = {
    DeliveryProfileName.DEPLOYED_SERVICE: DeliveryProfile(
        DeliveryProfileName.DEPLOYED_SERVICE,
        _COMMON
        + (
            "staging",
            "product-acceptance",
            "production",
            "observation",
        ),
        (
            "independent_review",
            "required_checks",
            "staging",
            "product_acceptance",
            "production",
            "rollback",
            "observation",
            "goal_evidence",
            "completion",
        ),
        True,
        True,
    ),
    DeliveryProfileName.TELEGRAM_BOT: DeliveryProfile(
        DeliveryProfileName.TELEGRAM_BOT,
        _COMMON
        + (
            "staging",
            "telegram-contract-smoke",
            "product-acceptance",
            "production",
            "observation",
        ),
        (
            "independent_review",
            "required_checks",
            "staging",
            "telegram_contract",
            "product_acceptance",
            "production",
            "rollback",
            "observation",
            "goal_evidence",
            "completion",
        ),
        True,
        True,
    ),
    DeliveryProfileName.WEB_APPLICATION: DeliveryProfile(
        DeliveryProfileName.WEB_APPLICATION,
        _COMMON
        + (
            "staging",
            "browser-acceptance",
            "product-acceptance",
            "production",
            "observation",
        ),
        (
            "independent_review",
            "required_checks",
            "staging",
            "browser_acceptance",
            "product_acceptance",
            "production",
            "rollback",
            "observation",
            "goal_evidence",
            "completion",
        ),
        True,
        True,
    ),
    DeliveryProfileName.CLI_PACKAGE: DeliveryProfile(
        DeliveryProfileName.CLI_PACKAGE,
        _COMMON
        + (
            "package-build",
            "install-smoke",
            "signed-release",
            "distribution-smoke",
            "observation-policy",
        ),
        (
            "independent_review",
            "required_checks",
            "package",
            "install_smoke",
            "signed_release",
            "distribution_smoke",
            "goal_evidence",
            "completion",
        ),
        False,
        True,
    ),
    DeliveryProfileName.LIBRARY_PACKAGE: DeliveryProfile(
        DeliveryProfileName.LIBRARY_PACKAGE,
        _COMMON
        + (
            "package-build",
            "compatibility-matrix",
            "publish-dry-run",
            "signed-publish",
            "consumer-smoke",
        ),
        (
            "independent_review",
            "required_checks",
            "package",
            "compatibility_matrix",
            "publish_dry_run",
            "signed_publish",
            "consumer_smoke",
            "goal_evidence",
            "completion",
        ),
        False,
        False,
    ),
    DeliveryProfileName.GITHUB_AUTOMATION: DeliveryProfile(
        DeliveryProfileName.GITHUB_AUTOMATION,
        _COMMON
        + (
            "workflow-dry-run",
            "permission-contract",
            "repository-acceptance",
            "signed-release",
            "distribution-smoke",
            "observation-policy",
        ),
        (
            "independent_review",
            "required_checks",
            "workflow_dry_run",
            "permission_contract",
            "repository_acceptance",
            "signed_release",
            "distribution_smoke",
            "goal_evidence",
            "completion",
        ),
        False,
        True,
    ),
    DeliveryProfileName.OFFLINE_BATCH: DeliveryProfile(
        DeliveryProfileName.OFFLINE_BATCH,
        _COMMON
        + (
            "package-build",
            "fixture-replay",
            "schedule-dry-run",
            "distribution-smoke",
        ),
        (
            "independent_review",
            "required_checks",
            "package",
            "fixture_replay",
            "schedule_dry_run",
            "distribution_smoke",
            "goal_evidence",
            "completion",
        ),
        False,
        False,
    ),
    DeliveryProfileName.STAGING_ONLY_PROTOTYPE: DeliveryProfile(
        DeliveryProfileName.STAGING_ONLY_PROTOTYPE,
        _COMMON + ("staging", "product-acceptance", "policy-approved-delivery"),
        (
            "independent_review",
            "required_checks",
            "staging",
            "product_acceptance",
            "policy_approved_delivery",
            "goal_evidence",
            "completion",
        ),
        False,
        False,
    ),
}


def delivery_profile(value: str | DeliveryProfileName) -> DeliveryProfile:
    try:
        key = value if isinstance(value, DeliveryProfileName) else DeliveryProfileName(value)
    except ValueError as error:
        raise ValueError(f"unknown delivery profile: {value}") from error
    return DELIVERY_PROFILES[key]


def infer_delivery_profile(goal_text: str, delivery_mode: str) -> DeliveryProfileName:
    """Bounded deterministic intake classification, never model-selected at runtime."""

    value = goal_text.lower()
    if "telegram" in value or "телеграм" in value or " bot" in value or "бот" in value:
        return DeliveryProfileName.TELEGRAM_BOT
    if any(token in value for token in ("cli", "command line", "консоль")):
        return DeliveryProfileName.CLI_PACKAGE
    if any(token in value for token in ("library", "sdk", "библиотек")):
        return DeliveryProfileName.LIBRARY_PACKAGE
    if any(token in value for token in ("github action", "workflow", "github automation")):
        return DeliveryProfileName.GITHUB_AUTOMATION
    if any(token in value for token in ("batch", "offline", "cron", "пакетн")):
        return DeliveryProfileName.OFFLINE_BATCH
    if any(token in value for token in ("web", "website", "веб", "сайт")):
        return DeliveryProfileName.WEB_APPLICATION
    if delivery_mode == "staging_only":
        return DeliveryProfileName.STAGING_ONLY_PROTOTYPE
    return DeliveryProfileName.DEPLOYED_SERVICE
