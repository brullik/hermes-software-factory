"""Deployment policy checks; side effects are delegated to an external adapter."""

from __future__ import annotations

from dataclasses import dataclass

from .providers import ExternalBlocker


@dataclass(frozen=True)
class DeploymentDecision:
    status: str
    reason: str
    image_digest: str


class DeploymentGuard:
    def promote(
        self,
        *,
        environment: str,
        risk: str,
        image_digest: str,
        staging_digest: str | None,
        stateful: bool,
        offsite_backup_configured: bool,
        current_vps: bool = True,
    ) -> DeploymentDecision:
        if environment not in {"staging", "production"}:
            raise ValueError("environment must be staging or production")
        if not image_digest.startswith("sha256:"):
            raise ValueError("deployment requires an immutable image digest")
        if environment == "production" and staging_digest != image_digest:
            raise ValueError("production must promote the exact staging image digest")
        if environment == "production" and risk == "high" and current_vps:
            raise ExternalBlocker("High-risk production requires a separate VPS")
        if environment == "production" and stateful and not offsite_backup_configured:
            raise ExternalBlocker("Stateful production requires an offsite encrypted backup")
        return DeploymentDecision("READY", "policy checks passed", image_digest)
