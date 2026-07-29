"""Deterministic capability preflight and owner-action boundary."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Protocol

from .autonomy import CAPABILITY_PROFILES, OWNER_ACTION_REASONS
from .common import sha256_text, stable_json, utc_now
from .config import FactoryConfig
from .state import StateStore


@dataclass(frozen=True)
class CapabilityCheck:
    capability: str
    status: str
    provider: str
    reason_code: str | None = None
    scope: dict[str, Any] | None = None

    def validate(self) -> None:
        if self.status not in {
            "AVAILABLE",
            "MISSING_EXTERNAL",
            "DENIED_POLICY",
            "EXPIRED",
        }:
            raise ValueError("capability check status is invalid")
        if self.status == "MISSING_EXTERNAL" and self.reason_code not in OWNER_ACTION_REASONS:
            raise ValueError("external capability gap is not owner-action eligible")


class CapabilityProbe(Protocol):
    def check(
        self,
        capability: str,
        *,
        product: dict[str, Any],
    ) -> CapabilityCheck: ...


class ConfiguredCapabilityProbe:
    """Read-only host checks; credential values are never returned or persisted."""

    def __init__(self, config: FactoryConfig) -> None:
        self.config = config

    @staticmethod
    def _command_ok(argv: list[str]) -> bool:
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "Never",
        }
        try:
            completed = subprocess.run(
                argv,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return completed.returncode == 0

    def check(
        self,
        capability: str,
        *,
        product: dict[str, Any],
    ) -> CapabilityCheck:
        if capability.startswith(("github.", "git.")):
            if shutil.which("git") is None or shutil.which("gh") is None:
                return CapabilityCheck(
                    capability,
                    "DENIED_POLICY",
                    "configured-host",
                    "controller_tool_missing",
                )
            if not self._command_ok(["gh", "auth", "status"]):
                return CapabilityCheck(
                    capability,
                    "MISSING_EXTERNAL",
                    "github",
                    "missing_credential",
                )
            return CapabilityCheck(capability, "AVAILABLE", "github")
        if capability == "staging.deploy":
            writable = self.config.worktrees_dir
            try:
                writable.mkdir(parents=True, exist_ok=True)
                available = os.access(writable, os.W_OK)
            except OSError:
                available = False
            return CapabilityCheck(
                capability,
                "AVAILABLE" if available else "DENIED_POLICY",
                "configured-host",
                None if available else "controller_staging_unwritable",
            )
        deployment = self.config.raw.get("deployment", {})
        backup = self.config.raw.get("backup", {})
        if capability == "backup.verify":
            available = backup.get("tool") == "restic"
        elif capability in {
            "production.deploy_transactional",
            "rollback.execute",
        }:
            available = bool(
                deployment.get("production_helper")
                or deployment.get("transactional_helper")
                or deployment.get("host")
            )
        else:
            available = True
        return CapabilityCheck(
            capability,
            "AVAILABLE" if available else "DENIED_POLICY",
            "configured-host",
            None if available else "controller_adapter_unconfigured",
        )


class CapabilityBroker:
    """Persist capability facts and route internal gaps to controller incidents."""

    def __init__(
        self,
        config: FactoryConfig,
        state: StateStore,
        probe: CapabilityProbe | None = None,
    ) -> None:
        self.config = config
        self.state = state
        self.probe = probe or ConfiguredCapabilityProbe(config)

    @staticmethod
    def required_for_product(product: dict[str, Any]) -> tuple[str, ...]:
        profiles = ["repository_bootstrap", "release_staging", "release_production"]
        return tuple(
            dict.fromkeys(
                capability
                for profile in profiles
                for capability in CAPABILITY_PROFILES[profile]
            )
        )

    def _controller_incident(
        self,
        product_id: str,
        check: CapabilityCheck,
    ) -> str:
        reason = check.reason_code or "controller_capability_unknown"
        incident_id = (
            "incident-"
            + sha256_text(
                stable_json([product_id, check.capability, check.provider, reason])
            )[:20]
        )
        evidence_ref = (
            f"internal://capability/{sha256_text(check.capability)[:16]}"
        )
        with self.state._lock, self.state._connection:
            self.state._connection.execute(
                """INSERT OR IGNORE INTO controller_incidents
                   (incident_id, product_id, task_id, reason_code,
                    evidence_ref, status, created_at)
                   VALUES (?, ?, NULL, ?, ?, 'OPEN', ?)""",
                (incident_id, product_id, reason, evidence_ref, utc_now()),
            )
            self.state._record_event(
                product_id,
                None,
                "controller_incident_created",
                {
                    "incident_id": incident_id,
                    "reason_code": reason,
                    "capability": check.capability,
                },
            )
        return incident_id

    def preflight_product(self, product_id: str) -> tuple[CapabilityCheck, ...]:
        product = self.state.get_product(product_id)
        if product is None:
            raise KeyError(product_id)
        results: list[CapabilityCheck] = []
        changed_external: dict[str, list[str]] = {}
        for capability in self.required_for_product(product):
            check = self.probe.check(capability, product=product)
            check.validate()
            results.append(check)
            with self.state._lock:
                previous = self.state._connection.execute(
                    """SELECT status, provider FROM capability_grants
                       WHERE product_id=? AND task_id IS NULL AND capability=?
                       ORDER BY created_at DESC LIMIT 1""",
                    (product_id, capability),
                ).fetchone()
            changed = (
                previous is None
                or str(previous["status"]) != check.status
                or str(previous["provider"]) != check.provider
            )
            self.state.grant_capability(
                product_id=product_id,
                task_id=None,
                capability=capability,
                scope=check.scope or {"product_id": product_id},
                provider=check.provider,
                status=check.status,
                expires_at=None,
            )
            if changed and check.status in {"DENIED_POLICY", "EXPIRED"}:
                self._controller_incident(product_id, check)
            elif changed and check.status == "MISSING_EXTERNAL":
                assert check.reason_code is not None
                changed_external.setdefault(check.reason_code, []).append(capability)
        for reason_code, capabilities in changed_external.items():
            self.state.record_event(
                product_id=product_id,
                task_id=None,
                event_type="owner_action_required",
                payload={
                    "reason_code": reason_code,
                    "capabilities": sorted(capabilities),
                },
            )
        return tuple(results)

    def preflight_all(self) -> dict[str, tuple[CapabilityCheck, ...]]:
        return {
            str(product["product_id"]): self.preflight_product(
                str(product["product_id"])
            )
            for product in self.state.list_products()
            if str(product["status"])
            not in {"CANCELLED", "COMPLETED", "FAILED_SAFE"}
        }
