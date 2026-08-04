"""Configuration loading and fail-closed validation."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml

from .common import sha256_text, stable_json


class ConfigError(ValueError):
    """Raised when a configuration violates a non-negotiable invariant."""


@dataclass(frozen=True)
class FactoryConfig:
    raw: dict[str, Any]
    source: Path

    @property
    def controller(self) -> dict[str, Any]:
        return cast(dict[str, Any], self.raw["controller"])

    @property
    def state_dir(self) -> Path:
        configured = self.raw.get("paths", {}).get("state")
        return self._local_or_configured_path(configured, self.source.parent / "state")

    @property
    def evidence_dir(self) -> Path:
        return self.state_dir / "evidence"

    @property
    def worktrees_dir(self) -> Path:
        configured = self.raw.get("paths", {}).get("worktrees")
        return self._local_or_configured_path(configured, self.state_dir / "worktrees")

    @property
    def database_path(self) -> Path:
        database_url = str(self.controller.get("database_url", ""))
        if database_url.startswith("sqlite:///"):
            configured = Path(database_url.removeprefix("sqlite:///"))
            if not self._looks_like_unix_path_on_windows(configured):
                return configured
            return self.source.parent / "state" / "controller.db"
        return self.state_dir / "controller.db"

    @staticmethod
    def _looks_like_unix_path_on_windows(path: Path) -> bool:
        return os.name == "nt" and str(path).replace("\\", "/").startswith("/var/")

    def _local_or_configured_path(self, value: Any, fallback: Path) -> Path:
        if not value:
            return fallback
        configured = Path(str(value))
        return fallback if self._looks_like_unix_path_on_windows(configured) else configured

    @property
    def max_active_workers(self) -> int:
        return int(self.controller.get("max_active_workers", 2))

    @property
    def max_active_products(self) -> int:
        return int(self.controller.get("max_active_products", 2))

    @property
    def reconcile_interval_seconds(self) -> float:
        return float(self.controller.get("reconcile_interval_seconds", 2.0))

    @property
    def max_repair_cycles(self) -> int:
        return int(self.controller.get("max_repair_cycles", 3))

    @property
    def agent_execution_timeout_seconds(self) -> int:
        return int(self.controller.get("agent_execution_timeout_seconds", 1800))

    @property
    def planning_execution_timeout_seconds(self) -> int:
        return int(self.controller.get("planning_execution_timeout_seconds", 900))

    @property
    def github_check_timeout_seconds(self) -> int:
        return int(self.controller.get("github_check_timeout_seconds", 300))

    @property
    def github_check_poll_seconds(self) -> float:
        return float(self.controller.get("github_check_poll_seconds", 5.0))

    @property
    def observation_seconds(self) -> int:
        return int(self.controller.get("observation_seconds", 14 * 24 * 60 * 60))

    @property
    def allowed_telegram_user_ids(self) -> set[str]:
        values = self.raw.get("telegram", {}).get("allowed_user_ids", [])
        configured = {str(value) for value in values}
        owner_id = os.environ.get("FACTORY_TELEGRAM_OWNER_ID", "").strip()
        if owner_id:
            configured.add(owner_id)
        return configured

    @property
    def intake_rate_limit_requests(self) -> int:
        return int(self.raw.get("intake", {}).get("rate_limit_requests", 10))

    @property
    def intake_rate_limit_window_seconds(self) -> int:
        return int(self.raw.get("intake", {}).get("rate_limit_window_seconds", 60))

    @property
    def max_idea_chars(self) -> int:
        return int(self.raw.get("intake", {}).get("max_idea_chars", 20_000))

    @property
    def max_attachments(self) -> int:
        return int(self.raw.get("intake", {}).get("max_attachments", 16))

    def policy_paths(self) -> list[Path]:
        configured = self.raw.get("paths", {}).get("policies")
        candidates = [Path(str(configured))] if configured else []
        candidates.extend((self.source.parent / "policies", self.source.parent.parent / "policies"))
        for root in candidates:
            if root.is_dir():
                return sorted(root.glob("*.yaml"))
        return []

    def schema_root(self) -> Path:
        configured = self.raw.get("paths", {}).get("schemas")
        candidates = [Path(str(configured))] if configured else []
        candidates.extend((self.source.parent / "schemas", self.source.parent.parent / "schemas"))
        for root in candidates:
            if root.is_dir():
                return root
        return self.source.parent / "schemas"


def load_config(path: Path | None = None) -> FactoryConfig:
    source = Path(path or os.environ.get("FACTORY_CONFIG", "config/factory-config.example.yaml"))
    if not source.is_absolute():
        source = (Path.cwd() / source).resolve()
    if not source.is_file():
        raise ConfigError(f"Configuration file does not exist: {source}")
    data = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ConfigError("Configuration root must be a mapping")
    config = FactoryConfig(data, source)
    errors = validate_config(config)
    if errors:
        raise ConfigError("; ".join(errors))
    return config


def validate_config(config: FactoryConfig) -> list[str]:
    errors: list[str] = []
    required_sections = ("controller", "paths", "github", "telegram", "deployment", "backup", "models")
    errors.extend(f"missing config section: {section}" for section in required_sections if section not in config.raw)
    controller = config.raw.get("controller", {})
    paths = config.raw.get("paths", {})
    models = config.raw.get("models", {})
    intake = config.raw.get("intake", {})
    qualification = config.raw.get("qualification")
    if int(controller.get("max_active_products", 2)) < 1:
        errors.append("max_active_products must be positive")
    if int(controller.get("max_active_products", 2)) > 2:
        errors.append("max_active_products must not exceed 2")
    if int(controller.get("max_active_workers", 2)) < 1:
        errors.append("max_active_workers must be positive")
    if int(controller.get("max_active_workers", 2)) > 2:
        errors.append("max_active_workers must not exceed 2")
    if float(controller.get("reconcile_interval_seconds", 2.0)) < 0.2:
        errors.append("reconcile_interval_seconds must be at least 0.2")
    if float(controller.get("capability_check_ttl_seconds", 300)) < 1:
        errors.append("capability_check_ttl_seconds must be at least 1")
    if float(controller.get("capability_retry_seconds", 15)) < 1:
        errors.append("capability_retry_seconds must be at least 1")
    if int(controller.get("max_repair_cycles", 3)) < 1:
        errors.append("max_repair_cycles must be positive")
    if int(controller.get("max_repair_cycles", 3)) > 3:
        errors.append("max_repair_cycles must not exceed 3")
    agent_timeout = int(controller.get("agent_execution_timeout_seconds", 1800))
    planning_timeout = int(controller.get("planning_execution_timeout_seconds", 900))
    if agent_timeout < 900:
        errors.append("agent_execution_timeout_seconds must be at least 900")
    if agent_timeout > 3600:
        errors.append("agent_execution_timeout_seconds must not exceed 3600")
    if planning_timeout < 60:
        errors.append("planning_execution_timeout_seconds must be at least 60")
    if planning_timeout > agent_timeout:
        errors.append(
            "planning_execution_timeout_seconds must not exceed "
            "agent_execution_timeout_seconds"
        )
    if int(controller.get("github_check_timeout_seconds", 300)) < 30:
        errors.append("github_check_timeout_seconds must be at least 30")
    if float(controller.get("github_check_poll_seconds", 5.0)) < 1.0:
        errors.append("github_check_poll_seconds must be at least 1")
    if int(controller.get("observation_seconds", 14 * 24 * 60 * 60)) < 0:
        errors.append("observation_seconds cannot be negative")
    if config.raw.get("network", {}).get("admin_bind", "127.0.0.1") != "127.0.0.1":
        errors.append("admin_bind must be localhost")
    if models.get("paid_api_fallback", False) is not False:
        errors.append("paid API fallback must be disabled")
    if config.raw.get("backup", {}).get("tool") != "restic":
        errors.append("backup tool must be restic")
    if int(
        config.raw.get("backup", {}).get(
            "max_proof_age_seconds",
            36 * 60 * 60,
        )
    ) < 1:
        errors.append("backup max_proof_age_seconds must be positive")
    if int(intake.get("rate_limit_requests", 10)) < 1:
        errors.append("intake rate_limit_requests must be positive")
    if int(intake.get("rate_limit_window_seconds", 60)) < 1:
        errors.append("intake rate_limit_window_seconds must be positive")
    if int(intake.get("max_idea_chars", 20_000)) < 3:
        errors.append("intake max_idea_chars must be at least 3")
    if int(intake.get("max_attachments", 16)) < 0:
        errors.append("intake max_attachments cannot be negative")
    for name in ("policies", "schemas", "prompts", "state", "worktrees", "logs"):
        if name not in paths:
            errors.append(f"missing path configuration: {name}")
    if qualification is not None:
        if not isinstance(qualification, dict):
            errors.append("qualification isolation config is invalid")
        else:
            plane = str(qualification.get("plane") or "")
            q6_keys = {
                "plane",
                "capability_attestation_path",
                "capability_attestation_digest",
            }
            canary_keys = {
                *q6_keys,
                "scenario_id",
                "scenario_digest",
                "controller_release_digest",
                "candidate_digest",
                "faults",
                "fault_receipt_root",
                "isolated_target_root",
                "existing_repository_url",
            }
            expected_keys = canary_keys if plane == "CLEAN_CANARY" else q6_keys
            if set(qualification) != expected_keys:
                errors.append("qualification isolation config is invalid")
            attestation_path = Path(
                str(qualification.get("capability_attestation_path") or "")
            )
            attestation_digest = str(
                qualification.get("capability_attestation_digest") or ""
            )
            deployment = config.raw.get("deployment", {})
            backup = config.raw.get("backup", {})
            target = deployment.get("production_target", {})
            if plane not in {"ISOLATED_Q6", "CLEAN_CANARY"}:
                errors.append("qualification plane is invalid")
            if not attestation_path.is_absolute():
                errors.append("qualification attestation path must be absolute")
            if len(attestation_digest) != 64 or any(
                character not in "0123456789abcdef" for character in attestation_digest
            ):
                errors.append("qualification attestation digest is invalid")
            if deployment.get("production_helper"):
                errors.append("isolated qualification cannot configure production helper")
            if not isinstance(target, dict) or target.get("mode") != "isolated_candidate":
                errors.append("isolated qualification requires isolated candidate target")
            if backup.get("offsite_configured") is not False:
                errors.append("isolated qualification cannot use offsite backup credentials")
            if plane == "CLEAN_CANARY":
                from .canary_qualification import load_canary_catalog

                scenario_id = str(qualification.get("scenario_id") or "")
                scenario_digest = str(qualification.get("scenario_digest") or "")
                candidate_digest = str(qualification.get("candidate_digest") or "")
                controller_digest = str(
                    qualification.get("controller_release_digest") or ""
                )
                fault_root = Path(str(qualification.get("fault_receipt_root") or ""))
                target_root = Path(str(qualification.get("isolated_target_root") or ""))
                catalog_path = config.source.parent.parent / "qualification" / "canaries" / "catalog.yaml"
                configured_catalog = config.raw.get("paths", {}).get("canary_catalog")
                if configured_catalog:
                    catalog_path = Path(str(configured_catalog))
                try:
                    scenario = load_canary_catalog(catalog_path)[scenario_id]
                except (KeyError, OSError, RuntimeError, ValueError):
                    errors.append("clean canary scenario contract is invalid")
                else:
                    if scenario.scenario_digest != scenario_digest:
                        errors.append("clean canary scenario digest differs")
                    if list(scenario.injected_faults) != qualification.get("faults"):
                        errors.append("clean canary fault contract differs")
                if any(
                    len(value) != 64
                    or any(character not in "0123456789abcdef" for character in value)
                    for value in (scenario_digest, candidate_digest, controller_digest)
                ):
                    errors.append("clean canary release digest is invalid")
                if not fault_root.is_absolute() or not target_root.is_absolute():
                    errors.append("clean canary roots must be absolute")
                if deployment.get("production_helper"):
                    errors.append("clean canary cannot configure production helper")
                existing_url = str(qualification.get("existing_repository_url") or "")
                if existing_url and not existing_url.startswith("https://github.com/"):
                    errors.append("clean canary existing repository URL is invalid")
    return errors


def config_digest(config: FactoryConfig) -> str:
    return sha256_text(stable_json(config.raw))
