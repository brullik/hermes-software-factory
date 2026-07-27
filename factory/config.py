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
        return int(self.controller.get("max_active_products", 1))

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
    if int(controller.get("max_active_products", 1)) < 1:
        errors.append("max_active_products must be positive")
    if int(controller.get("max_active_products", 1)) > 1:
        errors.append("max_active_products must not exceed 1")
    if int(controller.get("max_active_workers", 2)) < 1:
        errors.append("max_active_workers must be positive")
    if int(controller.get("max_active_workers", 2)) > 2:
        errors.append("max_active_workers must not exceed 2")
    if config.raw.get("network", {}).get("admin_bind", "127.0.0.1") != "127.0.0.1":
        errors.append("admin_bind must be localhost")
    if models.get("paid_api_fallback", False) is not False:
        errors.append("paid API fallback must be disabled")
    if config.raw.get("backup", {}).get("tool") != "restic":
        errors.append("backup tool must be restic")
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
    return errors


def config_digest(config: FactoryConfig) -> str:
    return sha256_text(stable_json(config.raw))
