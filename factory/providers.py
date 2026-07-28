"""Provider/model registry with health-gated, same-tier selection."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .config import FactoryConfig


class ExternalBlocker(RuntimeError):
    """Raised when an external credential or service probe is required."""


@dataclass(frozen=True)
class ModelSelection:
    provider: str
    alias: str
    model: str
    tier: str
    cli_provider: str | None = None


class ProviderRegistry:
    def __init__(self, config: FactoryConfig, registry_path: Path | None = None) -> None:
        configured = registry_path or Path(config.raw.get("models", {}).get("registry", ""))
        if not configured.is_file():
            configured = config.source.parent.parent / "config" / "model-routing" / "model-registry.template.yaml"
        self.path = configured
        data = yaml.safe_load(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise TypeError("Model registry must be a mapping")
        self.data: dict[str, Any] = data
        self._health: dict[str, bool] = {}

    def aliases(self) -> set[str]:
        return set(self.data.get("aliases", {}))

    def set_health(self, provider: str, healthy: bool) -> None:
        self._health[provider] = healthy

    def selected_model(self, alias: str) -> str | None:
        if alias not in self.aliases():
            raise ValueError(f"Unknown model alias: {alias}")
        selected = self.data["aliases"][alias].get("selected")
        return str(selected) if selected else None

    def candidate_models(self, alias: str) -> list[str]:
        if alias not in self.aliases():
            raise ValueError(f"Unknown model alias: {alias}")
        configured = self.data["aliases"][alias].get("candidates", [])
        if not isinstance(configured, list):
            raise TypeError(f"Candidates for alias {alias} must be a list")
        return [str(model) for model in configured if str(model).strip()]

    def providers_for(self, alias: str) -> list[str]:
        if alias not in self.aliases():
            raise ValueError(f"Unknown model alias: {alias}")
        providers = self.data.get("providers", {})
        return sorted(
            (
                str(provider)
                for provider, details in providers.items()
                if alias in details.get("permitted_aliases", [])
            ),
            key=lambda name: int(providers[name].get("priority", 999)),
        )

    def cli_provider_name(self, provider: str) -> str:
        providers = self.data.get("providers", {})
        details = providers.get(provider, {})
        configured = details.get("cli_provider")
        if configured:
            return str(configured)
        # The registry names are policy identities. Hermes uses its auth
        # provider identifiers at the CLI boundary.
        return {
            "openai_codex_subscription": "openai-codex",
            "nous_portal": "nous",
        }.get(provider, provider)

    def healthy_providers(self, alias: str) -> list[str]:
        providers = self.data.get("providers", {})
        result = []
        for provider, details in providers.items():
            if alias in details.get("permitted_aliases", []) and self._health.get(provider, False):
                result.append(str(provider))
        return sorted(result, key=lambda name: int(providers[name].get("priority", 999)))

    def select(self, alias: str, *, tier: str) -> ModelSelection:
        if alias not in self.aliases():
            raise ValueError(f"Unknown model alias: {alias}")
        healthy = self.healthy_providers(alias)
        if not healthy:
            raise ExternalBlocker(f"No healthy provider is available for alias {alias}")
        provider = healthy[0]
        selected = self.selected_model(alias)
        if not selected:
            raise ExternalBlocker(f"Provider discovery has not selected a model for alias {alias}")
        return ModelSelection(provider, alias, selected, tier, self.cli_provider_name(provider))
