"""Versioned policy bundle loading and digesting."""

from __future__ import annotations

from typing import Any

import yaml

from .common import sha256_text, stable_json
from .config import FactoryConfig


def load_policies(config: FactoryConfig) -> dict[str, dict[str, Any]]:
    policies: dict[str, dict[str, Any]] = {}
    for path in config.policy_paths():
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise TypeError(f"Policy must be a mapping: {path}")
        policy_id = str(data.get("policy_id", path.stem))
        policies[policy_id] = data
    return policies


def policy_digest(config: FactoryConfig) -> str:
    entries = []
    for path in config.policy_paths():
        entries.append({"path": path.name, "content": path.read_text(encoding="utf-8")})
    return sha256_text(stable_json(entries))


def visibility_for_markers(config: FactoryConfig, markers: set[str]) -> str:
    policy = load_policies(config)["repository"]
    forced = set(policy["product_repository"]["automatic_force_private_markers"])
    return "private" if forced & markers else str(policy["product_repository"]["default_visibility"])


def owner_action_allowed(config: FactoryConfig, reason: str) -> bool:
    policy = load_policies(config)["owner-action"]
    return reason in set(policy["allowed_reasons"])
