#!/usr/bin/env python3
"""Deterministic model-tier routing reference implementation."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml


class Tier(StrEnum):
    DETERMINISTIC = "deterministic"
    LUNA = "luna"
    TERRA = "terra"
    SOL = "sol"


class FailureClass(StrEnum):
    NONE = "none"
    TRANSIENT = "transient"
    SEMANTIC = "semantic"
    POLICY = "policy"
    EXTERNAL = "external"


_TRANSIENT_CODES = {
    "http_429",
    "provider_5xx",
    "network_timeout",
    "process_crash_before_result",
    "malformed_transport",
}
_EXTERNAL_CODES = {
    "missing_credential",
    "oauth_device_code",
    "two_factor_authentication",
    "captcha",
    "external_account_creation",
    "paid_resource_purchase",
    "dns_action_without_access",
    "legal_decision",
    "unapproved_irreversible_production_action",
}


@dataclass(frozen=True)
class RouteState:
    role: str
    risk: str
    complexity_score: int
    tier: Tier
    semantic_attempts_at_tier: int = 0
    transient_retries: int = 0


@dataclass(frozen=True)
class RouteDecision:
    action: str
    tier: Tier
    reason: str
    semantic_attempt_counted: bool


def load_policy(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("Routing policy must be a mapping")
    return data


def classify_failure(reason_code: str | None) -> FailureClass:
    if not reason_code:
        return FailureClass.NONE
    if reason_code in _TRANSIENT_CODES:
        return FailureClass.TRANSIENT
    if reason_code in _EXTERNAL_CODES:
        return FailureClass.EXTERNAL
    if reason_code.startswith("policy_") or reason_code in {"scope_violation", "secret_exposure"}:
        return FailureClass.POLICY
    return FailureClass.SEMANTIC


def tier_rank(tier: Tier) -> int:
    return {
        Tier.DETERMINISTIC: 0,
        Tier.LUNA: 1,
        Tier.TERRA: 2,
        Tier.SOL: 3,
    }[tier]


def max_tier(a: Tier, b: Tier) -> Tier:
    return a if tier_rank(a) >= tier_rank(b) else b


def complexity_tier(score: int, policy: dict[str, Any]) -> Tier:
    thresholds = policy["complexity"]
    if score <= int(thresholds["luna_max_score"]):
        return Tier.LUNA
    if score <= int(thresholds["terra_max_score"]):
        return Tier.TERRA
    return Tier.SOL


def initial_tier(role: str, risk: str, complexity_score: int, policy: dict[str, Any]) -> Tier:
    floor_value = policy["role_floors"].get(role, {}).get(risk, "luna")
    floor = Tier(floor_value)
    return max_tier(floor, complexity_tier(complexity_score, policy))


def next_tier(tier: Tier) -> Tier | None:
    return {
        Tier.DETERMINISTIC: Tier.LUNA,
        Tier.LUNA: Tier.TERRA,
        Tier.TERRA: Tier.SOL,
        Tier.SOL: None,
    }[tier]


def decide(
    state: RouteState,
    *,
    success: bool,
    reason_code: str | None,
    new_evidence: bool,
    policy: dict[str, Any],
) -> RouteDecision:
    """Return the next action without invoking any model."""
    if success:
        return RouteDecision("complete", state.tier, "accepted", False)

    failure = classify_failure(reason_code)

    if failure is FailureClass.EXTERNAL:
        return RouteDecision("block_owner_action", state.tier, reason_code or "external", False)

    if failure is FailureClass.TRANSIENT:
        retry_max = int(policy["global"]["transient_retries"]["max"])
        if state.transient_retries < retry_max:
            return RouteDecision("retry_same_tier", state.tier, reason_code or "transient", False)
        return RouteDecision("fallback_same_tier_or_delay", state.tier, "transient_retries_exhausted", False)

    if failure is FailureClass.POLICY:
        promoted = next_tier(state.tier)
        if promoted is None:
            return RouteDecision("failed_safe", state.tier, reason_code or "policy_violation", True)
        return RouteDecision("escalate", promoted, reason_code or "policy_violation", True)

    limits = policy["global"]["semantic_attempts_per_tier"]
    allowed = int(limits[state.tier.value])
    if state.semantic_attempts_at_tier + 1 < allowed:
        if not new_evidence:
            return RouteDecision("failed_safe", state.tier, "identical_retry_forbidden", True)
        return RouteDecision("repair_same_tier", state.tier, reason_code or "semantic_failure", True)

    promoted = next_tier(state.tier)
    if promoted is None:
        return RouteDecision("failed_safe", state.tier, "expert_attempt_exhausted", True)
    return RouteDecision("escalate", promoted, "semantic_attempts_exhausted", True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--risk", choices=["low", "medium", "high"], required=True)
    parser.add_argument("--complexity", type=int, required=True)
    args = parser.parse_args()
    policy = load_policy(args.policy)
    tier = initial_tier(args.role, args.risk, args.complexity, policy)
    print(json.dumps({"tier": tier.value}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
