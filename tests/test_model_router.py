from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from model_router import RouteState, Tier, decide, initial_tier, load_policy


class ModelRouterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = load_policy(ROOT / "policies" / "model-routing-policy.yaml")

    def test_simple_builder_starts_luna(self) -> None:
        self.assertEqual(initial_tier("builder", "low", 2, self.policy), Tier.LUNA)

    def test_medium_architect_starts_terra(self) -> None:
        self.assertEqual(initial_tier("solution_architect", "medium", 2, self.policy), Tier.TERRA)

    def test_high_security_starts_sol(self) -> None:
        self.assertEqual(initial_tier("security_reviewer", "high", 1, self.policy), Tier.SOL)

    def test_first_luna_failure_repairs_with_new_evidence(self) -> None:
        state = RouteState("builder", "low", 2, Tier.LUNA, semantic_attempts_at_tier=0)
        result = decide(
            state,
            success=False,
            reason_code="unit_test_failure",
            new_evidence=True,
            policy=self.policy,
        )
        self.assertEqual(result.action, "repair_same_tier")
        self.assertEqual(result.tier, Tier.LUNA)

    def test_identical_retry_is_forbidden(self) -> None:
        state = RouteState("builder", "low", 2, Tier.LUNA, semantic_attempts_at_tier=0)
        result = decide(
            state,
            success=False,
            reason_code="unit_test_failure",
            new_evidence=False,
            policy=self.policy,
        )
        self.assertEqual(result.action, "failed_safe")
        self.assertEqual(result.reason, "identical_retry_forbidden")

    def test_second_luna_failure_escalates_terra(self) -> None:
        state = RouteState("builder", "low", 2, Tier.LUNA, semantic_attempts_at_tier=1)
        result = decide(
            state,
            success=False,
            reason_code="unit_test_failure",
            new_evidence=True,
            policy=self.policy,
        )
        self.assertEqual(result.action, "escalate")
        self.assertEqual(result.tier, Tier.TERRA)

    def test_second_terra_failure_escalates_sol(self) -> None:
        state = RouteState("builder", "medium", 5, Tier.TERRA, semantic_attempts_at_tier=1)
        result = decide(
            state,
            success=False,
            reason_code="integration_failure",
            new_evidence=True,
            policy=self.policy,
        )
        self.assertEqual(result.action, "escalate")
        self.assertEqual(result.tier, Tier.SOL)

    def test_sol_failure_stops_safely(self) -> None:
        state = RouteState("builder", "high", 8, Tier.SOL, semantic_attempts_at_tier=0)
        result = decide(
            state,
            success=False,
            reason_code="expert_failure",
            new_evidence=True,
            policy=self.policy,
        )
        self.assertEqual(result.action, "failed_safe")

    def test_429_does_not_escalate(self) -> None:
        state = RouteState("builder", "low", 2, Tier.LUNA, transient_retries=0)
        result = decide(
            state,
            success=False,
            reason_code="http_429",
            new_evidence=False,
            policy=self.policy,
        )
        self.assertEqual(result.action, "retry_same_tier")
        self.assertEqual(result.tier, Tier.LUNA)
        self.assertFalse(result.semantic_attempt_counted)

    def test_transient_retry_cap_counts_the_current_retry(self) -> None:
        state = RouteState("builder", "low", 2, Tier.LUNA, transient_retries=3)
        result = decide(
            state,
            success=False,
            reason_code="network_timeout",
            new_evidence=False,
            policy=self.policy,
        )
        self.assertEqual(result.action, "fallback_same_tier_or_delay")
        self.assertEqual(result.reason, "transient_retries_exhausted")

    def test_agent_execution_timeout_retries_without_semantic_escalation(self) -> None:
        state = RouteState("builder", "low", 2, Tier.LUNA, transient_retries=0)
        result = decide(
            state,
            success=False,
            reason_code="agent_execution_timeout",
            new_evidence=False,
            policy=self.policy,
        )
        self.assertEqual(result.action, "retry_same_tier")
        self.assertEqual(result.tier, Tier.LUNA)
        self.assertFalse(result.semantic_attempt_counted)

    def test_release_policy_violation_is_a_policy_failure(self) -> None:
        state = RouteState("release_operator", "medium", 2, Tier.TERRA)
        result = decide(
            state,
            success=False,
            reason_code="release_policy_violation",
            new_evidence=False,
            policy=self.policy,
        )
        self.assertEqual(result.action, "escalate")
        self.assertEqual(result.tier, Tier.SOL)

    def test_external_blocker_creates_owner_action(self) -> None:
        state = RouteState("release_operator", "medium", 2, Tier.TERRA)
        result = decide(
            state,
            success=False,
            reason_code="oauth_device_code",
            new_evidence=False,
            policy=self.policy,
        )
        self.assertEqual(result.action, "block_owner_action")


if __name__ == "__main__":
    unittest.main()
