"""Semantic attempt accounting and evidence-driven tier routing."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scripts.model_router import RouteDecision, RouteState, Tier, decide, initial_tier, load_policy

from .common import new_id
from .state import StateStore


class IdenticalAttemptError(RuntimeError):
    """Raised when a task would repeat an identical prompt digest."""


@dataclass(frozen=True)
class Attempt:
    attempt_id: str
    task_id: str
    tier: Tier
    attempt_kind: str
    prompt_digest: str
    semantic_counted: bool


class AttemptManager:
    def __init__(self, state: StateStore, routing_policy: Path) -> None:
        self.state = state
        self.policy = load_policy(routing_policy)

    def initial_tier(self, role: str, risk: str, complexity_score: int) -> Tier:
        return initial_tier(role, risk, complexity_score, self.policy)

    def begin(
        self,
        *,
        task_id: str,
        tier: Tier,
        attempt_kind: str,
        prompt_digest: str,
    ) -> Attempt:
        semantic_counted = attempt_kind != "transient_retry"
        attempt = Attempt(new_id("attempt"), task_id, tier, attempt_kind, prompt_digest, semantic_counted)
        inserted = self.state.record_attempt(
            attempt_id=attempt.attempt_id,
            task_id=task_id,
            tier=tier.value,
            attempt_kind=attempt_kind,
            prompt_digest=prompt_digest,
            status="started",
            semantic_counted=semantic_counted,
        )
        if not inserted:
            existing = next(
                (
                    item
                    for item in self.state.attempts_for_task(task_id)
                    if str(item["prompt_digest"]) == prompt_digest
                ),
                None,
            )
            if (
                existing is not None
                and str(existing["status"]) == "started"
                and str(existing["tier"]) == tier.value
                and str(existing["attempt_kind"]) == attempt_kind
            ):
                return Attempt(
                    str(existing["attempt_id"]),
                    task_id,
                    tier,
                    attempt_kind,
                    prompt_digest,
                    bool(existing["semantic_counted"]),
                )
            raise IdenticalAttemptError(f"Prompt digest already attempted for task {task_id}")
        return attempt

    def finish(self, attempt: Attempt, *, status: str, reason_code: str | None = None) -> None:
        self.state.update_attempt(attempt.attempt_id, status=status, reason_code=reason_code)

    def route(
        self,
        *,
        task_id: str,
        role: str,
        risk: str,
        complexity_score: int,
        tier: Tier,
        success: bool,
        reason_code: str | None,
        new_evidence: bool,
        current_attempt: Attempt | None = None,
    ) -> RouteDecision:
        semantic, transient = self.state.attempt_counts(task_id, tier.value)
        if (
            current_attempt is not None
            and current_attempt.tier.value == tier.value
            and current_attempt.semantic_counted
        ):
            semantic = max(0, semantic - 1)
        # ``semantic`` is the count *before* the current semantic attempt
        # because the routing policy decides whether this failure gets a
        # repair or an escalation.  Transient retries are different: the
        # current retry must count toward the retry cap, otherwise every
        # retry would subtract itself and the cap would never be reached.
        state = RouteState(role, risk, complexity_score, tier, semantic, transient)
        return decide(
            state,
            success=success,
            reason_code=reason_code,
            new_evidence=new_evidence,
            policy=self.policy,
        )
