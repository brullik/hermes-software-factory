"""Provider circuit breaker that never escalates tier for transient failures."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CircuitSnapshot:
    provider: str
    state: str
    transient_failures: int
    quota_exhausted: bool


class ProviderCircuitBreaker:
    def __init__(self, provider: str, *, failure_threshold: int = 3) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be positive")
        self.provider = provider
        self.failure_threshold = failure_threshold
        self._transient_failures = 0
        self._quota_exhausted = False
        self._state = "closed"

    def snapshot(self) -> CircuitSnapshot:
        return CircuitSnapshot(self.provider, self._state, self._transient_failures, self._quota_exhausted)

    def record_transient_failure(self) -> CircuitSnapshot:
        self._transient_failures += 1
        if self._transient_failures >= self.failure_threshold:
            self._state = "open"
        return self.snapshot()

    def record_quota_exhausted(self) -> CircuitSnapshot:
        self._quota_exhausted = True
        self._state = "open"
        return self.snapshot()

    def health_probe(self, healthy: bool) -> CircuitSnapshot:
        if healthy:
            self._transient_failures = 0
            self._quota_exhausted = False
            self._state = "closed"
        return self.snapshot()

    def allow_request(self) -> bool:
        return self._state == "closed" and not self._quota_exhausted
