#!/usr/bin/env python3
"""Deterministic safe pilot repository scoring."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

EXCLUSION_MARKERS = {
    "bybit",
    "trading",
    "finance",
    "payment",
    "billing",
    "real_money",
    "medical",
    "legal",
    "confidential",
    "exploit",
}

WEIGHTS = {
    "react_or_next": 2,
    "rest_api": 2,
    "postgresql": 2,
    "telegram": 1,
    "authentication": 1,
    "tests": 2,
    "docker": 1,
    "ci": 1,
    "monitoring": 1,
    "rollback": 1,
}


@dataclass(frozen=True)
class Candidate:
    repository: str
    features: frozenset[str]
    markers: frozenset[str]
    buildable: bool = True


@dataclass(frozen=True)
class Score:
    repository: str
    points: int
    excluded: bool
    reasons: tuple[str, ...]


def score(candidate: Candidate) -> Score:
    reasons: list[str] = []
    matched_exclusions = sorted(candidate.markers & EXCLUSION_MARKERS)
    if matched_exclusions:
        reasons.append("risk markers: " + ", ".join(matched_exclusions))
    if not candidate.buildable:
        reasons.append("repository is not buildable")
    excluded = bool(reasons)
    points = sum(weight for feature, weight in WEIGHTS.items() if feature in candidate.features)
    return Score(candidate.repository, points, excluded, tuple(reasons))


def select(candidates: Iterable[Candidate], minimum_score: int = 10) -> Score | None:
    scores = [score(candidate) for candidate in candidates]
    eligible = [item for item in scores if not item.excluded and item.points >= minimum_score]
    if not eligible:
        return None
    return min(eligible, key=lambda item: (-item.points, item.repository))
