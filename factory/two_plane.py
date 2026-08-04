"""Stable A, Candidate B, and independent verifier isolation primitives."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .common import redact_text, sha256_text, stable_json
from .release_qualification import ReleaseQualificationGovernor


class PlaneIsolationError(RuntimeError):
    """Release planes share authority, state, or credentials."""


@dataclass(frozen=True)
class PlaneBoundary:
    plane: str
    root: Path
    database: Path
    credential_fingerprints: frozenset[str]
    production_authority: bool
    production_helper_available: bool


@dataclass(frozen=True)
class TwoPlaneLayout:
    stable_a: PlaneBoundary
    candidate_b: PlaneBoundary
    verifier: PlaneBoundary

    def validate(self) -> None:
        if (
            self.stable_a.plane != "LTS_A"
            or self.candidate_b.plane != "CANDIDATE_B"
            or self.verifier.plane != "INDEPENDENT_VERIFIER"
        ):
            raise PlaneIsolationError("release plane identities are not exact")
        boundaries = (self.stable_a, self.candidate_b, self.verifier)
        roots = [item.root.resolve() for item in boundaries]
        databases = [item.database.resolve() for item in boundaries]
        if len(set(roots)) != len(roots) or len(set(databases)) != len(databases):
            raise PlaneIsolationError("release planes must use distinct roots and databases")
        for index, root in enumerate(roots):
            if any(root in other.parents or other in root.parents for other in roots[index + 1 :]):
                raise PlaneIsolationError("release plane roots must not be nested")
        if not self.stable_a.production_authority:
            raise PlaneIsolationError("Stable A must own production authority")
        if self.candidate_b.production_authority or self.verifier.production_authority:
            raise PlaneIsolationError("Candidate B/verifier cannot own production authority")
        if self.candidate_b.production_helper_available:
            raise PlaneIsolationError("Candidate B cannot access the production helper")
        if self.verifier.production_helper_available:
            raise PlaneIsolationError("verifier cannot access the production helper")
        for left_index, left in enumerate(boundaries):
            for right in boundaries[left_index + 1 :]:
                if left.credential_fingerprints & right.credential_fingerprints:
                    raise PlaneIsolationError("release planes share a credential fingerprint")
        if self.verifier.credential_fingerprints:
            raise PlaneIsolationError("independent verifier must be credential-free")


@dataclass(frozen=True)
class ShadowReplayReport:
    event_count: int
    matched_count: int
    diverged_count: int
    redaction_count: int
    candidate_side_effect_count: int
    candidate_production_credentials: int
    stable_write_count: int
    candidate_write_count: int
    stable_task_count: int
    candidate_task_count: int
    max_evidence_indirection: int
    report_digest: str


DecisionFunction = Callable[[Mapping[str, Any]], Mapping[str, Any]]


@dataclass(frozen=True)
class BoundaryObservation:
    stable_state_digest: str
    candidate_state_digest: str
    candidate_side_effect_receipt_count: int
    candidate_production_credentials: int


BoundaryObserver = Callable[[], BoundaryObservation]


def _path_inventory_digest(root: Path, database: Path) -> str:
    records: list[tuple[str, int, int]] = []
    candidates = [database]
    if root.is_dir():
        excluded = {".git", ".venv", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__"}
        for current, directories, filenames in os.walk(root):
            directories[:] = sorted(name for name in directories if name not in excluded)
            candidates.extend(Path(current) / name for name in sorted(filenames))
    for path in sorted(set(candidates)):
        if not path.is_file() or path.is_symlink():
            continue
        metadata = path.stat()
        records.append((str(path.resolve()), metadata.st_size, metadata.st_mtime_ns))
    return sha256_text(stable_json(records))


def _side_effect_receipt_count(database: Path) -> int:
    if not database.is_file():
        return 0
    try:
        connection = sqlite3.connect(
            f"file:{database.resolve().as_posix()}?mode=ro&immutable=1",
            uri=True,
        )
        try:
            row = connection.execute(
                "SELECT COUNT(*) FROM side_effect_receipts"
            ).fetchone()
            return int(row[0]) if row is not None else 0
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise PlaneIsolationError("candidate side-effect ledger is unreadable") from error


def observe_layout(layout: TwoPlaneLayout) -> BoundaryObservation:
    """Capture read-only state used to prove a shadow replay had no effects."""

    layout.validate()
    shared = layout.stable_a.credential_fingerprints & (
        layout.candidate_b.credential_fingerprints
    )
    return BoundaryObservation(
        stable_state_digest=_path_inventory_digest(
            layout.stable_a.root, layout.stable_a.database
        ),
        candidate_state_digest=_path_inventory_digest(
            layout.candidate_b.root, layout.candidate_b.database
        ),
        candidate_side_effect_receipt_count=_side_effect_receipt_count(
            layout.candidate_b.database
        ),
        candidate_production_credentials=len(shared),
    )


class ShadowDifferentialLab:
    """Mirror redacted events to A/B and persist comparison, never B effects."""

    def __init__(
        self,
        *,
        layout: TwoPlaneLayout,
        governor: ReleaseQualificationGovernor,
        epoch_id: str,
        stable_decide: DecisionFunction,
        candidate_decide: DecisionFunction,
        observe_boundaries: BoundaryObserver | None = None,
    ) -> None:
        layout.validate()
        self.layout = layout
        self.governor = governor
        self.epoch_id = epoch_id
        self.stable_decide = stable_decide
        self.candidate_decide = candidate_decide
        self.observe_boundaries = observe_boundaries or (lambda: observe_layout(layout))

    @staticmethod
    def _redact_event(event: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
        serialized = stable_json(dict(event))
        redacted, findings = redact_text(serialized)
        import json

        value = json.loads(redacted)
        if not isinstance(value, dict):
            raise PlaneIsolationError("redacted shadow event is not an object")
        return value, sum(int(item["count"]) for item in findings)

    @staticmethod
    def _decision(value: Mapping[str, Any]) -> dict[str, Any]:
        decision = dict(value)
        required = {
            "chosen_transition",
            "failure_owner",
            "capability_proof_digest",
            "root_cause_key",
            "task_count",
            "side_effect_intent",
            "terminal_result",
        }
        if set(decision) != required:
            raise PlaneIsolationError("shadow decision schema is not closed")
        for key in ("capability_proof_digest", "root_cause_key"):
            digest_value = str(decision[key])
            if len(digest_value) != 64 or any(
                character not in "0123456789abcdef"
                for character in digest_value
            ):
                raise PlaneIsolationError("shadow decision digest is invalid")
        task_count = decision["task_count"]
        if isinstance(task_count, bool) or not isinstance(task_count, int) or task_count < 0:
            raise PlaneIsolationError("shadow task count is invalid")
        return decision

    def replay(self, events: Sequence[Mapping[str, Any]]) -> ShadowReplayReport:
        matched = 0
        diverged = 0
        redactions = 0
        before = self.observe_boundaries()
        event_digests: list[str] = []
        stable_tasks = 0
        candidate_tasks = 0
        for event in events:
            redacted, count = self._redact_event(event)
            redactions += count
            event_digest = sha256_text(stable_json(redacted))
            event_digests.append(event_digest)
            stable = self._decision(self.stable_decide(redacted))
            candidate = self._decision(self.candidate_decide(redacted))
            stable_tasks += int(stable["task_count"])
            candidate_tasks += int(candidate["task_count"])
            comparison = self.governor.compare_shadow_decision(
                epoch_id=self.epoch_id,
                event_digest=event_digest,
                stable_decision=stable,
                candidate_decision=candidate,
            )
            if comparison == "MATCH":
                matched += 1
            else:
                diverged += 1
        after = self.observe_boundaries()
        candidate_effects = (
            after.candidate_side_effect_receipt_count
            - before.candidate_side_effect_receipt_count
        )
        if candidate_effects < 0:
            raise PlaneIsolationError("candidate side-effect ledger regressed")
        stable_writes = int(after.stable_state_digest != before.stable_state_digest)
        candidate_writes = int(
            after.candidate_state_digest != before.candidate_state_digest
        )
        production_credentials = max(
            before.candidate_production_credentials,
            after.candidate_production_credentials,
        )
        payload = {
            "epoch_id": self.epoch_id,
            "event_digests": event_digests,
            "matched": matched,
            "diverged": diverged,
            "redactions": redactions,
            "candidate_side_effects": candidate_effects,
            "candidate_production_credentials": production_credentials,
            "stable_writes": stable_writes,
            "candidate_writes": candidate_writes,
            "stable_task_count": stable_tasks,
            "candidate_task_count": candidate_tasks,
            "max_evidence_indirection": 1 if events else 0,
        }
        return ShadowReplayReport(
            event_count=len(events),
            matched_count=matched,
            diverged_count=diverged,
            redaction_count=redactions,
            candidate_side_effect_count=candidate_effects,
            candidate_production_credentials=production_credentials,
            stable_write_count=stable_writes,
            candidate_write_count=candidate_writes,
            stable_task_count=stable_tasks,
            candidate_task_count=candidate_tasks,
            max_evidence_indirection=1 if events else 0,
            report_digest=sha256_text(stable_json(payload)),
        )
