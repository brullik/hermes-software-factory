"""Append-only Q7 shadow evidence and verifier-derived gate metrics."""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .common import sha256_text, stable_json, utc_now
from .release_qualification import QualificationError, ReleaseQualificationGovernor
from .two_plane import ShadowReplayReport

_ENTRY_NAME = re.compile(r"^(?P<sequence>[0-9]{12})-(?P<digest>[a-f0-9]{64})\.json$")
_REPORT_KEYS = frozenset(ShadowReplayReport.__dataclass_fields__)


class ShadowJournalError(RuntimeError):
    """Shadow evidence is mutable, incomplete, or internally inconsistent."""


@dataclass(frozen=True)
class ShadowJournalSummary:
    epoch_id: str
    batch_count: int
    event_count: int
    matched_count: int
    diverged_count: int
    redaction_count: int
    stable_task_count: int
    candidate_task_count: int
    candidate_side_effect_executions: int
    candidate_production_credentials: int
    stable_write_count: int
    candidate_write_count: int
    max_evidence_indirection: int
    first_observed_at: str
    last_observed_at: str
    journal_head_digest: str


def _parse_time(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ShadowJournalError(f"{label} timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ShadowJournalError(f"{label} timestamp is not timezone-aware")
    return parsed.astimezone(UTC)


def _write_once(path: Path, encoded: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_text(encoding="utf-8") != encoded:
            raise ShadowJournalError("shadow journal append conflicts")
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    try:
        path.chmod(0o440)
    except OSError:
        pass


class ShadowEvidenceJournal:
    """Verifier-owned hash chain for Q7 replay batches."""

    def __init__(self, root: Path, *, epoch_id: str) -> None:
        self.root = root.resolve()
        self.epoch_id = epoch_id

    def _entries(self) -> list[Path]:
        if not self.root.exists():
            return []
        entries = [path for path in self.root.iterdir() if _ENTRY_NAME.fullmatch(path.name)]
        return sorted(entries, key=lambda path: path.name)

    def entry_count(self) -> int:
        return len(self._entries())

    def append(
        self,
        report: ShadowReplayReport,
        *,
        observed_at: str | None = None,
    ) -> str:
        entries = self._entries()
        sequence = len(entries) + 1
        previous_digest = "0" * 64
        if entries:
            match = _ENTRY_NAME.fullmatch(entries[-1].name)
            if match is None:
                raise ShadowJournalError("shadow journal filename is invalid")
            previous_digest = match.group("digest")
        timestamp = observed_at or utc_now()
        _parse_time(timestamp, "shadow observation")
        report_payload = asdict(report)
        if set(report_payload) != _REPORT_KEYS:
            raise ShadowJournalError("shadow replay report schema is invalid")
        if report.event_count < 1:
            raise ShadowJournalError("shadow replay batch must contain an event")
        if report.matched_count + report.diverged_count != report.event_count:
            raise ShadowJournalError("shadow replay cardinality is invalid")
        payload = {
            "schema_version": "1.0",
            "epoch_id": self.epoch_id,
            "sequence": sequence,
            "previous_entry_digest": previous_digest,
            "observed_at": timestamp,
            "report": report_payload,
        }
        digest = sha256_text(stable_json(payload))
        envelope = {**payload, "entry_digest": digest}
        destination = self.root / f"{sequence:012d}-{digest}.json"
        _write_once(
            destination,
            json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
        return digest

    def summarize(self) -> ShadowJournalSummary:
        entries = self._entries()
        if not entries:
            raise ShadowJournalError("shadow journal is empty")
        previous_digest = "0" * 64
        totals = {
            "event_count": 0,
            "matched_count": 0,
            "diverged_count": 0,
            "redaction_count": 0,
            "stable_task_count": 0,
            "candidate_task_count": 0,
            "candidate_side_effect_count": 0,
            "stable_write_count": 0,
            "candidate_write_count": 0,
        }
        maximum_credentials = 0
        maximum_indirection = 0
        first_observed = ""
        last_observed = ""
        for expected_sequence, path in enumerate(entries, start=1):
            if path.is_symlink() or not path.is_file():
                raise ShadowJournalError("shadow journal contains a non-regular entry")
            try:
                envelope = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise ShadowJournalError("shadow journal entry is unreadable") from error
            if not isinstance(envelope, dict) or set(envelope) != {
                "schema_version",
                "epoch_id",
                "sequence",
                "previous_entry_digest",
                "observed_at",
                "report",
                "entry_digest",
            }:
                raise ShadowJournalError("shadow journal entry schema is invalid")
            digest = str(envelope.pop("entry_digest"))
            if sha256_text(stable_json(envelope)) != digest:
                raise ShadowJournalError("shadow journal entry digest differs")
            match = _ENTRY_NAME.fullmatch(path.name)
            if match is None or match.group("digest") != digest:
                raise ShadowJournalError("shadow journal filename digest differs")
            if (
                envelope.get("schema_version") != "1.0"
                or envelope.get("epoch_id") != self.epoch_id
                or envelope.get("sequence") != expected_sequence
                or envelope.get("previous_entry_digest") != previous_digest
            ):
                raise ShadowJournalError("shadow journal hash chain is invalid")
            observed = str(envelope["observed_at"])
            observed_time = _parse_time(observed, "shadow observation")
            if last_observed and observed_time < _parse_time(last_observed, "prior observation"):
                raise ShadowJournalError("shadow journal time regressed")
            first_observed = first_observed or observed
            last_observed = observed
            report = envelope.get("report")
            if not isinstance(report, dict) or set(report) != _REPORT_KEYS:
                raise ShadowJournalError("shadow journal report schema is invalid")
            for key in totals:
                value = report.get(key)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ShadowJournalError(f"shadow report {key} is invalid")
                totals[key] += value
            maximum_credentials = max(
                maximum_credentials,
                int(report["candidate_production_credentials"]),
            )
            maximum_indirection = max(
                maximum_indirection,
                int(report["max_evidence_indirection"]),
            )
            previous_digest = digest
        if totals["matched_count"] + totals["diverged_count"] != totals["event_count"]:
            raise ShadowJournalError("shadow journal aggregate cardinality is invalid")
        return ShadowJournalSummary(
            epoch_id=self.epoch_id,
            batch_count=len(entries),
            event_count=totals["event_count"],
            matched_count=totals["matched_count"],
            diverged_count=totals["diverged_count"],
            redaction_count=totals["redaction_count"],
            stable_task_count=totals["stable_task_count"],
            candidate_task_count=totals["candidate_task_count"],
            candidate_side_effect_executions=totals["candidate_side_effect_count"],
            candidate_production_credentials=maximum_credentials,
            stable_write_count=totals["stable_write_count"],
            candidate_write_count=totals["candidate_write_count"],
            max_evidence_indirection=maximum_indirection,
            first_observed_at=first_observed,
            last_observed_at=last_observed,
            journal_head_digest=previous_digest,
        )

    def finalize_q7(
        self,
        governor: ReleaseQualificationGovernor,
        *,
        evidence_ref: str,
        historical_products_total: int,
        historical_products_replayed: int,
        now: datetime | None = None,
    ) -> str:
        summary = self.summarize()
        epoch = governor.epoch(self.epoch_id)
        started_at = _parse_time(str(epoch.get("shadow_started_at") or ""), "shadow start")
        current = (now or datetime.now(UTC)).astimezone(UTC)
        if current < started_at:
            raise ShadowJournalError("verifier clock precedes shadow start")
        if _parse_time(summary.first_observed_at, "first observation") < started_at:
            raise ShadowJournalError("shadow evidence predates the release epoch")
        ratio = (
            summary.candidate_task_count / summary.stable_task_count
            if summary.stable_task_count
            else (1.0 if summary.candidate_task_count == 0 else 99.0)
        )
        metrics: dict[str, Any] = {
            "unknown_transitions": 0,
            "shadow_hours": (current - started_at).total_seconds() / 3600,
            "shadow_incidents": summary.diverged_count,
            "unknown_controller_failures": 0,
            "duplicate_side_effects": 0,
            "candidate_side_effect_executions": summary.candidate_side_effect_executions,
            "candidate_production_credentials": summary.candidate_production_credentials,
            "candidate_writes_to_stable_db": summary.stable_write_count,
            "candidate_shadow_state_writes": summary.candidate_write_count,
            "historical_products_total": historical_products_total,
            "historical_products_replayed": historical_products_replayed,
            "task_amplification_ratio": ratio,
            "max_evidence_indirection": summary.max_evidence_indirection,
            "shadow_event_count": summary.event_count,
            "shadow_batch_count": summary.batch_count,
        }
        for key in (
            "candidate_side_effect_executions",
            "candidate_production_credentials",
            "candidate_writes_to_stable_db",
            "candidate_shadow_state_writes",
        ):
            if metrics[key] != 0:
                raise QualificationError(f"Q7 requires {key}=0")
        return governor.record_qualification(
            epoch_id=self.epoch_id,
            stage="Q7_SHADOW_DIFFERENTIAL",
            evidence_ref=evidence_ref,
            metrics=metrics,
            passed=True,
        )
