"""Minimal Context Pack builder with file scope and provenance enforcement."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts.context_pack import select_files
from scripts.prompt_compiler import (
    find_secret_candidate_diagnostics,
    redact_secret_candidates,
)

from .artifacts import ArtifactStore
from .common import redact_text
from .config import FactoryConfig

_TRUNCATION_MARKER = "\n...[TRUNCATED_BY_CONTROLLER_TOTAL_BUDGET]...\n"
_EXACT_STRUCTURAL_KEYS = frozenset(
    {
        "accepted_unaffected_node_keys",
        "capability_profile",
        "conflict_keys",
        "default_branch",
        "delivery_mode",
        "dependencies",
        "evidence_profile",
        "failure_class",
        "fingerprint",
        "forbidden_actions",
        "kind",
        "lifecycle_stage",
        "model_floor",
        "output_schema",
        "policy_digest",
        "producer",
        "proposal_kind",
        "quality_gates",
        "reason_code",
        "repository_url",
        "repository_visibility",
        "required_capabilities",
        "review_kind",
        "risk_tier",
        "role",
        "schema_version",
        "scope",
        "stage_key",
        "status",
    }
)
_EXACT_STRUCTURAL_SUFFIXES = (
    "_digest",
    "_digests",
    "_glob",
    "_globs",
    "_id",
    "_ids",
    "_key",
    "_keys",
    "_kind",
    "_path",
    "_paths",
    "_ref",
    "_refs",
    "_role",
    "_sha",
    "_status",
    "_type",
    "_types",
    "_version",
)


def _truncate_preserving_coordinates(value: str, limit: int) -> str:
    """Keep a deterministic head and tail while respecting an exact limit."""

    if len(value) <= limit:
        return value
    if limit <= 0:
        return ""
    if limit <= len(_TRUNCATION_MARKER):
        return value[:limit]
    available = limit - len(_TRUNCATION_MARKER)
    head = (available * 3) // 4
    tail = available - head
    return value[:head] + _TRUNCATION_MARKER + (value[-tail:] if tail else "")


def _preserves_structural_strings(key: object) -> bool:
    normalized = str(key).strip().lower()
    return normalized in _EXACT_STRUCTURAL_KEYS or normalized.endswith(
        _EXACT_STRUCTURAL_SUFFIXES
    )


def _string_budget_profile(
    value: Any,
    *,
    preserve: bool = False,
) -> tuple[int, int]:
    """Return exact structural chars and narrative string count."""

    if isinstance(value, str):
        return (len(value), 0) if preserve else (0, 1)
    if isinstance(value, Mapping):
        exact_chars = 0
        narrative_strings = 0
        for key, item in value.items():
            child_exact, child_narrative = _string_budget_profile(
                item,
                preserve=preserve or _preserves_structural_strings(key),
            )
            exact_chars += child_exact
            narrative_strings += child_narrative
        return exact_chars, narrative_strings
    if isinstance(value, (list, tuple)):
        exact_chars = 0
        narrative_strings = 0
        for item in value:
            child_exact, child_narrative = _string_budget_profile(
                item,
                preserve=preserve,
            )
            exact_chars += child_exact
            narrative_strings += child_narrative
        return exact_chars, narrative_strings
    return 0, 0


def _bound_string_content(value: Any, max_chars: int) -> Any:
    """Cap narrative strings without corrupting controller-owned coordinates.

    Structural identifiers, digests, references, statuses, and path scopes are
    retained byte-for-byte and consume the budget first. If those coordinates
    alone exceed the requested budget, narrative text is emptied and the later
    compiled-prompt ceiling fails closed rather than sending malformed identity
    data to an agent.
    """

    if max_chars < 0:
        raise ValueError("max_chars must not be negative")
    exact_chars, remaining_strings = _string_budget_profile(value)
    remaining_chars = max(0, max_chars - exact_chars)

    def visit(item: Any, *, preserve: bool = False) -> Any:
        nonlocal remaining_chars, remaining_strings
        if isinstance(item, str):
            if preserve:
                return item
            limit = (
                remaining_chars // remaining_strings
                if remaining_strings > 0
                else 0
            )
            bounded = _truncate_preserving_coordinates(item, limit)
            remaining_chars -= len(bounded)
            remaining_strings -= 1
            return bounded
        if isinstance(item, Mapping):
            return {
                str(key): visit(
                    child,
                    preserve=preserve or _preserves_structural_strings(key),
                )
                for key, child in item.items()
            }
        if isinstance(item, (list, tuple)):
            return [visit(child, preserve=preserve) for child in item]
        return item

    return visit(value)


@dataclass(frozen=True)
class ContextPackResult:
    artifact: dict[str, Any]
    path: Path


class ContextBuilder:
    def __init__(self, config: FactoryConfig, repository_root: Path, artifacts: ArtifactStore | None = None) -> None:
        self.config = config
        self.repository_root = repository_root.resolve()
        self.artifacts = artifacts or ArtifactStore(config)

    def build(
        self,
        *,
        product_id: str,
        task_id: str,
        subject_sha: str,
        objective: str,
        acceptance: list[str],
        candidates: Iterable[tuple[str, str]],
        allowed_paths: list[str],
        forbidden_actions: list[str],
        output_schema: str,
        root_goal: str | None = None,
        root_task_id: str | None = None,
        plan_summary: dict[str, Any] | None = None,
        lineage: dict[str, Any] | None = None,
        open_failure: dict[str, Any] | None = None,
        capability_contract: dict[str, Any] | None = None,
        evidence: Iterable[dict[str, str]] = (),
        decisions: list[str] | None = None,
        max_files: int = 20,
        max_chars: int = 100_000,
        max_evidence_chars: int = 48_000,
        max_plan_summary_chars: int = 48_000,
        filename: str | None = None,
    ) -> ContextPackResult:
        if len(subject_sha) != 64 or any(char not in "0123456789abcdef" for char in subject_sha):
            raise ValueError("subject_sha must be a lowercase SHA-256 digest")
        if not objective.strip() or not acceptance:
            raise ValueError("objective and acceptance are required")
        if max_evidence_chars < 1 or max_plan_summary_chars < 1:
            raise ValueError("context string budgets must be positive")
        selected = select_files(
            self.repository_root,
            candidates,
            max_files=max_files,
            max_chars=max_chars,
        )
        selected_files: list[dict[str, Any]] = []
        redaction_count = 0
        for selected_file in selected:
            diagnostics = find_secret_candidate_diagnostics(selected_file.content)
            safe_content, common_redactions = redact_text(selected_file.content)
            safe_content, remaining_diagnostics = redact_secret_candidates(
                safe_content
            )
            redaction_count += sum(
                int(redaction["count"]) for redaction in common_redactions
            ) + len(remaining_diagnostics)
            selected_files.append(
                {
                    "path": selected_file.path,
                    "reason": selected_file.reason,
                    "digest": selected_file.digest,
                    "content": safe_content,
                    "truncated": selected_file.truncated,
                    "binary": selected_file.binary,
                    "redactions": diagnostics,
                }
            )
        prepared_evidence: list[dict[str, str]] = []
        for evidence_item in evidence:
            raw_summary = str(evidence_item.get("summary", ""))
            diagnostics = find_secret_candidate_diagnostics(raw_summary)
            summary, common_redactions = redact_text(raw_summary)
            summary, remaining_diagnostics = redact_secret_candidates(summary)
            redaction_count += sum(
                int(redaction["count"]) for redaction in common_redactions
            ) + len(remaining_diagnostics)
            if diagnostics:
                coordinates = ", ".join(
                    f"{diagnostic['detector']}@{diagnostic['location']}"
                    for diagnostic in diagnostics
                )
                summary += (
                    "\nSAFE_REDACTION_COORDINATES: "
                    f"{coordinates}. Secret values are not retained."
                )
            prepared_evidence.append(
                {
                    "type": str(evidence_item.get("type", "evidence")),
                    "summary": summary or "redacted evidence",
                    "artifact_ref": str(
                        evidence_item.get("artifact_ref", "unknown")
                    ),
                }
            )
        bounded_summaries = _bound_string_content(
            [item["summary"] for item in prepared_evidence],
            max_evidence_chars,
        )
        safe_evidence = [
            {**item, "summary": str(summary)}
            for item, summary in zip(
                prepared_evidence,
                bounded_summaries,
                strict=True,
            )
        ]
        artifact = {
            "schema_version": "2.0",
            "product_id": product_id,
            "task_id": task_id,
            "root_task_id": root_task_id or task_id,
            "subject_sha": subject_sha,
            "root_goal": root_goal or objective,
            "objective": objective,
            "acceptance": acceptance,
            "plan_summary": _bound_string_content(
                plan_summary or {},
                max_plan_summary_chars,
            ),
            "lineage": lineage
            or {
                "root_task_id": root_task_id or task_id,
                "parent_task_id": None,
                "source_task_id": task_id,
                "plan_id": "legacy",
                "plan_node_id": task_id,
                "task_revision": 1,
            },
            "open_failure": open_failure,
            "capability_contract": capability_contract
            or {"profile": "legacy", "required": [], "missing": []},
            "constraints": {
                "allowed_paths": allowed_paths,
                "forbidden_actions": sorted(set(forbidden_actions)),
            },
            "file_excerpts": selected_files,
            "evidence": safe_evidence,
            "decisions": decisions or [],
            "output_schema": output_schema,
            "redaction_count": redaction_count,
        }
        path = self.artifacts.write(
            "context-pack-v2.schema.json",
            artifact,
            filename=filename or f"context-{task_id}.json",
        )
        return ContextPackResult(artifact, path)
