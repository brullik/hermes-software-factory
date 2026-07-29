"""Minimal Context Pack builder with file scope and provenance enforcement."""

from __future__ import annotations

from collections.abc import Iterable
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
        filename: str | None = None,
    ) -> ContextPackResult:
        if len(subject_sha) != 64 or any(char not in "0123456789abcdef" for char in subject_sha):
            raise ValueError("subject_sha must be a lowercase SHA-256 digest")
        if not objective.strip() or not acceptance:
            raise ValueError("objective and acceptance are required")
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
        safe_evidence: list[dict[str, str]] = []
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
            safe_evidence.append(
                {
                    "type": str(evidence_item.get("type", "evidence")),
                    "summary": summary or "redacted evidence",
                    "artifact_ref": str(
                        evidence_item.get("artifact_ref", "unknown")
                    ),
                }
            )
        artifact = {
            "schema_version": "2.0",
            "product_id": product_id,
            "task_id": task_id,
            "root_task_id": root_task_id or task_id,
            "subject_sha": subject_sha,
            "root_goal": root_goal or objective,
            "objective": objective,
            "acceptance": acceptance,
            "plan_summary": plan_summary or {},
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
