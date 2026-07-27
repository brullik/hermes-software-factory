"""Minimal Context Pack builder with file scope and provenance enforcement."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts.context_pack import select_files

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
        evidence: Iterable[dict[str, str]] = (),
        decisions: list[str] | None = None,
        max_files: int = 20,
        max_chars: int = 100_000,
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
        selected_files = [
            {"path": item.path, "reason": item.reason, "digest": item.digest}
            for item in selected
        ]
        safe_evidence: list[dict[str, str]] = []
        redaction_count = 0
        for item in evidence:
            summary, redactions = redact_text(str(item.get("summary", "")))
            redaction_count += sum(int(redaction["count"]) for redaction in redactions)
            safe_evidence.append(
                {
                    "type": str(item.get("type", "evidence")),
                    "summary": summary or "redacted evidence",
                    "artifact_ref": str(item.get("artifact_ref", "unknown")),
                }
            )
        artifact = {
            "schema_version": "1.0",
            "product_id": product_id,
            "task_id": task_id,
            "subject_sha": subject_sha,
            "objective": objective,
            "acceptance": acceptance,
            "constraints": {
                "allowed_paths": allowed_paths,
                "forbidden_actions": sorted(set(forbidden_actions)),
            },
            "selected_files": selected_files,
            "evidence": safe_evidence,
            "decisions": decisions or [],
            "output_schema": output_schema,
            "redaction_count": redaction_count,
        }
        path = self.artifacts.write("context-pack.schema.json", artifact, filename=f"context-{task_id}.json")
        return ContextPackResult(artifact, path)
