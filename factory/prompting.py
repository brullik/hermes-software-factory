"""Deterministic role prompt compilation with policy and secret boundaries."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts.prompt_compiler import compile_prompt, find_secret_candidates

from .config import FactoryConfig
from .policy import load_policies


@dataclass(frozen=True)
class PromptBundle:
    role: str
    output_schema: str
    prompt: str
    digest: str
    size_chars: int
    redaction_count: int


class PromptCompiler:
    def __init__(self, config: FactoryConfig) -> None:
        self.config = config
        configured = config.raw.get("paths", {}).get("prompts")
        candidates = [Path(str(configured))] if configured else []
        candidates.extend((config.source.parent / "prompts", config.source.parent.parent / "prompts"))
        self.root = next((root for root in candidates if root.is_dir()), config.source.parent / "prompts")

    def compile(
        self,
        *,
        role: str,
        context_pack: dict[str, Any],
        output_schema: str,
        policy_summary: dict[str, Any] | None = None,
    ) -> PromptBundle:
        system = self.root / "fragments" / "00-common-system.md"
        common_output = self.root / "fragments" / "01-common-output.md"
        role_path = self.root / "roles" / f"{role}.md"
        schema_path = self.config.schema_root() / output_schema
        paths = (system, common_output, role_path)
        if any(not path.is_file() for path in paths) or not schema_path.is_file():
            missing = [str(path) for path in (*paths, schema_path) if not path.is_file()]
            raise FileNotFoundError(", ".join(missing))
        policy = policy_summary if policy_summary is not None else load_policies(self.config)
        context = json.dumps(context_pack, ensure_ascii=False, sort_keys=True)
        parts = [
            system.read_text(encoding="utf-8"),
            role_path.read_text(encoding="utf-8"),
            common_output.read_text(encoding="utf-8"),
            "POLICY_SUMMARY\n" + json.dumps(policy, ensure_ascii=False, sort_keys=True),
            "CONTEXT_PACK\n" + context,
            "OUTPUT_SCHEMA\n" + schema_path.read_text(encoding="utf-8"),
        ]
        prompt, digest = compile_prompt(parts)
        secret_candidates = find_secret_candidates(prompt)
        if secret_candidates:
            raise ValueError("Prompt compilation rejected secret-like content")
        return PromptBundle(role, output_schema, prompt, digest, len(prompt), 0)
