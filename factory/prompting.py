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

    @staticmethod
    def _schema_references(value: Any) -> set[str]:
        references: set[str] = set()
        pending = [value]
        while pending:
            current = pending.pop()
            if isinstance(current, dict):
                reference = current.get("$ref")
                if isinstance(reference, str):
                    references.add(reference)
                pending.extend(current.values())
            elif isinstance(current, list):
                pending.extend(current)
        return references

    def _schema_dependencies(self, schema_path: Path) -> list[tuple[str, str]]:
        """Load safe local JSON Schema references into the provider contract."""

        schema_root = self.config.schema_root().resolve()
        pending = [schema_path.resolve()]
        visited = {pending[0]}
        dependencies: list[tuple[str, str]] = []
        while pending:
            current = pending.pop(0)
            payload = json.loads(current.read_text(encoding="utf-8"))
            for reference in sorted(self._schema_references(payload)):
                local_name = reference.split("#", 1)[0]
                if not local_name:
                    continue
                if (
                    Path(local_name).name != local_name
                    or not local_name.endswith(".schema.json")
                ):
                    raise ValueError(f"output schema contains an unsafe reference: {reference}")
                dependency = (schema_root / local_name).resolve()
                if (
                    dependency.parent != schema_root
                    or dependency.is_symlink()
                    or not dependency.is_file()
                ):
                    raise FileNotFoundError(local_name)
                if dependency in visited:
                    continue
                visited.add(dependency)
                raw = dependency.read_text(encoding="utf-8")
                dependencies.append((local_name, raw))
                pending.append(dependency)
        return dependencies

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
        schema_dependencies = self._schema_dependencies(schema_path)
        parts = [
            system.read_text(encoding="utf-8"),
            role_path.read_text(encoding="utf-8"),
            common_output.read_text(encoding="utf-8"),
            "POLICY_SUMMARY\n" + json.dumps(policy, ensure_ascii=False, sort_keys=True),
            "CONTEXT_PACK\n" + context,
            "OUTPUT_SCHEMA\n" + schema_path.read_text(encoding="utf-8"),
            *[
                f"OUTPUT_SCHEMA_DEPENDENCY {name}\n{raw}"
                for name, raw in schema_dependencies
            ],
        ]
        prompt, digest = compile_prompt(parts)
        secret_candidates = find_secret_candidates(prompt)
        if secret_candidates:
            raise ValueError("Prompt compilation rejected secret-like content")
        return PromptBundle(role, output_schema, prompt, digest, len(prompt), 0)
