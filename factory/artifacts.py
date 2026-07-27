"""Immutable, schema-validated artifact storage."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .common import sha256_text, stable_json, utc_now
from .config import FactoryConfig
from .policy import policy_digest


class ArtifactConflictError(RuntimeError):
    """Raised when an artifact id is reused with different content."""


class ArtifactStore:
    def __init__(self, config: FactoryConfig) -> None:
        self.config = config
        self.root = config.evidence_dir
        self.root.mkdir(parents=True, exist_ok=True)

    def validate(self, schema_name: str, artifact: dict[str, Any]) -> list[str]:
        schema_path = self.config.schema_root() / schema_name
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        return [error.message for error in validator.iter_errors(artifact)]

    def write(self, schema_name: str, artifact: dict[str, Any], *, filename: str | None = None) -> Path:
        errors = self.validate(schema_name, artifact)
        if errors:
            raise ValueError(f"Artifact does not match {schema_name}: {'; '.join(errors)}")
        name = filename or f"{artifact['artifact_id']}.json"
        candidate = Path(name)
        if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
            raise ValueError("artifact filename must be a simple relative filename")
        target = (self.root / candidate).resolve()
        if target.parent != self.root.resolve():
            raise ValueError("artifact filename escapes evidence directory")
        payload = json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        try:
            with target.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            return target
        except FileExistsError:
            existing = target.read_text(encoding="utf-8")
            if existing != payload:
                raise ArtifactConflictError(f"Immutable artifact conflict: {target}")
            return target

    def digest(self, artifact: dict[str, Any]) -> str:
        return sha256_text(stable_json(artifact))


def artifact_metadata(config: FactoryConfig, producer: str, artifact_id: str, product_id: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "artifact_id": artifact_id,
        "product_id": product_id,
        "created_at": utc_now(),
        "producer": {"role": producer, "tier": "deterministic", "provider": None, "model": None},
        "policy_digest": policy_digest(config),
    }
