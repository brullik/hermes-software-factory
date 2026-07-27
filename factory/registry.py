"""Schema registry facade with explicit version and immutable artifact rules."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator

from .artifacts import ArtifactStore
from .common import sha256_text, stable_json
from .config import FactoryConfig


class UnknownSchemaVersion(ValueError):
    """Raised when an artifact requests a schema version not installed locally."""


@dataclass(frozen=True)
class RegisteredArtifact:
    schema_name: str
    artifact_id: str
    digest: str
    path: Path


class SchemaRegistry:
    def __init__(self, config: FactoryConfig, store: ArtifactStore | None = None) -> None:
        self.config = config
        self.store = store or ArtifactStore(config)

    def load_schema(self, schema_name: str) -> dict[str, Any]:
        path = self.config.schema_root() / schema_name
        if not path.is_file():
            raise FileNotFoundError(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(data)
        return cast(dict[str, Any], data)

    def validate(self, schema_name: str, artifact: dict[str, Any]) -> None:
        schema = self.load_schema(schema_name)
        version = artifact.get("schema_version")
        allowed = schema.get("properties", {}).get("schema_version", {}).get("const", "1.0")
        if version != allowed:
            raise UnknownSchemaVersion(f"{schema_name} accepts schema_version={allowed!r}, got {version!r}")
        errors = self.store.validate(schema_name, artifact)
        if errors:
            raise ValueError(f"Invalid {schema_name}: {'; '.join(errors)}")

    def register(self, schema_name: str, artifact: dict[str, Any], *, filename: str | None = None) -> RegisteredArtifact:
        self.validate(schema_name, artifact)
        path = self.store.write(schema_name, artifact, filename=filename)
        digest = sha256_text(stable_json(artifact))
        return RegisteredArtifact(schema_name, str(artifact["artifact_id"]), digest, path)
