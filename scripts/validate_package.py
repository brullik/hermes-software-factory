#!/usr/bin/env python3
"""Static validation gate for this specification package."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

ROOT = Path(__file__).resolve().parents[1]
IGNORED_DIRS = {
    ".git",
    ".deployment",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "build",
    "dist",
    ".venv",
    "state",
    "__pycache__",
}

REQUIRED = [
    "README.md",
    "USER-DECISIONS.md",
    "HANDOFF-PROMPT.md",
    "IMPLEMENTATION-SPEC.md",
    "ACCEPTANCE-PLAN.md",
    "OWNER-GUIDE.md",
    ".gitignore",
    ".editorconfig",
    "SECURITY.md",
    "LICENSE-DECISION.md",
    "requirements.lock",
    "evidence/compatibility-report.json",
    "evidence/sbom.spdx.json",
    ".github/pull_request_template.md",
    ".github/workflows/ci.yml",
    "config/caddy/Caddyfile",
    "config/caddy/README.md",
    "config/monitoring/README.md",
    "config/quality-gates.yaml",
    "factory/pipeline.py",
    "factory/quality.py",
    "factory/telegram.py",
    "scripts/bootstrap/install-telegram-credential.sh",
    "scripts/bootstrap/configure-telegram-owner.sh",
    "scripts/deploy/factory-rollback.sh",
    "scripts/deploy/health-and-rollback.sh",
    "policies/autonomy-policy.yaml",
    "policies/model-routing-policy.yaml",
    "policies/security-policy.yaml",
    "schemas/product-contract.schema.json",
    "schemas/task-contract.schema.json",
    "schemas/gate-evidence.schema.json",
    "schemas/attempt-result.schema.json",
    "schemas/owner-action.schema.json",
    "prompts/fragments/00-common-system.md",
    "prompts/roles/builder.md",
    "prompts/roles/independent-reviewer.md",
]

PROMPT_SECTIONS = ["## Назначение", "## Вход", "## Алгоритм", "## Tier behavior", "## Запрещено", "## Выход"]
MARKER_PATTERN = re.compile(r"\b(?:TODO|TBD|FIXME)\s*:", re.IGNORECASE)
SECRET_PATTERNS = [
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def is_project_file(path: Path) -> bool:
    """Return whether a path belongs to the source package, not generated tooling state."""
    relative = path.relative_to(ROOT)
    return not any(part in IGNORED_DIRS or part.endswith(".egg-info") for part in relative.parts)


def validate() -> list[str]:
    errors: list[str] = []

    for rel in REQUIRED:
        if not (ROOT / rel).is_file():
            errors.append(f"missing required file: {rel}")

    for path in sorted(path for path in ROOT.rglob("*.json") if is_project_file(path)):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"invalid JSON {path.relative_to(ROOT)}: {exc}")
            continue
        if path.parent.name == "schemas":
            try:
                Draft202012Validator.check_schema(data)
            except SchemaError as exc:
                errors.append(f"invalid schema {path.name}: {exc}")

    yaml_paths = [path for path in ROOT.rglob("*.yaml") if is_project_file(path)]
    yaml_paths.extend(path for path in ROOT.rglob("*.yml") if is_project_file(path))
    for path in sorted(yaml_paths):
        try:
            data = load_yaml(path)
            if data is None:
                errors.append(f"empty YAML: {path.relative_to(ROOT)}")
        except (OSError, yaml.YAMLError) as exc:
            errors.append(f"invalid YAML {path.relative_to(ROOT)}: {exc}")

    for path in sorted((ROOT / "prompts" / "roles").glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for section in PROMPT_SECTIONS:
            if section not in text:
                errors.append(f"role prompt {path.name} lacks section {section}")

    scan_suffixes = {".md", ".yaml", ".yml", ".json", ".py", ".sh", ".toml"}
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path.suffix not in scan_suffixes or not is_project_file(path):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if MARKER_PATTERN.search(text):
            errors.append(f"unresolved marker in {path.relative_to(ROOT)}")
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f"secret-like value in {path.relative_to(ROOT)}")

    routing = load_yaml(ROOT / "policies/model-routing-policy.yaml")
    if routing["global"]["semantic_attempts_per_tier"] != {"luna": 2, "terra": 2, "sol": 1}:
        errors.append("model escalation attempt limits changed")
    if routing["global"]["max_spawn_depth"] != 1:
        errors.append("max_spawn_depth must be 1")
    if routing["global"]["max_concurrent_children"] > 2:
        errors.append("max_concurrent_children must not exceed 2")
    if routing["global"]["paid_api_fallback"] != "forbidden":
        errors.append("paid API fallback must be forbidden")

    if len(list((ROOT / "policies").glob("*.yaml"))) != 12:
        errors.append("policy bundle must contain all 12 versioned policies")

    repository = load_yaml(ROOT / "policies/repository-policy.yaml")
    if repository["factory_repository"]["name"] != "hermes-software-factory":
        errors.append("factory repository name mismatch")
    if repository["product_repository"]["default_visibility"] != "public":
        errors.append("owner public-default decision mismatch")

    compatibility_path = ROOT / "evidence" / "compatibility-report.json"
    compatibility = json.loads(compatibility_path.read_text(encoding="utf-8"))
    hermes = next(
        (item for item in compatibility.get("components", []) if item.get("name") == "Hermes Agent"),
        None,
    )
    required_hermes = {
        "version": "0.19.0",
        "tag": "v2026.7.20",
        "source_commit": "3ef6bbd201263d354fd83ec55b3c306ded2eb72a",
        "artifact_sha256": "bd0bac012aee38a60894781f4597dc29ee7bedb3448540249921f10d3bef327f",
    }
    if not isinstance(hermes, dict) or any(hermes.get(key) != value for key, value in required_hermes.items()):
        errors.append("Hermes compatibility pin is incomplete or changed")

    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("PACKAGE VALIDATION FAILED")
        for error in errors:
            print(f"- {error}")
        return 1
    print("PACKAGE VALIDATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
