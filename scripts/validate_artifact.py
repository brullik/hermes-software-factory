#!/usr/bin/env python3
"""Validate a JSON artifact against a package JSON Schema."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


def validate(schema_path: Path, artifact_path: Path) -> list[str]:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(artifact), key=lambda error: list(error.absolute_path))
    formatted: list[str] = []
    for error in errors:
        location = "/".join(str(part) for part in error.absolute_path) or "$"
        formatted.append(f"{location}: {error.message}")
    return formatted


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    args = parser.parse_args()
    errors = validate(args.schema, args.artifact)
    if errors:
        print("\n".join(errors))
        return 1
    print("VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
