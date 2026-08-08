#!/usr/bin/env python3
"""Validate a repository registry or emit a non-destructive cleanup plan."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from factory.repository_registry import (
    RegistryViolation,
    cleanup_plan,
    load_json,
    validate_registry,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", type=Path, required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("registry", type=Path)
    cleanup = subparsers.add_parser("cleanup-plan")
    cleanup.add_argument("registry", type=Path)
    cleanup.add_argument("--repository-state", type=Path, required=True)
    cleanup.add_argument("--now")
    args = parser.parse_args()
    try:
        registry = load_json(args.registry)
        schema = load_json(args.schema)
        result = validate_registry(registry, schema)
        if args.command == "cleanup-plan":
            state = load_json(args.repository_state)
            now = datetime.fromisoformat(args.now) if args.now else None
            result = cleanup_plan(registry, repository_state=state, now=now)
    except (OSError, ValueError, json.JSONDecodeError, RegistryViolation) as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
