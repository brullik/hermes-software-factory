#!/usr/bin/env python3
"""Fail closed when source files contain known credential material."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from factory.common import SECRET_PATTERNS

IGNORED_DIRS = {
    ".deployment",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "audit_output",
    "audit_tools",
    "build",
    "dist",
    "state",
    "__pycache__",
}
SUFFIXES = {".json", ".md", ".py", ".sh", ".toml", ".yaml", ".yml", ".txt"}
EXTRA_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:AWS_SECRET_ACCESS_KEY|TELEGRAM_BOT_TOKEN|GH_TOKEN)\s*=\s*[^$\s][^\s]*"),
)


def main() -> int:
    findings: list[str] = []
    patterns = tuple(pattern for _, pattern in SECRET_PATTERNS) + EXTRA_PATTERNS
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path.suffix not in SUFFIXES:
            continue
        relative = path.relative_to(ROOT)
        if any(part in IGNORED_DIRS or part.endswith(".egg-info") for part in relative.parts):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if any(pattern.search(text) for pattern in patterns):
            findings.append(relative.as_posix())
    if findings:
        print("SECRET SCAN FAILED")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print("SECRET SCAN PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
