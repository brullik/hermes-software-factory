#!/usr/bin/env python3
"""Verify that SHA256SUMS exactly covers the source package."""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "SHA256SUMS"
IGNORED_DIRS = {".git", ".deployment", ".mypy_cache", ".pytest_cache", ".ruff_cache", "build", "dist", ".venv", "state", "__pycache__"}
IGNORED_RELATIVE_PREFIXES = {("evidence", "archive")}
IGNORED_RELATIVE_FILES = {"evidence/final-acceptance.json"}


def project_files() -> set[str]:
    files: set[str] = set()
    for path in ROOT.rglob("*"):
        if not path.is_file() or path == MANIFEST:
            continue
        relative = path.relative_to(ROOT)
        if relative.parts[:2] in IGNORED_RELATIVE_PREFIXES or relative.as_posix() in IGNORED_RELATIVE_FILES or any(
            part in IGNORED_DIRS or part.endswith(".egg-info") for part in relative.parts
        ):
            continue
        files.add(relative.as_posix())
    return files


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main() -> int:
    if not MANIFEST.is_file():
        print("MANIFEST VERIFY FAILED: SHA256SUMS is missing")
        return 1
    expected: dict[str, str] = {}
    for line_number, line in enumerate(MANIFEST.read_text(encoding="utf-8").splitlines(), 1):
        parts = line.split("  ", 1)
        if len(parts) != 2 or len(parts[0]) != 64:
            print(f"MANIFEST VERIFY FAILED: malformed line {line_number}")
            return 1
        expected[parts[1]] = parts[0]
    actual = project_files()
    listed = set(expected)
    if actual != listed:
        print(f"MANIFEST VERIFY FAILED: missing={sorted(actual - listed)} extra={sorted(listed - actual)}")
        return 1
    for relative, expected_digest in sorted(expected.items()):
        actual_digest = digest(ROOT / relative)
        if actual_digest != expected_digest:
            print(f"MANIFEST VERIFY FAILED: digest mismatch {relative}")
            return 1
    print(f"MANIFEST VERIFY PASSED: {len(expected)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
