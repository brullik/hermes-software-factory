#!/usr/bin/env python3
"""Build deterministic SHA-256 package manifest."""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "SHA256SUMS"
IGNORED_DIRS = {
    ".git",
    ".deployment",
    "build",
    "dist",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "state",
    "__pycache__",
}
IGNORED_RELATIVE_PREFIXES = {("evidence", "archive")}
IGNORED_RELATIVE_FILES = {"evidence/final-acceptance.json"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_manifest_file(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    return (
        relative.parts[:2] not in IGNORED_RELATIVE_PREFIXES
        and relative.as_posix() not in IGNORED_RELATIVE_FILES
        and not any(part in IGNORED_DIRS or part.endswith(".egg-info") for part in relative.parts)
    )


def main() -> int:
    files = sorted(
        path for path in ROOT.rglob("*")
        if path.is_file()
        and path != OUTPUT
        and is_manifest_file(path)
    )
    lines = [f"{sha256(path)}  {path.relative_to(ROOT).as_posix()}" for path in files]
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"Wrote {len(lines)} entries to {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
