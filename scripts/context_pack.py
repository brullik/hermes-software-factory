#!/usr/bin/env python3
"""Small helpers for deterministic Context Pack construction."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SelectedFile:
    path: str
    reason: str
    digest: str
    chars: int


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def select_files(
    repository_root: Path,
    candidates: Iterable[tuple[str, str]],
    *,
    max_files: int,
    max_chars: int,
) -> list[SelectedFile]:
    selected: list[SelectedFile] = []
    total = 0
    root = repository_root.resolve()
    for relative, reason in candidates:
        path = (root / relative).resolve()
        if path != root and root not in path.parents:
            continue
        if not path.is_file():
            continue
        size = len(path.read_text(encoding="utf-8", errors="replace"))
        if len(selected) >= max_files or total + size > max_chars:
            continue
        selected.append(SelectedFile(relative, reason, sha256_file(path), size))
        total += size
    return selected


def compact_log(text: str, *, max_lines: int = 200) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    head = max_lines // 2
    tail = max_lines - head
    omitted = len(lines) - max_lines
    return "\n".join(lines[:head] + [f"... {omitted} lines omitted ..."] + lines[-tail:])
