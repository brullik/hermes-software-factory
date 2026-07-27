#!/usr/bin/env python3
"""Compile minimal, deterministic role prompts and reject likely secrets."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path

SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)(?:password|token|secret|api[_-]?key)\s*[:=]\s*[\"']?[A-Za-z0-9_./+=-]{12,}"),
)


def find_secret_candidates(text: str) -> list[str]:
    findings: list[str] = []
    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(match.group(0)[:80])
    return findings


def compile_prompt(parts: Iterable[str]) -> tuple[str, str]:
    normalized = "\n\n".join(part.strip() for part in parts if part.strip()) + "\n"
    findings = find_secret_candidates(normalized)
    if findings:
        raise ValueError(f"Secret-like content detected ({len(findings)} finding(s))")
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return normalized, digest


def compile_from_files(paths: list[Path]) -> tuple[str, str]:
    return compile_prompt(path.read_text(encoding="utf-8") for path in paths)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    prompt, digest = compile_from_files(args.files)
    if args.out:
        args.out.write_text(prompt, encoding="utf-8")
    print(json.dumps({"sha256": digest, "bytes": len(prompt.encode("utf-8"))}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
