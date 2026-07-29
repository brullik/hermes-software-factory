#!/usr/bin/env python3
"""Compile minimal, deterministic role prompts and reject likely secrets."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github_classic_token", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    ("github_fine_grained_token", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    (
        "openai_style_key",
        re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}"),
    ),
    (
        "private_key_header",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "named_credential",
        re.compile(
            r"(?i)(?:password|token|secret|api[_-]?key)\s*[:=]\s*"
            r"[\"']?[A-Za-z0-9_./+=-]{12,}"
        ),
    ),
)
SECRET_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    pattern for _, pattern in SECRET_RULES
)
_SAFE_JSON_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")


def find_secret_candidates(text: str) -> list[str]:
    findings: list[str] = []
    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(match.group(0)[:80])
    return findings


def _json_child_path(parent: str, key: str, index: int) -> str:
    if _SAFE_JSON_KEY.fullmatch(key):
        return f"{parent}.{key}"
    return f"{parent}.<key#{index}>"


def find_secret_candidate_diagnostics(
    text: str,
    *,
    max_findings: int = 12,
) -> list[dict[str, str]]:
    """Return detector IDs and coordinates, never the matched values."""

    if max_findings < 1:
        raise ValueError("max_findings must be positive")
    diagnostics: list[dict[str, str]] = []

    def inspect_string(value: str, location: str) -> None:
        for rule_id, pattern in SECRET_RULES:
            for _ in pattern.finditer(value):
                diagnostics.append(
                    {"detector": rule_id, "location": location}
                )
                if len(diagnostics) >= max_findings:
                    return

    def inspect_json(value: Any, path: str) -> None:
        if len(diagnostics) >= max_findings:
            return
        if isinstance(value, dict):
            for index, (key, child) in enumerate(value.items()):
                key_text = str(key)
                inspect_string(key_text, f"{path}.<key#{index}>")
                inspect_json(child, _json_child_path(path, key_text, index))
                if len(diagnostics) >= max_findings:
                    return
        elif isinstance(value, list):
            for index, child in enumerate(value):
                inspect_json(child, f"{path}[{index}]")
                if len(diagnostics) >= max_findings:
                    return
        elif isinstance(value, str):
            inspect_string(value, path)

    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        payload = None
    if payload is not None:
        inspect_json(payload, "$")
        if diagnostics:
            return diagnostics

    for rule_id, pattern in SECRET_RULES:
        for match in pattern.finditer(text):
            prefix = text[: match.start()]
            line = prefix.count("\n") + 1
            last_newline = prefix.rfind("\n")
            column = (
                match.start() + 1
                if last_newline < 0
                else match.start() - last_newline
            )
            diagnostics.append(
                {
                    "detector": rule_id,
                    "location": f"line {line}, column {column}",
                }
            )
            if len(diagnostics) >= max_findings:
                return diagnostics
    return diagnostics


def redact_secret_candidates(text: str) -> tuple[str, list[dict[str, str]]]:
    """Redact candidates in-place while retaining only safe audit coordinates."""

    diagnostics = find_secret_candidate_diagnostics(text)
    redacted = text
    for _, pattern in SECRET_RULES:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted, diagnostics


def compile_prompt(parts: Iterable[str]) -> tuple[str, str]:
    normalized = "\n\n".join(part.strip() for part in parts if part.strip()) + "\n"
    findings = find_secret_candidates(normalized)
    if findings:
        diagnostics = find_secret_candidate_diagnostics(normalized)
        coordinates = ", ".join(
            f"{item['detector']}@{item['location']}"
            for item in diagnostics
        )
        raise ValueError(
            "Secret-like content detected "
            f"({len(findings)} finding(s)); safe coordinates: {coordinates}"
        )
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
