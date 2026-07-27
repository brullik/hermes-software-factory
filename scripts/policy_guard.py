#!/usr/bin/env python3
"""Reference policy enforcement helpers."""

from __future__ import annotations

import fnmatch
import os
import shlex
from collections.abc import Iterable
from pathlib import Path

FORCE_PRIVATE_MARKERS = {
    "personal_data",
    "confidential_data",
    "real_money",
    "payment",
    "medical",
    "legal",
    "privileged_infrastructure",
    "proprietary_customer_integration",
    "security_sensitive_material",
    "restrictive_license",
}

FORBIDDEN_COMMAND_TOKENS = {
    "printenv",
    "env",
    "set",
    "sudo",
    "su",
    "passwd",
    "iptables",
    "nft",
    "mkfs",
    "fdisk",
    "shutdown",
    "reboot",
}

FORBIDDEN_COMMAND_PATTERNS = (
    "rm -rf /",
    "git push --force",
    "git push -f",
    "git reset --hard origin/main",
    "docker system prune -a",
)


def repository_visibility(default: str, markers: Iterable[str]) -> str:
    marker_set = set(markers)
    if marker_set & FORCE_PRIVATE_MARKERS:
        return "private"
    if default not in {"public", "private"}:
        raise ValueError("Unsupported visibility")
    return default


def _normalize_relative(path: str) -> str:
    normalized = os.path.normpath(path).replace("\\", "/")
    if normalized == ".." or normalized.startswith(("../", "/")):
        raise ValueError(f"Path escapes workspace: {path}")
    return normalized.removeprefix("./")


def path_allowed(path: str, allowed_patterns: Iterable[str], forbidden_patterns: Iterable[str]) -> bool:
    try:
        normalized = _normalize_relative(path)
    except ValueError:
        return False
    if any(fnmatch.fnmatch(normalized, pattern) for pattern in forbidden_patterns):
        return False
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in allowed_patterns)


def enforce_changed_paths(
    changed_paths: Iterable[str],
    allowed_patterns: Iterable[str],
    forbidden_patterns: Iterable[str],
) -> list[str]:
    violations: list[str] = []
    for path in changed_paths:
        try:
            allowed = path_allowed(path, allowed_patterns, forbidden_patterns)
        except ValueError:
            allowed = False
        if not allowed:
            violations.append(path)
    return violations


def command_allowed(command: str, allowlist_prefixes: Iterable[str]) -> tuple[bool, str]:
    lowered = " ".join(command.strip().lower().split())
    if any(pattern in lowered for pattern in FORBIDDEN_COMMAND_PATTERNS):
        return False, "forbidden_pattern"
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False, "invalid_shell_syntax"
    if not tokens:
        return False, "empty_command"
    if tokens[0].lower() in FORBIDDEN_COMMAND_TOKENS:
        return False, "forbidden_executable"
    if any(token in {"|", "||", "&&", ";", ">", ">>", "<"} for token in tokens):
        return False, "shell_operator_forbidden"
    prefixes = tuple(prefix.strip() for prefix in allowlist_prefixes)
    if not any(lowered == prefix or lowered.startswith(prefix + " ") for prefix in prefixes):
        return False, "not_allowlisted"
    return True, "allowed"


def assert_under_root(root: Path, candidate: Path) -> Path:
    root_resolved = root.resolve()
    candidate_resolved = candidate.resolve()
    if candidate_resolved != root_resolved and root_resolved not in candidate_resolved.parents:
        raise ValueError(f"Candidate path is outside root: {candidate}")
    return candidate_resolved
