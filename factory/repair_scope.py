"""Safe structural repository coordinates for autonomous scope repair."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
from typing import Any

_REPOSITORY_PATH = re.compile(
    r"(?<![A-Za-z0-9_.@+/-])"
    r"([A-Za-z0-9_.@+-]+(?:/[A-Za-z0-9_.@+-]+)+)"
    r"(?![A-Za-z0-9_.@+/-])"
)
_ROOT_PATH_NAMES = {
    "Dockerfile",
    "LICENSE",
    "Makefile",
    "README",
    "SECURITY",
}
_MAX_REQUIRED_PATHS = 20


def _safe_exact_repository_path(value: object) -> str | None:
    candidate = str(value).strip()
    if not candidate or len(candidate) > 512 or "\\" in candidate or candidate.startswith("/"):
        return None
    path = PurePosixPath(candidate)
    if path.is_absolute() or any(part in {"", ".", ".."} or len(part) > 128 for part in path.parts):
        return None
    name = path.name
    if "/" not in candidate or ("." not in name and name not in _ROOT_PATH_NAMES):
        return None
    return candidate


def repository_path_candidates(text: object) -> tuple[str, ...]:
    """Extract bounded relative file paths without retaining surrounding prose."""

    candidates: list[str] = []
    for match in _REPOSITORY_PATH.finditer(str(text or "")[:12_000]):
        candidate = _safe_exact_repository_path(match.group(1))
        if candidate and candidate not in candidates:
            candidates.append(candidate)
        if len(candidates) >= _MAX_REQUIRED_PATHS:
            break
    return tuple(candidates)


def path_is_covered(path: str, scopes: Sequence[str]) -> bool:
    """Return whether one bounded task scope can edit an exact repository path."""

    for raw_scope in scopes:
        scope = str(raw_scope)
        if not scope:
            continue
        if path == scope or fnmatchcase(path, scope):
            return True
        if scope.endswith("/**"):
            prefix = scope[:-3].rstrip("/")
            if path == prefix or path.startswith(prefix + "/"):
                return True
    return False


def derive_scope_required_paths(actual: Mapping[str, Any]) -> tuple[str, ...]:
    """Recover exact out-of-scope files from current and legacy safe evidence."""

    raw_blocked = actual.get("blocked_allowed_paths")
    blocked = (
        tuple(str(value) for value in raw_blocked if isinstance(value, str))
        if isinstance(raw_blocked, list)
        else ()
    )
    candidates: list[str] = []

    def include(value: object) -> None:
        candidate = _safe_exact_repository_path(value)
        if candidate and not path_is_covered(candidate, blocked) and candidate not in candidates:
            candidates.append(candidate)

    raw_required = actual.get("scope_required_paths")
    if isinstance(raw_required, list):
        for value in raw_required[:_MAX_REQUIRED_PATHS]:
            include(value)

    raw_outside = actual.get("outside_scope_coordinates")
    if isinstance(raw_outside, list):
        for value in raw_outside[:_MAX_REQUIRED_PATHS]:
            include(value)

    raw_findings = actual.get("provider_scope_findings")
    if isinstance(raw_findings, list):
        for finding in raw_findings[:_MAX_REQUIRED_PATHS]:
            if not isinstance(finding, Mapping):
                continue
            for candidate in repository_path_candidates(finding.get("text")):
                include(candidate)
                if len(candidates) >= _MAX_REQUIRED_PATHS:
                    break
            if len(candidates) >= _MAX_REQUIRED_PATHS:
                break
    return tuple(candidates[:_MAX_REQUIRED_PATHS])
