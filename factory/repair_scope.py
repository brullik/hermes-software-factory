"""Safe structural repository coordinates for autonomous scope repair."""

from __future__ import annotations

import ast
import os
import re
from collections.abc import Mapping, Sequence
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
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
_MAX_SOURCE_SEARCH_FILES = 20_000
_SOURCE_SEARCH_EXCLUDED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}


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


def infer_unique_test_source_paths(
    repository_root: Path,
    diagnostic_coordinates: Sequence[str],
    blocked_paths: Sequence[str],
) -> tuple[str, ...]:
    """Map a failing ``test_<module>.py`` to one uniquely imported local module.

    The inference is intentionally fail-closed: it accepts only exact safe test
    paths, requires an AST import matching the test basename, ignores generated
    and dependency trees, and emits a production coordinate only when exactly
    one repository file matches.
    """

    try:
        root = repository_root.resolve(strict=True)
    except OSError:
        return ()
    inferred: list[str] = []
    for raw_coordinate in diagnostic_coordinates[:_MAX_REQUIRED_PATHS]:
        coordinate = _safe_exact_repository_path(raw_coordinate)
        if not coordinate:
            continue
        test_path = PurePosixPath(coordinate)
        if (
            "tests" not in test_path.parts
            or test_path.suffix != ".py"
            or not test_path.stem.startswith("test_")
        ):
            continue
        module_name = test_path.stem.removeprefix("test_")
        if not module_name:
            continue
        candidate_test = root.joinpath(*test_path.parts)
        try:
            resolved_test = candidate_test.resolve(strict=True)
            resolved_test.relative_to(root)
            source = resolved_test.read_text(encoding="utf-8")
            parsed = ast.parse(source)
        except (OSError, UnicodeError, SyntaxError, ValueError):
            continue
        imported_roots: set[str] = set()
        for node in ast.walk(parsed):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
        if module_name not in imported_roots:
            continue

        matches: list[str] = []
        inspected_files = 0
        search_exhausted = False
        for current, directories, filenames in os.walk(root, followlinks=False):
            directories[:] = sorted(
                directory
                for directory in directories
                if directory not in _SOURCE_SEARCH_EXCLUDED_DIRECTORIES
                and not (Path(current) / directory).is_symlink()
            )
            inspected_files += len(filenames)
            if inspected_files > _MAX_SOURCE_SEARCH_FILES:
                search_exhausted = True
                break
            expected_name = f"{module_name}.py"
            if expected_name not in filenames:
                continue
            candidate = Path(current) / expected_name
            try:
                resolved_candidate = candidate.resolve(strict=True)
                relative = resolved_candidate.relative_to(root).as_posix()
            except (OSError, ValueError):
                continue
            if (
                "tests" in PurePosixPath(relative).parts
                or path_is_covered(relative, blocked_paths)
            ):
                continue
            matches.append(relative)
            if len(matches) > 1:
                break
        if search_exhausted or len(matches) != 1:
            continue
        if matches[0] not in inferred:
            inferred.append(matches[0])
    return tuple(inferred[:_MAX_REQUIRED_PATHS])


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
