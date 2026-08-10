"""Content-addressed existing-repository fixture identity for qualification lanes."""

from __future__ import annotations

from typing import Any

from .common import sha256_text, stable_json


class PreQ8FixtureError(RuntimeError):
    """The deterministic existing-repository fixture is invalid."""


_FIXTURE_FILES = {
    "README.md": (
        "# Deterministic Hermes repair fixture\n\n"
        "This private qualification fixture contains one intentional product defect.\n"
    ),
    "pyproject.toml": (
        '[build-system]\nrequires = ["setuptools>=75"]\n'
        'build-backend = "setuptools.build_meta"\n\n'
        '[project]\nname = "hermes-existing-repository-fixture"\n'
        'version = "1.0.0"\nrequires-python = ">=3.12"\n\n'
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n'
    ),
    "src/fixture_math.py": (
        '"""One intentionally defective function for the repair scenario."""\n\n'
        "def bounded_total(values: list[int], limit: int) -> int:\n"
        '    """Return the sum capped at ``limit``."""\n\n'
        "    return min(sum(values), limit + 1)\n"
    ),
    "tests/test_fixture_math.py": (
        "from src.fixture_math import bounded_total\n\n\n"
        "def test_total_is_capped_at_declared_limit() -> None:\n"
        "    assert bounded_total([4, 7], 10) == 10\n\n\n"
        "def test_total_below_limit_is_unchanged() -> None:\n"
        "    assert bounded_total([2, 3], 10) == 5\n"
    ),
}


def fixture_files() -> dict[str, bytes]:
    return {path: content.encode("utf-8") for path, content in _FIXTURE_FILES.items()}


def fixture_manifest() -> dict[str, Any]:
    files = fixture_files()
    entries = [
        {
            "path": path,
            "digest": sha256_text(content.decode("utf-8")),
            "size": len(content),
        }
        for path, content in sorted(files.items())
    ]
    body = {
        "schema_version": "1.0",
        "fixture_type": "EXISTING_REPOSITORY_REPAIR",
        "default_branch": "main",
        "visibility": "private",
        "files": entries,
    }
    return {**body, "fixture_seed_digest": sha256_text(stable_json(body))}
