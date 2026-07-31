from __future__ import annotations

from factory.repair_scope import (
    derive_scope_required_paths,
    infer_unique_test_source_paths,
    path_is_covered,
    repository_path_candidates,
)


def test_scope_required_paths_recover_only_exact_out_of_scope_files() -> None:
    actual = {
        "blocked_allowed_paths": ["src/**", "tests/**"],
        "provider_scope_findings": [
            {
                "code": "OUT_OF_SCOPE_FULL_SUITE_FAILURE",
                "text": (
                    "tests/unit/test_image_security_verify.py fails because "
                    "scripts/image_security_verify.py returns success for malformed "
                    "scanner output; the production file is outside allowed task scope."
                ),
            }
        ],
    }

    assert derive_scope_required_paths(actual) == ("scripts/image_security_verify.py",)
    assert repository_path_candidates(
        "Inspect `scripts/image_security_verify.py`, not https://example.com/a/b."
    ) == ("scripts/image_security_verify.py",)
    assert path_is_covered("scripts/image_security_verify.py", ["scripts/**"])
    assert not path_is_covered(
        "scripts/image_security_verify.py",
        ["src/**", "tests/**"],
    )


def test_failing_test_maps_only_to_one_uniquely_imported_local_source(
    tmp_path,
) -> None:
    test_path = tmp_path / "tests" / "unit" / "test_server.py"
    test_path.parent.mkdir(parents=True)
    test_path.write_text(
        "from server import create_server\n\ndef test_runtime():\n    assert create_server\n",
        encoding="utf-8",
    )
    source_path = tmp_path / "container" / "server.py"
    source_path.parent.mkdir()
    source_path.write_text("def create_server():\n    return object()\n", encoding="utf-8")

    assert infer_unique_test_source_paths(
        tmp_path,
        ["tests/unit/test_server.py"],
        ["tests/**"],
    ) == ("container/server.py",)
    assert infer_unique_test_source_paths(
        tmp_path,
        ["tests/unit/test_server.py"],
        ["tests/**", "container/**"],
    ) == ()

    duplicate = tmp_path / "src" / "server.py"
    duplicate.parent.mkdir()
    duplicate.write_text("def create_server():\n    return object()\n", encoding="utf-8")
    assert infer_unique_test_source_paths(
        tmp_path,
        ["tests/unit/test_server.py"],
        ["tests/**"],
    ) == ()
