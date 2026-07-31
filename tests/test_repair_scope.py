from __future__ import annotations

from factory.repair_scope import (
    derive_scope_required_paths,
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
