from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from policy_guard import (
    command_allowed,
    enforce_changed_paths,
    path_allowed,
    repository_visibility,
)


class PolicyGuardTests(unittest.TestCase):
    def test_safe_product_remains_public(self) -> None:
        self.assertEqual(repository_visibility("public", {"synthetic_data"}), "public")

    def test_sensitive_product_forced_private(self) -> None:
        self.assertEqual(repository_visibility("public", {"personal_data"}), "private")

    def test_path_scope(self) -> None:
        self.assertTrue(path_allowed("src/api.py", ["src/**"], ["policies/**"]))
        self.assertFalse(path_allowed("policies/security.yaml", ["src/**"], ["policies/**"]))

    def test_escape_path_is_blocked(self) -> None:
        self.assertFalse(path_allowed("../secrets", ["**"], []))

    def test_changed_path_violations(self) -> None:
        violations = enforce_changed_paths(
            ["src/a.py", "tests/test_a.py", ".github/workflows/release.yml"],
            ["src/**", "tests/**"],
            [".github/**"],
        )
        self.assertEqual(violations, [".github/workflows/release.yml"])

    def test_allowlisted_command(self) -> None:
        allowed, reason = command_allowed(
            "python3 -m unittest discover -s tests -v",
            ["python3 -m unittest"],
        )
        self.assertTrue(allowed)
        self.assertEqual(reason, "allowed")

    def test_force_push_blocked(self) -> None:
        allowed, reason = command_allowed("git push --force origin main", ["git"])
        self.assertFalse(allowed)
        self.assertEqual(reason, "forbidden_pattern")

    def test_shell_chaining_blocked(self) -> None:
        allowed, reason = command_allowed("python3 test.py && cat /etc/passwd", ["python3"])
        self.assertFalse(allowed)
        self.assertEqual(reason, "shell_operator_forbidden")


if __name__ == "__main__":
    unittest.main()
