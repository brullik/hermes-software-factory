from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from prompt_compiler import compile_prompt, find_secret_candidates


class PromptCompilerTests(unittest.TestCase):
    def test_deterministic_digest(self) -> None:
        first, digest1 = compile_prompt(["a", "b"])
        second, digest2 = compile_prompt(["a", "b"])
        self.assertEqual(first, second)
        self.assertEqual(digest1, digest2)

    def test_whitespace_is_normalized_between_parts(self) -> None:
        compiled, _ = compile_prompt([" a ", "\n b\n"])
        self.assertEqual(compiled, "a\n\nb\n")

    def test_private_key_detected(self) -> None:
        text = "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nabc"
        self.assertTrue(find_secret_candidates(text))

    def test_secret_candidate_rejected(self) -> None:
        with self.assertRaises(ValueError):
            compile_prompt(["token=" + "abcdefghijklmnopqrstuvwxyz" + "123456"])


if __name__ == "__main__":
    unittest.main()
