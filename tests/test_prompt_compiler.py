from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from prompt_compiler import (
    compile_prompt,
    find_secret_candidate_diagnostics,
    find_secret_candidates,
    redact_secret_candidates,
)


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

    def test_task_identifiers_are_not_openai_key_false_positives(self) -> None:
        task_artifact = (
            '{"artifact_id":"task-contract-T-31C85BFFB34EBC8E",'
            '"contract_ref":"evidence/task-T-31C85BFFB34EBC8E.json"}'
        )

        compiled, _ = compile_prompt([task_artifact])

        self.assertEqual(find_secret_candidates(compiled), [])

    def test_secret_diagnostics_and_redaction_never_return_value(self) -> None:
        marker = "ghp_" + ("A" * 24)
        text = '{"findings":[{"description":"' + marker + '"}]}'

        redacted, diagnostics = redact_secret_candidates(text)

        self.assertEqual(
            diagnostics,
            [
                {
                    "detector": "github_classic_token",
                    "location": "$.findings[0].description",
                }
            ],
        )
        self.assertNotIn(marker, redacted)
        self.assertNotIn(marker, str(diagnostics))
        self.assertEqual(
            find_secret_candidate_diagnostics(redacted),
            [],
        )
        self.assertEqual(
            json.loads(redacted)["findings"][0]["description"],
            "[REDACTED]",
        )


if __name__ == "__main__":
    unittest.main()
