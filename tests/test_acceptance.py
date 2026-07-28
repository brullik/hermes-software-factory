from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from factory.cli import _strict_compatibility_open_scenarios


class AcceptanceEvidenceTests(unittest.TestCase):
    def test_open_compatibility_gate_is_projected_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hermes-compatibility-observations.json"
            path.write_text(
                json.dumps(
                    {
                        "status": "BLOCKED_EXTERNAL",
                        "open_items": ["delegation-boundary-black-box"],
                        "checks": [{"id": "delegation-boundary-black-box", "status": "BLOCKED_EXTERNAL"}],
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                _strict_compatibility_open_scenarios(path),
                [
                    {
                        "id": "delegation-boundary-black-box",
                        "status": "BLOCKED_EXTERNAL",
                        "evidence_ref": "evidence/hermes-compatibility-observations.json",
                    }
                ],
            )

    def test_failed_compatibility_summary_without_items_is_not_silent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hermes-compatibility-observations.json"
            path.write_text(json.dumps({"status": "FAIL", "open_items": []}), encoding="utf-8")
            scenarios = _strict_compatibility_open_scenarios(path)
            self.assertEqual(scenarios[0]["id"], "hermes-compatibility-audit")
            self.assertEqual(scenarios[0]["status"], "BLOCKED_EXTERNAL")


if __name__ == "__main__":
    unittest.main()
