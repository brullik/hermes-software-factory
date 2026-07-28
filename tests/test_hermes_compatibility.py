from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.verify_hermes_compatibility import expected_version


class HermesCompatibilityTests(unittest.TestCase):
    def test_reads_pinned_hermes_version(self) -> None:
        report = Path(__file__).resolve().parents[1] / "evidence" / "compatibility-report.json"
        self.assertEqual(expected_version(report), "0.19.0")

    def test_missing_pin_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            report.write_text(json.dumps({"components": []}), encoding="utf-8")
            with self.assertRaises(ValueError):
                expected_version(report)


if __name__ == "__main__":
    unittest.main()
