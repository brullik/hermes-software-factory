from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from pilot_selector import Candidate, score, select


class PilotSelectorTests(unittest.TestCase):
    def test_high_scoring_safe_repo_selected(self) -> None:
        candidate = Candidate(
            "brullik/safe",
            frozenset({"react_or_next", "rest_api", "postgresql", "tests", "docker", "ci"}),
            frozenset(),
        )
        result = select([candidate], minimum_score=10)
        self.assertIsNotNone(result)
        self.assertEqual(result.repository, "brullik/safe")

    def test_trading_repo_excluded_even_if_high_score(self) -> None:
        candidate = Candidate(
            "brullik/bybit",
            frozenset({
                "react_or_next", "rest_api", "postgresql", "tests",
                "docker", "ci", "monitoring", "rollback",
            }),
            frozenset({"bybit", "trading"}),
        )
        result = score(candidate)
        self.assertTrue(result.excluded)
        self.assertIsNone(select([candidate], minimum_score=1))

    def test_none_when_below_threshold(self) -> None:
        candidate = Candidate("brullik/tiny", frozenset({"tests"}), frozenset())
        self.assertIsNone(select([candidate], minimum_score=10))


if __name__ == "__main__":
    unittest.main()
