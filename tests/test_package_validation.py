from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_package import validate


class PackageValidationTests(unittest.TestCase):
    def test_package_validation_has_no_errors(self) -> None:
        self.assertEqual(validate(), [])


if __name__ == "__main__":
    unittest.main()
