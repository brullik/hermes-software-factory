from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from context_pack import compact_log, select_files


class ContextPackTests(unittest.TestCase):
    def test_select_files_respects_count_and_reason(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.py").write_text("a", encoding="utf-8")
            (root / "b.py").write_text("bb", encoding="utf-8")
            selected = select_files(
                root,
                [("a.py", "imported"), ("b.py", "test target")],
                max_files=1,
                max_chars=100,
            )
            self.assertEqual(len(selected), 1)
            self.assertEqual(selected[0].path, "a.py")
            self.assertEqual(selected[0].reason, "imported")
            self.assertEqual(selected[0].content, "a")

    def test_select_files_blocks_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = select_files(root, [("../outside", "bad")], max_files=10, max_chars=100)
            self.assertEqual(selected, [])

    def test_compact_log(self) -> None:
        text = "\n".join(str(index) for index in range(300))
        compacted = compact_log(text, max_lines=20)
        self.assertIn("280 lines omitted", compacted)
        self.assertLess(len(compacted.splitlines()), 22)


if __name__ == "__main__":
    unittest.main()
