from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from pilot.app import create_server
from scripts.pilot_black_box import build_artifact, run_checks, write_immutable


class PilotBlackBoxTests(unittest.TestCase):
    def test_black_box_runner_checks_real_http_surface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            server = create_server("127.0.0.1", 0, Path(directory) / "pilot.db")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                result = run_checks(f"http://127.0.0.1:{server.server_port}")
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(result["restart_persistence"], "NOT_RUN")
                self.assertEqual({item["status"] for item in result["checks"]}, {"PASS"})
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_restart_threshold_and_immutable_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "pilot.db"
            first = create_server("127.0.0.1", 0, database)
            first.server_close()
            second = create_server("127.0.0.1", 0, database)
            thread = threading.Thread(target=second.serve_forever, daemon=True)
            thread.start()
            try:
                artifact = build_artifact(None, f"http://127.0.0.1:{second.server_port}", 2)
                self.assertEqual(artifact["status"], "PASS")
                self.assertEqual(artifact["restart_persistence"], "PASS")
                evidence = Path(directory) / "pilot-black-box.json"
                write_immutable(evidence, artifact)
                self.assertEqual(json.loads(evidence.read_text(encoding="utf-8"))["status"], "PASS")
                with self.assertRaises(RuntimeError):
                    write_immutable(evidence, {**artifact, "summary": "tampered"})
            finally:
                second.shutdown()
                second.server_close()
                thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
