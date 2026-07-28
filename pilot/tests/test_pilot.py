from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

try:
    from pilot.app import create_server
except ModuleNotFoundError:
    # The pilot is also published as a standalone repository whose app.py
    # lives at repository root rather than under a pilot/ package.
    from app import create_server  # type: ignore[import-not-found,no-redef]


class PilotTests(unittest.TestCase):
    def test_black_box_health_and_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            server = create_server("127.0.0.1", 0, Path(directory) / "pilot.db")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                for path in ("/health/live", "/health/ready", "/api/status"):
                    client.request("GET", path)
                    response = client.getresponse()
                    self.assertEqual(response.status, 200)
                    payload = json.loads(response.read())
                    self.assertEqual(payload["status"], "PASS")
                client.request("GET", "/metrics")
                metrics = client.getresponse()
                self.assertEqual(metrics.status, 200)
                self.assertIn(b"hermes_factory_pilot_events_total", metrics.read())
                client.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_persistent_event_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "pilot.db"
            first = create_server("127.0.0.1", 0, database)
            first.server_close()
            second = create_server("127.0.0.1", 0, database)
            try:
                connection = sqlite3.connect(database)
                try:
                    count = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
                finally:
                    connection.close()
                self.assertEqual(count, 2)
            finally:
                second.server_close()


if __name__ == "__main__":
    unittest.main()
