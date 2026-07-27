"""Small low-risk neutral pilot used for staging and rollback smoke tests."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

VERSION = "0.1.0"
INDEX = Path(__file__).with_name("index.html")


class PilotStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _ensure_schema(self) -> None:
        connection = self._connect()
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS events ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "kind TEXT NOT NULL, "
                "created_at TEXT NOT NULL)"
            )
            connection.commit()
        finally:
            connection.close()

    def record(self, kind: str) -> None:
        now = datetime.now(UTC).isoformat()
        connection = self._connect()
        try:
            connection.execute("INSERT INTO events(kind, created_at) VALUES (?, ?)", (kind, now))
            connection.commit()
        finally:
            connection.close()

    def status(self) -> dict[str, Any]:
        connection = self._connect()
        try:
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
            count = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        finally:
            connection.close()
        return {"database": integrity == "ok", "integrity": integrity, "events": count}


def json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")


def create_handler(store: PilotStore) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
            self.close_connection = True
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path in {"/", "/index.html"}:
                self._send(HTTPStatus.OK, INDEX.read_bytes(), "text/html; charset=utf-8")
                return
            if self.path == "/health/live":
                self._send(HTTPStatus.OK, json_bytes({"status": "PASS", "service": "hermes-factory-pilot"}), "application/json")
                return
            if self.path == "/health/ready":
                status = store.status()
                code = HTTPStatus.OK if status["database"] else HTTPStatus.SERVICE_UNAVAILABLE
                self._send(code, json_bytes({"status": "PASS" if code == HTTPStatus.OK else "FAIL", **status}), "application/json")
                return
            if self.path == "/api/status":
                self._send(
                    HTTPStatus.OK,
                    json_bytes(
                        {
                            "status": "PASS",
                            "product": "hermes-factory-pilot",
                            "version": VERSION,
                            "risk": "low",
                            "credentials_required": False,
                            **store.status(),
                        }
                    ),
                    "application/json",
                )
                return
            if self.path == "/metrics":
                status = store.status()
                body = (
                    "# HELP hermes_factory_pilot_events_total Number of persisted pilot events.\n"
                    "# TYPE hermes_factory_pilot_events_total counter\n"
                    f"hermes_factory_pilot_events_total {status['events']}\n"
                    "# HELP hermes_factory_pilot_database_ready Whether the pilot database is ready.\n"
                    "# TYPE hermes_factory_pilot_database_ready gauge\n"
                    f"hermes_factory_pilot_database_ready {int(bool(status['database']))}\n"
                ).encode()
                self._send(HTTPStatus.OK, body, "text/plain; version=0.0.4; charset=utf-8")
                return
            self._send(HTTPStatus.NOT_FOUND, b"not found\n", "text/plain; charset=utf-8")

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def create_server(host: str, port: int, database: Path) -> ThreadingHTTPServer:
    store = PilotStore(database)
    store.record("startup")
    server = ThreadingHTTPServer((host, port), create_handler(store))
    server.daemon_threads = True
    return server


def main() -> int:
    host = os.environ.get("PILOT_HOST", "127.0.0.1")
    port = int(os.environ.get("PILOT_PORT", "8080"))
    database = Path(os.environ.get("PILOT_DB", "/data/pilot.db"))
    server = create_server(host, port, database)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
