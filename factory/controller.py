"""Long-lived localhost controller process.

This process intentionally exposes only health/status endpoints. Mutating
operations go through the durable StateStore and adapters rather than through
model-generated HTTP commands.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .artifacts import ArtifactStore
from .config import FactoryConfig, load_config
from .intake import IntakeRejected, IntakeService
from .kanban import KANBAN_HTML, build_kanban_snapshot
from .reconciler import PipelineReconciler, ReconcilerLoop
from .state import IntakeRateLimitError, ProductCapacityError, StateStore
from .workflow import WorkflowEngine


class ControllerHandler(BaseHTTPRequestHandler):
    server: ControllerHttpServer

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/kanban":
            self._send_text(200, KANBAN_HTML, "text/html; charset=utf-8")
            return
        if path == "/api/kanban":
            self._send_json(200, build_kanban_snapshot(self.server.state))
            return
        if path == "/metrics":
            database_ready = int(self.server.state.health())
            product_count = len(self.server.state.list_products())
            orphaned_count = self.server.state.orphaned_product_count()
            body = (
                "# HELP hermes_factory_database_ready Whether the controller database is ready.\n"
                "# TYPE hermes_factory_database_ready gauge\n"
                f"hermes_factory_database_ready {database_ready}\n"
                "# HELP hermes_factory_products_total Number of products in durable state.\n"
                "# TYPE hermes_factory_products_total gauge\n"
                f"hermes_factory_products_total {product_count}\n"
                "# HELP hermes_factory_orphaned_products Products without durable next work.\n"
                "# TYPE hermes_factory_orphaned_products gauge\n"
                f"hermes_factory_orphaned_products {orphaned_count}\n"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path not in {"/healthz", "/readyz", "/status"}:
            self.send_error(404)
            return
        payload: dict[str, Any] = {
            "status": "PASS",
            "service": "hermes-factory-controller",
            "database": self.server.state.health(),
        }
        if path == "/status":
            payload["products"] = self.server.state.list_products()
        self._send_json(200, payload)

    def do_POST(self) -> None:
        try:
            payload = self._read_json()
            path = urlsplit(self.path).path
            if path == "/intake":
                result = IntakeService(
                    self.server.config,
                    self.server.state,
                    ArtifactStore(self.server.config),
                ).submit(
                    source=str(payload.get("source", "cli")),
                    owner_id=str(payload["owner_id"]),
                    goal_text=str(payload.get("goal_text") or payload["idea"]),
                    delivery_mode=str(
                        payload.get("delivery_mode")
                        or (
                            "existing_repository"
                            if payload.get("repository_url")
                            else "new_repository"
                        )
                    ),
                    repository_url=payload.get("repository_url"),
                    repository_name=payload.get("repository_name"),
                    repository_visibility=str(
                        payload.get("repository_visibility", "private")
                    ),
                    constraints=payload.get("constraints", {}),
                    idempotency_key=payload.get("idempotency_key"),
                    attachments=payload.get("attachments", []),
                )
                self._send_json(
                    201 if result.created else 200,
                    {
                        "status": "PASS",
                        "product_id": result.product_id,
                        "artifact_path": result.artifact_path,
                        "correlation_id": result.correlation_id,
                        "created": result.created,
                    },
                )
                return
            parts = path.strip("/").split("/")
            if len(parts) == 3 and parts[0] == "products" and parts[2] in {"pause", "resume", "cancel"}:
                workflow = WorkflowEngine(self.server.state)
                if parts[2] == "pause":
                    product = workflow.pause(parts[1])
                elif parts[2] == "resume":
                    product = workflow.resume(parts[1], str(payload.get("status", "IMPLEMENTING")))
                else:
                    product = workflow.cancel(parts[1])
                self._send_json(200, {"status": "PASS", "product": product})
                return
            self.send_error(404)
        except (IntakeRateLimitError, ProductCapacityError) as error:
            self._send_json(429, {"status": "FAIL", "error": str(error)})
        except (KeyError, TypeError, ValueError, IntakeRejected) as error:
            self._send_json(400, {"status": "FAIL", "error": str(error)})

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 1 or length > 1_048_576:
            raise ValueError("request body must be between 1 byte and 1 MiB")
        body = self.rfile.read(length)
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("request body must be a JSON object")
        return payload

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def _send_text(self, status: int, body: str, content_type: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        return


class ControllerHttpServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], state: StateStore, config: FactoryConfig) -> None:
        super().__init__(address, ControllerHandler)
        self.state = state
        self.config = config


def serve(config: FactoryConfig) -> None:
    state = StateStore(
        config.database_path,
        max_active_workers=config.max_active_workers,
        max_active_products=config.max_active_products,
    )
    state.recover_expired_leases()
    bind = str(config.raw.get("network", {}).get("admin_bind", "127.0.0.1"))
    port = int(config.raw.get("network", {}).get("admin_port", 8787))
    if bind != "127.0.0.1":
        raise RuntimeError("Controller refuses to bind outside localhost")
    server = ControllerHttpServer((bind, port), state, config)
    reconciler = ReconcilerLoop(
        PipelineReconciler(config, state, ArtifactStore(config)),
        config.reconcile_interval_seconds,
    )
    reconciler.start()
    try:
        server.serve_forever()
    finally:
        reconciler.stop()
        server.server_close()
        state.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Hermes Software Factory controller")
    parser.add_argument("--config", type=Path)
    args = parser.parse_args()
    serve(load_config(args.config))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
