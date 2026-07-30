from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

import yaml

from factory.config import FactoryConfig
from factory.controller import ControllerHttpServer
from factory.state import StateStore

ROOT = Path(__file__).resolve().parents[1]


class ControllerHttpTests(unittest.TestCase):
    def _config_and_state(self, state_dir: Path) -> tuple[FactoryConfig, StateStore]:
        raw = yaml.safe_load((ROOT / "config" / "factory-config.example.yaml").read_text(encoding="utf-8"))
        raw["paths"]["state"] = str(state_dir)
        raw["paths"]["policies"] = str(ROOT / "policies")
        raw["paths"]["schemas"] = str(ROOT / "schemas")
        raw["paths"]["prompts"] = str(ROOT / "prompts")
        raw["paths"]["worktrees"] = str(state_dir / "worktrees")
        raw["paths"]["logs"] = str(state_dir / "logs")
        raw["controller"]["database_url"] = f"sqlite:///{(state_dir / 'controller.db').as_posix()}"
        config = FactoryConfig(raw, ROOT / "config" / "factory-config.example.yaml")
        return config, StateStore(config.database_path, max_active_workers=config.max_active_workers)

    def test_local_intake_endpoint_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            raw = yaml.safe_load((ROOT / "config" / "factory-config.example.yaml").read_text(encoding="utf-8"))
            raw["paths"]["state"] = str(state_dir)
            raw["paths"]["policies"] = str(ROOT / "policies")
            raw["paths"]["schemas"] = str(ROOT / "schemas")
            raw["paths"]["prompts"] = str(ROOT / "prompts")
            raw["paths"]["worktrees"] = str(state_dir / "worktrees")
            raw["paths"]["logs"] = str(state_dir / "logs")
            raw["controller"]["database_url"] = f"sqlite:///{(state_dir / 'controller.db').as_posix()}"
            config = FactoryConfig(raw, ROOT / "config" / "factory-config.example.yaml")
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            server = ControllerHttpServer(("127.0.0.1", 0), state, config)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                body = json.dumps({
                    "source": "cli",
                    "owner_id": "owner",
                    "idea": "Build a safe local tool",
                    "idempotency_key": "controller-request-1",
                })
                client.request("POST", "/intake", body=body, headers={"Content-Type": "application/json"})
                first = client.getresponse()
                first_payload = json.loads(first.read())
                self.assertEqual(first.status, 201)
                self.assertTrue(first_payload["created"])
                client.request("POST", "/intake", body=body, headers={"Content-Type": "application/json"})
                second = client.getresponse()
                second_payload = json.loads(second.read())
                self.assertEqual(second.status, 200)
                self.assertFalse(second_payload["created"])
                self.assertEqual(first_payload["product_id"], second_payload["product_id"])
                client.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
                state.close()

    def test_intake_capacity_returns_retryable_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            raw = yaml.safe_load((ROOT / "config" / "factory-config.example.yaml").read_text(encoding="utf-8"))
            raw["paths"]["state"] = str(state_dir)
            raw["paths"]["policies"] = str(ROOT / "policies")
            raw["paths"]["schemas"] = str(ROOT / "schemas")
            raw["paths"]["prompts"] = str(ROOT / "prompts")
            raw["paths"]["worktrees"] = str(state_dir / "worktrees")
            raw["paths"]["logs"] = str(state_dir / "logs")
            raw["controller"]["database_url"] = f"sqlite:///{(state_dir / 'controller.db').as_posix()}"
            raw["intake"]["rate_limit_requests"] = 1
            config = FactoryConfig(raw, ROOT / "config" / "factory-config.example.yaml")
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            server = ControllerHttpServer(("127.0.0.1", 0), state, config)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                for request_id, idea in (("one", "first"), ("two", "second")):
                    body = json.dumps({
                        "source": "cli",
                        "owner_id": "owner",
                        "idea": idea,
                        "idempotency_key": request_id,
                    })
                    client.request("POST", "/intake", body=body, headers={"Content-Type": "application/json"})
                    response = client.getresponse()
                    response.read()
                    if request_id == "one":
                        self.assertEqual(response.status, 201)
                    else:
                        self.assertEqual(response.status, 429)
                client.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
                state.close()

    def test_local_kanban_is_read_only_and_minimal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config, state = self._config_and_state(Path(directory))
            state.create_product(
                product_id="kanban-product",
                owner_id="private-owner",
                source="telegram",
                idea="private idea that must not enter the dashboard",
                idempotency_key="kanban-fixture",
            )
            state.add_task(
                task_id="kanban-task",
                product_id="kanban-product",
                title="Build the first slice",
                role="builder",
                priority=10,
            )
            server = ControllerHttpServer(("127.0.0.1", 0), state, config)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                client.request("GET", "/api/kanban?view=current")
                response = client.getresponse()
                payload = json.loads(response.read())
                self.assertEqual(response.status, 200)
                self.assertEqual(payload["summary"]["products_total"], 1)
                self.assertEqual(payload["products"][0]["product_id"], "kanban-product")
                self.assertEqual(payload["products"][0]["tasks"][0]["task_id"], "kanban-task")
                self.assertNotIn("idea", payload["products"][0])
                self.assertNotIn("owner_id", payload["products"][0])
                client.request("GET", "/kanban")
                html_response = client.getresponse()
                html = html_response.read().decode("utf-8")
                headers = dict(html_response.getheaders())
                self.assertEqual(html_response.status, 200)
                self.assertIn("Hermes Kanban", html)
                self.assertIn("/api/kanban", html)
                self.assertIn("Content-Security-Policy", headers)
                client.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
                state.close()

    def test_maintenance_is_visible_and_readiness_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config, state = self._config_and_state(Path(directory))
            state.enter_maintenance("semantic recovery")
            state.record_sqlite_busy_event()
            server = ControllerHttpServer(("127.0.0.1", 0), state, config)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = HTTPConnection(
                    "127.0.0.1", server.server_port, timeout=3
                )
                client.request("GET", "/healthz")
                health = client.getresponse()
                health_payload = json.loads(health.read())
                self.assertEqual(health.status, 200)
                self.assertTrue(health_payload["maintenance"]["active"])

                client.request("GET", "/readyz")
                ready = client.getresponse()
                ready_payload = json.loads(ready.read())
                self.assertEqual(ready.status, 503)
                self.assertEqual(ready_payload["status"], "MAINTENANCE")

                client.request("GET", "/metrics")
                metrics = client.getresponse().read().decode("utf-8")
                self.assertIn("hermes_factory_maintenance_active 1", metrics)
                self.assertIn(
                    "hermes_factory_sqlite_busy_events_total 1", metrics
                )
                client.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
                state.close()


if __name__ == "__main__":
    unittest.main()
