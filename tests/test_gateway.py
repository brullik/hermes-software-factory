from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

import yaml

from factory.artifacts import ArtifactStore
from factory.config import FactoryConfig
from factory.gateway import TelegramGateway
from factory.state import StateStore
from factory.telegram import TelegramApi

ROOT = Path(__file__).resolve().parents[1]


class FakeTelegramApi:
    def __init__(self, updates: list[dict[str, Any]] | None = None) -> None:
        self.updates = updates or []
        self.sent: list[tuple[str, str]] = []
        self.offsets: list[int | None] = []

    def get_updates(self, offset: int | None) -> list[dict[str, Any]]:
        self.offsets.append(offset)
        updates, self.updates = self.updates, []
        return updates

    def send_message(self, chat_id: str, text: str) -> None:
        self.sent.append((chat_id, text))


def make_config(root: Path) -> FactoryConfig:
    raw = yaml.safe_load((ROOT / "config" / "factory-config.example.yaml").read_text(encoding="utf-8"))
    raw["telegram"]["allowed_user_ids"] = [42]
    raw["paths"]["state"] = str(root)
    raw["paths"]["policies"] = str(ROOT / "policies")
    raw["paths"]["schemas"] = str(ROOT / "schemas")
    raw["paths"]["prompts"] = str(ROOT / "prompts")
    raw["paths"]["worktrees"] = str(root / "worktrees")
    raw["paths"]["logs"] = str(root / "logs")
    raw["controller"]["database_url"] = f"sqlite:///{(root / 'controller.db').as_posix()}"
    return FactoryConfig(raw, ROOT / "config" / "factory-config.example.yaml")


def update(update_id: int, user_id: int, text: str) -> dict[str, Any]:
    return {
        "update_id": update_id,
        "message": {
            "from": {"id": user_id},
            "chat": {"id": user_id, "type": "private"},
            "text": text,
        },
    }


class GatewayTests(unittest.TestCase):
    def test_systemd_unit_loads_gateway_from_stable_runtime(self) -> None:
        unit = (
            ROOT / "config" / "systemd" / "hermes-factory-gateway.service"
        ).read_text(encoding="utf-8")

        self.assertIn("WorkingDirectory=/opt/hermes-factory/current", unit)
        self.assertIn("Environment=PYTHONPATH=/opt/hermes-factory/current", unit)
        self.assertIn(
            "ExecStart=/opt/hermes-factory/venv/bin/python -P -m factory.gateway",
            unit,
        )
        self.assertIn("ReadOnlyPaths=/opt/hermes-factory", unit)
        self.assertNotIn("/opt/hermes-codex-runtime", unit)

    def test_telegram_api_base_url_allows_only_official_or_loopback(self) -> None:
        TelegramApi("fixture", api_base_url="https://api.telegram.org")
        TelegramApi("fixture", api_base_url="http://127.0.0.1:8765")
        with self.assertRaises(ValueError):
            TelegramApi("fixture", api_base_url="https://example.com")

    def test_allowlist_intake_and_update_idempotency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(Path(directory))
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            api = FakeTelegramApi()
            gateway = TelegramGateway(
                config,
                state,
                ArtifactStore(config),
                api,  # type: ignore[arg-type]
                offset_path=Path(directory) / "offset",
            )
            self.assertTrue(gateway.process_update(update(10, 42, "Build a safe tool")))
            self.assertTrue(gateway.process_update(update(10, 42, "Build a safe tool")))
            self.assertFalse(gateway.process_update(update(11, 99, "Build a rejected tool")))
            self.assertEqual(len(state.list_products()), 1)
            self.assertEqual(len(api.sent), 2)
            self.assertIn("создан", api.sent[0][1])
            self.assertIn("уже существует", api.sent[1][1])
            state.close()

    def test_command_errors_are_safe_and_poll_offset_is_durable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(Path(directory))
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            api = FakeTelegramApi([update(20, 42, "/idea " + "ghp_" + "abcdefghijklmnopqrstuvwxyz123456")])
            offset = Path(directory) / "offset"
            gateway = TelegramGateway(config, state, ArtifactStore(config), api, offset_path=offset)  # type: ignore[arg-type]
            self.assertEqual(gateway.poll_once(), 1)
            self.assertEqual(offset.read_text(encoding="utf-8").strip(), "21")
            self.assertIn("отклонена", api.sent[0][1])
            self.assertEqual(gateway.poll_once(), 0)
            self.assertEqual(api.offsets, [None, 21])
            state.close()

    def test_help_response_is_utf8_and_contains_cyrillic_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(Path(directory))
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            api = FakeTelegramApi()
            gateway = TelegramGateway(
                config,
                state,
                ArtifactStore(config),
                api,  # type: ignore[arg-type]
                offset_path=Path(directory) / "offset",
            )

            with self.assertLogs("factory.gateway", level="INFO") as logs:
                self.assertTrue(gateway.process_update(update(30, 42, "/help")))
            self.assertEqual(
                api.sent[0][1],
                "/idea <текст>, /status, /projects, /kanban, /pause <product>, "
                "/resume <product>, /cancel <product>, /owner_action, "
                "/approve <action_id> <code>, /deny <action_id>",
            )
            self.assertNotIn("Р", api.sent[0][1])
            self.assertIn("telegram update processed update_id=30 command=help", "\n".join(logs.output))
            state.close()

    def test_kanban_command_returns_read_only_task_summary_without_private_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(Path(directory))
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            state.create_product(
                product_id="telegram-kanban-product",
                owner_id="private-owner",
                source="telegram",
                idea="private idea must not be sent in the Kanban summary",
                idempotency_key="telegram-kanban-fixture",
            )
            state.add_task(
                task_id="telegram-kanban-task",
                product_id="telegram-kanban-product",
                title="Build the first slice",
                role="builder",
                priority=10,
            )
            api = FakeTelegramApi()
            gateway = TelegramGateway(
                config,
                state,
                ArtifactStore(config),
                api,  # type: ignore[arg-type]
                offset_path=Path(directory) / "offset",
            )

            self.assertTrue(gateway.process_update(update(40, 42, "/kanban")))
            response = api.sent[0][1]
            self.assertIn("Hermes Kanban (read-only)", response)
            self.assertIn("telegram-kanban-product", response)
            self.assertIn("telegram-kanban-task", response)
            self.assertIn("Build the first slice", response)
            self.assertNotIn("private-owner", response)
            self.assertNotIn("private idea", response)
            self.assertLessEqual(len(response), 4096)
            state.close()

    def test_api_client_never_exposes_token_in_request_payload(self) -> None:
        calls: list[tuple[str, dict[str, object]]] = []

        def request(method: str, payload: dict[str, object]) -> dict[str, Any]:
            calls.append((method, payload))
            return {"ok": True, "result": [] if method == "getUpdates" else {}}

        api = TelegramApi("123456:secret-token", request=request)
        self.assertEqual(api.get_updates(None), [])
        api.send_message("42", "safe")
        self.assertEqual([method for method, _ in calls], ["getUpdates", "sendMessage"])
        self.assertNotIn("secret-token", repr(calls))

    def test_durable_outbox_is_delivered_to_owner_in_russian(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(Path(directory))
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            state.enqueue_outbox(
                outbox_id="outbox-russian-owner",
                idempotency_key="outbox-russian-owner-key",
                event_type="telegram.owner_notification",
                payload={
                    "kind": "repair_exhausted",
                    "product_id": "product-notification",
                    "task_id": "T-NOTIFY",
                    "text": "Hermes самостоятельно исправляет ошибку. Действие владельца не требуется.",
                },
            )
            api = FakeTelegramApi()
            gateway = TelegramGateway(
                config,
                state,
                ArtifactStore(config),
                api,  # type: ignore[arg-type]
                offset_path=Path(directory) / "offset",
            )

            self.assertEqual(gateway.deliver_outbox(), 1)

            self.assertEqual(
                api.sent,
                [
                    (
                        "42",
                        (
                            "Hermes самостоятельно исправляет ошибку. "
                            "Действие владельца не требуется."
                        ),
                    )
                ],
            )
            outbox = state.list_outbox()
            self.assertEqual(outbox[0]["status"], "DONE")
            self.assertIsNotNone(outbox[0]["delivered_at"])
            state.close()

    def test_gateway_claims_only_telegram_events_without_blocking_on_generic_outbox(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(Path(directory))
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            state.enqueue_outbox(
                outbox_id="outbox-generic-first",
                idempotency_key="outbox-generic-first-key",
                event_type="task_result_committed",
                payload={"task_id": "T-GENERIC"},
            )
            state.enqueue_outbox(
                outbox_id="outbox-telegram-second",
                idempotency_key="outbox-telegram-second-key",
                event_type="telegram.owner_notification",
                payload={
                    "kind": "autonomous_progress",
                    "product_id": "product-notification",
                    "task_id": "T-NOTIFY",
                    "text": "Hermes продолжил проект автоматически.",
                },
            )
            api = FakeTelegramApi()
            gateway = TelegramGateway(
                config,
                state,
                ArtifactStore(config),
                api,  # type: ignore[arg-type]
                offset_path=Path(directory) / "offset",
            )

            self.assertEqual(gateway.deliver_outbox(), 1)

            self.assertEqual(
                api.sent,
                [("42", "Hermes продолжил проект автоматически.")],
            )
            outbox = {item["outbox_id"]: item for item in state.list_outbox()}
            self.assertEqual(outbox["outbox-generic-first"]["status"], "PENDING")
            self.assertEqual(outbox["outbox-generic-first"]["attempts"], 0)
            self.assertEqual(outbox["outbox-telegram-second"]["status"], "DONE")
            state.close()


if __name__ == "__main__":
    unittest.main()
