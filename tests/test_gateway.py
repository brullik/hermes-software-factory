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
                "/idea <текст>, /status, /projects, /pause <product>, /resume <product>, /cancel <product>, /owner_action",
            )
            self.assertNotIn("Р", api.sent[0][1])
            self.assertIn("telegram update processed update_id=30 command=help", "\n".join(logs.output))
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


if __name__ == "__main__":
    unittest.main()
