"""Fail-closed Telegram gateway with durable update idempotency."""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from .artifacts import ArtifactStore
from .capabilities import CapabilityBroker
from .config import FactoryConfig, load_config
from .gateway_commands import GatewayCommandError, parse_command
from .intake import IntakeService
from .kanban import build_kanban_snapshot, format_telegram_summary
from .state import StateStore
from .telegram import TelegramApi, TelegramApiError
from .workflow import WorkflowEngine

LOGGER = logging.getLogger(__name__)


def credential_path(name: str) -> Path | None:
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    candidates = []
    if directory:
        candidates.append(Path(directory) / name)
    candidates.append(Path("/etc/hermes-factory/credentials.d") / name)
    for path in candidates:
        try:
            if path.is_file() and not path.is_symlink():
                return path
        except OSError:
            continue
    return None


def credential_available(name: str) -> bool:
    return credential_path(name) is not None


def read_credential(name: str) -> str:
    path = credential_path(name)
    if path is None:
        raise FileNotFoundError(name)
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError(f"Credential file {name} is empty")
    return value


class TelegramGateway:
    def __init__(
        self,
        config: FactoryConfig,
        state: StateStore,
        artifacts: ArtifactStore,
        api: TelegramApi,
        *,
        offset_path: Path | None = None,
        capability_broker: CapabilityBroker | None = None,
    ) -> None:
        self.config = config
        self.state = state
        self.artifacts = artifacts
        self.api = api
        self.offset_path = offset_path or (config.state_dir / "telegram-offset")
        self.offset_path.parent.mkdir(parents=True, exist_ok=True)
        self.outbox_worker_id = "telegram-gateway"
        self.capability_broker = capability_broker

    def _read_offset(self) -> int | None:
        if not self.offset_path.is_file():
            return None
        value = self.offset_path.read_text(encoding="utf-8").strip()
        return int(value) if value else None

    def _write_offset(self, value: int) -> None:
        temporary = self.offset_path.with_suffix(".tmp")
        temporary.write_text(f"{value}\n", encoding="utf-8", newline="\n")
        os.replace(temporary, self.offset_path)

    @staticmethod
    def _message(update: dict[str, Any]) -> tuple[int, str, str] | None:
        message = update.get("message")
        if not isinstance(message, dict):
            return None
        sender = message.get("from")
        chat = message.get("chat")
        text = message.get("text")
        if not isinstance(sender, dict) or not isinstance(chat, dict) or not isinstance(text, str):
            return None
        if chat.get("type") != "private" or not isinstance(sender.get("id"), int):
            return None
        chat_id = chat.get("id")
        if not isinstance(chat_id, int):
            return None
        return sender["id"], str(chat_id), text

    def _products_text(self) -> str:
        products = self.state.list_products()
        if not products:
            return "Активных продуктов нет."
        lines = ["Продукты:"]
        for product in products[:20]:
            lines.append(f"- {product['product_id']}: {product['status']}")
        return "\n".join(lines)

    def _owner_actions_text(self) -> str:
        actions = self.state.open_capability_blocks()
        if not actions:
            return "Ожидающих OWNER_ACTION нет."
        names = list(
            dict.fromkeys(
                Path(str(item["owner_action_ref"])).name
                for item in actions
            )
        )
        return "OWNER_ACTION:\n" + "\n".join(
            f"- {name}"
            for name in names[:10]
        )

    @staticmethod
    def _product_id(argument: str | None) -> str:
        if argument is None or len(argument.split()) != 1:
            raise GatewayCommandError("Укажите один product_id")
        return argument

    def _dispatch(self, command: str, argument: str | None, owner_id: int, update_id: int) -> str:
        if command == "help":
            return "/idea <текст>, /status, /projects, /kanban, /pause <product>, /resume <product>, /cancel <product>, /owner_action"
        if command in {"status", "projects"}:
            return self._products_text()
        if command == "kanban":
            return format_telegram_summary(build_kanban_snapshot(self.state))
        if command == "owner_action":
            return self._owner_actions_text()
        if command == "idea":
            assert argument is not None
            result = IntakeService(
                self.config,
                self.state,
                self.artifacts,
                capability_broker=self.capability_broker,
            ).submit(
                source="telegram",
                owner_id=str(owner_id),
                goal_text=argument,
                delivery_mode="new_repository",
                repository_visibility="private",
                idempotency_key=f"telegram-update:{update_id}",
            )
            verb = "создан" if result.created else "уже существует"
            return f"Product {verb}: {result.product_id}"
        product_id = self._product_id(argument)
        workflow = WorkflowEngine(self.state)
        if command == "pause":
            product = workflow.pause(product_id)
        elif command == "resume":
            product = workflow.resume(product_id, "IMPLEMENTING")
        else:
            product = workflow.cancel(product_id)
        return f"{product_id}: {product['status']}"

    def process_update(self, update: dict[str, Any]) -> bool:
        update_id = update.get("update_id")
        message = self._message(update)
        if not isinstance(update_id, int) or message is None:
            return False
        owner_id, chat_id, raw_text = message
        if str(owner_id) not in self.config.allowed_telegram_user_ids:
            LOGGER.warning("telegram update rejected update_id=%s reason=allowlist", update_id)
            return False
        command_text = raw_text if raw_text.lstrip().startswith("/") else f"/idea {raw_text}"
        command_name = "rejected"
        try:
            parsed = parse_command(command_text)
            command_name = parsed.name
            response = self._dispatch(parsed.name, parsed.argument, owner_id, update_id)
        except (GatewayCommandError, ValueError, KeyError) as error:
            response = f"Команда отклонена: {error}"
        self.api.send_message(chat_id, response)
        LOGGER.info("telegram update processed update_id=%s command=%s", update_id, command_name)
        return True

    def deliver_outbox(self, limit: int = 10) -> int:
        delivered = 0
        recipients = sorted(self.config.allowed_telegram_user_ids)
        for _ in range(max(0, limit)):
            claimed = self.state.claim_outbox(
                self.outbox_worker_id,
                limit=1,
                lease_seconds=60,
                event_types=("telegram.owner_notification",),
            )
            if not claimed:
                break
            item = claimed[0]
            outbox_id = str(item["outbox_id"])
            try:
                if str(item.get("event_type")) != "telegram.owner_notification":
                    raise ValueError("unsupported_outbox_event")
                payload = json.loads(str(item["payload_json"]))
                if not isinstance(payload, dict):
                    raise TypeError("invalid_outbox_payload")
                text = payload.get("text")
                if not isinstance(text, str) or not text.strip():
                    raise ValueError("invalid_outbox_message")
                if not recipients:
                    raise ValueError("telegram_owner_allowlist_empty")
                for chat_id in recipients:
                    self.api.send_message(chat_id, text)
                self.state.mark_outbox_done(outbox_id, self.outbox_worker_id)
                LOGGER.info(
                    "telegram outbox delivered outbox_id=%s kind=%s",
                    outbox_id,
                    str(payload.get("kind", "notification"))[:80],
                )
                delivered += 1
            except (TelegramApiError, OSError, TypeError, ValueError, json.JSONDecodeError) as error:
                self.state.mark_outbox_failed(
                    outbox_id,
                    self.outbox_worker_id,
                    type(error).__name__,
                )
                LOGGER.warning(
                    "telegram outbox delivery failed outbox_id=%s reason=%s",
                    outbox_id,
                    type(error).__name__,
                )
                break
        return delivered

    def poll_once(self) -> int:
        self.deliver_outbox()
        offset = self._read_offset()
        processed = 0
        for update in self.api.get_updates(offset):
            update_id = update.get("update_id")
            if isinstance(update_id, int):
                self.process_update(update)
                self._write_offset(update_id + 1)
                processed += 1
        return processed

    def run_forever(self) -> None:
        delay = 1.0
        while True:
            try:
                self.poll_once()
                delay = 1.0
            except (TelegramApiError, OSError, ValueError) as error:
                print(f"gateway transport recovery: {type(error).__name__}", flush=True)
                time.sleep(delay)
                delay = min(delay * 2, 60.0)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="Hermes Software Factory Telegram gateway")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    config = load_config(args.config)
    credential_name = str(config.raw.get("telegram", {}).get("token_credential_name", "telegram-token"))
    try:
        token = read_credential(credential_name)
    except (FileNotFoundError, ValueError):
        print("OWNER_ACTION required: missing_credential telegram token", flush=True)
        return 78
    if args.check_only:
        print("gateway credential probe=PASS", flush=True)
        return 0
    state = StateStore(
        config.database_path,
        max_active_workers=config.max_active_workers,
        max_active_products=config.max_active_products,
    )
    try:
        TelegramGateway(config, state, ArtifactStore(config), TelegramApi(token)).run_forever()
    finally:
        state.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
