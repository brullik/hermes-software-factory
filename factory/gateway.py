"""Fail-closed Telegram gateway with durable update idempotency."""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path
from typing import Any

from .artifacts import ArtifactStore
from .config import FactoryConfig, load_config
from .gateway_commands import GatewayCommandError, parse_command
from .intake import IntakeService
from .state import StateStore
from .telegram import TelegramApi, TelegramApiError
from .workflow import WorkflowEngine


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
    ) -> None:
        self.config = config
        self.state = state
        self.artifacts = artifacts
        self.api = api
        self.offset_path = offset_path or (config.state_dir / "telegram-offset")
        self.offset_path.parent.mkdir(parents=True, exist_ok=True)

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
        actions = sorted(self.config.evidence_dir.glob("owner-action-*.json"))
        if not actions:
            return "Ожидающих OWNER_ACTION нет."
        return "OWNER_ACTION:\n" + "\n".join(f"- {path.name}" for path in actions[:10])

    @staticmethod
    def _product_id(argument: str | None) -> str:
        if argument is None or len(argument.split()) != 1:
            raise GatewayCommandError("Укажите один product_id")
        return argument

    def _dispatch(self, command: str, argument: str | None, owner_id: int, update_id: int) -> str:
        if command == "help":
            return "/idea <текст>, /status, /projects, /pause <product>, /resume <product>, /cancel <product>, /owner_action"
        if command in {"status", "projects"}:
            return self._products_text()
        if command == "owner_action":
            return self._owner_actions_text()
        if command == "idea":
            assert argument is not None
            result = IntakeService(self.config, self.state, self.artifacts).submit(
                source="telegram",
                owner_id=str(owner_id),
                idea=argument,
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
            return False
        command_text = raw_text if raw_text.lstrip().startswith("/") else f"/idea {raw_text}"
        try:
            parsed = parse_command(command_text)
            response = self._dispatch(parsed.name, parsed.argument, owner_id, update_id)
        except (GatewayCommandError, ValueError, KeyError) as error:
            response = f"Команда отклонена: {error}"
        self.api.send_message(chat_id, response)
        return True

    def poll_once(self) -> int:
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
