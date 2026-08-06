#!/usr/bin/env python3
"""Accept the exact Golden Product request from the configured Telegram owner."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from factory.artifacts import ArtifactStore
from factory.common import sha256_text, stable_json
from factory.config import load_config
from factory.gateway import read_credential
from factory.intake import IntakeService
from factory.notifications import NotificationOutbox, NotificationRequest
from factory.state import StateStore
from factory.telegram import TelegramApi

GOLDEN_IDEA = (
    "Создай приватный проект hermes-golden-acceptance: небольшой Python 3.12 HTTP-сервис "
    "и CLI-клиент. Сервис должен иметь /healthz, /v1/echo, структурированные логи, "
    "конфигурацию без секретов, unit/integration/E2E, контейнер, документацию, CI, "
    "безопасный staging, rollback и пользовательскую проверку."
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/hermes-factory/golden.yaml"))
    parser.add_argument("--timeout", type=int, default=86400)
    args = parser.parse_args()
    config = load_config(args.config)
    owners = config.allowed_telegram_user_ids
    if len(owners) != 1:
        raise ValueError("Golden intake requires exactly one owner")
    owner = next(iter(owners))
    token = read_credential("candidate-telegram-token")
    api = TelegramApi(
        token,
        api_base_url=str(config.raw.get("telegram", {}).get("api_base_url", "https://api.telegram.org")),
    )
    NotificationOutbox(
        Path("/var/lib/hermes-factory-functional/notifications"),
        attachment_roots=(
            Path("/var/lib/hermes-factory-functional"),
            Path("/var/lib/hermes-factory-verifier"),
        ),
    ).enqueue(
        NotificationRequest(
            request_id="GOLDEN-" + sha256_text(GOLDEN_IDEA)[:32],
            kind="GOLDEN_PRODUCT_STARTED",
            text=(
                "Golden Product lane is ready. Send the exact pre-authorized Golden Product "
                "idea to this bot; it will continue without a Codex message."
            ),
        )
    )
    state = StateStore(
        config.database_path,
        max_active_workers=config.max_active_workers,
        max_active_products=config.max_active_products,
    )
    deadline = time.monotonic() + args.timeout
    try:
        existing = state.list_products()
        if existing:
            if len(existing) != 1 or str(existing[0].get("idea") or "") != GOLDEN_IDEA:
                raise ValueError("Golden intake database contains a different product")
            result = {"product_id": str(existing[0]["product_id"]), "created": False}
        else:
            result = None
            while time.monotonic() < deadline and result is None:
                for update in api.get_updates(None):
                    message = update.get("message")
                    if not isinstance(message, dict):
                        continue
                    sender = message.get("from")
                    text = str(message.get("text") or "").strip()
                    sender_id = str(sender.get("id")) if isinstance(sender, dict) else ""
                    idea = text.removeprefix("/idea ").strip()
                    if sender_id != owner or idea != GOLDEN_IDEA:
                        continue
                    submitted = IntakeService(config, state, ArtifactStore(config)).submit(
                        source="telegram",
                        owner_id=owner,
                        goal_text=GOLDEN_IDEA,
                        delivery_mode="new_repository",
                        repository_name="hermes-golden-acceptance",
                        repository_visibility="private",
                        delivery_profile="DEPLOYED_SERVICE",
                        constraints={
                            "golden_product": True,
                            "python": "3.12",
                            "required_paths": ["/healthz", "/v1/echo"],
                            "observation_seconds": 900,
                            "production_target": "isolated_candidate",
                        },
                        idempotency_key=sha256_text(
                            stable_json(["golden-product-v1", owner, int(update.get("update_id", 0))])
                        ),
                    )
                    result = {"product_id": submitted.product_id, "created": submitted.created}
                    break
                if result is None:
                    time.sleep(2)
            if result is None:
                raise TimeoutError("Golden Telegram intake timed out")
    finally:
        state.close()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
