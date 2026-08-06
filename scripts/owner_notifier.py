#!/usr/bin/env python3
"""Deliver typed functional-factory notifications through Telegram."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from factory.config import load_config
from factory.gateway import read_credential
from factory.notifications import NotificationError, NotificationOutbox, OwnerNotifier
from factory.telegram import TelegramApi, TelegramApiError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/hermes-factory/config.yaml"))
    parser.add_argument(
        "--outbox", type=Path, default=Path("/var/lib/hermes-factory-functional/notifications")
    )
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        owners = sorted(config.allowed_telegram_user_ids)
        if len(owners) != 1:
            raise NotificationError("owner notifier requires exactly one allowed owner")
        credential_name = str(
            config.raw.get("telegram", {}).get("token_credential_name", "telegram-token")
        )
        token = read_credential(credential_name)
        outbox = NotificationOutbox(
            args.outbox,
            attachment_roots=(
                Path("/var/lib/hermes-factory-functional"),
                Path("/var/lib/hermes-factory-verifier"),
            ),
        )
        delivered = OwnerNotifier(
            outbox,
            TelegramApi(
                token,
                api_base_url=str(
                    config.raw.get("telegram", {}).get(
                        "api_base_url", "https://api.telegram.org"
                    )
                ),
            ),
            chat_id=owners[0],
        ).run_once()
    except (OSError, ValueError, KeyError, NotificationError, TelegramApiError) as error:
        print(json.dumps({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    print(json.dumps({"status": "PASS", "delivered": delivered}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
