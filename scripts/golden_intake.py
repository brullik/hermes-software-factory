#!/usr/bin/env python3
"""Accept the exact Golden Product request from the configured Telegram owner."""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from factory.artifacts import ArtifactStore
from factory.common import sha256_text, stable_json, utc_now
from factory.config import load_config
from factory.gateway import read_credential
from factory.intake import IntakeService
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
    parser.add_argument(
        "--deadline-file",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional/golden/intake-deadline.json"),
    )
    parser.add_argument(
        "--evidence-file",
        type=Path,
        default=None,
    )
    args = parser.parse_args()
    deadline_value = json.loads(args.deadline_file.read_text(encoding="utf-8"))
    if not isinstance(deadline_value, dict):
        raise TypeError("Golden intake durable deadline is invalid")
    deadline_digest = str(deadline_value.pop("deadline_digest", ""))
    expected_deadline_keys = {
        "schema_version",
        "epoch_id",
        "phase_id",
        "attempt",
        "started_at",
        "budget_seconds",
        "deadline_epoch",
    }
    if (
        set(deadline_value) != expected_deadline_keys
        or deadline_value.get("schema_version") != "1.0"
        or deadline_value.get("phase_id") != "golden-intake"
        or deadline_value.get("attempt") != 1
        or int(deadline_value.get("budget_seconds", 0)) != 86400
        or deadline_digest != sha256_text(stable_json(deadline_value))
    ):
        raise ValueError("Golden intake durable deadline differs")
    evidence_file = args.evidence_file or (
        args.deadline_file.parent
        / str(deadline_value["epoch_id"])
        / "intake-evidence.json"
    )
    remaining = int(deadline_value["deadline_epoch"]) - int(time.time())
    if remaining <= 0:
        raise TimeoutError("Golden Telegram intake durable deadline expired")
    timeout = min(args.timeout, remaining)
    config = load_config(args.config)
    owners = config.allowed_telegram_user_ids
    if len(owners) != 1:
        raise ValueError("Golden intake requires exactly one owner")
    owner = next(iter(owners))
    token = read_credential("candidate-telegram-token")
    api = TelegramApi(
        token,
        api_base_url=str(
            config.raw.get("telegram", {}).get("api_base_url", "https://api.telegram.org")
        ),
    )
    state = StateStore(
        config.database_path,
        max_active_workers=config.max_active_workers,
        max_active_products=config.max_active_products,
    )
    deadline = time.monotonic() + timeout
    try:
        existing = state.list_products()
        if existing:
            if len(existing) != 1 or str(existing[0].get("idea") or "") != GOLDEN_IDEA:
                raise ValueError("Golden intake database contains a different product")
            result = {
                "product_id": str(existing[0]["product_id"]),
                "created": False,
                "intake_receipt_digest": str(existing[0]["idempotency_key"]),
            }
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
                    intake_receipt_digest = sha256_text(
                        stable_json(["golden-product-v1", owner, int(update.get("update_id", 0))])
                    )
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
                        idempotency_key=intake_receipt_digest,
                    )
                    result = {
                        "product_id": submitted.product_id,
                        "created": submitted.created,
                        "intake_receipt_digest": intake_receipt_digest,
                    }
                    break
                if result is None:
                    time.sleep(2)
            if result is None:
                raise TimeoutError("Golden Telegram intake timed out")
    finally:
        state.close()
    evidence = {
        "schema_version": "1.0",
        "phase_id": "golden-intake",
        "status": "PASS",
        "product_id": str(result["product_id"]),
        "intake_source": "telegram_owner",
        "intake_receipt_digest": str(result["intake_receipt_digest"]),
        "accepted_at": utc_now(),
    }
    encoded = stable_json(evidence) + "\n"
    evidence_file.parent.mkdir(parents=True, exist_ok=True)
    if evidence_file.exists():
        if evidence_file.is_symlink() or not evidence_file.is_file():
            raise ValueError("Golden intake evidence path is unsafe")
        previous = json.loads(evidence_file.read_text(encoding="utf-8"))
        if (
            not isinstance(previous, dict)
            or previous.get("product_id") != evidence["product_id"]
            or previous.get("intake_receipt_digest") != evidence["intake_receipt_digest"]
            or previous.get("intake_source") != "telegram_owner"
        ):
            raise ValueError("Golden intake immutable evidence conflicts")
    else:
        temporary = evidence_file.with_name(f".{evidence_file.name}.{os.getpid()}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(evidence_file)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
