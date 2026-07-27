"""Small, injectable Telegram Bot API client with secret-free errors."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any


class TelegramApiError(RuntimeError):
    """Raised when Telegram transport or response validation fails."""


RequestHandler = Callable[[str, dict[str, object]], dict[str, Any]]


class TelegramApi:
    def __init__(self, token: str, *, timeout: float = 35.0, request: RequestHandler | None = None) -> None:
        if not token.strip() or any(char.isspace() for char in token):
            raise ValueError("Telegram token must be a non-empty single-line value")
        self._token = token.strip()
        self._timeout = timeout
        self._request_handler = request

    def _request(self, method: str, payload: dict[str, object]) -> dict[str, Any]:
        if self._request_handler is not None:
            result = self._request_handler(method, payload)
            if result.get("ok") is not True:
                raise TelegramApiError("Telegram API returned a failure")
            return result
        url = f"https://api.telegram.org/bot{self._token}/{method}"
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise TelegramApiError(f"Telegram transport failed: {type(error).__name__}") from error
        if not isinstance(decoded, dict) or decoded.get("ok") is not True:
            raise TelegramApiError("Telegram API returned a failure")
        return decoded

    def get_updates(self, offset: int | None) -> list[dict[str, Any]]:
        payload: dict[str, object] = {"timeout": 25, "allowed_updates": ["message"]}
        if offset is not None:
            payload["offset"] = offset
        result = self._request("getUpdates", payload).get("result", [])
        if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
            raise TelegramApiError("Telegram update payload is invalid")
        return result

    def send_message(self, chat_id: str, text: str) -> None:
        if not text.strip() or len(text) > 4096:
            raise ValueError("Telegram message must contain 1..4096 characters")
        self._request("sendMessage", {"chat_id": chat_id, "text": text, "disable_web_page_preview": True})
