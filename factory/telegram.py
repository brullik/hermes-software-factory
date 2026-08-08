"""Small, injectable Telegram Bot API client with secret-free errors."""

from __future__ import annotations

import json
import mimetypes
import secrets
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit


class TelegramApiError(RuntimeError):
    """Raised when Telegram transport or response validation fails."""


RequestHandler = Callable[[str, dict[str, object]], dict[str, Any]]


class TelegramApi:
    def __init__(
        self,
        token: str,
        *,
        timeout: float = 35.0,
        request: RequestHandler | None = None,
        api_base_url: str = "https://api.telegram.org",
    ) -> None:
        if not token.strip() or any(char.isspace() for char in token):
            raise ValueError("Telegram token must be a non-empty single-line value")
        self._token = token.strip()
        self._timeout = timeout
        self._request_handler = request
        base = api_base_url.rstrip("/")
        parsed = urlsplit(base)
        production = parsed.scheme == "https" and parsed.hostname == "api.telegram.org"
        isolated = (
            parsed.scheme == "http"
            and parsed.hostname in {"127.0.0.1", "localhost"}
            and parsed.port is not None
        )
        if not (production or isolated) or parsed.username or parsed.password or parsed.query:
            raise ValueError("Telegram API base URL is outside the allowlisted boundary")
        self._api_base_url = base

    def _request(self, method: str, payload: dict[str, object]) -> dict[str, Any]:
        if self._request_handler is not None:
            result = self._request_handler(method, payload)
            if result.get("ok") is not True:
                raise TelegramApiError("Telegram API returned a failure")
            return result
        url = f"{self._api_base_url}/bot{self._token}/{method}"
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

    @staticmethod
    def _message_id(response: dict[str, Any]) -> int:
        result = response.get("result")
        message_id = result.get("message_id") if isinstance(result, dict) else None
        if not isinstance(message_id, int) or message_id < 1:
            raise TelegramApiError("Telegram response lacks a message id")
        return message_id

    def send_message(self, chat_id: str, text: str, *, silent: bool = False) -> int:
        if not text.strip() or len(text) > 4096:
            raise ValueError("Telegram message must contain 1..4096 characters")
        response = self._request(
            "sendMessage",
            {
                "chat_id": chat_id,
                "text": text,
                "disable_web_page_preview": True,
                "disable_notification": silent,
            },
        )
        return self._message_id(response)

    def send_document(
        self,
        chat_id: str,
        document: bytes,
        *,
        filename: str,
        caption: str = "",
        silent: bool = False,
    ) -> int:
        if not document or len(document) > 50 * 1024 * 1024:
            raise ValueError("Telegram document must contain 1..52428800 bytes")
        if not filename or any(character in filename for character in ("/", "\\", "\x00")):
            raise ValueError("Telegram document filename is invalid")
        if len(caption) > 1024:
            raise ValueError("Telegram document caption is too long")
        if self._request_handler is not None:
            response = self._request(
                "sendDocument",
                {
                    "chat_id": chat_id,
                    "filename": filename,
                    "document_digest": __import__("hashlib").sha256(document).hexdigest(),
                    "caption": caption,
                    "disable_notification": silent,
                },
            )
            return self._message_id(response)
        boundary = f"HermesBoundary{secrets.token_hex(16)}"
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        fields = (
            ("chat_id", chat_id),
            ("caption", caption),
            ("disable_notification", "true" if silent else "false"),
        )
        body = bytearray()
        for name, value in fields:
            body.extend(f"--{boundary}\r\n".encode())
            body.extend(
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
            )
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(
            (
                'Content-Disposition: form-data; name="document"; '
                f'filename="{filename}"\r\nContent-Type: {content_type}\r\n\r\n'
            ).encode()
        )
        body.extend(document)
        body.extend(f"\r\n--{boundary}--\r\n".encode())
        request = urllib.request.Request(
            f"{self._api_base_url}/bot{self._token}/sendDocument",
            data=bytes(body),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise TelegramApiError(
                f"Telegram document transport failed: {type(error).__name__}"
            ) from error
        if not isinstance(decoded, dict) or decoded.get("ok") is not True:
            raise TelegramApiError("Telegram API returned a document failure")
        return self._message_id(decoded)

    def delete_message(self, chat_id: str, message_id: int) -> None:
        if not isinstance(message_id, int) or message_id < 1:
            raise ValueError("Telegram message id is invalid")
        self._request("deleteMessage", {"chat_id": chat_id, "message_id": message_id})
