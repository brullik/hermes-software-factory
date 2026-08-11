"""Small, injectable Telegram Bot API client with secret-free errors."""

from __future__ import annotations

import json
import mimetypes
import secrets
from collections.abc import Callable
from http import client as http_client
from typing import Any
from urllib.parse import urlsplit


class TelegramApiError(RuntimeError):
    """Raised when Telegram transport or response validation fails."""


RequestHandler = Callable[[str, dict[str, object]], dict[str, Any]]
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class TelegramApi:
    def __init__(
        self,
        token: str,
        *,
        timeout: float = 35.0,
        request: RequestHandler | None = None,
        api_base_url: str = "https://api.telegram.org",
    ) -> None:
        if (
            not token.strip()
            or any(char.isspace() for char in token)
            or any(
                char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:_-"
                for char in token
            )
        ):
            raise ValueError("Telegram token must be a non-empty single-line value")
        if not 0 < timeout <= 60:
            raise ValueError("Telegram timeout must be within 0..60 seconds")
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
        if (
            not (production or isolated)
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("Telegram API base URL is outside the allowlisted boundary")
        self._api_base_url = base
        self._scheme = parsed.scheme
        self._host = str(parsed.hostname)
        self._port = parsed.port

    def _transport(self, path: str, body: bytes, content_type: str) -> dict[str, Any]:
        """Issue one non-redirecting, size-bounded request to the fixed endpoint."""

        connection_type = (
            http_client.HTTPSConnection if self._scheme == "https" else http_client.HTTPConnection
        )
        connection = connection_type(self._host, self._port, timeout=self._timeout)
        try:
            connection.request(
                "POST",
                path,
                body=body,
                headers={"Content-Type": content_type, "Accept": "application/json"},
            )
            response = connection.getresponse()
            length_header = response.getheader("Content-Length")
            if length_header is not None:
                try:
                    content_length = int(length_header)
                except ValueError as error:
                    raise TelegramApiError("Telegram response length is invalid") from error
                if content_length < 0 or content_length > _MAX_RESPONSE_BYTES:
                    raise TelegramApiError("Telegram response is too large")
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(raw) > _MAX_RESPONSE_BYTES:
                raise TelegramApiError("Telegram response is too large")
            # http.client never follows redirects. Treat every non-200 response,
            # including all 3xx values, as a terminal transport failure.
            if response.status != 200:
                raise TelegramApiError("Telegram API returned a failure")
            decoded = json.loads(raw.decode("utf-8"))
        except (
            OSError,
            TimeoutError,
            http_client.HTTPException,
            UnicodeError,
            json.JSONDecodeError,
        ) as error:
            raise TelegramApiError(f"Telegram transport failed: {type(error).__name__}") from error
        finally:
            connection.close()
        if not isinstance(decoded, dict) or decoded.get("ok") is not True:
            raise TelegramApiError("Telegram API returned a failure")
        return decoded

    def _request(self, method: str, payload: dict[str, object]) -> dict[str, Any]:
        if self._request_handler is not None:
            result = self._request_handler(method, payload)
            if result.get("ok") is not True:
                raise TelegramApiError("Telegram API returned a failure")
            return result
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return self._transport(f"/bot{self._token}/{method}", body, "application/json")

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
        self._request(
            "sendMessage", {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
        )

    def send_document(
        self,
        chat_id: str,
        document: bytes,
        *,
        filename: str,
        caption: str = "",
    ) -> None:
        if not document or len(document) > 50 * 1024 * 1024:
            raise ValueError("Telegram document must contain 1..52428800 bytes")
        if not filename or any(character in filename for character in ("/", "\\", "\x00")):
            raise ValueError("Telegram document filename is invalid")
        if len(caption) > 1024:
            raise ValueError("Telegram document caption is too long")
        if self._request_handler is not None:
            self._request(
                "sendDocument",
                {
                    "chat_id": chat_id,
                    "filename": filename,
                    "document_digest": __import__("hashlib").sha256(document).hexdigest(),
                    "caption": caption,
                },
            )
            return
        boundary = f"HermesBoundary{secrets.token_hex(16)}"
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        fields = (("chat_id", chat_id), ("caption", caption))
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
        try:
            self._transport(
                f"/bot{self._token}/sendDocument",
                bytes(body),
                f"multipart/form-data; boundary={boundary}",
            )
        except TelegramApiError as error:
            raise TelegramApiError(
                f"Telegram document transport failed: {type(error).__name__}"
            ) from error
