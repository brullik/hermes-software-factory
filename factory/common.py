"""Shared deterministic helpers used by controller adapters."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github_token", re.compile(r"(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}")),
    ("api_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END [^-]+ PRIVATE KEY-----"),
    ),
)


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(10)}"


def slugify(value: str) -> str:
    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9а-яё]+", "-", value, flags=re.IGNORECASE)
    value = re.sub(r"-+", "-", value).strip("-")
    return value[:48] or "product"


def redact_text(value: str) -> tuple[str, list[dict[str, int | str]]]:
    redactions: list[dict[str, int | str]] = []
    redacted = value
    for kind, pattern in SECRET_PATTERNS:
        redacted, count = pattern.subn(f"[REDACTED:{kind}]", redacted)
        if count:
            redactions.append({"type": kind, "count": count})
    return redacted, redactions
