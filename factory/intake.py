"""Idempotent, redacting intake service."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .artifacts import ArtifactStore
from .common import new_id, redact_text, sha256_text, slugify, utc_now
from .config import FactoryConfig
from .state import StateStore


class IntakeRejected(ValueError):
    """Raised when intake fails an allowlist or input invariant."""


def _validate_attachments(
    attachments: Iterable[dict[str, Any]],
    *,
    max_attachments: int,
) -> list[dict[str, Any]]:
    values = list(attachments)
    if len(values) > max_attachments:
        raise IntakeRejected("too many attachments")
    validated: list[dict[str, Any]] = []
    for item in values:
        if not isinstance(item, Mapping):
            raise IntakeRejected("attachment metadata must be an object")
        name = item.get("name")
        digest = item.get("digest")
        if (
            not isinstance(name, str)
            or not name.strip()
            or len(name) > 255
            or "/" in name
            or "\\" in name
            or name in {".", ".."}
        ):
            raise IntakeRejected("attachment name is invalid")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise IntakeRejected("attachment digest must be a lowercase SHA-256")
        media_type = item.get("media_type")
        if media_type is not None and (not isinstance(media_type, str) or len(media_type) > 255):
            raise IntakeRejected("attachment media_type is invalid")
        entry: dict[str, Any] = {"name": name, "digest": digest}
        if media_type is not None:
            entry["media_type"] = media_type
        validated.append(entry)
    return validated


@dataclass(frozen=True)
class IntakeResult:
    product_id: str
    artifact_path: str
    created: bool
    correlation_id: str | None = None


class IntakeService:
    def __init__(self, config: FactoryConfig, state: StateStore, artifacts: ArtifactStore) -> None:
        self.config = config
        self.state = state
        self.artifacts = artifacts

    def submit(
        self,
        *,
        source: str,
        owner_id: str,
        idea: str,
        idempotency_key: str | None = None,
        attachments: Iterable[dict[str, Any]] = (),
    ) -> IntakeResult:
        if source not in {"telegram", "github", "cli"}:
            raise IntakeRejected(f"Unsupported intake source: {source}")
        if source == "telegram" and str(owner_id) not in self.config.allowed_telegram_user_ids:
            raise IntakeRejected("Telegram owner is not on the allowlist")
        clean_idea = idea.strip()
        if len(clean_idea) < 3:
            raise IntakeRejected("Idea must not be empty")
        if len(clean_idea) > self.config.max_idea_chars:
            raise IntakeRejected("Idea is too long")
        if not isinstance(owner_id, str) or not owner_id.strip() or any(char in owner_id for char in "\r\n\x00"):
            raise IntakeRejected("Owner id is invalid")
        if len(owner_id) > 256:
            raise IntakeRejected("Owner id is too long")
        try:
            normalized_attachments = _validate_attachments(
                attachments,
                max_attachments=self.config.max_attachments,
            )
        except TypeError as error:
            raise IntakeRejected("attachments must be an iterable of objects") from error
        raw_key = idempotency_key or sha256_text(f"{source}:{owner_id}:{clean_idea}")
        if not isinstance(raw_key, str) or not raw_key.strip():
            raise IntakeRejected("Idempotency key must not be empty")
        # Never persist a caller-controlled idempotency token.  The digest is
        # stable across retries and cannot leak a credential into SQLite/evidence.
        key = sha256_text(raw_key.strip())
        redacted_idea, redactions = redact_text(clean_idea)
        product_id = f"{slugify(redacted_idea)}-{sha256_text(key)[:8]}"
        row, created = self.state.create_product(
            product_id=product_id,
            owner_id=str(owner_id),
            source=source,
            idea=redacted_idea,
            idempotency_key=key,
            rate_limit=(
                self.config.intake_rate_limit_requests,
                self.config.intake_rate_limit_window_seconds,
            ),
        )
        if not created:
            return IntakeResult(
                row["product_id"],
                f"intake-{row['product_id']}.json",
                False,
                f"corr-{sha256_text(key)[:16]}",
            )
        artifact_id = new_id("intake")
        correlation_id = f"corr-{sha256_text(key)[:16]}"
        artifact = {
            "schema_version": "1.0",
            "artifact_id": artifact_id,
            "product_id": product_id,
            "created_at": utc_now(),
            "source": source,
            "owner_id": str(owner_id),
            "idea": redacted_idea,
            "idempotency_key": key,
            "correlation_id": correlation_id,
            "attachments": normalized_attachments,
            "redactions": redactions,
            "language": "ru",
        }
        path = self.artifacts.write("idea-intake.schema.json", artifact, filename=f"intake-{product_id}.json")
        return IntakeResult(product_id, str(path), True, correlation_id)
