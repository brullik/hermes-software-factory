"""Idempotent, redacting intake service."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .artifacts import ArtifactStore
from .capabilities import CapabilityBroker
from .common import new_id, redact_text, sha256_text, slugify, utc_now
from .config import FactoryConfig
from .state import StateStore
from .worker import ensure_initial_product_task


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
    def __init__(
        self,
        config: FactoryConfig,
        state: StateStore,
        artifacts: ArtifactStore,
        *,
        capability_broker: CapabilityBroker | None = None,
    ) -> None:
        self.config = config
        self.state = state
        self.artifacts = artifacts
        self.capability_broker = capability_broker or CapabilityBroker(
            config,
            state,
        )

    def submit(
        self,
        *,
        source: str,
        owner_id: str,
        idea: str | None = None,
        goal_text: str | None = None,
        delivery_mode: str | None = None,
        repository_url: str | None = None,
        repository_name: str | None = None,
        repository_visibility: str = "private",
        constraints: Mapping[str, Any] | None = None,
        owner_defaults_ref: str | None = None,
        idempotency_key: str | None = None,
        attachments: Iterable[dict[str, Any]] = (),
    ) -> IntakeResult:
        legacy_boundary = (
            goal_text is None
            and idea is not None
            and delivery_mode is None
            and repository_url is None
            and repository_name is None
            and constraints is None
            and owner_defaults_ref is None
            and repository_visibility == "private"
        )
        if source not in {"telegram", "github", "cli"}:
            raise IntakeRejected(f"Unsupported intake source: {source}")
        if source == "telegram" and str(owner_id) not in self.config.allowed_telegram_user_ids:
            raise IntakeRejected("Telegram owner is not on the allowlist")
        if goal_text is not None and idea is not None and goal_text.strip() != idea.strip():
            raise IntakeRejected("goal_text and deprecated idea disagree")
        raw_goal = goal_text if goal_text is not None else idea
        if not isinstance(raw_goal, str):
            raise IntakeRejected("goal_text is required")
        clean_goal = raw_goal.strip()
        if len(clean_goal) < 3:
            raise IntakeRejected("Goal must not be empty")
        if len(clean_goal) > self.config.max_idea_chars:
            raise IntakeRejected("Goal is too long")
        selected_mode = delivery_mode or (
            "existing_repository" if repository_url is not None else "new_repository"
        )
        if selected_mode not in {"new_repository", "existing_repository"}:
            raise IntakeRejected("delivery_mode is invalid")
        if selected_mode == "existing_repository":
            if not isinstance(repository_url, str) or not re.fullmatch(
                r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?",
                repository_url.strip(),
            ):
                raise IntakeRejected("existing_repository requires a GitHub repository_url")
            repository_url = repository_url.strip()
        elif repository_url is not None:
            raise IntakeRejected("new_repository does not accept repository_url")
        if repository_visibility not in {"private", "public"}:
            raise IntakeRejected("repository_visibility is invalid")
        if repository_name is not None:
            repository_name = repository_name.strip()
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?", repository_name):
                raise IntakeRejected("repository_name is invalid")
        clean_constraints = dict(constraints or {})
        if any(not isinstance(key, str) for key in clean_constraints):
            raise IntakeRejected("constraint keys must be strings")
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
        raw_key = idempotency_key or (
            sha256_text(f"{source}:{owner_id}:{clean_goal}")
            if legacy_boundary
            else sha256_text(
                f"{source}:{owner_id}:{clean_goal}:{selected_mode}:"
                f"{repository_url or ''}:{repository_name or ''}"
            )
        )
        if not isinstance(raw_key, str) or not raw_key.strip():
            raise IntakeRejected("Idempotency key must not be empty")
        # Never persist a caller-controlled idempotency token.  The digest is
        # stable across retries and cannot leak a credential into SQLite/evidence.
        key = sha256_text(raw_key.strip())
        redacted_goal, redactions = redact_text(clean_goal)
        constraints_text, constraint_redactions = redact_text(
            json.dumps(clean_constraints, ensure_ascii=False, sort_keys=True)
        )
        clean_constraints = json.loads(constraints_text)
        redactions.extend(constraint_redactions)
        product_id = f"{slugify(redacted_goal)}-{sha256_text(key)[:8]}"
        intake_ref = f"evidence/intake-{product_id}.json"
        constraints_ref = (
            f"inline-sha256:{sha256_text(constraints_text)}"
            if clean_constraints
            else None
        )
        if legacy_boundary:
            row, created = self.state.create_product(
                product_id=product_id,
                owner_id=str(owner_id),
                source=source,
                idea=redacted_goal,
                idempotency_key=key,
                rate_limit=(
                    self.config.intake_rate_limit_requests,
                    self.config.intake_rate_limit_window_seconds,
                ),
            )
        else:
            row, created = self.state.create_product_v2(
                product_id=product_id,
                owner_id=str(owner_id),
                source=source,
                goal_text=redacted_goal,
                delivery_mode=selected_mode,
                repository_url=repository_url,
                repository_name=repository_name,
                repository_visibility=repository_visibility,
                root_goal_ref=intake_ref,
                constraints_ref=constraints_ref,
                owner_defaults_ref=owner_defaults_ref,
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
        artifact: dict[str, Any] = {
            "schema_version": "2.0",
            "artifact_id": artifact_id,
            "product_id": product_id,
            "created_at": utc_now(),
            "source": source,
            "owner_id": str(owner_id),
            "goal_text": redacted_goal,
            "idea": redacted_goal,
            "delivery_mode": selected_mode,
            "repository_url": repository_url,
            "repository_name": repository_name,
            "repository_visibility": repository_visibility,
            "constraints": clean_constraints,
            "idempotency_key": key,
            "correlation_id": correlation_id,
            "attachments": normalized_attachments,
            "redactions": redactions,
            "language": "ru",
        }
        schema_name = "idea-intake-v2.schema.json"
        if legacy_boundary:
            artifact = {
                "schema_version": "1.0",
                "artifact_id": artifact_id,
                "product_id": product_id,
                "created_at": artifact["created_at"],
                "source": source,
                "owner_id": str(owner_id),
                "idea": redacted_goal,
                "idempotency_key": key,
                "correlation_id": correlation_id,
                "attachments": normalized_attachments,
                "redactions": redactions,
                "language": "ru",
            }
            schema_name = "idea-intake.schema.json"
        path = self.artifacts.write(
            schema_name, artifact, filename=f"intake-{product_id}.json"
        )
        ensure_initial_product_task(self.config, self.state, self.artifacts, product_id)
        self.capability_broker.preflight_product(product_id)
        return IntakeResult(product_id, str(path), True, correlation_id)
