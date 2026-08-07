"""Durable typed owner approvals and Codex notification outbox.

The store deliberately has no shell, URL fetch, filesystem-operation, or GitHub
execution capability.  It records a one-time typed decision and immutable receipt;
separate trusted code may observe the receipt and re-run its exact state probe.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .common import SECRET_PATTERNS, sha256_text, stable_json, utc_now

ALLOWED_ACTION_TYPES = frozenset(
    {
        "missing_credential",
        "oauth_device_code",
        "two_factor_authentication",
        "captcha",
        "external_account_creation",
        "paid_resource_purchase",
        "dns_action_without_access",
        "legal_decision",
        "unapproved_irreversible_production_action",
    }
)
ALLOWED_NOTIFICATION_KINDS = frozenset(
    {
        "MILESTONE",
        "WAITING_QUOTA",
        "WAITING_OWNER_ACTION",
        "RETRYABLE_FAILURE",
        "TERMINAL_BLOCKED",
        "COMPLETED",
    }
)

_ACTION_ID = re.compile(r"owner-action-[a-f0-9]{20}\Z")
_TARGET = re.compile(r"[a-z][a-z0-9_.-]{0,63}:[A-Za-z0-9_.:-]{1,160}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_CODE = re.compile(r"[A-F0-9]{8}\Z")
_EVENT_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")


class OwnerApprovalRejected(ValueError):
    """Raised when a typed approval fails closed."""


@dataclass(frozen=True)
class CreatedOwnerAction:
    action_id: str
    action_type: str
    target: str
    expected_state_digest: str
    action_digest: str
    nonce: str
    expires_at: str
    confirmation_code: str

    def notification_text(self) -> str:
        return (
            "OWNER_ACTION требуется. "
            f"Тип: {self.action_type}. Цель: {self.target}. "
            f"Подтверждение: /approve {self.action_id} {self.confirmation_code}. "
            "Не отправляйте секреты, OAuth/device code или пароли в Telegram."
        )


@dataclass(frozen=True)
class ApprovalResult:
    response: str
    receipt: dict[str, str] | None
    replayed: bool


@dataclass(frozen=True)
class PendingNotification:
    event_id: str
    kind: str
    text: str


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise OwnerApprovalRejected("invalid timestamp") from error
    if parsed.tzinfo is None:
        raise OwnerApprovalRejected("timestamp must be timezone-aware")
    return parsed.astimezone(UTC)


def _now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise OwnerApprovalRejected("current time must be timezone-aware")
    return current.astimezone(UTC).replace(microsecond=0)


def _rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _validate_digest(value: str, label: str) -> None:
    if _DIGEST.fullmatch(value) is None:
        raise OwnerApprovalRejected(f"{label} must be a lowercase SHA-256 digest")


def _validate_target(value: str) -> None:
    if _TARGET.fullmatch(value) is None:
        raise OwnerApprovalRejected("target is outside the typed target grammar")
    lowered = value.lower()
    if "url:" in lowered or "http:" in lowered or "https:" in lowered or "shell:" in lowered:
        raise OwnerApprovalRejected("target contains a forbidden capability")


def _command_digest(command: str, action_id: str, code: str | None) -> str:
    return sha256_text(stable_json({"action_id": action_id, "code": code, "command": command}))


class CodexOwnerActionStore:
    """SQLite-backed typed approval bridge shared by supervisor and gateway."""

    def __init__(self, path: Path) -> None:
        if not path.is_absolute():
            raise ValueError("owner action database path must be absolute")
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.connection = sqlite3.connect(path, timeout=10.0)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA busy_timeout=10000")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self._initialize()
        try:
            os.chmod(path, 0o660)
        except OSError:
            self.connection.close()
            raise

    def _initialize(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS codex_owner_actions (
                action_id TEXT PRIMARY KEY,
                action_type TEXT NOT NULL,
                target TEXT NOT NULL,
                expected_state_digest TEXT NOT NULL,
                current_state_digest TEXT NOT NULL,
                action_digest TEXT NOT NULL,
                nonce TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                confirmation_code_digest TEXT NOT NULL,
                status TEXT NOT NULL CHECK (
                    status IN ('PENDING', 'USED', 'DENIED', 'EXPIRED', 'STALE')
                ),
                approved_by TEXT,
                approved_at TEXT,
                used_at TEXT,
                receipt_json TEXT,
                receipt_digest TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS codex_processed_updates (
                update_id INTEGER PRIMARY KEY,
                command_digest TEXT NOT NULL,
                response TEXT NOT NULL,
                receipt_json TEXT,
                processed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS codex_notification_outbox (
                event_id TEXT PRIMARY KEY,
                event_key TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                text TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('PENDING', 'DELIVERED')),
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error_kind TEXT,
                created_at TEXT NOT NULL,
                delivered_at TEXT
            );
            """
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def create_action(
        self,
        *,
        action_type: str,
        target: str,
        expected_state_digest: str,
        action_digest: str,
        ttl_seconds: int = 900,
        now: datetime | None = None,
    ) -> CreatedOwnerAction:
        if action_type not in ALLOWED_ACTION_TYPES:
            raise OwnerApprovalRejected("action type is not allowed by owner-action policy")
        _validate_target(target)
        _validate_digest(expected_state_digest, "expected state digest")
        _validate_digest(action_digest, "action digest")
        if not 60 <= ttl_seconds <= 3600:
            raise OwnerApprovalRejected("approval TTL must be between 60 and 3600 seconds")
        created = _now(now)
        action_id = f"owner-action-{secrets.token_hex(10)}"
        nonce = secrets.token_hex(20)
        confirmation_code = secrets.token_hex(4).upper()
        expires_at = _rfc3339(created + timedelta(seconds=ttl_seconds))
        code_digest = self._confirmation_digest(
            action_id,
            action_type,
            target,
            expected_state_digest,
            action_digest,
            nonce,
            expires_at,
            confirmation_code,
        )
        self.connection.execute(
            """
            INSERT INTO codex_owner_actions (
                action_id, action_type, target, expected_state_digest,
                current_state_digest, action_digest, nonce, expires_at,
                confirmation_code_digest, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)
            """,
            (
                action_id,
                action_type,
                target,
                expected_state_digest,
                expected_state_digest,
                action_digest,
                nonce,
                expires_at,
                code_digest,
                _rfc3339(created),
            ),
        )
        self.connection.commit()
        return CreatedOwnerAction(
            action_id=action_id,
            action_type=action_type,
            target=target,
            expected_state_digest=expected_state_digest,
            action_digest=action_digest,
            nonce=nonce,
            expires_at=expires_at,
            confirmation_code=confirmation_code,
        )

    @staticmethod
    def _confirmation_digest(
        action_id: str,
        action_type: str,
        target: str,
        expected_state_digest: str,
        action_digest: str,
        nonce: str,
        expires_at: str,
        confirmation_code: str,
    ) -> str:
        return sha256_text(
            stable_json(
                {
                    "action_digest": action_digest,
                    "action_id": action_id,
                    "action_type": action_type,
                    "confirmation_code": confirmation_code,
                    "expected_state_digest": expected_state_digest,
                    "expires_at": expires_at,
                    "nonce": nonce,
                    "target": target,
                }
            )
        )

    def update_current_state(self, action_id: str, state_digest: str) -> None:
        if _ACTION_ID.fullmatch(action_id) is None:
            raise OwnerApprovalRejected("invalid action id")
        _validate_digest(state_digest, "current state digest")
        result = self.connection.execute(
            "UPDATE codex_owner_actions SET current_state_digest = ? WHERE action_id = ?",
            (state_digest, action_id),
        )
        if result.rowcount != 1:
            raise OwnerApprovalRejected("unknown action id")
        self.connection.commit()

    def pending_actions(self, limit: int = 10) -> list[dict[str, str]]:
        rows = self.connection.execute(
            """
            SELECT action_id, action_type, target, expires_at
            FROM codex_owner_actions WHERE status = 'PENDING'
            ORDER BY created_at, action_id LIMIT ?
            """,
            (max(0, min(limit, 100)),),
        ).fetchall()
        return [dict(row) for row in rows]

    def approve(
        self,
        *,
        action_id: str,
        confirmation_code: str,
        approved_by: str,
        expected_owner_id: str,
        update_id: int,
        now: datetime | None = None,
    ) -> ApprovalResult:
        return self._decide(
            command="approve",
            action_id=action_id,
            confirmation_code=confirmation_code,
            actor=approved_by,
            expected_owner_id=expected_owner_id,
            update_id=update_id,
            now=now,
        )

    def deny(
        self,
        *,
        action_id: str,
        denied_by: str,
        expected_owner_id: str,
        update_id: int,
        now: datetime | None = None,
    ) -> ApprovalResult:
        return self._decide(
            command="deny",
            action_id=action_id,
            confirmation_code=None,
            actor=denied_by,
            expected_owner_id=expected_owner_id,
            update_id=update_id,
            now=now,
        )

    def _decide(
        self,
        *,
        command: str,
        action_id: str,
        confirmation_code: str | None,
        actor: str,
        expected_owner_id: str,
        update_id: int,
        now: datetime | None,
    ) -> ApprovalResult:
        if actor != expected_owner_id or not actor.isdecimal():
            raise OwnerApprovalRejected("wrong Telegram owner")
        if _ACTION_ID.fullmatch(action_id) is None:
            raise OwnerApprovalRejected("invalid action id")
        if command == "approve" and (
            confirmation_code is None or _CODE.fullmatch(confirmation_code) is None
        ):
            raise OwnerApprovalRejected("invalid confirmation code")
        processed_at = _rfc3339(_now(now))
        digest = _command_digest(command, action_id, confirmation_code)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            replay = self.connection.execute(
                "SELECT command_digest, response, receipt_json FROM codex_processed_updates WHERE update_id = ?",
                (update_id,),
            ).fetchone()
            if replay is not None:
                if not hmac.compare_digest(str(replay["command_digest"]), digest):
                    raise OwnerApprovalRejected("conflicting duplicate Telegram update")
                receipt = json.loads(str(replay["receipt_json"])) if replay["receipt_json"] else None
                self.connection.commit()
                return ApprovalResult(str(replay["response"]), receipt, True)

            row = self.connection.execute(
                "SELECT * FROM codex_owner_actions WHERE action_id = ?", (action_id,)
            ).fetchone()
            if row is None:
                raise OwnerApprovalRejected("unknown action id")
            status = str(row["status"])
            if status == "USED" and row["receipt_json"]:
                receipt = json.loads(str(row["receipt_json"]))
                response = (
                    f"OWNER_ACTION уже использован: {action_id}; "
                    f"receipt={receipt['receipt_digest'][:16]}"
                )
                self._record_update(update_id, digest, response, receipt, processed_at)
                self.connection.commit()
                return ApprovalResult(response, receipt, True)
            if status != "PENDING":
                raise OwnerApprovalRejected(f"owner action is not pending: {status}")
            action_type = str(row["action_type"])
            if action_type not in ALLOWED_ACTION_TYPES:
                raise OwnerApprovalRejected("action type is no longer allowed")
            _validate_target(str(row["target"]))
            _validate_digest(str(row["expected_state_digest"]), "expected state digest")
            _validate_digest(str(row["current_state_digest"]), "current state digest")
            _validate_digest(str(row["action_digest"]), "action digest")
            current = _now(now)
            if current > _parse_time(str(row["expires_at"])):
                self.connection.execute(
                    "UPDATE codex_owner_actions SET status = 'EXPIRED' WHERE action_id = ?",
                    (action_id,),
                )
                raise OwnerApprovalRejected("owner action expired")
            if not hmac.compare_digest(
                str(row["expected_state_digest"]), str(row["current_state_digest"])
            ):
                self.connection.execute(
                    "UPDATE codex_owner_actions SET status = 'STALE' WHERE action_id = ?",
                    (action_id,),
                )
                raise OwnerApprovalRejected("owner action state changed")

            if command == "deny":
                response = f"OWNER_ACTION отклонён: {action_id}"
                self.connection.execute(
                    "UPDATE codex_owner_actions SET status = 'DENIED' WHERE action_id = ?",
                    (action_id,),
                )
                self._record_update(update_id, digest, response, None, processed_at)
                self.connection.commit()
                return ApprovalResult(response, None, False)

            assert confirmation_code is not None
            calculated = self._confirmation_digest(
                action_id,
                action_type,
                str(row["target"]),
                str(row["expected_state_digest"]),
                str(row["action_digest"]),
                str(row["nonce"]),
                str(row["expires_at"]),
                confirmation_code,
            )
            if not hmac.compare_digest(str(row["confirmation_code_digest"]), calculated):
                raise OwnerApprovalRejected("confirmation or immutable digest mismatch")
            approved_at = _rfc3339(current)
            receipt_core = {
                "action_id": action_id,
                "action_type": action_type,
                "target": str(row["target"]),
                "expected_state_digest": str(row["expected_state_digest"]),
                "action_digest": str(row["action_digest"]),
                "nonce": str(row["nonce"]),
                "expires_at": str(row["expires_at"]),
                "approved_by": actor,
                "approved_at": approved_at,
            }
            receipt = {**receipt_core, "receipt_digest": sha256_text(stable_json(receipt_core))}
            receipt_json = stable_json(receipt)
            self.connection.execute(
                """
                UPDATE codex_owner_actions
                SET status = 'USED', approved_by = ?, approved_at = ?, used_at = ?,
                    receipt_json = ?, receipt_digest = ?
                WHERE action_id = ? AND status = 'PENDING'
                """,
                (
                    actor,
                    approved_at,
                    approved_at,
                    receipt_json,
                    receipt["receipt_digest"],
                    action_id,
                ),
            )
            response = (
                f"OWNER_ACTION подтверждён и использован один раз: {action_id}; "
                f"receipt={receipt['receipt_digest'][:16]}"
            )
            self._record_update(update_id, digest, response, receipt, processed_at)
            self.connection.commit()
            return ApprovalResult(response, receipt, False)
        except Exception:
            self.connection.rollback()
            raise

    def _record_update(
        self,
        update_id: int,
        command_digest: str,
        response: str,
        receipt: dict[str, str] | None,
        processed_at: str,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO codex_processed_updates (
                update_id, command_digest, response, receipt_json, processed_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                update_id,
                command_digest,
                response,
                stable_json(receipt) if receipt is not None else None,
                processed_at,
            ),
        )

    def enqueue_notification(self, *, event_key: str, kind: str, text: str) -> str:
        if _EVENT_KEY.fullmatch(event_key) is None:
            raise ValueError("notification event key is invalid")
        if kind not in ALLOWED_NOTIFICATION_KINDS:
            raise ValueError("notification kind is not allowlisted")
        if not 1 <= len(text) <= 4096 or any(pattern.search(text) for _, pattern in SECRET_PATTERNS):
            raise ValueError("notification text is invalid or secret-like")
        event_id = f"codex-event-{sha256_text(event_key)[:20]}"
        existing = self.connection.execute(
            "SELECT event_id, kind, text FROM codex_notification_outbox WHERE event_key = ?",
            (event_key,),
        ).fetchone()
        if existing is not None:
            if str(existing["kind"]) != kind or str(existing["text"]) != text:
                raise ValueError("notification event key has conflicting immutable content")
            return str(existing["event_id"])
        self.connection.execute(
            """
            INSERT INTO codex_notification_outbox (
                event_id, event_key, kind, text, status, created_at
            ) VALUES (?, ?, ?, ?, 'PENDING', ?)
            """,
            (event_id, event_key, kind, text, utc_now()),
        )
        self.connection.commit()
        return event_id

    def pending_notifications(self, limit: int = 10) -> list[PendingNotification]:
        rows = self.connection.execute(
            """
            SELECT event_id, kind, text FROM codex_notification_outbox
            WHERE status = 'PENDING' ORDER BY created_at, event_id LIMIT ?
            """,
            (max(0, min(limit, 100)),),
        ).fetchall()
        return [
            PendingNotification(str(row["event_id"]), str(row["kind"]), str(row["text"]))
            for row in rows
        ]

    def mark_notification_delivered(self, event_id: str) -> None:
        result = self.connection.execute(
            """
            UPDATE codex_notification_outbox
            SET status = 'DELIVERED', attempts = attempts + 1,
                last_error_kind = NULL, delivered_at = ?
            WHERE event_id = ? AND status = 'PENDING'
            """,
            (utc_now(), event_id),
        )
        if result.rowcount != 1:
            raise ValueError("notification is not pending")
        self.connection.commit()

    def mark_notification_failed(self, event_id: str, error_kind: str) -> None:
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", error_kind) is None:
            error_kind = "TransportError"
        self.connection.execute(
            """
            UPDATE codex_notification_outbox
            SET attempts = attempts + 1, last_error_kind = ?
            WHERE event_id = ? AND status = 'PENDING'
            """,
            (error_kind, event_id),
        )
        self.connection.commit()

    def action_receipt(self, action_id: str) -> dict[str, str] | None:
        row = self.connection.execute(
            "SELECT receipt_json FROM codex_owner_actions WHERE action_id = ?", (action_id,)
        ).fetchone()
        if row is None or row["receipt_json"] is None:
            return None
        value: Any = json.loads(str(row["receipt_json"]))
        if not isinstance(value, dict) or not all(
            isinstance(key, str) and isinstance(item, str) for key, item in value.items()
        ):
            raise ValueError("stored owner action receipt is invalid")
        return value
