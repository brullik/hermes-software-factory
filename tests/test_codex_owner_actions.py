from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from factory.codex_owner_actions import CodexOwnerActionStore, OwnerApprovalRejected
from factory.common import sha256_text
from factory.gateway import TelegramGateway
from factory.gateway_commands import GatewayCommandError, parse_command
from factory.telegram import TelegramApiError

OWNER_ID = "239925384"


class FlakyTelegramApi:
    def __init__(self) -> None:
        self.calls = 0
        self.delivered: list[tuple[str, str]] = []

    def send_message(self, chat_id: str, text: str) -> None:
        self.calls += 1
        if self.calls == 1:
            raise TelegramApiError("synthetic transport failure")
        self.delivered.append((chat_id, text))


class CodexOwnerActionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name).resolve()
        self.root = root
        self.store = CodexOwnerActionStore(root / "actions.sqlite3")
        self.now = datetime(2026, 8, 7, 20, 0, tzinfo=UTC)

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def create(self, *, ttl_seconds: int = 900) -> Any:
        return self.store.create_action(
            action_type="legal_decision",
            target="commissioning:codex-vps-typed-approval-v1",
            expected_state_digest=sha256_text("pending-safe-probe"),
            action_digest=sha256_text("record-harmless-typed-approval"),
            ttl_seconds=ttl_seconds,
            now=self.now,
        )

    def test_typed_approval_is_used_once_with_immutable_receipt(self) -> None:
        action = self.create()
        result = self.store.approve(
            action_id=action.action_id,
            confirmation_code=action.confirmation_code,
            approved_by=OWNER_ID,
            expected_owner_id=OWNER_ID,
            update_id=100,
            now=self.now + timedelta(seconds=1),
        )
        assert result.receipt is not None
        self.assertFalse(result.replayed)
        self.assertEqual(result.receipt["approved_by"], OWNER_ID)
        self.assertEqual(result.receipt["action_digest"], action.action_digest)
        self.assertEqual(self.store.action_receipt(action.action_id), result.receipt)

        duplicate_update = self.store.approve(
            action_id=action.action_id,
            confirmation_code=action.confirmation_code,
            approved_by=OWNER_ID,
            expected_owner_id=OWNER_ID,
            update_id=100,
            now=self.now + timedelta(seconds=2),
        )
        later_replay = self.store.approve(
            action_id=action.action_id,
            confirmation_code=action.confirmation_code,
            approved_by=OWNER_ID,
            expected_owner_id=OWNER_ID,
            update_id=101,
            now=self.now + timedelta(seconds=2),
        )
        self.assertTrue(duplicate_update.replayed)
        self.assertTrue(later_replay.replayed)
        self.assertEqual(duplicate_update.receipt, result.receipt)
        self.assertEqual(later_replay.receipt, result.receipt)

    def test_wrong_owner_is_rejected(self) -> None:
        action = self.create()
        with self.assertRaisesRegex(OwnerApprovalRejected, "wrong Telegram owner"):
            self.store.approve(
                action_id=action.action_id,
                confirmation_code=action.confirmation_code,
                approved_by="42",
                expected_owner_id=OWNER_ID,
                update_id=200,
                now=self.now,
            )

    def test_expired_action_is_rejected(self) -> None:
        action = self.create(ttl_seconds=60)
        with self.assertRaisesRegex(OwnerApprovalRejected, "expired"):
            self.store.approve(
                action_id=action.action_id,
                confirmation_code=action.confirmation_code,
                approved_by=OWNER_ID,
                expected_owner_id=OWNER_ID,
                update_id=300,
                now=self.now + timedelta(seconds=61),
            )

    def test_changed_state_is_stale(self) -> None:
        action = self.create()
        self.store.update_current_state(action.action_id, sha256_text("state-changed"))
        with self.assertRaisesRegex(OwnerApprovalRejected, "state changed"):
            self.store.approve(
                action_id=action.action_id,
                confirmation_code=action.confirmation_code,
                approved_by=OWNER_ID,
                expected_owner_id=OWNER_ID,
                update_id=400,
                now=self.now,
            )

    def test_altered_action_digest_invalidates_confirmation(self) -> None:
        action = self.create()
        self.store.connection.execute(
            "UPDATE codex_owner_actions SET action_digest = ? WHERE action_id = ?",
            (sha256_text("altered-action"), action.action_id),
        )
        self.store.connection.commit()
        with self.assertRaisesRegex(OwnerApprovalRejected, "immutable digest mismatch"):
            self.store.approve(
                action_id=action.action_id,
                confirmation_code=action.confirmation_code,
                approved_by=OWNER_ID,
                expected_owner_id=OWNER_ID,
                update_id=500,
                now=self.now,
            )

    def test_conflicting_duplicate_update_is_rejected(self) -> None:
        action = self.create()
        self.store.deny(
            action_id=action.action_id,
            denied_by=OWNER_ID,
            expected_owner_id=OWNER_ID,
            update_id=600,
            now=self.now,
        )
        with self.assertRaisesRegex(OwnerApprovalRejected, "conflicting duplicate"):
            self.store.approve(
                action_id=action.action_id,
                confirmation_code=action.confirmation_code,
                approved_by=OWNER_ID,
                expected_owner_id=OWNER_ID,
                update_id=600,
                now=self.now,
            )

    def test_notification_transport_retry_does_not_duplicate_outbox_event(self) -> None:
        event_id = self.store.enqueue_notification(
            event_key="goal-1:milestone:commissioning-probe",
            kind="MILESTONE",
            text="Codex VPS commissioning milestone reached.",
        )
        duplicate_id = self.store.enqueue_notification(
            event_key="goal-1:milestone:commissioning-probe",
            kind="MILESTONE",
            text="Codex VPS commissioning milestone reached.",
        )
        self.assertEqual(event_id, duplicate_id)
        api = FlakyTelegramApi()
        config = SimpleNamespace(
            state_dir=self.root / "gateway-state",
            allowed_telegram_user_ids={OWNER_ID},
        )
        gateway = TelegramGateway(
            config,  # type: ignore[arg-type]
            SimpleNamespace(),  # type: ignore[arg-type]
            SimpleNamespace(),  # type: ignore[arg-type]
            api,  # type: ignore[arg-type]
            codex_action_store=self.store,
        )
        self.assertEqual(gateway.deliver_codex_outbox(), 0)
        self.assertEqual(len(self.store.pending_notifications()), 1)
        self.assertEqual(gateway.deliver_codex_outbox(), 1)
        self.assertEqual(self.store.pending_notifications(), [])
        self.assertEqual(api.delivered, [(OWNER_ID, "Codex VPS commissioning milestone reached.")])

    def test_database_mode_is_group_private(self) -> None:
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o660)
        with sqlite3.connect(self.store.path) as connection:
            count = connection.execute("SELECT COUNT(*) FROM codex_owner_actions").fetchone()[0]
        self.assertEqual(count, 0)

    def test_existing_shared_mode_does_not_require_owner_chmod(self) -> None:
        path = self.store.path
        self.store.close()
        with patch(
            "factory.codex_owner_actions.os.chmod",
            side_effect=PermissionError("not file owner"),
        ) as chmod:
            self.store = CodexOwnerActionStore(path)
        chmod.assert_not_called()
        self.assertEqual(path.stat().st_mode & 0o777, 0o660)
        self.assertEqual(self.store.pending_notifications(), [])

    def test_gateway_parser_accepts_only_typed_approval_arguments(self) -> None:
        action_id = "owner-action-0123456789abcdef0123"
        self.assertEqual(parse_command(f"/approve {action_id} ABCDEF01").name, "approve")
        self.assertEqual(parse_command(f"/deny {action_id}").name, "deny")
        for text in (
            f"/approve {action_id} abcdef01",
            f"/approve {action_id} ABCDEF01 extra",
            "/approve /tmp/action ABCDEF01",
            "/approve https://example.test ABCDEF01",
            "/deny {\"action_id\":\"x\"}",
        ):
            with self.subTest(text=text), self.assertRaises(GatewayCommandError):
                parse_command(text)


if __name__ == "__main__":
    unittest.main()
