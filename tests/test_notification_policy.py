from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from factory.common import sha256_file
from factory.notifications import (
    NotificationError,
    NotificationOutbox,
    NotificationRequest,
    OwnerNotifier,
)
from factory.telegram import TelegramApi, TelegramApiError


def test_qualification_delivery_probes_are_silent_and_ephemeral(tmp_path: Path) -> None:
    document = tmp_path / "probe.json"
    document.write_text('{"status":"PASS"}\n', encoding="utf-8")
    calls: list[tuple[str, dict[str, object]]] = []

    def request(method: str, payload: dict[str, object]) -> dict[str, Any]:
        calls.append((method, payload))
        if method == "deleteMessage":
            return {"ok": True, "result": True}
        return {"ok": True, "result": {"message_id": len(calls)}}

    outbox = NotificationOutbox(tmp_path / "notifications", attachment_roots=(tmp_path,))
    outbox.enqueue(
        NotificationRequest(
            request_id="Q65-TEXT-PROBE-1",
            kind="Q6_5_TEXT_PROBE",
            text="Hermes bounded text delivery proof.",
        )
    )
    outbox.enqueue(
        NotificationRequest(
            request_id="Q65-DOCUMENT-PROBE-1",
            kind="Q6_5_DOCUMENT_PROBE",
            text="Hermes bounded document delivery proof.",
            document_path=str(document),
            document_digest=sha256_file(document),
        )
    )
    notifier = OwnerNotifier(
        outbox,
        TelegramApi("fixture-token", request=request),
        chat_id="42",
    )
    assert notifier.run_once() == 2
    assert [method for method, _ in calls] == [
        "sendDocument",
        "deleteMessage",
        "sendMessage",
        "deleteMessage",
    ]
    assert calls[0][1]["disable_notification"] is True
    assert calls[2][1]["disable_notification"] is True


def test_ephemeral_delete_retry_never_resends(tmp_path: Path) -> None:
    calls: list[str] = []
    delete_attempts = 0

    def request(method: str, payload: dict[str, object]) -> dict[str, Any]:
        nonlocal delete_attempts
        del payload
        calls.append(method)
        if method == "deleteMessage":
            delete_attempts += 1
            if delete_attempts == 1:
                return {"ok": False}
            return {"ok": True, "result": True}
        return {"ok": True, "result": {"message_id": 77}}

    outbox = NotificationOutbox(tmp_path / "notifications", attachment_roots=(tmp_path,))
    outbox.enqueue(
        NotificationRequest(
            request_id="Q65-TEXT-PROBE-RETRY",
            kind="Q6_5_TEXT_PROBE",
            text="Hermes bounded text delivery retry proof.",
        )
    )
    notifier = OwnerNotifier(
        outbox,
        TelegramApi("fixture-token", request=request),
        chat_id="42",
    )
    try:
        notifier.run_once()
    except TelegramApiError:
        pass
    assert notifier.run_once() == 1
    assert calls == ["sendMessage", "deleteMessage", "deleteMessage"]


def test_dispatching_restart_fails_closed_without_duplicate_send(tmp_path: Path) -> None:
    calls: list[str] = []

    def request(method: str, payload: dict[str, object]) -> dict[str, Any]:
        del payload
        calls.append(method)
        return {"ok": True, "result": {"message_id": 88}}

    outbox = NotificationOutbox(tmp_path / "notifications", attachment_roots=(tmp_path,))
    request_value = NotificationRequest(
        request_id="OWNER-ACTION-UNCERTAIN-1",
        kind="OWNER_ACTION_REQUIRED",
        text="Perform the single authorized external action.",
    )
    queued = outbox.enqueue(request_value)
    outbox.pending.mkdir(parents=True)
    OwnerNotifier._write_pending(
        outbox.pending / queued.name,
        {
            "schema_version": "1.0",
            "request_id": request_value.request_id,
            "kind": request_value.kind,
            "phase": "DISPATCHING",
            "message_id": None,
        },
    )
    notifier = OwnerNotifier(
        outbox,
        TelegramApi("fixture-token", request=request),
        chat_id="42",
    )
    assert notifier.run_once() == 0
    assert calls == []
    receipt = json.loads((outbox.receipts / queued.name).read_text(encoding="utf-8"))
    assert receipt["status"] == "DELIVERY_UNCERTAIN"


def test_intermediate_owner_notifications_are_rejected_and_legacy_rows_retired(
    tmp_path: Path,
) -> None:
    outbox = NotificationOutbox(tmp_path / "notifications", attachment_roots=(tmp_path,))
    request = NotificationRequest(
        request_id="LEGACY-PROGRESS-0001",
        kind="PRE_Q8_PROGRESS",
        text="Intermediate progress must remain internal.",
    )
    with pytest.raises(NotificationError, match="intermediate owner notification"):
        outbox.enqueue(request)
    outbox.outbox.mkdir(parents=True)
    legacy = outbox.outbox / f"{request.request_id}.json"
    legacy.write_text(
        json.dumps(request.as_dict(), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    calls: list[str] = []

    def transport(method: str, payload: dict[str, object]) -> dict[str, Any]:
        del payload
        calls.append(method)
        return {"ok": True, "result": {"message_id": 1}}

    notifier = OwnerNotifier(
        outbox,
        TelegramApi("fixture-token", request=transport),
        chat_id="42",
    )
    assert notifier.run_once() == 0
    assert calls == []
    assert not legacy.exists()
    assert (outbox.retired / legacy.name).is_file()
