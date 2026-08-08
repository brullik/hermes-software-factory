"""Secret-free durable owner notifications for functional qualification."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .common import redact_text, sha256_file, sha256_text, stable_json, utc_now
from .telegram import TelegramApi


class NotificationError(RuntimeError):
    """A notification violated the typed outbox contract."""


NOTIFICATION_KINDS: Final[frozenset[str]] = frozenset(
    {
        "CAPABILITY_WAITING",
        "CAPABILITY_READY",
        "PRE_Q8_STARTED",
        "PRE_Q8_PROGRESS",
        "PRE_Q8_FAILED",
        "GOLDEN_PRODUCT_STARTED",
        "FACTORY_FUNCTIONALLY_READY",
        "Q7_STARTED",
        "Q7_PROGRESS",
        "Q7_PASSED_Q8_STARTED",
        "FACTORY_PROMOTED",
        "FACTORY_LTS_READY",
        "RECURSIVE_IMPROVEMENT_PROPOSED",
        "IMPROVEMENT_REJECTED",
        "NEW_CANDIDATE_QUALIFICATION_STARTED",
        "OWNER_ACTION_REQUIRED",
        "ASSISTANCE_REQUIRED_GPT_CODEX",
        "Q6_5_TEXT_PROBE",
        "Q6_5_DOCUMENT_PROBE",
    }
)
OWNER_VISIBLE_KINDS: Final[frozenset[str]] = frozenset(
    {
        "OWNER_ACTION_REQUIRED",
        "FACTORY_LTS_READY",
        # Capability qualification must exercise the real Bot API. These two
        # probes are silent and deleted immediately after their typed receipt.
        "Q6_5_TEXT_PROBE",
        "Q6_5_DOCUMENT_PROBE",
    }
)


@dataclass(frozen=True)
class NotificationRequest:
    request_id: str
    kind: str
    text: str
    document_path: str | None = None
    document_digest: str | None = None

    def validate(self, *, attachment_roots: tuple[Path, ...]) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,160}", self.request_id):
            raise NotificationError("notification request id is invalid")
        if self.kind not in NOTIFICATION_KINDS:
            raise NotificationError("notification kind is not allowlisted")
        if not self.text.strip() or len(self.text) > 4096:
            raise NotificationError("notification text is invalid")
        safe, redactions = redact_text(self.text)
        if redactions or safe != self.text:
            raise NotificationError("notification contains secret-like content")
        if (self.document_path is None) != (self.document_digest is None):
            raise NotificationError("notification document binding is incomplete")
        if self.document_path is None:
            return
        path = Path(self.document_path).resolve()
        if not any(
            path == root.resolve() or root.resolve() in path.parents for root in attachment_roots
        ):
            raise NotificationError("notification document is outside allowlist")
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 50 * 1024 * 1024:
            raise NotificationError("notification document is unavailable")
        if sha256_file(path) != self.document_digest:
            raise NotificationError("notification document digest differs")

    def as_dict(self) -> dict[str, str | None]:
        return {
            "schema_version": "1.0",
            "request_id": self.request_id,
            "kind": self.kind,
            "text": self.text,
            "document_path": self.document_path,
            "document_digest": self.document_digest,
        }


class NotificationOutbox:
    def __init__(
        self,
        root: Path,
        *,
        attachment_roots: tuple[Path, ...],
    ) -> None:
        self.root = root
        self.attachment_roots = attachment_roots
        self.outbox = root / "outbox"
        self.pending = root / "pending"
        self.receipts = root / "receipts"
        self.archive = root / "archive"
        self.retired = root / "retired"

    def archive_request(self, path: Path) -> None:
        if path.parent.resolve() != self.outbox.resolve() or path.is_symlink():
            raise NotificationError("notification archive source is invalid")
        self.archive.mkdir(parents=True, exist_ok=True)
        destination = self.archive / path.name
        if destination.exists():
            if destination.is_symlink() or destination.read_bytes() != path.read_bytes():
                raise NotificationError("notification archive conflicts")
            path.unlink()
            return
        path.replace(destination)

    def retire_request(self, path: Path) -> None:
        """Retain an unsent request after its bound owner action is superseded."""

        if path.parent.resolve() != self.outbox.resolve() or path.is_symlink():
            raise NotificationError("notification retirement source is invalid")
        self.retired.mkdir(parents=True, exist_ok=True)
        destination = self.retired / path.name
        if destination.exists():
            if destination.is_symlink() or destination.read_bytes() != path.read_bytes():
                raise NotificationError("notification retirement conflicts")
            path.unlink()
            return
        path.replace(destination)

    def enqueue(self, request: NotificationRequest) -> Path:
        request.validate(attachment_roots=self.attachment_roots)
        if request.kind not in OWNER_VISIBLE_KINDS:
            raise NotificationError("intermediate owner notification is prohibited")
        self.outbox.mkdir(parents=True, exist_ok=True)
        destination = self.outbox / f"{request.request_id}.json"
        encoded = json.dumps(request.as_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if destination.exists():
            if destination.is_symlink() or destination.read_text(encoding="utf-8") != encoded:
                raise NotificationError("notification idempotency conflict")
            return destination
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        return destination

    def load(self, path: Path) -> NotificationRequest:
        if (
            path.parent.resolve() != self.outbox.resolve()
            or not path.is_file()
            or path.is_symlink()
        ):
            raise NotificationError("notification outbox path is invalid")
        value = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(value, dict)
            or set(value)
            != {"schema_version", "request_id", "kind", "text", "document_path", "document_digest"}
            or value.get("schema_version") != "1.0"
        ):
            raise NotificationError("notification request schema is invalid")
        request = NotificationRequest(
            request_id=str(value["request_id"]),
            kind=str(value["kind"]),
            text=str(value["text"]),
            document_path=(str(value["document_path"]) if value["document_path"] else None),
            document_digest=(str(value["document_digest"]) if value["document_digest"] else None),
        )
        request.validate(attachment_roots=self.attachment_roots)
        return request


class OwnerNotifier:
    def __init__(self, outbox: NotificationOutbox, api: TelegramApi, *, chat_id: str) -> None:
        if not chat_id.strip():
            raise NotificationError("owner chat id is missing")
        self.outbox = outbox
        self.api = api
        self.chat_id = chat_id

    def run_once(self) -> int:
        self.outbox.pending.mkdir(parents=True, exist_ok=True)
        self.outbox.receipts.mkdir(parents=True, exist_ok=True)
        delivered = 0
        for path in sorted(self.outbox.outbox.glob("*.json")):
            request = self.outbox.load(path)
            if request.kind not in OWNER_VISIBLE_KINDS:
                self.outbox.retire_request(path)
                continue
            ephemeral_probe = request.kind in {
                "Q6_5_TEXT_PROBE",
                "Q6_5_DOCUMENT_PROBE",
            }
            receipt_path = self.outbox.receipts / path.name
            pending_path = self.outbox.pending / path.name
            if receipt_path.is_file() and not receipt_path.is_symlink():
                self.outbox.archive_request(path)
                continue
            pending = self._load_pending(pending_path, request)
            if pending is None:
                # Telegram has no idempotency key for Bot API sends. Persist an
                # at-most-once dispatch intent before the external call. If the
                # process disappears in the narrow send/receipt window, a
                # restart records an uncertain delivery instead of duplicating
                # the owner-visible side effect.
                self._write_pending(
                    pending_path,
                    {
                        "schema_version": "1.0",
                        "request_id": request.request_id,
                        "kind": request.kind,
                        "phase": "DISPATCHING",
                        "message_id": None,
                    },
                )
                if request.document_path:
                    document = Path(request.document_path)
                    message_id = self.api.send_document(
                        self.chat_id,
                        document.read_bytes(),
                        filename=document.name,
                        caption=f"[{request.kind}] {request.text}"[:1024],
                        silent=ephemeral_probe,
                    )
                else:
                    message_id = self.api.send_message(
                        self.chat_id,
                        f"[{request.kind}] {request.text}",
                        silent=ephemeral_probe,
                    )
                pending = {
                    "schema_version": "1.0",
                    "request_id": request.request_id,
                    "kind": request.kind,
                    "phase": "SENT_PENDING_DELETE" if ephemeral_probe else "SENT",
                    "message_id": message_id,
                }
                self._write_pending(pending_path, pending)
            elif pending["phase"] == "DISPATCHING":
                self._write_receipt(
                    receipt_path,
                    request=request,
                    status="DELIVERY_UNCERTAIN",
                )
                self.outbox.archive_request(path)
                pending_path.unlink()
                continue
            pending_message_id = pending["message_id"]
            if ephemeral_probe and pending["phase"] == "SENT_PENDING_DELETE":
                if not isinstance(pending_message_id, int):
                    raise NotificationError("ephemeral notification message id is invalid")
                self.api.delete_message(self.chat_id, pending_message_id)
                pending = {**pending, "phase": "SENT"}
                self._write_pending(pending_path, pending)
            if pending["phase"] != "SENT":
                raise NotificationError("notification pending phase is invalid")
            self._write_receipt(receipt_path, request=request, status="SENT")
            pending_path.unlink()
            self.outbox.archive_request(path)
            delivered += 1
        return delivered

    @staticmethod
    def _write_pending(path: Path, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        temporary = path.with_name(path.name + ".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o440)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)

    @staticmethod
    def _load_pending(path: Path, request: NotificationRequest) -> dict[str, object] | None:
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file():
            raise NotificationError("notification pending state is unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(value, dict)
            or set(value) != {"schema_version", "request_id", "kind", "phase", "message_id"}
            or value.get("schema_version") != "1.0"
            or value.get("request_id") != request.request_id
            or value.get("kind") != request.kind
            or value.get("phase") not in {"DISPATCHING", "SENT_PENDING_DELETE", "SENT"}
            or (
                value.get("phase") != "DISPATCHING"
                and (not isinstance(value.get("message_id"), int) or int(value["message_id"]) < 1)
            )
            or (value.get("phase") == "DISPATCHING" and value.get("message_id") is not None)
        ):
            raise NotificationError("notification pending state is invalid")
        return value

    @staticmethod
    def _write_receipt(path: Path, *, request: NotificationRequest, status: str) -> None:
        if status not in {"SENT", "DELIVERY_UNCERTAIN"}:
            raise NotificationError("notification receipt status is invalid")
        payload = {
            "schema_version": "1.0",
            "request_id": request.request_id,
            "kind": request.kind,
            "status": status,
            "document_digest": request.document_digest,
            "sent_at": utc_now(),
        }
        payload["receipt_digest"] = sha256_text(stable_json(payload))
        encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
