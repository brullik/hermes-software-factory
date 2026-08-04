"""Append-only redacted Stable A feed and isolated Candidate B projections."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .common import redact_text, sha256_text, stable_json, utc_now
from .shadow_projection import candidate_shadow_decision, validate_shadow_event

_FEED_NAME = re.compile(
    r"^(?P<first>[0-9]{12})-(?P<last>[0-9]{12})-(?P<digest>[a-f0-9]{64})\.json$"
)
_DECISION_NAME = re.compile(r"^(?P<digest>[a-f0-9]{64})\.json$")


class ShadowFeedError(RuntimeError):
    """A shadow feed batch or projection is unsafe or mutable."""


def _write_once(path: Path, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_text(encoding="utf-8") != encoded:
            raise ShadowFeedError("immutable shadow artifact conflicts")
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    try:
        path.chmod(0o440)
    except OSError:
        pass


def feed_paths(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(
        (path for path in root.iterdir() if _FEED_NAME.fullmatch(path.name)),
        key=lambda path: path.name,
    )


def _last_exported_event_id(root: Path) -> int:
    paths = feed_paths(root)
    if not paths:
        return 0
    match = _FEED_NAME.fullmatch(paths[-1].name)
    if match is None:
        raise ShadowFeedError("shadow feed filename is invalid")
    return int(match.group("last"))


def export_stable_events(
    database: Path,
    feed_root: Path,
    *,
    limit: int = 1000,
) -> dict[str, Any]:
    """Read Stable A through SQLite query_only and append one redacted batch."""

    if not database.is_absolute() or not database.is_file() or database.is_symlink():
        raise ShadowFeedError("Stable A database must be an absolute regular file")
    if limit < 1 or limit > 10000:
        raise ShadowFeedError("shadow feed batch limit is invalid")
    after_event_id = _last_exported_event_id(feed_root)
    connection = sqlite3.connect(
        f"file:{database.resolve().as_posix()}?mode=ro",
        uri=True,
        timeout=30,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    try:
        connection.execute("BEGIN")
        high_watermark = int(
            connection.execute("SELECT COALESCE(MAX(event_id),0) FROM events").fetchone()[0]
        )
        product_count = int(connection.execute("SELECT COUNT(*) FROM products").fetchone()[0])
        rows = connection.execute(
            """SELECT event_id,product_id,task_id,event_type,payload_json,created_at
                 FROM events WHERE event_id>? ORDER BY event_id LIMIT ?""",
            (after_event_id, limit),
        ).fetchall()
        connection.rollback()
    finally:
        connection.close()
    if not rows:
        return {
            "status": "IDLE",
            "event_count": 0,
            "after_event_id": after_event_id,
            "stable_event_high_watermark": high_watermark,
            "stable_product_count": product_count,
        }
    events: list[dict[str, Any]] = []
    redaction_count = 0
    for row in rows:
        try:
            payload = json.loads(str(row["payload_json"]))
        except json.JSONDecodeError as error:
            raise ShadowFeedError("Stable A event payload is invalid JSON") from error
        if not isinstance(payload, Mapping):
            raise ShadowFeedError("Stable A event payload is not an object")
        redacted_text, findings = redact_text(stable_json(dict(payload)))
        redacted_payload = json.loads(redacted_text)
        if not isinstance(redacted_payload, dict):
            raise ShadowFeedError("redacted Stable A payload is not an object")
        redaction_count += sum(int(item["count"]) for item in findings)
        events.append(
            validate_shadow_event(
                {
                    "event_id": int(row["event_id"]),
                    "product_id": row["product_id"],
                    "task_id": row["task_id"],
                    "event_type": str(row["event_type"]),
                    "payload": redacted_payload,
                    "created_at": str(row["created_at"]),
                }
            )
        )
    first_id = int(events[0]["event_id"])
    last_id = int(events[-1]["event_id"])
    body = {
        "schema_version": "1.0",
        "first_event_id": first_id,
        "last_event_id": last_id,
        "stable_event_high_watermark": high_watermark,
        "stable_product_count": product_count,
        "redaction_count": redaction_count,
        "events": events,
        "exported_at": utc_now(),
    }
    digest = sha256_text(stable_json(body))
    envelope = {**body, "batch_digest": digest}
    path = feed_root / f"{first_id:012d}-{last_id:012d}-{digest}.json"
    _write_once(path, envelope)
    return {
        "status": "PASS",
        "event_count": len(events),
        "first_event_id": first_id,
        "last_event_id": last_id,
        "batch_digest": digest,
        "path": str(path),
    }


def load_feed_batch(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ShadowFeedError("shadow feed batch is not a regular file")
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ShadowFeedError("shadow feed batch is unreadable") from error
    if not isinstance(envelope, dict) or set(envelope) != {
        "schema_version",
        "first_event_id",
        "last_event_id",
        "stable_event_high_watermark",
        "stable_product_count",
        "redaction_count",
        "events",
        "exported_at",
        "batch_digest",
    }:
        raise ShadowFeedError("shadow feed batch schema is invalid")
    digest = str(envelope.pop("batch_digest"))
    if sha256_text(stable_json(envelope)) != digest:
        raise ShadowFeedError("shadow feed batch digest differs")
    match = _FEED_NAME.fullmatch(path.name)
    if match is None or match.group("digest") != digest:
        raise ShadowFeedError("shadow feed filename digest differs")
    events = envelope.get("events")
    if not isinstance(events, list) or not events:
        raise ShadowFeedError("shadow feed batch is empty")
    normalized = [validate_shadow_event(event) for event in events if isinstance(event, Mapping)]
    if len(normalized) != len(events):
        raise ShadowFeedError("shadow feed event schema is invalid")
    event_ids = [int(event["event_id"]) for event in normalized]
    if (
        event_ids != sorted(event_ids)
        or len(set(event_ids)) != len(event_ids)
        or int(envelope["first_event_id"]) != event_ids[0]
        or int(envelope["last_event_id"]) != event_ids[-1]
    ):
        raise ShadowFeedError("shadow feed event range is invalid")
    return {**envelope, "events": normalized, "batch_digest": digest}


def evaluate_candidate_batches(feed_root: Path, output_root: Path) -> dict[str, Any]:
    """Evaluate every new feed batch with Candidate B's pure catalog projection."""

    evaluated = 0
    decisions = 0
    for feed_path in feed_paths(feed_root):
        batch = load_feed_batch(feed_path)
        source_digest = str(batch["batch_digest"])
        destination = output_root / f"{source_digest}.json"
        existed = destination.exists()
        if existed:
            decisions += len(
                load_candidate_evaluation(
                    destination,
                    source_batch_digest=source_digest,
                )
            )
            continue
        projected = []
        for event in batch["events"]:
            event_digest = sha256_text(stable_json(event))
            projected.append(
                {
                    "event_digest": event_digest,
                    "decision": candidate_shadow_decision(event),
                }
            )
        body = {
            "schema_version": "1.0",
            "source_batch_digest": source_digest,
            "candidate_decisions": projected,
            "evaluated_at": utc_now(),
        }
        digest = sha256_text(stable_json(body))
        _write_once(destination, {**body, "evaluation_digest": digest})
        evaluated += int(not existed)
        decisions += len(projected)
    return {
        "status": "PASS",
        "batch_count": len(feed_paths(feed_root)),
        "new_batch_count": evaluated,
        "decision_count": decisions,
    }


def load_candidate_evaluation(path: Path, *, source_batch_digest: str) -> list[dict[str, Any]]:
    match = _DECISION_NAME.fullmatch(path.name)
    if match is None or match.group("digest") != source_batch_digest:
        raise ShadowFeedError("candidate evaluation filename differs")
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ShadowFeedError("candidate evaluation is unreadable") from error
    if not isinstance(envelope, dict) or set(envelope) != {
        "schema_version",
        "source_batch_digest",
        "candidate_decisions",
        "evaluated_at",
        "evaluation_digest",
    }:
        raise ShadowFeedError("candidate evaluation schema is invalid")
    digest = str(envelope.pop("evaluation_digest"))
    if sha256_text(stable_json(envelope)) != digest:
        raise ShadowFeedError("candidate evaluation digest differs")
    if envelope.get("schema_version") != "1.0" or envelope.get(
        "source_batch_digest"
    ) != source_batch_digest:
        raise ShadowFeedError("candidate evaluation source differs")
    values = envelope.get("candidate_decisions")
    if not isinstance(values, list) or not values:
        raise ShadowFeedError("candidate evaluation is empty")
    results: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, Mapping) or set(value) != {"event_digest", "decision"}:
            raise ShadowFeedError("candidate decision envelope is invalid")
        decision = value.get("decision")
        if not isinstance(decision, Mapping):
            raise ShadowFeedError("candidate decision is not an object")
        results.append(
            {"event_digest": str(value["event_digest"]), "decision": dict(decision)}
        )
    return results
