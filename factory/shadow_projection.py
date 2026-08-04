"""Pure stable-observation and Candidate B decision projections for Q7."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .common import sha256_text, stable_json
from .failure_catalog import failure_disposition
from .transition_catalog import ProductState, transition_spec


class ShadowProjectionError(RuntimeError):
    """A redacted event cannot be projected without an open-world fallback."""


_EVENT_KEYS = {
    "event_id",
    "product_id",
    "task_id",
    "event_type",
    "payload",
    "created_at",
}


def validate_shadow_event(value: Mapping[str, Any]) -> dict[str, Any]:
    event = dict(value)
    if set(event) != _EVENT_KEYS or not isinstance(event.get("payload"), Mapping):
        raise ShadowProjectionError("redacted shadow event schema is invalid")
    event_id = event["event_id"]
    if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1:
        raise ShadowProjectionError("redacted shadow event identity is invalid")
    if not str(event["event_type"] or "").strip() or not str(event["created_at"] or ""):
        raise ShadowProjectionError("redacted shadow event coordinate is missing")
    event["payload"] = dict(event["payload"])
    return event


def _digest(value: Any, fallback: Any) -> str:
    text = str(value or "")
    if len(text) == 64 and all(character in "0123456789abcdef" for character in text):
        return text
    return sha256_text(stable_json(fallback))


def _observed_transition(event: Mapping[str, Any]) -> tuple[str, str | None]:
    payload = dict(event["payload"])
    explicit = str(payload.get("transition_id") or "")
    if explicit:
        return explicit, str(payload.get("to") or payload.get("status") or "") or None
    if str(event["event_type"]) == "product_transition":
        source = str(payload.get("from") or "")
        transition_event = str(payload.get("event") or "")
        target = str(payload.get("to") or "")
        if not transition_event:
            try:
                ProductState(source)
                ProductState(target)
            except ValueError:
                return f"UNREGISTERED:{source}:{transition_event}:{target}", target or None
            # Stable releases predating the closed transition catalog persisted
            # the observed from/to outcome without its triggering event.  That
            # record is evidence of an outcome, not a new event for Candidate B
            # to execute.  Preserve the known-state observation explicitly; a
            # non-empty unknown event still follows the fail-closed path below.
            return f"LEGACY_OBSERVED:{source}:{target}", target
        try:
            spec = transition_spec(source, transition_event, target)
        except KeyError:
            return f"UNREGISTERED:{source}:{transition_event}:{target}", target or None
        return spec.transition_id, target
    return str(event["event_type"]), str(payload.get("status") or "") or None


def _failure_owner(payload: Mapping[str, Any]) -> str:
    explicit = str(payload.get("failure_owner") or payload.get("owner") or "")
    reason = str(payload.get("reason_code") or payload.get("reason") or "")
    if reason:
        return failure_disposition(reason).owner
    return explicit if explicit in {"product", "controller", "external", "none"} else "none"


def _common_projection(event: Mapping[str, Any]) -> dict[str, Any]:
    normalized = validate_shadow_event(event)
    payload = dict(normalized["payload"])
    event_identity = {
        "event_id": normalized["event_id"],
        "product_id": normalized["product_id"],
        "task_id": normalized["task_id"],
        "event_type": normalized["event_type"],
        "payload": payload,
    }
    transition, terminal = _observed_transition(normalized)
    task_count_value = payload.get("task_count")
    task_count = (
        int(task_count_value)
        if isinstance(task_count_value, int) and not isinstance(task_count_value, bool)
        else int(str(normalized["event_type"]) == "task_created")
    )
    intent = payload.get("side_effect_intent") or payload.get("intent_id")
    if intent is not None and not isinstance(intent, (str, int, float, bool)):
        raise ShadowProjectionError("shadow side-effect intent is not scalar")
    return {
        "chosen_transition": transition,
        "failure_owner": _failure_owner(payload),
        "capability_proof_digest": _digest(
            payload.get("capability_proof_digest"),
            ["no-capability-proof", event_identity],
        ),
        "root_cause_key": _digest(
            payload.get("root_cause_key"),
            ["observed-root-cause", event_identity],
        ),
        "task_count": max(0, task_count),
        "side_effect_intent": intent,
        "terminal_result": terminal,
    }


def stable_observed_decision(event: Mapping[str, Any]) -> dict[str, Any]:
    """Project Stable A's persisted outcome without executing candidate logic."""

    return _common_projection(event)


def candidate_shadow_decision(event: Mapping[str, Any]) -> dict[str, Any]:
    """Re-evaluate the same redacted coordinate through Candidate B catalogs."""

    decision = _common_projection(event)
    if str(decision["chosen_transition"]).startswith("UNREGISTERED:"):
        decision["chosen_transition"] = "CONTROLLER_QUARANTINE"
        decision["failure_owner"] = "controller"
        decision["terminal_result"] = "FAILED_SAFE"
    return decision
