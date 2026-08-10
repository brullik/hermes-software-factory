"""Bind provider semantics to controller-owned artifact identity.

Provider output is untrusted semantic data.  Durable controller coordinates
must be attached after JSON parsing and before schema validation so a model
cannot select, corrupt, or accidentally mistype artifact identity.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

CONTROLLER_OWNED_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_id",
        "created_at",
        "producer",
        "policy_digest",
        "product_id",
        "task_id",
        "source_task_id",
        "attempt_id",
        "tier",
        "attempt_kind",
        "prompt_digest",
        "subject_sha",
        "subject_sha_before",
        "plan_id",
        "plan_revision",
        "parent_plan_id",
        "source_failure_id",
        "trigger_failure_id",
        "root_problem_signature",
    }
)


def bind_controller_envelope(
    semantic_payload: Mapping[str, Any],
    *,
    schema: Mapping[str, Any],
    controller_fields: Mapping[str, Any],
) -> dict[str, Any]:
    """Return schema-bounded semantics with exact controller identity fields.

    Unknown provider keys are not admitted into the artifact.  Every
    controller-owned key is removed from the provider body even when the
    caller intentionally omits it; schema validation then fails closed if a
    required durable coordinate was unavailable.
    """

    raw_properties = schema.get("properties")
    if not isinstance(raw_properties, Mapping):
        raise TypeError("artifact schema properties are unavailable")
    allowed = {str(key) for key in raw_properties}
    unexpected_controller_fields = set(controller_fields) - CONTROLLER_OWNED_FIELDS
    if unexpected_controller_fields:
        names = ", ".join(sorted(str(value) for value in unexpected_controller_fields))
        raise ValueError(f"unregistered controller envelope fields: {names}")

    bound = {
        str(key): value
        for key, value in semantic_payload.items()
        if str(key) in allowed and str(key) not in CONTROLLER_OWNED_FIELDS
    }
    bound.update(
        {
            str(key): value
            for key, value in controller_fields.items()
            if str(key) in allowed
        }
    )
    return bound
