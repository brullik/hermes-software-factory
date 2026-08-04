"""Fail-closed validation for adapter-authoritative release operations.

The release operator may propose an operation, but it cannot turn that
proposal into release evidence unless an injected executor performs the
side effects and returns an authoritative result whose lifecycle invariants
are true.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .providers import ExternalBlocker

RELEASE_OPERATIONS = frozenset(
    {
        "staging",
        "production",
        "publish-dry-run",
        "signed-release",
        "signed-publish",
    }
)


def canonical_release_operation(stage: str) -> str:
    aliases = {
        "release-staging": "staging",
        "release-production": "production",
    }
    normalized = aliases.get(stage, stage)
    if normalized not in RELEASE_OPERATIONS:
        raise ReleasePolicyError(f"unknown release operation: {stage}")
    return normalized


def release_predecessor_evidence(stage: str) -> str | None:
    """Return the exact immutable evidence type consumed by a release operation."""

    stage = canonical_release_operation(stage)
    if stage == "production":
        return "staging"
    if stage == "signed-publish":
        return "publish_dry_run"
    if stage in {"staging", "publish-dry-run", "signed-release"}:
        return None
    raise ReleasePolicyError(f"unknown release operation: {stage}")


class ReleasePolicyError(ValueError):
    """Raised when a release result violates an immutable lifecycle rule."""


class ReleaseOperationFailed(ExternalBlocker):
    """A release side effect reached a proven safe failure postcondition."""

    def __init__(
        self,
        detail: str,
        *,
        reason_code: str,
        receipt_ref: str,
        receipt_result: Mapping[str, Any],
    ) -> None:
        super().__init__(detail, reason_code=reason_code)
        if not receipt_ref or not isinstance(receipt_result, Mapping):
            raise ValueError("failed release receipt is invalid")
        self.receipt_ref = receipt_ref
        self.receipt_result = dict(receipt_result)


class ReleaseExecutor(Protocol):
    """Side-effect boundary for release operations.

    The model may provide a proposed operation, but only an injected adapter
    may return the authoritative result after performing the GitHub and/or
    deployment side effects.  Implementations must fail closed when the
    required external credential, approval, or target is unavailable.
    """

    def execute(
        self,
        *,
        stage: str,
        proposed: Mapping[str, Any],
        product_id: str,
        task_contract: Mapping[str, Any],
        workspace: Path,
        expected_staging_digest: str | None,
    ) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class ReleaseVerification:
    stage: str
    candidate_sha: str
    image_digest: str
    evidence_refs: tuple[str, ...]


_SHA = re.compile(r"^[a-f0-9]{40}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


def validate_release_operation(
    result: Mapping[str, Any],
    *,
    stage: str,
    expected_staging_digest: str | None = None,
) -> ReleaseVerification:
    """Validate release semantics after schema validation.

    ``stage`` is either ``staging`` or ``production``.  Production requires
    proof that the reviewed commit is the merge commit and that the exact
    staging image digest is promoted.  No model-generated text can satisfy
    this check by itself; the adapter must provide matching immutable values.
    """

    stage = canonical_release_operation(stage)
    if result.get("status") != "completed":
        raise ReleasePolicyError("release result is not completed")
    candidate_sha = str(result.get("candidate_sha", ""))
    release = result.get("release")
    merge = result.get("merge")
    evidence_refs = result.get("evidence_refs")
    if not _SHA.fullmatch(candidate_sha):
        raise ReleasePolicyError("candidate SHA is not an immutable 40-character commit")
    if not isinstance(release, Mapping) or not _DIGEST.fullmatch(str(release.get("image_digest", ""))):
        raise ReleasePolicyError("release image digest is not immutable")
    if not isinstance(merge, Mapping):
        raise ReleasePolicyError("merge evidence is missing")
    if not isinstance(evidence_refs, list) or not evidence_refs or len(evidence_refs) != len(set(evidence_refs)):
        raise ReleasePolicyError("release evidence references must be non-empty and unique")

    image_digest = str(release["image_digest"])
    if result.get("staging") != "deployed":
        raise ReleasePolicyError("release must have a successful staging deployment")

    if stage in {"staging", "publish-dry-run"}:
        if bool(merge.get("performed")) or merge.get("merge_sha") is not None:
            raise ReleasePolicyError("staging preparation cannot claim a merge")
        if result.get("production") != "not_started":
            raise ReleasePolicyError("staging preparation cannot claim production deployment")
        if result.get("rollback") not in {"not_tested", "not_needed"}:
            raise ReleasePolicyError("staging preparation has inconsistent rollback status")
    else:
        merge_sha = merge.get("merge_sha")
        if not bool(merge.get("performed")) or merge_sha != candidate_sha:
            raise ReleasePolicyError("production release must bind merge SHA to candidate SHA")
        if result.get("production") != "deployed":
            raise ReleasePolicyError("production release must report a deployed production")
        if result.get("rollback") not in {"not_needed", "succeeded"}:
            raise ReleasePolicyError("production release lacks rollback readiness")
        if stage in {"production", "signed-publish"}:
            if expected_staging_digest is None:
                raise ReleasePolicyError("accepted predecessor digest is missing")
            if (
                not _DIGEST.fullmatch(expected_staging_digest)
                or image_digest != expected_staging_digest
            ):
                raise ReleasePolicyError(
                    "release must promote the exact accepted predecessor digest"
                )
        elif expected_staging_digest is not None:
            raise ReleasePolicyError("signed release has an unexpected predecessor digest")

    return ReleaseVerification(stage, candidate_sha, image_digest, tuple(str(ref) for ref in evidence_refs))
