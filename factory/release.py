"""Fail-closed validation for model-reported release operations.

The release operator may describe an operation, but it cannot turn that
description into release evidence unless the lifecycle invariants are true.
Actual GitHub and deployment side effects remain adapter-owned.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


class ReleasePolicyError(ValueError):
    """Raised when a release result violates an immutable lifecycle rule."""


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

    if stage not in {"staging", "production"}:
        raise ReleasePolicyError("release stage must be staging or production")
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

    if stage == "staging":
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
        if expected_staging_digest is None:
            raise ReleasePolicyError("accepted staging digest is missing")
        if not _DIGEST.fullmatch(expected_staging_digest) or image_digest != expected_staging_digest:
            raise ReleasePolicyError("production must promote the exact accepted staging digest")

    return ReleaseVerification(stage, candidate_sha, image_digest, tuple(str(ref) for ref in evidence_refs))
