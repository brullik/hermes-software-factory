"""Closed controller mapping of PRE-Q8 delivery-profile obligations."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Final

from .common import sha256_text, stable_json
from .delivery_profiles import DeliveryProfileName


@dataclass(frozen=True)
class DeliveryObligation:
    obligation_id: str
    text: str

    def as_dict(self) -> dict[str, str]:
        return {"id": self.obligation_id, "text": self.text}


@dataclass(frozen=True)
class DeliveryObligationSet:
    delivery_profile: str
    delivery_mode: str
    declared_faults: tuple[str, ...]
    obligations: tuple[DeliveryObligation, ...]
    digest: str

    @property
    def obligation_ids(self) -> tuple[str, ...]:
        return tuple(item.obligation_id for item in self.obligations)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "contract_id": "PREQ8-DELIVERY-PROFILES-R01",
            "delivery_profile": self.delivery_profile,
            "delivery_mode": self.delivery_mode,
            "declared_faults": list(self.declared_faults),
            "obligations": [item.as_dict() for item in self.obligations],
            "obligation_ids": list(self.obligation_ids),
            "obligation_set_digest": self.digest,
        }


_UNIVERSAL: Final[tuple[DeliveryObligation, ...]] = (
    DeliveryObligation(
        "PY-PACKAGE-001",
        "pyproject.toml exists and declares an offline-attested build backend.",
    ),
    DeliveryObligation(
        "PY-DEPS-001",
        "project.dependencies is explicit; use [] when no runtime dependencies exist.",
    ),
    DeliveryObligation(
        "PY-LICENSE-001",
        "License metadata and license file are deterministic and gate-readable.",
    ),
    DeliveryObligation(
        "PY-DOCS-001",
        "README documents installation, invocation, deterministic errors and operator actions.",
    ),
    DeliveryObligation(
        "PY-TOOLCHAIN-001",
        "All tests/lint/build commands are derived from the attested Candidate toolchain.",
    ),
)

_PROFILE: Final[dict[str, tuple[DeliveryObligation, ...]]] = {
    "CLI_PACKAGE": (
        DeliveryObligation(
            "CLI-CANON-001",
            "Define UTF-8 decoding, duplicate-key policy, non-finite-number rejection, "
            "canonical number/string encoding, output bytes and exit code 2.",
        ),
        DeliveryObligation(
            "CLI-INSTALL-001",
            "Define reproducible clean-environment build, install and invocation commands "
            "without network runtime dependencies.",
        ),
    ),
    "DEPLOYED_SERVICE": (
        DeliveryObligation(
            "HTTP-HEAD-001",
            "HEAD responses transmit no message body for success and error statuses, "
            "including 405.",
        ),
        DeliveryObligation(
            "DEPLOY-ROLLBACK-001",
            "Staging, health, rollback and redeploy transitions have exact durable receipts.",
        ),
    ),
    "TELEGRAM_BOT": (
        DeliveryObligation(
            "TG-RETRY-001",
            "Define CLAIMED, SENT, FAILED_BEFORE_SEND and AMBIGUOUS states; retry only "
            "FAILED_BEFORE_SEND; never duplicate an ambiguous send.",
        ),
        DeliveryObligation(
            "TG-AUTH-001",
            "Isolated fixture authentication and rejection behavior are explicit and testable.",
        ),
        DeliveryObligation(
            "TG-DB-ROLLBACK-001",
            "SQLite migration compatibility and backup/restore or down-migration rollback "
            "are deterministic.",
        ),
        DeliveryObligation(
            "TG-TRANSPORT-001",
            "Use a fixed exact HTTP(S) endpoint with no redirects, bounded timeout and "
            "bounded response bytes.",
        ),
        DeliveryObligation(
            "TG-FIXTURE-TOKEN-001",
            "The isolated fixture token is mandatory configuration, has no default and "
            "never appears in logs or evidence.",
        ),
        DeliveryObligation(
            "TG-CONCURRENCY-001",
            "Concurrent delivery claims use a pre-migrated durable store, bounded waits "
            "and exactly one successful claimant.",
        ),
    ),
    "OFFLINE_BATCH": (
        DeliveryObligation(
            "BATCH-PATH-001",
            "Reject absolute input paths, any .. component, symlink escape and resolved paths "
            "outside workspace.",
        ),
        DeliveryObligation(
            "BATCH-LIMIT-001",
            "Define exact limits and units for definition size, input/output bytes, node count, "
            "fan-in and per-node memory.",
        ),
    ),
    "GITHUB_AUTOMATION": (
        DeliveryObligation(
            "GH-IDEMPOTENCY-001",
            "Use a stable workflow concurrency key, cancel-in-progress=false and a durable "
            "CLAIMED/COMPLETED marker before the dependent side effect.",
        ),
        DeliveryObligation(
            "GH-RESUME-001",
            "External-not-ready is a bounded wait with automatic resume and no routine owner action.",
        ),
    ),
    "LIBRARY_PACKAGE": (
        DeliveryObligation(
            "LIB-CONSUMER-001",
            "A clean consumer smoke proves installation and import.",
        ),
        DeliveryObligation(
            "LIB-SIGN-001",
            "Define signature algorithm/format, trust root, signer/key ID, artifact digest "
            "binding, expiry/revocation behavior and fail-closed verification.",
        ),
    ),
    # These controller profiles have no additional IDs in the supplied R01
    # contract; they still inherit every UNIVERSAL_PYTHON obligation.
    "WEB_APPLICATION": (),
    "STAGING_ONLY_PROTOTYPE": (),
}

_FAULT: Final[dict[str, tuple[DeliveryObligation, ...]]] = {
    "ONE_PROVIDER_TIMEOUT": (
        DeliveryObligation(
            "FAULT-TIMEOUT-001",
            "Only durable TIMED_OUT transitions to RETRY; recovery cannot complete a "
            "non-timeout state.",
        ),
    ),
    "ONE_PROCESS_RESTART": (
        DeliveryObligation(
            "FAULT-RESTART-001",
            "Retry intent is durable before process exit and exact-once after restart.",
        ),
    ),
    "ONE_PRODUCT_TEST_FAILURE": (
        DeliveryObligation(
            "FAULT-PRODUCT-TEST-001",
            "The injected gate is exactly target-tests and exactly one Builder repair "
            "produces fresh evidence.",
        ),
    ),
    "ONE_POST_DEPLOY_HEALTH_FAILURE": (
        DeliveryObligation(
            "FAULT-ROLLBACK-001",
            "The first production health failure rolls back exactly once; repaired redeploy "
            "completes.",
        ),
    ),
}


def delivery_profile_obligations(
    delivery_profile: str,
    delivery_mode: str,
    declared_faults: Iterable[str] = (),
) -> DeliveryObligationSet:
    """Compile the immutable obligation set without using a scenario identity."""

    try:
        profile = DeliveryProfileName(delivery_profile).value
    except ValueError as error:
        raise ValueError(f"unknown delivery profile: {delivery_profile}") from error
    if delivery_mode not in {"new_repository", "existing_repository"}:
        raise ValueError(f"unknown delivery mode: {delivery_mode}")
    normalized_faults = tuple(sorted({str(value) for value in declared_faults if str(value)}))
    obligations = tuple(
        dict.fromkeys(
            [
                *_UNIVERSAL,
                *_PROFILE[profile],
                *(
                    obligation
                    for fault in normalized_faults
                    for obligation in _FAULT.get(fault, ())
                ),
            ]
        )
    )
    payload = {
        "schema_version": "1.0",
        "contract_id": "PREQ8-DELIVERY-PROFILES-R01",
        "delivery_profile": profile,
        "delivery_mode": delivery_mode,
        "declared_faults": normalized_faults,
        "obligations": [item.as_dict() for item in obligations],
    }
    return DeliveryObligationSet(
        delivery_profile=profile,
        delivery_mode=delivery_mode,
        declared_faults=normalized_faults,
        obligations=obligations,
        digest=sha256_text(stable_json(payload)),
    )
