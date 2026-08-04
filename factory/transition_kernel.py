"""Fail-closed transition executor with proof and terminal-state guards."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass

from .common import sha256_text, stable_json, utc_now
from .transition_catalog import (
    TRANSITION_CATALOG,
    ProductEvent,
    ProductState,
    TransitionSpec,
    transition_spec,
)


class UnknownTransitionError(RuntimeError):
    """The event is outside the generated closed-world catalog."""


class TransitionProofError(RuntimeError):
    """A catalogued transition lacks a mandatory immutable proof."""


@dataclass(frozen=True)
class TransitionReceipt:
    receipt_id: str
    product_id: str
    transition_id: str
    source: str
    target: str
    event: str
    evidence_digest: str
    created_at: str


class TransitionKernel:
    """The only supported product-state transition implementation."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    @staticmethod
    def _validate_evidence(
        spec: TransitionSpec,
        evidence: Mapping[str, str],
    ) -> str:
        missing = [name for name in spec.required_evidence if not str(evidence.get(name) or "")]
        if missing:
            raise TransitionProofError(
                f"transition {spec.transition_id} lacks evidence: {missing[0]}"
            )
        return sha256_text(stable_json(dict(sorted(evidence.items()))))

    def apply_product(
        self,
        *,
        product_id: str,
        target: str,
        event: str,
        evidence: Mapping[str, str] | None = None,
        terminal_reason: str | None = None,
        terminal_evidence_ref: str | None = None,
        completion_evidence_ref: str | None = None,
    ) -> TransitionReceipt:
        row = self.connection.execute(
            "SELECT status FROM products WHERE product_id=?",
            (product_id,),
        ).fetchone()
        if row is None:
            raise KeyError(product_id)
        source = str(row[0])
        try:
            spec = transition_spec(source, event, target)
        except KeyError as error:
            raise UnknownTransitionError(str(error)) from error
        evidence_values = dict(evidence or {})
        evidence_digest = self._validate_evidence(spec, evidence_values)
        target_state = ProductState(target)
        if target_state not in {
            ProductState.FAILED_SAFE,
            ProductState.CANCELLED,
        } and terminal_reason is not None:
            raise TransitionProofError("active/completed transition cannot retain terminal_reason")
        if target_state is ProductState.FAILED_SAFE and (
            not terminal_reason or not terminal_evidence_ref
        ):
            raise TransitionProofError("FAILED_SAFE requires reason and terminal evidence")
        if target_state is ProductState.COMPLETED and not completion_evidence_ref:
            raise TransitionProofError("COMPLETED requires completion evidence")
        if target_state is ProductState.CANCELLED:
            claimable = self.connection.execute(
                """SELECT 1 FROM tasks WHERE product_id=?
                     AND status IN ('PENDING','CLAIMED','WAITING') LIMIT 1""",
                (product_id,),
            ).fetchone()
            if claimable is not None:
                raise TransitionProofError("CANCELLED requires zero claimable tasks")

        now = utc_now()
        receipt_id = "TR-" + sha256_text(
            stable_json(
                [product_id, spec.transition_id, source, target, event, evidence_digest]
            )
        )[:24].upper()
        self.connection.execute(
            """INSERT OR IGNORE INTO transition_receipts
               (receipt_id, product_id, transition_id, source_state, target_state,
                event_type, evidence_json, evidence_digest, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                receipt_id,
                product_id,
                spec.transition_id,
                source,
                target,
                event,
                stable_json(evidence_values),
                evidence_digest,
                now,
            ),
        )
        self.connection.execute(
            """UPDATE products
                  SET status=?, terminal_reason=?, terminal_evidence_ref=?,
                      completion_evidence_ref=?, last_transition_receipt_id=?,
                      updated_at=?
                WHERE product_id=? AND status=?""",
            (
                target,
                terminal_reason if target_state is ProductState.FAILED_SAFE else None,
                terminal_evidence_ref if target_state is ProductState.FAILED_SAFE else None,
                completion_evidence_ref if target_state is ProductState.COMPLETED else None,
                receipt_id,
                now,
                product_id,
                source,
            ),
        )
        if self.connection.execute("SELECT changes()").fetchone()[0] != 1:
            raise TransitionProofError("product state changed before transition commit")
        return TransitionReceipt(
            receipt_id,
            product_id,
            spec.transition_id,
            source,
            target,
            event,
            evidence_digest,
            now,
        )

    def apply_target(
        self,
        *,
        product_id: str,
        target: str,
        evidence: Mapping[str, str] | None = None,
        terminal_reason: str | None = None,
        terminal_evidence_ref: str | None = None,
        completion_evidence_ref: str | None = None,
        preferred_event: str | None = None,
    ) -> TransitionReceipt:
        """Resolve only an explicitly catalogued coordinate for a target state."""

        row = self.connection.execute(
            "SELECT status FROM products WHERE product_id=?",
            (product_id,),
        ).fetchone()
        if row is None:
            raise KeyError(product_id)
        source = str(row[0])
        event_order = tuple(
            dict.fromkeys(
                value
                for value in (
                    preferred_event,
                    ProductEvent.COMPLETE.value,
                    f"RESUME_TO_{target}",
                    f"OWNER_RESUME_TO_{target}",
                    f"RECOVERY_APPLY_TO_{target}",
                    ProductEvent.ADVANCE.value,
                    ProductEvent.RESUME.value,
                    ProductEvent.PRODUCT_REPAIR_REQUIRED.value,
                    ProductEvent.TRANSIENT_DELAY.value,
                    ProductEvent.EXTERNAL_BLOCK.value,
                    ProductEvent.PAUSE.value,
                    ProductEvent.CANCEL.value,
                    ProductEvent.FAIL_SAFE.value,
                    ProductEvent.CONTROLLER_QUARANTINE.value,
                    ProductEvent.ROLLBACK_REQUIRED.value,
                    ProductEvent.ROLLBACK_COMPLETE.value,
                )
                if value
            )
        )
        for event in event_order:
            try:
                transition_spec(source, event, target)
            except KeyError:
                continue
            return self.apply_product(
                product_id=product_id,
                target=target,
                event=event,
                evidence=evidence,
                terminal_reason=terminal_reason,
                terminal_evidence_ref=terminal_evidence_ref,
                completion_evidence_ref=completion_evidence_ref,
            )
        exact_targets = [
            spec
            for spec in TRANSITION_CATALOG
            if spec.source.value == source and spec.target.value == target
        ]
        if len(exact_targets) == 1:
            return self.apply_product(
                product_id=product_id,
                target=target,
                event=exact_targets[0].event,
                evidence=evidence,
                terminal_reason=terminal_reason,
                terminal_evidence_ref=terminal_evidence_ref,
                completion_evidence_ref=completion_evidence_ref,
            )
        if len(exact_targets) > 1:
            raise UnknownTransitionError(
                f"ambiguous transition coordinate to target: {source}/{target}"
            )
        raise UnknownTransitionError(
            f"unknown transition coordinate to target: {source}/{target}"
        )
