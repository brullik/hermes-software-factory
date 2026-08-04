"""Proof-carrying capability, side-effect, and completion records."""

from __future__ import annotations

import json
import platform
import re
import sqlite3
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .common import sha256_file, sha256_text, stable_json, utc_now

_SHA256 = re.compile(r"[a-f0-9]{64}")
_FORBIDDEN_WILDCARDS = {"*", "**", "**/*"}


class ProofObligationError(RuntimeError):
    """A proof cannot be built from the exact controller-owned inputs."""


def _require_digest(name: str, value: str) -> str:
    if not _SHA256.fullmatch(str(value)):
        raise ProofObligationError(f"{name} must be a lowercase SHA-256")
    return str(value)


def _contains_unbounded_scope(value: object) -> bool:
    if isinstance(value, str):
        return value.strip() in _FORBIDDEN_WILDCARDS
    if isinstance(value, Mapping):
        return any(_contains_unbounded_scope(item) for item in value.values())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_contains_unbounded_scope(item) for item in value)
    return False


@dataclass(frozen=True)
class ToolchainManifest:
    manifest_id: str
    controller_release_digest: str
    components: tuple[tuple[str, str], ...]
    capabilities: tuple[str, ...]
    created_at: str
    manifest_digest: str

    @classmethod
    def build(
        cls,
        *,
        controller_release_digest: str,
        components: Mapping[str, str],
        capabilities: Sequence[str],
        created_at: str | None = None,
    ) -> ToolchainManifest:
        release = _require_digest("controller_release_digest", controller_release_digest)
        normalized_components = tuple(
            sorted((str(name), str(version)) for name, version in components.items())
        )
        if not normalized_components or any(not name or not version for name, version in normalized_components):
            raise ProofObligationError("toolchain manifest requires exact components")
        normalized_capabilities = tuple(sorted({str(value) for value in capabilities if value}))
        now = created_at or utc_now()
        payload = {
            "controller_release_digest": release,
            "components": normalized_components,
            "capabilities": normalized_capabilities,
            "created_at": now,
        }
        digest = sha256_text(stable_json(payload))
        return cls(
            manifest_id=f"TM-{digest[:24].upper()}",
            controller_release_digest=release,
            components=normalized_components,
            capabilities=normalized_capabilities,
            created_at=now,
            manifest_digest=digest,
        )


def local_toolchain_manifest(controller_release_digest: str) -> ToolchainManifest:
    """Describe the controller interpreter without invoking mutable package tools."""

    executable = Path(sys.executable)
    return ToolchainManifest.build(
        controller_release_digest=controller_release_digest,
        components={
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "executable_name": executable.name,
        },
        capabilities=("toolchain.python",),
    )


def controller_source_digest(package_root: Path | None = None) -> str:
    """Hash the immutable controller inputs used by an executing process."""

    root = package_root or Path(__file__).resolve().parent.parent
    inputs: list[tuple[str, str]] = []
    for relative_root in ("factory", "schemas", "policies", "prompts"):
        directory = root / relative_root
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if path.is_file() and not path.is_symlink() and "__pycache__" not in path.parts:
                inputs.append((path.relative_to(root).as_posix(), sha256_file(path)))
    version = root / "VERSION"
    if version.is_file() and not version.is_symlink():
        inputs.append(("VERSION", sha256_file(version)))
    if not inputs:
        raise ProofObligationError("controller source inventory is empty")
    return sha256_text(stable_json(inputs))


@dataclass(frozen=True)
class CapabilityGrantProof:
    grant_id: str
    grant_epoch_id: str
    capability: str
    provider: str
    scope_digest: str
    expires_at: str | None


@dataclass(frozen=True)
class CapabilityProof:
    proof_id: str
    task_id: str
    task_contract_digest: str
    canonical_profile: str
    toolchain_manifest_digest: str
    grants: tuple[CapabilityGrantProof, ...]
    negative_assertions: tuple[str, ...]
    expires_at: str | None
    proof_digest: str
    created_at: str

    def payload(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "task_contract_digest": self.task_contract_digest,
            "canonical_profile": self.canonical_profile,
            "toolchain_manifest_digest": self.toolchain_manifest_digest,
            "grants": [asdict(value) for value in self.grants],
            "negative_assertions": list(self.negative_assertions),
            "expires_at": self.expires_at,
            "created_at": self.created_at,
        }


def compile_capability_proof(
    *,
    task_id: str,
    task_contract_digest: str,
    canonical_profile: str,
    canonical_capabilities: Sequence[str],
    toolchain_manifest_digest: str,
    grants: Sequence[Mapping[str, Any]],
    now: str | None = None,
) -> CapabilityProof:
    """Compile exact grants; parent tasks and model text are not inputs."""

    _require_digest("task_contract_digest", task_contract_digest)
    _require_digest("toolchain_manifest_digest", toolchain_manifest_digest)
    if not task_id or not canonical_profile:
        raise ProofObligationError("capability proof identity is incomplete")
    current = now or utc_now()
    by_capability: dict[str, CapabilityGrantProof] = {}
    expirations: list[str] = []
    for raw in grants:
        capability = str(raw.get("capability") or "")
        if capability not in canonical_capabilities:
            continue
        if str(raw.get("status") or "") != "AVAILABLE":
            continue
        expires_at = str(raw.get("expires_at") or "") or None
        if expires_at is not None and expires_at <= current:
            continue
        try:
            scope = raw.get("scope")
            if scope is None:
                scope = json.loads(str(raw.get("scope_json") or "{}"))
        except (TypeError, json.JSONDecodeError) as error:
            raise ProofObligationError("capability grant scope is invalid") from error
        if not isinstance(scope, Mapping) or _contains_unbounded_scope(scope):
            raise ProofObligationError("unbounded capability grant scope is forbidden")
        grant_epoch_id = str(raw.get("grant_epoch_id") or "")
        if not grant_epoch_id:
            raise ProofObligationError("capability grant lacks a grant epoch")
        candidate = CapabilityGrantProof(
            grant_id=str(raw.get("grant_id") or ""),
            grant_epoch_id=grant_epoch_id,
            capability=capability,
            provider=str(raw.get("provider") or ""),
            scope_digest=sha256_text(stable_json(dict(scope))),
            expires_at=expires_at,
        )
        if not candidate.grant_id or not candidate.provider:
            raise ProofObligationError("capability grant identity is incomplete")
        by_capability.setdefault(capability, candidate)
        if expires_at is not None:
            expirations.append(expires_at)
    missing = sorted(set(canonical_capabilities) - set(by_capability))
    if missing:
        raise ProofObligationError(f"canonical capability lacks exact grant: {missing[0]}")
    normalized_grants = tuple(by_capability[key] for key in sorted(by_capability))
    negative_assertions = (
        "no_parent_lineage_capabilities",
        "no_model_declared_capabilities",
        "no_missing_contract_fallback",
        "no_unbounded_scope",
        "no_raw_credentials",
    )
    expires_at = min(expirations) if expirations else None
    payload = {
        "task_id": task_id,
        "task_contract_digest": task_contract_digest,
        "canonical_profile": canonical_profile,
        "toolchain_manifest_digest": toolchain_manifest_digest,
        "grants": [asdict(value) for value in normalized_grants],
        "negative_assertions": list(negative_assertions),
        "expires_at": expires_at,
        "created_at": current,
    }
    digest = sha256_text(stable_json(payload))
    return CapabilityProof(
        proof_id=f"CP-{digest[:24].upper()}",
        task_id=task_id,
        task_contract_digest=task_contract_digest,
        canonical_profile=canonical_profile,
        toolchain_manifest_digest=toolchain_manifest_digest,
        grants=normalized_grants,
        negative_assertions=negative_assertions,
        expires_at=expires_at,
        proof_digest=digest,
        created_at=current,
    )


@dataclass(frozen=True)
class CompletionManifest:
    manifest_id: str
    product_id: str
    delivery_profile: str
    delivery_profile_digest: str
    product_contract_digest: str
    semantic_graph_digest: str
    candidate_snapshot_digest: str
    pr_checks_ref: str
    staging_ref: str
    acceptance_ref: str
    production_ref: str
    rollback_restore_ref: str
    observation_ref: str
    controller_release_digest: str
    policy_digest: str
    open_problem_count: int
    open_controller_incident_count: int
    not_applicable_proofs: tuple[dict[str, Any], ...]
    created_at: str
    manifest_digest: str


def profile_not_applicable_proof(
    *,
    product_id: str,
    delivery_profile: str,
    delivery_profile_digest: str,
    obligation: str,
    acceptable_substitutes: Sequence[str],
) -> dict[str, Any]:
    """Build a deterministic, profile-bound proof that an obligation is inapplicable."""

    _require_digest("delivery_profile_digest", delivery_profile_digest)
    substitutes = tuple(sorted({str(value) for value in acceptable_substitutes if value}))
    if not product_id or not delivery_profile or not obligation:
        raise ProofObligationError("not-applicable proof identity is incomplete")
    body = {
        "proof_type": "delivery_profile_not_applicable",
        "product_id": product_id,
        "delivery_profile": delivery_profile,
        "delivery_profile_digest": delivery_profile_digest,
        "obligation": obligation,
        "acceptable_substitutes": substitutes,
    }
    digest = sha256_text(stable_json(body))
    return {
        **body,
        "proof_digest": digest,
        "evidence_ref": f"state://profile-not-applicable/{digest}",
    }


def build_completion_manifest(**values: Any) -> CompletionManifest:
    """Build the atomic completion proof; zero-open-problem proof is mandatory."""

    digest_fields = (
        "product_contract_digest",
        "semantic_graph_digest",
        "candidate_snapshot_digest",
        "delivery_profile_digest",
        "controller_release_digest",
        "policy_digest",
    )
    for name in digest_fields:
        _require_digest(name, str(values.get(name) or ""))
    reference_fields = (
        "pr_checks_ref",
        "staging_ref",
        "acceptance_ref",
        "production_ref",
        "rollback_restore_ref",
        "observation_ref",
    )
    for name in reference_fields:
        if not str(values.get(name) or ""):
            raise ProofObligationError(f"completion manifest lacks {name}")
    delivery_profile = str(values.get("delivery_profile") or "")
    if not delivery_profile:
        raise ProofObligationError("completion manifest lacks delivery_profile")
    raw_proofs = values.get("not_applicable_proofs", ())
    if not isinstance(raw_proofs, Sequence) or isinstance(
        raw_proofs, (str, bytes, bytearray)
    ):
        raise ProofObligationError("not-applicable proofs must be a sequence")
    proofs: list[dict[str, Any]] = []
    proof_by_ref: dict[str, dict[str, Any]] = {}
    for raw in raw_proofs:
        if not isinstance(raw, Mapping):
            raise ProofObligationError("not-applicable proof is not an object")
        proof = dict(raw)
        if (
            proof.get("proof_type") != "delivery_profile_not_applicable"
            or proof.get("product_id") != values.get("product_id")
            or proof.get("delivery_profile") != delivery_profile
            or proof.get("delivery_profile_digest")
            != values.get("delivery_profile_digest")
        ):
            raise ProofObligationError("not-applicable proof identity does not match manifest")
        body = {
            key: proof.get(key)
            for key in (
                "proof_type",
                "product_id",
                "delivery_profile",
                "delivery_profile_digest",
                "obligation",
                "acceptable_substitutes",
            )
        }
        proof_digest = sha256_text(stable_json(body))
        evidence_ref = f"state://profile-not-applicable/{proof_digest}"
        if proof.get("proof_digest") != proof_digest or proof.get("evidence_ref") != evidence_ref:
            raise ProofObligationError("not-applicable proof digest does not verify")
        if evidence_ref in proof_by_ref:
            raise ProofObligationError("duplicate not-applicable proof")
        proof_by_ref[evidence_ref] = proof
        proofs.append(proof)
    for name in reference_fields:
        reference = str(values[name])
        if reference.startswith("state://profile-not-applicable/"):
            matched_proof = proof_by_ref.get(reference)
            if matched_proof is None or matched_proof.get("obligation") != name:
                raise ProofObligationError(
                    f"completion manifest has unproven not-applicable reference: {name}"
                )
    if int(values.get("open_problem_count", -1)) != 0:
        raise ProofObligationError("completion manifest requires zero open problems")
    if int(values.get("open_controller_incident_count", -1)) != 0:
        raise ProofObligationError("completion manifest requires zero controller incidents")
    now = str(values.get("created_at") or utc_now())
    payload = {
        key: values[key]
        for key in (
            "product_id",
            "delivery_profile",
            *digest_fields,
            *reference_fields,
            "open_problem_count",
            "open_controller_incident_count",
        )
    }
    payload["not_applicable_proofs"] = tuple(proofs)
    payload["created_at"] = now
    digest = sha256_text(stable_json(payload))
    return CompletionManifest(
        manifest_id=f"CM-{digest[:24].upper()}",
        created_at=now,
        manifest_digest=digest,
        **{key: payload[key] for key in payload if key != "created_at"},
    )


class SideEffectProtocol:
    """Crash-safe intent/receipt protocol for every external adapter call."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def prepare(
        self,
        *,
        product_id: str,
        operation: str,
        adapter: str,
        idempotency_key: str,
        expected_postcondition: Mapping[str, Any],
    ) -> str:
        if not product_id or not operation or not adapter or not idempotency_key:
            raise ProofObligationError("side-effect intent identity is incomplete")
        if _contains_unbounded_scope(expected_postcondition):
            raise ProofObligationError("side-effect postcondition cannot be unbounded")
        intent_id = "SEI-" + sha256_text(
            stable_json([product_id, operation, adapter, idempotency_key])
        )[:24].upper()
        now = utc_now()
        self.connection.execute(
            """INSERT OR IGNORE INTO side_effect_intents
               (intent_id, product_id, operation, adapter, idempotency_key,
                expected_postcondition_json, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, 'PREPARED', ?, ?)""",
            (
                intent_id,
                product_id,
                operation,
                adapter,
                idempotency_key,
                stable_json(dict(expected_postcondition)),
                now,
                now,
            ),
        )
        persisted = self.connection.execute(
            """SELECT product_id,operation,adapter,idempotency_key,
                      expected_postcondition_json
                 FROM side_effect_intents WHERE intent_id=?""",
            (intent_id,),
        ).fetchone()
        expected_identity = (
            product_id,
            operation,
            adapter,
            idempotency_key,
            stable_json(dict(expected_postcondition)),
        )
        if persisted is None or tuple(str(value) for value in persisted) != expected_identity:
            raise ProofObligationError("side-effect intent replay conflicts with durable state")
        return intent_id

    def status(self, intent_id: str) -> str:
        row = self.connection.execute(
            "SELECT status FROM side_effect_intents WHERE intent_id=?",
            (intent_id,),
        ).fetchone()
        if row is None:
            raise KeyError(intent_id)
        return str(row[0])

    def verified_result(self, intent_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """SELECT receipt.result_json
                 FROM side_effect_receipts AS receipt
                 JOIN side_effect_intents AS intent ON intent.intent_id=receipt.intent_id
                WHERE receipt.intent_id=? AND intent.status='VERIFIED'""",
            (intent_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(str(row[0]))
        except json.JSONDecodeError as error:
            raise ProofObligationError("verified side-effect result is corrupt") from error
        if not isinstance(value, dict):
            raise ProofObligationError("verified side-effect result is not an object")
        return value

    def mark_executing(self, intent_id: str) -> None:
        updated = self.connection.execute(
            """UPDATE side_effect_intents SET status='EXECUTING', updated_at=?
                WHERE intent_id=? AND status='PREPARED'""",
            (utc_now(), intent_id),
        ).rowcount
        if updated != 1:
            row = self.connection.execute(
                "SELECT status FROM side_effect_intents WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
            if row is None or str(row[0]) not in {"EXECUTING", "VERIFIED"}:
                raise ProofObligationError("side-effect intent is not executable")

    def verify(
        self,
        *,
        intent_id: str,
        receipt_ref: str,
        receipt_digest: str,
        observed_postcondition: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> None:
        _require_digest("receipt_digest", receipt_digest)
        if not receipt_ref or _contains_unbounded_scope(result):
            raise ProofObligationError("side-effect receipt is invalid")
        row = self.connection.execute(
            "SELECT expected_postcondition_json,status FROM side_effect_intents WHERE intent_id=?",
            (intent_id,),
        ).fetchone()
        if row is None:
            raise KeyError(intent_id)
        if str(row[1]) not in {"EXECUTING", "VERIFIED"}:
            raise ProofObligationError("side-effect intent was not executed")
        expected = json.loads(str(row[0]))
        if expected != dict(observed_postcondition):
            raise ProofObligationError("side-effect postcondition was not proven")
        now = utc_now()
        existing = self.connection.execute(
            """SELECT receipt_ref,receipt_digest,observed_postcondition_json,result_json
                 FROM side_effect_receipts WHERE intent_id=?""",
            (intent_id,),
        ).fetchone()
        receipt_values = (
            receipt_ref,
            receipt_digest,
            stable_json(dict(observed_postcondition)),
            stable_json(dict(result)),
        )
        if existing is not None:
            if tuple(str(value) for value in existing) != receipt_values:
                raise ProofObligationError("duplicate side-effect receipt conflicts")
        else:
            self.connection.execute(
                """INSERT INTO side_effect_receipts
               (receipt_id, intent_id, receipt_ref, receipt_digest,
                observed_postcondition_json, result_json, verified_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    f"SER-{receipt_digest[:24].upper()}",
                    intent_id,
                    *receipt_values,
                    now,
                ),
            )
        self.connection.execute(
            "UPDATE side_effect_intents SET status='VERIFIED', updated_at=? WHERE intent_id=?",
            (now, intent_id),
        )


@dataclass(frozen=True)
class DecisionArchiveManifest:
    archive_id: str
    product_id: str
    decisions: tuple[dict[str, Any], ...]
    decision_digests: tuple[tuple[str, str], ...]
    manifest_digest: str

    def payload(self) -> dict[str, Any]:
        return {
            "archive_id": self.archive_id,
            "product_id": self.product_id,
            "decisions": list(self.decisions),
            "decision_digests": [list(value) for value in self.decision_digests],
        }


class DecisionArchiveService:
    """Build, read back, and register a WORM decision-history export."""

    _WORM_REF = re.compile(r"^(?:worm|s3|b2)://[^\s]+$")

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def build(self, *, product_id: str) -> DecisionArchiveManifest:
        rows = self.connection.execute(
            """SELECT * FROM path_decisions
                 WHERE product_id=?
                   AND status IN ('APPLIED','REJECTED','FAILED_SAFE')
                 ORDER BY created_at,decision_id""",
            (product_id,),
        ).fetchall()
        if not rows:
            raise ProofObligationError("decision archive has no terminal decisions")
        decisions = tuple(dict(row) for row in rows)
        decision_digests = tuple(
            (str(row["decision_id"]), sha256_text(stable_json(dict(row))))
            for row in rows
        )
        body = {
            "product_id": product_id,
            "decisions": decisions,
            "decision_digests": decision_digests,
        }
        manifest_digest = sha256_text(stable_json(body))
        archive_id = f"DA-{manifest_digest[:24].upper()}"
        return DecisionArchiveManifest(
            archive_id,
            product_id,
            decisions,
            decision_digests,
            manifest_digest,
        )

    def confirm_export(
        self,
        *,
        manifest: DecisionArchiveManifest,
        readback_payload: Mapping[str, Any],
        archive_ref: str,
        export_checkpoint: str,
        archive_receipt_ref: str,
    ) -> str:
        if not self._WORM_REF.fullmatch(archive_ref) or not self._WORM_REF.fullmatch(
            archive_receipt_ref
        ):
            raise ProofObligationError("decision archive requires a WORM object and receipt")
        _require_digest("export_checkpoint", export_checkpoint)
        expected = manifest.payload()
        if dict(readback_payload) != expected:
            raise ProofObligationError("decision archive readback differs from manifest")
        readback_digest = sha256_text(
            stable_json(
                {
                    "product_id": readback_payload["product_id"],
                    "decisions": readback_payload["decisions"],
                    "decision_digests": readback_payload["decision_digests"],
                }
            )
        )
        if readback_digest != manifest.manifest_digest:
            raise ProofObligationError("decision archive readback digest mismatch")
        self.connection.execute(
            """INSERT INTO decision_archives
               (archive_id,product_id,archive_ref,manifest_digest,readback_digest,
                export_checkpoint,archive_receipt_ref,created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                manifest.archive_id,
                manifest.product_id,
                archive_ref,
                manifest.manifest_digest,
                readback_digest,
                export_checkpoint,
                archive_receipt_ref,
                utc_now(),
            ),
        )
        for decision_id, decision_digest in manifest.decision_digests:
            self.connection.execute(
                """INSERT INTO decision_archive_memberships
                   (archive_id,decision_id,decision_digest) VALUES (?, ?, ?)""",
                (manifest.archive_id, decision_id, decision_digest),
            )
        return manifest.archive_id

    def compact(self, *, archive_id: str) -> int:
        archive = self.connection.execute(
            """SELECT manifest_digest,readback_digest,archive_receipt_ref,
                      export_checkpoint
                 FROM decision_archives WHERE archive_id=?""",
            (archive_id,),
        ).fetchone()
        if (
            archive is None
            or str(archive[0]) != str(archive[1])
            or not str(archive[2])
            or not str(archive[3])
        ):
            raise ProofObligationError("verified decision archive receipt is missing")
        deleted = self.connection.execute(
            """DELETE FROM path_decisions
                 WHERE decision_id IN (
                     SELECT decision_id FROM decision_archive_memberships
                      WHERE archive_id=?
                 )""",
            (archive_id,),
        ).rowcount
        return int(deleted)


class RecoveryCertificateService:
    """Only path for reopening FAILED_SAFE under a new proven epoch."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def issue(
        self,
        *,
        product_id: str,
        previous_epoch_key: str,
        new_epoch_key: str,
        root_cause_key: str,
        controller_release_digest: str,
        policy_schema_digest: str,
        fixed_invariant_id: str,
        regression_evidence_ref: str,
        migration_dry_run_digest: str,
        backup_restore_proof_ref: str,
    ) -> str:
        for name, value in (
            ("previous_epoch_key", previous_epoch_key),
            ("new_epoch_key", new_epoch_key),
            ("root_cause_key", root_cause_key),
            ("controller_release_digest", controller_release_digest),
            ("policy_schema_digest", policy_schema_digest),
            ("migration_dry_run_digest", migration_dry_run_digest),
        ):
            _require_digest(name, value)
        if previous_epoch_key == new_epoch_key:
            raise ProofObligationError("recovery requires a new occurrence epoch")
        references = (
            fixed_invariant_id,
            regression_evidence_ref,
            backup_restore_proof_ref,
        )
        if any(not str(value) for value in references):
            raise ProofObligationError("recovery certificate evidence is incomplete")
        product = self.connection.execute(
            "SELECT status FROM products WHERE product_id=?",
            (product_id,),
        ).fetchone()
        if product is None:
            raise KeyError(product_id)
        if str(product[0]) != "FAILED_SAFE":
            raise ProofObligationError("recovery certificate requires FAILED_SAFE product")
        payload = {
            "product_id": product_id,
            "previous_epoch_key": previous_epoch_key,
            "new_epoch_key": new_epoch_key,
            "root_cause_key": root_cause_key,
            "controller_release_digest": controller_release_digest,
            "policy_schema_digest": policy_schema_digest,
            "fixed_invariant_id": fixed_invariant_id,
            "regression_evidence_ref": regression_evidence_ref,
            "migration_dry_run_digest": migration_dry_run_digest,
            "backup_restore_proof_ref": backup_restore_proof_ref,
        }
        digest = sha256_text(stable_json(payload))
        certificate_id = f"RC-{digest[:24].upper()}"
        self.connection.execute(
            """INSERT INTO recovery_certificates
               (certificate_id,product_id,previous_epoch_key,new_epoch_key,
                root_cause_key,controller_release_digest,policy_schema_digest,
                fixed_invariant_id,regression_evidence_ref,migration_dry_run_digest,
                backup_restore_proof_ref,certificate_digest,status,created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'READY', ?)""",
            (
                certificate_id,
                product_id,
                previous_epoch_key,
                new_epoch_key,
                root_cause_key,
                controller_release_digest,
                policy_schema_digest,
                fixed_invariant_id,
                regression_evidence_ref,
                migration_dry_run_digest,
                backup_restore_proof_ref,
                digest,
                utc_now(),
            ),
        )
        return certificate_id

    def apply(self, *, certificate_id: str, resume_status: str) -> None:
        if resume_status in {"FAILED_SAFE", "COMPLETED", "CANCELLED"}:
            raise ProofObligationError("recovery target must be an active state")
        certificate = self.connection.execute(
            "SELECT * FROM recovery_certificates WHERE certificate_id=? AND status='READY'",
            (certificate_id,),
        ).fetchone()
        if certificate is None:
            raise ProofObligationError("ready recovery certificate is missing")
        product_id = str(certificate["product_id"])
        now = utc_now()
        from .transition_kernel import TransitionKernel

        TransitionKernel(self.connection).apply_product(
            product_id=product_id,
            target=resume_status,
            event=f"RECOVERY_APPLY_TO_{resume_status}",
            evidence={
                "recovery_certificate": str(certificate["certificate_digest"]),
                "new_occurrence_epoch": str(certificate["new_epoch_key"]),
            },
        )
        self.connection.execute(
            """UPDATE recovery_certificates SET status='APPLIED',applied_at=?
                WHERE certificate_id=? AND status='READY'""",
            (now, certificate_id),
        )

    def apply_ready(self, *, product_id: str, resume_status: str) -> str:
        """Consume the sole ready certificate for a historical recovery."""

        rows = self.connection.execute(
            """SELECT certificate_id FROM recovery_certificates
                 WHERE product_id=? AND status='READY'
                 ORDER BY created_at""",
            (product_id,),
        ).fetchall()
        if len(rows) != 1:
            raise ProofObligationError(
                "historical recovery requires exactly one ready recovery certificate"
            )
        certificate_id = str(rows[0][0])
        self.apply(certificate_id=certificate_id, resume_status=resume_status)
        return certificate_id
