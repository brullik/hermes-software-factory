"""Signed PRE-Q8 convergence seals and fail-closed official admission checks."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .common import sha256_file, sha256_text, stable_json, utc_now
from .functional_readiness import PRE_Q8_SCENARIOS
from .pre_q8_convergence import validate_run_id

PREQ8_CONVERGENCE_SEAL: Final[str] = "PREQ8_CONVERGENCE_SEAL"
_SHA256: Final[re.Pattern[str]] = re.compile(r"^[a-f0-9]{64}$")
_SHA40: Final[re.Pattern[str]] = re.compile(r"^[a-f0-9]{40}$")


class PreQ8SealError(RuntimeError):
    """A convergence seal is invalid or differs from official Candidate bytes."""


_IDENTITY_FIELDS: Final[tuple[str, ...]] = (
    "git_tree",
    "release_tree_digest",
    "requirements_lock_digest",
    "toolchain_digest",
    "systemd_bundle_digest",
    "catalog_digest",
    "base_config_digest",
    "capability_attestation_digest",
    "fixture_seed_digest",
    "matrix_digest",
)
_DIGEST_IDENTITY_FIELDS: Final[tuple[str, ...]] = tuple(
    field for field in _IDENTITY_FIELDS if field != "git_tree"
)


def qualification_config_semantic_digest(value: Mapping[str, Any]) -> str:
    """Hash Candidate behavior while normalizing required isolation coordinates."""

    payload = copy.deepcopy(dict(value))
    qualification = payload.get("qualification")
    paths = payload.get("paths")
    if not isinstance(qualification, dict) or not isinstance(paths, dict):
        raise PreQ8SealError("qualification config semantic body is invalid")
    state_root = str(paths.get("state") or "")
    log_root = str(paths.get("logs") or "")
    if not state_root or not log_root:
        raise PreQ8SealError("qualification config semantic roots are unavailable")

    def normalized(item: Any) -> Any:
        if isinstance(item, dict):
            return {str(key): normalized(content) for key, content in item.items()}
        if isinstance(item, list):
            return [normalized(content) for content in item]
        if isinstance(item, str):
            return (
                item.replace(state_root, "{SCENARIO_STATE}")
                .replace(Path(state_root).as_posix(), "{SCENARIO_STATE}")
                .replace(log_root, "{SCENARIO_LOGS}")
                .replace(Path(log_root).as_posix(), "{SCENARIO_LOGS}")
            )
        return item

    body = normalized(payload)
    normalized_qualification = body["qualification"]
    normalized_qualification["qualification_plane"] = "{QUALIFICATION_PLANE}"
    normalized_qualification["epoch_id"] = "{RELEASE_EPOCH}"
    if normalized_qualification.get("existing_repository_url"):
        normalized_qualification["existing_repository_url"] = (
            "{EXISTING_REPOSITORY_FIXTURE}"
        )
    network = body.get("network")
    if isinstance(network, dict) and "admin_port" in network:
        network["admin_port"] = "{QUALIFICATION_PORT}"
    deployment = body.get("deployment")
    if isinstance(deployment, dict) and deployment.get("health_probe_url"):
        deployment["health_probe_url"] = "{QUALIFICATION_HEALTH_PROBE}"
    return sha256_text(stable_json(body))


def systemd_bundle_digest(root: Path) -> str:
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise PreQ8SealError("systemd bundle root is unavailable")
    files = sorted((*root.glob("hermes-factory-*.service"), *root.glob("hermes-factory-*.timer")))
    if not files or any(not path.is_file() or path.is_symlink() for path in files):
        raise PreQ8SealError("systemd bundle is incomplete")
    return sha256_text(
        stable_json(
            [[path.name, sha256_file(path)] for path in files]
        )
    )


def _digest(value: object, label: str) -> str:
    normalized = str(value)
    if _SHA256.fullmatch(normalized) is None:
        raise PreQ8SealError(f"{label} is not a SHA-256 digest")
    return normalized


def build_seal_payload(
    *,
    run_id: str,
    source_commit: str,
    git_tree: str,
    release_tree_digest: str,
    requirements_lock_digest: str,
    toolchain_digest: str,
    systemd_bundle_digest: str,
    catalog_digest: str,
    base_config_digest: str,
    generated_config_digests: Mapping[str, str],
    capability_attestation_digest: str,
    fixture_seed_digest: str,
    evidence_digests: Mapping[str, str],
    matrix_digest: str,
    public_key_digest: str,
) -> dict[str, Any]:
    run = validate_run_id(run_id)
    if _SHA40.fullmatch(source_commit) is None or _SHA40.fullmatch(git_tree) is None:
        raise PreQ8SealError("seal Git identity is invalid")
    scalar_digests = {
        "release_tree_digest": release_tree_digest,
        "requirements_lock_digest": requirements_lock_digest,
        "toolchain_digest": toolchain_digest,
        "systemd_bundle_digest": systemd_bundle_digest,
        "catalog_digest": catalog_digest,
        "base_config_digest": base_config_digest,
        "capability_attestation_digest": capability_attestation_digest,
        "fixture_seed_digest": fixture_seed_digest,
        "matrix_digest": matrix_digest,
        "public_key_digest": public_key_digest,
    }
    normalized_scalars = {
        key: _digest(value, key) for key, value in scalar_digests.items()
    }
    generated = {str(key): str(value) for key, value in generated_config_digests.items()}
    evidence = {str(key): str(value) for key, value in evidence_digests.items()}
    if tuple(generated) != PRE_Q8_SCENARIOS or tuple(evidence) != PRE_Q8_SCENARIOS:
        raise PreQ8SealError("seal scenario digests differ from canonical order")
    for scenario_id in PRE_Q8_SCENARIOS:
        _digest(generated[scenario_id], f"generated config {scenario_id}")
        _digest(evidence[scenario_id], f"evidence {scenario_id}")
    return {
        "schema_version": "1.0",
        "seal_type": PREQ8_CONVERGENCE_SEAL,
        "status": "10/10 PASS",
        "run_id": run,
        "source_commit": source_commit,
        "git_tree": git_tree,
        **{
            key: normalized_scalars[key]
            for key in _DIGEST_IDENTITY_FIELDS
            if key != "matrix_digest"
        },
        "ordered_scenarios": list(PRE_Q8_SCENARIOS),
        "generated_config_digests": generated,
        "evidence_digests": evidence,
        "matrix_digest": normalized_scalars["matrix_digest"],
        "verifier_public_key_digest": normalized_scalars["public_key_digest"],
    }


def sign_seal(payload: Mapping[str, Any], private_key_path: Path) -> dict[str, Any]:
    if not private_key_path.is_file() or private_key_path.is_symlink():
        raise PreQ8SealError("seal signing key is unavailable")
    raw = private_key_path.read_bytes()
    if len(raw) != 32:
        raise PreQ8SealError("seal signing key is not raw Ed25519")
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as error:
        raise PreQ8SealError("seal signing key is invalid") from error
    public = private_key.public_key().public_bytes_raw()
    public_digest = hashlib.sha256(public).hexdigest()
    if payload.get("verifier_public_key_digest") != public_digest:
        raise PreQ8SealError("seal signing key differs from verifier trust root")
    unsigned = {str(key): value for key, value in payload.items()}
    seal_digest = sha256_text(stable_json(unsigned))
    signed_body = {**unsigned, "seal_digest": seal_digest}
    signature = base64.b64encode(
        private_key.sign(stable_json(signed_body).encode("utf-8"))
    ).decode("ascii")
    return {**signed_body, "verifier_signature": signature, "signed_at": utc_now()}


def write_seal(path: Path, seal: Mapping[str, Any]) -> tuple[str, Path]:
    encoded = json.dumps(dict(seal), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_text(encoding="utf-8") != encoded:
            raise PreQ8SealError("immutable convergence seal conflicts")
        return str(seal["seal_digest"]), path
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return str(seal["seal_digest"]), path


def verify_seal(
    value: Mapping[str, Any],
    *,
    verifier_public_key: str,
    trusted_public_key_digest: str,
    expected_identity: Mapping[str, object],
    expected_generated_config_digests: Mapping[str, str],
) -> str:
    required = {
        "schema_version",
        "seal_type",
        "status",
        "run_id",
        "source_commit",
        "git_tree",
        "release_tree_digest",
        "requirements_lock_digest",
        "toolchain_digest",
        "systemd_bundle_digest",
        "catalog_digest",
        "ordered_scenarios",
        "base_config_digest",
        "generated_config_digests",
        "capability_attestation_digest",
        "fixture_seed_digest",
        "evidence_digests",
        "matrix_digest",
        "verifier_public_key_digest",
        "seal_digest",
        "verifier_signature",
        "signed_at",
    }
    if set(value) != required:
        raise PreQ8SealError("convergence seal schema differs")
    if (
        value.get("schema_version") != "1.0"
        or value.get("seal_type") != PREQ8_CONVERGENCE_SEAL
        or value.get("status") != "10/10 PASS"
        or tuple(str(item) for item in value.get("ordered_scenarios", ()))
        != PRE_Q8_SCENARIOS
    ):
        raise PreQ8SealError("convergence seal contract differs")
    validate_run_id(str(value["run_id"]))
    if _SHA40.fullmatch(str(value["source_commit"])) is None:
        raise PreQ8SealError("convergence source commit is invalid")
    if value.get("verifier_public_key_digest") != trusted_public_key_digest:
        raise PreQ8SealError("convergence seal trust root differs")
    try:
        public_bytes = base64.b64decode(verifier_public_key, validate=True)
        signature = base64.b64decode(str(value["verifier_signature"]), validate=True)
    except (ValueError, TypeError) as error:
        raise PreQ8SealError("convergence seal signature encoding is invalid") from error
    if len(public_bytes) != 32 or hashlib.sha256(public_bytes).hexdigest() != trusted_public_key_digest:
        raise PreQ8SealError("convergence verifier public key differs")
    unsigned = {
        str(key): item
        for key, item in value.items()
        if key not in {"seal_digest", "verifier_signature", "signed_at"}
    }
    seal_digest = sha256_text(stable_json(unsigned))
    if value.get("seal_digest") != seal_digest:
        raise PreQ8SealError("convergence seal digest differs")
    signed_body = {**unsigned, "seal_digest": seal_digest}
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature, stable_json(signed_body).encode("utf-8")
        )
    except (InvalidSignature, ValueError) as error:
        raise PreQ8SealError("convergence seal signature is invalid") from error
    for field in _IDENTITY_FIELDS:
        if str(value.get(field)) != str(expected_identity.get(field)):
            raise PreQ8SealError(f"convergence seal identity differs: {field}")
    generated = value.get("generated_config_digests")
    if not isinstance(generated, Mapping) or dict(generated) != dict(
        expected_generated_config_digests
    ):
        raise PreQ8SealError("convergence generated config digests differ")
    evidence = value.get("evidence_digests")
    if not isinstance(evidence, Mapping) or tuple(str(key) for key in evidence) != PRE_Q8_SCENARIOS:
        raise PreQ8SealError("convergence evidence set differs")
    for scenario_id in PRE_Q8_SCENARIOS:
        _digest(evidence[scenario_id], f"evidence {scenario_id}")
    for field in _IDENTITY_FIELDS:
        _digest(value[field], field) if field != "git_tree" else None
    return seal_digest


def load_and_verify_seal(
    path: Path,
    *,
    verifier_public_key: str,
    trusted_public_key_digest: str,
    expected_identity: Mapping[str, object],
    expected_generated_config_digests: Mapping[str, str],
) -> tuple[dict[str, Any], str]:
    if not path.is_file() or path.is_symlink():
        raise PreQ8SealError("convergence seal is unavailable")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise PreQ8SealError("convergence seal is not an object")
    normalized = {str(key): item for key, item in value.items()}
    digest = verify_seal(
        normalized,
        verifier_public_key=verifier_public_key,
        trusted_public_key_digest=trusted_public_key_digest,
        expected_identity=expected_identity,
        expected_generated_config_digests=expected_generated_config_digests,
    )
    return normalized, digest
