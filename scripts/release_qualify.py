#!/usr/bin/env python3
"""Run candidate gates and independently sign/install qualification evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from factory.common import sha256_file, sha256_text, stable_json
from factory.qualification_runner import (
    STAGE_RUNNERS,
    QualificationRunError,
    QualificationStageReport,
    run_q0,
    run_q1,
    run_q2,
    run_q3,
    run_q4,
    run_q5,
    run_q6,
)
from factory.release_qualification import (
    QualificationError,
    verify_qualification_manifest_envelope,
)

_SHA256 = re.compile(r"[a-f0-9]{64}")
_SHA40 = re.compile(r"[a-f0-9]{40}")
_VERIFIER_CONFIG_KEYS = {
    "schema_version",
    "request_path",
    "output_path",
    "private_key_path",
    "trusted_public_key_digest",
    "expected_source_commit",
    "expected_candidate_digest",
    "verifier_digest",
    "manifest_install_root",
}


class VerifierConfigurationError(RuntimeError):
    """The root-owned verifier boundary is incomplete or unsafe."""


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise VerifierConfigurationError(f"{label} must be an object")
    return {str(key): item for key, item in value.items()}


def _load_config(path: Path) -> dict[str, Any]:
    metadata = path.stat()
    if not path.is_file() or path.is_symlink():
        raise VerifierConfigurationError("verifier config must be a regular file")
    if os.name != "nt" and (
        metadata.st_uid != 0 or metadata.st_mode & 0o022
    ):
        raise VerifierConfigurationError("verifier config is not root-owned read-only")
    raw = _mapping(yaml.safe_load(path.read_text(encoding="utf-8")), "verifier config")
    if set(raw) != _VERIFIER_CONFIG_KEYS or raw.get("schema_version") != "1.0":
        raise VerifierConfigurationError("verifier config schema is invalid")
    for key in (
        "trusted_public_key_digest",
        "expected_candidate_digest",
        "verifier_digest",
    ):
        if not _SHA256.fullmatch(str(raw.get(key) or "")):
            raise VerifierConfigurationError(f"{key} is invalid")
    if not _SHA40.fullmatch(str(raw.get("expected_source_commit") or "")):
        raise VerifierConfigurationError("expected_source_commit is invalid")
    for key in (
        "request_path",
        "output_path",
        "private_key_path",
        "manifest_install_root",
    ):
        value = Path(str(raw.get(key) or ""))
        if not value.is_absolute():
            raise VerifierConfigurationError(f"{key} must be absolute")
    return raw


def _require_private_file(path: Path) -> None:
    metadata = path.stat()
    if not path.is_file() or path.is_symlink():
        raise VerifierConfigurationError("verifier private key must be a regular file")
    if os.name != "nt" and metadata.st_mode & 0o077:
        raise VerifierConfigurationError("verifier private key permissions are too broad")
    effective_uid = getattr(os, "geteuid", lambda: metadata.st_uid)()
    if os.name != "nt" and metadata.st_uid != effective_uid:
        raise VerifierConfigurationError("verifier private key owner differs")


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    _require_private_file(path)
    try:
        raw = base64.b64decode(path.read_text(encoding="ascii").strip(), validate=True)
    except (OSError, UnicodeError, ValueError) as error:
        raise VerifierConfigurationError("verifier private key encoding is invalid") from error
    if len(raw) != 32:
        raise VerifierConfigurationError("verifier private key length is invalid")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _public_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes_raw()


def _safe_write_once(path: Path, payload: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_text(encoding="utf-8") != payload:
            raise VerifierConfigurationError("immutable verifier output conflicts")
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    try:
        path.chmod(mode)
    except OSError:
        pass


def initialize_key(path: Path) -> str:
    if not path.is_absolute() or path.exists():
        raise VerifierConfigurationError("private key destination must be new and absolute")
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    _safe_write_once(path, base64.b64encode(raw).decode("ascii") + "\n", 0o600)
    return hashlib.sha256(_public_key_bytes(key)).hexdigest()


def key_info(path: Path) -> dict[str, str]:
    """Return only the non-secret Ed25519 verifier identity."""

    public_key = _public_key_bytes(_load_private_key(path))
    return {
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "public_key_digest": hashlib.sha256(public_key).hexdigest(),
        "signature_algorithm": "Ed25519",
    }


def verifier_code_digest(repository_root: Path) -> str:
    """Hash only the independently trusted signing and validation surface."""

    root = repository_root.resolve()
    relative_paths = (
        Path("scripts/release_qualify.py"),
        Path("factory/release_qualification.py"),
        Path("schemas/release-qualification-manifest.schema.json"),
    )
    records = []
    for relative in relative_paths:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise VerifierConfigurationError("verifier trust surface is incomplete")
        records.append((relative.as_posix(), sha256_file(path)))
    return sha256_text(stable_json(records))


def sign_qualification(config_path: Path) -> tuple[Path, str]:
    config = _load_config(config_path)
    private_key = _load_private_key(Path(str(config["private_key_path"])))
    public_key = _public_key_bytes(private_key)
    public_key_digest = hashlib.sha256(public_key).hexdigest()
    if public_key_digest != str(config["trusted_public_key_digest"]):
        raise VerifierConfigurationError("private key does not match root trust")
    request_path = Path(str(config["request_path"]))
    if not request_path.is_file() or request_path.is_symlink():
        raise VerifierConfigurationError("unsigned qualification request is unavailable")
    payload = _mapping(
        json.loads(request_path.read_text(encoding="utf-8")),
        "unsigned qualification payload",
    )
    verifier = _mapping(payload.get("verifier"), "verifier identity")
    expected_public = base64.b64encode(public_key).decode("ascii")
    if verifier != {
        "digest": str(config["verifier_digest"]),
        "public_key": expected_public,
        "public_key_digest": public_key_digest,
        "signature_algorithm": "Ed25519",
    }:
        raise VerifierConfigurationError("unsigned payload verifier identity differs")
    signature = base64.b64encode(
        private_key.sign(stable_json(payload).encode("utf-8"))
    ).decode("ascii")
    envelope = {**payload, "verifier_signature": signature}
    digest = verify_qualification_manifest_envelope(
        envelope,
        trusted_verifier_public_key_digest=str(config["trusted_public_key_digest"]),
        expected_source_commit=str(config["expected_source_commit"]),
        expected_candidate_digest=str(config["expected_candidate_digest"]),
    )
    output = Path(str(config["output_path"]))
    encoded = json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    _safe_write_once(output, encoded, 0o440)
    return output, digest


def install_manifest(config_path: Path) -> tuple[Path, str]:
    effective_uid = getattr(os, "geteuid", lambda: 0)()
    if os.name != "nt" and effective_uid != 0:
        raise VerifierConfigurationError("qualification manifest install requires root")
    config = _load_config(config_path)
    source = Path(str(config["output_path"]))
    envelope = _mapping(json.loads(source.read_text(encoding="utf-8")), "manifest")
    digest = verify_qualification_manifest_envelope(
        envelope,
        trusted_verifier_public_key_digest=str(config["trusted_public_key_digest"]),
        expected_source_commit=str(config["expected_source_commit"]),
        expected_candidate_digest=str(config["expected_candidate_digest"]),
    )
    destination = (
        Path(str(config["manifest_install_root"]))
        / f"{config['expected_source_commit']}.json"
    )
    encoded = json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    _safe_write_once(destination, encoded, 0o444)
    return destination, digest


def _stage_report(
    stage: str,
    repository_root: Path,
    evidence_root: Path,
) -> QualificationStageReport:
    if stage == "Q0_SOURCE_INTEGRITY":
        return run_q0(repository_root, evidence_root)
    if stage == "Q1_STATIC_CONTRACTS":
        return run_q1(repository_root, evidence_root)
    if stage == "Q2_MODEL_CHECKING":
        return run_q2(evidence_root)
    if stage == "Q3_PROPERTY_AND_MUTATION":
        return run_q3(repository_root, evidence_root)
    if stage == "Q4_HISTORICAL_REPLAY":
        return run_q4(repository_root, evidence_root)
    if stage == "Q5_MIGRATION_MATRIX":
        return run_q5(evidence_root)
    if stage == "Q6_SERVICE_E2E":
        return run_q6(repository_root, evidence_root)
    raise VerifierConfigurationError(f"unsupported qualification stage: {stage}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    stage = subparsers.add_parser("stage")
    stage.add_argument("stage", choices=sorted(STAGE_RUNNERS))
    stage.add_argument("--repository-root", type=Path, default=Path.cwd())
    stage.add_argument("--evidence-root", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/hermes-factory/verifier.yaml"),
    )
    install = subparsers.add_parser("install")
    install.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/hermes-factory/verifier.yaml"),
    )
    key = subparsers.add_parser("init-key")
    key.add_argument("--private-key", type=Path, required=True)
    identity = subparsers.add_parser("key-info")
    identity.add_argument("--private-key", type=Path, required=True)
    identity.add_argument("--code-root", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "stage":
            report = _stage_report(args.stage, args.repository_root, args.evidence_root)
            result = {
                "status": "PASS",
                "stage": report.stage,
                "report_digest": report.report_digest,
                "evidence_ref": report.evidence_ref,
                "report_path": report.report_path,
            }
        elif args.command == "verify":
            path, digest = sign_qualification(args.config)
            result = {"status": "PASS", "manifest_digest": digest, "path": str(path)}
        elif args.command == "install":
            path, digest = install_manifest(args.config)
            result = {"status": "PASS", "manifest_digest": digest, "path": str(path)}
        elif args.command == "init-key":
            digest = initialize_key(args.private_key)
            result = {"status": "PASS", "public_key_digest": digest}
        else:
            result = {"status": "PASS", **key_info(args.private_key)}
            if args.code_root is not None:
                result["verifier_digest"] = verifier_code_digest(args.code_root)
    except (
        QualificationError,
        QualificationRunError,
        VerifierConfigurationError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as error:
        print(
            stable_json({"status": "FAIL", "error_type": type(error).__name__}),
            file=sys.stderr,
        )
        return 1
    print(stable_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
