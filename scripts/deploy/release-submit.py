#!/usr/bin/env python3
"""Root-owned release boundary for the provider worker.

The worker can request only an immutable GitHub commit and the accepted
staging digest. This helper fetches that commit from the configured repository,
checks the digest, and invokes the trusted active release entrypoint. It never
accepts a source path, shell command, or arbitrary install root from the worker.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

import yaml

ROOT = Path("/opt/hermes-factory/current")
CONFIG_PATH = Path("/etc/hermes-factory/config.yaml")
QUALIFICATION_CONTROL_PATH = Path("/etc/hermes-factory/qualification-control.yaml")
QUALIFIED_HELPER_ROOT = Path("/opt/hermes-factory-verifier/current")
QUALIFIED_HELPER_PYTHON = Path("/opt/hermes-factory-verifier/venv/bin/python")
_SHA = re.compile(r"^[a-f0-9]{40}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_PRODUCT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")

for trusted_source in (ROOT, QUALIFIED_HELPER_ROOT):
    if str(trusted_source) not in sys.path:
        sys.path.insert(0, str(trusted_source))


class SubmitError(RuntimeError):
    """Raised when a root release submission is not safe to execute."""


def _run(argv: list[str], *, cwd: Path | None = None) -> None:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SubmitError(f"allowlisted command unavailable: {argv[0]}") from error
    if result.returncode != 0:
        raise SubmitError(f"allowlisted command failed: {argv[0]}")


def _config() -> dict[str, Any]:
    try:
        metadata = CONFIG_PATH.stat()
    except OSError as error:
        raise SubmitError("factory config is unavailable") from error
    if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SubmitError("factory config must be root-owned and not group/world writable")
    data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SubmitError("factory config is not a mapping")
    return data


def _factory_repository(data: dict[str, Any]) -> str:
    github = data.get("github", {})
    if not isinstance(github, dict):
        raise SubmitError("GitHub configuration is invalid")
    repository = f"{github.get('owner', '')}/{github.get('factory_repository', '')}"
    if not _REPOSITORY.fullmatch(repository):
        raise SubmitError("configured repository is invalid")
    return repository


def _configured_owner(data: dict[str, Any]) -> str:
    repository = _factory_repository(data)
    return repository.split("/", 1)[0]


def _install_root(data: dict[str, Any], repository: str, product_id: str) -> Path:
    if repository != _factory_repository(data):
        if repository.split("/", 1)[0] != _configured_owner(data):
            raise SubmitError("product repository owner is not allowlisted")
        if not _PRODUCT_ID.fullmatch(product_id):
            raise SubmitError("external product id is invalid")
        products_root = Path("/opt/hermes-factory-products").resolve()
        install_root = (products_root / product_id).resolve()
        if install_root.parent != products_root:
            raise SubmitError("external product install root escaped its boundary")
        return install_root
    deployment = data.get("deployment", {})
    target = deployment.get("production_target", {}) if isinstance(deployment, dict) else {}
    configured = target.get("install_root") if isinstance(target, dict) else None
    install_root = Path(str(configured or "/opt/hermes-factory")).resolve()
    if install_root != Path("/opt/hermes-factory"):
        raise SubmitError("only the configured Hermes install root is permitted")
    return install_root


def _load_factory_qualification_manifest(
    data: dict[str, Any],
    *,
    release_id: str,
    staging_digest: str,
) -> str:
    """Verify a root-owned independent manifest before self-hosting promotion."""

    _ = data
    try:
        control_metadata = QUALIFICATION_CONTROL_PATH.stat()
        control = yaml.safe_load(QUALIFICATION_CONTROL_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise SubmitError("qualification trust configuration is unavailable") from error
    if (
        QUALIFICATION_CONTROL_PATH.is_symlink()
        or not isinstance(control, dict)
        or control_metadata.st_uid != 0
        or control_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or control.get("source_commit") != release_id
        or control.get("candidate_digest") != staging_digest.removeprefix("sha256:")
    ):
        raise SubmitError("qualification trust configuration differs from release")
    manifest_root = Path("/etc/hermes-factory/qualification-manifests")
    trust_digest = str(control.get("trusted_verifier_public_key_digest") or "")
    path = manifest_root / f"{release_id}.json"
    try:
        metadata = path.stat()
    except OSError as error:
        raise SubmitError("release qualification manifest is unavailable") from error
    if (
        path.is_symlink()
        or not path.is_file()
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise SubmitError("release qualification manifest is not root-owned immutable data")
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SubmitError("release qualification manifest is unreadable") from error
    if not isinstance(envelope, dict):
        raise SubmitError("release qualification manifest is not an object")
    from factory.release_qualification import (
        QualificationError,
        verify_qualification_manifest_envelope,
    )

    try:
        return verify_qualification_manifest_envelope(
            envelope,
            trusted_verifier_public_key_digest=trust_digest,
            expected_source_commit=release_id,
            expected_candidate_digest=staging_digest.removeprefix("sha256:"),
        )
    except QualificationError as error:
        raise SubmitError("release qualification manifest verification failed") from error


def _write_json_exclusive(path: Path, payload: dict[str, Any]) -> None:
    content = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        if path.read_text(encoding="utf-8") != content:
            raise SubmitError(f"immutable metadata conflict: {path.name}") from None


def _root_receipt_path(product_id: str, release_id: str) -> Path:
    identity = product_id or "hermes-factory"
    if not _PRODUCT_ID.fullmatch(identity) or not _SHA.fullmatch(release_id):
        raise SubmitError("root receipt identity is invalid")
    return (
        Path("/var/lib/hermes-factory/evidence")
        / f"root-release-{identity}-{release_id[:12]}.json"
    )


def _factory_health_ready() -> bool:
    try:
        with urlopen("http://127.0.0.1:8787/healthz", timeout=5) as response:
            status = getattr(response, "status", None)
            return isinstance(status, int) and 200 <= status < 400
    except (OSError, URLError, TimeoutError):
        return False


def _reconcile_root_receipt(
    *,
    receipt_path: Path,
    install_root: Path,
    expected: dict[str, Any],
    require_factory_health: bool,
) -> dict[str, Any] | None:
    """Prove an already-applied exact release without repeating its effects."""

    current = install_root / "current"
    if not current.is_dir() or current.is_symlink():
        return None
    from factory.release_executor import _release_digest

    if _release_digest(current) != expected["image_digest"]:
        return None
    if require_factory_health:
        runtime = install_root / "venv"
        expected_runtime = (
            Path("/opt/hermes-factory-candidate/venvs") / str(expected["release_id"])
        ).resolve()
        if (
            not runtime.is_symlink()
            or runtime.resolve() != expected_runtime
            or not (expected_runtime / "bin" / "python").is_file()
            or not _factory_health_ready()
        ):
            return None
    if receipt_path.exists():
        if receipt_path.is_symlink() or not receipt_path.is_file():
            raise SubmitError("root release receipt is unsafe")
        try:
            persisted = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise SubmitError("root release receipt is unreadable") from error
        if persisted != expected:
            raise SubmitError("root release receipt conflicts with requested release")
    else:
        _write_json_exclusive(receipt_path, expected)
    return {**expected, "reconciliation": "verified_postcondition"}


def _bind_external_product(install_root: Path, product_id: str, repository: str) -> None:
    install_root.mkdir(parents=True, exist_ok=True)
    _write_json_exclusive(
        install_root / "product-binding.json",
        {
            "product_id": product_id,
            "repository": repository,
        },
    )


def _promote_external_product(
    *,
    source: Path,
    install_root: Path,
    product_id: str,
    repository: str,
    release_id: str,
    staging_digest: str,
) -> None:
    from factory.deployment import TransactionalDeployer
    from factory.release_executor import _release_digest

    _bind_external_product(install_root, product_id, repository)
    _run(["systemctl", "start", "hermes-factory-backup.service"])
    transaction = TransactionalDeployer(
        install_root,
        health_probe=lambda current: _release_digest(current) == staging_digest,
    ).promote(release_id, source)
    if transaction.status != "PROMOTED":
        raise SubmitError(f"external product transaction did not promote: {transaction.status}")
    _write_json_exclusive(
        Path("/var/lib/hermes-factory/evidence")
        / f"product-release-{product_id}-{release_id[:12]}.json",
        {
            "product_id": product_id,
            "repository": repository,
            "release_id": release_id,
            "image_digest": staging_digest,
            "transaction": transaction.__dict__,
        },
    )


def _extract_archive(archive: bytes, destination: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as handle:
        members = handle.getmembers()
        for member in members:
            name = Path(member.name)
            target = (destination / name).resolve()
            if name.is_absolute() or target != destination and destination not in target.parents:
                raise SubmitError("Git archive contains a path escape")
            if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                raise SubmitError("Git archive contains an unsupported entry")
        for member in members:
            target = (destination / member.name).resolve()
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                os.chmod(target, member.mode & 0o777)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = handle.extractfile(member)
            if extracted is None:
                raise SubmitError("Git archive file could not be read")
            with target.open("wb") as output:
                shutil.copyfileobj(extracted, output)
            os.chmod(target, member.mode & 0o777)


def _fetch_source(repository: str, release_id: str, destination: Path) -> None:
    repository_dir = destination / "repository"
    source_dir = destination / "source"
    _run(["git", "init", "--quiet", str(repository_dir)])
    _run(["git", "-C", str(repository_dir), "remote", "add", "origin", f"https://github.com/{repository}.git"])
    _run(["git", "-C", str(repository_dir), "fetch", "--quiet", "--depth", "1", "origin", release_id])
    archive = subprocess.run(
        ["git", "-C", str(repository_dir), "archive", "--format=tar", release_id],
        capture_output=True,
        check=False,
        timeout=120,
    )
    if archive.returncode != 0:
        raise SubmitError("immutable release archive could not be created")
    source_dir.mkdir()
    _extract_archive(archive.stdout, source_dir)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--product-id", default="")
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--staging-digest", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    if getattr(os, "geteuid", lambda: -1)() != 0:
        print(json.dumps({"status": "FAILED_SAFE", "reason": "root_required"}))
        return 78
    args = build_parser().parse_args(argv)
    try:
        if not _REPOSITORY.fullmatch(args.repository):
            raise SubmitError("repository contains unsafe characters")
        if not _SHA.fullmatch(args.release_id):
            raise SubmitError("release id must be an immutable commit SHA")
        if not _DIGEST.fullmatch(args.staging_digest):
            raise SubmitError("staging digest is invalid")
        data = _config()
        install_root = _install_root(data, args.repository, args.product_id)
        factory_repository = _factory_repository(data)
        qualification_manifest_digest = (
            _load_factory_qualification_manifest(
                data,
                release_id=args.release_id,
                staging_digest=args.staging_digest,
            )
            if args.repository == factory_repository
            else None
        )
        receipt_path = _root_receipt_path(args.product_id, args.release_id)
        receipt_payload = {
            "schema_version": "1.0",
            "status": "PROMOTED",
            "repository": args.repository,
            "product_id": args.product_id,
            "release_id": args.release_id,
            "image_digest": args.staging_digest,
        }
        if qualification_manifest_digest is not None:
            receipt_payload["qualification_manifest_digest"] = (
                qualification_manifest_digest
            )
        reconciled = _reconcile_root_receipt(
            receipt_path=receipt_path,
            install_root=install_root,
            expected=receipt_payload,
            require_factory_health=args.repository == factory_repository,
        )
        if reconciled is not None:
            print(json.dumps(reconciled, sort_keys=True))
            return 0
        with tempfile.TemporaryDirectory(prefix="hermes-release-submit-", dir="/var/tmp") as directory:
            staging = Path(directory)
            _fetch_source(args.repository, args.release_id, staging)
            from factory.release_executor import _release_digest

            source = staging / "source"
            if _release_digest(source) != args.staging_digest:
                raise SubmitError("immutable source does not match accepted staging digest")
            if args.repository == factory_repository:
                trusted_entrypoint = QUALIFIED_HELPER_ROOT / "scripts" / "deploy" / "promote-release.py"
                if (
                    not trusted_entrypoint.is_file()
                    or trusted_entrypoint.is_symlink()
                    or not QUALIFIED_HELPER_PYTHON.is_file()
                ):
                    raise SubmitError("trusted release entrypoint is missing")
                result = subprocess.run(
                    [
                        str(QUALIFIED_HELPER_PYTHON),
                        str(trusted_entrypoint),
                        "--release-id",
                        args.release_id,
                        "--source",
                        str(source),
                        "--install-root",
                        str(install_root),
                        "--health-url",
                        "http://127.0.0.1:8787/healthz",
                    ],
                    cwd=QUALIFIED_HELPER_ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=900,
                )
                if result.returncode != 0:
                    raise SubmitError("trusted release entrypoint failed")
            else:
                _promote_external_product(
                    source=source,
                    install_root=install_root,
                    product_id=args.product_id,
                    repository=args.repository,
                    release_id=args.release_id,
                    staging_digest=args.staging_digest,
                )
        _write_json_exclusive(receipt_path, receipt_payload)
        print(json.dumps({**receipt_payload, "reconciliation": "executed"}, sort_keys=True))
        return 0
    except (OSError, SubmitError, ValueError, yaml.YAMLError) as error:
        print(json.dumps({"status": "FAILED_SAFE", "reason": type(error).__name__}))
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
