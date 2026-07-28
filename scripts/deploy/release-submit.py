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

import yaml

ROOT = Path("/opt/hermes-factory/current")
CONFIG_PATH = Path("/etc/hermes-factory/config.yaml")
_SHA = re.compile(r"^[a-f0-9]{40}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_PRODUCT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


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
        with tempfile.TemporaryDirectory(prefix="hermes-release-submit-", dir="/var/tmp") as directory:
            staging = Path(directory)
            _fetch_source(args.repository, args.release_id, staging)
            from factory.release_executor import _release_digest

            source = staging / "source"
            if _release_digest(source) != args.staging_digest:
                raise SubmitError("immutable source does not match accepted staging digest")
            if args.repository == factory_repository:
                trusted_entrypoint = ROOT / "scripts" / "deploy" / "promote-release.py"
                if not trusted_entrypoint.is_file() or trusted_entrypoint.is_symlink():
                    raise SubmitError("trusted release entrypoint is missing")
                result = subprocess.run(
                    [
                        sys.executable,
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
                    cwd=ROOT,
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
        print(json.dumps({"status": "PROMOTED", "release_id": args.release_id}))
        return 0
    except (OSError, SubmitError, ValueError, yaml.YAMLError) as error:
        print(json.dumps({"status": "FAILED_SAFE", "reason": type(error).__name__}))
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
