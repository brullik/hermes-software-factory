#!/usr/bin/env python3
"""Promote a validated Hermes release through the transactional deploy adapter."""

# The source-tree import below is intentionally after the path bootstrap so
# this script works both from a checkout and from /opt/hermes-factory/current.
# ruff: noqa: I001

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from factory.deployment import DeploymentError, TransactionalDeployer


SERVICES = (
    "hermes-factory-controller.service",
    "hermes-factory-gateway.service",
    "hermes-factory-worker.service",
)
OPTIONAL_SERVICES = ("hermes-factory-worker-2.service",)
CANDIDATE_RUNTIME_LINK = Path("/opt/hermes-factory-candidate/venv")


def root_owned_immutable_runtime(path: Path) -> bool:
    """Return whether a runtime satisfies the production ownership boundary."""

    metadata = path.stat()
    return os.name == "nt" or (
        metadata.st_uid == 0
        and not metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )


def validate_health_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("health URL must be an HTTP loopback URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("health URL must not contain credentials or query data")
    return value


def run_checked(argv: list[str], *, cwd: Path | None = None) -> None:
    completed = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"allowlisted command failed: {argv[0]}")


def validate_source(source: Path) -> None:
    if not source.is_dir() or source.is_symlink():
        raise DeploymentError("release source directory is missing or unsafe")
    checks = (
        ("verify_version_consistency.py", "--factory-source"),
        ("verify_manifest.py",),
        ("validate_package.py",),
    )
    for command in checks:
        name = command[0]
        script = source / "scripts" / name
        if not script.is_file() or script.is_symlink():
            raise DeploymentError(f"release validation script is missing: {name}")
        run_checked(
            [sys.executable, str(script), *command[1:]],
            cwd=source,
        )


def restart_services() -> None:
    installed_optional = tuple(
        service
        for service in OPTIONAL_SERVICES
        if (Path("/etc/systemd/system") / service).is_file()
    )
    run_checked(["systemctl", "restart", *SERVICES, *installed_optional])


@dataclass
class RuntimeSwitch:
    """Crash-reconcilable switch between the Stable A and Candidate B runtimes."""

    install_root: Path
    release_id: str
    old_release_digest: str
    candidate_release_digest: str
    candidate_runtime_link: Path = CANDIDATE_RUNTIME_LINK
    candidate_runtime_root: Path = Path("/opt/hermes-factory-candidate/venvs")
    candidate_runtime_trust: Callable[[Path], bool] = root_owned_immutable_runtime

    @property
    def runtime_link(self) -> Path:
        return self.install_root / "venv"

    @property
    def preserved_runtime(self) -> Path:
        return self.install_root / f"venv-lts-before-{self.release_id[:12]}"

    @property
    def journal_path(self) -> Path:
        return self.install_root / f".runtime-{self.release_id}.json"

    def _candidate_runtime(self) -> Path:
        target = self.candidate_runtime_link.resolve()
        expected_root = self.candidate_runtime_root.resolve()
        if (
            not target.is_dir()
            or target.parent != expected_root
            or target.name != self.release_id
            or not (target / "bin" / "python").is_file()
        ):
            raise DeploymentError("Candidate runtime is not bound to the release commit")
        if not self.candidate_runtime_trust(target):
            raise DeploymentError("Candidate runtime is not root-owned immutable data")
        return target

    def prepare(self) -> None:
        candidate_runtime = self._candidate_runtime()
        expected = {
            "schema_version": "1.0",
            "release_id": self.release_id,
            "old_release_digest": self.old_release_digest,
            "candidate_release_digest": self.candidate_release_digest,
            "candidate_runtime": str(candidate_runtime),
            "preserved_runtime": str(self.preserved_runtime),
        }
        encoded = json.dumps(expected, sort_keys=True) + "\n"
        if self.journal_path.exists():
            if self.journal_path.is_symlink() or self.journal_path.read_text(encoding="utf-8") != encoded:
                raise DeploymentError("runtime switch journal conflicts")
        else:
            descriptor = os.open(
                self.journal_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o400,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        if self.runtime_link.is_dir() and not self.runtime_link.is_symlink():
            if self.preserved_runtime.exists() or self.preserved_runtime.is_symlink():
                raise DeploymentError("preserved Stable runtime already exists")
            self.runtime_link.replace(self.preserved_runtime)
        elif self.runtime_link.is_symlink() and not (
            self.preserved_runtime.exists() or self.preserved_runtime.is_symlink()
        ):
            self.preserved_runtime.symlink_to(
                self.runtime_link.resolve(), target_is_directory=True
            )
        if not self.preserved_runtime.is_dir():
            raise DeploymentError("Stable runtime rollback target is unavailable")
        current = self.install_root / "current"
        if current.is_dir() and not current.is_symlink():
            self.select_for(current)
        elif not (
            (self.install_root / f"backup-{self.release_id}-previous").is_dir()
            and (self.install_root / f"failed-{self.release_id}").is_dir()
        ):
            raise DeploymentError("runtime switch found an unknown source transaction state")

    def _replace_link(self, target: Path) -> None:
        if self.runtime_link.is_symlink() and self.runtime_link.resolve() == target.resolve():
            return
        if (self.runtime_link.exists() or self.runtime_link.is_symlink()) and not self.runtime_link.is_symlink():
            raise DeploymentError("runtime link boundary contains a directory")
        temporary = self.install_root / f".venv-next-{self.release_id[:12]}"
        if temporary.exists() or temporary.is_symlink():
            if not temporary.is_symlink() or temporary.resolve() != target.resolve():
                raise DeploymentError("runtime switch temporary path conflicts")
        else:
            temporary.symlink_to(target, target_is_directory=True)
        temporary.replace(self.runtime_link)

    def select_for(self, current: Path) -> None:
        from factory.release_executor import _release_digest

        observed = _release_digest(current).removeprefix("sha256:")
        if observed == self.candidate_release_digest:
            self._replace_link(self._candidate_runtime())
        elif observed == self.old_release_digest:
            self._replace_link(self.preserved_runtime)
        else:
            raise DeploymentError("current release is outside the runtime switch contract")

    def activate(self) -> None:
        self.select_for(self.install_root / "current")
        restart_services()


def health_probe(url: str, attempts: int, delay_seconds: float) -> Callable[[Path], bool]:
    if attempts < 1:
        raise ValueError("health attempts must be positive")
    if delay_seconds < 0:
        raise ValueError("health delay cannot be negative")

    def probe(_current: Path) -> bool:
        for attempt in range(attempts):
            try:
                with urlopen(url, timeout=5) as response:
                    status = getattr(response, "status", None)
                    if isinstance(status, int) and 200 <= status < 400:
                        return True
            except (OSError, URLError, TimeoutError):
                pass
            if attempt + 1 < attempts:
                time.sleep(delay_seconds)
        return False

    return probe


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--install-root", default="/opt/hermes-factory", type=Path)
    parser.add_argument("--health-url", default="http://127.0.0.1:8787/healthz")
    parser.add_argument("--health-attempts", default=12, type=int)
    parser.add_argument("--health-delay", default=2.0, type=float)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        health_url = validate_health_url(args.health_url)
        source = args.source.resolve()
        validate_source(source)
        from factory.release_executor import _release_digest

        current = args.install_root.resolve() / "current"
        runtime = RuntimeSwitch(
            install_root=args.install_root.resolve(),
            release_id=args.release_id,
            old_release_digest=_release_digest(current).removeprefix("sha256:"),
            candidate_release_digest=_release_digest(source).removeprefix("sha256:"),
        )
        runtime.prepare()
        run_checked(["systemctl", "start", "hermes-factory-resilience-proof.service"])
        result = TransactionalDeployer(
            args.install_root,
            health_probe(health_url, args.health_attempts, args.health_delay),
            activate=runtime.activate,
        ).promote(args.release_id, source)
    except (DeploymentError, OSError, RuntimeError, ValueError) as error:
        print(json.dumps({"status": "FAILED_SAFE", "reason": type(error).__name__}))
        return 78
    print(json.dumps(result.__dict__, sort_keys=True))
    return 0 if result.status == "PROMOTED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
