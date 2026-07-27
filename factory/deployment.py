"""Deployment policy checks; side effects are delegated to an external adapter."""

from __future__ import annotations

import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .providers import ExternalBlocker


@dataclass(frozen=True)
class DeploymentDecision:
    status: str
    reason: str
    image_digest: str


@dataclass(frozen=True)
class TransactionResult:
    """Outcome of an atomic directory release promotion."""

    release_id: str
    status: str
    current_path: str
    previous_path: str | None
    failed_path: str | None
    reason: str


class DeploymentError(RuntimeError):
    """Raised when a release cannot be promoted without weakening safety."""


class TransactionalDeployer:
    """Promote a prepared release and restore the previous one on failed health.

    The adapter intentionally knows nothing about systemd, Docker, or secrets.
    Callers inject a health probe that observes the real service.  Directory
    moves are kept inside ``install_root`` and the previous release is never
    overwritten, so an interrupted or failed promotion remains diagnosable.
    """

    _RELEASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")

    def __init__(self, install_root: Path, health_probe: Callable[[Path], bool]) -> None:
        self.install_root = install_root.resolve()
        self.health_probe = health_probe

    def _child(self, name: str) -> Path:
        candidate = self.install_root / name
        if candidate.parent != self.install_root:
            raise DeploymentError("deployment path escaped install root")
        return candidate

    @staticmethod
    def _exists(path: Path) -> bool:
        return path.exists() or path.is_symlink()

    @staticmethod
    def _reject_symlinks(source: Path) -> None:
        if source.is_symlink():
            raise DeploymentError("release source must not be a symlink")
        for path in source.rglob("*"):
            if path.is_symlink():
                raise DeploymentError("release source contains a symlink")

    def promote(self, release_id: str, source: Path) -> TransactionResult:
        """Copy ``source`` and atomically promote it after an injected health check."""

        if not self._RELEASE_ID.fullmatch(release_id):
            raise ValueError("release_id contains unsafe characters")
        source = source.resolve()
        if not source.is_dir():
            raise DeploymentError("release source directory is missing")
        if self.install_root == source or self.install_root in source.parents:
            raise DeploymentError("release source must not be inside install root")
        self._reject_symlinks(source)

        self.install_root.mkdir(parents=True, exist_ok=True)
        staged = self._child(f".staged-{release_id}")
        current = self._child("current")
        previous = self._child(f"backup-{release_id}-previous")
        failed = self._child(f"failed-{release_id}")
        for path, label in ((staged, "staged release"), (previous, "previous release"), (failed, "failed release")):
            if self._exists(path):
                raise DeploymentError(f"{label} path already exists")
        if self._exists(current) and current.is_symlink():
            raise DeploymentError("current release must not be a symlink")

        try:
            shutil.copytree(source, staged, symlinks=False)
        except OSError as error:
            if self._exists(staged):
                shutil.rmtree(staged)
            raise DeploymentError("release staging failed") from error

        had_previous = self._exists(current)
        try:
            if had_previous:
                os_replace(current, previous)
            os_replace(staged, current)
        except OSError as error:
            if self._exists(staged):
                shutil.rmtree(staged)
            if had_previous and self._exists(previous) and not self._exists(current):
                os_replace(previous, current)
            raise DeploymentError("release promotion failed") from error

        try:
            healthy = bool(self.health_probe(current))
        except Exception as error:  # noqa: BLE001  # health probes are external and must fail closed
            healthy = False
            reason = f"health_probe_error:{type(error).__name__}"
        else:
            reason = "health probe passed" if healthy else "health probe failed"
        if healthy:
            return TransactionResult(
                release_id,
                "PROMOTED",
                str(current),
                str(previous) if had_previous else None,
                None,
                reason,
            )

        # Keep the failed release for forensic inspection and restore the old
        # directory without deleting user data.
        os_replace(current, failed)
        if had_previous:
            os_replace(previous, current)
            return TransactionResult(
                release_id,
                "ROLLED_BACK",
                str(current),
                str(previous),
                str(failed),
                reason,
            )
        return TransactionResult(release_id, "FAILED_SAFE", str(current), None, str(failed), reason)


def os_replace(source: Path, destination: Path) -> None:
    """Keep directory replacement injectable in tests and explicit at call sites."""

    source.replace(destination)


class DeploymentGuard:
    def promote(
        self,
        *,
        environment: str,
        risk: str,
        image_digest: str,
        staging_digest: str | None,
        stateful: bool,
        offsite_backup_configured: bool,
        current_vps: bool = True,
    ) -> DeploymentDecision:
        if environment not in {"staging", "production"}:
            raise ValueError("environment must be staging or production")
        if not image_digest.startswith("sha256:"):
            raise ValueError("deployment requires an immutable image digest")
        if environment == "production" and staging_digest != image_digest:
            raise ValueError("production must promote the exact staging image digest")
        if environment == "production" and risk == "high" and current_vps:
            raise ExternalBlocker("High-risk production requires a separate VPS")
        if environment == "production" and stateful and not offsite_backup_configured:
            raise ExternalBlocker("Stateful production requires an offsite encrypted backup")
        return DeploymentDecision("READY", "policy checks passed", image_digest)
