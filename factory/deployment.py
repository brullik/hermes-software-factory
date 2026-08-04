"""Deployment policy checks; side effects are delegated to an external adapter."""

from __future__ import annotations

import hashlib
import json
import os
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

    def __init__(
        self,
        install_root: Path,
        health_probe: Callable[[Path], bool],
        activate: Callable[[], None] | None = None,
    ) -> None:
        self.install_root = install_root.resolve()
        self.health_probe = health_probe
        self.activate = activate

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

    @classmethod
    def _tree_digest(cls, source: Path) -> str:
        cls._reject_symlinks(source)
        digest = hashlib.sha256()
        for path in sorted(
            source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()
        ):
            if not path.is_file():
                continue
            relative = path.relative_to(source).as_posix().encode("utf-8")
            content = path.read_bytes()
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
        return digest.hexdigest()

    def _activate_and_probe(self, current: Path) -> tuple[bool, str]:
        try:
            if self.activate is not None:
                self.activate()
            healthy = bool(self.health_probe(current))
        except Exception as error:  # noqa: BLE001  # injected external observation
            return False, f"activation_or_health_error:{type(error).__name__}"
        return healthy, "health probe passed" if healthy else "health probe failed"

    def _journal_path(self, release_id: str) -> Path:
        return self._child(f".transaction-{release_id}.json")

    def _write_journal(
        self,
        *,
        release_id: str,
        source_digest: str,
        status: str,
    ) -> None:
        path = self._journal_path(release_id)
        temporary = path.with_suffix(".json.tmp")
        content = json.dumps(
            {
                "release_id": release_id,
                "source_digest": source_digest,
                "status": status,
            },
            sort_keys=True,
        ) + "\n"
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)

    def _load_journal(self, release_id: str, source_digest: str) -> str | None:
        path = self._journal_path(release_id)
        if not path.is_file() or path.is_symlink():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise DeploymentError("deployment transaction journal is corrupt") from error
        if (
            not isinstance(payload, dict)
            or payload.get("release_id") != release_id
            or payload.get("source_digest") != source_digest
            or payload.get("status")
            not in {"PREPARED", "PROMOTED", "ROLLED_BACK", "FAILED_SAFE"}
        ):
            raise DeploymentError("deployment transaction journal conflicts with source")
        return str(payload["status"])

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
        source_digest = self._tree_digest(source)

        self.install_root.mkdir(parents=True, exist_ok=True)
        staged = self._child(f".staged-{release_id}")
        current = self._child("current")
        previous = self._child(f"backup-{release_id}-previous")
        failed = self._child(f"failed-{release_id}")
        if self._exists(current) and current.is_symlink():
            raise DeploymentError("current release must not be a symlink")
        journal_status = self._load_journal(release_id, source_digest)
        if self._exists(failed):
            if (
                journal_status == "PREPARED"
                and failed.is_dir()
                and not failed.is_symlink()
                and self._tree_digest(failed) == source_digest
            ):
                if not self._exists(current) and self._exists(previous):
                    os_replace(previous, current)
                if self._exists(current) and not self._exists(previous):
                    reason = "reconciled interrupted rollback"
                    if self.activate is not None:
                        try:
                            self.activate()
                        except Exception as error:  # noqa: BLE001 - external activation boundary
                            reason += f"; rollback_activation_error:{type(error).__name__}"
                    self._write_journal(
                        release_id=release_id,
                        source_digest=source_digest,
                        status="ROLLED_BACK",
                    )
                    return TransactionResult(
                        release_id,
                        "ROLLED_BACK",
                        str(current),
                        str(previous),
                        str(failed),
                        reason,
                    )
            raise DeploymentError("failed release path already exists")
        if journal_status in {"ROLLED_BACK", "FAILED_SAFE"}:
            raise DeploymentError("failed deployment transaction cannot be replayed")
        journal_existed = journal_status is not None
        if not journal_existed and (self._exists(staged) or self._exists(previous)):
            raise DeploymentError("deployment paths exist without a transaction journal")
        if not journal_existed:
            self._write_journal(
                release_id=release_id,
                source_digest=source_digest,
                status="PREPARED",
            )

        # Reconcile an interrupted call after the atomic current swap.  The
        # exact source digest is the idempotency identity; no second copy or
        # directory swap is performed.
        if (
            journal_existed
            and self._exists(current)
            and self._tree_digest(current) == source_digest
        ):
            try:
                healthy = bool(self.health_probe(current))
            except Exception:  # noqa: BLE001  # injected external observation
                healthy = False
            if healthy:
                reason = "health probe passed without repeated activation"
            else:
                healthy, reason = self._activate_and_probe(current)
            if healthy:
                self._write_journal(
                    release_id=release_id,
                    source_digest=source_digest,
                    status="PROMOTED",
                )
                return TransactionResult(
                    release_id,
                    "PROMOTED",
                    str(current),
                    str(previous) if self._exists(previous) else None,
                    None,
                    f"reconciled: {reason}",
                )
            os_replace(current, failed)
            if self._exists(previous):
                os_replace(previous, current)
                if self.activate is not None:
                    try:
                        self.activate()
                    except Exception as error:  # noqa: BLE001 - external activation boundary
                        reason = f"{reason}; rollback_activation_error:{type(error).__name__}"
                self._write_journal(
                    release_id=release_id,
                    source_digest=source_digest,
                    status="ROLLED_BACK",
                )
                return TransactionResult(
                    release_id,
                    "ROLLED_BACK",
                    str(current),
                    str(previous),
                    str(failed),
                    f"reconciled: {reason}",
                )
            self._write_journal(
                release_id=release_id,
                source_digest=source_digest,
                status="FAILED_SAFE",
            )
            return TransactionResult(
                release_id,
                "FAILED_SAFE",
                str(current),
                None,
                str(failed),
                f"reconciled: {reason}",
            )

        staged_preexisting = self._exists(staged)
        if self._exists(previous) and not self._exists(current) and not staged_preexisting:
            raise DeploymentError("previous release exists without an interrupted staged release")
        if staged_preexisting:
            if staged.is_symlink() or self._tree_digest(staged) != source_digest:
                raise DeploymentError("interrupted staged release does not match source")
        else:
            try:
                shutil.copytree(source, staged, symlinks=False)
            except OSError as error:
                if self._exists(staged):
                    shutil.rmtree(staged)
                raise DeploymentError("release staging failed") from error

        had_previous = self._exists(current)
        if self._exists(previous) and had_previous:
            raise DeploymentError("previous release path conflicts with current release")
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

        healthy, reason = self._activate_and_probe(current)
        if healthy:
            self._write_journal(
                release_id=release_id,
                source_digest=source_digest,
                status="PROMOTED",
            )
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
            if self.activate is not None:
                try:
                    self.activate()
                except Exception as error:  # noqa: BLE001 - external activation boundary
                    reason = f"{reason}; rollback_activation_error:{type(error).__name__}"
            self._write_journal(
                release_id=release_id,
                source_digest=source_digest,
                status="ROLLED_BACK",
            )
            return TransactionResult(
                release_id,
                "ROLLED_BACK",
                str(current),
                str(previous),
                str(failed),
                reason,
            )
        self._write_journal(
            release_id=release_id,
            source_digest=source_digest,
            status="FAILED_SAFE",
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
