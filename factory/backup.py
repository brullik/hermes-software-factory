"""Restic command construction without embedding credentials or secret values."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BackupCommand:
    operation: str
    argv: tuple[str, ...]
    required_environment: tuple[str, ...]


class BackupAdapter:
    def backup(self, *paths: str) -> BackupCommand:
        if not paths:
            raise ValueError("at least one backup path is required")
        return BackupCommand(
            "backup",
            ("restic", "backup", *paths, "--tag", "hermes-factory"),
            ("RESTIC_REPOSITORY", "RESTIC_PASSWORD_FILE"),
        )

    def check(self) -> BackupCommand:
        return BackupCommand("check", ("restic", "check"), ("RESTIC_REPOSITORY", "RESTIC_PASSWORD_FILE"))

    def restore(self, snapshot: str, target: str) -> BackupCommand:
        if not snapshot or not target:
            raise ValueError("snapshot and target are required")
        return BackupCommand(
            "restore",
            ("restic", "restore", snapshot, "--target", target),
            ("RESTIC_REPOSITORY", "RESTIC_PASSWORD_FILE"),
        )
