"""Scoped task workspace leases with conflict-safe cleanup."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from scripts.policy_guard import assert_under_root, path_allowed

from .common import new_id, utc_now

_COPY_IGNORED_DIRS = {
    ".git",
    ".deployment",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "build",
    "dist",
    "state",
    "__pycache__",
}


@dataclass(frozen=True)
class WorkspaceLease:
    lease_id: str
    task_id: str
    worker_id: str
    path: Path


class WorkspaceManager:
    def __init__(self, root: Path, *, source_root: Path | None = None) -> None:
        self.root = root.resolve()
        self.source_root = source_root.resolve() if source_root is not None else None
        if self.source_root == self.root:
            raise ValueError("workspace source root cannot be the workspace root")
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _ignore_source(_directory: str, names: list[str]) -> list[str]:
        return [name for name in names if name in _COPY_IGNORED_DIRS]

    def acquire(self, *, product_id: str, task_id: str, worker_id: str) -> WorkspaceLease:
        path = self.root / product_id / task_id
        assert_under_root(self.root, path)
        path.mkdir(parents=True, exist_ok=True)
        marker = path / ".lease.json"
        if marker.exists():
            data = json.loads(marker.read_text(encoding="utf-8"))
            if data.get("worker_id") != worker_id:
                raise RuntimeError("workspace already leased by another worker")
            return WorkspaceLease(str(data["lease_id"]), task_id, worker_id, path)
        if self.source_root is not None:
            if not self.source_root.is_dir():
                raise FileNotFoundError(f"workspace source root is missing: {self.source_root}")
            shutil.copytree(self.source_root, path, dirs_exist_ok=True, ignore=self._ignore_source)
        lease = WorkspaceLease(new_id("lease"), task_id, worker_id, path)
        marker.write_text(
            json.dumps({"lease_id": lease.lease_id, "task_id": task_id, "worker_id": worker_id, "created_at": utc_now()}) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return lease

    def assert_write_allowed(self, lease: WorkspaceLease, relative_path: str, allowed_paths: list[str], forbidden_paths: list[str]) -> Path:
        if not path_allowed(relative_path, allowed_paths, forbidden_paths):
            raise PermissionError(f"Path is outside task scope: {relative_path}")
        candidate = (lease.path / relative_path).resolve()
        return assert_under_root(lease.path, candidate)

    def release(self, lease: WorkspaceLease) -> None:
        path = assert_under_root(self.root, lease.path)
        marker = path / ".lease.json"
        if not marker.is_file():
            raise RuntimeError("workspace lease marker is missing")
        data = json.loads(marker.read_text(encoding="utf-8"))
        if data.get("lease_id") != lease.lease_id or data.get("worker_id") != lease.worker_id:
            raise RuntimeError("workspace lease ownership mismatch")
        shutil.rmtree(path)
