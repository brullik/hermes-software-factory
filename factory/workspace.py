"""Scoped task workspace leases with conflict-safe cleanup."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
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


WorkspaceInitializer = Callable[[str, Path], None]


class WorkspaceManager:
    def __init__(
        self,
        root: Path,
        *,
        source_root: Path | None = None,
        persistent: bool = False,
        initializer: WorkspaceInitializer | None = None,
    ) -> None:
        self.root = root.resolve()
        self.source_root = source_root.resolve() if source_root is not None else None
        self.persistent = persistent
        self.initializer = initializer
        if initializer is not None and source_root is not None:
            raise ValueError("workspace initializer and source root are mutually exclusive")
        if self.source_root == self.root:
            raise ValueError("workspace source root cannot be the workspace root")
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _ignore_source(_directory: str, names: list[str]) -> list[str]:
        return [name for name in names if name in _COPY_IGNORED_DIRS]

    def _initialize(self, product_id: str, path: Path) -> None:
        temporary = path.parent / f".initialize-{new_id('workspace')}"
        assert_under_root(self.root, temporary)
        try:
            if self.initializer is not None:
                self.initializer(product_id, temporary)
            elif self.source_root is not None:
                if not self.source_root.is_dir():
                    raise FileNotFoundError(f"workspace source root is missing: {self.source_root}")
                shutil.copytree(self.source_root, temporary, ignore=self._ignore_source)
            else:
                temporary.mkdir(parents=True)
            if not temporary.is_dir() or temporary.is_symlink():
                raise RuntimeError("workspace initializer did not create a safe directory")
            temporary.replace(path)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)

    def acquire(self, *, product_id: str, task_id: str, worker_id: str) -> WorkspaceLease:
        path = self.root / product_id / ("repository" if self.persistent else task_id)
        assert_under_root(self.root, path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            self._initialize(product_id, path)
        if not path.is_dir() or path.is_symlink():
            raise RuntimeError("workspace path is missing or unsafe")
        marker = path / ".lease.json"
        if marker.exists():
            data = json.loads(marker.read_text(encoding="utf-8"))
            if data.get("worker_id") != worker_id or data.get("task_id") != task_id:
                raise RuntimeError("workspace already leased by another worker")
            return WorkspaceLease(str(data["lease_id"]), task_id, worker_id, path)
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
        if (
            data.get("lease_id") != lease.lease_id
            or data.get("worker_id") != lease.worker_id
            or data.get("task_id") != lease.task_id
        ):
            raise RuntimeError("workspace lease ownership mismatch")
        if self.persistent:
            marker.unlink()
        else:
            shutil.rmtree(path)
