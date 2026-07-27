"""Scoped task workspace leases with conflict-safe cleanup."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from scripts.policy_guard import assert_under_root, path_allowed

from .common import new_id, utc_now


@dataclass(frozen=True)
class WorkspaceLease:
    lease_id: str
    task_id: str
    worker_id: str
    path: Path


class WorkspaceManager:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

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
