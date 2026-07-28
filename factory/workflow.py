"""Durable workflow facade over the controller state store."""

from __future__ import annotations

from dataclasses import dataclass

from .common import new_id
from .state import StateStore


@dataclass(frozen=True)
class WorkflowTask:
    task_id: str
    product_id: str
    title: str
    priority: int
    dependencies: tuple[str, ...]
    conflict_keys: tuple[str, ...]


class WorkflowEngine:
    def __init__(self, state: StateStore) -> None:
        self.state = state

    def transition(self, product_id: str, status: str) -> dict[str, object]:
        return self.state.transition_product(product_id, status)

    def pause(self, product_id: str) -> dict[str, object]:
        return self.transition(product_id, "PAUSED")

    def resume(self, product_id: str, status: str) -> dict[str, object]:
        if status == "PAUSED":
            raise ValueError("resume status must be an active lifecycle state")
        product = self.state.get_product(product_id)
        if product is None:
            raise KeyError(product_id)
        if str(product["status"]) == "PAUSED":
            product = self.transition(product_id, status)
        elif str(product["status"]) in {"CANCELLED", "COMPLETED", "FAILED_SAFE"}:
            raise ValueError(f"cannot resume terminal product {product_id}")
        self.state.requeue_resumable_tasks(product_id)
        return product

    def cancel(self, product_id: str) -> dict[str, object]:
        return self.transition(product_id, "CANCELLED")

    def add_task(
        self,
        *,
        product_id: str,
        title: str,
        dependencies: tuple[str, ...] = (),
        conflict_keys: tuple[str, ...] = (),
        priority: int = 0,
        task_id: str | None = None,
    ) -> WorkflowTask:
        if priority < 0:
            raise ValueError("priority cannot be negative")
        created_id = task_id or new_id("task")
        self.state.add_task(
            task_id=created_id,
            product_id=product_id,
            title=title,
            dependencies=list(dependencies),
            conflict_keys=list(conflict_keys),
            priority=priority,
        )
        return WorkflowTask(created_id, product_id, title, priority, dependencies, conflict_keys)

    def claim(self, worker_id: str, lease_seconds: int = 300) -> dict[str, object] | None:
        return self.state.claim_task(worker_id=worker_id, lease_seconds=lease_seconds)

    def heartbeat(self, task_id: str, worker_id: str, lease_seconds: int = 300) -> None:
        self.state.heartbeat(task_id, worker_id, lease_seconds)

    def complete(self, task_id: str, worker_id: str, status: str = "DONE") -> None:
        self.state.complete_task(task_id, worker_id, status)
