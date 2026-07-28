"""Read-only Kanban projection for the local Hermes controller UI."""

from __future__ import annotations

import json
from typing import Any

from .common import utc_now
from .state import StateStore

KANBAN_COLUMNS = (
    ("intake", "Intake"),
    ("planning", "Planning"),
    ("build", "Build"),
    ("review", "Review"),
    ("deploy", "Deploy"),
    ("blocked", "Blocked"),
    ("done", "Done"),
)

_COLUMN_BY_STATUS = {
    "IDEA_RECEIVED": "intake",
    "CONTRACT_DRAFTED": "planning",
    "CONTRACT_VALIDATED": "planning",
    "RISK_CLASSIFIED": "planning",
    "ARCHITECTED": "planning",
    "BACKLOG_READY": "planning",
    "IMPLEMENTING": "build",
    "REPAIRING": "build",
    "DELAYED_QUOTA": "blocked",
    "BLOCKED_OWNER": "blocked",
    "INTEGRATING": "review",
    "STAGING_DEPLOYED": "review",
    "PRODUCT_ACCEPTANCE": "review",
    "RELEASE_READY": "review",
    "PRODUCTION_DEPLOYED": "deploy",
    "ROLLING_BACK": "deploy",
    "ROLLED_BACK": "deploy",
    "PAUSED": "blocked",
    "FAILED_SAFE": "blocked",
    "OBSERVATION": "done",
    "COMPLETED": "done",
    "CANCELLED": "done",
}


def _column_for(status: str) -> str:
    return _COLUMN_BY_STATUS.get(status, "blocked")


def _dependencies(row: dict[str, Any]) -> list[str]:
    try:
        parsed = json.loads(str(row.get("dependencies_json", "[]")))
    except (TypeError, json.JSONDecodeError):
        return []
    return [item for item in parsed if isinstance(item, str)] if isinstance(parsed, list) else []


def _task_card(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": str(row.get("task_id", "")),
        "title": str(row.get("title", "")),
        "role": row.get("role"),
        "status": str(row.get("status", "PENDING")),
        "priority": int(row.get("priority", 0)),
        "attempts": int(row.get("attempts", 0)),
        "depends_on": _dependencies(row),
        "claimed": row.get("status") == "CLAIMED",
        "updated_at": row.get("updated_at"),
    }


def build_kanban_snapshot(state: StateStore) -> dict[str, Any]:
    """Build a bounded, secret-free view of durable products and tasks."""

    products = state.list_products()
    selected_products = products[-100:]
    selected_ids = {str(product["product_id"]) for product in selected_products}
    tasks = [task for task in state.list_tasks() if str(task.get("product_id")) in selected_ids][:10_000]
    tasks_by_product: dict[str, list[dict[str, Any]]] = {product_id: [] for product_id in selected_ids}
    for task in tasks:
        product_id = str(task.get("product_id", ""))
        if len(tasks_by_product.get(product_id, [])) < 100:
            tasks_by_product.setdefault(product_id, []).append(_task_card(task))

    status_counts: dict[str, int] = {}
    for product in selected_products:
        status = str(product.get("status", "UNKNOWN"))
        status_counts[status] = status_counts.get(status, 0) + 1

    task_status_counts: dict[str, int] = {}
    claimed_workers: set[str] = set()
    for task in tasks:
        status = str(task.get("status", "UNKNOWN"))
        task_status_counts[status] = task_status_counts.get(status, 0) + 1
        worker = task.get("lease_owner")
        if status == "CLAIMED" and worker:
            claimed_workers.add(str(worker))

    cards = [
        {
            "product_id": str(product["product_id"]),
            "status": str(product.get("status", "UNKNOWN")),
            "source": str(product.get("source", "unknown")),
            "created_at": product.get("created_at"),
            "updated_at": product.get("updated_at"),
            "column": _column_for(str(product.get("status", "UNKNOWN"))),
            "tasks": tasks_by_product.get(str(product["product_id"]), []),
        }
        for product in selected_products
    ]
    return {
        "schema_version": "1.0",
        "generated_at": utc_now(),
        "columns": [{"id": key, "title": title} for key, title in KANBAN_COLUMNS],
        "summary": {
            "products_total": len(selected_products),
            "tasks_total": len(tasks),
            "product_statuses": status_counts,
            "task_statuses": task_status_counts,
            "claimed_workers": len(claimed_workers),
        },
        "products": cards,
    }


def _telegram_value(value: object, *, limit: int = 180) -> str:
    """Keep user-controlled task text compact and single-line in Telegram."""

    text = " ".join(str(value or "").split())
    return text[:limit] + ("…" if len(text) > limit else "")


def format_telegram_summary(snapshot: dict[str, Any]) -> str:
    """Format the read-only Kanban projection for a bounded Telegram message."""

    summary = snapshot.get("summary", {})
    products = snapshot.get("products", [])
    columns = snapshot.get("columns", [])
    products_by_column: dict[str, list[dict[str, Any]]] = {str(column["id"]): [] for column in columns}
    for product in products[:20]:
        if isinstance(product, dict):
            products_by_column.setdefault(str(product.get("column", "blocked")), []).append(product)

    lines = [
        "Hermes Kanban (read-only)",
        (
            f"Products: {summary.get('products_total', 0)} | "
            f"Tasks: {summary.get('tasks_total', 0)} | "
            f"Claimed workers: {summary.get('claimed_workers', 0)}"
        ),
    ]
    for column in columns:
        column_id = str(column.get("id", "blocked"))
        title = _telegram_value(column.get("title", column_id), limit=40)
        cards = products_by_column.get(column_id, [])
        lines.append(f"\n{title} ({len(cards)})")
        if not cards:
            lines.append("— empty")
            continue
        for product in cards:
            product_id = _telegram_value(product.get("product_id"), limit=100)
            status = _telegram_value(product.get("status"), limit=60)
            lines.append(f"• {product_id} — {status}")
            tasks = product.get("tasks", [])
            if isinstance(tasks, list):
                for task in tasks[:8]:
                    if not isinstance(task, dict):
                        continue
                    task_id = _telegram_value(task.get("task_id"), limit=80)
                    role = _telegram_value(task.get("role") or "task", limit=40)
                    task_status = _telegram_value(task.get("status"), limit=30)
                    task_title = _telegram_value(task.get("title"), limit=120)
                    lines.append(f"  └ {task_id} | {role}: {task_status} — {task_title}")
                if len(tasks) > 8:
                    lines.append(f"  └ … and {len(tasks) - 8} more tasks")
    text = "\n".join(lines)
    return text[:4096]


KANBAN_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Hermes Kanban</title>
  <style>
    :root { color-scheme: dark; font-family: system-ui, sans-serif; }
    body { margin: 0; background: #10131a; color: #e8edf5; }
    header { padding: 20px 24px 12px; display: flex; justify-content: space-between; gap: 16px; align-items: baseline; }
    h1 { margin: 0; font-size: 1.35rem; }
    #meta { color: #94a3b8; font-size: .85rem; }
    main { overflow-x: auto; padding: 0 24px 24px; }
    #board { display: grid; grid-template-columns: repeat(7, minmax(210px, 1fr)); gap: 12px; min-width: 1510px; }
    .column { background: #181d27; border: 1px solid #293241; border-radius: 10px; min-height: 180px; padding: 10px; }
    .column h2 { font-size: .9rem; margin: 0 0 10px; color: #b9c7dc; }
    .count { color: #64748b; font-weight: normal; }
    .card { background: #222936; border: 1px solid #334155; border-radius: 8px; padding: 10px; margin: 8px 0; }
    .card strong { display: block; overflow-wrap: anywhere; font-size: .86rem; }
    .status, .task { color: #aebbd0; font-size: .76rem; margin-top: 5px; }
    .task { border-top: 1px solid #334155; padding-top: 5px; }
    .error { color: #fca5a5; padding: 24px; }
  </style>
</head>
<body>
  <header><h1>Hermes Kanban</h1><div id="meta">Loading…</div></header>
  <main><div id="board" aria-live="polite"></div></main>
  <script>
    const board = document.getElementById("board");
    const meta = document.getElementById("meta");
    function node(tag, text, className) {
      const element = document.createElement(tag);
      if (className) element.className = className;
      if (text !== undefined) element.textContent = text;
      return element;
    }
    function render(data) {
      board.replaceChildren();
      const columns = new Map(data.columns.map((column) => [column.id, node("section", undefined, "column")]));
      for (const column of data.columns) {
        const section = columns.get(column.id);
        section.append(node("h2", column.title));
        section.dataset.count = "0";
        board.append(section);
      }
      for (const product of data.products) {
        const section = columns.get(product.column) || columns.get("blocked");
        const card = node("article", undefined, "card");
        card.append(node("strong", product.product_id));
        card.append(node("div", product.status + " · " + product.source, "status"));
        for (const task of product.tasks) {
          card.append(node("div", (task.role || "task") + ": " + task.status + " · " + task.title, "task"));
        }
        section.append(card);
        section.dataset.count = String(Number(section.dataset.count) + 1);
      }
      for (const section of columns.values()) {
        const heading = section.querySelector("h2");
        heading.append(node("span", " (" + section.dataset.count + ")", "count"));
      }
      meta.textContent = data.summary.products_total + " product(s) · " + data.summary.tasks_total + " task(s) · updated " + data.generated_at;
    }
    async function refresh() {
      try {
        const response = await fetch("/api/kanban", { cache: "no-store" });
        if (!response.ok) throw new Error("HTTP " + response.status);
        render(await response.json());
      } catch (error) {
        board.replaceChildren(node("div", "Kanban unavailable: " + error.message, "error"));
        meta.textContent = "retrying";
      }
    }
    refresh();
    setInterval(refresh, 5000);
  </script>
</body>
</html>
"""
