"""Durable reconciliation, repair-cycle, watchdog, and owner notification logic."""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from scripts.model_router import FailureClass, Tier, classify_failure, next_tier

from .artifacts import ArtifactStore, artifact_metadata
from .common import new_id, sha256_text
from .config import FactoryConfig
from .owner_actions import OwnerActionService
from .pipeline import PipelineCoordinator
from .policy import load_policies, owner_action_allowed
from .state import StateStore
from .workflow import WorkflowEngine

LOGGER = logging.getLogger(__name__)

_TERMINAL_PRODUCTS = {"CANCELLED", "COMPLETED", "FAILED_SAFE"}
_NON_RUNNING_PRODUCTS = {"PAUSED", "BLOCKED_OWNER"}
_HANDOFF_ROLES = {
    "test-engineer",
    "security-reviewer",
    "independent-reviewer",
    "release-operator",
    "product-tester",
}

_REASON_RU = {
    "pm_acceptance_failed": "обязательная проверка GitHub pm-acceptance завершилась ошибкой",
    "product_acceptance_blocked": "пользовательская проверка продукта потребовала исправления",
    "mandatory_gate_failed": "не пройдена обязательная проверка качества",
    "model_requested_repair": "исполнитель подтвердил необходимость исправления",
    "schema_validation": "ответ исполнителя не прошёл проверку схемы",
    "scope_violation": "изменения вышли за разрешённые пути задачи",
    "release_adapter_error": "адаптер релиза завершился внутренней ошибкой",
    "release_adapter_blocked": "адаптер релиза не смог продолжить автоматически",
    "worker_internal_error": "worker завершился внутренней ошибкой",
    "malformed_transport": "провайдер вернул повреждённый транспортный ответ",
    "provider_unavailable": "ни один разрешённый провайдер модели не доступен",
    "internal_blocker": "обнаружена внутренняя блокировка конвейера",
}


@dataclass(frozen=True)
class ReconcileResult:
    inspected: int = 0
    repaired: int = 0
    owner_actions: int = 0
    exhausted: int = 0
    recovered_successors: int = 0


class PipelineReconciler:
    """Guarantee that every running product has durable next work."""

    def __init__(
        self,
        config: FactoryConfig,
        state: StateStore,
        artifacts: ArtifactStore | None = None,
    ) -> None:
        self.config = config
        self.state = state
        self.artifacts = artifacts or ArtifactStore(config)
        self.pipeline = PipelineCoordinator(config, state, self.artifacts)
        self.workflow = WorkflowEngine(state)
        self.owner_actions = OwnerActionService(config)
        routing = load_policies(config).get("model-routing", {})
        global_policy = routing.get("global", {}) if isinstance(routing, dict) else {}
        configured_limits = (
            global_policy.get("semantic_attempts_per_tier", {})
            if isinstance(global_policy, dict)
            else {}
        )
        self.semantic_limits = {
            "luna": int(configured_limits.get("luna", 2)),
            "terra": int(configured_limits.get("terra", 2)),
            "sol": int(configured_limits.get("sol", 1)),
        }
        transient = (
            global_policy.get("transient_retries", {})
            if isinstance(global_policy, dict)
            else {}
        )
        self.transient_limit = int(transient.get("max", 3))

    @staticmethod
    def _reason_text(reason_code: str, detail: str | None = None) -> str:
        base = _REASON_RU.get(reason_code, reason_code.replace("_", " "))
        clean_detail = (detail or "").strip().replace("\x00", "")[:1200]
        return f"{base}: {clean_detail}" if clean_detail and clean_detail != reason_code else base

    def _enqueue_notification(
        self,
        *,
        product_id: str,
        kind: str,
        text: str,
        task_id: str | None = None,
        discriminator: str = "",
    ) -> bool:
        digest = sha256_text(
            f"telegram:{product_id}:{kind}:{task_id or ''}:{discriminator}"
        )
        return self.state.enqueue_outbox(
            outbox_id=f"outbox-{digest[:24]}",
            idempotency_key=digest,
            event_type="telegram.owner_notification",
            payload={
                "kind": kind,
                "product_id": product_id,
                "task_id": task_id,
                "text": text[:4096],
            },
        )

    def _watchdog_incident(self, product: dict[str, Any], task: dict[str, Any] | None) -> None:
        product_id = str(product["product_id"])
        task_id = str(task["task_id"]) if task else None
        reason = str(task.get("terminal_reason") or "empty_pipeline") if task else "empty_pipeline"
        self.state.record_event(
            product_id=product_id,
            task_id=task_id,
            event_type="watchdog_incident",
            payload={
                "reason": reason,
                "product_status": product["status"],
                "action": "automatic_reconcile",
            },
        )
        self._enqueue_notification(
            product_id=product_id,
            task_id=task_id,
            kind="automatic_repair",
            discriminator=f"{task_id}:{reason}:{task.get('attempts', 0) if task else 0}",
            text=(
                "⚠️ Hermes обнаружил разрыв конвейера и запустил автоматическое "
                f"восстановление.\nПроект: {product_id}\n"
                f"Причина: {self._reason_text(reason)}\n"
                "Действие владельца: не требуется."
            ),
        )

    def _task_reason(self, task: dict[str, Any]) -> tuple[str, str]:
        reason = str(task.get("terminal_reason") or "").strip()
        detail = str(task.get("terminal_detail") or reason).strip()
        attempts = self.state.attempts_for_task(str(task["task_id"]))
        if not reason and attempts:
            reason = str(attempts[-1].get("reason_code") or "").strip()
        if not reason:
            reason = "internal_blocker"
        result_ref = str(task.get("result_ref") or "")
        if result_ref:
            candidate = Path(result_ref)
            if not candidate.is_absolute():
                candidate = self.config.evidence_dir / candidate.name
            if candidate.is_file() and candidate.parent.resolve() == self.config.evidence_dir.resolve():
                try:
                    payload = json.loads(candidate.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError):
                    payload = None
                if isinstance(payload, dict):
                    detail = str(payload.get("summary") or reason)
        return reason, detail

    def _next_repair_tier(self, task: dict[str, Any], reason: str) -> str | None:
        attempts = self.state.attempts_for_task(str(task["task_id"]))
        if classify_failure(reason) is FailureClass.TRANSIENT:
            transient_count = sum(
                1 for item in attempts if str(item.get("attempt_kind")) == "transient_retry"
            )
            if transient_count >= self.transient_limit:
                return None
            current = str(
                (attempts[-1].get("tier") if attempts else None)
                or task.get("next_tier")
                or "luna"
            )
            return current if current in self.semantic_limits else "luna"

        semantic_counts = {
            tier: sum(
                1
                for item in attempts
                if str(item.get("tier")) == tier and bool(item.get("semantic_counted"))
            )
            for tier in self.semantic_limits
        }
        contract_path = self.config.evidence_dir / f"task-{task['task_id']}.json"
        try:
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            contract = {}
        current_value = str(
            (attempts[-1].get("tier") if attempts else None)
            or task.get("next_tier")
            or (contract.get("model_floor") if isinstance(contract, dict) else None)
            or "luna"
        )
        try:
            current = Tier(current_value)
        except ValueError:
            current = Tier.LUNA
        while current is not Tier.DETERMINISTIC:
            if semantic_counts[current.value] < self.semantic_limits[current.value]:
                return current.value
            promoted = next_tier(current)
            if promoted is None:
                return None
            current = promoted
        return "luna"

    def _write_same_task_repair(
        self,
        task: dict[str, Any],
        *,
        reason: str,
        detail: str,
        tier: str,
    ) -> str:
        task_id = str(task["task_id"])
        product_id = str(task["product_id"])
        contract_path = self.config.evidence_dir / f"task-{task_id}.json"
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        attempts = self.state.attempts_for_task(task_id)
        attempt_id = (
            str(attempts[-1]["attempt_id"]) if attempts else new_id("reconcile-attempt")
        )
        evidence_refs = [
            value
            for value in (
                str(task.get("result_ref") or ""),
                f"evidence/{contract_path.name}",
            )
            if value
        ]
        brief = {
            **artifact_metadata(
                self.config,
                "repair-coordinator",
                new_id("repair-brief"),
                product_id,
            ),
            "producer": {
                "role": "repair-coordinator",
                "tier": "deterministic",
                "provider": None,
                "model": None,
            },
            "task_id": task_id,
            "attempt_id": attempt_id,
            "failure_class": reason,
            "failed_gate_ids": ["pm-acceptance"] if "pm_acceptance" in reason else [],
            "relevant_log_fragment": detail[:4000],
            "expected_vs_actual": {
                "expected": "the task satisfies every mandatory acceptance criterion",
                "actual": detail[:1000],
            },
            "changed_files": [],
            "forbidden_actions": [str(item) for item in contract["forbidden_paths"]],
            "previous_attempt_summary": detail[:2000],
            "definition_of_done": [
                str(item["verification"]) for item in contract["acceptance"]
            ],
            "evidence_refs": list(dict.fromkeys(evidence_refs)),
        }
        path = self.artifacts.write(
            "repair-brief.schema.json",
            brief,
            filename=f"repair-brief-{task_id}-{new_id('reconcile')}.json",
        )
        self.state.requeue_terminal_task(
            task_id,
            next_tier=tier,
            repair_context_ref=f"evidence/{path.name}",
        )
        return f"evidence/{path.name}"

    def _owner_action(
        self,
        product: dict[str, Any],
        task: dict[str, Any],
        reason: str,
        detail: str,
    ) -> None:
        product_id = str(product["product_id"])
        title = "Требуется внешнее действие владельца"
        single_action = (
            "Подключите или восстановите требуемый внешний доступ, следуя безопасной "
            "инструкции на VPS."
        )
        instruction = [
            "Откройте отдельный сеанс PuTTY к VPS.",
            "Запустите официальный OAuth/credential setup для указанного сервиса.",
            "Не отправляйте пароль, токен или private key в Telegram или чат.",
        ]
        if reason == "paid_resource_purchase":
            single_action = "Предоставьте требуемый внешний ресурс и подтвердите его доступность."
            instruction = [
                "Создайте ресурс только в официальной панели поставщика.",
                "Не отправляйте платёжные данные или секреты в Telegram.",
            ]
        action_path = self.owner_actions.create(
            reason=reason,
            title=title,
            why_blocked=self._reason_text(reason, detail),
            single_action=single_action,
            safe_instruction=instruction,
            unblock_probe=f"factory external-probe --product {product_id}",
            unblock_expected="PASS",
            independent_work_continues=["Состояние проекта и evidence сохранены."],
        )
        if str(product["status"]) != "BLOCKED_OWNER":
            self.workflow.transition(product_id, "BLOCKED_OWNER")
        self._enqueue_notification(
            product_id=product_id,
            task_id=str(task["task_id"]),
            kind="owner_action",
            discriminator=action_path.name,
            text=(
                "🟠 Hermes: требуется одно действие владельца.\n"
                f"Проект: {product_id}\n"
                f"Причина: {self._reason_text(reason, detail)}\n"
                f"Действие: {single_action}\n"
                "Секреты в Telegram не отправляйте.\n"
                "После выполнения Hermes проверит условие возобновления."
            ),
        )

    def _exhaust(
        self,
        product: dict[str, Any],
        task: dict[str, Any],
        reason: str,
        detail: str,
    ) -> None:
        product_id = str(product["product_id"])
        if str(product["status"]) != "FAILED_SAFE":
            self.workflow.transition(product_id, "FAILED_SAFE")
        attempts = len(self.state.attempts_for_task(str(task["task_id"])))
        self.state.record_event(
            product_id=product_id,
            task_id=str(task["task_id"]),
            event_type="repair_budget_exhausted",
            payload={"reason_code": reason, "attempts": attempts},
        )
        self._enqueue_notification(
            product_id=product_id,
            task_id=str(task["task_id"]),
            kind="repair_exhausted",
            discriminator=f"{reason}:{attempts}",
            text=(
                "⛔ Hermes исчерпал автоматические попытки исправления.\n"
                f"Проект: {product_id}\n"
                f"Этап: {task.get('title')}\n"
                f"Точная причина: {self._reason_text(reason, detail)}\n"
                f"Выполнено попыток для задачи: {attempts}.\n"
                "OWNER_ACTION не создан: это технический инцидент, а не внешний доступ."
            ),
        )

    def _recover_successor(
        self,
        product: dict[str, Any],
        task: dict[str, Any],
    ) -> bool:
        product_id = str(product["product_id"])
        stage = str(task.get("stage_key") or "")
        role = str(task.get("role") or "")
        cycle = int(task.get("cycle") or 0)
        successor = {
            "product-director": "product-analyst",
            "product-analyst": "solution-architect",
            "solution-architect": "task-specifier",
            "task-specifier": "builder-core",
            "builder-core": "test-engineer",
            "test-engineer": "security-reviewer",
            "security-reviewer": "independent-reviewer",
            "independent-reviewer": "release-staging",
            "release-staging": "product-tester",
            "product-tester": "release-production",
        }.get(stage)
        if not stage:
            successor = {
                "product-director": "product-analyst",
                "product-analyst": "solution-architect",
                "solution-architect": "task-specifier",
                "task-specifier": "builder-core",
                "builder": "test-engineer",
                "test-engineer": "security-reviewer",
                "security-reviewer": "independent-reviewer",
                "independent-reviewer": "release-staging",
                "product-tester": "release-production",
            }.get(role)
            if role == "release-operator":
                successor = (
                    "product-tester"
                    if "Staging" in str(task.get("title"))
                    else "observation"
                )
        if stage == "release-production" or (
            role == "release-operator" and str(product["status"]) == "OBSERVATION"
        ):
            available = (
                datetime.now(UTC) + timedelta(seconds=self.config.observation_seconds)
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            self.pipeline.create_task(
                product_id,
                "observation",
                dependencies=(str(task["task_id"]),),
                cycle=cycle,
                available_at=available,
            )
            return True
        if stage == "observation":
            if str(product["status"]) == "OBSERVATION":
                self.workflow.transition(product_id, "COMPLETED")
            return True
        if successor is None:
            return False
        self.pipeline.create_task(
            product_id,
            successor,
            dependencies=(str(task["task_id"]),),
            cycle=cycle,
        )
        return True

    def reconcile_product(self, product: dict[str, Any]) -> str:
        product_id = str(product["product_id"])
        status = str(product["status"])
        if status in _TERMINAL_PRODUCTS | _NON_RUNNING_PRODUCTS:
            return "ignored"
        if self.state.active_tasks(product_id):
            return "active"

        task = self.state.latest_task(product_id)
        self._watchdog_incident(product, task)
        if task is None:
            self.pipeline.seed_initial(product_id)
            return "repaired"

        task_status = str(task["status"])
        if task_status == "DONE":
            if (
                str(task.get("role") or "") == "product-tester"
                and str(task.get("stage_key") or "") != "observation"
                and status == "STAGING_DEPLOYED"
            ):
                path = self.pipeline.begin_repair_cycle(
                    task,
                    reason_code="product_acceptance_blocked",
                    summary=(
                        "Product Tester завершил проверку без разрешения production release."
                    ),
                    evidence_refs=[
                        str(task.get("result_ref") or ""),
                        f"evidence/task-{task['task_id']}.json",
                    ],
                )
                if path is not None:
                    return "repaired"
                self._exhaust(
                    product,
                    task,
                    "product_acceptance_blocked",
                    "Product Tester не разрешил production release.",
                )
                return "exhausted"
            return "successor" if self._recover_successor(product, task) else "unresolved"
        if task_status not in {"FAILED_SAFE", "BLOCKED_EXTERNAL"}:
            return "unresolved"

        reason, detail = self._task_reason(task)
        if owner_action_allowed(self.config, reason):
            self._owner_action(product, task, reason, detail)
            return "owner_action"

        failure_class = classify_failure(reason)
        if failure_class is FailureClass.EXTERNAL:
            # Unknown external labels are never promoted into OWNER_ACTION.
            reason = "internal_blocker"

        role = str(task.get("role") or "")
        if failure_class is FailureClass.TRANSIENT:
            tier = self._next_repair_tier(task, reason)
            if tier is None:
                self._exhaust(product, task, reason, detail)
                return "exhausted"
            self._write_same_task_repair(task, reason=reason, detail=detail, tier=tier)
            return "repaired"
        if role in _HANDOFF_ROLES:
            path = self.pipeline.begin_repair_cycle(
                task,
                reason_code=reason,
                summary=detail,
                evidence_refs=[
                    str(task.get("result_ref") or ""),
                    f"evidence/task-{task['task_id']}.json",
                ],
                attempt_id=(
                    str(self.state.attempts_for_task(str(task["task_id"]))[-1]["attempt_id"])
                    if self.state.attempts_for_task(str(task["task_id"]))
                    else None
                ),
            )
            if path is not None:
                return "repaired"
            self._exhaust(product, task, reason, detail)
            return "exhausted"

        tier = self._next_repair_tier(task, reason)
        if tier is None or int(task.get("attempts") or 0) > 8:
            self._exhaust(product, task, reason, detail)
            return "exhausted"
        self._write_same_task_repair(task, reason=reason, detail=detail, tier=tier)
        return "repaired"

    def reconcile_once(self) -> ReconcileResult:
        self.state.recover_expired_leases()
        counts = {
            "inspected": 0,
            "repaired": 0,
            "owner_actions": 0,
            "exhausted": 0,
            "recovered_successors": 0,
        }
        for product in self.state.list_products():
            if str(product["status"]) in _TERMINAL_PRODUCTS | _NON_RUNNING_PRODUCTS:
                continue
            counts["inspected"] += 1
            action = self.reconcile_product(product)
            if action == "repaired":
                counts["repaired"] += 1
            elif action == "owner_action":
                counts["owner_actions"] += 1
            elif action == "exhausted":
                counts["exhausted"] += 1
            elif action == "successor":
                counts["recovered_successors"] += 1
        return ReconcileResult(**counts)


class ReconcilerLoop:
    """Small stoppable controller companion loop."""

    def __init__(self, reconciler: PipelineReconciler, interval_seconds: float) -> None:
        self.reconciler = reconciler
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("reconciler loop is already started")
        self._thread = threading.Thread(
            target=self._run,
            name="hermes-reconciler",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(5.0, self.interval_seconds * 2))

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                result = self.reconciler.reconcile_once()
                if any(
                    (
                        result.repaired,
                        result.owner_actions,
                        result.exhausted,
                        result.recovered_successors,
                    )
                ):
                    LOGGER.info("pipeline reconcile result=%s", result)
            except (OSError, RuntimeError, TypeError, ValueError):
                LOGGER.exception("pipeline reconcile failed")
            self._stop.wait(self.interval_seconds)
