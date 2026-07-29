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
from scripts.quality_gate import load_catalog

from .artifacts import ArtifactStore, artifact_metadata
from .capabilities import CapabilityReconciler
from .common import new_id, sha256_text, stable_json, utc_now
from .config import FactoryConfig
from .failure_router import FailureRouter
from .owner_actions import OwnerActionService
from .pipeline import PipelineCoordinator
from .policy import load_policies, owner_action_allowed
from .repair_brief import (
    builder_result_is_controller_complete,
    builder_result_is_locally_complete,
    normalized_repair_findings,
    repair_finding_detail,
    repair_requirements,
)
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
    "duplicate_prompt_attempt": "задача попыталась повторить уже завершённый запрос без новых данных",
    "internal_blocker": "обнаружена внутренняя блокировка конвейера",
}


@dataclass(frozen=True)
class ReconcileResult:
    inspected: int = 0
    repaired: int = 0
    replanned: int = 0
    incidents: int = 0
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
        self.failure_router = FailureRouter(config, state, self.artifacts)
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
        packaged_catalog = (
            Path(__file__).resolve().parents[1] / "config" / "quality-gates.yaml"
        )
        configured_catalog = config.raw.get("paths", {}).get("quality_gates")
        gate_catalog = load_catalog(
            Path(str(configured_catalog)) if configured_catalog else packaged_catalog
        )
        entries = gate_catalog.get("gates", [])
        self.optional_gate_ids = {
            str(item["id"])
            for item in entries
            if (
                isinstance(item, dict)
                and item.get("id")
                and item.get("mandatory") is False
            )
        }

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

    def _read_evidence_payload(self, reference: str) -> dict[str, Any] | None:
        if not reference:
            return None
        candidate = Path(reference)
        if not candidate.is_absolute():
            candidate = self.config.evidence_dir / candidate.name
        try:
            resolved = candidate.resolve()
        except OSError:
            return None
        evidence_root = self.config.evidence_dir.resolve()
        if (
            resolved.parent != evidence_root
            or not resolved.is_file()
            or resolved.is_symlink()
        ):
            return None
        try:
            payload = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def _validated_output_payload(
        self,
        attempt_payload: dict[str, Any],
    ) -> dict[str, Any] | None:
        test_results = attempt_payload.get("test_results", [])
        if not isinstance(test_results, list):
            return None
        for item in test_results:
            if (
                isinstance(item, dict)
                and item.get("gate_id") == "schema-validation"
                and item.get("status") == "PASS"
            ):
                payload = self._read_evidence_payload(
                    str(item.get("evidence_ref") or "")
                )
                if payload is not None:
                    return payload
        return None

    @staticmethod
    def _blocking_finding_detail(output: dict[str, Any]) -> str | None:
        return (
            repair_finding_detail(output)
            if normalized_repair_findings(output)
            else None
        )

    def _task_reason(self, task: dict[str, Any]) -> tuple[str, str]:
        reason = str(task.get("terminal_reason") or "").strip()
        detail = str(task.get("terminal_detail") or reason).strip()
        attempts = self.state.attempts_for_task(str(task["task_id"]))
        if not reason and attempts:
            reason = str(attempts[-1].get("reason_code") or "").strip()
        if not reason:
            reason = "internal_blocker"
        if not detail:
            detail = reason
        result_ref = str(task.get("result_ref") or "")
        payload = self._read_evidence_payload(result_ref)
        if payload is not None:
            detail = str(payload.get("summary") or reason)
            test_results = payload.get("test_results", [])
            failed_observations: list[str] = []
            failed_gates = (
                sorted(
                    str(item["gate_id"])
                    for item in test_results
                    if (
                        isinstance(item, dict)
                        and item.get("gate_id")
                        and item.get("status") not in {"PASS", "NOT_RUN"}
                    )
                )
                if isinstance(test_results, list)
                else []
            )
            if isinstance(test_results, list):
                for item in test_results:
                    if (
                        not isinstance(item, dict)
                        or item.get("status") in {"PASS", "NOT_RUN"}
                    ):
                        continue
                    gate_id = str(item.get("gate_id") or "unknown-gate")
                    gate_payload = self._read_evidence_payload(
                        str(item.get("evidence_ref") or "")
                    )
                    gate_summary = (
                        str(gate_payload.get("summary") or "").strip()
                        if gate_payload is not None
                        else ""
                    )
                    if gate_summary:
                        failed_observations.append(
                            f"{gate_id}: {gate_summary}"
                        )
            if failed_gates:
                detail = f"{detail}; failed gates: {', '.join(failed_gates)}"
            if failed_observations:
                detail = (
                    f"{detail}; controller gate evidence: "
                    + " | ".join(failed_observations)
                )[:4000]
            output = self._validated_output_payload(payload)
            finding_detail = (
                self._blocking_finding_detail(output)
                if output is not None
                else None
            )
            if finding_detail:
                detail = finding_detail
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
        requeue: bool = True,
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
        attempt_payload = self._read_evidence_payload(
            str(task.get("result_ref") or "")
        )
        output = (
            self._validated_output_payload(attempt_payload)
            if attempt_payload is not None
            else None
        )
        failed_gate_ids: list[str] = []
        gate_required_fixes: list[str] = []
        if attempt_payload is not None:
            test_results = attempt_payload.get("test_results", [])
            if isinstance(test_results, list):
                for item in test_results:
                    if (
                        not isinstance(item, dict)
                        or item.get("status") in {"PASS", "NOT_RUN"}
                    ):
                        continue
                    gate_id = str(item.get("gate_id") or "unknown-gate")
                    failed_gate_ids.append(gate_id)
                    gate_payload = self._read_evidence_payload(
                        str(item.get("evidence_ref") or "")
                    )
                    gate_summary = (
                        str(gate_payload.get("summary") or "").strip()
                        if gate_payload is not None
                        else ""
                    )
                    if gate_summary:
                        gate_required_fixes.append(
                            f"Make controller gate {gate_id} pass. "
                            f"Observed failure: {gate_summary}"
                        )
        failed_gate_ids, required_fixes = repair_requirements(
            output=output,
            reason_code=reason,
            detail=detail,
            failed_gate_ids=[
                *(["pm-acceptance"] if "pm_acceptance" in reason else []),
                *failed_gate_ids,
            ],
        )
        required_fixes = list(
            dict.fromkeys([*gate_required_fixes, *required_fixes])
        )
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
            "failed_gate_ids": failed_gate_ids,
            "required_fixes": required_fixes,
            "allowed_paths": [str(item) for item in contract["allowed_paths"]],
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
        if requeue:
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

    def _recover_successor_legacy_v1(
        self,
        product: dict[str, Any],
        task: dict[str, Any],
    ) -> bool:
        """Recover a revision-0 v1 stage; executable v2 plans never call this."""

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

    def _previous_status_before_failed_safe(self, product_id: str) -> str | None:
        for event in reversed(self.state.events(product_id)):
            if str(event.get("event_type")) != "product_transition":
                continue
            try:
                payload = json.loads(str(event.get("payload_json") or "{}"))
            except json.JSONDecodeError:
                continue
            if payload.get("to") == "FAILED_SAFE":
                previous = str(payload.get("from") or "")
                return previous or None
        return None

    def _recover_builder_downstream_gate(self, product: dict[str, Any]) -> bool:
        """Do not charge Builder for a GitHub check owned by a later stage."""

        product_id = str(product["product_id"])
        task = self.state.legacy_latest_task_v1(product_id)
        if (
            task is None
            or str(task.get("status")) != "BLOCKED_EXTERNAL"
            or str(task.get("role")) != "builder"
            or str(task.get("stage_key")) != "builder-core"
        ):
            return False
        attempt_payload = self._read_evidence_payload(
            str(task.get("result_ref") or "")
        )
        if attempt_payload is None:
            return False
        controller_results = attempt_payload.get("test_results", [])
        if (
            not isinstance(controller_results, list)
            or any(
                not isinstance(item, dict)
                or (
                    item.get("status") == "FAIL"
                    and str(item.get("gate_id") or "") not in self.optional_gate_ids
                )
                for item in controller_results
            )
        ):
            return False
        output = self._validated_output_payload(attempt_payload)
        if output is None or not builder_result_is_locally_complete(output):
            return False
        resume_status = self._previous_status_before_failed_safe(product_id)
        if resume_status is None:
            return False
        recovered = self.state.recover_deferred_builder_gate(
            product_id=product_id,
            task_id=str(task["task_id"]),
            resume_status=resume_status,
        )
        if not recovered:
            return False
        self._enqueue_notification(
            product_id=product_id,
            task_id=str(task["task_id"]),
            kind="automatic_recovery",
            discriminator=f"builder-downstream-gate:{task['task_id']}",
            text=(
                "✅ Hermes автоматически продолжил проект после исправления "
                "внутренней границы ролей.\n"
                f"Проект: {product_id}\n"
                "Builder завершил реализацию и локальные проверки. GitHub "
                "pm-acceptance перенесён на этап immutable candidate, где он и "
                "должен выполняться.\n"
                "Следующий шаг: Test Engineer.\n"
                "Действие владельца: не требуется."
            ),
        )
        return True

    def _recover_controller_valid_builder(self, product: dict[str, Any]) -> bool:
        """Resume from an earlier Builder result already proven by controller gates."""

        product_id = str(product["product_id"])
        tasks = self.state.list_tasks(product_id)
        latest = self.state.legacy_latest_task_v1(product_id)
        if len(tasks) < 2 or latest is None:
            return False
        if (
            str(latest.get("status")) not in {"FAILED_SAFE", "BLOCKED_EXTERNAL"}
            or str(latest.get("role")) != "builder"
            or str(latest.get("stage_key")) != "builder-core"
        ):
            return False
        required_controller_gates = {
            "target-environment",
            "target-tests",
            "target-compile",
            "target-secret-scan",
        }
        candidates = sorted(
            (
                candidate
                for candidate in tasks
                if str(candidate.get("task_id")) != str(latest["task_id"])
            ),
            key=lambda candidate: (
                int(candidate.get("cycle") or 0),
                str(candidate.get("created_at") or ""),
            ),
            reverse=True,
        )
        for candidate in candidates:
            if (
                str(candidate.get("status")) not in {"FAILED_SAFE", "BLOCKED_EXTERNAL"}
                or str(candidate.get("role")) != "builder"
                or str(candidate.get("stage_key")) != "builder-core"
                or int(candidate.get("cycle") or 0) > int(latest.get("cycle") or 0)
            ):
                continue
            attempt_payload = self._read_evidence_payload(
                str(candidate.get("result_ref") or "")
            )
            if attempt_payload is None:
                continue
            controller_results = attempt_payload.get("test_results", [])
            if not isinstance(controller_results, list):
                continue
            passed_controller_gates: set[str] = set()
            controller_failed = False
            for item in controller_results:
                if not isinstance(item, dict):
                    controller_failed = True
                    break
                gate_id = str(item.get("gate_id") or "")
                status = str(item.get("status") or "")
                if status == "PASS":
                    passed_controller_gates.add(gate_id)
                elif status == "FAIL" and gate_id not in self.optional_gate_ids:
                    controller_failed = True
                    break
            if (
                controller_failed
                or not required_controller_gates.issubset(passed_controller_gates)
            ):
                continue
            output = self._validated_output_payload(attempt_payload)
            if output is None or not builder_result_is_controller_complete(output):
                continue
            task_id = str(candidate["task_id"])
            if not self.state.adopt_controller_valid_builder(
                product_id=product_id,
                task_id=task_id,
            ):
                continue
            refreshed = self.state.get_product(product_id)
            if refreshed is None or not self._recover_successor_legacy_v1(
                refreshed,
                candidate,
            ):
                raise RuntimeError(
                    f"controller-valid Builder successor was not created for {task_id}"
                )
            self._enqueue_notification(
                product_id=product_id,
                task_id=task_id,
                kind="automatic_recovery",
                discriminator=f"builder-controller-gates:{task_id}",
                text=(
                    "✅ Hermes автоматически продолжил проект по доказанному результату Builder.\n"
                    f"Проект: {product_id}\n"
                    "Обязательные проверки контроллера прошли. Запрос на перепланирование "
                    "касался внутреннего детектора, для которого потребовался бы выход за "
                    "разрешённую область изменений; дефект продукта не обнаружен.\n"
                    "Следующий шаг: Test Engineer.\n"
                    "Действие владельца: не требуется."
                ),
            )
            return True
        return False

    def _recover_interrupted_product(self, product: dict[str, Any]) -> bool:
        product_id = str(product["product_id"])
        task = self.state.legacy_latest_task_v1(product_id)
        if task is None:
            return False
        detail = str(task.get("terminal_detail") or "")
        if not detail.startswith("Prompt digest already attempted for task "):
            return False
        resume_status = self._previous_status_before_failed_safe(product_id)
        if resume_status is None:
            return False
        recovered = self.state.recover_interrupted_attempt(
            product_id=product_id,
            task_id=str(task["task_id"]),
            resume_status=resume_status,
        )
        if not recovered:
            return False
        self._enqueue_notification(
            product_id=product_id,
            task_id=str(task["task_id"]),
            kind="automatic_recovery",
            discriminator=f"interrupted-attempt:{task['task_id']}",
            text=(
                "✅ Hermes автоматически возобновил внутренне прерванную задачу.\n"
                f"Проект: {product_id}\n"
                f"Этап: {task.get('title')}\n"
                "Причина устранена: незавершённая попытка безопасно продолжена после "
                "перезапуска worker.\n"
                "Действие владельца: не требуется."
            ),
        )
        return True

    def _recover_undiagnosed_secret_exposure(
        self,
        product: dict[str, Any],
    ) -> bool:
        """Retry one old opaque rejection with deterministic output sanitizing."""

        product_id = str(product["product_id"])
        task = self.state.legacy_latest_task_v1(product_id)
        if (
            task is None
            or str(task.get("status")) not in {"FAILED_SAFE", "BLOCKED_EXTERNAL"}
            or str(task.get("terminal_reason") or "") != "secret_exposure"
            or str(task.get("terminal_detail") or "").strip()
        ):
            return False
        resume_status = self._previous_status_before_failed_safe(product_id)
        if resume_status is None:
            return False
        detail = (
            "The legacy detector rejected the provider response without preserving "
            "usable coordinates. Repeat this task once under provider-output "
            "sanitizer v2. The controller will replace only credential-like values "
            "with [REDACTED], validate the complete sanitized JSON, and continue "
            "without copying matched values into durable evidence."
        )
        repair_context_ref = self._write_same_task_repair(
            task,
            reason="secret_exposure",
            detail=detail,
            tier="sol",
            requeue=False,
        )
        recovered = self.state.recover_undiagnosed_secret_exposure(
            product_id=product_id,
            task_id=str(task["task_id"]),
            resume_status=resume_status,
            repair_context_ref=repair_context_ref,
        )
        if not recovered:
            return False
        self._enqueue_notification(
            product_id=product_id,
            task_id=str(task["task_id"]),
            kind="automatic_recovery",
            discriminator=f"provider-output-sanitizer-v2:{task['task_id']}",
            text=(
                "🔁 Hermes автоматически исправляет внутреннюю потерю диагностики.\n"
                f"Проект: {product_id}\n"
                "Старый детектор сообщил только secret_exposure. Задача один раз "
                "повторена на уровне Sol; найденные значения будут автоматически "
                "заменены на [REDACTED], а остальной ответ сохранён и проверен.\n"
                "Действие владельца: не требуется."
            ),
        )
        return True

    def _recover_deferred_dependency_consumer(
        self,
        product: dict[str, Any],
    ) -> bool:
        """Retry Test Engineer after a controller-accepted deferred Builder."""

        product_id = str(product["product_id"])
        task = self.state.legacy_latest_task_v1(product_id)
        if (
            task is None
            or str(task.get("status")) != "BLOCKED_EXTERNAL"
            or str(task.get("role")) != "test-engineer"
            or str(task.get("stage_key")) != "test-engineer"
            or str(task.get("terminal_reason") or "") != "internal_blocker"
        ):
            return False
        detail = str(task.get("terminal_detail") or "")
        prefixes = (
            "accepted task result is missing for ",
            "deferred Builder evidence is invalid for ",
        )
        prefix = next(
            (candidate for candidate in prefixes if detail.startswith(candidate)),
            None,
        )
        if prefix is None:
            return False
        dependency_task_id = detail.removeprefix(prefix).strip()
        if not dependency_task_id:
            return False
        resume_status = self._previous_status_before_failed_safe(product_id)
        if resume_status is None:
            return False
        recovered = self.state.recover_deferred_dependency_consumer(
            product_id=product_id,
            task_id=str(task["task_id"]),
            dependency_task_id=dependency_task_id,
            resume_status=resume_status,
        )
        if not recovered:
            return False
        self._enqueue_notification(
            product_id=product_id,
            task_id=str(task["task_id"]),
            kind="automatic_recovery",
            discriminator=f"deferred-dependency:{task['task_id']}",
            text=(
                "✅ Hermes автоматически восстановил передачу результата Builder.\n"
                f"Проект: {product_id}\n"
                f"Builder: {dependency_task_id}\n"
                "Test Engineer повторно поставлен в очередь без нового Builder-вызова.\n"
                "Действие владельца: не требуется."
            ),
        )
        return True

    def _recover_exhausted_builder_cycle(self, product: dict[str, Any]) -> bool:
        product_id = str(product["product_id"])
        task = self.state.legacy_latest_task_v1(product_id)
        if (
            task is None
            or str(task.get("role")) != "builder"
            or str(task.get("stage_key")) != "builder-core"
            or int(task.get("cycle") or 0) >= self.config.max_repair_cycles
        ):
            return False
        reason, detail = self._task_reason(task)
        if (
            owner_action_allowed(self.config, reason)
            or classify_failure(reason)
            in {FailureClass.EXTERNAL, FailureClass.TRANSIENT}
        ):
            return False
        resume_status = self._previous_status_before_failed_safe(product_id)
        if resume_status is None:
            return False
        recovered = self.state.recover_exhausted_builder_cycle(
            product_id=product_id,
            task_id=str(task["task_id"]),
            resume_status=resume_status,
            max_repair_cycles=self.config.max_repair_cycles,
        )
        if not recovered:
            return False
        self._enqueue_notification(
            product_id=product_id,
            task_id=str(task["task_id"]),
            kind="automatic_recovery",
            discriminator=f"builder-cycle:{task['task_id']}",
            text=(
                "🔧 Hermes автоматически открыл следующий ограниченный цикл "
                "исправления Builder.\n"
                f"Проект: {product_id}\n"
                f"Точный blocker: {self._reason_text(reason, detail)}\n"
                f"Следующий repair cycle: {int(task.get('cycle') or 0) + 1} "
                f"из {self.config.max_repair_cycles}.\n"
                "Действие владельца: не требуется."
            ),
        )
        return True

    def _recover_extended_repair_budget(self, product: dict[str, Any]) -> bool:
        product_id = str(product["product_id"])
        task = self.state.legacy_latest_task_v1(product_id)
        maximum_product_cycle = max(
            (
                int(item.get("cycle") or 0)
                for item in self.state.list_tasks(product_id)
            ),
            default=0,
        )
        if task is None or maximum_product_cycle >= self.config.max_repair_cycles:
            return False
        reason, detail = self._task_reason(task)
        if owner_action_allowed(self.config, reason):
            return False
        if classify_failure(reason) is FailureClass.EXTERNAL:
            return False
        resume_status = self._previous_status_before_failed_safe(product_id)
        if resume_status is None:
            return False
        recovered = self.state.recover_exhausted_product_budget(
            product_id=product_id,
            task_id=str(task["task_id"]),
            resume_status=resume_status,
            max_repair_cycles=self.config.max_repair_cycles,
        )
        if not recovered:
            return False
        self._enqueue_notification(
            product_id=product_id,
            task_id=str(task["task_id"]),
            kind="automatic_recovery",
            discriminator=(
                f"repair-budget:{task['task_id']}:{self.config.max_repair_cycles}"
            ),
            text=(
                "🔁 Hermes автоматически возобновил проект в рамках расширенного, "
                "но ограниченного бюджета исправлений.\n"
                f"Проект: {product_id}\n"
                f"Точный blocker: {self._reason_text(reason, detail)}\n"
                f"Новый предел repair cycles: {self.config.max_repair_cycles}.\n"
                "Действие владельца: не требуется."
            ),
        )
        return True

    def _recover_director_root_cause_budget(self, product: dict[str, Any]) -> bool:
        """Treat a newly proven blocker as a new diagnosis, not an old failed attempt."""

        product_id = str(product["product_id"])
        task = self.state.legacy_latest_task_v1(product_id)
        maximum_product_cycle = max(
            (
                int(item.get("cycle") or 0)
                for item in self.state.list_tasks(product_id)
            ),
            default=0,
        )
        if task is None or maximum_product_cycle < 3:
            return False
        task_id = str(task["task_id"])
        if not any(
            str(event.get("task_id") or "") == task_id
            and str(event.get("event_type") or "") == "repair_budget_exhausted"
            for event in self.state.events(product_id)
        ):
            return False
        reason, detail = self._task_reason(task)
        if (
            owner_action_allowed(self.config, reason)
            or classify_failure(reason) is FailureClass.EXTERNAL
        ):
            return False
        blocker_ids: list[str] = []
        attempt_payload = self._read_evidence_payload(
            str(task.get("result_ref") or "")
        )
        if attempt_payload is not None:
            test_results = attempt_payload.get("test_results", [])
            if isinstance(test_results, list):
                blocker_ids.extend(
                    str(item.get("gate_id") or "")
                    for item in test_results
                    if (
                        isinstance(item, dict)
                        and item.get("gate_id")
                        and item.get("status") == "FAIL"
                    )
                )
            output = self._validated_output_payload(attempt_payload)
            if output is not None:
                blocker_ids.extend(
                    finding.finding_id
                    for finding in normalized_repair_findings(output)
                )
        blocker_ids = list(
            dict.fromkeys(value.strip() for value in blocker_ids if value.strip())
        )
        if not blocker_ids:
            blocker_ids = [reason]
        blocker_signature = sha256_text(
            json.dumps(
                {
                    "role": str(task.get("role") or ""),
                    "stage": str(task.get("stage_key") or ""),
                    "reason": reason,
                    "blocker_ids": sorted(blocker_ids),
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        prior_hypothesis_attempts = 0
        for event in self.state.events(product_id):
            if str(event.get("event_type") or "") != "director_root_cause_replan":
                continue
            try:
                payload = json.loads(str(event.get("payload_json") or "{}"))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if (
                isinstance(payload, dict)
                and str(payload.get("blocker_signature") or "")
                == blocker_signature
            ):
                prior_hypothesis_attempts += 1
        diagnosis_reassessment = prior_hypothesis_attempts >= 3
        effective_signature = (
            sha256_text(f"diagnosis-reassessment-v1:{blocker_signature}")
            if diagnosis_reassessment
            else blocker_signature
        )
        effective_blocker_ids = (
            ["DIAGNOSIS-REASSESSMENT", *blocker_ids]
            if diagnosis_reassessment
            else blocker_ids
        )
        if not self.state.reopen_for_director_root_cause(
            product_id=product_id,
            task_id=task_id,
            blocker_signature=effective_signature,
            blocker_ids=effective_blocker_ids,
        ):
            return False
        attempts = self.state.attempts_for_task(task_id)
        reassessment_instruction = (
            "Three repair cycles returned the same blocker. Do not repeat the "
            "previous fix. First prove whether the task statement, allowed scope, "
            "controller gate/environment, or implementation diagnosis is wrong; "
            "then apply the smallest correction supported by that evidence and "
            "rerun every failed gate."
            if diagnosis_reassessment
            else None
        )
        diagnosed_summary = (
            (
                "Director diagnosis reassessment: three bounded repair cycles for "
                "the same hypothesis failed. The next task must challenge the "
                "problem statement before changing code. "
            )
            if diagnosis_reassessment
            else (
                "Director root-cause diagnosis: the previous bounded budget is "
                "closed, but this evidence identifies a distinct problem hypothesis. "
            )
        ) + (
            f"Blockers: {', '.join(blocker_ids)}. Exact evidence: {detail}"
        )
        path = self.pipeline.begin_repair_cycle(
            task,
            reason_code=reason,
            summary=diagnosed_summary,
            evidence_refs=[
                str(task.get("result_ref") or ""),
                f"evidence/task-{task_id}.json",
            ],
            attempt_id=(
                str(attempts[-1]["attempt_id"]) if attempts else None
            ),
            director_replan=True,
            director_instruction=reassessment_instruction,
        )
        if path is None:
            raise RuntimeError(
                f"Director root-cause replan did not create a Builder task for {task_id}"
            )
        next_task = self.state.legacy_latest_task_v1(product_id)
        self._enqueue_notification(
            product_id=product_id,
            task_id=task_id,
            kind="automatic_recovery",
            discriminator=f"director-root-cause:{effective_signature}",
            text=(
                (
                    "🧭 Director меняет диагноз после трёх неудачных repair-cycles.\n"
                    if diagnosis_reassessment
                    else (
                        "🧭 Director пересмотрел постановку после исчерпания "
                        "прежних попыток.\n"
                    )
                )
                + f"Проект: {product_id}\n"
                f"Problem hypothesis: {', '.join(effective_blocker_ids)}.\n"
                "Создан новый ограниченный repair budget с отдельным доказательным brief.\n"
                f"Следующая задача Builder: "
                f"{next_task.get('task_id') if next_task else 'создана'}.\n"
                "Действие владельца: не требуется."
            ),
        )
        return True

    def _route_liveness_violation(
        self,
        product: dict[str, Any],
        plans: list[dict[str, Any]],
        unmet_conditions: tuple[str, ...],
    ) -> str:
        product_id = str(product["product_id"])
        active_plan = next(
            (
                plan
                for plan in plans
                if str(plan.get("status")) == "ACTIVE"
            ),
            None,
        )
        if active_plan is None:
            raise RuntimeError("liveness recovery requires an active plan")
        causal_task_id = str(active_plan.get("created_by_task_id") or "")
        if not causal_task_id or self.state.get_task(causal_task_id) is None:
            raise RuntimeError("active plan creator is unavailable for liveness recovery")
        fingerprint = sha256_text(
            stable_json(
                [
                    product_id,
                    active_plan["plan_id"],
                    active_plan["revision"],
                    "liveness_invariant_violation",
                ]
            )
        )
        failure_id = f"failure-{fingerprint[:20]}"
        incident_id = f"incident-{sha256_text(failure_id)[:20]}"
        now = utc_now()
        safe_message = (
            "Active plan has no runnable task while completion prerequisites "
            "remain unmet; create plan revision N+1 with non-planning delivery, "
            "release, observation, and evidence nodes."
        )
        with self.state._lock, self.state._connection:
            inserted = self.state._connection.execute(
                """
                INSERT OR IGNORE INTO failures
                    (failure_id, product_id, task_id, attempt_id,
                     parent_failure_id, failure_class, reason_code, fingerprint,
                     safe_message, exception_type, stack_fingerprint,
                     evidence_ref, status, retryable, owner_action_eligible,
                     expected_json, actual_json, failed_gate_ids_json,
                     first_seen_at, last_seen_at, occurrence_count)
                VALUES (?, ?, ?, NULL, NULL, 'semantic',
                        'liveness_invariant_violation', ?, ?, NULL, NULL,
                        'state://graph-frontier', 'OPEN', 0, 0, ?, ?, ?,
                        ?, ?, 1)
                """,
                (
                    failure_id,
                    product_id,
                    causal_task_id,
                    fingerprint,
                    safe_message,
                    stable_json(
                        {
                            "progress_path": (
                                "READY, CLAIMED, bounded wait, or active "
                                "controller recovery task"
                            )
                        }
                    ),
                    stable_json(
                        {
                            "active_plan_id": active_plan["plan_id"],
                            "active_plan_revision": active_plan["revision"],
                            "unmet_completion": list(unmet_conditions),
                        }
                    ),
                    stable_json(["liveness_invariant_violation"]),
                    now,
                    now,
                ),
            ).rowcount
            self.state._connection.execute(
                """
                INSERT OR IGNORE INTO controller_incidents
                    (incident_id, product_id, task_id, reason_code,
                     evidence_ref, status, created_at)
                VALUES (?, ?, ?, 'liveness_invariant_violation',
                        'state://graph-frontier', 'OPEN', ?)
                """,
                (incident_id, product_id, causal_task_id, now),
            )
            if inserted:
                self.state._record_event(
                    product_id,
                    causal_task_id,
                    "controller_incident",
                    {
                        "incident_id": incident_id,
                        "failure_id": failure_id,
                        "reason_code": "liveness_invariant_violation",
                    },
                )
        return self.failure_router.route(failure_id)

    def reconcile_product(self, product: dict[str, Any]) -> str:
        product_id = str(product["product_id"])
        status = str(product["status"])
        if status in _TERMINAL_PRODUCTS | _NON_RUNNING_PRODUCTS:
            return "ignored"
        plans = self.state.list_plans(product_id)
        active_v2 = any(
            str(plan.get("status")) == "ACTIVE"
            and int(plan.get("revision") or 0) >= 1
            for plan in plans
        )
        if active_v2 or self.state.list_failures(product_id):
            routed = self.failure_router.route_open_failures(product_id)
            if routed:
                roles = {
                    str((self.state.get_task(task_id) or {}).get("role") or "")
                    for task_id in routed
                }
                if "replanner" in roles:
                    return "replanned"
                if "incident-recovery" in roles:
                    return "incident"
                return "repaired"
            if self.state.has_bounded_progress_path(product_id):
                return "active"
            completion = self.state.reduce_completion(
                product_id,
                artifacts=self.artifacts,
            )
            if completion.completed:
                return "completed"
            self._route_liveness_violation(
                product,
                plans,
                completion.unmet_conditions,
            )
            return "replanned"
        if self.state.active_tasks(product_id):
            return "active"

        task = self.state.legacy_latest_task_v1(product_id)
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
            return (
                "successor"
                if self._recover_successor_legacy_v1(product, task)
                else "unresolved"
            )
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
            if role == "builder":
                attempts = self.state.attempts_for_task(str(task["task_id"]))
                path = self.pipeline.begin_repair_cycle(
                    task,
                    reason_code=reason,
                    summary=detail,
                    evidence_refs=[
                        str(task.get("result_ref") or ""),
                        f"evidence/task-{task['task_id']}.json",
                    ],
                    attempt_id=(
                        str(attempts[-1]["attempt_id"]) if attempts else None
                    ),
                )
                if path is not None:
                    return "repaired"
            self._exhaust(product, task, reason, detail)
            return "exhausted"
        self._write_same_task_repair(task, reason=reason, detail=detail, tier=tier)
        return "repaired"

    def reconcile_once(self) -> ReconcileResult:
        self.state.recover_expired_leases()
        counts = {
            "inspected": 0,
            "repaired": 0,
            "replanned": 0,
            "incidents": 0,
            "owner_actions": 0,
            "exhausted": 0,
            "recovered_successors": 0,
        }
        for product in self.state.list_products():
            status = str(product["status"])
            if status == "FAILED_SAFE" and self._recover_controller_valid_builder(
                product
            ):
                counts["inspected"] += 1
                counts["recovered_successors"] += 1
                continue
            if status == "FAILED_SAFE" and self._recover_builder_downstream_gate(product):
                counts["inspected"] += 1
                refreshed = self.state.get_product(str(product["product_id"]))
                if refreshed is None:
                    continue
                action = self.reconcile_product(refreshed)
                if action == "successor":
                    counts["recovered_successors"] += 1
                elif action == "repaired":
                    counts["repaired"] += 1
                continue
            if status == "FAILED_SAFE" and self._recover_interrupted_product(product):
                counts["inspected"] += 1
                counts["repaired"] += 1
                continue
            if (
                status == "FAILED_SAFE"
                and self._recover_undiagnosed_secret_exposure(product)
            ):
                counts["inspected"] += 1
                counts["repaired"] += 1
                continue
            if status == "FAILED_SAFE" and self._recover_deferred_dependency_consumer(
                product
            ):
                counts["inspected"] += 1
                counts["repaired"] += 1
                continue
            if status == "FAILED_SAFE" and self._recover_exhausted_builder_cycle(product):
                counts["inspected"] += 1
                refreshed = self.state.get_product(str(product["product_id"]))
                if refreshed is None:
                    continue
                action = self.reconcile_product(refreshed)
                if action == "repaired":
                    counts["repaired"] += 1
                elif action == "exhausted":
                    counts["exhausted"] += 1
                continue
            if status == "FAILED_SAFE" and self._recover_extended_repair_budget(product):
                counts["inspected"] += 1
                refreshed = self.state.get_product(str(product["product_id"]))
                if refreshed is None:
                    continue
                action = self.reconcile_product(refreshed)
                if action == "repaired":
                    counts["repaired"] += 1
                elif action == "owner_action":
                    counts["owner_actions"] += 1
                elif action == "exhausted":
                    counts["exhausted"] += 1
                elif action == "successor":
                    counts["recovered_successors"] += 1
                continue
            if status == "FAILED_SAFE" and self._recover_director_root_cause_budget(
                product
            ):
                counts["inspected"] += 1
                counts["repaired"] += 1
                continue
            if status in _TERMINAL_PRODUCTS | _NON_RUNNING_PRODUCTS:
                continue
            counts["inspected"] += 1
            action = self.reconcile_product(product)
            if action == "repaired":
                counts["repaired"] += 1
            elif action == "replanned":
                counts["replanned"] += 1
            elif action == "incident":
                counts["incidents"] += 1
            elif action == "owner_action":
                counts["owner_actions"] += 1
            elif action == "exhausted":
                counts["exhausted"] += 1
            elif action == "successor":
                counts["recovered_successors"] += 1
        return ReconcileResult(**counts)


class ReconcilerLoop:
    """Small stoppable controller companion loop."""

    def __init__(
        self,
        reconciler: PipelineReconciler,
        interval_seconds: float,
        *,
        capability_reconciler: CapabilityReconciler | None = None,
    ) -> None:
        self.reconciler = reconciler
        self.capability_reconciler = capability_reconciler
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
                capability_result = (
                    self.capability_reconciler.reconcile_once()
                    if self.capability_reconciler is not None
                    else None
                )
                result = self.reconciler.reconcile_once()
                if capability_result is not None and any(
                    (
                        capability_result.changed,
                        capability_result.resumed_tasks,
                    )
                ):
                    LOGGER.info(
                        "capability reconcile result=%s",
                        capability_result,
                    )
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
