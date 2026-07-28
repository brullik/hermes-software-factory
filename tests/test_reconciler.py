from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import yaml

from factory.artifacts import ArtifactStore
from factory.config import FactoryConfig
from factory.pipeline import PipelineCoordinator
from factory.reconciler import PipelineReconciler
from factory.state import StateStore

ROOT = Path(__file__).resolve().parents[1]


def make_config(root: Path) -> FactoryConfig:
    raw = yaml.safe_load(
        (ROOT / "config" / "factory-config.example.yaml").read_text(encoding="utf-8")
    )
    raw["paths"]["state"] = str(root)
    raw["paths"]["policies"] = str(ROOT / "policies")
    raw["paths"]["schemas"] = str(ROOT / "schemas")
    raw["paths"]["prompts"] = str(ROOT / "prompts")
    raw["paths"]["worktrees"] = str(root / "worktrees")
    raw["paths"]["logs"] = str(root / "logs")
    raw["controller"]["database_url"] = f"sqlite:///{(root / 'controller.db').as_posix()}"
    raw["telegram"]["allowed_user_ids"] = [42]
    return FactoryConfig(raw, ROOT / "config" / "factory-config.example.yaml")


def product_at_staging(state: StateStore, product_id: str) -> None:
    for status in (
        "CONTRACT_DRAFTED",
        "CONTRACT_VALIDATED",
        "RISK_CLASSIFIED",
        "ARCHITECTED",
        "BACKLOG_READY",
        "IMPLEMENTING",
        "INTEGRATING",
        "STAGING_DEPLOYED",
    ):
        state.transition_product(product_id, status)


def write_pm_task(config: FactoryConfig, product_id: str) -> list[str]:
    required = [
        "src/product/core.py",
        "scripts/check_product.py",
        "tests/test_product.py",
    ]
    path = config.worktrees_dir / product_id / "repository" / "pm_acceptance"
    path.mkdir(parents=True)
    (path / "active_task.json").write_text(
        json.dumps(
            {
                "schema": "pm_active_task_v1",
                "task_id": "p0-active-product-task",
                "allowed_paths": required,
                "required_paths": required,
                "forbidden_paths": [
                    "pm_acceptance/**",
                    ".github/workflows/**",
                    "pyproject.toml",
                ],
            }
        ),
        encoding="utf-8",
    )
    repository = path.parent
    for relative in required:
        candidate = repository / relative
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_text("# baseline\n", encoding="utf-8")
    return required


def test_orphaned_product_is_seeded_and_watchdog_is_durable() -> None:
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(Path(directory))
        state = StateStore(config.database_path)
        state.create_product(
            product_id="orphan-product",
            owner_id="owner",
            source="cli",
            idea="Build an orphan recovery fixture",
            idempotency_key="orphan-product-key",
        )

        assert state.orphaned_product_count() == 1
        result = PipelineReconciler(config, state).reconcile_once()

        assert result.repaired == 1
        assert state.orphaned_product_count() == 0
        tasks = state.active_tasks("orphan-product")
        assert len(tasks) == 1
        assert tasks[0]["stage_key"] == "product-director"
        assert any(
            event["event_type"] == "watchdog_incident"
            for event in state.events("orphan-product")
        )
        state.close()


def test_failed_staging_acceptance_starts_exact_pm_scoped_repair_cycle() -> None:
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(Path(directory))
        state = StateStore(config.database_path)
        product_id = "external-product-repair"
        state.create_product(
            product_id=product_id,
            owner_id="owner",
            source="cli",
            idea="https://github.com/brullik/bybit-grid-research",
            idempotency_key="external-product-repair-key",
        )
        product_at_staging(state, product_id)
        required = write_pm_task(config, product_id)
        pipeline = PipelineCoordinator(config, state, ArtifactStore(config))
        task_path = pipeline.create_task(product_id, "product-tester")
        task_id = json.loads(task_path.read_text(encoding="utf-8"))["task_id"]
        claimed = state.claim_task(worker_id="tester")
        assert claimed is not None
        failed_attempt = config.evidence_dir / "attempt-failed-pm-gates.json"
        failed_attempt.write_text(
            json.dumps(
                {
                    "summary": "repository acceptance failed",
                    "test_results": [
                        {"gate_id": "target-tests", "status": "FAIL"},
                        {"gate_id": "target-lint", "status": "FAIL"},
                        {"gate_id": "target-compile", "status": "PASS"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        state.complete_task(
            task_id,
            "tester",
            "FAILED_SAFE",
            reason_code="pm_acceptance_failed",
            detail="required_path_missing and out_of_scope_path",
            failure_kind="semantic",
            result_ref=str(failed_attempt),
        )

        result = PipelineReconciler(config, state).reconcile_once()

        assert result.repaired == 1
        product = state.get_product(product_id)
        assert product is not None
        assert product["status"] == "REPAIRING"
        active = state.active_tasks(product_id)
        assert len(active) == 1
        repair = active[0]
        assert repair["stage_key"] == "builder-core"
        assert repair["cycle"] == 1
        assert repair["next_tier"] == "terra"
        contract = json.loads(
            (config.evidence_dir / f"task-{repair['task_id']}.json").read_text(
                encoding="utf-8"
            )
        )
        assert contract["allowed_paths"] == required
        assert "pm_acceptance/**" in contract["forbidden_paths"]
        assert all(
            path in "\n".join(item["verification"] for item in contract["acceptance"])
            for path in required
        )
        assert "frozen local PM acceptance suite" in contract["objective"]
        assert "runs later against the immutable candidate" in contract["objective"]
        brief = json.loads(
            (config.evidence_dir / Path(repair["repair_context_ref"]).name).read_text(
                encoding="utf-8"
            )
        )
        assert brief["failed_gate_ids"] == [
            "pm-acceptance",
            "target-lint",
            "target-tests",
        ]
        assert brief["required_fixes"]
        assert brief["allowed_paths"] == required
        assert list(config.evidence_dir.glob("owner-action-*.json")) == []
        assert any(item["status"] == "PENDING" for item in state.list_outbox())
        state.close()


def test_repair_task_cannot_be_claimed_before_brief_is_attached() -> None:
    class RaceProbeArtifacts(ArtifactStore):
        def __init__(self, config: FactoryConfig, state: StateStore) -> None:
            super().__init__(config)
            self.state = state
            self.claimed_during_brief: dict[str, object] | None = None

        def write(
            self,
            schema_name: str,
            data: dict[str, Any],
            *,
            filename: str | None = None,
        ) -> Path:
            if schema_name == "repair-brief.schema.json":
                self.claimed_during_brief = self.state.claim_task(worker_id="race-worker")
            return super().write(schema_name, data, filename=filename)

    with tempfile.TemporaryDirectory() as directory:
        config = make_config(Path(directory))
        state = StateStore(config.database_path)
        product_id = "atomic-repair-product"
        state.create_product(
            product_id=product_id,
            owner_id="owner",
            source="cli",
            idea="https://github.com/brullik/bybit-grid-research",
            idempotency_key="atomic-repair-key",
        )
        product_at_staging(state, product_id)
        write_pm_task(config, product_id)
        artifacts = RaceProbeArtifacts(config, state)
        task_path = PipelineCoordinator(config, state, artifacts).create_task(
            product_id,
            "product-tester",
        )
        task_id = json.loads(task_path.read_text(encoding="utf-8"))["task_id"]
        assert state.claim_task(worker_id="failed-tester") is not None
        state.complete_task(task_id, "failed-tester", "FAILED_SAFE")

        result = PipelineReconciler(config, state, artifacts).reconcile_once()

        assert result.repaired == 1
        assert artifacts.claimed_during_brief is None
        active = state.active_tasks(product_id)
        assert len(active) == 1
        assert active[0]["status"] == "PENDING"
        assert active[0]["next_tier"] == "terra"
        assert active[0]["repair_context_ref"]
        state.close()


def test_repair_cycle_resumes_from_staging_without_restarting_planning() -> None:
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(Path(directory))
        state = StateStore(config.database_path)
        product_id = "staging-resume-product"
        state.create_product(
            product_id=product_id,
            owner_id="owner",
            source="cli",
            idea="https://github.com/brullik/bybit-grid-research",
            idempotency_key="staging-resume-key",
        )
        product_at_staging(state, product_id)
        write_pm_task(config, product_id)
        pipeline = PipelineCoordinator(config, state, ArtifactStore(config))
        failed_path = pipeline.create_task(product_id, "product-tester")
        failed_id = json.loads(failed_path.read_text(encoding="utf-8"))["task_id"]
        assert state.claim_task(worker_id="failed-tester") is not None
        state.complete_task(
            failed_id,
            "failed-tester",
            "FAILED_SAFE",
            reason_code="pm_acceptance_failed",
            detail="required paths were missing",
            failure_kind="semantic",
        )
        PipelineReconciler(config, state).reconcile_once()

        worker_number = 0

        def accept(role: str, output: dict[str, object] | None = None) -> dict[str, object]:
            nonlocal worker_number
            worker_number += 1
            worker_id = f"repair-worker-{worker_number}"
            task = state.claim_task(worker_id=worker_id)
            assert task is not None
            assert task["role"] == role
            pipeline.advance_after(
                task,
                output or {"status": "completed"},
                Path("unused.json"),
            )
            state.complete_task(str(task["task_id"]), worker_id)
            return task

        builder = accept("builder")
        accept("test-engineer")
        accept("security-reviewer")
        accept("independent-reviewer")
        staging = accept("release-operator")

        product = state.get_product(product_id)
        assert product is not None
        assert product["status"] == "STAGING_DEPLOYED"
        assert builder["cycle"] == 1
        assert staging["stage_key"] == "release-staging"
        assert staging["cycle"] == 1
        roles_in_cycle = [
            task["role"] for task in state.list_tasks(product_id) if task["cycle"] == 1
        ]
        assert roles_in_cycle == [
            "builder",
            "test-engineer",
            "security-reviewer",
            "independent-reviewer",
            "release-operator",
            "product-tester",
        ]
        assert not any(
            role in roles_in_cycle
            for role in (
                "product-director",
                "product-analyst",
                "solution-architect",
                "task-specifier",
            )
        )
        state.close()


def test_completed_but_blocked_product_acceptance_starts_repair() -> None:
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(Path(directory))
        state = StateStore(config.database_path)
        product_id = "acceptance-blocked-product"
        state.create_product(
            product_id=product_id,
            owner_id="owner",
            source="cli",
            idea="https://github.com/brullik/bybit-grid-research",
            idempotency_key="acceptance-blocked-key",
        )
        product_at_staging(state, product_id)
        write_pm_task(config, product_id)
        pipeline = PipelineCoordinator(config, state)
        task_path = pipeline.create_task(product_id, "product-tester")
        task_id = json.loads(task_path.read_text(encoding="utf-8"))["task_id"]
        assert state.claim_task(worker_id="tester") is not None
        state.complete_task(
            task_id,
            "tester",
            "DONE",
            result_ref="evidence/product-test-blocked.json",
        )

        result = PipelineReconciler(config, state).reconcile_once()

        assert result.repaired == 1
        product = state.get_product(product_id)
        assert product is not None
        assert product["status"] == "REPAIRING"
        active = state.active_tasks(product_id)
        assert len(active) == 1
        assert active[0]["stage_key"] == "builder-core"
        assert active[0]["cycle"] == 1
        state.close()


def test_external_credential_block_creates_owner_action_but_internal_failure_does_not() -> None:
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(Path(directory))
        state = StateStore(config.database_path)
        product_id = "credential-blocked-product"
        state.create_product(
            product_id=product_id,
            owner_id="owner",
            source="cli",
            idea="Build a credential fixture",
            idempotency_key="credential-product-key",
        )
        task_path = PipelineCoordinator(config, state).seed_initial(product_id)
        task_id = json.loads(task_path.read_text(encoding="utf-8"))["task_id"]
        assert state.claim_task(worker_id="worker") is not None
        state.complete_task(
            task_id,
            "worker",
            "BLOCKED_EXTERNAL",
            reason_code="missing_credential",
            detail="GitHub credential is not connected",
            failure_kind="external",
        )

        result = PipelineReconciler(config, state).reconcile_once()

        assert result.owner_actions == 1
        product = state.get_product(product_id)
        assert product is not None
        assert product["status"] == "BLOCKED_OWNER"
        actions = list(config.evidence_dir.glob("owner-action-*.json"))
        assert len(actions) == 1
        action = json.loads(actions[0].read_text(encoding="utf-8"))
        assert action["reason"] == "missing_credential"
        assert "GitHub credential" in action["why_blocked"]
        state.close()


def test_repair_budget_exhaustion_is_terminal_and_notified_in_russian() -> None:
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(Path(directory))
        config.raw["controller"]["max_repair_cycles"] = 2
        state = StateStore(config.database_path)
        product_id = "repair-budget-product"
        state.create_product(
            product_id=product_id,
            owner_id="owner",
            source="cli",
            idea="Build a repair budget fixture",
            idempotency_key="repair-budget-key",
        )
        product_at_staging(state, product_id)
        pipeline = PipelineCoordinator(config, state)
        builder_path = pipeline.create_task(product_id, "builder-core", cycle=2)
        builder_id = json.loads(builder_path.read_text(encoding="utf-8"))["task_id"]
        assert state.claim_task(worker_id="builder") is not None
        state.complete_task(builder_id, "builder")
        task_path = pipeline.create_task(product_id, "product-tester", cycle=2)
        task_id = json.loads(task_path.read_text(encoding="utf-8"))["task_id"]
        claimed = state.claim_task(worker_id="tester")
        assert claimed is not None
        assert claimed["task_id"] == task_id
        state.complete_task(
            task_id,
            "tester",
            "FAILED_SAFE",
            reason_code="pm_acceptance_failed",
            detail="required_path_missing: tests/test_product.py",
            failure_kind="semantic",
        )

        result = PipelineReconciler(config, state).reconcile_once()

        assert result.exhausted == 1
        product = state.get_product(product_id)
        assert product is not None
        assert product["status"] == "FAILED_SAFE"
        payloads = [json.loads(item["payload_json"]) for item in state.list_outbox()]
        exhausted = next(item for item in payloads if item["kind"] == "repair_exhausted")
        assert "исчерпал автоматические попытки" in exhausted["text"]
        assert "required_path_missing: tests/test_product.py" in exhausted["text"]
        assert list(config.evidence_dir.glob("owner-action-*.json")) == []
        state.close()


def test_expanded_bounded_budget_reopens_exact_security_repair() -> None:
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(Path(directory))
        config.raw["controller"]["max_repair_cycles"] = 2
        state = StateStore(config.database_path)
        product_id = "expanded-security-budget-product"
        state.create_product(
            product_id=product_id,
            owner_id="owner",
            source="cli",
            idea="Repair a validated security finding",
            idempotency_key="expanded-security-budget-key",
        )
        for status in (
            "CONTRACT_DRAFTED",
            "CONTRACT_VALIDATED",
            "RISK_CLASSIFIED",
            "ARCHITECTED",
            "BACKLOG_READY",
            "IMPLEMENTING",
        ):
            state.transition_product(product_id, status)
        pipeline = PipelineCoordinator(config, state)
        task_path = pipeline.create_task(product_id, "security-reviewer", cycle=2)
        task_id = json.loads(task_path.read_text(encoding="utf-8"))["task_id"]
        security_output = config.evidence_dir / "security-review-output.json"
        security_output.write_text(
            json.dumps(
                {
                    "status": "repair_required",
                    "release_blocked": True,
                    "findings": [
                        {
                            "id": "SEC-WF-ASSIGNED-BOUNDARY-FAIL-OPEN",
                            "severity": "medium",
                            "description": "Assigned outcome end crosses its role boundary.",
                            "required_fix": "Reject every assigned row that crosses its role end.",
                        },
                        {
                            "id": "SEC-SCANS-NO-REGRESSION",
                            "severity": "info",
                            "description": "Scanner gates passed.",
                            "required_fix": "No fix required.",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        attempt_path = config.evidence_dir / "attempt-security-repair.json"
        attempt_path.write_text(
            json.dumps(
                {
                    "summary": "provider requested repair",
                    "test_results": [
                        {
                            "gate_id": "schema-validation",
                            "status": "PASS",
                            "evidence_ref": str(security_output),
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        assert state.claim_task(worker_id="security-worker") is not None
        assert state.record_attempt(
            attempt_id="attempt-security",
            task_id=task_id,
            tier="sol",
            attempt_kind="initial",
            prompt_digest="e" * 64,
            status="repair_required",
            semantic_counted=True,
            reason_code="model_requested_repair",
        )
        state.complete_task(
            task_id,
            "security-worker",
            "BLOCKED_EXTERNAL",
            reason_code="model_requested_repair",
            failure_kind="semantic",
            result_ref=str(attempt_path),
        )

        exhausted_result = PipelineReconciler(config, state).reconcile_once()

        assert exhausted_result.exhausted == 1
        product = state.get_product(product_id)
        assert product is not None
        assert product["status"] == "FAILED_SAFE"
        exhausted_payload = next(
            json.loads(item["payload_json"])
            for item in state.list_outbox()
            if json.loads(item["payload_json"])["kind"] == "repair_exhausted"
        )
        assert "SEC-WF-ASSIGNED-BOUNDARY-FAIL-OPEN" in exhausted_payload["text"]
        assert "Reject every assigned row" in exhausted_payload["text"]

        unchanged_result = PipelineReconciler(config, state).reconcile_once()
        assert unchanged_result.repaired == 0
        config.raw["controller"]["max_repair_cycles"] = 3

        reopened_result = PipelineReconciler(config, state).reconcile_once()

        assert reopened_result.repaired == 1
        product = state.get_product(product_id)
        assert product is not None
        assert product["status"] == "REPAIRING"
        active = state.active_tasks(product_id)
        assert len(active) == 1
        assert active[0]["stage_key"] == "builder-core"
        assert active[0]["cycle"] == 3
        assert active[0]["next_tier"] == "sol"
        brief = json.loads(
            (
                config.evidence_dir / Path(active[0]["repair_context_ref"]).name
            ).read_text(encoding="utf-8")
        )
        assert brief["failed_gate_ids"] == [
            "SEC-WF-ASSIGNED-BOUNDARY-FAIL-OPEN"
        ]
        assert brief["required_fixes"] == [
            "Reject every assigned row that crosses its role end."
        ]
        assert brief["allowed_paths"]
        assert "Reject every assigned row" in brief["relevant_log_fragment"]
        assert any(
            event["event_type"] == "repair_budget_reopened"
            for event in state.events(product_id)
        )
        recovered_payload = next(
            json.loads(item["payload_json"])
            for item in state.list_outbox()
            if (
                json.loads(item["payload_json"])["kind"] == "automatic_recovery"
                and "расширенного" in json.loads(item["payload_json"])["text"]
            )
        )
        assert "Действие владельца: не требуется" in recovered_payload["text"]
        assert list(config.evidence_dir.glob("owner-action-*.json")) == []
        state.close()


def test_interrupted_started_attempt_is_recovered_without_owner_action() -> None:
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(Path(directory))
        state = StateStore(config.database_path)
        product_id = "interrupted-attempt-product"
        state.create_product(
            product_id=product_id,
            owner_id="owner",
            source="cli",
            idea="Recover an interrupted task",
            idempotency_key="interrupted-attempt-key",
        )
        for status in (
            "CONTRACT_DRAFTED",
            "CONTRACT_VALIDATED",
            "RISK_CLASSIFIED",
            "ARCHITECTED",
            "BACKLOG_READY",
            "IMPLEMENTING",
        ):
            state.transition_product(product_id, status)
        task_path = PipelineCoordinator(config, state).create_task(
            product_id,
            "test-engineer",
            cycle=2,
        )
        task_id = json.loads(task_path.read_text(encoding="utf-8"))["task_id"]
        assert state.claim_task(worker_id="worker") is not None
        assert state.record_attempt(
            attempt_id="attempt-interrupted",
            task_id=task_id,
            tier="sol",
            attempt_kind="initial",
            prompt_digest="f" * 64,
            status="started",
            semantic_counted=True,
        )
        state.complete_task(
            task_id,
            "worker",
            "BLOCKED_EXTERNAL",
            reason_code="internal_blocker",
            detail=f"Prompt digest already attempted for task {task_id}",
            failure_kind="semantic",
        )
        state.transition_product(product_id, "FAILED_SAFE")

        result = PipelineReconciler(config, state).reconcile_once()

        assert result.repaired == 1
        product = state.get_product(product_id)
        assert product is not None
        assert product["status"] == "IMPLEMENTING"
        task = state.get_task(task_id)
        assert task is not None
        assert task["status"] == "PENDING"
        assert task["terminal_reason"] is None
        assert state.attempts_for_task(task_id)[0]["status"] == "started"
        assert any(
            event["event_type"] == "interrupted_attempt_recovered"
            for event in state.events(product_id)
        )
        payloads = [json.loads(item["payload_json"]) for item in state.list_outbox()]
        recovered = next(item for item in payloads if item["kind"] == "automatic_recovery")
        assert "Действие владельца: не требуется" in recovered["text"]
        assert list(config.evidence_dir.glob("owner-action-*.json")) == []
        state.close()


def test_completed_builder_is_recovered_when_only_github_gate_is_downstream() -> None:
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(Path(directory))
        state = StateStore(config.database_path)
        product_id = "builder-downstream-gate-product"
        state.create_product(
            product_id=product_id,
            owner_id="owner",
            source="cli",
            idea="https://github.com/brullik/bybit-grid-research",
            idempotency_key="builder-downstream-gate-key",
        )
        for status in (
            "CONTRACT_DRAFTED",
            "CONTRACT_VALIDATED",
            "RISK_CLASSIFIED",
            "ARCHITECTED",
            "BACKLOG_READY",
            "IMPLEMENTING",
            "REPAIRING",
        ):
            state.transition_product(product_id, status)
        pipeline = PipelineCoordinator(config, state)
        builder_path = pipeline.create_task(product_id, "builder-core", cycle=3)
        task_id = json.loads(builder_path.read_text(encoding="utf-8"))["task_id"]
        output_path = config.evidence_dir / "builder-deferred-output.json"
        output_path.write_text(
            json.dumps(
                {
                    "status": "blocked_external",
                    "summary": "Implementation and local PM acceptance are complete.",
                    "changed_files": [
                        {"path": "src/product.py", "change": "Applied the repair."}
                    ],
                    "test_results": [
                        {
                            "gate_id": "target-tests",
                            "status": "PASS",
                            "evidence_ref": "pytest: 715 passed",
                        },
                        {
                            "gate_id": "local-pm-acceptance",
                            "status": "PASS",
                            "evidence_ref": "frozen suite: 32 passed",
                        },
                        {
                            "gate_id": "AC-PM-SCOPE-GITHUB",
                            "status": "NOT_RUN",
                            "evidence_ref": None,
                        },
                    ],
                    "findings": [
                        {
                            "code": "GITHUB_REQUIRED_CHECK_NOT_RUN",
                            "severity": "medium",
                            "text": "The immutable candidate check belongs to release staging.",
                        },
                        {
                            "code": "OUT_OF_SCOPE_RUFF_BASELINE",
                            "severity": "low",
                            "text": "Unrelated repository baseline remains out of scope.",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        attempt_path = config.evidence_dir / "attempt-builder-deferred.json"
        attempt_path.write_text(
            json.dumps(
                {
                    "summary": "Provider reported a downstream-only blocker.",
                    "test_results": [
                        {
                            "gate_id": "schema-validation",
                            "status": "PASS",
                            "evidence_ref": str(output_path),
                        },
                        {"gate_id": "target-tests", "status": "PASS"},
                        {"gate_id": "target-lint", "status": "FAIL"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        assert state.claim_task(worker_id="builder-worker") is not None
        assert state.record_attempt(
            attempt_id="attempt-builder-deferred",
            task_id=task_id,
            tier="sol",
            attempt_kind="repair",
            prompt_digest="f" * 64,
            status="repair_required",
            semantic_counted=True,
            reason_code="model_requested_repair",
        )
        state.complete_task(
            task_id,
            "builder-worker",
            "BLOCKED_EXTERNAL",
            reason_code="model_requested_repair",
            detail="GitHub required check was not run.",
            result_ref=str(attempt_path),
            failure_kind="semantic",
        )
        state.transition_product(product_id, "FAILED_SAFE")

        result = PipelineReconciler(config, state).reconcile_once()

        assert result.recovered_successors == 1
        product = state.get_product(product_id)
        assert product is not None
        assert product["status"] == "REPAIRING"
        active = state.active_tasks(product_id)
        assert len(active) == 1
        assert active[0]["stage_key"] == "test-engineer"
        assert any(
            event["event_type"] == "builder_downstream_gate_deferred"
            for event in state.events(product_id)
        )
        notifications = [
            json.loads(item["payload_json"]) for item in state.list_outbox()
        ]
        assert any(
            "Следующий шаг: Test Engineer" in item["text"]
            and "Действие владельца: не требуется" in item["text"]
            for item in notifications
        )
        assert list(config.evidence_dir.glob("owner-action-*.json")) == []

        test_task_id = str(active[0]["task_id"])
        claimed = state.claim_task(worker_id="test-worker")
        assert claimed is not None
        assert claimed["task_id"] == test_task_id
        state.complete_task(
            test_task_id,
            "test-worker",
            "BLOCKED_EXTERNAL",
            reason_code="internal_blocker",
            detail=f"accepted task result is missing for {task_id}",
            failure_kind="semantic",
        )
        state.transition_product(product_id, "FAILED_SAFE")

        consumer_recovery = PipelineReconciler(config, state).reconcile_once()

        assert consumer_recovery.repaired == 1
        recovered_product = state.get_product(product_id)
        assert recovered_product is not None
        assert recovered_product["status"] == "REPAIRING"
        recovered_test_task = state.get_task(test_task_id)
        assert recovered_test_task is not None
        assert recovered_test_task["status"] == "PENDING"
        assert recovered_test_task["next_attempt_kind"] == "initial"
        recovery_events = [
            event
            for event in state.events(product_id)
            if event["event_type"] == "deferred_dependency_consumer_recovered"
        ]
        assert len(recovery_events) == 1

        PipelineReconciler(config, state).reconcile_once()
        assert len(
            [
                event
                for event in state.events(product_id)
                if event["event_type"]
                == "deferred_dependency_consumer_recovered"
            ]
        ) == 1
        state.close()


def test_reconciler_reads_optional_gate_policy_fail_closed() -> None:
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(Path(directory))
        state = StateStore(config.database_path)

        reconciler = PipelineReconciler(config, state)

        assert "target-lint" in reconciler.optional_gate_ids
        assert "target-tests" not in reconciler.optional_gate_ids
        assert "unknown-gate" not in reconciler.optional_gate_ids
        state.close()


def test_exhausted_builder_opens_next_cycle_with_exact_gate_traceback() -> None:
    with tempfile.TemporaryDirectory() as directory:
        config = make_config(Path(directory))
        state = StateStore(config.database_path)
        product_id = "bounded-builder-cycle-product"
        state.create_product(
            product_id=product_id,
            owner_id="owner",
            source="cli",
            idea="https://github.com/brullik/example-product",
            idempotency_key="bounded-builder-cycle-key",
        )
        for status in (
            "CONTRACT_DRAFTED",
            "CONTRACT_VALIDATED",
            "RISK_CLASSIFIED",
            "ARCHITECTED",
            "BACKLOG_READY",
        ):
            state.transition_product(product_id, status)
        pipeline = PipelineCoordinator(config, state)
        builder_path = pipeline.create_task(product_id, "builder-core", cycle=0)
        task_id = json.loads(builder_path.read_text(encoding="utf-8"))["task_id"]
        gate_path = config.evidence_dir / "gate-builder-target-tests.json"
        gate_path.write_text(
            json.dumps(
                {
                    "gate_id": "target-tests",
                    "status": "FAIL",
                    "summary": (
                        "ImportError in tests/test_core.py: "
                        "ModuleNotFoundError: No module named 'grid_bot'"
                    ),
                }
            ),
            encoding="utf-8",
        )
        attempt_path = config.evidence_dir / "attempt-builder-exhausted.json"
        attempt_path.write_text(
            json.dumps(
                {
                    "summary": "Mandatory quality gate failed.",
                    "test_results": [
                        {
                            "gate_id": "target-tests",
                            "status": "FAIL",
                            "evidence_ref": str(gate_path),
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        assert state.claim_task(worker_id="builder-worker") is not None
        attempts = (
            ("luna-1", "luna"),
            ("luna-2", "luna"),
            ("terra-1", "terra"),
            ("terra-2", "terra"),
            ("sol-1", "sol"),
        )
        for index, (attempt_id, tier) in enumerate(attempts, start=1):
            assert state.record_attempt(
                attempt_id=attempt_id,
                task_id=task_id,
                tier=tier,
                attempt_kind="repair",
                prompt_digest=(str(index) * 64),
                status="failed",
                semantic_counted=True,
                reason_code="mandatory_gate_failed",
            )
        state.complete_task(
            task_id,
            "builder-worker",
            "FAILED_SAFE",
            reason_code="mandatory_gate_failed",
            detail="failed mandatory gates: target-tests",
            result_ref=str(attempt_path),
            failure_kind="semantic",
        )
        state.transition_product(product_id, "FAILED_SAFE")
        state.record_event(
            product_id=product_id,
            task_id=task_id,
            event_type="repair_budget_exhausted",
            payload={"reason_code": "mandatory_gate_failed", "attempts": 5},
        )

        first = PipelineReconciler(config, state).reconcile_once()

        assert first.repaired == 1
        product = state.get_product(product_id)
        assert product is not None
        assert product["status"] == "REPAIRING"
        active = state.active_tasks(product_id)
        assert len(active) == 1
        assert active[0]["role"] == "builder"
        assert active[0]["cycle"] == 1
        assert active[0]["next_tier"] == "terra"
        brief = json.loads(
            (
                config.evidence_dir / Path(active[0]["repair_context_ref"]).name
            ).read_text(encoding="utf-8")
        )
        assert "target-tests" in brief["failed_gate_ids"]
        assert any(
            "ModuleNotFoundError: No module named 'grid_bot'" in item
            for item in brief["required_fixes"]
        )
        assert "ModuleNotFoundError" in brief["relevant_log_fragment"]
        assert any(
            event["event_type"] == "builder_cycle_reopened"
            for event in state.events(product_id)
        )

        second = PipelineReconciler(config, state).reconcile_once()

        assert second.repaired == 0
        assert len(state.active_tasks(product_id)) == 1
        state.close()
