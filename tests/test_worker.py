from __future__ import annotations

import json
import sqlite3
import subprocess
import tempfile
import time
import unittest
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml

from factory.artifacts import ArtifactStore, artifact_metadata
from factory.attempts import IdenticalAttemptError
from factory.common import sha256_text, stable_json
from factory.config import FactoryConfig
from factory.intake import IntakeService
from factory.pipeline import PipelineCoordinator
from factory.policy import policy_digest
from factory.providers import ModelSelection
from factory.quality import QualityGateRun
from factory.reconciler import PipelineReconciler
from factory.state import StateStore
from factory.worker import (
    AgentWorker,
    HermesRunResult,
    SubprocessHermesRunner,
    TaskExecutionSpec,
    WorkerResult,
    _workspace_snapshot,
    public_github_repository_url,
)

ROOT = Path(__file__).resolve().parents[1]


def make_retry_due(state: StateStore, task_id: str) -> None:
    """Advance one durable retry timer without sleeping in a unit test."""

    with state._lock, state._connection:
        state._connection.execute(
            "UPDATE tasks SET available_at='2000-01-01T00:00:00Z' "
            "WHERE task_id=? AND graph_status='WAITING_TIME'",
            (task_id,),
        )


def make_config(root: Path, registry: Path | None = None) -> FactoryConfig:
    raw = yaml.safe_load((ROOT / "config" / "factory-config.example.yaml").read_text(encoding="utf-8"))
    raw["paths"]["state"] = str(root)
    raw["paths"]["policies"] = str(ROOT / "policies")
    raw["paths"]["schemas"] = str(ROOT / "schemas")
    raw["paths"]["prompts"] = str(ROOT / "prompts")
    raw["paths"]["worktrees"] = str(root / "worktrees")
    raw["paths"]["logs"] = str(root / "logs")
    raw["controller"]["database_url"] = f"sqlite:///{(root / 'controller.db').as_posix()}"
    if registry is not None:
        raw["models"]["registry"] = str(registry)
    return FactoryConfig(raw, ROOT / "config" / "factory-config.example.yaml")


class FakeRunner:
    def __init__(self, output: str) -> None:
        self.output = output
        self.calls: list[tuple[str, str, Path]] = []

    def run(
        self,
        *,
        selection: Any,
        prompt: str,
        cwd: Path,
        usage_path: Path | None = None,
    ) -> HermesRunResult:
        self.calls.append((selection.model, selection.provider, cwd))
        return HermesRunResult("PASS", self.output, "fake-output-digest", None, str(usage_path) if usage_path else None)


class SequenceRunner:
    def __init__(self, outputs: list[str]) -> None:
        self.outputs = list(outputs)
        self.prompts: list[str] = []

    def run(
        self,
        *,
        selection: Any,
        prompt: str,
        cwd: Path,
        usage_path: Path | None = None,
    ) -> HermesRunResult:
        del selection, cwd
        self.prompts.append(prompt)
        if not self.outputs:
            raise AssertionError("SequenceRunner was called more times than expected")
        output = self.outputs.pop(0)
        return HermesRunResult("PASS", output, "sequence-output-digest", None, str(usage_path) if usage_path else None)


class UsageRunner(FakeRunner):
    def run(
        self,
        *,
        selection: Any,
        prompt: str,
        cwd: Path,
        usage_path: Path | None = None,
    ) -> HermesRunResult:
        if usage_path is not None:
            usage_path.write_text(
                json.dumps(
                    {
                        "input_tokens": 42,
                        "output_tokens": 7,
                        "cache_tokens": 3,
                        "tool_rounds": 1,
                        "wall_clock_seconds": 0.25,
                    }
                ),
                encoding="utf-8",
            )
        return super().run(selection=selection, prompt=prompt, cwd=cwd, usage_path=usage_path)


class ScopeViolatingRunner(FakeRunner):
    def run(
        self,
        *,
        selection: Any,
        prompt: str,
        cwd: Path,
        usage_path: Path | None = None,
    ) -> HermesRunResult:
        (cwd / "forbidden.txt").write_text("unexpected change\n", encoding="utf-8")
        return super().run(selection=selection, prompt=prompt, cwd=cwd, usage_path=usage_path)


class PassingQuality:
    def run(self, **_: object) -> QualityGateRun:
        return QualityGateRun(
            (
                {
                    "gate_id": "security-preflight",
                    "status": "PASS",
                    "evidence_ref": "evidence/security-preflight.json",
                },
            ),
            (),
            True,
        )


class RecordingReleaseExecutor:
    def __init__(self, result: dict[str, object]) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def execute(
        self,
        *,
        stage: str,
        proposed: Mapping[str, Any],
        product_id: str,
        task_contract: Mapping[str, Any],
        workspace: Path,
        expected_staging_digest: str | None,
    ) -> Mapping[str, Any]:
        self.calls.append(
            {
                "stage": stage,
                "proposed": dict(proposed),
                "product_id": product_id,
                "task_contract": dict(task_contract),
                "workspace": workspace,
                "expected_staging_digest": expected_staging_digest,
            }
        )
        return self.result


def selected_registry(path: Path, *, selected: str | None) -> Path:
    data = yaml.safe_load((ROOT / "config" / "model-routing" / "model-registry.template.yaml").read_text(encoding="utf-8"))
    for alias in ("economy", "standard", "expert"):
        data["aliases"][alias]["selected"] = selected
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def product_contract(config: FactoryConfig, product_id: str) -> str:
    artifact = json.loads((ROOT / "templates" / "product-contract.example.json").read_text(encoding="utf-8"))
    artifact["artifact_id"] = "product-contract-worker-test"
    artifact["product_id"] = product_id
    artifact["policy_digest"] = policy_digest(config)
    artifact["producer"] = {
        "role": "product-director",
        "tier": "luna",
        "provider": "openai_codex_subscription",
        "model": "gpt-5.6-luna",
    }
    artifact["status"] = "completed"
    artifact["created_at"] = "2026-01-01T00:00:00Z"
    return json.dumps(artifact, ensure_ascii=False)


def replanner_task_contract(
    config: FactoryConfig,
    product_id: str,
    task_id: str,
) -> dict[str, Any]:
    plan_id = f"PLAN-SYSTEM-{sha256_text(product_id)[:16].upper()}"
    return {
        "schema_version": "2.0",
        "artifact_id": f"task-contract-{task_id}",
        "product_id": product_id,
        "task_id": task_id,
        "root_task_id": task_id,
        "parent_task_id": None,
        "source_task_id": task_id,
        "plan_id": plan_id,
        "plan_node_id": "replanner",
        "task_revision": 1,
        "root_context_ref": f"evidence/intake-{product_id}.json",
        "active_context_ref": f"evidence/task-{task_id}.json",
        "failure_id": None,
        "hypothesis_id": None,
        "supersedes_task_id": None,
        "title": "Replan the product graph",
        "objective": "Create a corrected executable product graph revision",
        "role": "replanner",
        "output_schema": "backlog-plan-v2.schema.json",
        "dependencies": [],
        "conflict_keys": [f"{product_id}:planning"],
        "acceptance": [
            {
                "criterion_id": "accept-replan",
                "verification": "The corrected graph passes semantic validation",
                "mandatory": True,
            }
        ],
        "required_capabilities": [
            "artifact.read",
            "artifact.write",
            "repository.read_bounded",
            "state.read",
            "plan.propose",
        ],
        "capability_profile": "planning_readonly",
        "allowed_paths": ["artifacts/**"],
        "forbidden_paths": ["secrets/**"],
        "risk_tier": "medium",
        "model_floor": "luna",
        "idempotency_key": sha256_text(f"replanner:{product_id}:{task_id}"),
        "status": "READY",
        "priority": 100,
        "critical_path_rank": 0,
    }


def backlog_plan_with_missing_edge(
    config: FactoryConfig,
    product_id: str,
    replanner_task_id: str,
) -> dict[str, Any]:
    plan_id = "PLAN-SEMANTIC-REPAIR"
    child_task_id = "T-SEMANTIC-CHILD"
    child_contract = {
        **replanner_task_contract(config, product_id, child_task_id),
        "artifact_id": f"task-contract-{child_task_id}",
        "root_task_id": replanner_task_id,
        "parent_task_id": replanner_task_id,
        "source_task_id": replanner_task_id,
        "plan_id": plan_id,
        "plan_node_id": "node-a",
        "title": "Implement the corrected node",
        "objective": "Implement and verify the corrected product behavior",
        "role": "builder",
        "output_schema": "attempt-result.schema.json",
        "conflict_keys": [f"{product_id}:src"],
        "required_capabilities": [
            "artifact.read",
            "artifact.write",
            "repository.read",
            "repository.write_scoped",
            "command.execute_allowlisted",
            "test.execute",
        ],
        "capability_profile": "builder_workspace",
        "allowed_paths": ["src/**"],
        "idempotency_key": sha256_text(
            f"{plan_id}:node-a:{child_task_id}"
        ),
        "priority": 50,
    }
    return {
        "schema_version": "2.0",
        "artifact_id": "backlog-plan-semantic-repair",
        "product_id": product_id,
        "created_at": "2026-07-29T00:00:00Z",
        "producer": {
            "role": "replanner",
            "tier": "luna",
            "provider": "openai_codex_subscription",
            "model": "gpt-5.6-luna",
        },
        "policy_digest": policy_digest(config),
        "status": "completed",
        "plan_id": plan_id,
        "revision": 1,
        "parent_plan_id": None,
        "source_failure_id": None,
        "goals": [
            {
                "goal_id": "root-goal",
                "statement": "Deliver the corrected product",
                "mandatory": True,
                "acceptance_ids": ["accept-replan"],
            }
        ],
        "nodes": [
            {
                "node_id": "node-a",
                "mandatory": True,
                "task_contract": child_contract,
            }
        ],
        "edges": [
            {
                "from": "node-a",
                "to": "missing-node",
                "edge_type": "depends_on",
                "required": True,
            }
        ],
        "completion_criteria": [
            "The mandatory corrected node has immutable PASS evidence"
        ],
        "summary": "A schema-valid plan with one missing semantic edge endpoint",
    }


def requirements_package(config: FactoryConfig, product_id: str) -> str:
    artifact = {
        **artifact_metadata(config, "product-analyst", "requirements-worker-test", product_id),
        "status": "completed",
        "summary": "Traceable requirements derived from the accepted Product Contract.",
        "domain_terms": [{"term": "product", "definition": "The owner-scoped deliverable."}],
        "user_stories": [
            {
                "id": "US-001",
                "actor": "owner",
                "goal": "inspect the accepted deliverable",
                "benefit": "the result is verifiable",
                "acceptance_ids": ["AC-001"],
            }
        ],
        "edge_cases": [],
        "traceability": [{"requirement_id": "REQ-001", "story_ids": ["US-001"], "acceptance_ids": ["AC-001"]}],
        "assumptions": ["The owner can inspect the result locally."],
        "findings": [],
        "evidence_refs": ["evidence/product-contract-worker-test.json"],
    }
    return json.dumps(artifact, ensure_ascii=False)


def release_operation(
    config: FactoryConfig,
    product_id: str,
    *,
    candidate_sha: str,
    image_digest: str,
) -> dict[str, object]:
    return {
        **artifact_metadata(config, "release-operator", "release-operation-test", product_id),
        "status": "completed",
        "repository": "brullik/hermes-software-factory",
        "candidate_sha": candidate_sha,
        "merge": {"performed": False, "merge_sha": None},
        "release": {"version": "0.1.0", "image_digest": image_digest},
        "staging": "deployed",
        "production": "not_started",
        "rollback": "not_tested",
        "summary": "Adapter-backed staging release fixture.",
        "findings": [],
        "evidence_refs": ["evidence/gates.json", "evidence/staging.json"],
    }


def staging_release_task(config: FactoryConfig, state: Any, artifacts: ArtifactStore) -> tuple[str, Path]:
    product_id = "P-RELEASE-001"
    state.create_product(
        product_id=product_id,
        owner_id="owner",
        source="test",
        idea="Build a release-backed product",
        idempotency_key="release-test-001",
    )
    for status in (
        "CONTRACT_DRAFTED",
        "CONTRACT_VALIDATED",
        "RISK_CLASSIFIED",
        "ARCHITECTED",
        "BACKLOG_READY",
        "IMPLEMENTING",
        "INTEGRATING",
    ):
        state.transition_product(product_id, status)
    return product_id, PipelineCoordinator(config, state, artifacts).create_task(product_id, "release-staging")


class WorkerTests(unittest.TestCase):
    def test_provider_output_secret_is_redacted_and_task_continues(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(
                root / "registry.yaml",
                selected="gpt-5.6-luna",
            )
            config = make_config(root, registry_path)
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
            )
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli",
                owner_id="owner",
                idea="Sanitize provider transport without blocking the product",
            )
            marker = "ghp_" + ("A" * 24)
            payload = json.loads(
                product_contract(config, intake_result.product_id)
            )
            payload["summary"] = f"Example credential {marker}"
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner(json.dumps(payload)),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "completed")
            self.assertIsNone(result.reason_code)
            self.assertIsNotNone(result.artifact_ref)
            attempt = json.loads(
                Path(str(result.artifact_ref)).read_text(encoding="utf-8")
            )
            self.assertIn(
                "$.summary (github_classic_token)",
                attempt["summary"],
            )
            output_ref = next(
                item["evidence_ref"]
                for item in attempt["test_results"]
                if item["gate_id"] == "schema-validation"
            )
            output = json.loads(Path(output_ref).read_text(encoding="utf-8"))
            self.assertEqual(
                output["summary"],
                "Example credential [REDACTED]",
            )
            self.assertNotIn(marker, attempt["summary"])
            self.assertTrue(
                all(
                    marker not in path.read_text(encoding="utf-8")
                    for path in config.evidence_dir.glob("*.json")
                )
            )
            state.close()

    def test_run_once_renews_lease_during_long_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root,
                selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"),
            )
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            state.create_product(
                product_id="P-LEASE-HEARTBEAT",
                owner_id="owner",
                source="test",
                idea="Verify long task lease renewal",
                idempotency_key="lease-heartbeat-test",
            )
            PipelineCoordinator(config, state).seed_initial("P-LEASE-HEARTBEAT")
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner("{}"),
                repository_root=ROOT,
                lease_seconds=1,
                heartbeat_interval_seconds=0.02,
            )

            def slow_execute(spec: TaskExecutionSpec) -> WorkerResult:
                time.sleep(0.08)
                return WorkerResult(
                    str(spec.task_contract["task_id"]),
                    "completed",
                    None,
                )

            with (
                patch.object(worker, "execute", side_effect=slow_execute),
                patch.object(state, "heartbeat", wraps=state.heartbeat) as heartbeat,
            ):
                result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "completed")
            self.assertGreaterEqual(heartbeat.call_count, 2)
            tasks = state.list_tasks("P-LEASE-HEARTBEAT")
            self.assertEqual(tasks[0]["status"], "DONE")
            state.close()

    def test_schema_valid_repair_is_requeued_with_targeted_brief(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli", owner_id="owner", idea="Repairable provider task"
            )
            repair = json.loads(product_contract(config, intake_result.product_id))
            repair["status"] = "repair_required"
            repair["summary"] = "The provider needs one targeted repair before acceptance."
            completed = json.loads(product_contract(config, intake_result.product_id))
            runner = SequenceRunner([json.dumps(repair), json.dumps(completed)])
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            first = worker.run_once()

            self.assertIsNotNone(first)
            assert first is not None
            self.assertEqual(first.status, "repair_required")
            source_task = next(iter(state.list_tasks(intake_result.product_id)))
            self.assertEqual(source_task["status"], "FAILED_SAFE")
            self.assertEqual(source_task["graph_status"], "FAILED_SEMANTIC")
            self.assertEqual(len(state.list_failures(intake_result.product_id)), 1)

            recovery = PipelineReconciler(config, state).reconcile_once()

            self.assertEqual(recovery.repaired, 1)
            tasks = state.list_tasks(intake_result.product_id)
            self.assertEqual(len(tasks), 2)
            task = next(
                item for item in tasks if item["task_id"] != source_task["task_id"]
            )
            self.assertEqual(task["status"], "PENDING")
            self.assertEqual(task["graph_status"], "READY")
            self.assertEqual(task["parent_task_id"], source_task["task_id"])
            self.assertEqual(task["source_task_id"], source_task["task_id"])
            self.assertEqual(task["root_task_id"], source_task["root_task_id"])
            self.assertEqual(task["next_attempt_kind"], "initial")
            brief_paths = list(config.evidence_dir.glob("repair-brief-*.json"))
            self.assertEqual(len(brief_paths), 1)
            brief = json.loads(brief_paths[0].read_text(encoding="utf-8"))
            self.assertEqual(brief["schema_version"], "2.0")
            self.assertEqual(brief["failed_task_id"], source_task["task_id"])
            self.assertEqual(brief["hypothesis_id"], task["hypothesis_id"])
            self.assertTrue(brief["failed_gate_ids"])
            self.assertTrue(brief["required_fixes"])
            self.assertEqual(brief["allowed_paths"], ["artifacts/**"])

            second = worker.run_once()

            self.assertIsNotNone(second)
            assert second is not None
            self.assertEqual(second.status, "completed", second.reason_code)
            repaired = state.get_task(str(task["task_id"]))
            self.assertIsNotNone(repaired)
            assert repaired is not None
            self.assertEqual(repaired["status"], "DONE")
            superseded = state.get_task(str(source_task["task_id"]))
            self.assertIsNotNone(superseded)
            assert superseded is not None
            self.assertEqual(superseded["graph_status"], "SUPERSEDED")
            self.assertEqual(len(state.attempts_for_task(str(task["task_id"]))), 1)
            self.assertIn("repair-brief-", runner.prompts[1])
            self.assertIn("UNTRUSTED_DATA targeted repair brief", runner.prompts[1])
            self.assertIn(str(brief["failure_id"]), runner.prompts[1])
            state.close()

    def test_partial_repair_brief_fails_internally_before_provider_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(
                root / "registry.yaml", selected="gpt-5.6-luna"
            )
            config = make_config(root, registry_path)
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
            )
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli",
                owner_id="owner",
                idea="Reject an incomplete internal repair brief",
            )
            task = state.claim_task(worker_id="failed-worker")
            self.assertIsNotNone(task)
            assert task is not None
            state.complete_task(
                str(task["task_id"]),
                "failed-worker",
                "FAILED_SAFE",
                reason_code="worker_internal_error",
                detail="repair preparation failed",
                failure_kind="semantic",
            )
            bad_brief = {
                **artifact_metadata(
                    config,
                    "repair-coordinator",
                    "repair-brief-partial-test",
                    intake_result.product_id,
                ),
                "producer": {
                    "role": "repair-coordinator",
                    "tier": "deterministic",
                    "provider": None,
                    "model": None,
                },
                "task_id": str(task["task_id"]),
                "attempt_id": "attempt-partial-brief",
                "failure_class": "worker_internal_error",
                "failed_gate_ids": ["repair-brief-validation"],
                "required_fixes": ["Attach the exact allowed paths."],
                "relevant_log_fragment": "allowed_paths is missing",
                "expected_vs_actual": {
                    "expected": "a complete actionable brief",
                    "actual": "allowed_paths is missing",
                },
                "changed_files": [],
                "forbidden_actions": [],
                "previous_attempt_summary": "Repair preparation failed.",
                "definition_of_done": ["The brief passes schema validation."],
                "evidence_refs": [f"evidence/task-{task['task_id']}.json"],
            }
            brief_path = config.evidence_dir / (
                f"repair-brief-{task['task_id']}-partial.json"
            )
            brief_path.write_text(json.dumps(bad_brief), encoding="utf-8")
            state.requeue_terminal_task(
                str(task["task_id"]),
                next_tier="luna",
                repair_context_ref=f"evidence/{brief_path.name}",
            )
            runner = FakeRunner(product_contract(config, intake_result.product_id))
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(
                result.reason_code,
                "controller_exception_value_error",
            )
            self.assertEqual(runner.calls, [])
            durable = state.get_task(str(task["task_id"]))
            self.assertIsNotNone(durable)
            assert durable is not None
            self.assertEqual(durable["status"], "FAILED_SAFE")
            failure = state.list_failures(intake_result.product_id)[-1]
            self.assertEqual(failure["exception_type"], "ValueError")
            self.assertTrue(failure["stack_fingerprint"])
            actual = json.loads(str(failure["actual_json"]))
            self.assertIn("traceback_excerpt", actual)
            state.close()

    def test_semantic_backlog_error_schedules_exact_repair_without_worker_crash(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root,
                selected_registry(
                    root / "registry.yaml",
                    selected="gpt-5.6-luna",
                ),
            )
            state = StateStore(config.database_path)
            artifacts = ArtifactStore(config)
            product_id = "P-SEMANTIC-PLAN"
            task_id = "T-SEMANTIC-REPLANNER"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="test",
                idea="Repair a semantically invalid BacklogPlan",
                idempotency_key="semantic-plan-product",
            )
            task_contract = replanner_task_contract(
                config,
                product_id,
                task_id,
            )
            contract_path = artifacts.write(
                "task-contract-v2.schema.json",
                task_contract,
                filename=f"task-{task_id}.json",
            )
            state.add_task(
                task_id=task_id,
                product_id=product_id,
                title=str(task_contract["title"]),
                role="replanner",
                output_schema="backlog-plan-v2.schema.json",
                contract_ref=f"evidence/{contract_path.name}",
                conflict_keys=[f"{product_id}:planning"],
                priority=100,
                capability_profile="planning_readonly",
                idempotency_key=str(task_contract["idempotency_key"]),
                required_capabilities=[
                    str(value)
                    for value in task_contract["required_capabilities"]
                ],
            )
            plan = backlog_plan_with_missing_edge(
                config,
                product_id,
                task_id,
            )
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner(json.dumps(plan)),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "repair_scheduled")
            self.assertEqual(result.reason_code, "schema_validation")
            durable = state.get_task(task_id)
            self.assertIsNotNone(durable)
            assert durable is not None
            self.assertEqual(durable["status"], "PENDING")
            self.assertEqual(durable["graph_status"], "READY")
            self.assertEqual(durable["next_attempt_kind"], "repair")
            self.assertTrue(durable["repair_context_ref"])
            repair = json.loads(
                next(
                    config.evidence_dir.glob(
                        f"repair-brief-{task_id}-*.json"
                    )
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                repair["failed_gate_ids"],
                ["BACKLOG_PLAN_SEMANTIC_VALIDATION"],
            )
            self.assertIn(
                "BacklogPlan edges[0].to endpoint is missing",
                repair["expected_vs_actual"]["actual"],
            )
            diagnostic = json.loads(
                next(
                    config.evidence_dir.glob(
                        "transport-diagnostic-*.json"
                    )
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                diagnostic["parser_error_safe_message"],
                "BacklogPlan edges[0].to endpoint is missing",
            )
            self.assertEqual(len(state.list_tasks(product_id)), 1)
            self.assertFalse(
                (
                    config.evidence_dir
                    / "task-T-SEMANTIC-CHILD.json"
                ).exists()
            )
            state.close()

    def test_outcome_commit_integrity_error_becomes_controller_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root,
                selected_registry(
                    root / "registry.yaml",
                    selected="gpt-5.6-luna",
                ),
            )
            state = StateStore(config.database_path)
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli",
                owner_id="owner",
                idea="Persist a controller failure instead of crashing",
            )
            original_commit = state.commit_task_outcome
            commit_calls = 0

            def fail_first_commit(outcome: object) -> object:
                nonlocal commit_calls
                commit_calls += 1
                if commit_calls == 1:
                    raise sqlite3.IntegrityError(
                        "UNIQUE constraint failed: tasks.idempotency_key"
                    )
                return original_commit(outcome)

            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner(
                    product_contract(config, intake_result.product_id)
                ),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )
            with patch.object(
                state,
                "commit_task_outcome",
                side_effect=fail_first_commit,
            ):
                result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(
                result.reason_code,
                "controller_exception_integrity_error",
            )
            self.assertEqual(commit_calls, 2)
            task = state.list_tasks(intake_result.product_id)[0]
            self.assertEqual(task["status"], "FAILED_SAFE")
            self.assertEqual(task["graph_status"], "FAILED_SEMANTIC")
            failure = state.list_failures(intake_result.product_id)[-1]
            self.assertEqual(failure["failure_class"], "controller")
            self.assertEqual(
                failure["reason_code"],
                "controller_exception_integrity_error",
            )
            self.assertEqual(failure["exception_type"], "IntegrityError")
            state.close()

    def test_malformed_transport_is_requeued_at_same_tier_and_can_resume(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli", owner_id="owner", idea="Resume after transient provider failure"
            )
            runner = SequenceRunner(["not-json", product_contract(config, intake_result.product_id)])
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            first = worker.run_once()

            self.assertIsNotNone(first)
            assert first is not None
            self.assertEqual(first.status, "repair_scheduled")
            self.assertEqual(first.reason_code, "malformed_transport")
            task = next(iter(state.list_tasks(intake_result.product_id)))
            self.assertEqual(task["status"], "WAITING")
            self.assertEqual(task["graph_status"], "WAITING_TIME")
            self.assertTrue(task["available_at"])
            attempts = state.attempts_for_task(str(task["task_id"]))
            self.assertEqual(len(attempts), 1)
            self.assertEqual(attempts[0]["attempt_kind"], "initial")

            make_retry_due(state, str(task["task_id"]))
            second = worker.run_once()

            self.assertIsNotNone(second)
            assert second is not None
            self.assertEqual(second.status, "completed")
            attempts = state.attempts_for_task(str(task["task_id"]))
            self.assertEqual(len(attempts), 2)
            self.assertEqual(attempts[1]["attempt_kind"], "transient_retry")
            self.assertNotEqual(attempts[0]["prompt_digest"], attempts[1]["prompt_digest"])
            self.assertIn("repair-brief-", runner.prompts[1])
            state.close()

    def test_transient_retry_preserves_original_repair_hypothesis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(
                root / "registry.yaml",
                selected="gpt-5.6-luna",
            )
            config = make_config(root, registry_path)
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
            )
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli",
                owner_id="owner",
                idea="Preserve the diagnosed repair across a transient retry",
            )
            repair = json.loads(product_contract(config, intake_result.product_id))
            repair["status"] = "repair_required"
            repair["summary"] = "The original security hypothesis needs one repair."
            repair["findings"] = [
                {
                    "code": "SEC-ORIGINAL-HYPOTHESIS",
                    "severity": "high",
                    "text": "Add the exact original security regression.",
                }
            ]
            completed = json.loads(product_contract(config, intake_result.product_id))
            runner = SequenceRunner(
                [
                    json.dumps(repair),
                    "not-json",
                    json.dumps(completed),
                ]
            )
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            first = worker.run_once()

            self.assertIsNotNone(first)
            assert first is not None
            self.assertEqual(first.status, "repair_required")
            source_task = next(iter(state.list_tasks(intake_result.product_id)))
            recovery = PipelineReconciler(config, state).reconcile_once()
            self.assertEqual(recovery.repaired, 1)
            task = next(
                item
                for item in state.list_tasks(intake_result.product_id)
                if item["task_id"] != source_task["task_id"]
            )
            original_ref = str(task["repair_context_ref"])
            original_brief = json.loads(
                (config.evidence_dir / Path(original_ref).name).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                original_brief["failed_gate_ids"],
                ["SEC-ORIGINAL-HYPOTHESIS"],
            )

            second = worker.run_once()

            self.assertIsNotNone(second)
            assert second is not None
            self.assertEqual(second.status, "repair_scheduled")
            self.assertEqual(second.reason_code, "malformed_transport")
            task = state.get_task(str(task["task_id"]))
            self.assertIsNotNone(task)
            assert task is not None
            self.assertEqual(task["status"], "WAITING")
            self.assertEqual(task["graph_status"], "WAITING_TIME")
            transient_ref = str(task["repair_context_ref"])
            self.assertNotEqual(transient_ref, original_ref)
            transient_brief = json.loads(
                (config.evidence_dir / Path(transient_ref).name).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                transient_brief["failed_gate_ids"],
                ["SEC-ORIGINAL-HYPOTHESIS"],
            )
            self.assertEqual(
                transient_brief["required_fixes"],
                original_brief["required_fixes"],
            )
            self.assertEqual(
                transient_brief["hypothesis_id"],
                original_brief["hypothesis_id"],
            )
            self.assertIn(original_ref, transient_brief["evidence_refs"])

            make_retry_due(state, str(task["task_id"]))
            third = worker.run_once()

            self.assertIsNotNone(third)
            assert third is not None
            self.assertEqual(third.status, "completed", third.reason_code)
            self.assertIn("SEC-ORIGINAL-HYPOTHESIS", runner.prompts[2])
            self.assertIn(
                "Add the exact original security regression.",
                runner.prompts[2],
            )
            state.close()

    def test_release_task_blocks_before_model_without_side_effect_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            product_id, _ = staging_release_task(config, state, artifacts)
            runner = FakeRunner(
                json.dumps(
                    release_operation(
                        config,
                        product_id,
                        candidate_sha="a" * 40,
                        image_digest="sha256:" + "b" * 64,
                    )
                )
            )
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(result.reason_code, "release_adapter_missing")
            self.assertEqual(result.detail, "release side-effect adapter is not configured")
            self.assertEqual(runner.calls, [])
            task = next(iter(state.list_tasks(product_id)))
            self.assertEqual(task["status"], "FAILED_SAFE")
            self.assertEqual(task["graph_status"], "FAILED_SEMANTIC")
            self.assertEqual(state.attempts_for_task(str(task["task_id"])), [])
            failure = state.list_failures(product_id)[0]
            self.assertEqual(failure["failure_class"], "controller")
            self.assertEqual(
                list(config.evidence_dir.glob("owner-action-*.json")),
                [],
            )
            state.close()

    def test_completed_duplicate_prompt_is_internal_not_external(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli",
                owner_id="owner",
                idea="Classify a duplicate prompt safely",
            )
            runner = FakeRunner(product_contract(config, intake_result.product_id))
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            with patch.object(
                worker.attempts,
                "begin",
                side_effect=IdenticalAttemptError("Prompt digest already attempted"),
            ):
                result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(result.reason_code, "duplicate_prompt_attempt")
            task = next(iter(state.list_tasks(intake_result.product_id)))
            self.assertEqual(task["status"], "FAILED_SAFE")
            self.assertEqual(task["terminal_reason"], "duplicate_prompt_attempt")
            self.assertEqual(runner.calls, [])
            state.close()

    def test_release_task_persists_only_adapter_authoritative_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            product_id, _ = staging_release_task(config, state, artifacts)
            proposed = release_operation(
                config,
                product_id,
                candidate_sha="a" * 40,
                image_digest="sha256:" + "b" * 64,
            )
            authoritative = release_operation(
                config,
                product_id,
                candidate_sha="c" * 40,
                image_digest="sha256:" + "d" * 64,
            )
            executor = RecordingReleaseExecutor(authoritative)
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner(json.dumps(proposed)),
                release_executor=executor,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "completed")
            self.assertEqual(len(executor.calls), 1)
            self.assertEqual(executor.calls[0]["proposed"], proposed)
            output_paths = list(config.evidence_dir.glob("release-operation-result-*.json"))
            self.assertEqual(len(output_paths), 1)
            persisted = json.loads(output_paths[0].read_text(encoding="utf-8"))
            self.assertEqual(persisted["candidate_sha"], "c" * 40)
            self.assertEqual(persisted["release"]["image_digest"], "sha256:" + "d" * 64)
            self.assertEqual(state.get_product(product_id)["status"], "STAGING_DEPLOYED")
            state.close()

    def test_release_scope_is_checked_before_adapter_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            product_id, _ = staging_release_task(config, state, artifacts)
            proposed = release_operation(
                config,
                product_id,
                candidate_sha="a" * 40,
                image_digest="sha256:" + "b" * 64,
            )
            executor = RecordingReleaseExecutor(proposed)
            worker = AgentWorker(
                config,
                state,
                runner=ScopeViolatingRunner(json.dumps(proposed)),
                release_executor=executor,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(result.reason_code, "scope_violation")
            self.assertEqual(executor.calls, [])
            state.close()

    def test_worker_runs_selected_provider_and_persists_contract_and_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            intake = IntakeService(config, state, artifacts)
            intake_result = intake.submit(source="cli", owner_id="owner", idea="Build a safe product")
            runner = UsageRunner(product_contract(config, intake_result.product_id))
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda selection: selection.model == "gpt-5.6-luna",
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "completed")
            self.assertEqual(runner.calls[0][0:2], ("gpt-5.6-luna", "openai_codex_subscription"))
            self.assertTrue(runner.calls[0][2].is_relative_to(config.state_dir / "worktrees"))
            product = state.get_product(intake_result.product_id)
            self.assertIsNotNone(product)
            assert product is not None
            self.assertEqual(product["status"], "RISK_CLASSIFIED")
            task_files = list(config.evidence_dir.glob("task-T-*.json"))
            self.assertEqual(len(task_files), 2)
            tasks = state.list_tasks(intake_result.product_id)
            director_tasks = [task for task in tasks if task["role"] == "product-director"]
            analyst_tasks = [task for task in tasks if task["role"] == "product-analyst"]
            self.assertEqual(len(director_tasks), 1)
            self.assertEqual(len(analyst_tasks), 1)
            task_id = str(director_tasks[0]["task_id"])
            task = state.get_task(task_id)
            self.assertIsNotNone(task)
            assert task is not None
            self.assertEqual(task["status"], "DONE")
            self.assertEqual(analyst_tasks[0]["status"], "PENDING")
            attempts = state.attempts_for_task(task_id)
            self.assertEqual(len(attempts), 1)
            self.assertEqual(attempts[0]["status"], "completed")
            attempt_artifact = json.loads(Path(result.artifact_ref or "").read_text(encoding="utf-8"))
            self.assertEqual(artifacts.validate("attempt-result.schema.json", attempt_artifact), [])
            self.assertTrue(any(ref.startswith("evidence/usage-") for ref in attempt_artifact["evidence_refs"]))
            state.close()

    def test_completed_dependency_output_is_in_next_context_pack(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli", owner_id="owner", idea="Build a dependency-aware product"
            )
            runner = SequenceRunner(
                [
                    product_contract(config, intake_result.product_id),
                    requirements_package(config, intake_result.product_id),
                ]
            )
            health_checks: list[str] = []

            def health_probe(selection: Any) -> bool:
                health_checks.append(selection.provider)
                return True

            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=health_probe,
                repository_root=ROOT,
            )

            first = worker.run_once()
            analyst_task = state.list_tasks(intake_result.product_id)[1]
            current_spec = worker.default_spec(analyst_task)
            stale_spec = replace(
                current_spec,
                evidence=tuple(
                    item for item in current_spec.evidence if item.get("type") != "dependency-result"
                ),
            )
            worker._context_and_prompt(stale_spec)
            second = worker.run_once()

            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            assert second is not None
            self.assertEqual(second.status, "completed")
            self.assertEqual(len(runner.prompts), 2)
            self.assertIn("UNTRUSTED_DATA accepted output for dependency", runner.prompts[1])
            self.assertIn("product-contract-worker-test", runner.prompts[1])
            self.assertIn("Do not run repository commands such as pytest or make", runner.prompts[1])
            completed_task = state.get_task(str(analyst_task["task_id"]))
            self.assertIsNotNone(completed_task)
            assert completed_task is not None
            self.assertEqual(completed_task["status"], "DONE")
            context_paths = list(config.evidence_dir.glob(f"context-{analyst_task['task_id']}*.json"))
            self.assertEqual(len(context_paths), 2)
            self.assertEqual(len(health_checks), 1)
            state.close()

    def test_independent_reviewer_gets_upstream_and_dependency_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(
                root / "registry.yaml",
                selected="gpt-5.6-terra",
            )
            config = make_config(root / "state", registry_path)
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
            )
            product_id = "P-INDEPENDENT-CONTEXT"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="test",
                idea="Review one immutable candidate",
                idempotency_key="independent-context-test",
            )
            task_path = PipelineCoordinator(
                config,
                state,
                ArtifactStore(config),
            ).create_task(product_id, "independent-reviewer")
            task_id = json.loads(task_path.read_text(encoding="utf-8"))["task_id"]
            task = state.get_task(task_id)
            assert task is not None
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner("{}"),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )
            upstream = {
                "type": "accepted-review-evidence",
                "summary": "complete upstream contracts and gates",
                "artifact_ref": "evidence/upstream.json",
            }
            dependency = {
                "type": "dependency-result",
                "summary": "accepted security review",
                "artifact_ref": "evidence/security.json",
            }

            with (
                patch.object(
                    worker,
                    "_completed_review_evidence",
                    return_value=[upstream],
                ) as completed,
                patch.object(
                    worker,
                    "_dependency_evidence",
                    return_value=[dependency],
                ) as dependencies,
            ):
                spec = worker.default_spec(task)

            completed.assert_called_once_with(
                task,
                include_security_dependency=True,
            )
            dependencies.assert_called_once_with(task)
            self.assertIn(upstream, spec.evidence)
            self.assertIn(dependency, spec.evidence)
            state.close()

    def test_deferred_builder_output_is_accepted_by_test_engineer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(
                root / "registry.yaml",
                selected="gpt-5.6-luna",
            )
            config = make_config(root, registry_path)
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
                max_active_products=2,
            )
            artifacts = ArtifactStore(config)
            product_id = "deferred-builder-worker-product"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="cli",
                idea="https://github.com/brullik/example-product",
                idempotency_key="deferred-builder-worker-key",
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
            pipeline = PipelineCoordinator(config, state, artifacts)
            builder_path = pipeline.create_task(
                product_id,
                "builder-core",
                cycle=3,
            )
            builder_id = str(
                json.loads(builder_path.read_text(encoding="utf-8"))["task_id"]
            )
            attempt_id = "attempt-deferred-builder"
            changed_files = [
                {
                    "path": "src/product.py",
                    "change": "Completed the locally accepted implementation.",
                }
            ]
            output = {
                **artifact_metadata(
                    config,
                    "builder",
                    "builder-deferred-output",
                    product_id,
                ),
                "producer": {
                    "role": "builder",
                    "tier": "sol",
                    "provider": "openai_codex_subscription",
                    "model": "gpt-5.6-sol",
                },
                "task_id": builder_id,
                "attempt_id": attempt_id,
                "tier": "sol",
                "attempt_kind": "repair",
                "prompt_digest": "a" * 64,
                "subject_sha_before": "b" * 64,
                "status": "blocked_external",
                "summary": "Implementation and local PM acceptance are complete.",
                "changed_files": changed_files,
                "commands": [
                    {
                        "command_id": "local-acceptance",
                        "result": "pass",
                        "artifact_ref": "evidence/local-acceptance.json",
                    }
                ],
                "test_results": [
                    {
                        "gate_id": "target-tests",
                        "status": "PASS",
                        "evidence_ref": "pytest: pass",
                    },
                    {
                        "gate_id": "local-pm-acceptance",
                        "status": "PASS",
                        "evidence_ref": "pm: pass",
                    },
                    {
                        "gate_id": "AC-PM-SCOPE-GITHUB",
                        "status": "NOT_RUN",
                        "evidence_ref": None,
                    },
                ],
                "assumptions": [],
                "findings": [
                    {
                        "code": "GITHUB_REQUIRED_CHECK_NOT_RUN",
                        "severity": "medium",
                        "text": "The immutable candidate check belongs to staging.",
                    }
                ],
                "evidence_refs": [],
            }
            output_path = artifacts.write(
                "attempt-result.schema.json",
                output,
                filename="builder-deferred-output.json",
            )
            attempt_artifact = {
                **artifact_metadata(
                    config,
                    "builder",
                    "builder-deferred-attempt",
                    product_id,
                ),
                "producer": {
                    "role": "builder",
                    "tier": "sol",
                    "provider": "openai_codex_subscription",
                    "model": "gpt-5.6-sol",
                },
                "task_id": builder_id,
                "attempt_id": attempt_id,
                "tier": "sol",
                "attempt_kind": "repair",
                "prompt_digest": "a" * 64,
                "subject_sha_before": "b" * 64,
                "status": "blocked_external",
                "summary": "Provider reported a downstream-only blocker.",
                "changed_files": changed_files,
                "commands": [
                    {
                        "command_id": "hermes-oneshot",
                        "result": "pass",
                        "artifact_ref": "evidence/context.json",
                    }
                ],
                "test_results": [
                    {
                        "gate_id": "schema-validation",
                        "status": "PASS",
                        "evidence_ref": str(output_path),
                    },
                    {
                        "gate_id": "target-tests",
                        "status": "PASS",
                        "evidence_ref": "evidence/tests.json",
                    },
                    {
                        "gate_id": "target-lint",
                        "status": "FAIL",
                        "evidence_ref": "evidence/lint.json",
                    },
                ],
                "assumptions": [],
                "findings": [
                    {
                        "code": "model_requested_repair",
                        "severity": "medium",
                        "text": "Provider requested repair.",
                    }
                ],
                "evidence_refs": [str(output_path)],
            }
            attempt_path = artifacts.write(
                "attempt-result.schema.json",
                attempt_artifact,
                filename=f"attempt-{attempt_id}.json",
            )
            claimed = state.claim_task(worker_id="builder-worker")
            self.assertIsNotNone(claimed)
            self.assertTrue(
                state.record_attempt(
                    attempt_id=attempt_id,
                    task_id=builder_id,
                    tier="sol",
                    attempt_kind="repair",
                    prompt_digest="a" * 64,
                    status="repair_required",
                    semantic_counted=True,
                    reason_code="model_requested_repair",
                )
            )
            state.complete_task(
                builder_id,
                "builder-worker",
                "BLOCKED_EXTERNAL",
                reason_code="model_requested_repair",
                detail="GitHub required check was not run.",
                result_ref=str(attempt_path),
                failure_kind="semantic",
            )
            state.transition_product(product_id, "FAILED_SAFE")
            self.assertTrue(
                state.recover_deferred_builder_gate(
                    product_id=product_id,
                    task_id=builder_id,
                    resume_status="REPAIRING",
                )
            )
            test_path = pipeline.create_task(
                product_id,
                "test-engineer",
                dependencies=(builder_id,),
                cycle=3,
            )
            test_id = str(
                json.loads(test_path.read_text(encoding="utf-8"))["task_id"]
            )
            test_task = state.get_task(test_id)
            self.assertIsNotNone(test_task)
            assert test_task is not None
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner("{}"),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            result_path, result_payload, controller_payload = (
                worker._accepted_task_artifacts(builder_id)
            )
            spec = worker.default_spec(test_task)

            self.assertEqual(result_path, output_path)
            self.assertEqual(result_payload["status"], "blocked_external")
            self.assertEqual(controller_payload["status"], "blocked_external")
            dependency = next(
                item
                for item in spec.evidence
                if item["type"] == "dependency-result"
            )
            self.assertIn(
                "Implementation and local PM acceptance are complete.",
                dependency["summary"],
            )
            self.assertEqual(
                dependency["artifact_ref"],
                f"evidence/{output_path.name}",
            )

            adopted_product_id = "controller-adopted-builder-product"
            state.create_product(
                product_id=adopted_product_id,
                owner_id="owner",
                source="cli",
                idea="https://github.com/brullik/grid-bot",
                idempotency_key="controller-adopted-builder-key",
            )
            for status in (
                "CONTRACT_DRAFTED",
                "CONTRACT_VALIDATED",
                "RISK_CLASSIFIED",
                "ARCHITECTED",
                "BACKLOG_READY",
                "IMPLEMENTING",
            ):
                state.transition_product(adopted_product_id, status)
            adopted_builder_path = pipeline.create_task(
                adopted_product_id,
                "builder-core",
                cycle=2,
            )
            adopted_builder_id = str(
                json.loads(
                    adopted_builder_path.read_text(encoding="utf-8")
                )["task_id"]
            )
            adopted_attempt_id = "attempt-controller-adopted-builder"
            adopted_changed_files = [
                {
                    "path": "src/grid_bot/core.py",
                    "change": "Implemented the offline grid simulation.",
                }
            ]
            adopted_output = {
                **artifact_metadata(
                    config,
                    "builder",
                    "builder-controller-adopted-output",
                    adopted_product_id,
                ),
                "producer": output["producer"],
                "task_id": adopted_builder_id,
                "attempt_id": adopted_attempt_id,
                "tier": "sol",
                "attempt_kind": "repair",
                "prompt_digest": "c" * 64,
                "subject_sha_before": "d" * 64,
                "status": "needs_replan",
                "summary": "Implementation passes; detector scope requires controller handling.",
                "changed_files": adopted_changed_files,
                "commands": [
                    {
                        "command_id": "repository-acceptance",
                        "result": "pass",
                        "artifact_ref": "evidence/repository-acceptance.json",
                    }
                ],
                "test_results": [
                    {"gate_id": "target-environment", "status": "PASS"},
                    {"gate_id": "target-tests", "status": "PASS"},
                    {"gate_id": "target-compile", "status": "PASS"},
                    {"gate_id": "target-lint", "status": "PASS"},
                    {"gate_id": "target-secret-scan", "status": "PASS"},
                    {
                        "gate_id": "canonical-command-detector",
                        "status": "NOT_RUN",
                        "evidence_ref": None,
                    },
                ],
                "assumptions": [],
                "findings": [
                    {
                        "code": "CANONICAL_DETECTOR_SCOPE_CONFLICT",
                        "severity": "medium",
                        "text": "A root manifest is outside the exact Builder write scope.",
                    },
                    {
                        "code": "UNTRACKED_BYTECODE_PRESENT",
                        "severity": "low",
                        "text": "Runtime bytecode is excluded from release candidates.",
                    },
                ],
                "evidence_refs": [],
            }
            adopted_output_path = artifacts.write(
                "attempt-result.schema.json",
                adopted_output,
                filename="builder-controller-adopted-output.json",
            )
            adopted_attempt_artifact = {
                **artifact_metadata(
                    config,
                    "builder",
                    "builder-controller-adopted-attempt",
                    adopted_product_id,
                ),
                "producer": output["producer"],
                "task_id": adopted_builder_id,
                "attempt_id": adopted_attempt_id,
                "tier": "sol",
                "attempt_kind": "repair",
                "prompt_digest": "c" * 64,
                "subject_sha_before": "d" * 64,
                "status": "blocked_external",
                "summary": "Controller gates prove the implementation is complete.",
                "changed_files": adopted_changed_files,
                "commands": [
                    {
                        "command_id": "hermes-oneshot",
                        "result": "pass",
                        "artifact_ref": "evidence/context.json",
                    }
                ],
                "test_results": [
                    {
                        "gate_id": "schema-validation",
                        "status": "PASS",
                        "evidence_ref": str(adopted_output_path),
                    },
                    {"gate_id": "target-environment", "status": "PASS"},
                    {"gate_id": "target-tests", "status": "PASS"},
                    {"gate_id": "target-compile", "status": "PASS"},
                    {"gate_id": "target-lint", "status": "PASS"},
                    {"gate_id": "target-secret-scan", "status": "PASS"},
                ],
                "assumptions": [],
                "findings": [
                    {
                        "code": "model_requested_repair",
                        "severity": "medium",
                        "text": "Provider requested controller replanning.",
                    }
                ],
                "evidence_refs": [str(adopted_output_path)],
            }
            adopted_attempt_path = artifacts.write(
                "attempt-result.schema.json",
                adopted_attempt_artifact,
                filename=f"attempt-{adopted_attempt_id}.json",
            )
            claimed_adopted = state.claim_task(worker_id="adopted-builder-worker")
            self.assertIsNotNone(claimed_adopted)
            assert claimed_adopted is not None
            self.assertEqual(claimed_adopted["task_id"], adopted_builder_id)
            self.assertTrue(
                state.record_attempt(
                    attempt_id=adopted_attempt_id,
                    task_id=adopted_builder_id,
                    tier="sol",
                    attempt_kind="repair",
                    prompt_digest="c" * 64,
                    status="repair_required",
                    semantic_counted=True,
                    reason_code="model_requested_repair",
                )
            )
            state.complete_task(
                adopted_builder_id,
                "adopted-builder-worker",
                "FAILED_SAFE",
                reason_code="model_requested_repair",
                detail="Canonical detector conflicts with exact Builder scope.",
                result_ref=str(adopted_attempt_path),
                failure_kind="semantic",
            )
            superseded_path = pipeline.create_task(
                adopted_product_id,
                "builder-core",
                cycle=3,
            )
            superseded_id = str(
                json.loads(superseded_path.read_text(encoding="utf-8"))["task_id"]
            )
            claimed_superseded = state.claim_task(worker_id="superseded-builder-worker")
            self.assertIsNotNone(claimed_superseded)
            assert claimed_superseded is not None
            self.assertEqual(claimed_superseded["task_id"], superseded_id)
            state.complete_task(
                superseded_id,
                "superseded-builder-worker",
                "FAILED_SAFE",
                reason_code="secret_exposure",
                detail="Later provider response was rejected.",
                failure_kind="semantic",
            )
            state.transition_product(adopted_product_id, "FAILED_SAFE")
            self.assertTrue(
                state.adopt_controller_valid_builder(
                    product_id=adopted_product_id,
                    task_id=adopted_builder_id,
                )
            )

            adopted_result_path, adopted_payload, adopted_controller = (
                worker._accepted_task_artifacts(adopted_builder_id)
            )

            self.assertEqual(adopted_result_path, adopted_output_path)
            self.assertEqual(adopted_payload["status"], "needs_replan")
            self.assertEqual(adopted_controller["status"], "blocked_external")
            state.close()

    def test_public_github_repository_url_accepts_only_exact_repository_urls(self) -> None:
        self.assertEqual(
            public_github_repository_url("https://github.com/brullik/bybit-grid-research"),
            "https://github.com/brullik/bybit-grid-research.git",
        )
        self.assertEqual(
            public_github_repository_url("https://github.com/brullik/bybit-grid-research.git/"),
            "https://github.com/brullik/bybit-grid-research.git",
        )
        self.assertIsNone(
            public_github_repository_url(
                "https://github.com/brullik/bybit-grid-research?token=not-allowed"
            )
        )
        self.assertIsNone(public_github_repository_url("https://example.com/brullik/repository"))

    def test_unselected_route_blocks_before_provider_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected=None)
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            intake_result = IntakeService(config, state, ArtifactStore(config)).submit(
                source="cli", owner_id="owner", idea="Build a blocked product"
            )
            runner = FakeRunner("{}")
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: False,
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(runner.calls, [])
            task_file = next(config.evidence_dir.glob("task-T-*.json"))
            task = state.get_task(json.loads(task_file.read_text(encoding="utf-8"))["task_id"])
            self.assertIsNotNone(task)
            assert task is not None
            self.assertEqual(task["status"], "FAILED_SAFE")
            self.assertEqual(task["graph_status"], "FAILED_SEMANTIC")
            self.assertEqual(state.attempts_for_task(str(task["task_id"])), [])
            self.assertEqual(result.reason_code, "model_route_unapproved")
            self.assertIn("not approved", result.detail or "")
            self.assertEqual(intake_result.product_id, task["product_id"])
            self.assertEqual(
                state.list_failures(intake_result.product_id)[0]["failure_class"],
                "controller",
            )
            self.assertEqual(
                list(config.evidence_dir.glob("owner-action-*.json")),
                [],
            )
            state.close()

    def test_workspace_scope_violation_is_failed_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            intake_result = IntakeService(config, state, ArtifactStore(config)).submit(
                source="cli", owner_id="owner", idea="Build a scoped product"
            )
            runner = ScopeViolatingRunner(product_contract(config, intake_result.product_id))
            worker = AgentWorker(config, state, runner=runner, health_probe=lambda _: True, repository_root=ROOT)

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(result.reason_code, "scope_violation")
            product = state.get_product(intake_result.product_id)
            self.assertIsNotNone(product)
            assert product is not None
            self.assertEqual(product["status"], "IDEA_RECEIVED")
            task = next(iter(state.list_tasks(intake_result.product_id)))
            self.assertEqual(task["status"], "FAILED_SAFE")
            state.close()

    def test_malformed_provider_output_is_requeued_and_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            intake_result = IntakeService(config, state, ArtifactStore(config)).submit(
                source="cli", owner_id="owner", idea="Build a malformed output product"
            )
            runner = FakeRunner("not-json")
            worker = AgentWorker(config, state, runner=runner, health_probe=lambda _: True, repository_root=ROOT)

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "repair_scheduled")
            self.assertEqual(result.reason_code, "malformed_transport")
            task_file = next(config.evidence_dir.glob("task-T-*.json"))
            task_id = str(json.loads(task_file.read_text(encoding="utf-8"))["task_id"])
            self.assertEqual(len(state.attempts_for_task(task_id)), 1)
            task = state.list_tasks(intake_result.product_id)[0]
            self.assertEqual(task["status"], "WAITING")
            self.assertEqual(task["graph_status"], "WAITING_TIME")
            self.assertTrue(task["available_at"])
            product = state.get_product(intake_result.product_id)
            self.assertIsNotNone(product)
            assert product is not None
            self.assertEqual(product["status"], "IDEA_RECEIVED")
            state.close()

    def test_subprocess_runner_rejects_secret_like_prompt_before_exec(self) -> None:
        runner = SubprocessHermesRunner(binary="does-not-exist")
        with self.assertRaises(ValueError):
            runner.run(
                selection=ModelSelection("openai-codex", "economy", "gpt-5.6-luna", "luna"),
                prompt="token " + "ghp_" + "abcdefghijklmnopqrstuvwxyz123456",
                cwd=Path.cwd(),
            )

    def test_subprocess_runner_pins_tools_and_ignores_repository_rules(self) -> None:
        selection = ModelSelection("openai-codex", "economy", "gpt-5.6-luna", "luna")
        coding = SubprocessHermesRunner()
        planning = SubprocessHermesRunner(toolsets=("vision",))

        coding_argv = coding.build_argv(selection, "prompt", None)
        planning_argv = planning.build_argv(selection, "prompt", None)

        self.assertEqual(coding_argv[coding_argv.index("--toolsets") + 1], "file,terminal")
        self.assertEqual(planning_argv[planning_argv.index("--toolsets") + 1], "vision")
        self.assertIn("--ignore-rules", coding_argv)
        self.assertIn("--ignore-rules", planning_argv)

    def test_security_context_is_bound_to_candidate_diff_and_preflight_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
            source = repository / "source.py"
            source.write_text("value = 1\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "source.py"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "-c",
                    "user.name=Hermes Test",
                    "-c",
                    "user.email=hermes@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "baseline",
                ],
                check=True,
            )
            source.write_text("value = 2\n", encoding="utf-8")
            (repository / ".lease.json").write_text("{}\n", encoding="utf-8")
            generated = repository / "artifacts" / "security-review.json"
            generated.parent.mkdir()
            generated.write_text('{"status":"repair_required"}\n', encoding="utf-8")
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root / "state", registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner("{}"),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )
            subject_sha = sha256_text(stable_json(_workspace_snapshot(repository)))
            spec = TaskExecutionSpec(
                task_contract={
                    "product_id": "P-SECURITY-CONTEXT",
                    "task_id": "T-SECURITY-CONTEXT",
                    "quality_gates": ["target-secret-scan"],
                },
                role="security-reviewer",
                output_schema="security-review-result.schema.json",
                subject_sha=subject_sha,
            )
            preflight = worker.quality.run(
                cwd=repository,
                subject_sha=subject_sha,
                task_id="T-SECURITY-CONTEXT",
                attempt_id="preflight-test",
                gate_ids=["target-secret-scan"],
            )

            evidence, candidates, decisions = worker._security_review_context(
                spec,
                repository,
                preflight,
            )

            self.assertTrue(preflight.mandatory_passed)
            self.assertIn(f"subject_sha={subject_sha}", evidence["summary"])
            self.assertIn("source.py status=present", evidence["summary"])
            self.assertIn("+value = 2", evidence["summary"])
            self.assertIn('"status":"PASS"', evidence["summary"])
            self.assertIn("gate statuses above are authoritative", evidence["summary"])
            self.assertIn(
                ("source.py", "immutable review candidate changed from base"),
                candidates,
            )
            self.assertNotIn(".lease.json", evidence["summary"])
            self.assertNotIn("artifacts/security-review.json", evidence["summary"])
            self.assertTrue(any("Context Pack subject_sha" in item for item in decisions))

            independent_spec = replace(
                spec,
                role="independent-reviewer",
                output_schema="review-result.schema.json",
            )
            independent_evidence, independent_candidates, independent_decisions = (
                worker._independent_review_context(independent_spec, repository)
            )

            self.assertIn(
                f"subject_sha={subject_sha}",
                independent_evidence["summary"],
            )
            self.assertIn("+value = 2", independent_evidence["summary"])
            self.assertIn(
                ("source.py", "immutable review candidate changed from base"),
                independent_candidates,
            )
            self.assertTrue(
                any(
                    "exact read-only workspace" in item
                    for item in independent_decisions
                )
            )
            state.close()

    def test_review_gate_evidence_preserves_optional_failure_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root / "state", registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            gate_path = artifacts.write(
                "gate-evidence.schema.json",
                {
                    "schema_version": "1.0",
                    "gate_id": "target-lint",
                    "status": "FAIL",
                    "subject_sha": "a" * 64,
                    "command_digest": "b" * 64,
                    "started_at": "2026-01-01T00:00:00Z",
                    "finished_at": "2026-01-01T00:00:01Z",
                    "exit_code": 1,
                    "artifact_digest": "c" * 64,
                    "summary": "Baseline lint finding outside the candidate slice.",
                    "mandatory": False,
                },
                filename="gate-review-test-target-lint.json",
            )
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner("{}"),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            results = worker._review_gate_results(
                {
                    "test_results": [
                        {
                            "gate_id": "target-lint",
                            "status": "FAIL",
                            "evidence_ref": str(gate_path),
                        }
                    ]
                }
            )

            self.assertEqual(
                results,
                [
                    {
                        "gate_id": "target-lint",
                        "status": "FAIL",
                        "mandatory": False,
                        "subject_sha": "a" * 64,
                        "command_digest": "b" * 64,
                        "started_at": "2026-01-01T00:00:00Z",
                        "finished_at": "2026-01-01T00:00:01Z",
                        "exit_code": 1,
                        "artifact_digest": "c" * 64,
                        "evidence_ref": "evidence/gate-review-test-target-lint.json",
                        "summary": "Baseline lint finding outside the candidate slice.",
                    }
                ],
            )
            state.close()

    def test_security_finding_hands_off_without_same_role_model_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            (repository / "README.md").write_text("minimal workspace\n", encoding="utf-8")
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root / "state", registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            product_id = "P-SECURITY-HANDOFF"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="test",
                idea="Review a candidate and hand findings to the builder",
                idempotency_key="security-handoff-test",
            )
            task_path = PipelineCoordinator(config, state, ArtifactStore(config)).create_task(
                product_id,
                "security-reviewer",
            )
            contract = json.loads(task_path.read_text(encoding="utf-8"))
            output = {
                **artifact_metadata(
                    config,
                    "security-reviewer",
                    "security-review-handoff-test",
                    product_id,
                ),
                "producer": {
                    "role": "security-reviewer",
                    "tier": "terra",
                    "provider": "openai_codex_subscription",
                    "model": "gpt-5.6-terra",
                },
                "task_id": contract["task_id"],
                "subject_sha": "b" * 64,
                "status": "repair_required",
                "changed_trust_boundaries": ["untrusted input boundary"],
                "findings": [
                    {
                        "id": "SEC-001",
                        "severity": "medium",
                        "category": "input-validation",
                        "description": "An input boundary needs a deterministic bound.",
                        "evidence": "source.py:1",
                        "required_fix": "Add the bound and a negative test.",
                    }
                ],
                "release_blocked": True,
                "assumptions": ["The candidate remains immutable during review."],
                "evidence_refs": ["evidence/security-preflight.json"],
            }
            runner = FakeRunner(json.dumps(output))
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=repository,
            )
            worker.quality = PassingQuality()  # type: ignore[assignment]
            spec = TaskExecutionSpec(
                task_contract=contract,
                role="security-reviewer",
                output_schema="security-review-result.schema.json",
                subject_sha="a" * 64,
            )

            result = worker.execute(spec)

            self.assertEqual(result.status, "repair_required")
            self.assertEqual(result.reason_code, "model_requested_repair")
            self.assertIn("SEC-001 [medium]", result.detail or "")
            self.assertIn("Add the bound and a negative test.", result.detail or "")
            self.assertEqual(len(runner.calls), 1)
            self.assertEqual(list(config.evidence_dir.glob("repair-brief-*.json")), [])
            attempt = json.loads(Path(result.artifact_ref or "").read_text(encoding="utf-8"))
            self.assertIn("builder_repair_handoff", attempt["summary"])
            self.assertIn("SEC-001 [medium]", attempt["summary"])
            state.close()

    def test_security_preflight_failure_skips_provider_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            (repository / "README.md").write_text("minimal workspace\n", encoding="utf-8")
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root / "state", registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            product_id = "P-SECURITY-PREFLIGHT"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="test",
                idea="Review an internal copied workspace",
                idempotency_key="security-preflight-test",
            )
            task_path = PipelineCoordinator(config, state, ArtifactStore(config)).create_task(
                product_id,
                "security-reviewer",
            )
            contract = json.loads(task_path.read_text(encoding="utf-8"))
            runner = FakeRunner("{}")
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=repository,
            )
            spec = TaskExecutionSpec(
                task_contract=contract,
                role="security-reviewer",
                output_schema="security-review-result.schema.json",
                subject_sha="a" * 64,
            )

            result = worker.execute(spec)

            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(result.reason_code, "mandatory_gate_failed")
            self.assertEqual(result.detail, "failed mandatory gates: secret-scan")
            self.assertEqual(runner.calls, [])
            attempt = json.loads(Path(result.artifact_ref or "").read_text(encoding="utf-8"))
            self.assertEqual(attempt["commands"][0]["result"], "not_run")
            self.assertTrue(
                any(item["gate_id"] == "secret-scan" and item["status"] == "FAIL"
                    for item in attempt["test_results"])
            )
            state.close()

    def test_git_workspace_snapshot_ignores_generated_files_but_tracks_source_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
            (repository / ".gitignore").write_text(".pytest_cache/\n", encoding="utf-8")
            source = repository / "source.py"
            source.write_text("value = 1\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(repository), "add", ".gitignore", "source.py"],
                check=True,
            )
            baseline = _workspace_snapshot(repository)

            ignored = repository / ".pytest_cache" / "cache"
            ignored.parent.mkdir()
            ignored.write_text("generated\n", encoding="utf-8")
            self.assertEqual(_workspace_snapshot(repository), baseline)

            source.write_text("value = 2\n", encoding="utf-8")
            changed = _workspace_snapshot(repository)
            self.assertNotEqual(changed["source.py"], baseline["source.py"])
            untracked = repository / "new.py"
            untracked.write_text("new = True\n", encoding="utf-8")
            self.assertIn("new.py", _workspace_snapshot(repository))


if __name__ == "__main__":
    unittest.main()
