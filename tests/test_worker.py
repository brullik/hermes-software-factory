from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

from factory.artifacts import ArtifactStore, artifact_metadata
from factory.common import sha256_text, stable_json
from factory.config import FactoryConfig
from factory.intake import IntakeService
from factory.pipeline import PipelineCoordinator
from factory.policy import policy_digest
from factory.providers import ModelSelection
from factory.quality import QualityGateRun
from factory.state import StateStore
from factory.worker import (
    AgentWorker,
    HermesRunResult,
    SubprocessHermesRunner,
    TaskExecutionSpec,
    _workspace_snapshot,
    public_github_repository_url,
)

ROOT = Path(__file__).resolve().parents[1]


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
            self.assertEqual(first.status, "repair_scheduled")
            task = next(iter(state.list_tasks(intake_result.product_id)))
            self.assertEqual(task["status"], "PENDING")
            self.assertEqual(task["next_tier"], "luna")
            self.assertEqual(task["next_attempt_kind"], "repair")
            brief_paths = list(config.evidence_dir.glob("repair-brief-*.json"))
            self.assertEqual(len(brief_paths), 1)
            brief = json.loads(brief_paths[0].read_text(encoding="utf-8"))
            self.assertEqual(brief["failure_class"], "model_requested_repair")

            second = worker.run_once()

            self.assertIsNotNone(second)
            assert second is not None
            self.assertEqual(second.status, "completed", second.reason_code)
            self.assertEqual(state.list_tasks(intake_result.product_id)[0]["status"], "DONE")
            self.assertEqual(len(state.attempts_for_task(str(task["task_id"]))), 2)
            self.assertIn("repair-brief-", runner.prompts[1])
            self.assertIn("UNTRUSTED_DATA targeted repair brief", runner.prompts[1])
            self.assertIn("model_requested_repair", runner.prompts[1])
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
            self.assertEqual(task["status"], "PENDING")
            attempts = state.attempts_for_task(str(task["task_id"]))
            self.assertEqual(len(attempts), 1)
            self.assertEqual(attempts[0]["attempt_kind"], "initial")

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
            self.assertEqual(result.status, "blocked_external")
            self.assertEqual(result.reason_code, "release side-effect adapter is not configured")
            self.assertEqual(runner.calls, [])
            task = next(iter(state.list_tasks(product_id)))
            self.assertEqual(task["status"], "BLOCKED_EXTERNAL")
            self.assertEqual(state.attempts_for_task(str(task["task_id"])), [])
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
            self.assertEqual(result.status, "blocked_external")
            self.assertEqual(runner.calls, [])
            task_file = next(config.evidence_dir.glob("task-T-*.json"))
            task = state.get_task(json.loads(task_file.read_text(encoding="utf-8"))["task_id"])
            self.assertIsNotNone(task)
            assert task is not None
            self.assertEqual(task["status"], "BLOCKED_EXTERNAL")
            self.assertEqual(state.attempts_for_task(str(task["task_id"])), [])
            self.assertIn("not approved", result.reason_code or "")
            self.assertEqual(intake_result.product_id, task["product_id"])
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
            self.assertEqual(state.list_tasks(intake_result.product_id)[0]["status"], "PENDING")
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
            self.assertIn(("source.py", "security review candidate changed from base"), candidates)
            self.assertNotIn(".lease.json", evidence["summary"])
            self.assertNotIn("artifacts/security-review.json", evidence["summary"])
            self.assertTrue(any("Context Pack subject_sha" in item for item in decisions))
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
            self.assertEqual(len(runner.calls), 1)
            self.assertEqual(list(config.evidence_dir.glob("repair-brief-*.json")), [])
            attempt = json.loads(Path(result.artifact_ref or "").read_text(encoding="utf-8"))
            self.assertIn("builder_repair_handoff", attempt["summary"])
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
