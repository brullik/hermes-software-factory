from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from factory.artifacts import ArtifactStore, artifact_metadata
from factory.config import FactoryConfig
from factory.intake import IntakeService
from factory.pipeline import PipelineCoordinator
from factory.policy import policy_digest
from factory.providers import ModelSelection
from factory.state import StateStore
from factory.worker import AgentWorker, HermesRunResult, SubprocessHermesRunner

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
            self.assertEqual(second.status, "completed")
            self.assertEqual(state.list_tasks(intake_result.product_id)[0]["status"], "DONE")
            self.assertEqual(len(state.attempts_for_task(str(task["task_id"]))), 2)
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

    def test_worker_runs_selected_provider_and_persists_contract_and_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            intake = IntakeService(config, state, artifacts)
            intake_result = intake.submit(source="cli", owner_id="owner", idea="Build a safe product")
            runner = FakeRunner(product_contract(config, intake_result.product_id))
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
            state.close()

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

    def test_malformed_provider_output_is_failed_safe_and_recorded(self) -> None:
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
            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(result.reason_code, "malformed_transport")
            task_file = next(config.evidence_dir.glob("task-T-*.json"))
            task_id = str(json.loads(task_file.read_text(encoding="utf-8"))["task_id"])
            self.assertEqual(len(state.attempts_for_task(task_id)), 1)
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


if __name__ == "__main__":
    unittest.main()
