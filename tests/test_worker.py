from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

import yaml

from factory.artifacts import ArtifactStore
from factory.config import FactoryConfig
from factory.intake import IntakeService
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


class WorkerTests(unittest.TestCase):
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
