from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from test_worker import make_config, selected_registry

from factory.artifacts import ArtifactStore
from factory.intake import IntakeService
from factory.pipeline import PipelineCoordinator
from factory.state import StateStore


class PipelineTests(unittest.TestCase):
    def test_different_products_have_disjoint_workspace_locks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root,
                selected_registry(
                    root / "registry.yaml",
                    selected="gpt-5.6-luna",
                ),
            )
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
                max_active_products=config.max_active_products,
            )
            pipeline = PipelineCoordinator(config, state)
            product_ids = ("isolated-product-a", "isolated-product-b")
            for product_id in product_ids:
                state.create_product(
                    product_id=product_id,
                    owner_id="owner",
                    source="test",
                    idea=f"https://github.com/brullik/{product_id}",
                    idempotency_key=f"isolation-{product_id}",
                )
                pipeline.create_task(product_id, "builder-core")

            first = state.claim_task(worker_id="worker-a")
            second = state.claim_task(worker_id="worker-b")

            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            assert first is not None and second is not None
            self.assertNotEqual(first["product_id"], second["product_id"])
            first_locks = set(json.loads(first["conflict_keys_json"]))
            second_locks = set(json.loads(second["conflict_keys_json"]))
            self.assertTrue(first_locks)
            self.assertTrue(second_locks)
            self.assertTrue(first_locks.isdisjoint(second_locks))
            state.close()

    def test_external_repository_uses_portable_target_gates_and_shared_workspace_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root,
                selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"),
            )
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            product = IntakeService(config, state, artifacts).submit(
                source="cli",
                owner_id="owner",
                idea="https://github.com/brullik/bybit-grid-research",
            )
            pipeline = PipelineCoordinator(config, state, artifacts)

            builder_path = pipeline.create_task(product.product_id, "builder-core")
            tester_path = pipeline.create_task(product.product_id, "test-engineer")
            security_path = pipeline.create_task(product.product_id, "security-reviewer")

            builder = json.loads(builder_path.read_text(encoding="utf-8"))
            tester = json.loads(tester_path.read_text(encoding="utf-8"))
            security = json.loads(security_path.read_text(encoding="utf-8"))
            self.assertEqual(
                builder["quality_gates"],
                [
                    "target-environment",
                    "target-tests",
                    "target-compile",
                    "target-lint",
                    "target-secret-scan",
                ],
            )
            self.assertEqual(tester["quality_gates"], builder["quality_gates"])
            self.assertEqual(
                security["quality_gates"],
                [
                    "target-sast",
                    "target-dependency-audit",
                    "target-license-check",
                    "target-secret-scan",
                ],
            )
            self.assertIn("pyproject.toml", builder["allowed_paths"])
            self.assertNotIn("pyproject.toml", builder["forbidden_paths"])
            self.assertEqual(builder["conflict_keys"], tester["conflict_keys"])
            self.assertEqual(tester["conflict_keys"], security["conflict_keys"])
            state.close()

    def test_role_dag_reaches_observation_with_durable_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(root, selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"))
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            product = IntakeService(config, state, artifacts).submit(
                source="cli", owner_id="owner", idea="Build a deterministic pipeline"
            )
            product_id = product.product_id
            pipeline = PipelineCoordinator(config, state, artifacts)
            pipeline.seed_initial(product_id)

            worker_number = 0

            def accept(role: str, output: dict[str, object] | None = None) -> None:
                nonlocal worker_number
                worker_number += 1
                pending = [
                    task
                    for task in state.list_tasks(product_id)
                    if task["role"] == role and task["status"] == "PENDING"
                ]
                self.assertEqual(len(pending), 1, role)
                claimed = state.claim_task(worker_id=f"pipeline-test-{worker_number}")
                self.assertIsNotNone(claimed)
                assert claimed is not None
                self.assertEqual(claimed["task_id"], pending[0]["task_id"])
                pipeline.advance_after(claimed, output or {"status": "completed"}, Path("unused.json"))
                state.complete_task(claimed["task_id"], f"pipeline-test-{worker_number}")

            accept(
                "product-director",
                {
                    "status": "completed",
                    "risk_markers": [],
                    "data_classification": "internal",
                    "repository_visibility": "public",
                },
            )
            accept("product-analyst")
            accept("solution-architect")
            accept("task-specifier")
            accept("builder")
            accept("test-engineer")
            accept("security-reviewer")
            accept("independent-reviewer")
            accept("release-operator")
            accept("product-tester", {"status": "completed", "release_blocked": False})
            accept("release-operator")

            final_product = state.get_product(product_id)
            self.assertIsNotNone(final_product)
            assert final_product is not None
            self.assertEqual(final_product["status"], "OBSERVATION")
            tasks = state.list_tasks(product_id)
            self.assertEqual(len(tasks), 11)
            self.assertTrue(all(task["status"] == "DONE" for task in tasks))
            self.assertEqual(
                [task["role"] for task in tasks],
                [
                    "product-director",
                    "product-analyst",
                    "solution-architect",
                    "task-specifier",
                    "builder",
                    "test-engineer",
                    "security-reviewer",
                    "independent-reviewer",
                    "release-operator",
                    "product-tester",
                    "release-operator",
                ],
            )
            for task in tasks:
                self.assertTrue(task["output_schema"])
                self.assertTrue(task["contract_ref"].startswith("evidence/task-T-"))
                for dependency in json.loads(task["dependencies_json"]):
                    self.assertIn(dependency, {item["task_id"] for item in tasks})
            by_role = {str(task["role"]): task for task in tasks if task["role"] != "release-operator"}
            self.assertEqual(
                json.loads(by_role["test-engineer"]["dependencies_json"]),
                [by_role["builder"]["task_id"]],
            )
            self.assertEqual(
                json.loads(by_role["security-reviewer"]["dependencies_json"]),
                [by_role["test-engineer"]["task_id"]],
            )
            self.assertEqual(
                json.loads(by_role["independent-reviewer"]["dependencies_json"]),
                [by_role["security-reviewer"]["task_id"]],
            )
            self.assertEqual(artifacts.validate("risk-assessment.schema.json", json.loads((config.evidence_dir / f"risk-{product_id}.json").read_text(encoding="utf-8"))), [])
            state.close()


if __name__ == "__main__":
    unittest.main()
