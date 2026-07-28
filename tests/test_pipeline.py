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
            self.assertEqual(artifacts.validate("risk-assessment.schema.json", json.loads((config.evidence_dir / f"risk-{product_id}.json").read_text(encoding="utf-8"))), [])
            state.close()


if __name__ == "__main__":
    unittest.main()
