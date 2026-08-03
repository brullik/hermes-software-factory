from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from test_worker import make_config, selected_registry

from factory.artifacts import ArtifactStore
from factory.autonomy import (
    CANONICAL_ROLE_OUTPUT_SCHEMAS,
    CAPABILITY_PROFILES,
)
from factory.common import sha256_text
from factory.intake import IntakeService
from factory.pipeline import (
    PipelineCoordinator,
    _replan_blocked_scope_paths,
    _replan_mandatory_gate_ids,
    _replan_required_scope_paths,
)
from factory.policy import policy_digest
from factory.state import StateStore


class PipelineTests(unittest.TestCase):
    def test_replan_gate_inventory_uses_only_bounded_causal_gate_failures(
        self,
    ) -> None:
        failures = [
            {
                "failure_id": "failure-root",
                "parent_failure_id": None,
                "reason_code": "mandatory_gate_failed",
                "failed_gate_ids_json": ('["target-dependency-audit", "target-license-check"]'),
            },
            {
                "failure_id": "failure-repair",
                "parent_failure_id": "failure-root",
                "reason_code": "model_requested_repair",
                "failed_gate_ids_json": '["MODEL_REPAIR_REQUIRED"]',
            },
            {
                "failure_id": "failure-replan",
                "parent_failure_id": "failure-repair",
                "reason_code": "plan_contract_violation",
                "failed_gate_ids_json": (
                    '["PLAN_CONTRACT_VIOLATION", '
                    '"RELEASE-EVIDENCE-SUBJECT-MISMATCH", '
                    '"RELEASE-PREREQUISITES-MISSING"]'
                ),
            },
            {
                "failure_id": "failure-unrelated",
                "parent_failure_id": None,
                "reason_code": "mandatory_gate_failed",
                "failed_gate_ids_json": '["target-tests"]',
            },
        ]

        self.assertEqual(
            _replan_mandatory_gate_ids(
                failures,
                source_failure_id="failure-replan",
            ),
            (
                "RELEASE-EVIDENCE-SUBJECT-MISMATCH",
                "RELEASE-PREREQUISITES-MISSING",
                "target-dependency-audit",
                "target-license-check",
            ),
        )

    def test_replan_scope_inventory_uses_only_causal_scope_failure(self) -> None:
        failures = [
            {
                "failure_id": "failure-root",
                "parent_failure_id": None,
                "actual_json": json.dumps(
                    {
                        "scope_reassessment_required": True,
                        "blocked_allowed_paths": ["tests/**"],
                        "provider_scope_findings": [
                            {
                                "code": "SCOPE_INSUFFICIENT",
                                "text": (
                                    "scripts/image_security_verify.py is outside "
                                    "allowed task scope."
                                ),
                            }
                        ],
                    }
                ),
            },
            {
                "failure_id": "failure-child",
                "parent_failure_id": "failure-root",
                "actual_json": "{}",
            },
            {
                "failure_id": "failure-unrelated",
                "parent_failure_id": None,
                "actual_json": json.dumps(
                    {
                        "scope_reassessment_required": True,
                        "blocked_allowed_paths": ["docs/**"],
                    }
                ),
            },
        ]

        self.assertEqual(
            _replan_blocked_scope_paths(
                failures,
                source_failure_id="failure-child",
            ),
            ("tests/**",),
        )
        self.assertEqual(
            _replan_required_scope_paths(
                failures,
                source_failure_id="failure-child",
            ),
            ("scripts/image_security_verify.py",),
        )

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
                    "target-container-image-scan",
                ],
            )
            self.assertIn("pyproject.toml", builder["allowed_paths"])
            self.assertIn(".gitignore", builder["allowed_paths"])
            self.assertIn("uv.lock", builder["allowed_paths"])
            self.assertIn("requirements*.txt", builder["allowed_paths"])
            self.assertNotIn("pyproject.toml", builder["forbidden_paths"])
            self.assertEqual(builder["conflict_keys"], tester["conflict_keys"])
            self.assertEqual(tester["conflict_keys"], security["conflict_keys"])
            state.close()

    def test_executable_plan_runs_from_durable_dependency_frontier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root, selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            )
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            product_id = "deterministic-pipeline-product"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="test",
                idea="Build a deterministic pipeline",
                idempotency_key="deterministic-pipeline-product",
            )
            pipeline = PipelineCoordinator(config, state, artifacts)
            for status in (
                "CONTRACT_DRAFTED",
                "CONTRACT_VALIDATED",
                "RISK_CLASSIFIED",
                "ARCHITECTED",
            ):
                state.transition_product(product_id, status)
            specifier_path = pipeline.create_task(product_id, "task-specifier")
            specifier_id = str(json.loads(specifier_path.read_text(encoding="utf-8"))["task_id"])
            specifier = state.claim_task(worker_id="task-specifier-worker")
            self.assertIsNotNone(specifier)
            assert specifier is not None

            plan_id = "PLAN-PIPELINE-V2"
            node_specs = (
                ("build", "T-PIPEBUILD1", "builder", "builder_workspace"),
                ("test", "T-PIPETEST01", "test-engineer", "test_workspace"),
                (
                    "security",
                    "T-PIPESEC001",
                    "security-reviewer",
                    "reviewer_readonly",
                ),
                (
                    "release-production",
                    "T-PIPEREL001",
                    "release-operator",
                    "release_production",
                ),
            )
            for capability in CAPABILITY_PROFILES["release_production"]:
                state.grant_capability(
                    product_id=product_id,
                    task_id=None,
                    capability=capability,
                    provider="fake-controller",
                    scope={"repository": "brullik/deterministic-pipeline"},
                    status="AVAILABLE",
                )

            def contract(
                node_id: str,
                task_id: str,
                role: str,
                profile: str,
            ) -> dict[str, object]:
                criterion_id = f"accept-{node_id}"
                return {
                    "schema_version": "2.0",
                    "artifact_id": f"task-contract-{task_id}",
                    "product_id": product_id,
                    "task_id": task_id,
                    "root_task_id": specifier_id,
                    "parent_task_id": specifier_id,
                    "source_task_id": specifier_id,
                    "plan_id": plan_id,
                    "plan_node_id": node_id,
                    "task_revision": 1,
                    "root_context_ref": f"evidence/intake-{product_id}.json",
                    "active_context_ref": f"evidence/task-{task_id}.json",
                    "failure_id": None,
                    "hypothesis_id": None,
                    "supersedes_task_id": None,
                    "title": f"Execute {node_id}",
                    "objective": f"Complete and verify the {node_id} plan node",
                    "role": role,
                    "output_schema": CANONICAL_ROLE_OUTPUT_SCHEMAS[role],
                    "dependencies": [],
                    "conflict_keys": [f"{product_id}:workspace"],
                    "acceptance": [
                        {
                            "criterion_id": criterion_id,
                            "verification": f"Evidence proves {node_id}",
                            "mandatory": True,
                        }
                    ],
                    "required_capabilities": list(CAPABILITY_PROFILES[profile]),
                    "capability_profile": profile,
                    "allowed_paths": ["artifacts/**"],
                    "forbidden_paths": ["secrets/**"],
                    "risk_tier": "medium",
                    "model_floor": "luna",
                    "idempotency_key": sha256_text(f"{plan_id}:{node_id}:{task_id}"),
                    "status": "DRAFT",
                    "priority": 10,
                    "critical_path_rank": 0,
                }

            plan = {
                "schema_version": "2.0",
                "artifact_id": "backlog-plan-pipeline-v2",
                "product_id": product_id,
                "created_at": "2026-07-29T00:00:00Z",
                "producer": {
                    "role": "task-specifier",
                    "tier": "luna",
                    "provider": "fake",
                    "model": "fake",
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
                        "statement": "Deliver a verified release candidate",
                        "mandatory": True,
                        "acceptance_ids": [f"accept-{node_id}" for node_id, *_ in node_specs],
                    }
                ],
                "nodes": [
                    {
                        "node_id": node_id,
                        "mandatory": True,
                        "task_contract": contract(
                            node_id,
                            task_id,
                            role,
                            profile,
                        ),
                    }
                    for node_id, task_id, role, profile in node_specs
                ],
                "edges": [
                    {
                        "from": source,
                        "to": target,
                        "edge_type": "depends_on",
                        "required": True,
                    }
                    for source, target in (
                        ("build", "test"),
                        ("test", "security"),
                        ("security", "release-production"),
                    )
                ],
                "completion_criteria": [
                    "Every mandatory plan node has immutable acceptance evidence"
                ],
                "summary": "A real four-node executable release DAG",
            }
            pipeline.advance_after_legacy_v1(
                specifier,
                plan,
                Path("backlog-plan.json"),
            )
            state.complete_task(specifier_id, "task-specifier-worker")

            claimed_ids: list[str] = []
            for index, (_, expected_id, _, _) in enumerate(node_specs, start=1):
                claimed = state.claim_task(worker_id=f"pipeline-worker-{index}")
                self.assertIsNotNone(claimed)
                assert claimed is not None
                self.assertEqual(claimed["task_id"], expected_id)
                claimed_ids.append(str(claimed["task_id"]))
                state.complete_task(
                    str(claimed["task_id"]),
                    f"pipeline-worker-{index}",
                )

            self.assertEqual(
                claimed_ids,
                [task_id for _, task_id, _, _ in node_specs],
            )
            planned = [task for task in state.list_tasks(product_id) if task["plan_id"] == plan_id]
            self.assertEqual(len(planned), 4)
            self.assertTrue(all(task["graph_status"] == "ACCEPTED" for task in planned))
            edges = state.list_edges(plan_id)
            self.assertEqual(len(edges), 3)
            self.assertEqual(
                {(edge["from_task_id"], edge["to_task_id"]) for edge in edges},
                {
                    ("T-PIPEBUILD1", "T-PIPETEST01"),
                    ("T-PIPETEST01", "T-PIPESEC001"),
                    ("T-PIPESEC001", "T-PIPEREL001"),
                },
            )
            state.close()


if __name__ == "__main__":
    unittest.main()
