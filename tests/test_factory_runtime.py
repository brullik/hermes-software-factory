from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from factory.artifacts import ArtifactStore
from factory.attempts import AttemptManager, IdenticalAttemptError
from factory.backup import BackupAdapter
from factory.config import FactoryConfig, load_config, validate_config
from factory.context_builder import ContextBuilder
from factory.deployment import DeploymentError, DeploymentGuard, TransactionalDeployer
from factory.gateway_commands import GatewayCommandError, parse_command
from factory.github import GitHubAdapter, GitHubCommandError
from factory.intake import IntakeRejected, IntakeService
from factory.owner_actions import OwnerActionService
from factory.prompting import PromptCompiler
from factory.providers import ExternalBlocker, ProviderRegistry
from factory.quota import ProviderCircuitBreaker
from factory.registry import SchemaRegistry
from factory.state import IntakeRateLimitError, StateStore
from factory.tools import ToolPolicyAdapter
from factory.workflow import WorkflowEngine
from factory.workspace import WorkspaceManager
from scripts.model_router import Tier

ROOT = Path(__file__).resolve().parents[1]


def _make_config(state_dir: Path) -> FactoryConfig:
    raw = yaml.safe_load(
        (ROOT / "config" / "factory-config.example.yaml").read_text(encoding="utf-8")
    )
    raw["paths"]["policies"] = str(ROOT / "policies")
    raw["paths"]["schemas"] = str(ROOT / "schemas")
    raw["paths"]["prompts"] = str(ROOT / "prompts")
    raw["paths"]["state"] = str(state_dir)
    raw["paths"]["worktrees"] = str(state_dir / "worktrees")
    raw["paths"]["logs"] = str(state_dir / "logs")
    raw["controller"]["database_url"] = f"sqlite:///{(state_dir / 'controller.db').as_posix()}"
    return FactoryConfig(raw, ROOT / "config" / "factory-config.example.yaml")


class FactoryRuntimeTests(unittest.TestCase):
    def test_intake_redacts_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = _make_config(Path(directory))
            state = StateStore(config.database_path)
            artifacts = ArtifactStore(config)
            intake = IntakeService(config, state, artifacts)
            first = intake.submit(
                source="cli",
                owner_id="owner",
                idea="Сделай бот token=" + "ghp_" + "abcdefghijklmnopqrstuvwxyz123456",
                idempotency_key="same-request",
            )
            second = intake.submit(
                source="cli",
                owner_id="owner",
                idea="другое содержание не должно создать второй продукт",
                idempotency_key="same-request",
            )
            artifact = json.loads(Path(first.artifact_path).read_text(encoding="utf-8"))
            self.assertTrue(first.created)
            self.assertFalse(second.created)
            self.assertEqual(first.product_id, second.product_id)
            self.assertEqual(first.correlation_id, second.correlation_id)
            self.assertNotIn("ghp_", artifact["idea"])
            self.assertNotEqual(artifact["idempotency_key"], "same-request")
            self.assertNotIn("same-request", artifact["idempotency_key"])
            self.assertEqual(artifact["redactions"][0]["type"], "github_token")
            state.close()

    def test_intake_rate_limit_is_durable_and_idempotent_retries_are_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = _make_config(Path(directory))
            config.raw["intake"]["rate_limit_requests"] = 1
            state = StateStore(config.database_path, max_active_products=2)
            intake = IntakeService(config, state, ArtifactStore(config))
            first = intake.submit(
                source="cli", owner_id="owner", idea="first", idempotency_key="one"
            )
            duplicate = intake.submit(
                source="cli", owner_id="owner", idea="different", idempotency_key="one"
            )
            self.assertFalse(duplicate.created)
            self.assertEqual(first.product_id, duplicate.product_id)
            with self.assertRaises(IntakeRateLimitError):
                intake.submit(source="cli", owner_id="owner", idea="second", idempotency_key="two")
            state.close()

    def test_intake_rejects_invalid_attachment_metadata_before_state_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = _make_config(Path(directory))
            state = StateStore(config.database_path)
            intake = IntakeService(config, state, ArtifactStore(config))
            with self.assertRaises(IntakeRejected):
                intake.submit(
                    source="cli",
                    owner_id="owner",
                    idea="safe idea",
                    idempotency_key="attachment-invalid",
                    attachments=[{"name": "../secret", "digest": "a" * 64}],
                )
            self.assertEqual(state.list_products(), [])
            state.close()

    def test_cli_configuration_environment_is_respected(self) -> None:
        from factory import cli

        with tempfile.TemporaryDirectory() as directory:
            custom_path = Path(directory) / "config.yaml"
            custom_path.write_text(
                (ROOT / "config" / "factory-config.example.yaml").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"FACTORY_CONFIG": str(custom_path)}):
                loaded = cli._config(None)
            self.assertEqual(loaded.source, custom_path.resolve())

    def test_default_config_resolves_repository_resources(self) -> None:
        config = load_config(ROOT / "config" / "factory-config.example.yaml")
        self.assertEqual(len(config.policy_paths()), 12)
        self.assertEqual(config.schema_root(), (ROOT / "schemas").resolve())
        self.assertEqual(PromptCompiler(config).root, (ROOT / "prompts").resolve())
        self.assertEqual(config.agent_execution_timeout_seconds, 1800)
        self.assertEqual(config.planning_execution_timeout_seconds, 900)

    def test_agent_execution_timeout_configuration_is_bounded(self) -> None:
        cases = (
            (
                {"agent_execution_timeout_seconds": 899},
                "agent_execution_timeout_seconds must be at least 900",
            ),
            (
                {"agent_execution_timeout_seconds": 3601},
                "agent_execution_timeout_seconds must not exceed 3600",
            ),
            (
                {"planning_execution_timeout_seconds": 59},
                "planning_execution_timeout_seconds must be at least 60",
            ),
            (
                {
                    "agent_execution_timeout_seconds": 900,
                    "planning_execution_timeout_seconds": 901,
                },
                (
                    "planning_execution_timeout_seconds must not exceed "
                    "agent_execution_timeout_seconds"
                ),
            ),
        )
        for overrides, expected in cases:
            with self.subTest(overrides=overrides):
                config = _make_config(Path("state"))
                config.raw["controller"].update(overrides)
                self.assertIn(expected, validate_config(config))

    def test_task_dependencies_and_lease(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(Path(directory) / "controller.db")
            state.create_product(
                product_id="product",
                owner_id="owner",
                source="cli",
                idea="idea",
                idempotency_key="key",
            )
            workflow = WorkflowEngine(state)
            self.assertEqual(
                workflow.transition("product", "CONTRACT_DRAFTED")["status"], "CONTRACT_DRAFTED"
            )
            self.assertEqual(workflow.pause("product")["status"], "PAUSED")
            self.assertEqual(
                workflow.resume("product", "CONTRACT_DRAFTED")["status"], "CONTRACT_DRAFTED"
            )
            state.add_task(task_id="first", product_id="product", title="First")
            state.add_task(
                task_id="second", product_id="product", title="Second", dependencies=["first"]
            )
            claimed = state.claim_task(worker_id="worker")
            self.assertIsNotNone(claimed)
            assert claimed is not None
            self.assertEqual(claimed["task_id"], "first")
            self.assertIsNone(state.claim_task(worker_id="other"))
            state.complete_task("first", "worker")
            blocked_claim = state.claim_task(worker_id="worker")
            self.assertIsNotNone(blocked_claim)
            assert blocked_claim is not None
            self.assertEqual(blocked_claim["task_id"], "second")
            state.complete_task("second", "worker", "BLOCKED_EXTERNAL")
            self.assertEqual(
                workflow.resume("product", "IMPLEMENTING")["status"], "CONTRACT_DRAFTED"
            )
            self.assertEqual(state.get_task("second")["status"], "PENDING")
            next_task = state.claim_task(worker_id="other")
            self.assertIsNotNone(next_task)
            assert next_task is not None
            self.assertEqual(next_task["task_id"], "second")
            self.assertTrue(
                state.enqueue_outbox(
                    outbox_id="outbox-1",
                    idempotency_key="effect-1",
                    event_type="github_pr_create",
                    payload={"subject": "sha"},
                )
            )
            self.assertFalse(
                state.enqueue_outbox(
                    outbox_id="outbox-duplicate",
                    idempotency_key="effect-1",
                    event_type="github_pr_create",
                    payload={"subject": "sha"},
                )
            )
            outbox = state.claim_outbox("worker")
            self.assertEqual(len(outbox), 1)
            state.mark_outbox_done("outbox-1", "worker")
            state.close()

    def test_owner_resume_requeues_task_that_failed_safe_before_provider_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(Path(directory) / "controller.db")
            state.create_product(
                product_id="product",
                owner_id="owner",
                source="cli",
                idea="idea",
                idempotency_key="failed-safe-resume",
            )
            state.transition_product("product", "CONTRACT_DRAFTED")
            state.add_task(task_id="failed", product_id="product", title="Failed before provider")
            claimed = state.claim_task(worker_id="worker")
            self.assertIsNotNone(claimed)
            state.complete_task("failed", "worker", "FAILED_SAFE")

            product = WorkflowEngine(state).resume("product", "IMPLEMENTING")

            self.assertEqual(product["status"], "CONTRACT_DRAFTED")
            resumed = state.get_task("failed")
            self.assertIsNotNone(resumed)
            assert resumed is not None
            self.assertEqual(resumed["status"], "PENDING")
            event = state.events("product")[-1]
            self.assertEqual(event["event_type"], "task_requeued")
            self.assertEqual(json.loads(event["payload_json"])["previous_status"], "FAILED_SAFE")
            state.close()

    def test_owner_resume_is_atomic_and_selects_only_the_causal_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(Path(directory) / "controller.db")
            state.create_product(
                product_id="product",
                owner_id="owner",
                source="cli",
                idea="idea",
                idempotency_key="selective-owner-resume",
            )
            state.transition_product("product", "CONTRACT_DRAFTED")
            state.add_task(
                task_id="ancestor",
                product_id="product",
                title="Historical failed ancestor",
            )
            claimed = state.claim_task(worker_id="worker")
            self.assertIsNotNone(claimed)
            state.complete_task(
                "ancestor",
                "worker",
                "FAILED_SAFE",
                reason_code="schema_validation",
                detail="safe historical failure",
                result_ref="evidence/failure-ancestor.json",
                failure_kind="semantic",
            )
            state.add_task(
                task_id="causal-leaf",
                product_id="product",
                title="Current recovery leaf",
                parent_task_id="ancestor",
                source_task_id="ancestor",
                supersedes_task_id="ancestor",
            )
            state.transition_product("product", "PAUSED")
            with state._lock, state._connection:
                state._connection.execute(
                    """UPDATE tasks
                       SET status='PENDING', graph_status='READY',
                           terminal_reason=NULL, terminal_detail=NULL,
                           result_ref=NULL, failure_kind=NULL
                       WHERE task_id='ancestor'"""
                )
                state._record_event(
                    "product",
                    "ancestor",
                    "task_requeued",
                    {
                        "attempt_kind": "owner_resume",
                        "previous_status": "FAILED_SAFE",
                        "reason": "owner_resume",
                    },
                )

            product = WorkflowEngine(state).resume("product", "IMPLEMENTING")

            self.assertEqual(product["status"], "IMPLEMENTING")
            ancestor = state.get_task("ancestor")
            self.assertIsNotNone(ancestor)
            assert ancestor is not None
            self.assertEqual(ancestor["status"], "FAILED_SAFE")
            self.assertEqual(ancestor["graph_status"], "FAILED_SEMANTIC")
            self.assertEqual(
                ancestor["result_ref"],
                "evidence/failure-ancestor.json",
            )
            self.assertEqual(ancestor["terminal_reason"], "schema_validation")
            self.assertEqual(ancestor["failure_kind"], "semantic")
            claimed_leaf = state.claim_task(worker_id="resume-worker")
            self.assertIsNotNone(claimed_leaf)
            assert claimed_leaf is not None
            self.assertEqual(claimed_leaf["task_id"], "causal-leaf")
            event_types = [
                event["event_type"]
                for event in state.events("product")
            ]
            self.assertIn("owner_resume_ancestor_reconciled", event_types)
            state.close()

    def test_owner_resume_leaves_open_semantic_failure_to_router(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(Path(directory) / "controller.db")
            state.create_product(
                product_id="product",
                owner_id="owner",
                source="cli",
                idea="idea",
                idempotency_key="router-owned-resume",
            )
            state.transition_product("product", "CONTRACT_DRAFTED")
            state.add_task(
                task_id="failed",
                product_id="product",
                title="Router-owned failure",
            )
            claimed = state.claim_task(worker_id="worker")
            self.assertIsNotNone(claimed)
            state.complete_task(
                "failed",
                "worker",
                "FAILED_SAFE",
                reason_code="plan_contract_violation",
                detail="safe causal coordinate",
                result_ref="evidence/failure-failed.json",
                failure_kind="semantic",
            )
            now = "2026-07-31T00:00:00Z"
            with state._lock, state._connection:
                state._connection.execute(
                    """INSERT INTO failures
                       (failure_id, product_id, task_id, attempt_id,
                        parent_failure_id, failure_class, reason_code,
                        fingerprint, safe_message, exception_type,
                        stack_fingerprint, evidence_ref, status, retryable,
                        owner_action_eligible, expected_json, actual_json,
                        failed_gate_ids_json, first_seen_at, last_seen_at)
                       VALUES ('failure-router-owned', 'product', 'failed', NULL,
                               NULL, 'semantic', 'plan_contract_violation',
                               'router-owned-fingerprint', 'safe causal coordinate',
                               NULL, NULL, 'evidence/failure-failed.json', 'OPEN',
                               0, 0, '{}', '{}', '[]', ?, ?)""",
                    (now, now),
                )

            WorkflowEngine(state).resume("product", "IMPLEMENTING")

            failed = state.get_task("failed")
            self.assertIsNotNone(failed)
            assert failed is not None
            self.assertEqual(failed["status"], "FAILED_SAFE")
            self.assertEqual(failed["graph_status"], "FAILED_SEMANTIC")
            self.assertFalse(
                any(
                    event["event_type"] == "task_requeued"
                    for event in state.events("product")
                )
            )
            state.close()

    def test_conflict_keys_serialize_same_file_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(Path(directory) / "controller.db")
            state.create_product(
                product_id="product",
                owner_id="owner",
                source="cli",
                idea="idea",
                idempotency_key="conflict-key",
            )
            state.add_task(
                task_id="first",
                product_id="product",
                title="First writer",
                conflict_keys=["src/shared.py"],
                priority=10,
            )
            state.add_task(
                task_id="second",
                product_id="product",
                title="Second writer",
                conflict_keys=["src/shared.py"],
            )
            first = state.claim_task(worker_id="worker-a")
            self.assertIsNotNone(first)
            self.assertIsNone(state.claim_task(worker_id="worker-b"))
            state.complete_task("first", "worker-a")
            second = state.claim_task(worker_id="worker-b")
            self.assertIsNotNone(second)
            assert second is not None
            self.assertEqual(second["task_id"], "second")
            state.close()

    def test_max_active_workers_and_outbox_lease_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(
                Path(directory) / "controller.db",
                max_active_workers=2,
                max_active_products=3,
            )
            for index, task_id in enumerate(("first", "second", "third"), 1):
                product_id = f"product-{index}"
                state.create_product(
                    product_id=product_id,
                    owner_id="owner",
                    source="cli",
                    idea=task_id,
                    idempotency_key=f"worker-limit-{index}",
                )
                state.add_task(
                    task_id=task_id,
                    product_id=product_id,
                    title=task_id,
                )
            self.assertEqual(state.claim_task(worker_id="worker-a")["task_id"], "first")
            self.assertEqual(state.claim_task(worker_id="worker-b")["task_id"], "second")
            self.assertIsNone(state.claim_task(worker_id="worker-c"))
            state.complete_task("first", "worker-a")
            self.assertEqual(state.claim_task(worker_id="worker-c")["task_id"], "third")
            self.assertTrue(
                state.enqueue_outbox(
                    outbox_id="lease-outbox",
                    idempotency_key="lease-outbox-key",
                    event_type="test",
                    payload={},
                )
            )
            claimed = state.claim_outbox("worker-a", lease_seconds=1)
            self.assertEqual(len(claimed), 1)
            state._connection.execute(
                "UPDATE outbox SET lease_until='2000-01-01T00:00:00Z' WHERE outbox_id='lease-outbox'"
            )
            state._connection.commit()
            recovered = state.claim_outbox("worker-b")
            self.assertEqual(recovered[0]["lease_owner"], "worker-b")
            state.close()

    def test_product_intake_queues_while_active_execution_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(
                Path(directory) / "controller.db",
                max_active_workers=2,
                max_active_products=1,
            )
            state.create_product(
                product_id="first-product",
                owner_id="owner",
                source="cli",
                idea="first",
                idempotency_key="first-product-key",
            )
            created, was_created = state.create_product(
                product_id="second-product",
                owner_id="owner",
                source="cli",
                idea="second",
                idempotency_key="second-product-key",
            )
            self.assertTrue(was_created)
            self.assertEqual(created["product_id"], "second-product")
            state.add_task(
                task_id="first-task",
                product_id="first-product",
                title="First",
            )
            state.add_task(
                task_id="second-task",
                product_id="second-product",
                title="Second",
            )

            first = state.claim_task(worker_id="worker-a")
            self.assertIsNotNone(first)
            self.assertEqual(first["task_id"], "first-task")
            self.assertIsNone(state.claim_task(worker_id="worker-b"))
            state.complete_task("first-task", "worker-a")

            second = state.claim_task(worker_id="worker-b")
            self.assertIsNotNone(second)
            self.assertEqual(second["task_id"], "second-task")
            state.close()

    def test_cancel_stops_queued_and_leased_product_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(Path(directory) / "controller.db")
            state.create_product(
                product_id="product",
                owner_id="owner",
                source="cli",
                idea="idea",
                idempotency_key="cancel-product-key",
            )
            state.add_task(task_id="claimed", product_id="product", title="Claimed")
            state.add_task(task_id="queued", product_id="product", title="Queued")
            claimed = state.claim_task(worker_id="worker")
            self.assertIsNotNone(claimed)

            WorkflowEngine(state).cancel("product")

            self.assertEqual(state.get_product("product")["status"], "CANCELLED")
            for task_id in ("claimed", "queued"):
                task = state.get_task(task_id)
                self.assertEqual(task["status"], "FAILED_SAFE")
                self.assertIsNone(task["lease_owner"])
                self.assertIsNone(task["lease_until"])
            self.assertIsNone(state.claim_task(worker_id="other"))
            cancelled_events = [
                event
                for event in state.events("product")
                if event["event_type"] == "task_cancelled"
            ]
            self.assertEqual(len(cancelled_events), 2)
            state.close()

    def test_claim_skips_tasks_for_terminal_products(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(Path(directory) / "controller.db")
            state.create_product(
                product_id="product",
                owner_id="owner",
                source="cli",
                idea="idea",
                idempotency_key="terminal-product-key",
            )
            state.add_task(task_id="queued", product_id="product", title="Queued")
            state.transition_product("product", "CANCELLED")
            self.assertIsNone(state.claim_task(worker_id="worker"))
            state.close()

    def test_registry_context_prompt_and_attempt_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _make_config(root / "state")
            state = StateStore(config.database_path)
            artifacts = ArtifactStore(config)
            intake = IntakeService(config, state, artifacts)
            intake_result = intake.submit(source="cli", owner_id="owner", idea="A safe product")
            intake_artifact = json.loads(
                Path(intake_result.artifact_path).read_text(encoding="utf-8")
            )
            registered = SchemaRegistry(config, artifacts).register(
                "idea-intake.schema.json", intake_artifact, filename="registered-intake.json"
            )
            self.assertEqual(registered.artifact_id, intake_artifact["artifact_id"])

            repo = root / "repo"
            repo.mkdir()
            fake_credential = "A" * 24
            (repo / "main.py").write_text(
                f"password = {fake_credential}\nprint('ok')\n",
                encoding="utf-8",
            )
            context = ContextBuilder(config, repo, artifacts).build(
                product_id="product",
                task_id="task",
                subject_sha="a" * 64,
                objective="Run the safe check",
                acceptance=["The command exits successfully"],
                candidates=[("main.py", "task target")],
                allowed_paths=["main.py"],
                forbidden_actions=["deploy"],
                output_schema="attempt-result.schema.json",
                evidence=[
                    {"type": "test", "summary": "passed", "artifact_ref": "registered-intake.json"}
                ],
            )
            selected_file = context.artifact["file_excerpts"][0]
            self.assertIn("[REDACTED]", selected_file["content"])
            self.assertNotIn(fake_credential, selected_file["content"])
            self.assertEqual(
                selected_file["redactions"][0]["detector"],
                "named_credential",
            )
            prompt = PromptCompiler(config).compile(
                role="builder",
                context_pack=context.artifact,
                output_schema="attempt-result.schema.json",
            )
            self.assertEqual(len(prompt.digest), 64)
            self.assertGreater(prompt.size_chars, 100)
            planning_prompt = PromptCompiler(config).compile(
                role="task-specifier",
                context_pack=context.artifact,
                output_schema="backlog-plan-v2.schema.json",
            )
            self.assertIn(
                "OUTPUT_SCHEMA_DEPENDENCY task-contract-v2.schema.json",
                planning_prompt.prompt,
            )
            self.assertIn('"root_context_ref"', planning_prompt.prompt)
            self.assertIn('"idempotency_key"', planning_prompt.prompt)
            self.assertIn('"FAILED_SEMANTIC"', planning_prompt.prompt)

            (root / "task-marker").write_text("", encoding="utf-8")
            state.transition_product(intake_result.product_id, "CANCELLED")
            state.create_product(
                product_id="product",
                owner_id="owner",
                source="cli",
                idea="idea",
                idempotency_key="attempt-product-key",
            )
            state.add_task(task_id="attempt-task", product_id="product", title="Attempt")
            manager = AttemptManager(state, ROOT / "policies" / "model-routing-policy.yaml")
            attempt = manager.begin(
                task_id="attempt-task",
                tier=Tier.LUNA,
                attempt_kind="semantic",
                prompt_digest=prompt.digest,
            )
            resumed = manager.begin(
                task_id="attempt-task",
                tier=Tier.LUNA,
                attempt_kind="semantic",
                prompt_digest=prompt.digest,
            )
            self.assertEqual(resumed, attempt)
            self.assertFalse(attempt.resumed)
            self.assertTrue(resumed.resumed)
            self.assertEqual(len(state.attempts_for_task("attempt-task")), 1)
            manager.finish(attempt, status="repair_required", reason_code="unit_test_failure")
            decision = manager.route(
                task_id="attempt-task",
                role="builder",
                risk="low",
                complexity_score=2,
                tier=Tier.LUNA,
                success=False,
                reason_code="unit_test_failure",
                new_evidence=True,
            )
            self.assertEqual(decision.action, "escalate")
            with self.assertRaises(IdenticalAttemptError):
                manager.begin(
                    task_id="attempt-task",
                    tier=Tier.LUNA,
                    attempt_kind="semantic",
                    prompt_digest=prompt.digest,
                )
            state.close()

    def test_prompt_compiler_rejects_path_escaping_schema_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            schema_root = root / "schemas"
            schema_root.mkdir()
            (schema_root / "unsafe.schema.json").write_text(
                json.dumps({"$ref": "../outside.schema.json"}),
                encoding="utf-8",
            )
            config = _make_config(root / "state")
            config.raw["paths"]["schemas"] = str(schema_root)

            with self.assertRaisesRegex(ValueError, "unsafe reference"):
                PromptCompiler(config).compile(
                    role="builder",
                    context_pack={"safe": True},
                    output_schema="unsafe.schema.json",
                )

    def test_tool_adapter_and_workspace_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = WorkspaceManager(root / "worktrees")
            lease = manager.acquire(product_id="product", task_id="task", worker_id="worker")
            with self.assertRaises(RuntimeError):
                manager.acquire(product_id="product", task_id="task", worker_id="other")
            target = manager.assert_write_allowed(lease, "src/main.py", ["src/**"], [])
            self.assertEqual(target, (lease.path / "src/main.py").resolve())
            adapter = ToolPolicyAdapter(lease.path, ["python"])
            result = adapter.run("python -c \"print('ok')\"", cwd=lease.path)
            self.assertEqual(result.status, "PASS")
            denied = adapter.run("git push --force origin main", cwd=lease.path)
            self.assertEqual(denied.status, "DENIED")
            manager.release(lease)
            self.assertFalse(lease.path.exists())

    def test_worker_workspace_starts_from_source_snapshot_without_runtime_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            (source / "src").mkdir(parents=True)
            (source / "src" / "main.py").write_text("print('ok')\n", encoding="utf-8")
            (source / "state").mkdir()
            (source / "state" / "controller.db").write_text("runtime\n", encoding="utf-8")
            manager = WorkspaceManager(root / "worktrees", source_root=source)
            lease = manager.acquire(product_id="product", task_id="task", worker_id="worker")
            self.assertTrue((lease.path / "src" / "main.py").is_file())
            self.assertFalse((lease.path / "state").exists())
            manager.release(lease)

    def test_persistent_product_workspace_preserves_changes_between_task_leases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def initialize(_product_id: str, destination: Path) -> None:
                destination.mkdir(parents=True)
                (destination / "README.md").write_text("target repository\n", encoding="utf-8")

            manager = WorkspaceManager(
                root / "worktrees",
                persistent=True,
                initializer=initialize,
            )
            first = manager.acquire(product_id="product", task_id="builder", worker_id="worker")
            (first.path / "src.py").write_text("value = 1\n", encoding="utf-8")
            manager.release(first)

            second = manager.acquire(product_id="product", task_id="tests", worker_id="worker")

            self.assertEqual(second.path, first.path)
            self.assertEqual((second.path / "src.py").read_text(encoding="utf-8"), "value = 1\n")
            manager.release(second)
            self.assertTrue(second.path.is_dir())
            self.assertFalse((second.path / ".lease.json").exists())
            self.assertFalse(
                (second.path.parent / ".repository.lease.json").exists()
            )

    def test_provider_cleanup_cannot_remove_controller_workspace_lease(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def initialize(_product_id: str, destination: Path) -> None:
                destination.mkdir(parents=True)
                (destination / "README.md").write_text(
                    "target repository\n",
                    encoding="utf-8",
                )

            manager = WorkspaceManager(
                root / "worktrees",
                persistent=True,
                initializer=initialize,
            )
            lease = manager.acquire(
                product_id="product",
                task_id="builder",
                worker_id="worker",
            )
            marker = lease.path.parent / ".repository.lease.json"
            self.assertTrue(marker.is_file())

            for child in lease.path.iterdir():
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()

            self.assertTrue(marker.is_file())
            manager.release(lease)
            self.assertFalse(marker.exists())

    def test_persistent_workspace_reclaims_only_durably_stale_lease(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active_leases = {("product", "builder", "worker-a")}

            def initialize(_product_id: str, destination: Path) -> None:
                destination.mkdir(parents=True)
                (destination / "README.md").write_text(
                    "target repository\n",
                    encoding="utf-8",
                )

            manager = WorkspaceManager(
                root / "worktrees",
                persistent=True,
                initializer=initialize,
                lease_is_active=lambda product_id, task_id, worker_id: (
                    product_id,
                    task_id,
                    worker_id,
                )
                in active_leases,
            )
            first = manager.acquire(
                product_id="product",
                task_id="builder",
                worker_id="worker-a",
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "workspace already leased",
            ):
                manager.acquire(
                    product_id="product",
                    task_id="tests",
                    worker_id="worker-b",
                )

            active_leases.clear()
            second = manager.acquire(
                product_id="product",
                task_id="tests",
                worker_id="worker-b",
            )

            self.assertEqual(second.path, first.path)
            self.assertNotEqual(second.lease_id, first.lease_id)
            manager.release(second)

    def test_workspace_marker_activity_uses_durable_task_lease(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = _make_config(Path(directory))
            state = StateStore(config.database_path)
            state.create_product(
                product_id="product",
                owner_id="owner",
                source="test",
                idea="test durable workspace lease",
                idempotency_key="workspace-lease",
            )
            state.add_task(
                task_id="builder",
                product_id="product",
                title="Build",
                role="builder",
                stage_key="builder-core",
            )
            claimed = state.claim_task(worker_id="worker-a", lease_seconds=300)
            self.assertIsNotNone(claimed)
            self.assertTrue(
                state.workspace_lease_is_active(
                    "product",
                    "builder",
                    "worker-a",
                )
            )
            self.assertFalse(
                state.workspace_lease_is_active(
                    "product",
                    "builder",
                    "worker-b",
                )
            )
            with state._lock, state._connection:
                state._connection.execute(
                    "UPDATE tasks SET lease_until='2000-01-01T00:00:00Z' "
                    "WHERE task_id='builder'"
                )
            self.assertFalse(
                state.workspace_lease_is_active(
                    "product",
                    "builder",
                    "worker-a",
                )
            )
            state.close()

    def test_external_boundaries_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = _make_config(Path(directory) / "state")
            provider = ProviderRegistry(config)
            with self.assertRaises(ExternalBlocker):
                provider.select("economy", tier="luna")

            breaker = ProviderCircuitBreaker("provider", failure_threshold=2)
            breaker.record_transient_failure()
            self.assertTrue(breaker.allow_request())
            breaker.record_transient_failure()
            self.assertFalse(breaker.allow_request())
            breaker.health_probe(True)
            self.assertTrue(breaker.allow_request())

            owner_action = OwnerActionService(config).create(
                reason="missing_credential",
                title="Connect credential",
                why_blocked="External credential is absent",
                single_action="Connect the credential through the secure VPS path",
                safe_instruction=["Use the existing secure credential flow."],
                unblock_probe="credential health probe",
                unblock_expected="PASS",
                independent_work_continues=["Keep local validation available"],
            )
            self.assertTrue(owner_action.is_file())
            artifact_store = ArtifactStore(config)
            artifact = json.loads(owner_action.read_text(encoding="utf-8"))
            self.assertEqual(artifact_store.validate("owner-action.schema.json", artifact), [])
            self.assertEqual(
                OwnerActionService(config).create(
                    reason="missing_credential",
                    title="Connect credential",
                    why_blocked="External credential is absent",
                    single_action="Connect the credential through the secure VPS path",
                    safe_instruction=["Use the existing secure credential flow."],
                    unblock_probe="credential health probe",
                    unblock_expected="PASS",
                    independent_work_continues=["Keep local validation available"],
                ),
                owner_action,
            )

            self.assertEqual(parse_command("/idea Build a safe tool").name, "idea")
            with self.assertRaises(GatewayCommandError):
                parse_command("/status now")
            with self.assertRaises(GatewayCommandError):
                parse_command("/idea " + "ghp_" + "abcdefghijklmnopqrstuvwxyz123456")

            guard = DeploymentGuard()
            self.assertEqual(
                guard.promote(
                    environment="staging",
                    risk="low",
                    image_digest="sha256:" + "a" * 64,
                    staging_digest=None,
                    stateful=False,
                    offsite_backup_configured=False,
                ).status,
                "READY",
            )
            with self.assertRaises(ExternalBlocker):
                guard.promote(
                    environment="production",
                    risk="high",
                    image_digest="sha256:" + "a" * 64,
                    staging_digest="sha256:" + "a" * 64,
                    stateful=False,
                    offsite_backup_configured=False,
                )

            backup = BackupAdapter().backup("/var/lib/hermes-factory")
            self.assertNotIn("RESTIC_PASSWORD", " ".join(backup.argv))
            with (
                patch.dict(os.environ, {"GH_TOKEN": ""}, clear=False),
                self.assertRaises(ExternalBlocker),
            ):
                GitHubAdapter("brullik", "hermes-software-factory").require_authentication()

    def test_transactional_deployer_promotes_and_retains_previous_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "install"
            source = Path(directory) / "candidate"
            source.mkdir(parents=True)
            (source / "VERSION").write_text("new\n", encoding="utf-8")
            (root / "current").mkdir(parents=True)
            (root / "current" / "VERSION").write_text("old\n", encoding="utf-8")

            deployer = TransactionalDeployer(
                root,
                health_probe=lambda current: (
                    (current / "VERSION").read_text(encoding="utf-8").strip() == "new"
                ),
            )
            result = deployer.promote("candidate-1", source)

            self.assertEqual(result.status, "PROMOTED")
            self.assertEqual(
                (root / "current" / "VERSION").read_text(encoding="utf-8").strip(), "new"
            )
            self.assertEqual(
                (root / "backup-candidate-1-previous" / "VERSION")
                .read_text(encoding="utf-8")
                .strip(),
                "old",
            )

    def test_transactional_deployer_activates_before_health_probe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "install"
            source = Path(directory) / "candidate"
            source.mkdir(parents=True)
            (root / "current").mkdir(parents=True)
            activation_calls: list[str] = []

            result = TransactionalDeployer(
                root,
                health_probe=lambda _current: True,
                activate=lambda: activation_calls.append("restart"),
            ).promote("candidate-activate", source)

            self.assertEqual(result.status, "PROMOTED")
            self.assertEqual(activation_calls, ["restart"])

    def test_transactional_deployer_rolls_back_failed_health_and_keeps_failed_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "install"
            source = Path(directory) / "candidate"
            source.mkdir(parents=True)
            (source / "VERSION").write_text("bad\n", encoding="utf-8")
            (root / "current").mkdir(parents=True)
            (root / "current" / "VERSION").write_text("safe\n", encoding="utf-8")

            deployer = TransactionalDeployer(root, health_probe=lambda _current: False)
            result = deployer.promote("candidate-2", source)

            self.assertEqual(result.status, "ROLLED_BACK")
            self.assertEqual(
                (root / "current" / "VERSION").read_text(encoding="utf-8").strip(), "safe"
            )
            self.assertEqual(
                (root / "failed-candidate-2" / "VERSION").read_text(encoding="utf-8").strip(), "bad"
            )

    def test_transactional_deployer_rejects_existing_backup_before_swap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "install"
            source = Path(directory) / "candidate"
            source.mkdir(parents=True)
            (root / "backup-candidate-3-previous").mkdir(parents=True)

            with self.assertRaises(DeploymentError):
                TransactionalDeployer(root, health_probe=lambda _current: True).promote(
                    "candidate-3", source
                )

    def test_github_cli_boundary_is_allowlisted_and_sha_guarded(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str]):
            calls.append(argv)
            from subprocess import CompletedProcess

            output = (
                '{"headRefOid":"' + "a" * 40 + '"}' if "pr" in argv and "view" in argv else "ok"
            )
            return CompletedProcess(argv, 0, output, "")

        adapter = GitHubAdapter("brullik", "hermes-software-factory", runner=runner)
        with patch.dict(os.environ, {"GH_TOKEN": "token-is-not-used-in-argv"}, clear=False):
            self.assertEqual(adapter.repository_view().status, "PASS")
            self.assertEqual(
                adapter.merge_pull_request("17", expected_sha="a" * 40).status,
                "PASS",
            )
        with self.assertRaises(ValueError):
            adapter.create_issue(title="safe", body="ghp_" + "abcdefghijklmnopqrstuvwxyz123456")
        with self.assertRaises(ValueError):
            adapter.merge_pull_request("17", expected_sha="bad")
        self.assertTrue(all("token-is-not-used-in-argv" not in str(call) for call in calls))
        with (
            patch.dict(os.environ, {"GH_TOKEN": "token-is-not-used-in-argv"}, clear=False),
            self.assertRaises(GitHubCommandError),
        ):
            adapter.merge_pull_request("17", expected_sha="b" * 40)

    def test_github_release_lookup_requires_unique_head_and_reads_merge_sha(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str]):
            calls.append(argv)
            from subprocess import CompletedProcess

            if "list" in argv:
                output = json.dumps([{"number": 17, "headRefOid": "a" * 40}])
            else:
                output = json.dumps({"state": "MERGED", "mergeCommit": {"oid": "b" * 40}})
            return CompletedProcess(argv, 0, output, "")

        adapter = GitHubAdapter("brullik", "hermes-software-factory", runner=runner)
        with patch.dict(os.environ, {"GH_TOKEN": "token-is-not-used-in-argv"}, clear=False):
            self.assertEqual(adapter.pull_request_for_head_sha("a" * 40), "17")
            self.assertEqual(adapter.merged_commit("17"), "b" * 40)
        self.assertTrue(any("--json" in call for call in calls))

    def test_github_governance_gate_requires_approval_and_checks(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str]):
            calls.append(argv)
            from subprocess import CompletedProcess

            if "view" in argv:
                output = json.dumps(
                    {
                        "headRefOid": "a" * 40,
                        "state": "OPEN",
                        "reviewDecision": "APPROVED",
                        "mergeStateStatus": "CLEAN",
                        "statusCheckRollup": [
                            {"name": "factory/quality", "state": "SUCCESS"},
                        ],
                    }
                )
            else:
                output = "merged"
            return CompletedProcess(argv, 0, output, "")

        adapter = GitHubAdapter("brullik", "hermes-software-factory", runner=runner)
        with patch.dict(os.environ, {"GH_TOKEN": "token-is-not-used-in-argv"}, clear=False):
            gate = adapter.verify_pull_request(
                "17",
                expected_sha="a" * 40,
                required_checks=("factory/quality",),
            )
            self.assertTrue(gate.approved)
            self.assertEqual(gate.approval_mode, "independent")
            self.assertEqual(
                adapter.merge_pull_request_checked("17", expected_sha="a" * 40).status, "PASS"
            )

        def blocked_runner(argv: list[str]):
            from subprocess import CompletedProcess

            return CompletedProcess(
                argv,
                0,
                json.dumps(
                    {
                        "headRefOid": "a" * 40,
                        "state": "OPEN",
                        "reviewDecision": "REVIEW_REQUIRED",
                        "mergeStateStatus": "CLEAN",
                        "statusCheckRollup": [],
                    }
                ),
                "",
            )

        blocked = GitHubAdapter("brullik", "hermes-software-factory", runner=blocked_runner)
        with (
            patch.dict(os.environ, {"GH_TOKEN": "token-is-not-used-in-argv"}, clear=False),
            self.assertRaises(GitHubCommandError),
        ):
            blocked.merge_pull_request_checked("17", expected_sha="a" * 40)

    def test_single_owner_override_is_explicit_and_audited(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str]):
            calls.append(argv)
            from subprocess import CompletedProcess

            if "view" in argv:
                output = json.dumps(
                    {
                        "headRefOid": "a" * 40,
                        "state": "OPEN",
                        "reviewDecision": "REVIEW_REQUIRED",
                        "mergeStateStatus": "CLEAN",
                        "statusCheckRollup": [
                            {"name": "factory/quality", "state": "SUCCESS"},
                        ],
                    }
                )
            else:
                output = "merged"
            return CompletedProcess(argv, 0, output, "")

        reason = "Owner explicitly enabled single-owner release for this VPS"
        normal = GitHubAdapter("brullik", "hermes-software-factory", runner=runner)
        with (
            patch.dict(os.environ, {"GH_TOKEN": "token-is-not-used-in-argv"}, clear=False),
            self.assertRaises(GitHubCommandError),
        ):
            normal.merge_pull_request_checked(
                "17",
                expected_sha="a" * 40,
                owner_override=True,
                owner_override_reason=reason,
            )

        calls.clear()
        single_owner = GitHubAdapter(
            "brullik",
            "hermes-software-factory",
            runner=runner,
            single_owner_mode=True,
        )
        with patch.dict(os.environ, {"GH_TOKEN": "token-is-not-used-in-argv"}, clear=False):
            gate = single_owner.verify_pull_request(
                "17",
                expected_sha="a" * 40,
                required_checks=("factory/quality",),
                owner_override=True,
                owner_override_reason=reason,
            )
            self.assertFalse(gate.approved)
            self.assertEqual(gate.approval_mode, "owner_override")
            self.assertEqual(gate.owner_override_reason, reason)
            result = single_owner.merge_pull_request_checked(
                "17",
                expected_sha="a" * 40,
                owner_override=True,
                owner_override_reason=reason,
            )
            self.assertEqual(result.status, "PASS")
            self.assertIn("approval_mode=owner_override", result.output)
        self.assertTrue(any("--admin" in call for call in calls))


if __name__ == "__main__":
    unittest.main()
