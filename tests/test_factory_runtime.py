from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from factory.artifacts import ArtifactStore
from factory.attempts import AttemptManager, IdenticalAttemptError
from factory.backup import BackupAdapter
from factory.config import FactoryConfig, load_config
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
    raw = yaml.safe_load((ROOT / "config" / "factory-config.example.yaml").read_text(encoding="utf-8"))
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
            first = intake.submit(source="cli", owner_id="owner", idea="first", idempotency_key="one")
            duplicate = intake.submit(source="cli", owner_id="owner", idea="different", idempotency_key="one")
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
            self.assertEqual(workflow.transition("product", "CONTRACT_DRAFTED")["status"], "CONTRACT_DRAFTED")
            self.assertEqual(workflow.pause("product")["status"], "PAUSED")
            self.assertEqual(workflow.resume("product", "CONTRACT_DRAFTED")["status"], "CONTRACT_DRAFTED")
            state.add_task(task_id="first", product_id="product", title="First")
            state.add_task(task_id="second", product_id="product", title="Second", dependencies=["first"])
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
            self.assertEqual(workflow.resume("product", "IMPLEMENTING")["status"], "CONTRACT_DRAFTED")
            self.assertEqual(state.get_task("second")["status"], "PENDING")
            next_task = state.claim_task(worker_id="other")
            self.assertIsNotNone(next_task)
            assert next_task is not None
            self.assertEqual(next_task["task_id"], "second")
            self.assertTrue(state.enqueue_outbox(
                outbox_id="outbox-1",
                idempotency_key="effect-1",
                event_type="github_pr_create",
                payload={"subject": "sha"},
            ))
            self.assertFalse(state.enqueue_outbox(
                outbox_id="outbox-duplicate",
                idempotency_key="effect-1",
                event_type="github_pr_create",
                payload={"subject": "sha"},
            ))
            outbox = state.claim_outbox("worker")
            self.assertEqual(len(outbox), 1)
            state.mark_outbox_done("outbox-1", "worker")
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
            state = StateStore(Path(directory) / "controller.db", max_active_workers=2)
            state.create_product(
                product_id="product",
                owner_id="owner",
                source="cli",
                idea="idea",
                idempotency_key="worker-limit",
            )
            for task_id in ("first", "second", "third"):
                state.add_task(task_id=task_id, product_id="product", title=task_id)
            self.assertEqual(state.claim_task(worker_id="worker-a")["task_id"], "first")
            self.assertEqual(state.claim_task(worker_id="worker-b")["task_id"], "second")
            self.assertIsNone(state.claim_task(worker_id="worker-c"))
            state.complete_task("first", "worker-a")
            self.assertEqual(state.claim_task(worker_id="worker-c")["task_id"], "third")
            self.assertTrue(state.enqueue_outbox(
                outbox_id="lease-outbox",
                idempotency_key="lease-outbox-key",
                event_type="test",
                payload={},
            ))
            claimed = state.claim_outbox("worker-a", lease_seconds=1)
            self.assertEqual(len(claimed), 1)
            state._connection.execute(
                "UPDATE outbox SET lease_until='2000-01-01T00:00:00Z' WHERE outbox_id='lease-outbox'"
            )
            state._connection.commit()
            recovered = state.claim_outbox("worker-b")
            self.assertEqual(recovered[0]["lease_owner"], "worker-b")
            state.close()

    def test_active_product_capacity_is_enforced_and_released(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(Path(directory) / "controller.db", max_active_products=1)
            state.create_product(
                product_id="first-product",
                owner_id="owner",
                source="cli",
                idea="first",
                idempotency_key="first-product-key",
            )
            with self.assertRaises(ValueError):
                state.create_product(
                    product_id="second-product",
                    owner_id="owner",
                    source="cli",
                    idea="second",
                    idempotency_key="second-product-key",
                )
            state.transition_product("first-product", "CANCELLED")
            created, was_created = state.create_product(
                product_id="second-product",
                owner_id="owner",
                source="cli",
                idea="second",
                idempotency_key="second-product-key",
            )
            self.assertTrue(was_created)
            self.assertEqual(created["product_id"], "second-product")
            state.close()

    def test_registry_context_prompt_and_attempt_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _make_config(root / "state")
            state = StateStore(config.database_path)
            artifacts = ArtifactStore(config)
            intake = IntakeService(config, state, artifacts)
            intake_result = intake.submit(source="cli", owner_id="owner", idea="A safe product")
            intake_artifact = json.loads(Path(intake_result.artifact_path).read_text(encoding="utf-8"))
            registered = SchemaRegistry(config, artifacts).register(
                "idea-intake.schema.json", intake_artifact, filename="registered-intake.json"
            )
            self.assertEqual(registered.artifact_id, intake_artifact["artifact_id"])

            repo = root / "repo"
            repo.mkdir()
            (repo / "main.py").write_text("print('ok')\n", encoding="utf-8")
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
                evidence=[{"type": "test", "summary": "passed", "artifact_ref": "registered-intake.json"}],
            )
            prompt = PromptCompiler(config).compile(
                role="builder",
                context_pack=context.artifact,
                output_schema="attempt-result.schema.json",
            )
            self.assertEqual(len(prompt.digest), 64)
            self.assertGreater(prompt.size_chars, 100)

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
            self.assertEqual(OwnerActionService(config).create(
                reason="missing_credential",
                title="Connect credential",
                why_blocked="External credential is absent",
                single_action="Connect the credential through the secure VPS path",
                safe_instruction=["Use the existing secure credential flow."],
                unblock_probe="credential health probe",
                unblock_expected="PASS",
                independent_work_continues=["Keep local validation available"],
            ), owner_action)

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
            with patch.dict(os.environ, {"GH_TOKEN": ""}, clear=False), self.assertRaises(ExternalBlocker):
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
                health_probe=lambda current: (current / "VERSION").read_text(encoding="utf-8").strip() == "new",
            )
            result = deployer.promote("candidate-1", source)

            self.assertEqual(result.status, "PROMOTED")
            self.assertEqual((root / "current" / "VERSION").read_text(encoding="utf-8").strip(), "new")
            self.assertEqual(
                (root / "backup-candidate-1-previous" / "VERSION").read_text(encoding="utf-8").strip(),
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
            self.assertEqual((root / "current" / "VERSION").read_text(encoding="utf-8").strip(), "safe")
            self.assertEqual((root / "failed-candidate-2" / "VERSION").read_text(encoding="utf-8").strip(), "bad")

    def test_transactional_deployer_rejects_existing_backup_before_swap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "install"
            source = Path(directory) / "candidate"
            source.mkdir(parents=True)
            (root / "backup-candidate-3-previous").mkdir(parents=True)

            with self.assertRaises(DeploymentError):
                TransactionalDeployer(root, health_probe=lambda _current: True).promote("candidate-3", source)

    def test_github_cli_boundary_is_allowlisted_and_sha_guarded(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str]):
            calls.append(argv)
            from subprocess import CompletedProcess

            output = "{\"headRefOid\":\"" + "a" * 40 + "\"}" if "pr" in argv and "view" in argv else "ok"
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
        with patch.dict(os.environ, {"GH_TOKEN": "token-is-not-used-in-argv"}, clear=False), self.assertRaises(GitHubCommandError):
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
            self.assertEqual(adapter.merge_pull_request_checked("17", expected_sha="a" * 40).status, "PASS")

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
        with patch.dict(os.environ, {"GH_TOKEN": "token-is-not-used-in-argv"}, clear=False), self.assertRaises(GitHubCommandError):
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
        with patch.dict(os.environ, {"GH_TOKEN": "token-is-not-used-in-argv"}, clear=False), self.assertRaises(
            GitHubCommandError
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
