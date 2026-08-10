from __future__ import annotations

import json
import subprocess
import tempfile
import tomllib
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from factory.codex_supervisor import (
    CodexSupervisor,
    CommandResult,
    SupervisorBoundary,
    SupervisorConfig,
    SupervisorConfigurationError,
)
from factory.common import sha256_text, stable_json, utc_now
from factory.credential_broker import BrokerReceipt, BrokerRequest

SESSION_ID = "019c3fd5-3d61-7d20-a668-a2855efa25b1"
PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def ready_result(manifest: str = "artifact://ready/result") -> dict[str, Any]:
    return {
        "status": "AUTONOMOUS_FACTORY_READY",
        "factory": {
            "golden_product": "COMPLETED",
            "real_telegram_intake": "PASS",
            "github_delivery": "PASS",
            "product_delivery": "PASS",
            "internal_state_verification": "PASS",
            "ready_result_manifest": manifest,
        },
        "autonomy": {
            "routine_gpt_codex_required": False,
            "routine_owner_action_required": False,
            "restart_recovery": "PASS",
            "automatic_continuation": "PASS",
            "telegram_notifier": "ACTIVE",
            "support_bundle": "ACTIVE",
        },
        "self_improvement": {
            "status": "ACTIVE",
            "stable_self_write": False,
            "isolated_candidate_only": True,
            "finite_budget": True,
            "independent_evaluation": True,
        },
        "safety": {
            "credential_exposure": False,
            "manual_database_edits": 0,
            "branch_protection_bypassed": False,
            "duplicate_side_effects": 0,
            "open_controller_incidents": 0,
        },
        "reason_code": None,
        "single_action": None,
        "safe_instruction": None,
        "unblock_probe": None,
        "independent_work_completed": None,
        "user_action_required": False,
        "next_authority": "HERMES_AUTONOMOUS_RUNTIME",
    }


def owner_action_result() -> dict[str, Any]:
    return {
        "status": "OWNER_ACTION_REQUIRED",
        "factory": None,
        "autonomy": None,
        "self_improvement": None,
        "safety": None,
        "reason_code": "two_factor_authentication",
        "single_action": "Approve the existing login.",
        "safe_instruction": ["Open the official login prompt and approve it."],
        "unblock_probe": "Broker identity read returns PASS.",
        "independent_work_completed": ["All credential-free checks completed."],
        "user_action_required": True,
        "next_authority": "OWNER",
    }


def continuation_result(
    probe: str = "artifact://continuation/progress-one",
    completed: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "status": "CONTINUE_AUTONOMOUSLY",
        "factory": None,
        "autonomy": None,
        "self_improvement": None,
        "safety": None,
        "reason_code": None,
        "single_action": None,
        "safe_instruction": None,
        "unblock_probe": probe,
        "independent_work_completed": completed or ["Closed one bounded obligation."],
        "user_action_required": False,
        "next_authority": "HERMES_AUTONOMOUS_RUNTIME",
    }


class FakeNotificationStore:
    def __init__(self) -> None:
        self.events: list[dict[str, str]] = []

    def enqueue_notification(self, **event: str) -> None:
        self.events.append(event)


class FakeRunner:
    def __init__(self, steps: list[tuple[list[dict[str, Any]], CommandResult | Exception]]) -> None:
        self.steps = list(steps)
        self.commands: list[list[str]] = []
        self.prompts: list[str] = []
        self.environments: list[dict[str, str]] = []
        self.working_directories: list[Path] = []

    def run(
        self,
        command: list[str],
        *,
        cwd: Path,
        prompt: str,
        environment: dict[str, str],
        on_event: Callable[[dict[str, Any]], None],
    ) -> CommandResult:
        self.commands.append(command)
        self.prompts.append(prompt)
        self.environments.append(environment)
        self.working_directories.append(cwd)
        events, outcome = self.steps.pop(0)
        for event in events:
            if event.get("type") == "test.structured_result":
                result_index = command.index("--output-last-message") + 1
                Path(command[result_index]).write_text(
                    json.dumps(event["value"]), encoding="utf-8"
                )
            else:
                on_event(event)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeGenerationBroker:
    def __init__(self, source: Path, allowed_remote: str) -> None:
        self.source = source
        self.allowed_remote = allowed_remote
        self.old_head = self._git(source, "rev-parse", "HEAD")
        self.old_branch = self._git(source, "branch", "--show-current")
        self.seed = source.parent / "generation-main-seed"
        subprocess.run(
            ["/usr/bin/git", "clone", "--no-hardlinks", str(source), str(self.seed)],
            check=True,
            capture_output=True,
        )
        self._git(self.seed, "config", "user.name", "Generation Test")
        self._git(self.seed, "config", "user.email", "generation@example.invalid")
        self._git(self.seed, "branch", "-m", "main")
        self._git(self.seed, "commit", "--allow-empty", "-m", "merged main")
        self.merge_sha = self._git(self.seed, "rev-parse", "HEAD")
        self.requests: list[BrokerRequest] = []

    @staticmethod
    def _git(workspace: Path, *arguments: str) -> str:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(workspace), *arguments],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout.strip()

    @staticmethod
    def _receipt(request: BrokerRequest, object_ids: tuple[str, ...]) -> BrokerReceipt:
        unsigned = BrokerReceipt(
            request_id=request.request_id,
            operation=request.operation,
            target_slug="brullik/hermes-software-factory",
            subject_identity="brullik",
            result="PASS",
            object_ids=object_ids,
            credential_epoch_id="CE-GENERATION-TEST",
            timestamp=utc_now(),
            request_digest=request.digest(),
            receipt_digest="",
        )
        value = unsigned.as_dict()
        value.pop("receipt_digest")
        return BrokerReceipt(
            **{**value, "object_ids": tuple(value["object_ids"])},
            receipt_digest=sha256_text(stable_json(value)),
        )

    def execute(self, request: BrokerRequest) -> BrokerReceipt:
        self.requests.append(request)
        query = str(request.payload.get("query") or "")
        if query == "workspace_generation_for_head_sha":
            head = str(request.payload["sha"])
            if head != self.old_head:
                return self._receipt(
                    request,
                    (f"head_sha:{head}", "state:unpublished", "merged:False"),
                )
            return self._receipt(
                request,
                (
                    "number:192",
                    f"head_sha:{self.old_head}",
                    f"merge_sha:{self.merge_sha}",
                    "state:closed",
                    "merged:True",
                    f"head_ref:{self.old_branch}",
                    "base:main",
                ),
            )
        destination = Path(str(request.payload["workspace"]))
        subprocess.run(
            ["/usr/bin/git", "clone", "--no-hardlinks", str(self.seed), str(destination)],
            check=True,
            capture_output=True,
        )
        self._git(destination, "remote", "set-url", "origin", self.allowed_remote)
        return self._receipt(request, (f"sha:{self.merge_sha}", "state:cloned"))


class CodexSupervisorTests(unittest.TestCase):
    def test_vps_config_uses_exact_permissions_without_shell_snapshot(self) -> None:
        config = tomllib.loads(
            (PACKAGE_ROOT / "config" / "codex-vps" / "config.toml").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(config["approval_policy"], "on-request")
        self.assertEqual(config["approvals_reviewer"], "auto_review")
        self.assertEqual(config["default_permissions"], "codex-vps-workspace")
        self.assertEqual(config["model"], "gpt-5.6-sol")
        self.assertEqual(config["model_reasoning_effort"], "xhigh")
        self.assertFalse(config["features"]["shell_snapshot"])
        profile = config["permissions"]["codex-vps-workspace"]
        self.assertEqual(profile["extends"], ":workspace")
        workspace = profile["filesystem"][":workspace_roots"]
        self.assertEqual(workspace["."], "write")
        self.assertEqual(workspace[".git"], "write")
        self.assertEqual(workspace[".codex"], "read")
        self.assertEqual(
            profile["filesystem"]["/home/hermescodex/.codex/auth.json"], "deny"
        )
        self.assertEqual(
            profile["network"]["unix_sockets"]["/run/hermes-codex-github-broker/broker.sock"],
            "allow",
        )
        self.assertNotIn("danger-full-access", json.dumps(config, sort_keys=True))

    def test_vps_systemd_unit_keeps_code_mode_compatible_hardening(self) -> None:
        unit = (
            PACKAGE_ROOT / "config" / "systemd" / "hermes-codex-vps@.service"
        ).read_text(encoding="utf-8")
        self.assertIn("MemoryDenyWriteExecute=false", unit)
        self.assertNotIn("MemoryDenyWriteExecute=true", unit)
        for invariant in (
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "InaccessiblePaths=/etc/hermes-factory",
            "InaccessiblePaths=/opt/hermes-factory",
            "InaccessiblePaths=/var/lib/hermes-factory",
            "InaccessiblePaths=/var/log/hermes-factory",
        ):
            self.assertIn(invariant, unit)

    def test_git_probes_trust_only_the_exact_resolved_workspace(self) -> None:
        observed: list[tuple[list[str], dict[str, Any]]] = []

        def fake_run(
            argv: list[str], **kwargs: Any
        ) -> subprocess.CompletedProcess[Any]:
            observed.append((argv, kwargs))
            stdout: str | bytes = "value\n" if kwargs.get("text") else b"value\n"
            return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

        resolved = self.workspace.resolve(strict=True)
        with patch("factory.codex_supervisor.subprocess.run", side_effect=fake_run):
            self.assertEqual(CodexSupervisor._git_at(self.workspace, "status"), "value")
            self.assertEqual(
                CodexSupervisor._git_bytes_at(self.workspace, "diff"), b"value\n"
            )

        expected_prefix = [
            "/usr/bin/git",
            "-c",
            f"safe.directory={resolved}",
            "-C",
            str(resolved),
        ]
        self.assertEqual(observed[0][0], [*expected_prefix, "status"])
        self.assertEqual(observed[1][0], [*expected_prefix, "diff"])
        self.assertTrue(observed[0][1]["text"])
        self.assertNotIn("text", observed[1][1])
        self.assertTrue(
            all("safe.directory=*" not in argv for argv, _kwargs in observed)
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.worktree_root = self.root / "worktrees"
        self.state_root = self.root / "state"
        self.workspace = self.worktree_root / "goal-one"
        self.workspace.mkdir(parents=True)
        self.state_root.mkdir()
        self._git("init", "-b", "codex/test-supervisor")
        self._git("config", "user.name", "Codex Supervisor Test")
        self._git("config", "user.email", "codex-supervisor@example.invalid")
        (self.workspace / "README.md").write_text("trusted fixture\n", encoding="utf-8")
        self._git("add", "README.md")
        self._git("commit", "-m", "trusted fixture")
        self._git(
            "remote",
            "add",
            "origin",
            "https://github.com/brullik/hermes-software-factory.git",
        )
        self.base_sha = self._git("rev-parse", "HEAD")
        self.goal_dir = self.state_root / "goal-one"
        self.goal_dir.mkdir()
        self.goal_path = self.goal_dir / "goal.txt"
        self.goal_path.write_text("Inspect the trusted fixture and finish safely.\n", encoding="utf-8")
        self.schema_path = self.root / "result.schema.json"
        self.schema_path.write_text(
            json.dumps({"type": "object", "properties": {"status": {"type": "string"}}}),
            encoding="utf-8",
        )
        self.codex_binary = self.root / "bin" / "codex"
        self.codex_binary.parent.mkdir()
        self.codex_binary.write_text("fixture\n", encoding="utf-8")
        self.owner_action_db = self.root / "owner-actions" / "actions.sqlite3"
        self.boundary = SupervisorBoundary(
            worktree_root=self.worktree_root,
            state_root=self.state_root,
            codex_binary=self.codex_binary,
            owner_action_db=self.owner_action_db,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.workspace), *arguments],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return result.stdout.strip()

    def config(self, **overrides: Any) -> SupervisorConfig:
        values: dict[str, Any] = {
            "goal_id": "goal-one",
            "workspace": self.workspace,
            "state_path": self.goal_dir / "supervisor-state.json",
            "event_log_path": self.goal_dir / "events.jsonl",
            "result_path": self.goal_dir / "last-result.json",
            "goal_path": self.goal_path,
            "output_schema_path": self.schema_path,
            "codex_binary": self.codex_binary,
            "owner_action_db": self.owner_action_db,
            "trusted_base_sha": self.base_sha,
            "base_backoff_seconds": 0.0,
            "max_backoff_seconds": 0.0,
            "quota_retry_seconds": 1.0,
        }
        values.update(overrides)
        return SupervisorConfig(**values)

    def supervisor(self, runner: FakeRunner, **overrides: Any) -> CodexSupervisor:
        return CodexSupervisor(
            self.config(**overrides),
            runner=runner,
            sleep=lambda _delay: None,
            boundary=self.boundary,
        )

    def test_start_persists_thread_and_completes_with_private_jsonl(self) -> None:
        runner = FakeRunner(
            [
                (
                    [
                        {"type": "thread.started", "thread_id": SESSION_ID},
                        {
                            "type": "test.structured_result",
                            "value": ready_result(),
                        },
                        {"type": "turn.completed", "usage": {"input_tokens": 10}},
                    ],
                    CommandResult(0, ""),
                )
            ]
        )
        supervisor = self.supervisor(runner)
        state = supervisor.run_attempt()
        self.assertEqual(state.status, "COMPLETED")
        self.assertEqual(state.session_id, SESSION_ID)
        self.assertEqual(state.resume_count, 0)
        self.assertEqual(supervisor.config.event_log_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(supervisor.config.state_path.stat().st_mode & 0o777, 0o600)
        command = runner.commands[0]
        self.assertNotIn("--permission-profile", command)
        self.assertIn("--strict-config", command)
        self.assertNotIn("--sandbox", command)
        self.assertNotIn("--approve-for-me", command)
        self.assertIn("--json", command)
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", command)
        self.assertNotIn("danger-full-access", command)
        self.assertNotIn("--skip-git-repo-check", command)
        self.assertEqual(runner.environments[0].get("GITHUB_TOKEN"), None)
        self.assertEqual(runner.environments[0].get("GH_TOKEN"), None)

    def test_controlled_crash_preserves_and_resumes_exact_session(self) -> None:
        crashing = FakeRunner(
            [([{"type": "thread.started", "thread_id": SESSION_ID}], RuntimeError("killed"))]
        )
        first = self.supervisor(crashing)
        with self.assertRaisesRegex(RuntimeError, "killed"):
            first.run_attempt()
        crashed_state = first.load_state()
        self.assertEqual(crashed_state.status, "RUNNING")
        self.assertEqual(crashed_state.session_id, SESSION_ID)

        resumed = FakeRunner(
            [
                (
                    [
                        {
                            "type": "test.structured_result",
                            "value": ready_result(),
                        },
                        {"type": "turn.completed"},
                    ],
                    CommandResult(0, ""),
                )
            ]
        )
        second = self.supervisor(resumed)
        completed = second.run_attempt()
        self.assertEqual(completed.status, "COMPLETED")
        self.assertEqual(completed.session_id, SESSION_ID)
        self.assertEqual(completed.resume_count, 1)
        command = resumed.commands[0]
        self.assertIn("resume", command)
        self.assertIn(SESSION_ID, command)
        self.assertEqual(
            resumed.prompts,
            [
                (
                    "Продолжи ровно эту сохранённую задачу с последней безопасной контрольной "
                    "точки. Не создавай новый thread, не используй fork/внешний checkout и не "
                    "ослабляй gates."
                )
            ],
        )

    def test_quota_preserves_thread_and_never_creates_new_task(self) -> None:
        quota = FakeRunner(
            [
                (
                    [{"type": "thread.started", "thread_id": SESSION_ID}],
                    CommandResult(1, "usage limit reached; retry later"),
                )
            ]
        )
        supervisor = self.supervisor(quota)
        waiting = supervisor.run_attempt()
        self.assertEqual(waiting.status, "WAITING_QUOTA")
        self.assertEqual(waiting.session_id, SESSION_ID)
        self.assertIsNotNone(waiting.next_attempt_at)

        resumed = FakeRunner(
            [
                (
                    [
                        {
                            "type": "test.structured_result",
                            "value": ready_result(),
                        },
                        {"type": "turn.completed"},
                    ],
                    CommandResult(0, ""),
                )
            ]
        )
        finished = self.supervisor(resumed).run_attempt()
        self.assertEqual(finished.status, "COMPLETED")
        self.assertIn("resume", resumed.commands[0])
        self.assertIn(SESSION_ID, resumed.commands[0])

    def test_turn_completed_without_structured_result_is_not_success(self) -> None:
        runner = FakeRunner(
            [
                (
                    [
                        {"type": "thread.started", "thread_id": SESSION_ID},
                        {"type": "turn.completed"},
                    ],
                    CommandResult(0, ""),
                )
            ]
        )
        state = self.supervisor(runner).run_attempt()
        self.assertEqual(state.status, "RETRYABLE_FAILURE")
        self.assertEqual(state.last_failure_class, "missing_structured_terminal_result")

    def test_progress_continuation_keeps_session_and_clears_transient_failures(self) -> None:
        runner = FakeRunner(
            [
                (
                    [{"type": "thread.started", "thread_id": SESSION_ID}],
                    CommandResult(1, "deterministic transient failure"),
                ),
                (
                    [
                        {
                            "type": "test.structured_result",
                            "value": continuation_result(),
                        },
                        {"type": "turn.completed"},
                    ],
                    CommandResult(0, ""),
                ),
            ]
        )
        notifications = FakeNotificationStore()
        supervisor = CodexSupervisor(
            self.config(),
            runner=runner,
            notification_store=cast(Any, notifications),
            sleep=lambda _delay: None,
            boundary=self.boundary,
        )
        failed = supervisor.run_attempt()
        self.assertEqual(failed.status, "RETRYABLE_FAILURE")
        self.assertEqual(failed.attempts, 1)
        notifications.events.clear()

        continued = supervisor.run_attempt()
        self.assertEqual(continued.status, "RUNNING")
        self.assertEqual(continued.session_id, SESSION_ID)
        self.assertEqual(continued.attempts, 0)
        self.assertEqual(continued.repeated_failure_count, 0)
        self.assertIsNone(continued.last_failure_digest)
        self.assertIsNone(continued.last_failure_class)
        self.assertEqual(continued.repeated_continuation_count, 1)
        self.assertEqual(notifications.events, [])

    def test_progress_continuation_resumes_automatically_on_same_session(self) -> None:
        runner = FakeRunner(
            [
                (
                    [
                        {"type": "thread.started", "thread_id": SESSION_ID},
                        {
                            "type": "test.structured_result",
                            "value": continuation_result(),
                        },
                        {"type": "turn.completed"},
                    ],
                    CommandResult(0, ""),
                ),
                (
                    [
                        {"type": "test.structured_result", "value": ready_result()},
                        {"type": "turn.completed"},
                    ],
                    CommandResult(0, ""),
                ),
            ]
        )
        supervisor = self.supervisor(runner)
        self.assertEqual(supervisor.run_until_stable(), 0)
        completed = supervisor.load_state()
        self.assertEqual(completed.status, "COMPLETED")
        self.assertEqual(completed.session_id, SESSION_ID)
        self.assertEqual(len(runner.commands), 2)
        self.assertIn("resume", runner.commands[1])
        self.assertIn(SESSION_ID, runner.commands[1])

    def test_identical_no_progress_continuations_stop_at_loop_threshold(self) -> None:
        repeated = continuation_result()
        runner = FakeRunner(
            [
                (
                    [
                        {"type": "thread.started", "thread_id": SESSION_ID},
                        {"type": "test.structured_result", "value": repeated},
                    ],
                    CommandResult(0, ""),
                ),
                (
                    [{"type": "test.structured_result", "value": repeated}],
                    CommandResult(0, ""),
                ),
                (
                    [{"type": "test.structured_result", "value": repeated}],
                    CommandResult(0, ""),
                ),
            ]
        )
        supervisor = self.supervisor(runner, max_retries=10, loop_threshold=3)
        self.assertEqual(supervisor.run_attempt().status, "RUNNING")
        self.assertEqual(supervisor.run_attempt().status, "RUNNING")
        blocked = supervisor.run_attempt()
        self.assertEqual(blocked.status, "TERMINAL_BLOCKED")
        self.assertEqual(blocked.repeated_continuation_count, 3)
        self.assertEqual(blocked.attempts, 0)
        self.assertEqual(
            blocked.last_failure_class, "repeated_no_progress_continuation"
        )

    def test_transient_failure_does_not_erase_no_progress_continuation_history(self) -> None:
        repeated = continuation_result()
        runner = FakeRunner(
            [
                (
                    [
                        {"type": "thread.started", "thread_id": SESSION_ID},
                        {"type": "test.structured_result", "value": repeated},
                    ],
                    CommandResult(0, ""),
                ),
                ([], CommandResult(1, "transient execution failure")),
                (
                    [{"type": "test.structured_result", "value": repeated}],
                    CommandResult(0, ""),
                ),
                ([], CommandResult(1, "transient execution failure")),
                (
                    [{"type": "test.structured_result", "value": repeated}],
                    CommandResult(0, ""),
                ),
            ]
        )
        supervisor = self.supervisor(runner, max_retries=10, loop_threshold=3)
        self.assertEqual(supervisor.run_attempt().status, "RUNNING")
        self.assertEqual(supervisor.run_attempt().status, "RETRYABLE_FAILURE")
        self.assertEqual(supervisor.run_attempt().status, "RUNNING")
        self.assertEqual(supervisor.run_attempt().status, "RETRYABLE_FAILURE")
        blocked = supervisor.run_attempt()
        self.assertEqual(blocked.status, "TERMINAL_BLOCKED")
        self.assertEqual(blocked.repeated_continuation_count, 3)

    def test_malformed_continuation_remains_fail_closed(self) -> None:
        malformed = continuation_result()
        malformed["independent_work_completed"] = []
        runner = FakeRunner(
            [
                (
                    [
                        {"type": "thread.started", "thread_id": SESSION_ID},
                        {"type": "test.structured_result", "value": malformed},
                    ],
                    CommandResult(0, ""),
                )
            ]
        )
        state = self.supervisor(runner).run_attempt()
        self.assertEqual(state.status, "RETRYABLE_FAILURE")
        self.assertEqual(state.last_failure_class, "missing_structured_terminal_result")

    def test_typed_owner_action_is_the_only_external_stop(self) -> None:
        runner = FakeRunner(
            [
                (
                    [
                        {"type": "thread.started", "thread_id": SESSION_ID},
                        {
                            "type": "test.structured_result",
                            "value": owner_action_result(),
                        },
                        {"type": "turn.completed"},
                    ],
                    CommandResult(0, ""),
                )
            ]
        )
        self.assertEqual(
            self.supervisor(runner).run_attempt().status, "WAITING_OWNER_ACTION"
        )

    def test_incomplete_owner_action_is_not_a_terminal_stop(self) -> None:
        malformed = owner_action_result()
        malformed["safe_instruction"] = None
        runner = FakeRunner(
            [
                (
                    [
                        {"type": "thread.started", "thread_id": SESSION_ID},
                        {"type": "test.structured_result", "value": malformed},
                        {"type": "turn.completed"},
                    ],
                    CommandResult(0, ""),
                )
            ]
        )
        state = self.supervisor(runner).run_attempt()
        self.assertEqual(state.status, "RETRYABLE_FAILURE")
        self.assertEqual(state.last_failure_class, "missing_structured_terminal_result")

    def test_incomplete_ready_result_is_not_success(self) -> None:
        malformed = ready_result()
        malformed["safety"] = None
        runner = FakeRunner(
            [
                (
                    [
                        {"type": "thread.started", "thread_id": SESSION_ID},
                        {"type": "test.structured_result", "value": malformed},
                        {"type": "turn.completed"},
                    ],
                    CommandResult(0, ""),
                )
            ]
        )
        state = self.supervisor(runner).run_attempt()
        self.assertEqual(state.status, "RETRYABLE_FAILURE")
        self.assertEqual(state.last_failure_class, "missing_structured_terminal_result")

    def test_terminal_schema_is_supported_root_object_with_all_fields_required(self) -> None:
        schema = json.loads(
            (PACKAGE_ROOT / "schemas" / "autonomous-factory-ready-result.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(schema["type"], "object")
        self.assertNotIn("oneOf", schema)
        self.assertNotIn("anyOf", schema)
        self.assertEqual(set(schema["required"]), set(schema["properties"]))
        self.assertEqual(
            set(schema["properties"]["status"]["enum"]),
            {
                "AUTONOMOUS_FACTORY_READY",
                "CONTINUE_AUTONOMOUSLY",
                "OWNER_ACTION_REQUIRED",
            },
        )
        for field in ("factory", "autonomy", "self_improvement", "safety"):
            nested = schema["properties"][field]
            self.assertEqual(set(nested["required"]), set(nested["properties"]))

    def test_work_in_progress_ready_claim_is_rejected(self) -> None:
        runner = FakeRunner(
            [
                (
                    [
                        {"type": "thread.started", "thread_id": SESSION_ID},
                        {
                            "type": "test.structured_result",
                            "value": ready_result("WORK_IN_PROGRESS: still running"),
                        },
                        {"type": "turn.completed"},
                    ],
                    CommandResult(0, ""),
                )
            ]
        )
        state = self.supervisor(runner).run_attempt()
        self.assertEqual(state.status, "RETRYABLE_FAILURE")
        self.assertEqual(state.last_failure_class, "missing_structured_terminal_result")

    def test_digest_bound_continuation_handoff_augments_same_session_prompt(self) -> None:
        crashing = FakeRunner(
            [([{"type": "thread.started", "thread_id": SESSION_ID}], RuntimeError("killed"))]
        )
        supervisor = self.supervisor(crashing)
        with self.assertRaises(RuntimeError):
            supervisor.run_attempt()
        state = supervisor.load_state()
        handoff = {
            "schema_version": "1.0",
            "goal_id": state.goal_id,
            "original_goal_digest": state.prompt_digest,
            "session_id": SESSION_ID,
            "active_obligation": "publish bounded canary",
            "instructions": ["Do not mutate the frozen omnibus branch."],
            "replay_guard": "CANARY-ONE",
            "handoff_digest": "",
        }
        unsigned = dict(handoff)
        unsigned.pop("handoff_digest")
        from factory.common import sha256_text, stable_json

        handoff["handoff_digest"] = sha256_text(stable_json(unsigned))
        self.goal_dir.joinpath("continuation-handoff.json").write_text(
            json.dumps(handoff), encoding="utf-8"
        )
        resumed = FakeRunner(
            [
                (
                    [
                        {
                            "type": "test.structured_result",
                            "value": ready_result(),
                        },
                        {"type": "turn.completed"},
                    ],
                    CommandResult(0, ""),
                )
            ]
        )
        self.supervisor(resumed).run_attempt()
        self.assertIn("publish bounded canary", resumed.prompts[0])
        self.assertIn("Do not mutate the frozen omnibus branch.", resumed.prompts[0])

    def test_generation_bundle_trusts_only_exact_resolved_workspace(self) -> None:
        supervisor = self.supervisor(FakeRunner([]))
        state = supervisor._initial_state()
        request = BrokerRequest(
            request_id="CODEX-GENERATION-CAPTURE-TEST",
            operation="repository.read",
            owner="brullik",
            repository="hermes-software-factory",
            payload={"query": "workspace_generation_for_head_sha"},
        )
        receipt = FakeGenerationBroker._receipt(request, ())
        real_run = subprocess.run
        observed: list[list[str]] = []

        def observe_run(
            argv: list[str], **kwargs: Any
        ) -> subprocess.CompletedProcess[Any]:
            observed.append(list(argv))
            return real_run(argv, **kwargs)

        with patch(
            "factory.codex_supervisor.subprocess.run", side_effect=observe_run
        ):
            manifest_path, _manifest = supervisor._capture_generation(
                state,
                head_sha=self.base_sha,
                branch="codex/test-supervisor",
                receipt=receipt,
                fields={"number": "202", "merge_sha": self.base_sha},
            )

        resolved = self.workspace.resolve(strict=True)
        bundle_path = manifest_path.parent / "committed-head.bundle"
        bundle_argv = [
            argv for argv in observed if "bundle" in argv and "create" in argv
        ]
        self.assertEqual(
            bundle_argv,
            [[
                "/usr/bin/git",
                "-c",
                f"safe.directory={resolved}",
                "-C",
                str(resolved),
                "bundle",
                "create",
                str(bundle_path),
                "codex/test-supervisor",
            ]],
        )
        self.assertNotIn("safe.directory=*", bundle_argv[0])

    def test_merged_head_rolls_same_session_to_new_workspace_generation(self) -> None:
        config = self.config()
        config_path = self.goal_dir / "supervisor.json"
        config_path.write_text(
            json.dumps(config.as_dict(), sort_keys=True), encoding="utf-8"
        )
        bootstrap = CodexSupervisor(
            config,
            runner=FakeRunner([]),
            boundary=self.boundary,
            config_path=config_path,
        )
        state = bootstrap._initial_state()
        state.session_id = SESSION_ID
        bootstrap._save_state(state)
        (self.workspace / "README.md").write_text(
            "trusted fixture\ncontinued work\n", encoding="utf-8"
        )
        notes = self.workspace / "notes" / "progress.txt"
        notes.parent.mkdir()
        notes.write_text("bounded follow-up\n", encoding="utf-8")
        broker = FakeGenerationBroker(self.workspace, self.boundary.allowed_remote)
        runner = FakeRunner(
            [
                (
                    [
                        {
                            "type": "test.structured_result",
                            "value": ready_result(),
                        },
                        {"type": "turn.completed"},
                    ],
                    CommandResult(0, ""),
                )
            ]
        )

        completed = CodexSupervisor(
            config,
            runner=runner,
            boundary=self.boundary,
            config_path=config_path,
            generation_broker=broker,
        ).run_attempt()

        self.assertEqual(completed.status, "COMPLETED")
        self.assertEqual(completed.session_id, SESSION_ID)
        self.assertEqual(completed.workspace_generation, 2)
        self.assertEqual(len(completed.generation_history), 1)
        self.assertEqual(completed.generation_history[0]["status"], "SUPERSEDED")
        self.assertEqual(completed.generation_history[0]["workspace"], str(self.workspace))
        new_workspace = Path(completed.workspace)
        self.assertNotEqual(new_workspace, self.workspace)
        self.assertTrue(self.workspace.is_dir())
        self.assertEqual(
            (new_workspace / "README.md").read_text(encoding="utf-8"),
            "trusted fixture\ncontinued work\n",
        )
        self.assertEqual(
            (new_workspace / "notes" / "progress.txt").read_text(encoding="utf-8"),
            "bounded follow-up\n",
        )
        self.assertEqual(runner.working_directories, [new_workspace])
        self.assertIn("resume", runner.commands[0])
        self.assertIn(SESSION_ID, runner.commands[0])
        self.assertIn("SUPERSEDED", runner.prompts[0])
        persisted = SupervisorConfig.load(config_path)
        self.assertEqual(persisted.workspace, new_workspace)
        self.assertEqual(persisted.trusted_base_sha, broker.merge_sha)
        evidence = Path(completed.generation_history[0]["evidence_ref"])
        manifest = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "SUPERSEDED")
        self.assertGreater(manifest["dirty_patch"]["size"], 0)
        self.assertEqual(manifest["untracked"][0]["path"], "notes/progress.txt")
        subprocess.run(
            ["/usr/bin/git", "bundle", "verify", str(evidence.parent / "committed-head.bundle")],
            check=True,
            capture_output=True,
        )

    def test_generation_closeout_rejects_secret_named_untracked_file(self) -> None:
        config = self.config()
        bootstrap = CodexSupervisor(
            config,
            runner=FakeRunner([]),
            boundary=self.boundary,
        )
        state = bootstrap._initial_state()
        state.session_id = SESSION_ID
        bootstrap._save_state(state)
        (self.workspace / ".env.production").write_text(
            "not-a-real-secret\n", encoding="utf-8"
        )
        broker = FakeGenerationBroker(self.workspace, self.boundary.allowed_remote)

        with self.assertRaisesRegex(
            SupervisorConfigurationError, "untracked path is unsafe"
        ):
            CodexSupervisor(
                config,
                runner=FakeRunner([]),
                boundary=self.boundary,
                generation_broker=broker,
            ).run_attempt()

        self.assertEqual(len(broker.requests), 1)

    def test_github_outage_has_bounded_retries_on_same_session(self) -> None:
        runner = FakeRunner(
            [
                (
                    [{"type": "thread.started", "thread_id": SESSION_ID}],
                    CommandResult(1, "GitHub broker temporarily unavailable"),
                ),
                ([], CommandResult(1, "GitHub broker temporarily unavailable")),
                ([], CommandResult(1, "GitHub broker temporarily unavailable")),
            ]
        )
        supervisor = self.supervisor(runner, max_retries=3, loop_threshold=4)
        self.assertEqual(supervisor.run_attempt().status, "RETRYABLE_FAILURE")
        self.assertEqual(supervisor.run_attempt().status, "RETRYABLE_FAILURE")
        blocked = supervisor.run_attempt()
        self.assertEqual(blocked.status, "TERMINAL_BLOCKED")
        self.assertEqual(blocked.last_failure_class, "github_outage")
        self.assertNotIn("resume", runner.commands[0])
        for command in runner.commands[1:]:
            self.assertIn("resume", command)
            self.assertIn(SESSION_ID, command)

    def test_repeated_failure_loop_is_stopped_before_retry_budget(self) -> None:
        runner = FakeRunner(
            [
                (
                    [{"type": "thread.started", "thread_id": SESSION_ID}],
                    CommandResult(1, "deterministic compiler failure"),
                ),
                ([], CommandResult(1, "deterministic compiler failure")),
                ([], CommandResult(1, "deterministic compiler failure")),
            ]
        )
        supervisor = self.supervisor(runner, max_retries=10, loop_threshold=3)
        supervisor.run_attempt()
        supervisor.run_attempt()
        blocked = supervisor.run_attempt()
        self.assertEqual(blocked.status, "TERMINAL_BLOCKED")
        self.assertEqual(blocked.repeated_failure_count, 3)

    def test_failure_before_thread_id_fails_closed_without_duplicate_task(self) -> None:
        runner = FakeRunner([([], CommandResult(1, "network unavailable"))])
        state = self.supervisor(runner).run_attempt()
        self.assertEqual(state.status, "TERMINAL_BLOCKED")
        self.assertEqual(state.last_failure_class, "missing_session_after_failure")

    def test_untrusted_remote_and_main_branch_are_rejected(self) -> None:
        self._git("remote", "set-url", "origin", "https://github.com/evil/fork.git")
        with self.assertRaisesRegex(SupervisorConfigurationError, "repository allowlist"):
            self.supervisor(FakeRunner([]))
        self._git("remote", "set-url", "origin", self.boundary.allowed_remote)
        self._git("branch", "-m", "main")
        with self.assertRaisesRegex(SupervisorConfigurationError, "trusted task branch"):
            self.supervisor(FakeRunner([]))

    def test_event_log_redacts_secret_like_output(self) -> None:
        token = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456"
        runner = FakeRunner(
            [
                (
                    [
                        {"type": "thread.started", "thread_id": SESSION_ID},
                        {"type": "item.completed", "text": token},
                        {"type": "turn.completed"},
                    ],
                    CommandResult(0, ""),
                )
            ]
        )
        supervisor = self.supervisor(runner)
        supervisor.run_attempt()
        log = supervisor.config.event_log_path.read_text(encoding="utf-8")
        self.assertNotIn(token, log)
        self.assertIn("[REDACTED:github_token]", log)


if __name__ == "__main__":
    unittest.main()
