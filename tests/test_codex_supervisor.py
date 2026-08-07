from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from factory.codex_supervisor import (
    CodexSupervisor,
    CommandResult,
    SupervisorBoundary,
    SupervisorConfig,
    SupervisorConfigurationError,
)

SESSION_ID = "019c3fd5-3d61-7d20-a668-a2855efa25b1"


class FakeRunner:
    def __init__(self, steps: list[tuple[list[dict[str, Any]], CommandResult | Exception]]) -> None:
        self.steps = list(steps)
        self.commands: list[list[str]] = []
        self.prompts: list[str] = []
        self.environments: list[dict[str, str]] = []

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
        events, outcome = self.steps.pop(0)
        for event in events:
            on_event(event)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class CodexSupervisorTests(unittest.TestCase):
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
        self.assertIn("--permission-profile", command)
        self.assertIn("codex-vps-workspace", command)
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
            [([{"type": "turn.completed"}], CommandResult(0, ""))]
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

        resumed = FakeRunner([([{"type": "turn.completed"}], CommandResult(0, ""))])
        finished = self.supervisor(resumed).run_attempt()
        self.assertEqual(finished.status, "COMPLETED")
        self.assertIn("resume", resumed.commands[0])
        self.assertIn(SESSION_ID, resumed.commands[0])

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
