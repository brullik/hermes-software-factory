"""Durable least-privilege supervisor for one non-interactive Codex goal."""

from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from .codex_owner_actions import CodexOwnerActionStore
from .common import redact_text, sha256_text, stable_json, utc_now

SUPERVISOR_STATES = frozenset(
    {
        "RUNNING",
        "WAITING_QUOTA",
        "WAITING_OWNER_ACTION",
        "RETRYABLE_FAILURE",
        "TERMINAL_BLOCKED",
        "COMPLETED",
    }
)
_TERMINAL_STATES = frozenset({"TERMINAL_BLOCKED", "COMPLETED"})
_GOAL_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_TASK_BRANCH = re.compile(r"codex/[a-z0-9][a-z0-9._/-]{0,118}[a-z0-9]\Z")
_SHA = re.compile(r"[a-f0-9]{40}\Z")
_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{7,127}\Z")
_ALLOWED_REMOTE = "https://github.com/brullik/hermes-software-factory.git"
_RESUME_PROMPT = (
    "Продолжи ровно эту сохранённую задачу с последней безопасной контрольной точки. "
    "Не создавай новый thread, не используй fork/внешний checkout и не ослабляй gates."
)


class SupervisorConfigurationError(ValueError):
    """Raised when the configured workspace is outside the trusted boundary."""


class SupervisorAlreadyRunning(RuntimeError):
    """Raised when flock proves another process owns the same goal."""


@dataclass(frozen=True)
class SupervisorConfig:
    goal_id: str
    workspace: Path
    state_path: Path
    event_log_path: Path
    result_path: Path
    goal_path: Path
    output_schema_path: Path
    codex_binary: Path
    owner_action_db: Path
    trusted_base_sha: str
    permission_profile: str = "codex-vps-workspace"
    max_retries: int = 4
    base_backoff_seconds: float = 2.0
    max_backoff_seconds: float = 60.0
    quota_retry_seconds: float = 300.0
    loop_threshold: int = 3

    @classmethod
    def load(cls, path: Path) -> SupervisorConfig:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise SupervisorConfigurationError("supervisor config must be a JSON object")
        required = {
            "codex_binary",
            "event_log_path",
            "goal_id",
            "goal_path",
            "output_schema_path",
            "owner_action_db",
            "state_path",
            "result_path",
            "trusted_base_sha",
            "workspace",
        }
        missing = required - raw.keys()
        if missing:
            raise SupervisorConfigurationError(f"missing supervisor config keys: {sorted(missing)}")
        return cls(
            goal_id=str(raw["goal_id"]),
            workspace=Path(str(raw["workspace"])),
            state_path=Path(str(raw["state_path"])),
            event_log_path=Path(str(raw["event_log_path"])),
            result_path=Path(str(raw["result_path"])),
            goal_path=Path(str(raw["goal_path"])),
            output_schema_path=Path(str(raw["output_schema_path"])),
            codex_binary=Path(str(raw["codex_binary"])),
            owner_action_db=Path(str(raw["owner_action_db"])),
            trusted_base_sha=str(raw["trusted_base_sha"]),
            permission_profile=str(raw.get("permission_profile", "codex-vps-workspace")),
            max_retries=int(raw.get("max_retries", 4)),
            base_backoff_seconds=float(raw.get("base_backoff_seconds", 2.0)),
            max_backoff_seconds=float(raw.get("max_backoff_seconds", 60.0)),
            quota_retry_seconds=float(raw.get("quota_retry_seconds", 300.0)),
            loop_threshold=int(raw.get("loop_threshold", 3)),
        )


@dataclass(frozen=True)
class SupervisorBoundary:
    worktree_root: Path = Path("/var/lib/hermes-codex/worktrees")
    state_root: Path = Path("/var/lib/hermes-codex/state")
    codex_binary: Path = Path("/home/hermescodex/.local/bin/codex")
    owner_action_db: Path = Path("/var/lib/hermes-codex-owner-actions/actions.sqlite3")
    allowed_remote: str = _ALLOWED_REMOTE


@dataclass
class SupervisorState:
    schema_version: str
    goal_id: str
    workspace: str
    branch: str
    trusted_base_sha: str
    prompt_digest: str
    status: str
    session_id: str | None
    attempts: int
    resume_count: int
    transition_sequence: int
    repeated_failure_count: int
    last_failure_digest: str | None
    last_failure_class: str | None
    last_event_type: str | None
    next_attempt_at: str | None
    started_at: str
    updated_at: str
    completed_at: str | None


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    diagnostics: str


class CommandRunner(Protocol):
    def run(
        self,
        command: list[str],
        *,
        cwd: Path,
        prompt: str,
        environment: dict[str, str],
        on_event: Callable[[dict[str, Any]], None],
    ) -> CommandResult: ...


class SubprocessCommandRunner:
    """Run Codex without a shell and stream JSON events to durable state."""

    def run(
        self,
        command: list[str],
        *,
        cwd: Path,
        prompt: str,
        environment: dict[str, str],
        on_event: Callable[[dict[str, Any]], None],
    ) -> CommandResult:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=False,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        process.stdin.write(prompt)
        process.stdin.close()
        diagnostics: list[str] = []
        diagnostic_size = 0
        for line in process.stdout:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                event: Any = json.loads(stripped)
            except json.JSONDecodeError:
                if diagnostic_size < 65_536:
                    redacted, _ = redact_text(stripped)
                    diagnostics.append(redacted[:4096])
                    diagnostic_size += len(redacted)
                continue
            if isinstance(event, dict):
                on_event(event)
                event_type = event.get("type")
                if isinstance(event_type, str) and (
                    "error" in event_type or "failed" in event_type
                ):
                    redacted, _ = redact_text(stable_json(event))
                    diagnostics.append(redacted[:4096])
        return CommandResult(process.wait(), "\n".join(diagnostics))


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


class CodexSupervisor:
    def __init__(
        self,
        config: SupervisorConfig,
        *,
        runner: CommandRunner | None = None,
        notification_store: CodexOwnerActionStore | None = None,
        sleep: Callable[[float], None] = time.sleep,
        boundary: SupervisorBoundary | None = None,
    ) -> None:
        self.config = config
        self.runner = runner or SubprocessCommandRunner()
        self.notification_store = notification_store
        self.sleep = sleep
        self.boundary = boundary or SupervisorBoundary()
        self._validate_static_config()

    def _validate_static_config(self) -> None:
        config = self.config
        if _GOAL_ID.fullmatch(config.goal_id) is None:
            raise SupervisorConfigurationError("invalid goal id")
        if _SHA.fullmatch(config.trusted_base_sha) is None:
            raise SupervisorConfigurationError("invalid trusted base SHA")
        if config.permission_profile != "codex-vps-workspace":
            raise SupervisorConfigurationError("unexpected permission profile")
        if not 1 <= config.max_retries <= 10 or not 2 <= config.loop_threshold <= 10:
            raise SupervisorConfigurationError("retry or loop bounds are invalid")
        if not 0 <= config.base_backoff_seconds <= config.max_backoff_seconds <= 900:
            raise SupervisorConfigurationError("backoff bounds are invalid")
        if not 1 <= config.quota_retry_seconds <= 86_400:
            raise SupervisorConfigurationError("quota retry bound is invalid")
        workspace = config.workspace.resolve(strict=True)
        if not _is_within(workspace, self.boundary.worktree_root.resolve(strict=True)):
            raise SupervisorConfigurationError("workspace is outside the Codex worktree root")
        for path in (
            config.state_path,
            config.event_log_path,
            config.result_path,
            config.goal_path,
        ):
            if not path.is_absolute() or not _is_within(
                path.resolve(strict=False), self.boundary.state_root.resolve(strict=True)
            ):
                raise SupervisorConfigurationError("state artifact is outside the Codex state root")
        if config.codex_binary != self.boundary.codex_binary:
            raise SupervisorConfigurationError("unexpected Codex executable")
        if not config.codex_binary.is_file():
            raise SupervisorConfigurationError("Codex executable is missing")
        if config.owner_action_db != self.boundary.owner_action_db:
            raise SupervisorConfigurationError("unexpected owner-action database")
        if not config.goal_path.is_file() or not config.output_schema_path.is_file():
            raise SupervisorConfigurationError("goal or output schema is missing")
        self._validate_git_workspace(workspace)

    def _git(self, *arguments: str) -> str:
        result = subprocess.run(
            ["/usr/bin/git", "-C", str(self.config.workspace), *arguments],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"},
        )
        if result.returncode != 0:
            raise SupervisorConfigurationError(f"trusted Git probe failed: {arguments[0]}")
        return result.stdout.strip()

    def _validate_git_workspace(self, workspace: Path) -> None:
        if Path(self._git("rev-parse", "--show-toplevel")).resolve() != workspace:
            raise SupervisorConfigurationError("Git top-level differs from configured worktree")
        remotes = self._git("remote").splitlines()
        if remotes != ["origin"]:
            raise SupervisorConfigurationError("worktree must have only the exact origin remote")
        if self._git("remote", "get-url", "origin") != self.boundary.allowed_remote:
            raise SupervisorConfigurationError("origin is outside the exact repository allowlist")
        branch = self._git("branch", "--show-current")
        if _TASK_BRANCH.fullmatch(branch) is None or branch == "main":
            raise SupervisorConfigurationError("worktree is not on a trusted task branch")
        self._git("cat-file", "-e", f"{self.config.trusted_base_sha}^{{commit}}")
        self._git("merge-base", "--is-ancestor", self.config.trusted_base_sha, "HEAD")

    def _goal(self) -> str:
        value = self.config.goal_path.read_text(encoding="utf-8")
        if not 1 <= len(value) <= 120_000:
            raise SupervisorConfigurationError("goal text size is outside bounds")
        return value

    def _branch(self) -> str:
        return self._git("branch", "--show-current")

    def _initial_state(self) -> SupervisorState:
        timestamp = utc_now()
        return SupervisorState(
            schema_version="1.0",
            goal_id=self.config.goal_id,
            workspace=str(self.config.workspace),
            branch=self._branch(),
            trusted_base_sha=self.config.trusted_base_sha,
            prompt_digest=sha256_text(self._goal()),
            status="RUNNING",
            session_id=None,
            attempts=0,
            resume_count=0,
            transition_sequence=0,
            repeated_failure_count=0,
            last_failure_digest=None,
            last_failure_class=None,
            last_event_type=None,
            next_attempt_at=None,
            started_at=timestamp,
            updated_at=timestamp,
            completed_at=None,
        )

    def load_state(self) -> SupervisorState:
        if not self.config.state_path.is_file():
            state = self._initial_state()
            self._save_state(state)
            return state
        raw = json.loads(self.config.state_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise SupervisorConfigurationError("supervisor state must be an object")
        state = SupervisorState(**raw)
        if state.status not in SUPERVISOR_STATES:
            raise SupervisorConfigurationError("unknown supervisor state")
        if state.goal_id != self.config.goal_id or state.workspace != str(self.config.workspace):
            raise SupervisorConfigurationError("supervisor state identity mismatch")
        if state.prompt_digest != sha256_text(self._goal()):
            raise SupervisorConfigurationError("immutable goal text changed")
        if state.session_id is not None and _SESSION_ID.fullmatch(state.session_id) is None:
            raise SupervisorConfigurationError("invalid durable session id")
        return state

    def _save_state(self, state: SupervisorState) -> None:
        state.updated_at = utc_now()
        _write_private(
            self.config.state_path,
            json.dumps(asdict(state), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )

    def _append_event(self, event: dict[str, Any]) -> None:
        self.config.event_log_path.parent.mkdir(parents=True, exist_ok=True)
        redacted, _ = redact_text(stable_json(event))
        descriptor = os.open(
            self.config.event_log_path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        with os.fdopen(descriptor, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(redacted + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(self.config.event_log_path, 0o600)

    def _on_event(self, state: SupervisorState, event: dict[str, Any]) -> None:
        self._append_event(event)
        event_type = event.get("type")
        if isinstance(event_type, str):
            state.last_event_type = event_type
        if event_type == "thread.started":
            session_id = event.get("thread_id")
            if not isinstance(session_id, str) or _SESSION_ID.fullmatch(session_id) is None:
                raise SupervisorConfigurationError("thread.started has invalid thread id")
            if state.session_id is not None and state.session_id != session_id:
                raise SupervisorConfigurationError("Codex attempted to replace the durable thread")
            state.session_id = session_id
        self._save_state(state)

    def _continuation_prompt(self, state: SupervisorState) -> str:
        path = self.config.goal_path.with_name("continuation-handoff.json")
        if not path.exists():
            return _RESUME_PROMPT
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 32_768:
            raise SupervisorConfigurationError("continuation handoff path is unsafe")
        try:
            value: Any = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as error:
            raise SupervisorConfigurationError("continuation handoff is unreadable") from error
        required = {
            "schema_version",
            "goal_id",
            "original_goal_digest",
            "session_id",
            "active_obligation",
            "instructions",
            "replay_guard",
            "handoff_digest",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise SupervisorConfigurationError("continuation handoff schema differs")
        unsigned = dict(value)
        supplied_digest = str(unsigned.pop("handoff_digest"))
        if supplied_digest != sha256_text(stable_json(unsigned)):
            raise SupervisorConfigurationError("continuation handoff digest differs")
        if (
            value["schema_version"] != "1.0"
            or value["goal_id"] != state.goal_id
            or value["original_goal_digest"] != state.prompt_digest
            or value["session_id"] != state.session_id
        ):
            raise SupervisorConfigurationError("continuation handoff identity differs")
        obligation = value["active_obligation"]
        replay_guard = value["replay_guard"]
        instructions = value["instructions"]
        if (
            not isinstance(obligation, str)
            or not obligation
            or not isinstance(replay_guard, str)
            or not replay_guard
            or not isinstance(instructions, list)
            or not 1 <= len(instructions) <= 20
            or not all(
                isinstance(instruction, str) and 1 <= len(instruction) <= 2_000
                for instruction in instructions
            )
        ):
            raise SupervisorConfigurationError("continuation handoff content is invalid")
        rendered = "\n".join(f"- {instruction}" for instruction in instructions)
        return (
            _RESUME_PROMPT
            + "\n\nDurable recovery handoff "
            + supplied_digest
            + f" (replay guard {replay_guard}). Active obligation: {obligation}.\n"
            + rendered
        )

    def _command(self, state: SupervisorState) -> tuple[list[str], str]:
        base = [
            str(self.config.codex_binary),
            "--strict-config",
            "exec",
        ]
        common = [
            "--json",
            "--output-schema",
            str(self.config.output_schema_path),
            "--output-last-message",
            str(self.config.result_path),
        ]
        if state.session_id is None:
            command = [*base, *common, "--cd", str(self.config.workspace), "-"]
            prompt = (
                self._goal()
                + "\n\nRuntime constraints: use only this worktree; never fork or check out an "
                "external repository; never read credentials; use only the typed GitHub broker "
                "wrapper; preserve gates; return the configured structured final result."
            )
            return command, prompt
        command = [*base, "resume", *common, state.session_id, "-"]
        return command, self._continuation_prompt(state)

    @staticmethod
    def _environment() -> dict[str, str]:
        return {
            "CODEX_HOME": "/home/hermescodex/.codex",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": "/home/hermescodex",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/home/hermescodex/.local/bin:/usr/local/bin:/usr/bin:/bin",
        }

    def _structured_result(self) -> str | None:
        if not self.config.result_path.is_file():
            return None
        os.chmod(self.config.result_path, 0o600)
        try:
            value: Any = json.loads(self.config.result_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        if not isinstance(value, dict):
            return None
        status = value.get("status")
        if status == "OWNER_ACTION_REQUIRED":
            return "WAITING_OWNER_ACTION"
        if status != "AUTONOMOUS_FACTORY_READY":
            return None
        factory = value.get("factory")
        manifest = factory.get("ready_result_manifest") if isinstance(factory, dict) else None
        if (
            not isinstance(manifest, str)
            or not manifest
            or manifest == "<immutable reference>"
            or manifest.startswith("WORK_IN_PROGRESS")
        ):
            return None
        return "COMPLETED"

    @staticmethod
    def _failure_class(diagnostics: str, returncode: int) -> str:
        lowered = diagnostics.lower()
        if any(marker in lowered for marker in ("usage limit", "quota", "rate limit exceeded")):
            return "quota"
        if any(
            marker in lowered
            for marker in ("not logged in", "authentication required", "oauth", "unauthorized")
        ):
            return "owner_action"
        if any(
            marker in lowered
            for marker in ("github", "broker", "connection refused", "temporarily unavailable")
        ):
            return "github_outage"
        return f"codex_exit_{returncode}"

    def _transition(self, state: SupervisorState, status: str, failure_class: str | None) -> None:
        if status not in SUPERVISOR_STATES:
            raise ValueError("invalid supervisor transition")
        if state.status != status:
            state.transition_sequence += 1
        state.status = status
        state.last_failure_class = failure_class
        if status == "COMPLETED":
            state.completed_at = utc_now()
            state.next_attempt_at = None
        self._save_state(state)
        if self.notification_store is not None and status in {
            "WAITING_QUOTA",
            "WAITING_OWNER_ACTION",
            "RETRYABLE_FAILURE",
            "TERMINAL_BLOCKED",
            "COMPLETED",
        }:
            self.notification_store.enqueue_notification(
                event_key=(
                    f"{state.goal_id}:transition:{state.transition_sequence}:{status.lower()}"
                ),
                kind=status,
                text=f"Codex VPS goal {state.goal_id}: {status}.",
            )

    def run_attempt(self) -> SupervisorState:
        state = self.load_state()
        if state.status in _TERMINAL_STATES:
            return state
        was_resume = state.session_id is not None
        state.status = "RUNNING"
        state.next_attempt_at = None
        if was_resume:
            state.resume_count += 1
        self._save_state(state)
        command, prompt = self._command(state)
        self.config.result_path.unlink(missing_ok=True)
        result = self.runner.run(
            command,
            cwd=self.config.workspace,
            prompt=prompt,
            environment=self._environment(),
            on_event=lambda event: self._on_event(state, event),
        )
        structured_status = self._structured_result()
        if result.returncode == 0 and structured_status is not None:
            self._transition(state, structured_status, None)
            return state

        failure_class = (
            "missing_structured_terminal_result"
            if result.returncode == 0
            else self._failure_class(result.diagnostics, result.returncode)
        )
        failure_digest = sha256_text(
            stable_json(
                {
                    "class": failure_class,
                    "diagnostics": result.diagnostics[-8192:],
                    "returncode": result.returncode,
                }
            )
        )
        state.attempts += 1
        if state.last_failure_digest == failure_digest:
            state.repeated_failure_count += 1
        else:
            state.repeated_failure_count = 1
        state.last_failure_digest = failure_digest
        if state.session_id is None:
            self._transition(state, "TERMINAL_BLOCKED", "missing_session_after_failure")
        elif failure_class == "quota":
            retry_at = datetime.now(UTC) + timedelta(seconds=self.config.quota_retry_seconds)
            state.next_attempt_at = retry_at.replace(microsecond=0).isoformat().replace("+00:00", "Z")
            self._transition(state, "WAITING_QUOTA", failure_class)
        elif failure_class == "owner_action":
            self._transition(state, "WAITING_OWNER_ACTION", failure_class)
        elif (
            state.attempts >= self.config.max_retries
            or state.repeated_failure_count >= self.config.loop_threshold
        ):
            self._transition(state, "TERMINAL_BLOCKED", failure_class)
        else:
            self._transition(state, "RETRYABLE_FAILURE", failure_class)
        return state

    def _wait_for_quota_window(self, state: SupervisorState) -> None:
        if state.next_attempt_at is None:
            return
        retry_at = datetime.fromisoformat(state.next_attempt_at)
        delay = max(0.0, (retry_at - datetime.now(UTC)).total_seconds())
        self.sleep(min(delay, self.config.quota_retry_seconds))

    def run_until_stable(self) -> int:
        lock_path = self.config.state_path.with_suffix(".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise SupervisorAlreadyRunning("another supervisor owns this goal") from error
            while True:
                current = self.load_state()
                if current.status in _TERMINAL_STATES:
                    return 0
                if current.status == "WAITING_QUOTA":
                    self._wait_for_quota_window(current)
                state = self.run_attempt()
                if state.status in _TERMINAL_STATES:
                    return 0
                if state.status == "WAITING_OWNER_ACTION":
                    return 75
                if state.status == "WAITING_QUOTA":
                    continue
                if state.status == "RETRYABLE_FAILURE":
                    exponent = max(0, state.attempts - 1)
                    self.sleep(
                        min(
                            self.config.base_backoff_seconds * (2**exponent),
                            self.config.max_backoff_seconds,
                        )
                    )
        finally:
            os.close(descriptor)
