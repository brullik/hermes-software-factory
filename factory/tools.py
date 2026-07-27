"""Shell-free tool/policy adapter for model-requested commands."""

from __future__ import annotations

import hashlib
import shlex
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from scripts.policy_guard import assert_under_root, command_allowed

from .common import redact_text


@dataclass(frozen=True)
class ToolResult:
    status: str
    exit_code: int | None
    summary: str
    output_digest: str
    reason: str | None = None


class ToolPolicyAdapter:
    def __init__(self, workspace_root: Path, allowlist_prefixes: Iterable[str]) -> None:
        self.workspace_root = workspace_root.resolve()
        self.allowlist_prefixes = tuple(allowlist_prefixes)

    def run(self, command: str, *, cwd: Path, timeout_seconds: int = 300, max_output_chars: int = 4000) -> ToolResult:
        allowed, reason = command_allowed(command, self.allowlist_prefixes)
        if not allowed:
            return ToolResult("DENIED", None, "command rejected by policy", hashlib.sha256(reason.encode()).hexdigest(), reason)
        try:
            safe_cwd = assert_under_root(self.workspace_root, cwd)
        except ValueError as error:
            return ToolResult("DENIED", None, "cwd rejected by policy", hashlib.sha256(str(error).encode()).hexdigest(), str(error))
        try:
            tokens = shlex.split(command, posix=True)
            if not tokens:
                return ToolResult("DENIED", None, "empty command", hashlib.sha256(b"empty").hexdigest(), "empty_command")
            completed = subprocess.run(
                tokens,
                cwd=safe_cwd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as error:
            output, _ = redact_text(str(error))
            return ToolResult("TIMEOUT", None, output[:max_output_chars], hashlib.sha256(output.encode()).hexdigest(), "timeout")
        except (OSError, ValueError) as error:
            message = str(error)
            return ToolResult("ERROR", None, message[:max_output_chars], hashlib.sha256(message.encode()).hexdigest(), "execution_error")
        output, _ = redact_text((completed.stdout + "\n" + completed.stderr).strip())
        output = output[:max_output_chars]
        status = "PASS" if completed.returncode == 0 else "FAIL"
        return ToolResult(status, completed.returncode, output, hashlib.sha256(output.encode()).hexdigest())
