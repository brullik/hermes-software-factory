"""Allowlisted GitHub CLI boundary with fail-closed authentication and secrets."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .common import SECRET_PATTERNS, redact_text
from .providers import ExternalBlocker


@dataclass(frozen=True)
class GitHubStatus:
    authenticated: bool
    owner: str
    repository: str


@dataclass(frozen=True)
class GitHubResult:
    status: str
    output: str


@dataclass(frozen=True)
class PullRequestGate:
    pull_request: str
    head_sha: str
    approved: bool
    merge_state: str
    checks: tuple[str, ...]


class GitHubCommandError(RuntimeError):
    """Raised when an allowlisted gh operation fails."""


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, check=False, timeout=120)


class GitHubAdapter:
    def __init__(self, owner: str, repository: str, *, runner: Runner | None = None) -> None:
        self.owner = owner
        self.repository = repository
        self._runner = runner or _default_runner

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repository}"

    @staticmethod
    def _safe(value: str, field: str) -> str:
        if any(pattern.search(value) for _, pattern in SECRET_PATTERNS):
            raise ValueError(f"secret-like content is not accepted in {field}")
        return value

    def _run(self, args: list[str]) -> GitHubResult:
        if not args or args[0] != "gh":
            raise ValueError("GitHub commands must start with gh")
        try:
            result = self._runner(args)
        except (OSError, subprocess.SubprocessError) as error:
            raise GitHubCommandError(f"GitHub CLI unavailable: {type(error).__name__}") from error
        output = redact_text((result.stdout + "\n" + result.stderr).strip())[0]
        if result.returncode != 0:
            raise GitHubCommandError(f"GitHub operation failed with exit code {result.returncode}")
        return GitHubResult("PASS", output[:4000])

    def status(self) -> GitHubStatus:
        authenticated = bool(os.environ.get("GH_TOKEN"))
        if not authenticated and shutil.which("gh"):
            try:
                self._run(["gh", "auth", "status", "--hostname", "github.com"])
                authenticated = True
            except GitHubCommandError:
                authenticated = False
        return GitHubStatus(authenticated, self.owner, self.repository)

    def require_authentication(self) -> GitHubStatus:
        status = self.status()
        if not status.authenticated:
            raise ExternalBlocker("GitHub credential is not connected")
        return status

    def repository_view(self) -> GitHubResult:
        self.require_authentication()
        return self._run(["gh", "repo", "view", self.slug, "--json", "name,visibility,defaultBranchRef"])

    def create_repository(self, *, visibility: str, description: str) -> GitHubResult:
        if visibility not in {"public", "private"}:
            raise ValueError("visibility must be public or private")
        self._safe(description, "description")
        self.require_authentication()
        return self._run(
            ["gh", "repo", "create", self.slug, f"--{visibility}", "--description", description]
        )

    def create_issue(self, *, title: str, body: str, labels: tuple[str, ...] = ()) -> GitHubResult:
        self._safe(title, "issue title")
        self._safe(body, "issue body")
        self.require_authentication()
        args = ["gh", "issue", "create", self.slug, "--title", title, "--body", body]
        for label in labels:
            self._safe(label, "issue label")
            args.extend(["--label", label])
        return self._run(args)

    def create_pull_request(
        self,
        *,
        head: str,
        base: str,
        title: str,
        body: str,
    ) -> GitHubResult:
        for value, field in ((head, "head"), (base, "base"), (title, "PR title"), (body, "PR body")):
            self._safe(value, field)
        self.require_authentication()
        return self._run(
            [
                "gh",
                "pr",
                "create",
                "--repo",
                self.slug,
                "--head",
                head,
                "--base",
                base,
                "--title",
                title,
                "--body",
                body,
            ]
        )

    def review_threads(self, pull_request: str) -> GitHubResult:
        self._safe(pull_request, "pull request")
        self.require_authentication()
        return self._run(["gh", "pr", "view", pull_request, "--repo", self.slug, "--json", "reviews,latestReviews"])

    def verify_pull_request(
        self,
        pull_request: str,
        *,
        expected_sha: str,
        required_checks: tuple[str, ...] = (),
    ) -> PullRequestGate:
        """Verify immutable review and CI state before a merge side effect."""

        self._safe(pull_request, "pull request")
        if len(expected_sha) != 40 or not all(char in "0123456789abcdef" for char in expected_sha.lower()):
            raise ValueError("expected_sha must be a 40-character commit SHA")
        self.require_authentication()
        view = self._run(
            [
                "gh",
                "pr",
                "view",
                pull_request,
                "--repo",
                self.slug,
                "--json",
                "headRefOid,state,reviewDecision,mergeStateStatus,statusCheckRollup",
            ]
        )
        try:
            payload = json.loads(view.output)
        except json.JSONDecodeError as error:
            raise GitHubCommandError("GitHub PR view did not return JSON") from error
        if not isinstance(payload, dict):
            raise GitHubCommandError("GitHub PR view returned an invalid object")
        head_sha = str(payload.get("headRefOid", ""))
        if head_sha != expected_sha:
            raise GitHubCommandError("reviewed SHA does not match expected SHA")
        if payload.get("state") != "OPEN":
            raise GitHubCommandError("pull request is not open")
        if payload.get("reviewDecision") != "APPROVED":
            raise GitHubCommandError("independent approval is missing")
        merge_state = str(payload.get("mergeStateStatus", ""))
        if merge_state != "CLEAN":
            raise GitHubCommandError("pull request is not cleanly mergeable")
        checks = payload.get("statusCheckRollup", [])
        if not isinstance(checks, list):
            raise GitHubCommandError("pull request check rollup is invalid")
        check_states = {
            str(item.get("name", item.get("context", ""))): str(item.get("state", item.get("conclusion", "")))
            for item in checks
            if isinstance(item, dict)
        }
        missing = [name for name in required_checks if check_states.get(name) not in {"SUCCESS", "SKIPPED", "NEUTRAL"}]
        if missing:
            raise GitHubCommandError("required checks are not passing: " + ", ".join(missing))
        return PullRequestGate(
            pull_request=str(pull_request),
            head_sha=head_sha,
            approved=True,
            merge_state=merge_state,
            checks=tuple(sorted(name for name in required_checks if name in check_states)),
        )

    def merge_pull_request_checked(
        self,
        pull_request: str,
        *,
        expected_sha: str,
        required_checks: tuple[str, ...] = (),
    ) -> GitHubResult:
        """Squash merge only after the independent governance gate passes."""

        self.verify_pull_request(
            pull_request,
            expected_sha=expected_sha,
            required_checks=required_checks,
        )
        return self._run(
            ["gh", "pr", "merge", pull_request, "--repo", self.slug, "--squash", "--delete-branch"]
        )

    def merge_pull_request(self, pull_request: str, *, expected_sha: str) -> GitHubResult:
        self._safe(pull_request, "pull request")
        if len(expected_sha) != 40 or any(char not in "0123456789abcdef" for char in expected_sha.lower()):
            raise ValueError("expected_sha must be a 40-character commit SHA")
        self.require_authentication()
        view = self._run(["gh", "pr", "view", pull_request, "--repo", self.slug, "--json", "headRefOid"])
        if expected_sha not in view.output:
            raise GitHubCommandError("reviewed SHA does not match expected SHA")
        return self._run(
            ["gh", "pr", "merge", pull_request, "--repo", self.slug, "--squash", "--delete-branch"]
        )

    def rulesets(self) -> GitHubResult:
        self.require_authentication()
        return self._run(["gh", "api", f"repos/{self.slug}/rulesets"])

    def create_release(self, *, tag: str, title: str, notes: str) -> GitHubResult:
        self._safe(tag, "release tag")
        self._safe(title, "release title")
        self._safe(notes, "release notes")
        self.require_authentication()
        return self._run(["gh", "release", "create", tag, "--repo", self.slug, "--title", title, "--notes", notes])


def command_result_as_dict(result: GitHubResult) -> dict[str, Any]:
    """Return a schema-friendly compact result without raw CLI stderr."""
    return {"status": result.status, "summary": result.output}
