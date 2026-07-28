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
    approval_mode: str
    owner_override_reason: str | None = None


class GitHubCommandError(RuntimeError):
    """Raised when an allowlisted gh operation fails."""


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, check=False, timeout=120)


class GitHubAdapter:
    def __init__(
        self,
        owner: str,
        repository: str,
        *,
        runner: Runner | None = None,
        single_owner_mode: bool = False,
    ) -> None:
        self.owner = owner
        self.repository = repository
        self._runner = runner or _default_runner
        self.single_owner_mode = single_owner_mode

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

    def pull_request_for_head_sha(self, expected_sha: str) -> str:
        """Return the unique open PR whose head is ``expected_sha``.

        A release executor must never trust a model-supplied PR number.  The
        immutable head SHA is the lookup key; ambiguity or a missing PR is a
        hard external block.
        """

        if len(expected_sha) != 40 or not all(char in "0123456789abcdef" for char in expected_sha.lower()):
            raise ValueError("expected_sha must be a 40-character commit SHA")
        self.require_authentication()
        result = self._run(
            [
                "gh",
                "pr",
                "list",
                "--repo",
                self.slug,
                "--state",
                "open",
                "--limit",
                "100",
                "--json",
                "number,headRefOid",
            ]
        )
        try:
            payload = json.loads(result.output)
        except json.JSONDecodeError as error:
            raise GitHubCommandError("GitHub PR list did not return JSON") from error
        if not isinstance(payload, list):
            raise GitHubCommandError("GitHub PR list returned an invalid object")
        matches = [
            str(item["number"])
            for item in payload
            if isinstance(item, dict) and str(item.get("headRefOid", "")) == expected_sha
        ]
        if len(matches) != 1:
            raise GitHubCommandError("expected exactly one open pull request for the candidate SHA")
        return matches[0]

    def merged_commit(self, pull_request: str) -> str:
        """Read the immutable merge commit after a successful merge."""

        self._safe(pull_request, "pull request")
        self.require_authentication()
        result = self._run(
            [
                "gh",
                "pr",
                "view",
                pull_request,
                "--repo",
                self.slug,
                "--json",
                "state,mergeCommit",
            ]
        )
        try:
            payload = json.loads(result.output)
        except json.JSONDecodeError as error:
            raise GitHubCommandError("GitHub PR view did not return JSON") from error
        if not isinstance(payload, dict) or payload.get("state") != "MERGED":
            raise GitHubCommandError("pull request is not merged")
        merge_commit = payload.get("mergeCommit")
        sha = merge_commit.get("oid") if isinstance(merge_commit, dict) else None
        if not isinstance(sha, str) or len(sha) != 40 or not all(char in "0123456789abcdef" for char in sha.lower()):
            raise GitHubCommandError("merged pull request lacks an immutable merge SHA")
        return sha

    def verify_pull_request(
        self,
        pull_request: str,
        *,
        expected_sha: str,
        required_checks: tuple[str, ...] = (),
        owner_override: bool = False,
        owner_override_reason: str | None = None,
    ) -> PullRequestGate:
        """Verify immutable review/CI state before a merge side effect.

        The owner override is deliberately explicit and does not masquerade as
        an independent approval. It is available only when the adapter is
        configured for single-owner operation and a non-secret audit reason is
        supplied.
        """

        self._safe(pull_request, "pull request")
        if len(expected_sha) != 40 or not all(char in "0123456789abcdef" for char in expected_sha.lower()):
            raise ValueError("expected_sha must be a 40-character commit SHA")
        if owner_override and not self.single_owner_mode:
            raise GitHubCommandError("owner override requires single-owner mode")
        if owner_override and not owner_override_reason:
            raise ValueError("owner_override_reason is required")
        if not owner_override and owner_override_reason is not None:
            raise ValueError("owner_override_reason requires owner_override=True")
        if owner_override_reason is not None:
            owner_override_reason = owner_override_reason.strip()
            if len(owner_override_reason) < 12:
                raise ValueError("owner_override_reason must contain at least 12 characters")
            if len(owner_override_reason) > 240:
                raise ValueError("owner_override_reason must not exceed 240 characters")
            self._safe(owner_override_reason, "owner override reason")
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
        approved = payload.get("reviewDecision") == "APPROVED"
        approval_mode = "independent"
        if not approved:
            if not owner_override:
                raise GitHubCommandError("independent approval is missing")
            approval_mode = "owner_override"
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
            approved=approved,
            merge_state=merge_state,
            checks=tuple(sorted(name for name in required_checks if name in check_states)),
            approval_mode=approval_mode,
            owner_override_reason=owner_override_reason if approval_mode == "owner_override" else None,
        )

    def merge_pull_request_checked(
        self,
        pull_request: str,
        *,
        expected_sha: str,
        required_checks: tuple[str, ...] = (),
        owner_override: bool = False,
        owner_override_reason: str | None = None,
    ) -> GitHubResult:
        """Squash merge only after the configured governance gate passes."""

        gate = self.verify_pull_request(
            pull_request,
            expected_sha=expected_sha,
            required_checks=required_checks,
            owner_override=owner_override,
            owner_override_reason=owner_override_reason,
        )
        args = ["gh", "pr", "merge", pull_request, "--repo", self.slug, "--squash", "--delete-branch"]
        if gate.approval_mode == "owner_override":
            args.append("--admin")
        result = self._run(args)
        if gate.approval_mode == "owner_override":
            return GitHubResult(
                result.status,
                "approval_mode=owner_override; "
                f"owner_override_reason={gate.owner_override_reason}; {result.output}",
            )
        return result

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
