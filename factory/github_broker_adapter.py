"""Release-side GitHub adapter backed only by typed broker operations."""

from __future__ import annotations

import re
from pathlib import Path

from .common import sha256_text, stable_json
from .credential_broker import BrokerClient, BrokerReceipt, BrokerRequest, CredentialBrokerError
from .github import GitHubCommandError, GitHubResult, PullRequestGate, RequiredChecksStatus


class BrokerGitHubAdapter:
    def __init__(
        self,
        owner: str,
        repository: str,
        *,
        socket_path: Path,
        single_owner_mode: bool,
    ) -> None:
        self.owner = owner
        self.repository = repository
        self.client = BrokerClient(socket_path)
        self.single_owner_mode = single_owner_mode
        self._read_counter = 0

    def _request(
        self,
        operation: str,
        payload: dict[str, object],
        *,
        read: bool = False,
    ) -> BrokerReceipt:
        self._read_counter += 1
        nonce: object = self._read_counter if read else payload
        request_id = "REL-" + sha256_text(
            stable_json([self.owner, self.repository, operation, payload, nonce])
        )[:40]
        try:
            return self.client.execute(
                BrokerRequest(
                    request_id=request_id,
                    operation=operation,
                    owner=self.owner,
                    repository=self.repository,
                    payload=payload,
                )
            )
        except CredentialBrokerError as error:
            raise GitHubCommandError(str(error)) from error

    @staticmethod
    def _value(receipt: BrokerReceipt, prefix: str) -> str | None:
        values = [item.removeprefix(prefix) for item in receipt.object_ids if item.startswith(prefix)]
        return values[0] if len(values) == 1 else None

    def create_pull_request(self, *, head: str, base: str, title: str, body: str) -> GitHubResult:
        del body
        receipt = self._request(
            "pull_request.create",
            {"head": head, "base": base, "title": title},
        )
        return GitHubResult("PASS", receipt.receipt_digest)

    def pull_request_for_head_sha(self, expected_sha: str) -> str:
        receipt = self._request(
            "repository.read",
            {"query": "pull_request_for_head_sha", "sha": expected_sha},
            read=True,
        )
        number = self._value(receipt, "number:")
        head = self._value(receipt, "head_sha:")
        if number is None or head != expected_sha or not number.isdigit():
            raise GitHubCommandError("broker PR lookup differs from expected SHA")
        return number

    def required_checks_status(
        self,
        pull_request: str,
        *,
        expected_sha: str,
        required_checks: tuple[str, ...],
    ) -> RequiredChecksStatus:
        receipt = self._request("checks.read", {"sha": expected_sha}, read=True)
        observed: dict[str, str] = {}
        for item in receipt.object_ids:
            if not item.startswith("check:"):
                continue
            body = item.removeprefix("check:")
            name, separator, state = body.rpartition(":")
            if separator and name:
                observed[name] = state.upper()
        success = {"SUCCESS", "SKIPPED", "NEUTRAL"}
        failure = {"FAILURE", "ERROR", "CANCELLED", "TIMED_OUT", "ACTION_REQUIRED"}
        passed = tuple(name for name in required_checks if observed.get(name) in success)
        failed = tuple(name for name in required_checks if observed.get(name) in failure)
        pending = tuple(name for name in required_checks if name not in set(passed) | set(failed))
        return RequiredChecksStatus(
            pull_request=str(pull_request),
            head_sha=expected_sha,
            states=tuple((name, observed.get(name, "MISSING")) for name in required_checks),
            passed=passed,
            pending=pending,
            failed=failed,
        )

    def close_pull_request(self, pull_request: str) -> GitHubResult:
        receipt = self._request(
            "pull_request.merge_or_close",
            {"number": int(pull_request), "action": "close"},
        )
        return GitHubResult("PASS", receipt.receipt_digest)

    def verify_pull_request(
        self,
        pull_request: str,
        *,
        expected_sha: str,
        required_checks: tuple[str, ...],
        owner_override: bool,
        owner_override_reason: str | None,
    ) -> PullRequestGate:
        if owner_override and (not self.single_owner_mode or not owner_override_reason):
            raise GitHubCommandError("broker owner override policy is incomplete")
        status = self.required_checks_status(
            pull_request,
            expected_sha=expected_sha,
            required_checks=required_checks,
        )
        if status.pending or status.failed:
            raise GitHubCommandError("broker required checks are not passing")
        return PullRequestGate(
            pull_request=pull_request,
            head_sha=expected_sha,
            approved=True,
            merge_state="CLEAN",
            checks=status.passed,
            approval_mode="owner_override" if owner_override else "independent",
            owner_override_reason=owner_override_reason,
        )

    def merge_pull_request_checked(
        self,
        pull_request: str,
        *,
        expected_sha: str,
        required_checks: tuple[str, ...],
        owner_override: bool,
        owner_override_reason: str | None,
    ) -> GitHubResult:
        self.verify_pull_request(
            pull_request,
            expected_sha=expected_sha,
            required_checks=required_checks,
            owner_override=owner_override,
            owner_override_reason=owner_override_reason,
        )
        receipt = self._request(
            "pull_request.merge_or_close",
            {"number": int(pull_request), "action": "merge"},
        )
        return GitHubResult("PASS", receipt.receipt_digest)

    def merged_commit(self, pull_request: str) -> str:
        receipt = self._request(
            "repository.read",
            {"query": "pull_request", "number": int(pull_request)},
            read=True,
        )
        state = self._value(receipt, "state:")
        merge_sha = self._value(receipt, "merge_sha:")
        merged = self._value(receipt, "merged:")
        if (
            state != "closed"
            or merged != "True"
            or merge_sha is None
            or not re.fullmatch(r"[a-f0-9]{40}", merge_sha)
        ):
            raise GitHubCommandError("broker pull request is not merge-bound")
        return merge_sha
