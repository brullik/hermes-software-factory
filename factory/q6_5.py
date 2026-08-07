"""Real, operation-specific Q6.5 capability probes for one immutable Candidate."""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .common import sha256_file, sha256_text, stable_json
from .credential_broker import BrokerClient, BrokerReceipt, BrokerRequest, CredentialBrokerError
from .functional_readiness import CapabilityHandshakeReport, CapabilityStatus
from .providers import ModelSelection
from .worker import HermesRunResult


class Q65ProbeError(RuntimeError):
    """A real capability probe could not produce authoritative evidence."""


class Q65ExternalCapabilityError(Q65ProbeError):
    """A broker-authenticated Q6.5 operation needs an external permission."""

    def __init__(self, broker_operation: str, safe_reason_code: str) -> None:
        self.broker_operation = broker_operation
        self.operation = (
            "git.branch.push"
            if broker_operation == "branch.push"
            else f"github.{broker_operation}"
        )
        self.capability = self.operation
        self.safe_reason_code = safe_reason_code
        super().__init__(safe_reason_code)


class Q65ProviderCapabilityError(Q65ProbeError):
    """A real provider invocation needs Candidate-scoped external authentication."""

    def __init__(
        self,
        *,
        tier: str,
        alias: str,
        selection: ModelSelection,
        semantic_id: str,
    ) -> None:
        self.operation = f"provider.{tier}.invoke"
        self.capability = self.operation
        self.safe_reason_code = "missing_candidate_provider_credential"
        self.scope = {
            "alias": alias,
            "provider": selection.provider,
            "model": selection.model,
            "credential_provider": selection.cli_provider or selection.provider,
            "semantic_id": semantic_id,
            "stdout_contract": "json-only",
        }
        super().__init__(self.safe_reason_code)


@dataclass(frozen=True)
class ProbeIdentity:
    candidate_digest: str
    toolchain_digest: str
    credential_epoch_id: str | None


@dataclass(frozen=True)
class OperationEvidence:
    operation: str
    scope: Mapping[str, Any]
    receipts: tuple[str, ...]


class HermesProbeRunner(Protocol):
    def run(
        self,
        *,
        selection: ModelSelection,
        prompt: str,
        cwd: Path,
        usage_path: Path | None = None,
    ) -> HermesRunResult: ...


def _request_id(epoch_id: str, operation: str, ordinal: int = 0) -> str:
    return "Q65-" + sha256_text(stable_json([epoch_id, operation, ordinal]))[:40]


def _receipt_digest(receipt: BrokerReceipt) -> str:
    if not re.fullmatch(r"[a-f0-9]{64}", receipt.receipt_digest):
        raise Q65ProbeError("broker receipt digest is invalid")
    return receipt.receipt_digest


class GitHubOperationHandshake:
    """Exercise the complete canary repository lifecycle through the broker."""

    def __init__(
        self,
        *,
        broker: BrokerClient,
        identity: ProbeIdentity,
        epoch_id: str,
        owner: str,
        repository: str,
        workspace: Path,
        git_runner: Callable[[list[str], Path], subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        if not repository.startswith("hermes-canary-"):
            raise Q65ProbeError("Q6.5 repository is outside the dedicated namespace")
        self.broker = broker
        self.identity = identity
        self.epoch_id = epoch_id
        self.owner = owner
        self.repository = repository
        self.workspace = workspace.resolve()
        self.git_runner = git_runner or self._default_git_runner

    @staticmethod
    def _default_git_runner(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
        if not argv or argv[0] != "git":
            raise Q65ProbeError("local git runner command is invalid")
        trusted_workspace = cwd.resolve()
        return subprocess.run(
            ["git", "-c", f"safe.directory={trusted_workspace}", *argv[1:]],
            cwd=trusted_workspace,
            env={
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                "HOME": os.environ.get("HOME", "/var/lib/hermes-factory-candidate"),
                "GIT_TERMINAL_PROMPT": "0",
                "GCM_INTERACTIVE": "Never",
            },
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            check=False,
            timeout=300,
        )

    def _request(
        self, operation: str, payload: Mapping[str, Any], *, ordinal: int = 0
    ) -> BrokerReceipt:
        try:
            return self.broker.execute(
                BrokerRequest(
                    request_id=_request_id(self.epoch_id, operation, ordinal),
                    operation=operation,
                    owner=self.owner,
                    repository=self.repository,
                    payload=dict(payload),
                )
            )
        except CredentialBrokerError as error:
            reason_code = str(error)
            if reason_code == "candidate_github_operation_denied":
                raise Q65ExternalCapabilityError(operation, reason_code) from error
            raise

    def _git(self, *argv: str) -> str:
        result = self.git_runner(list(argv), self.workspace)
        if result.returncode != 0:
            raise Q65ProbeError(f"local git fixture failed:{argv[0]}")
        return result.stdout.strip()

    def _git_ref(self, ref: str) -> str | None:
        result = self.git_runner(["git", "rev-parse", "--verify", ref], self.workspace)
        value = result.stdout.strip()
        return value if result.returncode == 0 and re.fullmatch(r"[a-f0-9]{40}", value) else None

    def _fixture_phase(self, ref: str) -> str | None:
        result = self.git_runner(
            ["git", "show", f"{ref}:q6_5_fixture.json"], self.workspace
        )
        if result.returncode != 0:
            return None
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
        return str(value.get("phase") or "") if isinstance(value, dict) else None

    def _report(
        self,
        operation: str,
        receipts: Sequence[BrokerReceipt],
        *,
        scope: Mapping[str, Any] | None = None,
    ) -> CapabilityHandshakeReport:
        if any(
            receipt.operation != operation
            or receipt.target_slug != f"{self.owner}/{self.repository}"
            or receipt.credential_epoch_id != self.identity.credential_epoch_id
            for receipt in receipts
        ):
            raise Q65ProbeError("broker receipt identity differs from requested operation")
        return CapabilityHandshakeReport.create(
            candidate_digest=self.identity.candidate_digest,
            capability=f"github.{operation}" if operation != "branch.push" else "git.branch.push",
            operation=f"github.{operation}" if operation != "branch.push" else "git.branch.push",
            scope={
                "owner": self.owner,
                "repository": self.repository,
                "private": True,
                **dict(scope or {}),
            },
            status=CapabilityStatus.AVAILABLE,
            credential_epoch_id=self.identity.credential_epoch_id,
            toolchain_digest=self.identity.toolchain_digest,
            receipts=tuple(_receipt_digest(receipt) for receipt in receipts),
        )

    def run(self) -> tuple[CapabilityHandshakeReport, ...]:
        self.workspace.parent.mkdir(parents=True, exist_ok=True)
        identity = self._request("identity.read", {})
        created = self._request(
            "repository.create_private", {"visibility": "private"}
        )
        cloned = self._request(
            "repository.read", {"workspace": str(self.workspace)}
        )
        fixture = self.workspace / "q6_5_fixture.json"
        if self._fixture_phase("refs/heads/main") != "main":
            self._git("git", "checkout", "-B", "main")
            fixture.write_text(
                stable_json({"schema_version": "1.0", "status": "PASS", "phase": "main"})
                + "\n",
                encoding="utf-8",
                newline="\n",
            )
            self._git("git", "add", "--", fixture.name)
            self._git(
                "git",
                "-c",
                "user.name=Hermes Q6.5",
                "-c",
                "user.email=hermes-q6-5@localhost",
                "commit",
                "-m",
                "Initialize Q6.5 fixture",
            )
        else:
            self._git("git", "checkout", "main")
        push_main = self._request(
            "branch.push", {"workspace": str(self.workspace), "branch": "main"}, ordinal=0
        )
        if self._fixture_phase("refs/heads/q6-5-proof") != "branch":
            self._git("git", "checkout", "-B", "q6-5-proof", "main")
            fixture.write_text(
                stable_json({"schema_version": "1.0", "status": "PASS", "phase": "branch"})
                + "\n",
                encoding="utf-8",
                newline="\n",
            )
            self._git("git", "add", "--", fixture.name)
            self._git(
                "git",
                "-c",
                "user.name=Hermes Q6.5",
                "-c",
                "user.email=hermes-q6-5@localhost",
                "commit",
                "-m",
                "Prove broker branch push",
            )
        else:
            self._git("git", "checkout", "q6-5-proof")
        commit = self._git_ref("refs/heads/q6-5-proof") or ""
        if not re.fullmatch(r"[a-f0-9]{40}", commit):
            raise Q65ProbeError("Q6.5 fixture commit is invalid")
        push_branch = self._request(
            "branch.push",
            {"workspace": str(self.workspace), "branch": "q6-5-proof"},
            ordinal=1,
        )
        pull_request = self._request(
            "pull_request.create",
            {"head": "q6-5-proof", "base": "main", "title": "Hermes Q6.5 proof"},
        )
        number_values = [
            value.removeprefix("number:")
            for value in pull_request.object_ids
            if value.startswith("number:")
        ]
        if len(number_values) != 1 or not number_values[0].isdigit():
            raise Q65ProbeError("Q6.5 pull request receipt lacks its number")
        checks = self._request("checks.read", {"sha": commit})
        terminal = self._request(
            "pull_request.merge_or_close",
            {"number": int(number_values[0]), "action": "close"},
        )
        cleaned = self._request("repository.archive_or_delete", {"action": "delete"})

        # Exact negative policy calls must fail before any adapter subprocess.
        forbidden_requests = (
                BrokerRequest(
                    request_id=_request_id(self.epoch_id, "negative.outside", 0),
                    operation="repository.read",
                    owner=self.owner,
                    repository="outside-the-hermes-canary-namespace",
                    payload={},
                ),
                BrokerRequest(
                    request_id=_request_id(self.epoch_id, "negative.public", 1),
                    operation="repository.create_private",
                    owner=self.owner,
                    repository=f"{self.repository}-public",
                    payload={"visibility": "public"},
                ),
            )
        for forbidden in forbidden_requests:
            try:
                self.broker.execute(forbidden)
            except CredentialBrokerError:
                continue
            raise Q65ProbeError("GitHub broker negative policy proof failed")

        return (
            self._report("identity.read", (identity,), scope={"subject": identity.subject_identity}),
            self._report("repository.create_private", (created,)),
            self._report("repository.read", (cloned,)),
            self._report("branch.push", (push_main, push_branch)),
            self._report("pull_request.create", (pull_request,)),
            self._report("checks.read", (checks,), scope={"commit": commit}),
            self._report("pull_request.merge_or_close", (terminal,)),
            self._report("repository.archive_or_delete", (cleaned,)),
        )


class ProviderOperationHandshake:
    """Perform one schema-valid, side-effect-free invocation for every model tier."""

    ROUTES = (
        ("luna", "economy"),
        ("terra", "standard"),
        ("sol", "expert"),
    )

    def __init__(
        self,
        *,
        identity: ProbeIdentity,
        runner: HermesProbeRunner,
        selections: Mapping[str, ModelSelection],
        workspace: Path,
        evidence_root: Path,
    ) -> None:
        self.identity = identity
        self.runner = runner
        self.selections = selections
        self.workspace = workspace
        self.evidence_root = evidence_root

    def run(self) -> tuple[CapabilityHandshakeReport, ...]:
        reports: list[CapabilityHandshakeReport] = []
        semantic_id = sha256_text("q6.5-provider-no-side-effect-v1")
        for tier, alias in self.ROUTES:
            selection = self.selections[tier]
            prompt = (
                "Do not use tools and do not modify anything. Return exactly one JSON object: "
                f'{{"schema_version":"1.0","status":"PASS","tier":"{tier}",'
                f'"semantic_id":"{semantic_id}"}}'
            )
            usage_path = self.evidence_root / f"provider-{tier}-usage.json"
            result = self.runner.run(
                selection=selection,
                prompt=prompt,
                cwd=self.workspace,
                usage_path=usage_path,
            )
            if result.status != "PASS":
                if result.reason_code == "missing_credential":
                    raise Q65ProviderCapabilityError(
                        tier=tier,
                        alias=alias,
                        selection=selection,
                        semantic_id=semantic_id,
                    )
                raise Q65ProbeError(f"provider {tier} real invocation failed:{result.reason_code}")
            try:
                value = json.loads(result.output)
            except json.JSONDecodeError as error:
                raise Q65ProbeError(f"provider {tier} output parser failed") from error
            expected = {
                "schema_version": "1.0",
                "status": "PASS",
                "tier": tier,
                "semantic_id": semantic_id,
            }
            if value != expected:
                raise Q65ProbeError(f"provider {tier} output schema differs")
            receipts = [result.output_digest]
            if usage_path.is_file() and not usage_path.is_symlink():
                receipts.append(sha256_file(usage_path))
            reports.append(
                CapabilityHandshakeReport.create(
                    candidate_digest=self.identity.candidate_digest,
                    capability=f"provider.{tier}.invoke",
                    operation=f"provider.{tier}.invoke",
                    scope={
                        "alias": alias,
                        "provider": selection.provider,
                        "model": selection.model,
                        "semantic_id": semantic_id,
                        "stdout_contract": "json-only",
                    },
                    status=CapabilityStatus.AVAILABLE,
                    credential_epoch_id=None,
                    toolchain_digest=self.identity.toolchain_digest,
                    receipts=tuple(receipts),
                )
            )
        return tuple(reports)


def external_operation_report(
    *,
    identity: ProbeIdentity,
    operation: str,
    scope: Mapping[str, Any],
    receipt_paths: Sequence[Path],
) -> CapabilityHandshakeReport:
    """Bind a generic real adapter proof to exact immutable files."""

    if not receipt_paths or any(
        not path.is_file() or path.is_symlink() for path in receipt_paths
    ):
        raise Q65ProbeError(f"{operation} proof receipt is unavailable")
    return CapabilityHandshakeReport.create(
        candidate_digest=identity.candidate_digest,
        capability=operation,
        operation=operation,
        scope=dict(scope),
        status=CapabilityStatus.AVAILABLE,
        credential_epoch_id=None,
        toolchain_digest=identity.toolchain_digest,
        receipts=tuple(sha256_file(path) for path in receipt_paths),
    )
