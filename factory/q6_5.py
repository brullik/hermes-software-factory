"""Real, operation-specific Q6.5 capability probes for one immutable Candidate."""

from __future__ import annotations

import json
import os
import re
import stat
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

    WORKFLOW_PROOF = (
        "name: Hermes Q6.5 broker proof\n"
        "on:\n"
        "  push:\n"
        "    branches: [main, q6-5-proof]\n"
        "  pull_request:\n"
        "jobs:\n"
        "  proof:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: printf 'Q6.5 workflow write PASS\\n'\n"
    )

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
            if reason_code in {
                "candidate_github_operation_denied",
                "candidate_github_workflow_permission_denied",
            }:
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

    def _workflow_is_bound(self, ref: str) -> bool:
        result = self.git_runner(
            ["git", "show", f"{ref}:.github/workflows/q6-5-proof.yml"],
            self.workspace,
        )
        return result.returncode == 0 and result.stdout == self.WORKFLOW_PROOF

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
        configured = self._request(
            "repository.read", {"query": "configuration"}, ordinal=0
        )
        cloned = self._request(
            "repository.read", {"workspace": str(self.workspace)}, ordinal=1
        )
        fixture = self.workspace / "q6_5_fixture.json"
        workflow = self.workspace / ".github" / "workflows" / "q6-5-proof.yml"
        if (
            self._fixture_phase("refs/heads/main") != "main"
            or not self._workflow_is_bound("refs/heads/main")
        ):
            self._git("git", "checkout", "-B", "main")
            fixture.write_text(
                stable_json({"schema_version": "1.0", "status": "PASS", "phase": "main"})
                + "\n",
                encoding="utf-8",
                newline="\n",
            )
            workflow.parent.mkdir(parents=True, exist_ok=True)
            workflow.write_text(
                self.WORKFLOW_PROOF,
                encoding="utf-8",
                newline="\n",
            )
            self._git(
                "git",
                "add",
                "--",
                fixture.name,
                str(workflow.relative_to(self.workspace)),
            )
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
        cleaned = self._request("repository.archive_or_delete", {"action": "archive"})

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
            self._report(
                "repository.read",
                (configured, cloned),
                scope={"repository_configuration": "verified"},
            ),
            self._report(
                "branch.push",
                (push_main, push_branch),
                scope={"workflow_write": "verified"},
            ),
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
    MAX_STRUCTURED_ATTEMPTS = 2
    _RECEIPT_FIELDS = {
        "schema_version", "candidate_digest", "toolchain_digest",
        "credential_epoch_id", "tier", "alias", "provider", "model",
        "cli_provider", "semantic_id", "attempt", "status", "reason_code",
        "output_digest", "usage_digest", "receipt_digest",
    }
    _FAILURE_REASONS = {
        "provider_invocation_failed", "provider_output_digest_mismatch",
        "provider_structured_output_invalid_json",
        "provider_structured_output_contract_mismatch",
    }

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

    def _receipt_identity(
        self,
        *,
        tier: str,
        alias: str,
        selection: ModelSelection,
        semantic_id: str,
    ) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "candidate_digest": self.identity.candidate_digest,
            "toolchain_digest": self.identity.toolchain_digest,
            "credential_epoch_id": self.identity.credential_epoch_id,
            "tier": tier,
            "alias": alias,
            "provider": selection.provider,
            "model": selection.model,
            "cli_provider": selection.cli_provider or selection.provider,
            "semantic_id": semantic_id,
        }

    def _success_path(self, tier: str) -> Path:
        return self.evidence_root / f"provider-{tier}-success.json"

    def _failure_path(self, tier: str, attempt: int) -> Path:
        return self.evidence_root / f"provider-{tier}-attempt-{attempt}-failure.json"

    def _usage_path(self, tier: str, attempt: int) -> Path:
        return self.evidence_root / f"provider-{tier}-attempt-{attempt}-usage.json"

    @staticmethod
    def _immutable_file(path: Path, *, kind: str) -> os.stat_result:
        try:
            metadata = path.lstat()
        except OSError as error:
            raise Q65ProbeError(f"provider {kind} evidence is unavailable") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o222
            or not 1 <= metadata.st_size <= 1_048_576
        ):
            raise Q65ProbeError(f"provider {kind} evidence is not immutable")
        return metadata

    @classmethod
    def _read_receipt(cls, path: Path) -> dict[str, Any]:
        cls._immutable_file(path, kind="receipt")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise Q65ProbeError("provider receipt is malformed") from error
        if not isinstance(value, dict) or set(value) != cls._RECEIPT_FIELDS:
            raise Q65ProbeError("provider receipt fields differ")
        unsigned = dict(value)
        digest = str(unsigned.pop("receipt_digest", ""))
        if not re.fullmatch(r"[a-f0-9]{64}", digest) or digest != sha256_text(
            stable_json(unsigned)
        ):
            raise Q65ProbeError("provider receipt digest differs")
        return value

    @staticmethod
    def _write_receipt(path: Path, value: Mapping[str, Any]) -> Path:
        core = dict(value)
        encoded = (
            stable_json({**core, "receipt_digest": sha256_text(stable_json(core))}) + "\n"
        ).encode("utf-8")
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o400,
            )
        except FileExistsError as error:
            raise Q65ProbeError("provider receipt already exists") from error
        except OSError as error:
            raise Q65ProbeError("provider receipt cannot be created") from error
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as error:
            raise Q65ProbeError("provider receipt cannot be persisted") from error
        return path

    @classmethod
    def _usage_digest(cls, path: Path, *, freeze: bool = False) -> str | None:
        if not path.exists() and not path.is_symlink():
            return None
        if freeze:
            try:
                metadata = path.lstat()
                if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                    raise Q65ProbeError("provider usage evidence is invalid")
                os.chmod(path, 0o400)
            except OSError as error:
                raise Q65ProbeError("provider usage evidence is invalid") from error
        cls._immutable_file(path, kind="usage")
        return sha256_file(path)

    def _validate_receipt(
        self,
        path: Path,
        *,
        identity: Mapping[str, Any],
        expected_status: str,
        expected_attempt: int | None = None,
    ) -> dict[str, Any]:
        receipt = self._read_receipt(path)
        if any(receipt.get(key) != value for key, value in identity.items()):
            raise Q65ProbeError("provider receipt identity differs")
        attempt = receipt.get("attempt")
        if (
            not isinstance(attempt, int)
            or not 1 <= attempt <= self.MAX_STRUCTURED_ATTEMPTS
            or (expected_attempt is not None and attempt != expected_attempt)
            or receipt.get("status") != expected_status
            or re.fullmatch(r"[a-f0-9]{64}", str(receipt.get("output_digest") or ""))
            is None
        ):
            raise Q65ProbeError("provider receipt contract differs")
        reason = receipt.get("reason_code")
        if (expected_status == "PASS" and reason is not None) or (
            expected_status == "FAIL" and reason not in self._FAILURE_REASONS
        ):
            raise Q65ProbeError("provider receipt reason differs")
        usage_digest = receipt.get("usage_digest")
        usage_path = self._usage_path(str(identity["tier"]), attempt)
        if usage_digest is None:
            if usage_path.exists() or usage_path.is_symlink():
                raise Q65ProbeError("provider usage evidence is orphaned")
        elif (
            not isinstance(usage_digest, str)
            or re.fullmatch(r"[a-f0-9]{64}", usage_digest) is None
            or self._usage_digest(usage_path) != usage_digest
        ):
            raise Q65ProbeError("provider usage evidence differs")
        return receipt

    def _existing_success(
        self,
        *,
        identity: Mapping[str, Any],
    ) -> tuple[tuple[Path, dict[str, Any]] | None, int]:
        tier = str(identity["tier"])
        success_path = self._success_path(tier)
        expected_names = {success_path.name}
        for attempt in range(1, self.MAX_STRUCTURED_ATTEMPTS + 1):
            expected_names.update(
                (
                self._failure_path(tier, attempt).name,
                self._usage_path(tier, attempt).name,
                )
            )
        try:
            tier_evidence = tuple(self.evidence_root.glob(f"provider-{tier}-*"))
        except OSError as error:
            raise Q65ProbeError("provider evidence cannot be enumerated") from error
        if any(path.name not in expected_names for path in tier_evidence):
            raise Q65ProbeError("provider evidence is orphaned")
        failures: dict[int, dict[str, Any]] = {}
        for attempt in range(1, self.MAX_STRUCTURED_ATTEMPTS + 1):
            failure_path = self._failure_path(tier, attempt)
            if failure_path.exists() or failure_path.is_symlink():
                failures[attempt] = self._validate_receipt(
                    failure_path,
                    identity=identity,
                    expected_status="FAIL",
                    expected_attempt=attempt,
                )
        if success_path.exists() or success_path.is_symlink():
            success = self._validate_receipt(
                success_path, identity=identity, expected_status="PASS"
            )
            success_attempt = int(success["attempt"])
            if set(failures) != set(range(1, success_attempt)):
                raise Q65ProbeError("provider success evidence conflicts with attempts")
            return (success_path, success), len(failures)
        if failures and set(failures) != set(range(1, len(failures) + 1)):
            raise Q65ProbeError("provider failure evidence is orphaned")
        for attempt in range(1, self.MAX_STRUCTURED_ATTEMPTS + 1):
            usage_path = self._usage_path(tier, attempt)
            if (usage_path.exists() or usage_path.is_symlink()) and attempt not in failures:
                raise Q65ProbeError("provider usage evidence is orphaned")
        return None, len(failures)

    def _report_from_success(
        self,
        *,
        tier: str,
        alias: str,
        selection: ModelSelection,
        semantic_id: str,
        path: Path,
        receipt: Mapping[str, Any],
    ) -> CapabilityHandshakeReport:
        receipts = [sha256_file(path)]
        usage_digest = receipt.get("usage_digest")
        if isinstance(usage_digest, str):
            receipts.append(usage_digest)
        return CapabilityHandshakeReport.create(
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

    def run(self) -> tuple[CapabilityHandshakeReport, ...]:
        reports: list[CapabilityHandshakeReport] = []
        semantic_id = sha256_text("q6.5-provider-no-side-effect-v1")
        for tier, alias in self.ROUTES:
            selection = self.selections[tier]
            identity = self._receipt_identity(
                tier=tier,
                alias=alias,
                selection=selection,
                semantic_id=semantic_id,
            )
            existing, failures = self._existing_success(identity=identity)
            if existing is not None:
                path, receipt = existing
                reports.append(
                    self._report_from_success(
                        tier=tier,
                        alias=alias,
                        selection=selection,
                        semantic_id=semantic_id,
                        path=path,
                        receipt=receipt,
                    )
                )
                continue
            prompt = (
                "Do not use tools and do not modify anything. Return exactly one JSON object: "
                f'{{"schema_version":"1.0","status":"PASS","tier":"{tier}",'
                f'"semantic_id":"{semantic_id}"}}'
            )
            expected = {
                "schema_version": "1.0",
                "status": "PASS",
                "tier": tier,
                "semantic_id": semantic_id,
            }
            if failures >= self.MAX_STRUCTURED_ATTEMPTS:
                raise Q65ProbeError(f"provider {tier} structured output attempts exhausted")
            success: tuple[Path, dict[str, Any]] | None = None
            for attempt in range(failures + 1, self.MAX_STRUCTURED_ATTEMPTS + 1):
                usage_path = self._usage_path(tier, attempt)
                result = self.runner.run(
                    selection=selection,
                    prompt=prompt,
                    cwd=self.workspace,
                    usage_path=usage_path,
                )
                if result.status != "PASS" and result.reason_code == "missing_credential":
                    if usage_path.exists() or usage_path.is_symlink():
                        raise Q65ProbeError("provider usage evidence is orphaned")
                    raise Q65ProviderCapabilityError(
                        tier=tier,
                        alias=alias,
                        selection=selection,
                        semantic_id=semantic_id,
                    )
                output_digest = sha256_text(result.output)
                usage_digest = self._usage_digest(usage_path, freeze=True)
                reason: str | None = None
                if result.output_digest != output_digest:
                    reason = "provider_output_digest_mismatch"
                elif result.status != "PASS":
                    reason = "provider_invocation_failed"
                else:
                    try:
                        value = json.loads(result.output)
                    except json.JSONDecodeError:
                        reason = "provider_structured_output_invalid_json"
                    else:
                        if value != expected:
                            reason = "provider_structured_output_contract_mismatch"
                receipt_core = {
                    **identity,
                    "attempt": attempt,
                    "status": "FAIL" if reason is not None else "PASS",
                    "reason_code": reason,
                    "output_digest": output_digest,
                    "usage_digest": usage_digest,
                }
                if reason is not None:
                    self._write_receipt(self._failure_path(tier, attempt), receipt_core)
                    continue
                success_path = self._write_receipt(self._success_path(tier), receipt_core)
                success = (
                    success_path,
                    self._validate_receipt(
                        success_path,
                        identity=identity,
                        expected_status="PASS",
                        expected_attempt=attempt,
                    ),
                )
                break
            if success is None:
                raise Q65ProbeError(f"provider {tier} structured output attempts exhausted")
            success_path, success_receipt = success
            reports.append(
                self._report_from_success(
                    tier=tier,
                    alias=alias,
                    selection=selection,
                    semantic_id=semantic_id,
                    path=success_path,
                    receipt=success_receipt,
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
