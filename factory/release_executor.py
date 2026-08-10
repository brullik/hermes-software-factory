"""Concrete, fail-closed release side-effect boundary.

The provider may propose a release operation, but this adapter derives the
staging digest locally, verifies that the candidate belongs to exactly one
open GitHub PR, and performs only the configured transactional operation.
Production additionally requires an accepted staging digest, offsite backup,
the configured GitHub governance path, and an explicit root-owned helper.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from scripts.verify_version_consistency import (
    VersionConsistencyError,
    verify_version_consistency,
)

from .common import sha256_text, stable_json
from .config import FactoryConfig
from .credential_broker import BrokerClient, BrokerRequest, CredentialBrokerError
from .deployment import DeploymentGuard, TransactionalDeployer, TransactionResult
from .github import GitHubAdapter, GitHubCommandError, RequiredChecksStatus
from .providers import ExternalBlocker
from .release import ReleaseExecutor

_SHA = re.compile(r"^[a-f0-9]{40}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_HTTPS_REMOTE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repository>[A-Za-z0-9_.-]+?)(?:\.git)?$"
)
_PROTECTED_CANDIDATE_ROOTS = {".git", "artifacts", "release-artifacts", "secrets", "production"}
_PROTECTED_CANDIDATE_PATHS = {".gitmodules"}


class ReleaseAdapterError(RuntimeError):
    """Raised when a release side effect cannot be completed safely."""


class CandidateChecksPending(ExternalBlocker):
    """Required checks did not finish within the bounded polling window."""

    def __init__(self, checks: tuple[str, ...]) -> None:
        super().__init__(
            "GitHub required checks are still pending: " + ", ".join(checks),
            reason_code="github_checks_pending",
        )
        self.checks = checks


class CandidateChecksFailed(RuntimeError):
    """A candidate failed a mandatory repository check and needs code repair."""

    def __init__(self, detail: str, evidence_ref: str) -> None:
        super().__init__(detail)
        self.reason_code = "pm_acceptance_failed"
        self.evidence_ref = evidence_ref


CommandRunner = Callable[[list[str], Path], subprocess.CompletedProcess[str]]
AssuranceRunner = Callable[[Path, str], Mapping[str, Mapping[str, Any]]]


class ReleaseGitHub(Protocol):
    def create_pull_request(self, *, head: str, base: str, title: str, body: str) -> Any: ...

    def pull_request_for_head_sha(self, expected_sha: str) -> str: ...

    def required_checks_status(
        self,
        pull_request: str,
        *,
        expected_sha: str,
        required_checks: tuple[str, ...],
    ) -> RequiredChecksStatus: ...

    def close_pull_request(self, pull_request: str) -> Any: ...

    def verify_pull_request(
        self,
        pull_request: str,
        *,
        expected_sha: str,
        required_checks: tuple[str, ...],
        owner_override: bool,
        owner_override_reason: str | None,
    ) -> Any: ...

    def merge_pull_request_checked(
        self,
        pull_request: str,
        *,
        expected_sha: str,
        required_checks: tuple[str, ...],
        owner_override: bool,
        owner_override_reason: str | None,
    ) -> Any: ...

    def merged_commit(self, pull_request: str) -> str: ...


@dataclass(frozen=True)
class PublishedCandidate:
    repository: str
    candidate_sha: str
    branch: str
    base_branch: str
    pull_request: str
    source: Path
    temporary: tempfile.TemporaryDirectory[str]


def _default_command_runner(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False, timeout=120)


def _release_digest(root: Path) -> str:
    """Compute a deterministic content digest without trusting model output."""

    root = root.resolve()
    if not root.is_dir() or root.is_symlink():
        raise ReleaseAdapterError("release source directory is missing or unsafe")
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        parts = Path(relative).parts
        if (
            (parts and parts[0] == ".git")
            or "__pycache__" in parts
            or path.suffix in {".pyc", ".pyo"}
            or relative == ".lease.json"
        ):
            continue
        if path.is_symlink():
            raise ReleaseAdapterError("release source contains a symlink")
        if not path.is_file():
            continue
        name = relative.encode("utf-8")
        content = path.read_bytes()
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"sha256:{digest.hexdigest()}"


class ConfiguredReleaseExecutor(ReleaseExecutor):
    """Use the configured GitHub and deployment boundaries for release tasks."""

    def __init__(
        self,
        config: FactoryConfig,
        *,
        github: ReleaseGitHub | None = None,
        github_factory: Callable[[str, str], ReleaseGitHub] | None = None,
        command_runner: CommandRunner | None = None,
        assurance_runner: AssuranceRunner | None = None,
    ) -> None:
        self.config = config
        github_config = config.raw.get("github", {})
        deployment_config = config.raw.get("deployment", {})
        governance = github_config.get("governance", {})
        self.owner = str(github_config.get("owner", ""))
        self.repository = f"{self.owner}/{github_config.get('factory_repository', '')}"
        if not _REPOSITORY.fullmatch(self.repository):
            raise ValueError("GitHub release repository is not safely configured")
        self.single_owner_mode = (
            str(governance.get("mode", "")) == "single_owner"
            and bool(governance.get("owner_override_enabled", False))
        )
        broker_socket = str(os.environ.get("HERMES_GITHUB_BROKER_SOCKET") or "").strip()
        if github is not None:
            self.github = github
        elif broker_socket:
            from .github_broker_adapter import BrokerGitHubAdapter

            self.github = BrokerGitHubAdapter(
                self.owner,
                str(github_config["factory_repository"]),
                socket_path=Path(broker_socket),
                single_owner_mode=self.single_owner_mode,
            )
        else:
            self.github = GitHubAdapter(
                self.owner,
                str(github_config["factory_repository"]),
                single_owner_mode=self.single_owner_mode,
            )
        self.github_factory = github_factory
        configured_staging = deployment_config.get("staging_root")
        self.staging_root = Path(str(configured_staging)) if configured_staging else config.state_dir / "staging"
        self.production_helper = str(deployment_config.get("production_helper", "")).strip()
        self.command_runner = command_runner or _default_command_runner
        self.assurance_runner = assurance_runner or self._default_assurance_runner
        self.required_checks = tuple(str(item) for item in governance.get("required_checks", []) if str(item).strip())
        self.owner_override_enabled = bool(governance.get("owner_override_enabled", False))
        self.owner_override_reason = str(governance.get("owner_override_reason", "")).strip()
        self.owner_override_reason_required = bool(governance.get("owner_override_reason_required", False))
        self.external_required_checks = tuple(
            str(item)
            for item in governance.get("external_required_checks", [])
            if str(item).strip()
        )
        self.github_check_timeout_seconds = config.github_check_timeout_seconds
        self.github_check_poll_seconds = config.github_check_poll_seconds

    def _github_for_repository(self, repository: str) -> ReleaseGitHub:
        if repository == self.repository:
            return self.github
        owner, name = repository.split("/", 1)
        if owner != self.owner:
            raise ExternalBlocker("product repository is outside the configured GitHub owner")
        if self.github_factory is not None:
            return self.github_factory(owner, name)
        broker_socket = str(os.environ.get("HERMES_GITHUB_BROKER_SOCKET") or "").strip()
        if broker_socket:
            from .github_broker_adapter import BrokerGitHubAdapter

            return BrokerGitHubAdapter(
                owner,
                name,
                socket_path=Path(broker_socket),
                single_owner_mode=self.single_owner_mode,
            )
        return GitHubAdapter(owner, name, single_owner_mode=self.single_owner_mode)

    def _default_assurance_runner(
        self,
        workspace: Path,
        candidate_sha: str,
    ) -> Mapping[str, Mapping[str, Any]]:
        from scripts.quality_gate import load_catalog, run_gate

        catalog_path = Path(__file__).resolve().parents[1] / "config" / "quality-gates.yaml"
        catalog = load_catalog(catalog_path)
        gates = catalog.get("gates", [])
        if not isinstance(gates, list):
            raise ReleaseAdapterError("target assurance catalog is invalid")
        target_python = workspace.parent / "venv" / "bin" / "python"
        if not target_python.is_file():
            windows_python = workspace.parent / "venv" / "Scripts" / "python.exe"
            target_python = windows_python if windows_python.is_file() else target_python
        if not target_python.is_file():
            raise ExternalBlocker("target virtual environment is unavailable for release assurance")
        required = (
            "target-secret-scan",
            "target-sast",
            "target-dependency-audit",
            "target-license-check",
        )
        results: dict[str, Mapping[str, Any]] = {}
        for gate_id in required:
            gate = next(
                (
                    item
                    for item in gates
                    if isinstance(item, dict) and str(item.get("id", "")) == gate_id
                ),
                None,
            )
            if gate is None:
                raise ReleaseAdapterError(f"mandatory target assurance gate is missing: {gate_id}")
            results[gate_id] = run_gate(
                gate,
                workspace,
                candidate_sha,
                python_executable=str(target_python),
                temporary_root=self.config.state_dir / "tmp" / "quality-gates",
            )
        return results

    def _run_release_assurance(
        self,
        product_id: str,
        workspace: Path,
        candidate_sha: str,
    ) -> str:
        results = dict(self.assurance_runner(workspace, candidate_sha))
        required = {
            "target-secret-scan",
            "target-sast",
            "target-dependency-audit",
            "target-license-check",
        }
        if set(results) != required:
            raise ExternalBlocker("release assurance did not return every mandatory target gate")
        path = self.config.evidence_dir / f"release-assurance-{product_id}-{candidate_sha[:12]}.json"
        payload = {
            "schema_version": "1.0",
            "product_id": product_id,
            "subject_sha": candidate_sha,
            "gates": results,
        }
        content = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        self.config.evidence_dir.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            if path.read_text(encoding="utf-8") != content:
                raise ReleaseAdapterError("release assurance evidence conflict")
        failed = sorted(
            gate_id
            for gate_id, result in results.items()
            if str(result.get("status", "")) != "PASS"
        )
        if failed:
            raise ExternalBlocker("mandatory release assurance failed: " + ", ".join(failed))
        return f"evidence/{path.name}"

    @staticmethod
    def _safe_product_id(value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("product_id contains unsafe characters")
        return value

    @staticmethod
    def _version(source: Path, candidate_sha: str) -> str:
        del candidate_sha
        try:
            return verify_version_consistency(source)
        except VersionConsistencyError as error:
            raise ReleaseAdapterError(str(error)) from error

    def _command(
        self,
        argv: list[str],
        cwd: Path,
        *,
        allowed_returncodes: tuple[int, ...] = (0,),
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = self.command_runner(argv, cwd)
        except (OSError, subprocess.SubprocessError) as error:
            raise ReleaseAdapterError(f"allowlisted command unavailable: {argv[0]}") from error
        if result.returncode not in allowed_returncodes:
            raise ReleaseAdapterError(f"allowlisted command failed: {argv[0]}")
        return result

    def _repository_for_workspace(self, workspace: Path) -> str:
        result = self._command(["git", "remote", "get-url", "origin"], workspace)
        remote = result.stdout.strip()
        match = _HTTPS_REMOTE.fullmatch(remote)
        if match is None:
            raise ExternalBlocker("workspace origin must be an HTTPS GitHub repository")
        owner = match.group("owner")
        repository = match.group("repository")
        if owner != self.owner:
            raise ExternalBlocker("workspace repository is outside the configured GitHub owner")
        slug = f"{owner}/{repository}"
        if not _REPOSITORY.fullmatch(slug):
            raise ReleaseAdapterError("derived workspace repository is invalid")
        return slug

    def _default_branch(self, workspace: Path) -> str:
        symbolic = self._command(
            ["git", "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"],
            workspace,
            allowed_returncodes=(0, 1),
        )
        if symbolic.returncode == 0:
            value = symbolic.stdout.strip()
            if value.startswith("origin/"):
                branch = value.removeprefix("origin/")
                if re.fullmatch(r"[A-Za-z0-9._/-]+", branch):
                    return branch
        main = self._command(
            ["git", "show-ref", "--verify", "--quiet", "refs/remotes/origin/main"],
            workspace,
            allowed_returncodes=(0, 1),
        )
        if main.returncode == 0:
            return "main"
        raise ExternalBlocker("workspace default branch cannot be derived safely")

    @staticmethod
    def _candidate_path(value: str) -> PurePosixPath:
        path = PurePosixPath(value)
        if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
            raise ReleaseAdapterError("Git candidate path is unsafe")
        return path

    def _candidate_paths(self, workspace: Path) -> list[str]:
        result = self._command(
            ["git", "ls-files", "--modified", "--deleted", "--others", "--exclude-standard", "-z"],
            workspace,
        )
        selected: list[str] = []
        for raw in result.stdout.split("\0"):
            if not raw:
                continue
            path = self._candidate_path(raw)
            root = path.parts[0]
            if (
                root in {"artifacts", "release-artifacts"}
                or "__pycache__" in path.parts
                or path.suffix in {".pyc", ".pyo"}
                or raw == ".lease.json"
            ):
                continue
            if (
                root in _PROTECTED_CANDIDATE_ROOTS
                or raw in _PROTECTED_CANDIDATE_PATHS
                or path.parts[:2] == (".github", "workflows")
                or root.startswith(".env")
            ):
                raise ExternalBlocker(f"candidate contains a protected path: {raw}")
            local = workspace.joinpath(*path.parts)
            if local.exists():
                if local.is_symlink() or not local.is_file():
                    raise ReleaseAdapterError(f"candidate path is not a regular file: {raw}")
                if local.stat().st_size > 10 * 1024 * 1024:
                    raise ExternalBlocker(f"candidate file exceeds the 10 MiB boundary: {raw}")
            selected.append(raw)
        selected = sorted(set(selected))
        if len(selected) > 500:
            raise ExternalBlocker("candidate contains more than 500 changed files")
        return selected

    @staticmethod
    def _extract_git_archive(archive: Path, destination: Path) -> None:
        destination.mkdir()
        with tarfile.open(archive, mode="r:") as handle:
            members = handle.getmembers()
            for member in members:
                relative = PurePosixPath(member.name)
                if (
                    relative.is_absolute()
                    or not relative.parts
                    or any(part in {"", ".", ".."} for part in relative.parts)
                    or member.issym()
                    or member.islnk()
                    or not (member.isdir() or member.isfile())
                ):
                    raise ReleaseAdapterError("Git archive contains an unsafe entry")
            for member in members:
                relative = PurePosixPath(member.name)
                target = destination.joinpath(*relative.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                source = handle.extractfile(member)
                if source is None:
                    raise ReleaseAdapterError("Git archive file could not be read")
                with target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                os.chmod(target, stat.S_IMODE(member.mode))

    def _candidate_source(
        self,
        workspace: Path,
        candidate_sha: str,
    ) -> tuple[Path, tempfile.TemporaryDirectory[str]]:
        temporary = tempfile.TemporaryDirectory(prefix="candidate-source-", dir=self.config.state_dir)
        parent = Path(temporary.name)
        archive = parent / "candidate.tar"
        source = parent / "source"
        try:
            self._command(
                ["git", "archive", "--format=tar", f"--output={archive}", candidate_sha],
                workspace,
            )
            self._extract_git_archive(archive, source)
        except Exception:
            temporary.cleanup()
            raise
        return source, temporary

    def _publish_candidate(
        self,
        *,
        product_id: str,
        repository: str,
        workspace: Path,
        github: ReleaseGitHub,
    ) -> PublishedCandidate:
        base_branch = self._default_branch(workspace)
        self._command(["git", "reset", "--quiet", "HEAD", "--"], workspace)
        changed_paths = self._candidate_paths(workspace)
        if changed_paths:
            self._command(["git", "add", "--all", "--", *changed_paths], workspace)
        changed = self._command(
            ["git", "diff", "--cached", "--quiet"],
            workspace,
            allowed_returncodes=(0, 1),
        ).returncode == 1
        if changed:
            tree_sha = self._command(["git", "write-tree"], workspace).stdout.strip()
            if not _SHA.fullmatch(tree_sha):
                raise ReleaseAdapterError("Git candidate tree is invalid")
            branch = f"codex/hermes-{product_id[-20:].lower()}-{tree_sha[:12]}"
            existing = self._command(
                ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
                workspace,
                allowed_returncodes=(0, 1),
            )
            if existing.returncode == 0:
                existing_tree = self._command(["git", "rev-parse", f"{branch}^{{tree}}"], workspace).stdout.strip()
                if existing_tree != tree_sha:
                    raise ReleaseAdapterError("existing candidate branch has a different tree")
                self._command(["git", "switch", branch], workspace)
            else:
                self._command(["git", "switch", "-c", branch], workspace)
                self._command(
                    [
                        "git",
                        "-c",
                        "user.name=Hermes Software Factory",
                        "-c",
                        "user.email=hermes-factory@users.noreply.github.com",
                        "commit",
                        "--no-gpg-sign",
                        "-m",
                        f"Hermes candidate for {product_id}",
                    ],
                    workspace,
                )
        else:
            branch = self._command(["git", "branch", "--show-current"], workspace).stdout.strip()
            if not branch or branch == base_branch:
                raise ExternalBlocker("workspace has no unpublished candidate changes")
        candidate_sha = self._command(["git", "rev-parse", "HEAD"], workspace).stdout.strip()
        if not _SHA.fullmatch(candidate_sha):
            raise ReleaseAdapterError("published candidate SHA is invalid")
        broker_socket = str(os.environ.get("HERMES_GITHUB_BROKER_SOCKET") or "").strip()
        if broker_socket:
            owner, name = repository.split("/", 1)
            request_id = "REL-" + sha256_text(
                stable_json([repository, candidate_sha, branch, "branch.push"])
            )[:40]
            try:
                BrokerClient(Path(broker_socket)).execute(
                    BrokerRequest(
                        request_id=request_id,
                        operation="branch.push",
                        owner=owner,
                        repository=name,
                        payload={"workspace": str(workspace.resolve()), "branch": branch},
                    )
                )
            except CredentialBrokerError as error:
                failure_reason = (
                    "missing_credential"
                    if "credential" in str(error)
                    else "internal_blocker"
                )
                raise ExternalBlocker(
                    "Candidate GitHub branch push was rejected",
                    reason_code=failure_reason,
                ) from error
        else:
            self._command(
                ["git", "push", "--set-upstream", "origin", f"{candidate_sha}:refs/heads/{branch}"],
                workspace,
            )
        try:
            pull_request = github.pull_request_for_head_sha(candidate_sha)
        except GitHubCommandError:
            visible_paths = changed_paths[:50]
            path_summary = "\n".join(f"- `{path}`" for path in visible_paths) or "- existing committed candidate"
            github.create_pull_request(
                head=branch,
                base=base_branch,
                title=f"[Hermes] Candidate for {product_id}",
                body=(
                    "Controller-owned release candidate produced after mandatory pipeline gates.\n\n"
                    f"Candidate SHA: `{candidate_sha}`\n\n"
                    "Included source changes:\n"
                    f"{path_summary}"
                ),
            )
            pull_request = github.pull_request_for_head_sha(candidate_sha)
        source, temporary = self._candidate_source(workspace, candidate_sha)
        return PublishedCandidate(
            repository=repository,
            candidate_sha=candidate_sha,
            branch=branch,
            base_branch=base_branch,
            pull_request=pull_request,
            source=source,
            temporary=temporary,
        )

    @staticmethod
    def _health_probe(current: Path) -> bool:
        required = (current / "VERSION", current / "SHA256SUMS", current / "factory", current / "scripts")
        if not all(path.exists() for path in required):
            return False
        verifier = current / "scripts" / "verify_manifest.py"
        if not verifier.is_file():
            return False
        try:
            result = subprocess.run(
                [sys.executable, str(verifier)],
                cwd=current,
                text=True,
                capture_output=True,
                check=False,
                timeout=60,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return result.returncode == 0

    @staticmethod
    def _filtered_source(workspace: Path, parent: Path) -> tuple[Path, tempfile.TemporaryDirectory[str]]:
        if not workspace.is_dir() or workspace.is_symlink():
            raise ReleaseAdapterError("leased workspace is missing or unsafe")
        temporary = tempfile.TemporaryDirectory(prefix="release-source-", dir=parent)
        source = Path(temporary.name) / "source"
        shutil.copytree(
            workspace,
            source,
            symlinks=False,
            ignore=shutil.ignore_patterns(".git", ".lease.json"),
        )
        return source, temporary

    def _write_audit(self, product_id: str, candidate_sha: str, payload: Mapping[str, Any]) -> str:
        stage = str(payload.get("stage", "unknown"))
        path = self.config.evidence_dir / f"release-adapter-{stage}-{product_id}-{candidate_sha[:12]}.json"
        content = json.dumps(dict(payload), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        self.config.evidence_dir.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
                handle.flush()
        except FileExistsError:
            if path.read_text(encoding="utf-8") != content:
                raise ReleaseAdapterError("release adapter audit conflict")
        return f"evidence/{path.name}"

    def _candidate_check_evidence(
        self,
        product_id: str,
        candidate: PublishedCandidate,
        status: RequiredChecksStatus,
    ) -> str:
        path = (
            self.config.evidence_dir
            / f"candidate-check-{product_id}-{candidate.candidate_sha[:12]}.json"
        )
        payload = {
            "schema_version": "1.0",
            "product_id": product_id,
            "repository": candidate.repository,
            "pull_request": candidate.pull_request,
            "candidate_sha": candidate.candidate_sha,
            "required_checks": list(status.states),
            "passed": list(status.passed),
            "pending": list(status.pending),
            "failed": list(status.failed),
            "summary": (
                (
                    "Mandatory GitHub candidate checks failed: "
                    + ", ".join(status.failed)
                )
                if status.failed
                else "All mandatory GitHub candidate checks passed."
            ),
        }
        content = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        self.config.evidence_dir.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            if path.read_text(encoding="utf-8") != content:
                raise ReleaseAdapterError("candidate check evidence conflict")
        return f"evidence/{path.name}"

    def _discard_failed_candidate(
        self,
        candidate: PublishedCandidate,
        workspace: Path,
        github: ReleaseGitHub,
    ) -> None:
        github.close_pull_request(candidate.pull_request)
        self._command(["git", "switch", candidate.base_branch], workspace)
        self._command(
            ["git", "reset", "--hard", f"origin/{candidate.base_branch}"],
            workspace,
        )
        self._command(
            ["git", "clean", "-fd", "--", "artifacts", "release-artifacts"],
            workspace,
        )
        self._command(
            ["git", "branch", "-D", candidate.branch],
            workspace,
            allowed_returncodes=(0, 1),
        )

    def _wait_for_candidate_checks(
        self,
        *,
        product_id: str,
        candidate: PublishedCandidate,
        workspace: Path,
        github: ReleaseGitHub,
        required_checks: tuple[str, ...],
    ) -> str | None:
        if not required_checks:
            return None
        deadline = time.monotonic() + self.github_check_timeout_seconds
        latest: RequiredChecksStatus | None = None
        while True:
            latest = github.required_checks_status(
                candidate.pull_request,
                expected_sha=candidate.candidate_sha,
                required_checks=required_checks,
            )
            if latest.failed:
                evidence_ref = self._candidate_check_evidence(
                    product_id,
                    candidate,
                    latest,
                )
                self._discard_failed_candidate(candidate, workspace, github)
                raise CandidateChecksFailed(
                    "mandatory GitHub checks failed: " + ", ".join(latest.failed),
                    evidence_ref,
                )
            if not latest.pending:
                return self._candidate_check_evidence(
                    product_id,
                    candidate,
                    latest,
                )
            if time.monotonic() >= deadline:
                raise CandidateChecksPending(latest.pending)
            time.sleep(self.github_check_poll_seconds)

    def _stage(
        self,
        product_id: str,
        candidate_sha: str,
        source: Path,
        repository: str,
    ) -> tuple[str, TransactionResult, str]:
        staging_root = (self.staging_root / product_id).resolve()
        if staging_root.parent != self.staging_root.resolve():
            raise ReleaseAdapterError("staging path escaped configured root")
        staging_root.mkdir(parents=True, exist_ok=True)
        digest = _release_digest(source)
        current = staging_root / "current"
        if current.is_dir() and _release_digest(current) == digest:
            transaction = TransactionResult(candidate_sha, "PROMOTED", str(current), None, None, "already promoted")
        else:
            health_probe = (
                self._health_probe
                if repository == self.repository
                else lambda promoted: _release_digest(promoted) == digest
            )
            transaction = TransactionalDeployer(
                staging_root,
                health_probe=health_probe,
            ).promote(candidate_sha, source)
            if transaction.status != "PROMOTED":
                raise ReleaseAdapterError(f"staging transaction did not promote: {transaction.status}")
        return digest, transaction, self._version(source, candidate_sha)

    def _staging_record_path(self, product_id: str) -> Path:
        staging_root = (self.staging_root / product_id).resolve()
        if staging_root.parent != self.staging_root.resolve():
            raise ReleaseAdapterError("staging record path escaped configured root")
        return staging_root / "release.json"

    def _write_staging_record(self, product_id: str, payload: Mapping[str, Any]) -> None:
        path = self._staging_record_path(product_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".json.tmp")
        content = json.dumps(dict(payload), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)

    def _load_staging_record(self, product_id: str) -> dict[str, str]:
        path = self._staging_record_path(product_id)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ExternalBlocker("trusted staging release record is unavailable") from error
        if not isinstance(payload, dict):
            raise ExternalBlocker("trusted staging release record is invalid")
        record = {key: str(payload.get(key, "")) for key in ("repository", "candidate_sha", "pull_request", "image_digest", "version")}
        if (
            not _REPOSITORY.fullmatch(record["repository"])
            or not _SHA.fullmatch(record["candidate_sha"])
            or not record["pull_request"].isdigit()
            or not _DIGEST.fullmatch(record["image_digest"])
            or not record["version"]
        ):
            raise ExternalBlocker("trusted staging release record is incomplete")
        current = path.parent / "current"
        if not current.is_dir() or _release_digest(current) != record["image_digest"]:
            raise ExternalBlocker("staging content does not match its accepted release record")
        return record

    @staticmethod
    def _authoritative_result(
        proposed: Mapping[str, Any],
        product_id: str,
        fields: Mapping[str, Any],
    ) -> dict[str, Any]:
        envelope = {
            key: proposed[key]
            for key in ("schema_version", "artifact_id", "created_at", "producer", "policy_digest")
            if key in proposed
        }
        envelope["product_id"] = product_id
        envelope.update(fields)
        return envelope

    def _production_policy(self, *, risk: str, image_digest: str, staging_digest: str | None) -> None:
        decision = DeploymentGuard().promote(
            environment="production",
            risk=risk,
            image_digest=image_digest,
            staging_digest=staging_digest,
            stateful=True,
            offsite_backup_configured=bool(self.config.raw.get("backup", {}).get("offsite_configured", False)),
            current_vps=str(self.config.raw.get("deployment", {}).get("production_target", {}).get("mode", "")) == "current_vps",
        )
        if decision.status != "READY":
            raise ExternalBlocker("production deployment policy did not return READY")

    def _validate_production_helper(self) -> PurePosixPath:
        if not self.production_helper:
            raise ExternalBlocker("production release helper is not configured")
        helper = PurePosixPath(self.production_helper)
        if not helper.is_absolute() or not helper.name.startswith("hermes-factory-"):
            raise ValueError("production release helper must be an absolute hermes-factory command")
        return helper

    def _run_production_helper(
        self,
        *,
        repository: str,
        product_id: str,
        release_id: str,
        staging_digest: str,
    ) -> dict[str, str]:
        helper = self._validate_production_helper()
        isolated = (
            str(
                self.config.raw.get("deployment", {})
                .get("production_target", {})
                .get("mode", "")
            )
            == "isolated_candidate"
        )
        sudo = shutil.which("sudo") or "/usr/bin/sudo"
        prefix = [] if isolated else [sudo, "-n"]
        result = self.command_runner(
            [
                *prefix,
                str(helper),
                "--repository",
                repository,
                "--product-id",
                product_id,
                "--release-id",
                release_id,
                "--staging-digest",
                staging_digest,
            ],
            self.config.state_dir,
        )
        if result.returncode != 0:
            raise ReleaseAdapterError("allowlisted production release helper failed")
        receipt: object | None = None
        for line in reversed(result.stdout.splitlines()):
            try:
                receipt = json.loads(line)
            except json.JSONDecodeError:
                continue
            break
        if (
            not isinstance(receipt, dict)
            or receipt.get("status") != "PROMOTED"
            or receipt.get("release_id") != release_id
        ):
            raise ReleaseAdapterError("production helper returned an invalid receipt")
        return {
            "status": "PROMOTED",
            "release_id": release_id,
        }

    def _merge_or_observe(
        self,
        *,
        github: ReleaseGitHub,
        pull_request: str,
        candidate_sha: str,
        required_checks: tuple[str, ...],
        owner_override: bool,
    ) -> tuple[str, bool]:
        """Return an existing merge receipt or perform the checked merge once."""

        try:
            merge_sha = github.merged_commit(pull_request)
        except GitHubCommandError:
            derived_pull_request = github.pull_request_for_head_sha(candidate_sha)
            if derived_pull_request != pull_request:
                raise GitHubCommandError(
                    "accepted staging pull request no longer matches its candidate"
                )
            github.verify_pull_request(
                pull_request,
                expected_sha=candidate_sha,
                required_checks=required_checks,
                owner_override=owner_override,
                owner_override_reason=(
                    self.owner_override_reason if owner_override else None
                ),
            )
            github.merge_pull_request_checked(
                pull_request,
                expected_sha=candidate_sha,
                required_checks=required_checks,
                owner_override=owner_override,
                owner_override_reason=(
                    self.owner_override_reason if owner_override else None
                ),
            )
            return github.merged_commit(pull_request), True
        if not _SHA.fullmatch(merge_sha):
            raise GitHubCommandError("merged pull request lacks an immutable merge SHA")
        return merge_sha, False

    def _execute_non_service_promotion(
        self,
        *,
        stage: str,
        proposed: Mapping[str, Any],
        product_id: str,
        repository: str,
        github: ReleaseGitHub,
        expected_digest: str,
    ) -> Mapping[str, Any]:
        """Promote a checked immutable package/repository artifact without VPS deploy."""

        record = self._load_staging_record(product_id)
        if repository != record["repository"]:
            raise ExternalBlocker("release repository differs from accepted package candidate")
        if not _DIGEST.fullmatch(expected_digest) or record["image_digest"] != expected_digest:
            raise ExternalBlocker("accepted package digest differs from the trusted dry run")
        candidate_sha = record["candidate_sha"]
        pull_request = record["pull_request"]
        required_checks = (
            self.required_checks
            if repository == self.repository
            else self.external_required_checks
        )
        if repository == self.repository and not required_checks:
            raise ExternalBlocker("required GitHub checks are not configured")
        owner_override = self.owner_override_enabled
        if owner_override and self.owner_override_reason_required and not self.owner_override_reason:
            raise ExternalBlocker("owner override reason is not configured")
        try:
            merge_sha, _merge_performed = self._merge_or_observe(
                github=github,
                pull_request=pull_request,
                candidate_sha=candidate_sha,
                required_checks=required_checks,
                owner_override=owner_override,
            )
        except GitHubCommandError as error:
            raise ExternalBlocker(str(error)) from error
        evidence_ref = self._write_audit(
            product_id,
            merge_sha,
            {
                "stage": stage,
                "repository": repository,
                "pull_request": pull_request,
                "candidate_sha": candidate_sha,
                "merge_sha": merge_sha,
                "artifact_digest": expected_digest,
                "approval_mode": "owner_override" if owner_override else "independent",
            },
        )
        return self._authoritative_result(
            proposed,
            product_id,
            {
                "status": "completed",
                "repository": repository,
                "candidate_sha": merge_sha,
                "merge": {"performed": True, "merge_sha": merge_sha},
                "release": {
                    "version": record["version"],
                    "image_digest": expected_digest,
                },
                "staging": "deployed",
                "production": "deployed",
                "rollback": "not_needed",
                "summary": (
                    "Adapter verified and promoted the exact checked package/repository "
                    "artifact without invoking the service-production helper."
                ),
                "findings": [],
                "evidence_refs": [evidence_ref],
            },
        )

    def execute(
        self,
        *,
        stage: str,
        proposed: Mapping[str, Any],
        product_id: str,
        task_contract: Mapping[str, Any],
        workspace: Path,
        expected_staging_digest: str | None,
    ) -> Mapping[str, Any]:
        if stage not in {
            "staging",
            "production",
            "publish-dry-run",
            "signed-release",
            "signed-publish",
        }:
            raise ValueError("release operation is not catalogued")
        product_id = self._safe_product_id(product_id)
        repository = self._repository_for_workspace(workspace)
        github = self._github_for_repository(repository)

        if stage == "publish-dry-run":
            return self.execute(
                stage="staging",
                proposed=proposed,
                product_id=product_id,
                task_contract=task_contract,
                workspace=workspace,
                expected_staging_digest=None,
            )
        if stage == "signed-release":
            prepared = self.execute(
                stage="staging",
                proposed=proposed,
                product_id=product_id,
                task_contract=task_contract,
                workspace=workspace,
                expected_staging_digest=None,
            )
            release = prepared.get("release")
            if not isinstance(release, Mapping):
                raise ReleaseAdapterError("signed release preparation lacks artifact digest")
            prepared_digest = str(release.get("image_digest") or "")
            return self._execute_non_service_promotion(
                stage=stage,
                proposed=proposed,
                product_id=product_id,
                repository=repository,
                github=github,
                expected_digest=prepared_digest,
            )
        if stage == "signed-publish":
            if expected_staging_digest is None:
                raise ExternalBlocker("accepted publish dry-run digest is missing")
            return self._execute_non_service_promotion(
                stage=stage,
                proposed=proposed,
                product_id=product_id,
                repository=repository,
                github=github,
                expected_digest=expected_staging_digest,
            )

        if stage == "staging":
            try:
                candidate = self._publish_candidate(
                    product_id=product_id,
                    repository=repository,
                    workspace=workspace,
                    github=github,
                )
            except GitHubCommandError as error:
                raise ExternalBlocker(str(error)) from error
            try:
                required_checks = (
                    self.required_checks
                    if repository == self.repository
                    else self.external_required_checks
                )
                candidate_check_ref = self._wait_for_candidate_checks(
                    product_id=product_id,
                    candidate=candidate,
                    workspace=workspace,
                    github=github,
                    required_checks=required_checks,
                )
                assurance_ref = self._run_release_assurance(
                    product_id,
                    workspace,
                    candidate.candidate_sha,
                )
                digest, transaction, version = self._stage(
                    product_id,
                    candidate.candidate_sha,
                    candidate.source,
                    repository,
                )
                self._write_staging_record(
                    product_id,
                    {
                        "repository": repository,
                        "candidate_sha": candidate.candidate_sha,
                        "pull_request": candidate.pull_request,
                        "image_digest": digest,
                        "version": version,
                    },
                )
                evidence_ref = self._write_audit(
                    product_id,
                    candidate.candidate_sha,
                    {
                        "stage": stage,
                        "repository": repository,
                        "pull_request": candidate.pull_request,
                        "candidate_sha": candidate.candidate_sha,
                        "branch": candidate.branch,
                        "base_branch": candidate.base_branch,
                        "image_digest": digest,
                        "transaction": transaction.__dict__,
                    },
                )
            finally:
                candidate.temporary.cleanup()
            return self._authoritative_result(
                proposed,
                product_id,
                {
                    "status": "completed",
                    "repository": repository,
                    "candidate_sha": candidate.candidate_sha,
                    "merge": {"performed": False, "merge_sha": None},
                    "release": {"version": version, "image_digest": digest},
                    "staging": "deployed",
                    "production": "not_started",
                    "rollback": "not_tested",
                    "summary": (
                        "Adapter published a controller-owned immutable PR candidate "
                        "and promoted its Git archive to local staging."
                    ),
                    "findings": [],
                    "evidence_refs": [
                        value
                        for value in (candidate_check_ref, assurance_ref, evidence_ref)
                        if value
                    ],
                },
            )

        record = self._load_staging_record(product_id)
        if repository != record["repository"]:
            raise ExternalBlocker("production workspace repository differs from accepted staging")
        candidate_sha = record["candidate_sha"]
        pull_request = record["pull_request"]
        if expected_staging_digest is None or not _DIGEST.fullmatch(expected_staging_digest):
            raise ExternalBlocker("accepted staging digest is missing")
        if record["image_digest"] != expected_staging_digest:
            raise ExternalBlocker("accepted staging digest differs from the trusted staging record")
        try:
            verify_version_consistency(
                self._staging_record_path(product_id).parent / "current",
                release_record=self._staging_record_path(product_id),
                expected=record["version"],
            )
        except VersionConsistencyError as error:
            raise ExternalBlocker(
                f"accepted release version evidence is inconsistent: {error}"
            ) from error
        self._production_policy(
            risk=str(task_contract.get("risk_tier", "medium")),
            image_digest=expected_staging_digest,
            staging_digest=expected_staging_digest,
        )
        required_checks = self.required_checks if repository == self.repository else self.external_required_checks
        if repository == self.repository and not required_checks:
            raise ExternalBlocker("required GitHub checks are not configured")
        owner_override = self.owner_override_enabled
        if owner_override and self.owner_override_reason_required and not self.owner_override_reason:
            raise ExternalBlocker("owner override reason is not configured")
        self._validate_production_helper()
        try:
            merge_sha, _merge_performed = self._merge_or_observe(
                github=github,
                pull_request=pull_request,
                candidate_sha=candidate_sha,
                required_checks=required_checks,
                owner_override=owner_override,
            )
            helper_receipt = self._run_production_helper(
                repository=repository,
                product_id=product_id,
                release_id=merge_sha,
                staging_digest=expected_staging_digest,
            )
        except GitHubCommandError as error:
            raise ExternalBlocker(str(error)) from error
        evidence_ref = self._write_audit(
            product_id,
            merge_sha,
            {
                "stage": stage,
                "repository": repository,
                "pull_request": pull_request,
                "candidate_sha": candidate_sha,
                "merge_sha": merge_sha,
                "image_digest": expected_staging_digest,
                "root_helper_receipt": helper_receipt,
                "approval_mode": "owner_override" if owner_override else "independent",
            },
        )
        return self._authoritative_result(
            proposed,
            product_id,
            {
                "status": "completed",
                "repository": repository,
                "candidate_sha": merge_sha,
                "merge": {"performed": True, "merge_sha": merge_sha},
                "release": {"version": record["version"], "image_digest": expected_staging_digest},
                "staging": "deployed",
                "production": "deployed",
                "rollback": "not_needed",
                "summary": "Adapter verified, merged, and promoted the accepted immutable release.",
                "findings": [],
                "evidence_refs": [evidence_ref],
            },
        )

    def reconcile(
        self,
        *,
        stage: str,
        proposed: Mapping[str, Any],
        product_id: str,
        task_contract: Mapping[str, Any],
        workspace: Path,
        expected_staging_digest: str | None,
    ) -> Mapping[str, Any]:
        """Resume the same deterministic idempotent operation after a crash boundary."""

        return self.execute(
            stage=stage,
            proposed=proposed,
            product_id=product_id,
            task_contract=task_contract,
            workspace=workspace,
            expected_staging_digest=expected_staging_digest,
        )


def build_release_executor(config: FactoryConfig) -> ConfiguredReleaseExecutor:
    """Construct the runtime executor after configuration validation."""

    return ConfiguredReleaseExecutor(config)
