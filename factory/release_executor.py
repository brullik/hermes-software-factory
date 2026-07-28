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
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol

from .config import FactoryConfig
from .deployment import DeploymentGuard, TransactionalDeployer, TransactionResult
from .github import GitHubAdapter, GitHubCommandError
from .providers import ExternalBlocker
from .release import ReleaseExecutor

_SHA = re.compile(r"^[a-f0-9]{40}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


class ReleaseAdapterError(RuntimeError):
    """Raised when a release side effect cannot be completed safely."""


CommandRunner = Callable[[list[str], Path], subprocess.CompletedProcess[str]]


class ReleaseGitHub(Protocol):
    def pull_request_for_head_sha(self, expected_sha: str) -> str: ...

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
        if relative == ".lease.json":
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
        command_runner: CommandRunner | None = None,
    ) -> None:
        self.config = config
        github_config = config.raw.get("github", {})
        deployment_config = config.raw.get("deployment", {})
        governance = github_config.get("governance", {})
        self.repository = f"{github_config.get('owner', '')}/{github_config.get('factory_repository', '')}"
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository):
            raise ValueError("GitHub release repository is not safely configured")
        self.github = github or GitHubAdapter(
            str(github_config["owner"]),
            str(github_config["factory_repository"]),
            single_owner_mode=(
                str(governance.get("mode", "")) == "single_owner"
                and bool(governance.get("owner_override_enabled", False))
            ),
        )
        configured_staging = deployment_config.get("staging_root")
        self.staging_root = Path(str(configured_staging)) if configured_staging else config.state_dir / "staging"
        self.production_helper = str(deployment_config.get("production_helper", "")).strip()
        self.command_runner = command_runner or _default_command_runner
        self.required_checks = tuple(str(item) for item in governance.get("required_checks", []) if str(item).strip())
        self.owner_override_enabled = bool(governance.get("owner_override_enabled", False))
        self.owner_override_reason = str(governance.get("owner_override_reason", "")).strip()
        self.owner_override_reason_required = bool(governance.get("owner_override_reason_required", False))

    @staticmethod
    def _safe_product_id(value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("product_id contains unsafe characters")
        return value

    @staticmethod
    def _version(source: Path) -> str:
        version_path = source / "VERSION"
        if not version_path.is_file():
            raise ReleaseAdapterError("release VERSION file is missing")
        version = version_path.read_text(encoding="utf-8").strip()
        if not version or len(version) > 120 or any(char in version for char in "\r\n"):
            raise ReleaseAdapterError("release VERSION is invalid")
        return version

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
        shutil.copytree(workspace, source, symlinks=False, ignore=shutil.ignore_patterns(".lease.json"))
        return source, temporary

    def _write_audit(self, product_id: str, candidate_sha: str, payload: Mapping[str, Any]) -> str:
        path = self.config.evidence_dir / f"release-adapter-{product_id}-{candidate_sha[:12]}.json"
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

    def _stage(self, product_id: str, candidate_sha: str, workspace: Path) -> tuple[str, TransactionResult, str]:
        staging_root = (self.staging_root / product_id).resolve()
        if staging_root.parent != self.staging_root.resolve():
            raise ReleaseAdapterError("staging path escaped configured root")
        staging_root.mkdir(parents=True, exist_ok=True)
        digest = _release_digest(workspace)
        current = staging_root / "current"
        if current.is_dir() and _release_digest(current) == digest:
            transaction = TransactionResult(candidate_sha, "PROMOTED", str(current), None, None, "already promoted")
        else:
            source, temporary = self._filtered_source(workspace, self.config.state_dir)
            try:
                transaction = TransactionalDeployer(
                    staging_root,
                    health_probe=self._health_probe,
                ).promote(candidate_sha, source)
            finally:
                temporary.cleanup()
            if transaction.status != "PROMOTED":
                raise ReleaseAdapterError(f"staging transaction did not promote: {transaction.status}")
        return digest, transaction, self._version(workspace)

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

    def _validate_production_helper(self) -> Path:
        if not self.production_helper:
            raise ExternalBlocker("production release helper is not configured")
        helper = Path(self.production_helper)
        if not helper.is_absolute() or not helper.name.startswith("hermes-factory-"):
            raise ValueError("production release helper must be an absolute hermes-factory command")
        return helper

    def _run_production_helper(self, *, repository: str, release_id: str, staging_digest: str) -> None:
        helper = self._validate_production_helper()
        sudo = shutil.which("sudo") or "/usr/bin/sudo"
        result = self.command_runner(
            [
                sudo,
                "-n",
                str(helper),
                "--repository",
                repository,
                "--release-id",
                release_id,
                "--staging-digest",
                staging_digest,
            ],
            self.config.state_dir,
        )
        if result.returncode != 0:
            raise ReleaseAdapterError("allowlisted production release helper failed")

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
        if stage not in {"staging", "production"}:
            raise ValueError("release stage must be staging or production")
        product_id = self._safe_product_id(product_id)
        if str(proposed.get("repository", "")) != self.repository:
            raise ExternalBlocker("release proposal repository is not the configured repository")
        candidate_sha = str(proposed.get("candidate_sha", ""))
        if not _SHA.fullmatch(candidate_sha):
            raise ValueError("release proposal candidate SHA is invalid")
        try:
            pull_request = self.github.pull_request_for_head_sha(candidate_sha)
        except GitHubCommandError as error:
            raise ExternalBlocker(str(error)) from error

        if stage == "staging":
            digest, transaction, version = self._stage(product_id, candidate_sha, workspace)
            evidence_ref = self._write_audit(
                product_id,
                candidate_sha,
                {
                    "stage": stage,
                    "repository": self.repository,
                    "pull_request": pull_request,
                    "candidate_sha": candidate_sha,
                    "image_digest": digest,
                    "transaction": transaction.__dict__,
                },
            )
            return {
                "status": "completed",
                "repository": self.repository,
                "candidate_sha": candidate_sha,
                "merge": {"performed": False, "merge_sha": None},
                "release": {"version": version, "image_digest": digest},
                "staging": "deployed",
                "production": "not_started",
                "rollback": "not_tested",
                "summary": "Adapter verified the immutable open PR and promoted the candidate to local staging.",
                "findings": [],
                "evidence_refs": [evidence_ref],
            }

        if expected_staging_digest is None or not _DIGEST.fullmatch(expected_staging_digest):
            raise ExternalBlocker("accepted staging digest is missing")
        digest = _release_digest(workspace)
        if digest != expected_staging_digest:
            raise ExternalBlocker("workspace does not match the accepted staging digest")
        self._production_policy(
            risk=str(task_contract.get("risk_tier", "medium")),
            image_digest=expected_staging_digest,
            staging_digest=expected_staging_digest,
        )
        if not self.required_checks:
            raise ExternalBlocker("required GitHub checks are not configured")
        owner_override = self.owner_override_enabled
        if owner_override and self.owner_override_reason_required and not self.owner_override_reason:
            raise ExternalBlocker("owner override reason is not configured")
        self._validate_production_helper()
        try:
            self.github.verify_pull_request(
                pull_request,
                expected_sha=candidate_sha,
                required_checks=self.required_checks,
                owner_override=owner_override,
                owner_override_reason=self.owner_override_reason if owner_override else None,
            )
            self.github.merge_pull_request_checked(
                pull_request,
                expected_sha=candidate_sha,
                required_checks=self.required_checks,
                owner_override=owner_override,
                owner_override_reason=self.owner_override_reason if owner_override else None,
            )
            merge_sha = self.github.merged_commit(pull_request)
            self._run_production_helper(
                repository=self.repository,
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
                "repository": self.repository,
                "pull_request": pull_request,
                "candidate_sha": candidate_sha,
                "merge_sha": merge_sha,
                "image_digest": expected_staging_digest,
                "approval_mode": "owner_override" if owner_override else "independent",
            },
        )
        return {
            "status": "completed",
            "repository": self.repository,
            "candidate_sha": merge_sha,
            "merge": {"performed": True, "merge_sha": merge_sha},
            "release": {"version": self._version(workspace), "image_digest": expected_staging_digest},
            "staging": "deployed",
            "production": "deployed",
            "rollback": "not_needed",
            "summary": "Adapter verified, merged, and promoted the accepted immutable release.",
            "findings": [],
            "evidence_refs": [evidence_ref],
        }


def build_release_executor(config: FactoryConfig) -> ConfiguredReleaseExecutor:
    """Construct the runtime executor after configuration validation."""

    return ConfiguredReleaseExecutor(config)
