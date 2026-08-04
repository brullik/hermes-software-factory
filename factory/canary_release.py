"""Candidate-safe release adapter for clean canaries on an isolated target."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .canary_faults import CanaryFaultJournal
from .common import sha256_text, stable_json, utc_now
from .config import FactoryConfig
from .deployment import TransactionalDeployer
from .release import ReleaseOperationFailed, canonical_release_operation
from .release_executor import ReleaseAdapterError, _release_digest

_SHA = re.compile(r"^[a-f0-9]{40}$")


class IsolatedCanaryReleaseExecutor:
    """Exercise real transactional copies without GitHub or production authority."""

    def __init__(
        self,
        config: FactoryConfig,
        journal: CanaryFaultJournal,
    ) -> None:
        self.config = config
        self.journal = journal
        self.target_root = journal.contract.isolated_target_root.resolve()
        configured_state = config.state_dir.resolve()
        if self.target_root == configured_state or configured_state not in self.target_root.parents:
            raise ValueError("clean canary target must stay inside its isolated state root")

    @staticmethod
    def _git(workspace: Path, *arguments: str) -> str:
        environment = {
            "HOME": os.environ.get("HOME", ""),
            "PATH": os.environ.get("PATH", ""),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
        completed = subprocess.run(
            ["git", "-C", str(workspace), *arguments],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=120,
        )
        if completed.returncode != 0:
            raise ReleaseAdapterError("isolated candidate Git operation failed")
        return completed.stdout.strip()

    def _candidate_sha(self, workspace: Path) -> str:
        status = self._git(workspace, "status", "--porcelain=v1", "--untracked-files=all")
        if status:
            self._git(workspace, "add", "--all", "--")
            self._git(
                workspace,
                "-c",
                "user.name=Hermes Clean Canary",
                "-c",
                "user.email=hermes-canary@localhost",
                "commit",
                "-m",
                "Record isolated clean-canary candidate",
            )
        candidate_sha = self._git(workspace, "rev-parse", "--verify", "HEAD")
        if not _SHA.fullmatch(candidate_sha):
            raise ReleaseAdapterError("isolated candidate commit is invalid")
        return candidate_sha

    def _snapshot(self, workspace: Path, digest: str) -> Path:
        digest_value = digest.removeprefix("sha256:")
        root = self.config.state_dir / "qualification" / "release-snapshots"
        destination = root / digest_value
        if destination.is_dir():
            if _release_digest(destination) != digest:
                raise ReleaseAdapterError("immutable clean-canary snapshot conflicts")
            return destination
        if destination.exists() or destination.is_symlink():
            raise ReleaseAdapterError("clean-canary snapshot path is unsafe")
        root.mkdir(parents=True, exist_ok=True)
        temporary = root / f".{digest_value}.preparing"
        if temporary.exists() or temporary.is_symlink():
            raise ReleaseAdapterError("interrupted clean-canary snapshot requires review")
        shutil.copytree(
            workspace,
            temporary,
            symlinks=False,
            ignore=shutil.ignore_patterns(
                ".git",
                ".venv",
                "venv",
                "__pycache__",
                "*.pyc",
                "*.pyo",
                ".lease.json",
            ),
        )
        if _release_digest(temporary) != digest:
            raise ReleaseAdapterError("clean-canary snapshot digest changed during copy")
        temporary.replace(destination)
        return destination

    @staticmethod
    def _version(workspace: Path) -> str:
        version_file = workspace / "VERSION"
        if version_file.is_file():
            value = version_file.read_text(encoding="utf-8").strip()
            if value:
                return value
        return "0.0.0-clean-canary"

    def _evidence(
        self,
        *,
        product_id: str,
        stage: str,
        candidate_sha: str,
        image_digest: str,
        transaction_status: str,
    ) -> str:
        payload = {
            "schema_version": "1.0",
            "scenario_id": self.journal.contract.scenario_id,
            "scenario_digest": self.journal.contract.scenario_digest,
            "candidate_digest": self.journal.contract.candidate_digest,
            "controller_release_digest": self.journal.contract.controller_release_digest,
            "product_id": product_id,
            "stage": stage,
            "candidate_sha": candidate_sha,
            "image_digest": image_digest,
            "transaction_status": transaction_status,
            "target": "isolated_candidate",
            "created_at": utc_now(),
        }
        digest = sha256_text(stable_json(payload))
        envelope = {**payload, "report_digest": digest}
        path = self.config.evidence_dir / f"canary-release-{product_id}-{stage}-{digest}.json"
        encoded = json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        self.config.evidence_dir.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if path.is_symlink() or path.read_text(encoding="utf-8") != encoded:
                raise ReleaseAdapterError("immutable clean-canary release evidence conflicts")
        else:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        return f"evidence/{path.name}"

    def _seed_rollback_target(self, install_root: Path) -> None:
        current = install_root / "current"
        if current.exists():
            return
        current.mkdir(parents=True, exist_ok=False)
        (current / "BASELINE.txt").write_text(
            "Isolated clean-canary rollback baseline.\n",
            encoding="utf-8",
            newline="\n",
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
        stage = canonical_release_operation(stage)
        candidate_sha = self._candidate_sha(workspace)
        image_digest = _release_digest(workspace)
        if stage in {"production", "signed-publish"} and image_digest != expected_staging_digest:
            raise ReleaseAdapterError("isolated release differs from accepted predecessor")
        snapshot = self._snapshot(workspace, image_digest)
        target_kind = (
            "staging" if stage in {"staging", "publish-dry-run"} else "distribution"
        )
        install_root = self.target_root / target_kind / product_id / stage
        release_id = sha256_text(
            stable_json(
                [
                    candidate_sha,
                    stage,
                    task_contract.get("idempotency_key"),
                    self.journal.contract.scenario_digest,
                ]
            )
        )[:32]
        inject_health_failure = (
            stage == "production"
            and "ONE_POST_DEPLOY_HEALTH_FAILURE" in self.journal.contract.faults
            and not self.journal.consumed("ONE_POST_DEPLOY_HEALTH_FAILURE")
        )
        if inject_health_failure:
            self._seed_rollback_target(install_root)
        transaction = TransactionalDeployer(
            install_root,
            health_probe=(
                (lambda _current: False)
                if inject_health_failure
                else (lambda current: _release_digest(current) == image_digest)
            ),
        ).promote(release_id, snapshot)
        evidence_ref = self._evidence(
            product_id=product_id,
            stage=stage,
            candidate_sha=candidate_sha,
            image_digest=image_digest,
            transaction_status=transaction.status,
        )
        if inject_health_failure:
            fault = self.journal.consume(
                "ONE_POST_DEPLOY_HEALTH_FAILURE",
                point="isolated_post_deploy_health",
                product_id=product_id,
                task_id=str(task_contract.get("task_id") or ""),
                observed={
                    "transaction_status": transaction.status,
                    "rollback": transaction.status == "ROLLED_BACK",
                    "release_id": release_id,
                },
            )
            if transaction.status != "ROLLED_BACK":
                raise ReleaseAdapterError("injected health failure did not roll back")
            receipt = {
                "status": "FAILED_SAFE",
                "reason_code": "deployment_health_failed",
                "product_id": product_id,
                "stage": stage,
                "candidate_sha": candidate_sha,
                "image_digest": image_digest,
                "rollback": "succeeded",
                "evidence_ref": evidence_ref,
                "fault_receipt_digest": str(fault["receipt_digest"]),
            }
            raise ReleaseOperationFailed(
                "The declared isolated post-deploy health fault rolled back safely.",
                reason_code="deployment_health_failed",
                receipt_ref=evidence_ref,
                receipt_result=receipt,
            )
        if transaction.status != "PROMOTED":
            raise ReleaseAdapterError("isolated release did not reach its postcondition")
        staging_only = stage in {"staging", "publish-dry-run"}
        repository = str(proposed.get("repository") or "").strip()
        if not repository:
            repository = f"qualification/{self.journal.contract.scenario_id}"
        envelope = {
            key: proposed[key]
            for key in (
                "schema_version",
                "artifact_id",
                "created_at",
                "producer",
                "policy_digest",
            )
            if key in proposed
        }
        envelope.update(
            {
                "product_id": product_id,
                "status": "completed",
                "repository": repository,
                "candidate_sha": candidate_sha,
                "merge": {
                    "performed": not staging_only,
                    "merge_sha": None if staging_only else candidate_sha,
                },
                "release": {
                    "version": self._version(workspace),
                    "image_digest": image_digest,
                },
                "staging": "deployed",
                "production": "not_started" if staging_only else "deployed",
                "rollback": "not_tested" if staging_only else "not_needed",
                "summary": "Independent clean-canary adapter completed an isolated transaction.",
                "findings": [],
                "evidence_refs": [evidence_ref],
            }
        )
        return envelope

    def reconcile(self, **values: Any) -> Mapping[str, Any]:
        return self.execute(**values)
