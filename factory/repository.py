"""Idempotent repository bootstrap and protected private-repository access."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

from .common import redact_text, sha256_text, stable_json, utc_now
from .config import FactoryConfig
from .github import GitHubAdapter, GitHubCommandError
from .proof_obligations import SideEffectProtocol
from .providers import ExternalBlocker
from .state import StateStore


class RepositoryAdapter(Protocol):
    def create_repository(
        self,
        *,
        name: str,
        visibility: str,
        description: str,
        idempotency_key: str,
    ) -> str: ...

    def clone(
        self,
        *,
        repository_url: str,
        destination: Path,
        idempotency_key: str,
    ) -> tuple[str, str]: ...

    def bootstrap_commit(
        self,
        *,
        workspace: Path,
        default_branch: str,
        idempotency_key: str,
    ) -> str: ...


class ConfiguredRepositoryAdapter:
    """Deterministic GitHub/git adapter; credentials never cross model boundary."""

    def __init__(self, config: FactoryConfig) -> None:
        self.config = config
        self.owner = str(config.raw.get("github", {}).get("owner", "")).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", self.owner):
            raise ValueError("configured GitHub owner is invalid")

    @staticmethod
    def _run(argv: list[str], *, cwd: Path | None = None) -> str:
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "GCM_INTERACTIVE": "Never",
            }
        )
        try:
            result = subprocess.run(
                argv,
                cwd=cwd,
                env=environment,
                text=True,
                capture_output=True,
                timeout=300,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise RuntimeError(
                f"repository adapter command unavailable: {type(error).__name__}"
            ) from error
        if result.returncode != 0:
            safe, _ = redact_text((result.stdout + "\n" + result.stderr).strip())
            raise RuntimeError(
                f"repository adapter command failed ({result.returncode}): {safe[:500]}"
            )
        return result.stdout.strip()

    def create_repository(
        self,
        *,
        name: str,
        visibility: str,
        description: str,
        idempotency_key: str,
    ) -> str:
        adapter = GitHubAdapter(self.owner, name)
        adapter.require_authentication()
        try:
            adapter.repository_view()
        except GitHubCommandError:
            adapter.create_repository(visibility=visibility, description=description)
        return f"https://github.com/{self.owner}/{name}"

    def clone(
        self,
        *,
        repository_url: str,
        destination: Path,
        idempotency_key: str,
    ) -> tuple[str, str]:
        if destination.exists() and (destination / ".git").is_dir():
            default_branch = self._run(
                ["git", "-C", str(destination), "branch", "--show-current"]
            ) or "main"
            try:
                starting_sha = self._run(
                    ["git", "-C", str(destination), "rev-parse", "HEAD"]
                )
            except RuntimeError:
                starting_sha = ""
            return default_branch, starting_sha
        if destination.exists() and any(destination.iterdir()):
            raise RuntimeError("repository clone destination is not empty")
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._run(
            [
                "gh",
                "repo",
                "clone",
                repository_url,
                str(destination),
                "--",
                "--no-tags",
            ],
            cwd=destination.parent,
        )
        default_branch = self._run(
            ["git", "-C", str(destination), "branch", "--show-current"]
        ) or "main"
        try:
            starting_sha = self._run(
                ["git", "-C", str(destination), "rev-parse", "HEAD"]
            )
        except RuntimeError:
            # A newly created remote is valid but has no HEAD until the neutral
            # bootstrap commit is pushed.
            starting_sha = ""
        return default_branch, starting_sha

    def bootstrap_commit(
        self,
        *,
        workspace: Path,
        default_branch: str,
        idempotency_key: str,
    ) -> str:
        try:
            existing = self._run(
                ["git", "-C", str(workspace), "rev-parse", "HEAD"]
            )
        except RuntimeError:
            existing = ""
        if re.fullmatch(r"[a-f0-9]{40}", existing):
            return existing
        readme = workspace / "README.md"
        decision = workspace / "LICENSE-DECISION.md"
        gitignore = workspace / ".gitignore"
        readme.write_text(
            "# Product bootstrap\n\n"
            "This neutral repository was created by Hermes Software Factory. "
            "The accepted product plan owns all application content.\n",
            encoding="utf-8",
            newline="\n",
        )
        decision.write_text(
            "# License decision\n\nNo public license selected yet.\n",
            encoding="utf-8",
            newline="\n",
        )
        gitignore.write_text(
            ".env\n*.key\n*.pem\n__pycache__/\n*.pyc\n",
            encoding="utf-8",
            newline="\n",
        )
        self._run(
            ["git", "-C", str(workspace), "checkout", "-B", default_branch]
        )
        self._run(
            [
                "git",
                "-C",
                str(workspace),
                "add",
                "--",
                ".gitignore",
                "README.md",
                "LICENSE-DECISION.md",
            ]
        )
        self._run(
            [
                "git",
                "-C",
                str(workspace),
                "-c",
                "user.name=Hermes Software Factory",
                "-c",
                "user.email=hermes-factory@localhost",
                "commit",
                "-m",
                "Initialize product repository",
            ]
        )
        self._run(
            ["git", "-C", str(workspace), "push", "-u", "origin", default_branch]
        )
        return self._run(["git", "-C", str(workspace), "rev-parse", "HEAD"])


class RepositoryBootstrapper:
    def __init__(
        self,
        config: FactoryConfig,
        state: StateStore,
        adapter: RepositoryAdapter,
    ) -> None:
        self.config = config
        self.state = state
        self.adapter = adapter

    @staticmethod
    def _name(product: Mapping[str, Any]) -> str:
        configured = str(product.get("repository_name") or "").strip()
        if configured:
            return configured
        base = re.sub(r"[^a-z0-9]+", "-", str(product["product_id"]).lower()).strip("-")
        return base[:90] or f"product-{sha256_text(str(product['product_id']))[:8]}"

    def ensure(self, product_id: str, destination: Path) -> dict[str, str]:
        """Bootstrap through one crash-safe intent and verified receipt.

        Repository creation, clone and the neutral bootstrap push form one
        idempotent adapter operation.  A restart may reconcile that operation,
        but it cannot silently execute it without the original durable intent
        or create a second receipt.
        """

        product = self.state.get_product(product_id)
        if product is None:
            raise KeyError(product_id)
        mode = str(product.get("delivery_mode") or "")
        if mode not in {"new_repository", "existing_repository"}:
            raise ValueError("canonical repository delivery_mode is missing")
        expected_postcondition = {
            "product_id": product_id,
            "delivery_mode": mode,
            "repository_name": self._name(product),
            "repository_visibility": str(
                product.get("repository_visibility") or "private"
            ),
            "repository_url": (
                "controller-assigned"
                if mode == "new_repository"
                else str(product.get("repository_url") or "")
            ),
            "workspace": str(destination.resolve()),
            "terminal_state": "READY",
        }
        side_effect_key = sha256_text(
            stable_json(["repository-bootstrap-v1", expected_postcondition])
        )
        with self.state._lock, self.state._connection:
            protocol = SideEffectProtocol(self.state._connection)
            intent_id = protocol.prepare(
                product_id=product_id,
                operation="repository:bootstrap",
                adapter="configured-repository-adapter",
                idempotency_key=side_effect_key,
                expected_postcondition=expected_postcondition,
            )
            status = protocol.status(intent_id)
            prior = protocol.verified_result(intent_id)
            if status == "PREPARED":
                protocol.mark_executing(intent_id)

        result = self._ensure_adapter(product_id, destination)
        if set(result) != {
            "repository_url",
            "default_branch",
            "starting_sha",
            "bootstrap_sha",
        }:
            raise RuntimeError("repository bootstrap returned an invalid receipt")
        if prior is not None and prior != result:
            raise RuntimeError("repository bootstrap reconciliation conflicts with receipt")
        if prior is None:
            receipt_digest = sha256_text(stable_json(result))
            with self.state._lock, self.state._connection:
                SideEffectProtocol(self.state._connection).verify(
                    intent_id=intent_id,
                    receipt_ref=f"state://repository-saga/{product_id}",
                    receipt_digest=receipt_digest,
                    observed_postcondition=expected_postcondition,
                    result=result,
                )
        return result

    def _ensure_adapter(self, product_id: str, destination: Path) -> dict[str, str]:
        product = self.state.get_product(product_id)
        if product is None:
            raise KeyError(product_id)
        mode = str(product.get("delivery_mode") or "")
        if mode not in {"new_repository", "existing_repository"}:
            raise ValueError("canonical repository delivery_mode is missing")
        key = sha256_text(f"repository-bootstrap:{product_id}")
        visibility = str(product.get("repository_visibility") or "private")
        name = self._name(product)
        with self.state._lock, self.state._connection:
            saga = self.state._connection.execute(
                "SELECT * FROM repository_sagas WHERE product_id=?", (product_id,)
            ).fetchone()
            if saga is None:
                self.state._connection.execute(
                    """INSERT INTO repository_sagas
                       (product_id, idempotency_key, repository_url,
                        repository_name, visibility, state, updated_at)
                       VALUES (?, ?, ?, ?, ?, 'RESERVED', ?)""",
                    (
                        product_id,
                        key,
                        product.get("repository_url"),
                        name,
                        visibility,
                        utc_now(),
                    ),
                )
                saga = self.state._connection.execute(
                    "SELECT * FROM repository_sagas WHERE product_id=?",
                    (product_id,),
                ).fetchone()
            assert saga is not None
            saga_state = dict(saga)
        try:
            repository_url = str(
                saga_state.get("repository_url")
                or product.get("repository_url")
                or ""
            )
            if mode == "new_repository" and not repository_url:
                repository_url = self.adapter.create_repository(
                    name=name,
                    visibility=visibility,
                    description=f"Hermes product {product_id}",
                    idempotency_key=f"{key}:create",
                )
                with self.state._lock, self.state._connection:
                    self.state._connection.execute(
                        """UPDATE repository_sagas SET repository_url=?,
                               state='REPOSITORY_CREATED', updated_at=?
                           WHERE product_id=?""",
                        (repository_url, utc_now(), product_id),
                    )
            default_branch, starting_sha = self.adapter.clone(
                repository_url=repository_url,
                destination=destination,
                idempotency_key=f"{key}:clone",
            )
            bootstrap_sha = starting_sha
            persisted_bootstrap = str(saga_state.get("bootstrap_sha") or "")
            if mode == "new_repository" and not persisted_bootstrap:
                bootstrap_sha = self.adapter.bootstrap_commit(
                    workspace=destination,
                    default_branch=default_branch,
                    idempotency_key=f"{key}:bootstrap",
                )
            elif persisted_bootstrap:
                bootstrap_sha = persisted_bootstrap
            if not starting_sha:
                starting_sha = bootstrap_sha
            with self.state._lock, self.state._connection:
                self.state._connection.execute(
                    """UPDATE repository_sagas SET state='READY',
                           repository_url=?, default_branch=?, bootstrap_sha=?,
                           last_error=NULL, updated_at=? WHERE product_id=?""",
                    (
                        repository_url,
                        default_branch,
                        bootstrap_sha,
                        utc_now(),
                        product_id,
                    ),
                )
                self.state._connection.execute(
                    """UPDATE products SET repository_url=?, default_branch=?,
                           starting_sha=?, bootstrap_sha=?,
                           repository_bootstrap_state='READY', updated_at=?
                       WHERE product_id=?""",
                    (
                        repository_url,
                        default_branch,
                        starting_sha,
                        bootstrap_sha,
                        utc_now(),
                        product_id,
                    ),
                )
                self.state._record_event(
                    product_id,
                    None,
                    "repository_ready",
                    {
                        "repository_url": repository_url,
                        "default_branch": default_branch,
                        "bootstrap_sha": bootstrap_sha,
                    },
                )
            return {
                "repository_url": repository_url,
                "default_branch": default_branch,
                "starting_sha": starting_sha,
                "bootstrap_sha": bootstrap_sha,
            }
        except ExternalBlocker:
            raise
        except Exception as error:
            safe, _ = redact_text(str(error))
            with self.state._lock, self.state._connection:
                self.state._connection.execute(
                    """UPDATE repository_sagas SET state='FAILED',
                           last_error=?, updated_at=? WHERE product_id=?""",
                    (safe[:1000], utc_now(), product_id),
                )
                self.state._connection.execute(
                    """UPDATE products SET repository_bootstrap_state='FAILED',
                           updated_at=? WHERE product_id=?""",
                    (utc_now(), product_id),
                )
            if "credential" in safe.lower() or "authentication" in safe.lower():
                raise ExternalBlocker(
                    "GitHub credential is unavailable for repository bootstrap",
                    reason_code="missing_credential",
                ) from error
            raise RuntimeError("repository bootstrap adapter failed") from error


def build_repository_bootstrapper(
    config: FactoryConfig, state: StateStore
) -> RepositoryBootstrapper:
    return RepositoryBootstrapper(
        config,
        state,
        ConfiguredRepositoryAdapter(config),
    )
