"""Deterministic capability preflight and owner-action boundary."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .autonomy import CAPABILITY_PROFILES, OWNER_ACTION_REASONS
from .common import sha256_file, sha256_text, stable_json, utc_now
from .config import FactoryConfig
from .owner_actions import OwnerActionService
from .proof_obligations import ToolchainManifest
from .state import StateStore


@dataclass(frozen=True)
class CapabilityCheck:
    capability: str
    status: str
    provider: str
    reason_code: str | None = None
    scope: dict[str, Any] | None = None

    def validate(self) -> None:
        if self.status not in {
            "AVAILABLE",
            "MISSING_EXTERNAL",
            "DENIED_POLICY",
            "EXPIRED",
        }:
            raise ValueError("capability check status is invalid")
        if self.status == "MISSING_EXTERNAL" and self.reason_code not in OWNER_ACTION_REASONS:
            raise ValueError("external capability gap is not owner-action eligible")


class CapabilityProbe(Protocol):
    def check(
        self,
        capability: str,
        *,
        product: dict[str, Any],
    ) -> CapabilityCheck: ...


@dataclass(frozen=True)
class ProbeCommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class ConfiguredCapabilityProbe:
    """Scoped read-only probes; credential values never enter a result."""

    def __init__(
        self,
        config: FactoryConfig,
        *,
        command_runner: Any | None = None,
    ) -> None:
        self.config = config
        self.command_runner = command_runner or self._run
        self._github_cache: dict[str, tuple[datetime, dict[str, Any]]] = {}
        self._production_cache: tuple[datetime, dict[str, bool]] | None = None
        self._isolated_attestations = self._load_isolated_attestations()

    def _load_isolated_attestations(self) -> dict[str, CapabilityCheck]:
        qualification = self.config.raw.get("qualification")
        if not isinstance(qualification, dict):
            return {}
        path = Path(str(qualification["capability_attestation_path"]))
        if (
            not path.is_file()
            or path.is_symlink()
            or sha256_file(path) != qualification["capability_attestation_digest"]
        ):
            raise ValueError("isolated capability attestation is unavailable")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version",
            "plane",
            "capabilities",
        }:
            raise ValueError("isolated capability attestation schema is invalid")
        expected_plane = str(qualification.get("plane") or "")
        if (
            payload["schema_version"] != "1.0"
            or payload["plane"] != expected_plane
            or expected_plane not in {"ISOLATED_Q6", "CLEAN_CANARY"}
        ):
            raise ValueError("isolated capability attestation identity is invalid")
        capabilities = payload["capabilities"]
        if not isinstance(capabilities, dict):
            raise TypeError("isolated capability attestations must be an object")
        checks: dict[str, CapabilityCheck] = {}
        allowed_prefixes = ("git.", "github.", "repository.")
        for capability, raw in capabilities.items():
            if (
                not isinstance(capability, str)
                or not capability.startswith(allowed_prefixes)
                or not isinstance(raw, dict)
                or set(raw) != {"status", "scope"}
                or raw["status"] != "AVAILABLE"
                or not isinstance(raw["scope"], dict)
                or raw["scope"].get("allowed_operations") != [capability]
            ):
                raise ValueError("isolated capability attestation entry is invalid")
            checks[capability] = CapabilityCheck(
                capability,
                "AVAILABLE",
                "isolated-qualification-target",
                scope=dict(raw["scope"]),
            )
        return checks

    @staticmethod
    def _run(argv: list[str]) -> ProbeCommandResult:
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "XDG_RUNTIME_DIR": os.environ.get("XDG_RUNTIME_DIR", ""),
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "Never",
            "LANG": "C.UTF-8",
        }
        try:
            completed = subprocess.run(
                argv,
                env=environment,
                stdin=subprocess.DEVNULL,
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ProbeCommandResult(127)
        return ProbeCommandResult(
            completed.returncode,
            completed.stdout[-1_000_000:],
            completed.stderr[-20_000:],
        )

    @staticmethod
    def _response(result: ProbeCommandResult) -> tuple[int | None, dict[str, str], Any]:
        status_match = re.search(r"(?im)^HTTP/\S+\s+(\d{3})\b", result.stdout)
        status = int(status_match.group(1)) if status_match else None
        body_offset = result.stdout.find("{")
        array_offset = result.stdout.find("[")
        offsets = [value for value in (body_offset, array_offset) if value >= 0]
        payload: Any = None
        header_text = result.stdout
        if offsets:
            offset = min(offsets)
            header_text = result.stdout[:offset]
            try:
                payload = json.loads(result.stdout[offset:])
            except json.JSONDecodeError:
                payload = None
        headers: dict[str, str] = {}
        for line in header_text.splitlines():
            name, separator, value = line.partition(":")
            if separator and re.fullmatch(r"[A-Za-z0-9-]+", name.strip()):
                headers[name.strip().lower()] = value.strip()
        return status, headers, payload

    @staticmethod
    def _repository_scope(product: dict[str, Any], config: FactoryConfig) -> tuple[str, str]:
        owner = str(config.raw.get("github", {}).get("owner", "")).strip()
        repository_url = str(product.get("repository_url") or "").strip()
        if repository_url:
            parsed = urlparse(repository_url)
            parts = [value for value in parsed.path.strip("/").split("/") if value]
            if parsed.hostname == "github.com" and len(parts) == 2:
                return parts[0], parts[1].removesuffix(".git")
        repository = str(product.get("repository_name") or "").strip()
        if not repository:
            repository = re.sub(
                r"[^a-z0-9]+",
                "-",
                str(product["product_id"]).lower(),
            ).strip("-")[:90]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(
            r"[A-Za-z0-9_.-]+",
            repository,
        ):
            raise ValueError("GitHub capability scope is invalid")
        return owner, repository

    @staticmethod
    def _permission(payload: Any) -> str:
        permissions = payload.get("permissions", {}) if isinstance(payload, dict) else {}
        if not isinstance(permissions, dict):
            return "none"
        for value in ("admin", "maintain", "push", "triage", "pull"):
            if permissions.get(value) is True:
                return value
        return "none"

    @staticmethod
    def _can_push(permission: str) -> bool:
        return permission in {"admin", "maintain", "push"}

    @staticmethod
    def _can_admin(permission: str) -> bool:
        return permission in {"admin", "maintain"}

    @staticmethod
    def _scope_allows_creation(
        scopes: set[str],
        *,
        visibility: str,
    ) -> bool:
        if "repo" in scopes:
            return True
        return visibility == "public" and "public_repo" in scopes

    def _github_context(self, product: dict[str, Any]) -> dict[str, Any]:
        owner, repository = self._repository_scope(product, self.config)
        cache_key = f"{owner}/{repository}"
        now = datetime.now(UTC)
        cached = self._github_cache.get(cache_key)
        if cached is not None and now - cached[0] < timedelta(seconds=5):
            return cached[1]
        context: dict[str, Any] = {
            "owner": owner,
            "repository": repository,
            "repository_exists": False,
            "identity": "",
            "credential_type": "unknown",
            "oauth_scopes": set(),
            "permission": "none",
            "governance_readable": False,
            "merge_enabled": False,
            "failure_status": "DENIED_POLICY",
            "failure_reason": "controller_github_probe_unverifiable",
        }
        identity_result = self.command_runner(["gh", "api", "-i", "user"])
        status, headers, payload = self._response(identity_result)
        if status in {401, 403} or identity_result.returncode == 4:
            context.update(
                failure_status="MISSING_EXTERNAL",
                failure_reason="missing_credential",
            )
            self._github_cache[cache_key] = (now, context)
            return context
        if status != 200 or not isinstance(payload, dict):
            self._github_cache[cache_key] = (now, context)
            return context
        login = str(payload.get("login") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", login):
            self._github_cache[cache_key] = (now, context)
            return context
        scopes = {
            value.strip()
            for value in headers.get("x-oauth-scopes", "").split(",")
            if value.strip()
        }
        context.update(
            identity=login,
            credential_type=(
                "oauth_or_classic_pat"
                if scopes
                else "fine_grained_pat_or_github_app"
            ),
            oauth_scopes=scopes,
            failure_reason="controller_github_permission_unverifiable",
        )
        repository_result = self.command_runner(
            ["gh", "api", "-i", f"repos/{owner}/{repository}"]
        )
        repository_status, _, repository_payload = self._response(repository_result)
        if repository_status == 200 and isinstance(repository_payload, dict):
            permission = self._permission(repository_payload)
            context.update(
                repository_exists=True,
                permission=permission,
                default_branch=str(repository_payload.get("default_branch") or "main"),
                merge_enabled=any(
                    repository_payload.get(key) is True
                    for key in (
                        "allow_merge_commit",
                        "allow_squash_merge",
                        "allow_rebase_merge",
                    )
                ),
            )
            rulesets_result = self.command_runner(
                ["gh", "api", "-i", f"repos/{owner}/{repository}/rulesets"]
            )
            rulesets_status, _, _ = self._response(rulesets_result)
            branch = str(context["default_branch"])
            protection_result = self.command_runner(
                [
                    "gh",
                    "api",
                    "-i",
                    f"repos/{owner}/{repository}/branches/{branch}/protection",
                ]
            )
            protection_status, _, _ = self._response(protection_result)
            context["governance_readable"] = (
                rulesets_status == 200 and protection_status in {200, 404}
            )
        elif repository_status == 404:
            context["repository_exists"] = False
        elif repository_status in {401, 403}:
            context.update(
                failure_status="DENIED_POLICY",
                failure_reason="controller_github_repository_denied",
            )
        self._github_cache[cache_key] = (now, context)
        return context

    @staticmethod
    def _github_scope_payload(
        context: dict[str, Any],
        capability: str,
    ) -> dict[str, Any]:
        return {
            "owner": str(context["owner"]),
            "repository": str(context["repository"]),
            "allowed_operations": [capability],
            "identity": str(context.get("identity") or ""),
            "credential_type": str(context.get("credential_type") or "unknown"),
            "repository_permission": str(context.get("permission") or "none"),
        }

    def _github_check(
        self,
        capability: str,
        product: dict[str, Any],
    ) -> CapabilityCheck:
        if shutil.which("git") is None or shutil.which("gh") is None:
            return CapabilityCheck(
                capability,
                "DENIED_POLICY",
                "configured-host",
                "controller_tool_missing",
            )
        if capability == "git.commit_candidate":
            return CapabilityCheck(
                capability,
                "AVAILABLE",
                "configured-host",
                scope={"allowed_operations": [capability]},
            )
        context = self._github_context(product)
        scope = self._github_scope_payload(context, capability)
        if not context.get("identity"):
            return CapabilityCheck(
                capability,
                str(context["failure_status"]),
                "github",
                str(context["failure_reason"]),
                scope,
            )
        permission = str(context.get("permission") or "none")
        repository_exists = bool(context.get("repository_exists"))
        identity_is_owner = (
            str(context["identity"]).lower() == str(context["owner"]).lower()
        )
        can_create = identity_is_owner and self._scope_allows_creation(
            set(context.get("oauth_scopes") or ()),
            visibility=str(product.get("repository_visibility") or "private"),
        )
        available = False
        reason = "controller_github_permission_denied"
        if capability in {"repository.read", "repository.read_bounded"}:
            available = repository_exists and permission != "none"
        elif capability == "github.repository.create":
            available = repository_exists or can_create
            reason = "controller_github_creation_unverifiable"
        elif capability in {
            "git.initial_commit",
            "git.push_branch",
            "github.pull_request.create",
        }:
            available = (
                repository_exists and self._can_push(permission)
            ) or (not repository_exists and can_create)
        elif capability == "github.workflow.write":
            scope_allows_workflow = "workflow" in set(
                context.get("oauth_scopes") or ()
            )
            available = (
                (
                    repository_exists
                    and self._can_push(permission)
                    and scope_allows_workflow
                )
                or (
                    not repository_exists
                    and can_create
                    and scope_allows_workflow
                )
            )
            reason = "controller_github_workflow_permission_unverifiable"
        elif capability == "github.repository.configure":
            available = (
                repository_exists
                and self._can_admin(permission)
            ) or (not repository_exists and can_create)
        elif capability in {
            "github.checks.read",
            "github.pull_request.verify",
        }:
            available = repository_exists and permission != "none"
        elif capability == "github.pull_request.merge":
            available = (
                repository_exists
                and self._can_push(permission)
                and bool(context.get("merge_enabled"))
            )
            reason = "controller_github_merge_permission_unverifiable"
        else:
            reason = "controller_github_capability_unverifiable"
        return CapabilityCheck(
            capability,
            "AVAILABLE" if available else "DENIED_POLICY",
            "github",
            None if available else reason,
            scope,
        )

    def _backup_check(self, capability: str) -> CapabilityCheck:
        backup = self.config.raw.get("backup", {})
        configured = (
            isinstance(backup, dict)
            and backup.get("tool") == "restic"
            and backup.get("offsite_configured") is True
        )
        configured_proof = (
            str(backup.get("proof_path") or "")
            if isinstance(backup, dict)
            else ""
        )
        proof_path = (
            Path(configured_proof)
            if configured_proof
            else self.config.evidence_dir / "backup-latest.json"
        )
        available = False
        scope: dict[str, Any] = {"allowed_operations": [capability]}
        try:
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            completed_at = datetime.fromisoformat(
                str(proof["completed_at"])
            )
            max_age = int(
                backup.get("max_proof_age_seconds", 36 * 60 * 60)
                if isinstance(backup, dict)
                else 36 * 60 * 60
            )
            snapshot_id = str(proof.get("snapshot_id") or "")
            available = bool(
                configured
                and proof.get("status") == "PASS"
                and proof.get("restic_check") == "PASS"
                and proof.get("repository_kind") == "offsite"
                and re.fullmatch(r"[a-f0-9]{8,64}", snapshot_id)
                and datetime.now(UTC) - completed_at <= timedelta(seconds=max_age)
            )
            scope.update(
                {
                    "snapshot_fingerprint": sha256_text(snapshot_id)[:16],
                    "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
                }
            )
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            available = False
        return CapabilityCheck(
            capability,
            "AVAILABLE" if available else "DENIED_POLICY",
            "restic-proof",
            None if available else "controller_backup_proof_unavailable",
            scope,
        )

    @staticmethod
    def _trusted_executable(path: Path) -> bool:
        try:
            metadata = path.stat()
        except OSError:
            return False
        return bool(
            path.is_file()
            and not path.is_symlink()
            and metadata.st_uid == 0
            and not metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            and metadata.st_mode & stat.S_IXUSR
        )

    def _production_context(self) -> dict[str, bool]:
        now = datetime.now(UTC)
        if (
            self._production_cache is not None
            and now - self._production_cache[0] < timedelta(seconds=5)
        ):
            return self._production_cache[1]
        deployment = self.config.raw.get("deployment", {})
        helper = Path(str(deployment.get("production_helper") or ""))
        rollback = Path(
            str(
                deployment.get("rollback_helper")
                or "/opt/hermes-factory/bin/factory-rollback"
            )
        )
        sudo = shutil.which("sudo") or "/usr/bin/sudo"
        boundary = self.command_runner(
            [sudo, "-n", str(helper), "--help"]
        ).returncode == 0 if helper.is_absolute() else False
        health_url = str(
            deployment.get("health_probe_url")
            or "http://127.0.0.1:8787/healthz"
        )
        healthy = False
        if health_url.startswith("http://127.0.0.1:"):
            try:
                with urlopen(
                    Request(health_url, headers={"User-Agent": "hermes-capability-probe"}),
                    timeout=5,
                ) as response:
                    payload = json.loads(response.read(65536).decode("utf-8"))
                    healthy = (
                        response.status == 200
                        and isinstance(payload, dict)
                        and payload.get("status") == "PASS"
                    )
            except (OSError, URLError, ValueError, json.JSONDecodeError):
                healthy = False
        context = {
            "production_helper": self._trusted_executable(helper),
            "rollback_helper": self._trusted_executable(rollback),
            "sudo_boundary": boundary,
            "target_health": healthy,
        }
        self._production_cache = (now, context)
        return context

    def _toolchain_check(self, capability: str) -> CapabilityCheck:
        available = False
        scope: dict[str, Any] = {"allowed_operations": [capability]}
        reason = "controller_toolchain_unavailable"
        if capability == "toolchain.python":
            interpreter = Path(sys.executable)
            version = self.command_runner(
                [
                    str(interpreter),
                    "-c",
                    (
                        "import importlib.metadata as m,platform;"
                        "print(platform.python_version());"
                        "print(m.version('pip'));print(m.version('pytest'))"
                    ),
                ]
            )
            available = interpreter.is_file() and version.returncode == 0
            scope["runtime"] = str(interpreter)
            scope["includes"] = ["pip", "pytest"]
            scope["exact_versions"] = version.stdout.strip().splitlines()
            reason = "controller_toolchain_python_missing"
        elif capability == "toolchain.make":
            make = shutil.which("make")
            version = self.command_runner([make, "--version"]) if make else None
            available = bool(version is not None and version.returncode == 0)
            scope["runtime"] = str(make or "")
            scope["exact_version"] = (
                version.stdout.strip().splitlines()[0]
                if version is not None and version.stdout.strip()
                else ""
            )
            reason = "controller_toolchain_make_missing"
        elif capability == "toolchain.container_builder":
            selected = ""
            podman = shutil.which("podman")
            if podman is not None:
                info = self.command_runner(
                    ["podman", "info", "--format", "{{.Store.RunRoot}}"]
                )
                runroot = info.stdout.strip().splitlines()[-1] if info.stdout.strip() else ""
                expected_runtime = os.environ.get("XDG_RUNTIME_DIR", "").strip()
                expected_runroot = (
                    os.path.normpath(os.path.join(expected_runtime, "containers"))
                    if expected_runtime
                    else ""
                )
                normalized_runroot = os.path.normpath(runroot) if runroot else ""
                scope.update(
                    {
                        "runtime": "podman",
                        "runroot": normalized_runroot,
                        "network_preflight": "required",
                    }
                )
                if info.returncode != 0 or not normalized_runroot:
                    reason = "controller_toolchain_container_builder_unavailable"
                elif expected_runroot and normalized_runroot != expected_runroot:
                    reason = "controller_toolchain_container_storage_scope_mismatch"
                else:
                    ipam_database = Path(normalized_runroot) / "networks" / "ipam.db"
                    try:
                        metadata = ipam_database.stat()
                        current_uid = getattr(os, "geteuid", lambda: metadata.st_uid)()
                        ownership_safe = bool(
                            os.name == "nt"
                            or (
                                metadata.st_uid == current_uid
                                and stat.S_IMODE(metadata.st_mode) == 0o600
                            )
                        )
                        ipam_ready = bool(
                            ipam_database.is_file()
                            and not ipam_database.is_symlink()
                            and ownership_safe
                            and os.access(ipam_database, os.R_OK | os.W_OK)
                        )
                    except OSError:
                        ipam_ready = False
                    if not ipam_ready:
                        reason = "controller_toolchain_container_network_uninitialized"
                    else:
                        network_name = f"hermes-capability-preflight-{os.getpid()}"
                        created = self.command_runner(
                            ["podman", "network", "create", network_name]
                        )
                        removed = (
                            self.command_runner(
                                ["podman", "network", "rm", network_name]
                            )
                            if created.returncode == 0
                            else ProbeCommandResult(1)
                        )
                        if created.returncode == 0 and removed.returncode == 0:
                            selected = "podman"
                            version = self.command_runner(["podman", "--version"])
                            if version.returncode != 0:
                                selected = ""
                            else:
                                scope["exact_version"] = version.stdout.strip()
                        else:
                            reason = "controller_toolchain_container_network_unavailable"
            available = bool(selected)
            if selected:
                scope["runtime"] = selected
                reason = "controller_toolchain_container_builder_unavailable"
        elif capability == "toolchain.scanners":
            root = Path(__file__).resolve().parents[1]
            scanner = Path("/usr/local/bin/osv-scanner")
            version = self.command_runner([str(scanner), "--version"])
            available = (
                (root / "config" / "quality-gates.yaml").is_file()
                and (root / "scripts" / "quality_gate.py").is_file()
                and self._trusted_executable(scanner)
                and version.returncode == 0
            )
            scope["scanner"] = str(scanner)
            scope["exact_version"] = version.stdout.strip()
            reason = "controller_toolchain_scanner_missing"
        return CapabilityCheck(
            capability,
            "AVAILABLE" if available else "DENIED_POLICY",
            "controller-toolchain",
            None if available else reason,
            scope,
        )

    def check(
        self,
        capability: str,
        *,
        product: dict[str, Any],
    ) -> CapabilityCheck:
        if capability in self._isolated_attestations:
            return self._isolated_attestations[capability]
        if capability.startswith("toolchain."):
            return self._toolchain_check(capability)
        if capability.startswith(("github.", "git.")) or capability in {
            "repository.read",
            "repository.read_bounded",
        }:
            return self._github_check(capability, product)
        if capability == "staging.deploy":
            writable = self.config.worktrees_dir
            try:
                writable.mkdir(parents=True, exist_ok=True)
                available = os.access(writable, os.W_OK)
            except OSError:
                available = False
            return CapabilityCheck(
                capability,
                "AVAILABLE" if available else "DENIED_POLICY",
                "configured-host",
                None if available else "controller_staging_unwritable",
            )
        if capability == "backup.verify":
            return self._backup_check(capability)
        if capability in {"production.deploy_transactional", "rollback.execute"}:
            context = self._production_context()
            available = bool(
                context["sudo_boundary"]
                and context["target_health"]
                and context["production_helper"]
                and (
                    capability != "rollback.execute"
                    or context["rollback_helper"]
                )
            )
            return CapabilityCheck(
                capability,
                "AVAILABLE" if available else "DENIED_POLICY",
                "production-boundary",
                None if available else "controller_production_boundary_unavailable",
                {
                    "allowed_operations": [capability],
                    **context,
                },
            )
        return CapabilityCheck(
            capability,
            "DENIED_POLICY",
            "configured-host",
            "controller_capability_unknown",
            scope={"allowed_operations": [capability]},
        )


class CapabilityBroker:
    """Persist capability facts and route internal gaps to controller incidents."""

    def __init__(
        self,
        config: FactoryConfig,
        state: StateStore,
        probe: CapabilityProbe | None = None,
    ) -> None:
        self.config = config
        self.state = state
        self.probe = probe or ConfiguredCapabilityProbe(config)
        self.owner_actions = OwnerActionService(config)

    @staticmethod
    def required_for_product(product: dict[str, Any]) -> tuple[str, ...]:
        from .delivery_profiles import delivery_profile
        from .lifecycle import stage_contract

        selected_profile = delivery_profile(
            str(product.get("delivery_profile") or "DEPLOYED_SERVICE")
        )
        profiles = ["repository_bootstrap"]
        profiles.extend(
            stage_contract(stage).capability_profile
            for stage in selected_profile.lifecycle
            if stage_contract(stage).capability_profile.startswith("release_")
        )
        capabilities = [
            capability
            for profile in profiles
            for capability in CAPABILITY_PROFILES[profile]
        ]
        capabilities.extend(
            (
                "toolchain.python",
                "toolchain.container_builder",
                "toolchain.scanners",
            )
        )
        if str(product.get("delivery_mode") or "") in {
            "new_repository",
            "existing_repository",
        }:
            capabilities.append("toolchain.make")
        return tuple(
            dict.fromkeys(capabilities)
        )

    def _controller_incident(
        self,
        product_id: str,
        check: CapabilityCheck,
    ) -> str:
        reason = check.reason_code or "controller_capability_unknown"
        incident_id = (
            "incident-"
            + sha256_text(
                stable_json([product_id, check.capability, check.provider, reason])
            )[:20]
        )
        evidence_ref = (
            f"internal://capability/{sha256_text(check.capability)[:16]}"
        )
        with self.state._lock, self.state._connection:
            inserted = self.state._connection.execute(
                """INSERT OR IGNORE INTO controller_incidents
                   (incident_id, product_id, task_id, reason_code,
                    evidence_ref, status, created_at)
                   VALUES (?, ?, NULL, ?, ?, 'OPEN', ?)""",
                (incident_id, product_id, reason, evidence_ref, utc_now()),
            ).rowcount
            if inserted:
                self.state._record_event(
                    product_id,
                    None,
                    "controller_incident_created",
                    {
                        "incident_id": incident_id,
                        "reason_code": reason,
                        "capability": check.capability,
                    },
                )
        return incident_id

    @staticmethod
    def _check_fingerprint(check: CapabilityCheck) -> str:
        return sha256_text(
            stable_json(
                {
                    "capability": check.capability,
                    "status": check.status,
                    "provider": check.provider,
                    "reason_code": check.reason_code,
                    "scope": check.scope or {},
                    "expires_at": None,
                }
            )
        )

    def _persist_check(
        self,
        product_id: str,
        check: CapabilityCheck,
    ) -> tuple[bool, str | None]:
        fingerprint = self._check_fingerprint(check)
        now = utc_now()
        with self.state._lock, self.state._connection:
            previous = self.state._connection.execute(
                """SELECT check_fingerprint, reason_code
                     FROM capability_check_results
                    WHERE product_id=? AND capability=?""",
                (product_id, check.capability),
            ).fetchone()
            self.state._connection.execute(
                """INSERT INTO capability_check_results
                       (product_id, capability, provider, status, reason_code,
                        scope_json, checked_at, expires_at, check_fingerprint)
                   VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)
                   ON CONFLICT(product_id, capability) DO UPDATE SET
                       provider=excluded.provider,
                       status=excluded.status,
                       reason_code=excluded.reason_code,
                       scope_json=excluded.scope_json,
                       checked_at=excluded.checked_at,
                       expires_at=excluded.expires_at,
                       check_fingerprint=excluded.check_fingerprint""",
                (
                    product_id,
                    check.capability,
                    check.provider,
                    check.status,
                    check.reason_code,
                    stable_json(check.scope or {"product_id": product_id}),
                    now,
                    fingerprint,
                ),
            )
        return (
            previous is None or str(previous["check_fingerprint"]) != fingerprint,
            str(previous["reason_code"]) if previous and previous["reason_code"] else None,
        )

    def _open_external_blocks(
        self,
        product_id: str,
        checks: list[CapabilityCheck],
    ) -> bool:
        if not checks:
            return False
        check = checks[0]
        assert check.reason_code in OWNER_ACTION_REASONS
        reason = str(check.reason_code)
        capabilities = sorted({item.capability for item in checks})
        group_id = "capblock-group-" + sha256_text(
            stable_json([product_id, reason])
        )[:20]
        with self.state._lock:
            existing = self.state._connection.execute(
                """SELECT owner_action_ref, notification_outbox_id
                     FROM capability_blocks
                    WHERE product_id=? AND reason_code=? AND status='OPEN'
                    LIMIT 1""",
                (product_id, reason),
            ).fetchone()
        if existing is not None:
            now = utc_now()
            inserted = 0
            with self.state._lock, self.state._connection:
                for capability in capabilities:
                    block_id = "capblock-" + sha256_text(
                        stable_json([product_id, capability, reason])
                    )[:20]
                    inserted += self.state._connection.execute(
                        """INSERT OR IGNORE INTO capability_blocks
                               (block_id, product_id, capability, reason_code,
                                status, owner_action_ref, failure_ref,
                                notification_outbox_id, created_at)
                           VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?, ?)""",
                        (
                            block_id,
                            product_id,
                            capability,
                            reason,
                            str(existing["owner_action_ref"]),
                            f"capability://{sha256_text(block_id)[:20]}",
                            existing["notification_outbox_id"],
                            now,
                        ),
                    ).rowcount
                if inserted:
                    self.state._record_event(
                        product_id,
                        None,
                        "owner_action_scope_expanded",
                        {
                            "reason_code": reason,
                            "capabilities": capabilities,
                            "owner_action_ref": str(existing["owner_action_ref"]),
                        },
                    )
            return bool(inserted)
        action_path = self.owner_actions.create(
            reason=reason,
            title="Требуется внешний доступ",
            why_blocked=(
                "Hermes не получил подтверждение внешнего доступа для "
                f"{', '.join(capabilities)}."
            ),
            single_action=(
                "Подключите требуемый credential через защищённую настройку на VPS."
            ),
            safe_instruction=[
                "Откройте отдельный сеанс PuTTY к VPS.",
                "Выполните официальный OAuth/credential setup для GitHub.",
                "Не отправляйте пароль, token или private key в Telegram.",
            ],
            unblock_probe=f"capability:{product_id}:{reason}",
            unblock_expected="AVAILABLE",
            independent_work_continues=[
                "Hermes продолжит проверять доступ автоматически."
            ],
        )
        notification_id = f"outbox-{sha256_text(group_id)[:24]}"
        now = utc_now()
        with self.state._lock, self.state._connection:
            inserted = 0
            for capability in capabilities:
                block_id = "capblock-" + sha256_text(
                    stable_json([product_id, capability, reason])
                )[:20]
                inserted += self.state._connection.execute(
                    """INSERT INTO capability_blocks
                           (block_id, product_id, capability, reason_code, status,
                            owner_action_ref, failure_ref, notification_outbox_id,
                            created_at)
                       VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?, ?)
                       ON CONFLICT(product_id, capability, reason_code) DO UPDATE SET
                           status='OPEN',
                           owner_action_ref=excluded.owner_action_ref,
                           failure_ref=excluded.failure_ref,
                           notification_outbox_id=excluded.notification_outbox_id,
                           created_at=excluded.created_at,
                           resolved_at=NULL""",
                    (
                        block_id,
                        product_id,
                        capability,
                        reason,
                        f"evidence/{action_path.name}",
                        f"capability://{sha256_text(block_id)[:20]}",
                        notification_id,
                        now,
                    ),
                ).rowcount
            self.state._record_event(
                product_id,
                None,
                "owner_action_required",
                {
                    "reason_code": reason,
                    "capabilities": capabilities,
                    "owner_action_ref": f"evidence/{action_path.name}",
                },
            )
        self.state.enqueue_outbox(
            outbox_id=notification_id,
            idempotency_key=sha256_text(
                f"capability-owner-action:{group_id}"
            ),
            event_type="telegram.owner_notification",
            payload={
                "kind": "owner_action",
                "product_id": product_id,
                "task_id": None,
                "text": (
                    "🟠 Hermes: требуется одно действие владельца.\n"
                    f"Проект: {product_id}\n"
                    f"Доступ: {', '.join(capabilities)}\n"
                    "Подключите credential на VPS; секреты в Telegram не отправляйте. "
                    "После появления доступа Hermes продолжит автоматически."
                ),
            },
        )
        return bool(inserted)

    def _resolve_capability(
        self,
        product_id: str,
        check: CapabilityCheck,
        previous_reason: str | None,
    ) -> int:
        now = utc_now()
        with self.state._lock, self.state._connection:
            notifications = self.state._connection.execute(
                """SELECT notification_outbox_id
                     FROM capability_blocks
                    WHERE product_id=? AND capability=? AND status='OPEN'""",
                (product_id, check.capability),
            ).fetchall()
            resolved = self.state._connection.execute(
                """UPDATE capability_blocks
                      SET status='RESOLVED', resolved_at=?
                    WHERE product_id=? AND capability=? AND status='OPEN'""",
                (now, product_id, check.capability),
            ).rowcount
            for row in notifications:
                if row[0]:
                    still_open = self.state._connection.execute(
                        """SELECT 1 FROM capability_blocks
                            WHERE notification_outbox_id=? AND status='OPEN'
                            LIMIT 1""",
                        (str(row[0]),),
                    ).fetchone()
                    if still_open is None:
                        self.state._connection.execute(
                            """UPDATE outbox
                                  SET status='DONE',
                                      delivered_at=COALESCE(delivered_at, ?),
                                      lease_owner=NULL, lease_until=NULL
                                WHERE outbox_id=? AND status='PENDING'""",
                            (now, str(row[0])),
                        )
            if previous_reason:
                self.state._connection.execute(
                    """UPDATE failures SET status='RESOLVED', last_seen_at=?
                        WHERE product_id=? AND reason_code=?
                          AND status IN ('OPEN','OWNER_BLOCKED')""",
                    (now, product_id, previous_reason),
                )
                self.state._connection.execute(
                    """UPDATE controller_incidents
                          SET status='RESOLVED', resolved_at=?
                        WHERE product_id=? AND reason_code=? AND status='OPEN'
                          AND evidence_ref LIKE 'internal://capability/%'""",
                    (now, product_id, previous_reason),
                )
            if resolved:
                self.state._record_event(
                    product_id,
                    None,
                    "capability_owner_action_resolved",
                    {
                        "capability": check.capability,
                        "resolved_blocks": resolved,
                    },
                )
        return int(resolved)

    def preflight_product(self, product_id: str) -> tuple[CapabilityCheck, ...]:
        product = self.state.get_product(product_id)
        if product is None:
            raise KeyError(product_id)
        results: list[CapabilityCheck] = []
        changed_external: dict[str, list[CapabilityCheck]] = {}
        for capability in self.required_for_product(product):
            check = self.probe.check(capability, product=product)
            check.validate()
            results.append(check)
            changed, previous_reason = self._persist_check(product_id, check)
            self.state.grant_capability(
                product_id=product_id,
                task_id=None,
                capability=capability,
                scope=check.scope or {"product_id": product_id},
                provider=check.provider,
                status=check.status,
                expires_at=None,
            )
            if check.status == "AVAILABLE":
                self._resolve_capability(product_id, check, previous_reason)
            elif changed and check.reason_code in OWNER_ACTION_REASONS:
                changed_external.setdefault(
                    str(check.reason_code),
                    [],
                ).append(check)
            elif changed:
                self._controller_incident(product_id, check)
        for checks in changed_external.values():
            self._open_external_blocks(product_id, checks)
        available_toolchain = [
            check
            for check in results
            if check.capability.startswith("toolchain.") and check.status == "AVAILABLE"
        ]
        if available_toolchain:
            manifest = ToolchainManifest.build(
                controller_release_digest=self.state.controller_release_digest,
                components={
                    "product_binding": sha256_text(product_id),
                    **{
                        check.capability: stable_json(check.scope or {})
                        for check in available_toolchain
                    },
                },
                capabilities=[check.capability for check in available_toolchain],
            )
            with self.state._lock, self.state._connection:
                self.state._connection.execute(
                    """UPDATE toolchain_manifests SET status='SUPERSEDED'
                         WHERE product_id=? AND status='ACTIVE'
                           AND manifest_digest!=?""",
                    (product_id, manifest.manifest_digest),
                )
                self.state._connection.execute(
                    """INSERT OR IGNORE INTO toolchain_manifests
                       (manifest_id,product_id,controller_release_digest,manifest_json,
                        manifest_digest,status,created_at)
                       VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?)""",
                    (
                        manifest.manifest_id,
                        product_id,
                        manifest.controller_release_digest,
                        stable_json(
                            {
                                "product_id": product_id,
                                "components": dict(manifest.components),
                                "capabilities": list(manifest.capabilities),
                            }
                        ),
                        manifest.manifest_digest,
                        manifest.created_at,
                    ),
                )
                self.state.toolchain_manifest_digest = manifest.manifest_digest
        return tuple(results)

    def preflight_all(self) -> dict[str, tuple[CapabilityCheck, ...]]:
        return {
            str(product["product_id"]): self.preflight_product(
                str(product["product_id"])
            )
            for product in self.state.list_products()
            if str(product["status"])
            not in {"CANCELLED", "COMPLETED", "FAILED_SAFE"}
        }


@dataclass(frozen=True)
class CapabilityReconcileResult:
    inspected_products: int = 0
    checks: int = 0
    changed: int = 0
    resumed_tasks: int = 0


class CapabilityReconciler:
    """Durably refresh capability facts for a long-lived controller."""

    def __init__(
        self,
        config: FactoryConfig,
        state: StateStore,
        probe: CapabilityProbe | None = None,
        *,
        ttl_seconds: float | None = None,
        retry_seconds: float | None = None,
    ) -> None:
        self.config = config
        self.state = state
        self.broker = CapabilityBroker(config, state, probe=probe)
        self.ttl_seconds = float(
            ttl_seconds
            if ttl_seconds is not None
            else config.controller.get("capability_check_ttl_seconds", 300)
        )
        self.retry_seconds = float(
            retry_seconds
            if retry_seconds is not None
            else config.controller.get("capability_retry_seconds", 15)
        )
        if self.ttl_seconds < 0 or self.retry_seconds < 0:
            raise ValueError("capability reconciliation intervals cannot be negative")

    def _due_products(self) -> list[str]:
        now = datetime.now(UTC)
        ttl_cutoff = (now - timedelta(seconds=self.ttl_seconds)).replace(
            microsecond=0
        ).isoformat().replace("+00:00", "Z")
        retry_cutoff = (now - timedelta(seconds=self.retry_seconds)).replace(
            microsecond=0
        ).isoformat().replace("+00:00", "Z")
        due: list[str] = []
        with self.state._lock:
            for product in self.state.list_products():
                product_id = str(product["product_id"])
                if str(product["status"]) in {
                    "CANCELLED",
                    "COMPLETED",
                    "FAILED_SAFE",
                }:
                    continue
                expected = self.broker.required_for_product(product)
                checks = self.state._connection.execute(
                    """SELECT capability, status, checked_at
                         FROM capability_check_results
                        WHERE product_id=?""",
                    (product_id,),
                ).fetchall()
                by_capability = {str(row["capability"]): row for row in checks}
                blocked = self.state._connection.execute(
                    """SELECT 1 FROM tasks
                        WHERE product_id=? AND graph_status='BLOCKED_CAPABILITY'
                        LIMIT 1""",
                    (product_id,),
                ).fetchone()
                product_due = False
                for capability in expected:
                    row = by_capability.get(capability)
                    if row is None:
                        product_due = True
                        break
                    cutoff = (
                        retry_cutoff
                        if blocked is not None
                        or str(row["status"])
                        in {"MISSING_EXTERNAL", "DENIED_POLICY", "EXPIRED"}
                        else ttl_cutoff
                    )
                    if str(row["checked_at"]) <= cutoff:
                        product_due = True
                        break
                if product_due:
                    due.append(product_id)
        return due

    def preflight_product(self, product_id: str) -> tuple[CapabilityCheck, ...]:
        return self.broker.preflight_product(product_id)

    def reconcile_once(self) -> CapabilityReconcileResult:
        inspected = 0
        checks = 0
        changed = 0
        resumed = 0
        for product_id in self._due_products():
            with self.state._lock:
                before = {
                    str(row["task_id"])
                    for row in self.state._connection.execute(
                        """SELECT task_id FROM tasks
                            WHERE product_id=?
                              AND graph_status='BLOCKED_CAPABILITY'""",
                        (product_id,),
                    ).fetchall()
                }
                fingerprints = {
                    str(row["capability"]): str(row["check_fingerprint"])
                    for row in self.state._connection.execute(
                        """SELECT capability, check_fingerprint
                             FROM capability_check_results
                            WHERE product_id=?""",
                        (product_id,),
                    ).fetchall()
                }
            results = self.broker.preflight_product(product_id)
            inspected += 1
            checks += len(results)
            with self.state._lock:
                after_fingerprints = {
                    str(row["capability"]): str(row["check_fingerprint"])
                    for row in self.state._connection.execute(
                        """SELECT capability, check_fingerprint
                             FROM capability_check_results
                            WHERE product_id=?""",
                        (product_id,),
                    ).fetchall()
                }
                remaining = {
                    str(row["task_id"])
                    for row in self.state._connection.execute(
                        """SELECT task_id FROM tasks
                            WHERE product_id=?
                              AND graph_status='BLOCKED_CAPABILITY'""",
                        (product_id,),
                    ).fetchall()
                }
            changed += sum(
                fingerprints.get(capability) != fingerprint
                for capability, fingerprint in after_fingerprints.items()
            )
            resumed += len(before - remaining)
        return CapabilityReconcileResult(
            inspected_products=inspected,
            checks=checks,
            changed=changed,
            resumed_tasks=resumed,
        )
