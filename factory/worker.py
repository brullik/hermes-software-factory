"""Provider-backed, fail-closed task execution for the factory controller."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from scripts.model_router import Tier
from scripts.policy_guard import enforce_changed_paths
from scripts.prompt_compiler import find_secret_candidates

from .artifacts import ArtifactStore, artifact_metadata
from .attempts import Attempt, AttemptManager, IdenticalAttemptError
from .common import new_id, redact_text, sha256_file, sha256_text, stable_json
from .config import FactoryConfig, load_config
from .context_builder import ContextBuilder
from .pipeline import PipelineCoordinator
from .prompting import PromptCompiler
from .providers import ExternalBlocker, ModelSelection, ProviderRegistry
from .quality import QualityGateEngine
from .registry import SchemaRegistry
from .release import ReleaseExecutor, ReleasePolicyError, validate_release_operation
from .state import StateStore
from .workflow import WorkflowEngine
from .workspace import WorkspaceManager

_ALIAS_BY_TIER = {
    Tier.LUNA: "economy",
    Tier.TERRA: "standard",
    Tier.SOL: "expert",
}
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.:/-]+$")


@dataclass(frozen=True)
class HermesRunResult:
    status: str
    output: str
    output_digest: str
    reason_code: str | None = None
    usage_path: str | None = None


class HermesRunner(Protocol):
    def run(
        self,
        *,
        selection: ModelSelection,
        prompt: str,
        cwd: Path,
        usage_path: Path | None = None,
    ) -> HermesRunResult: ...


class SubprocessHermesRunner:
    """Run Hermes with a fixed argv and a deliberately small environment."""

    def __init__(
        self,
        *,
        binary: str = "hermes",
        timeout_seconds: int = 900,
        max_output_chars: int = 100_000,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
        if max_output_chars < 1:
            raise ValueError("max_output_chars must be positive")
        self.binary = binary
        self.timeout_seconds = timeout_seconds
        self.max_output_chars = max_output_chars
        self.environment = dict(environment) if environment is not None else None

    def build_argv(self, selection: ModelSelection, prompt: str, usage_path: Path | None) -> list[str]:
        provider = selection.cli_provider or selection.provider
        if not _SAFE_NAME.fullmatch(provider) or not _SAFE_NAME.fullmatch(selection.model):
            raise ValueError("provider and model identifiers contain unsafe characters")
        argv = [
            self.binary,
            "--model",
            selection.model,
            "--provider",
            provider,
            "--oneshot",
            prompt,
            "--no-restore-cwd",
        ]
        if usage_path is not None:
            argv.extend(["--usage-file", str(usage_path)])
        return argv

    def _environment(self) -> dict[str, str]:
        if self.environment is not None:
            return dict(self.environment)
        allowed = {
            "HOME",
            "PATH",
            "HERMES_HOME",
            "XDG_CONFIG_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
            "LANG",
            "LC_ALL",
            "NO_COLOR",
            "PYTHONUNBUFFERED",
        }
        return {key: value for key, value in os.environ.items() if key in allowed}

    def run(
        self,
        *,
        selection: ModelSelection,
        prompt: str,
        cwd: Path,
        usage_path: Path | None = None,
    ) -> HermesRunResult:
        if find_secret_candidates(prompt):
            raise ValueError("Prompt compilation rejected secret-like content")
        if len(prompt) > self.max_output_chars:
            raise ValueError("prompt exceeds the worker input limit")
        if not cwd.is_dir():
            return HermesRunResult("FAIL", "", sha256_text("missing_cwd"), "workspace_missing")
        if usage_path is not None:
            usage_path.parent.mkdir(parents=True, exist_ok=True)
        argv = self.build_argv(selection, prompt, usage_path)
        try:
            completed = subprocess.run(
                argv,
                cwd=cwd,
                env=self._environment(),
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as error:
            raw = str(error)
            safe, _ = redact_text(raw)
            return HermesRunResult("TIMEOUT", safe[: self.max_output_chars], sha256_text(safe), "network_timeout")
        except OSError as error:
            raw = str(error)
            safe, _ = redact_text(raw)
            return HermesRunResult("FAIL", safe[: self.max_output_chars], sha256_text(safe), "process_crash_before_result")
        raw = (completed.stdout + "\n" + completed.stderr).strip()
        safe, _ = redact_text(raw)
        safe = safe[: self.max_output_chars]
        if completed.returncode == 0:
            return HermesRunResult("PASS", safe, sha256_text(safe), None, str(usage_path) if usage_path else None)
        return HermesRunResult("FAIL", safe, sha256_text(safe), "process_crash_before_result")


@dataclass(frozen=True)
class TaskExecutionSpec:
    task_contract: dict[str, Any]
    role: str
    output_schema: str
    subject_sha: str
    candidates: tuple[tuple[str, str], ...] = ()
    evidence: tuple[dict[str, str], ...] = ()
    decisions: tuple[str, ...] = ()
    attempt_kind: str = "initial"
    new_evidence: bool = False


@dataclass(frozen=True)
class WorkerResult:
    task_id: str
    status: str
    reason_code: str | None
    artifact_ref: str | None = None
    attempt_id: str | None = None


def _workspace_snapshot(root: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in root.rglob("*"):
        if path.name == ".lease.json":
            continue
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            snapshot[relative] = f"SYMLINK:{path.resolve()}"
        elif path.is_file():
            snapshot[relative] = sha256_file(path)
    return snapshot


def ensure_initial_product_task(
    config: FactoryConfig,
    state: StateStore,
    artifacts: ArtifactStore,
    product_id: str,
) -> Path:
    """Create the first durable task exactly once for a newly accepted idea."""
    return PipelineCoordinator(config, state, artifacts).seed_initial(product_id)


class AgentWorker:
    """Claim one task, execute one bounded provider call, and persist evidence."""

    def __init__(
        self,
        config: FactoryConfig,
        state: StateStore,
        *,
        runner: HermesRunner | None = None,
        health_probe: Callable[[ModelSelection], bool] | None = None,
        repository_root: Path | None = None,
        release_executor: ReleaseExecutor | None = None,
        worker_id: str = "hermes-worker-1",
        poll_seconds: float = 2.0,
    ) -> None:
        if poll_seconds < 0.1:
            raise ValueError("poll_seconds is too small")
        self.config = config
        self.state = state
        self.worker_id = worker_id
        self.poll_seconds = poll_seconds
        self.repository_root = (repository_root or Path.cwd()).resolve()
        self.release_executor = release_executor
        configured_worktrees = Path(str(config.raw["paths"]["worktrees"]))
        if os.name == "nt" and str(configured_worktrees).replace("\\", "/").startswith("/var/"):
            configured_worktrees = config.state_dir / "worktrees"
        self.workspace = WorkspaceManager(configured_worktrees, source_root=self.repository_root)
        self.artifacts = ArtifactStore(config)
        self.schemas = SchemaRegistry(config, self.artifacts)
        self.registry = ProviderRegistry(config)
        routing_policy = next(
            (path for path in config.policy_paths() if path.name == "model-routing-policy.yaml"),
            None,
        )
        if routing_policy is None:
            raise FileNotFoundError("model-routing-policy.yaml")
        self.attempts = AttemptManager(state, routing_policy)
        self.workflow = WorkflowEngine(state)
        self.pipeline = PipelineCoordinator(config, state, self.artifacts)
        self.quality = QualityGateEngine(config, self.artifacts)
        self.runner = runner or SubprocessHermesRunner()
        self.health_probe = health_probe or self._live_health_probe

    def _live_health_probe(self, selection: ModelSelection) -> bool:
        probe = self.runner.run(
            selection=selection,
            prompt='Return exactly {"status":"PASS"} and no other text.',
            cwd=self.workspace.root,
        )
        return probe.status == "PASS"

    def default_spec(self, task: Mapping[str, Any]) -> TaskExecutionSpec:
        task_id = str(task["task_id"])
        contract_path = self.config.evidence_dir / f"task-{task_id}.json"
        if not contract_path.is_file():
            raise ExternalBlocker(f"Task Contract is missing for {task_id}")
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        if not isinstance(contract, dict):
            raise ExternalBlocker(f"Task Contract is not an object for {task_id}")
        self.schemas.validate("task-contract.schema.json", contract)
        role = str(task.get("role") or contract.get("producer", {}).get("role", ""))
        output_schema = str(task.get("output_schema") or "")
        if not role or not output_schema:
            raise ExternalBlocker(f"Task role metadata is missing for {task_id}")
        prompt_role = role.replace("_", "-")
        subject_sha = os.environ.get("FACTORY_SUBJECT_SHA", "")
        if not re.fullmatch(r"[a-f0-9]{7,64}", subject_sha):
            subject_file = self.repository_root / "SHA256SUMS"
            subject_sha = sha256_file(subject_file) if subject_file.is_file() else sha256_text(stable_json(contract))
        product = self.state.get_product(str(task["product_id"])) or {}
        idea = str(product.get("idea", "redacted owner idea"))
        return TaskExecutionSpec(
            task_contract=contract,
            role=prompt_role,
            output_schema=output_schema,
            subject_sha=subject_sha,
            candidates=(
                (f"schemas/{output_schema}", "required output contract"),
                (f"prompts/roles/{prompt_role}.md", "role boundary"),
            ),
            evidence=(
                {
                    "type": "idea-intake",
                    "summary": f"Owner idea is UNTRUSTED_DATA: {idea}",
                    "artifact_ref": f"evidence/intake-{task['product_id']}.json",
                },
            ),
            decisions=("Use safe defaults for unspecified reversible product details.",),
        )

    def _select(self, tier: Tier) -> ModelSelection:
        alias = _ALIAS_BY_TIER.get(tier)
        if alias is None:
            raise ExternalBlocker("deterministic tasks do not use the provider worker")
        selected = self.registry.selected_model(alias)
        if not selected:
            raise ExternalBlocker(f"Model route for alias {alias} is not approved")
        for provider in self.registry.providers_for(alias):
            candidate = ModelSelection(
                provider,
                alias,
                selected,
                tier.value,
                self.registry.cli_provider_name(provider),
            )
            if self.health_probe(candidate):
                self.registry.set_health(provider, True)
                break
            self.registry.set_health(provider, False)
        return self.registry.select(alias, tier=tier.value)

    def _context_and_prompt(self, spec: TaskExecutionSpec) -> tuple[str, str, Path]:
        task = spec.task_contract
        acceptance = [str(item["verification"]) for item in task["acceptance"]]
        context = ContextBuilder(self.config, self.repository_root, self.artifacts).build(
            product_id=str(task["product_id"]),
            task_id=str(task["task_id"]),
            subject_sha=spec.subject_sha,
            objective=str(task["objective"]),
            acceptance=acceptance,
            candidates=spec.candidates,
            allowed_paths=[str(path) for path in task["allowed_paths"]],
            forbidden_actions=[str(path) for path in task["forbidden_paths"]],
            output_schema=spec.output_schema,
            evidence=spec.evidence,
            decisions=list(spec.decisions),
        )
        prompt_context = {
            "task_contract": task,
            "context_pack": context.artifact,
        }
        prompt = PromptCompiler(self.config).compile(
            role=spec.role,
            context_pack=prompt_context,
            output_schema=spec.output_schema,
        )
        return prompt.prompt, prompt.digest, context.path

    def _accepted_staging_digest(self, product_id: str) -> str | None:
        """Read the immutable digest from the durable staging operation artifact."""

        candidates = sorted(
            self.config.evidence_dir.glob(
                f"release-operation-result-{product_id}-*.json"
            ),
            key=lambda path: path.stat().st_mtime_ns,
            reverse=True,
        )
        for path in candidates:
            try:
                artifact = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(artifact, dict) or artifact.get("staging") != "deployed":
                continue
            release = artifact.get("release")
            if isinstance(release, dict):
                digest = release.get("image_digest")
                if isinstance(digest, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
                    return digest
        return None

    def _attempt_artifact(
        self,
        spec: TaskExecutionSpec,
        attempt: Attempt,
        selection: ModelSelection,
        *,
        status: str,
        summary: str,
        prompt_digest: str,
        subject_sha: str,
        command_result: str,
        command_ref: str | None,
        output_ref: str | None,
        reason_code: str | None,
        gate_results: list[dict[str, Any]] | None = None,
        changed_files: list[dict[str, str]] | None = None,
    ) -> Path:
        findings: list[dict[str, str]] = []
        if reason_code:
            findings.append({"code": reason_code, "severity": "medium", "text": summary})
        test_results = [
            {
                "gate_id": "schema-validation",
                "status": "PASS" if output_ref else "NOT_RUN",
                "evidence_ref": output_ref,
            }
        ]
        if gate_results:
            test_results.extend(gate_results)
        evidence_refs: list[str] = []
        for ref in (output_ref, command_ref, *(item.get("evidence_ref") for item in test_results)):
            if ref and ref not in evidence_refs:
                evidence_refs.append(ref)
        artifact = {
            **artifact_metadata(self.config, spec.role, new_id("attempt-result"), str(spec.task_contract["product_id"])),
            "producer": {
                "role": spec.role,
                "tier": attempt.tier.value,
                "provider": selection.provider,
                "model": selection.model,
            },
            "task_id": attempt.task_id,
            "attempt_id": attempt.attempt_id,
            "tier": attempt.tier.value,
            "attempt_kind": attempt.attempt_kind,
            "prompt_digest": prompt_digest,
            "subject_sha_before": subject_sha,
            "status": status,
            "summary": summary,
            "changed_files": changed_files or [],
            "commands": [{"command_id": "hermes-oneshot", "result": command_result, "artifact_ref": command_ref}],
            "test_results": test_results,
            "assumptions": ["The provider route was selected only after the configured health probe."],
            "findings": findings,
            "evidence_refs": evidence_refs,
        }
        return self.artifacts.write(
            "attempt-result.schema.json",
            artifact,
            filename=f"attempt-{attempt.attempt_id}.json",
        )

    def _route(self, spec: TaskExecutionSpec, tier: Tier, *, success: bool, reason_code: str | None) -> str:
        decision = self.attempts.route(
            task_id=str(spec.task_contract["task_id"]),
            role=spec.role.replace("-", "_"),
            risk=str(spec.task_contract["risk_tier"]),
            complexity_score=max(1, len(spec.task_contract["complexity_features"])),
            tier=tier,
            success=success,
            reason_code=reason_code,
            new_evidence=spec.new_evidence,
        )
        return decision.action

    def execute(self, spec: TaskExecutionSpec) -> WorkerResult:
        self.schemas.validate("task-contract.schema.json", spec.task_contract)
        if spec.role == "release-operator" and self.release_executor is None:
            raise ExternalBlocker("release side-effect adapter is not configured")
        tier = Tier(str(spec.task_contract["model_floor"]))
        selection = self._select(tier)
        prompt, prompt_digest, context_path = self._context_and_prompt(spec)
        try:
            attempt = self.attempts.begin(
                task_id=str(spec.task_contract["task_id"]),
                tier=tier,
                attempt_kind=spec.attempt_kind,
                prompt_digest=prompt_digest,
            )
        except IdenticalAttemptError as error:
            raise ExternalBlocker(str(error)) from error
        lease = self.workspace.acquire(
            product_id=str(spec.task_contract["product_id"]),
            task_id=str(spec.task_contract["task_id"]),
            worker_id=self.worker_id,
        )
        before_snapshot = _workspace_snapshot(lease.path)
        usage_path = self.config.evidence_dir / f"usage-{attempt.attempt_id}.json"
        try:
            run = self.runner.run(
                selection=selection,
                prompt=prompt,
                cwd=lease.path,
                usage_path=usage_path,
            )
            if run.status != "PASS":
                self.attempts.finish(attempt, status="failed", reason_code=run.reason_code)
                route_action = self._route(spec, tier, success=False, reason_code=run.reason_code)
                result_path = self._attempt_artifact(
                    spec,
                    attempt,
                    selection,
                    status="blocked_external" if run.reason_code == "missing_credential" else "failed_safe",
                    summary=f"Hermes did not return a usable result; routing={route_action}.",
                    prompt_digest=prompt_digest,
                    subject_sha=spec.subject_sha,
                    command_result="fail",
                    command_ref=str(context_path),
                    output_ref=None,
                    reason_code=run.reason_code,
                )
                return WorkerResult(str(spec.task_contract["task_id"]), "failed_safe", run.reason_code, str(result_path), attempt.attempt_id)
            if find_secret_candidates(run.output):
                raise ValueError("secret_exposure")
            output = json.loads(run.output)
            if not isinstance(output, dict):
                raise TypeError("malformed_transport")
            self.schemas.validate(spec.output_schema, output)
            if spec.role == "release-operator":
                stage = "staging" if "staging" in str(spec.task_contract.get("title", "")).lower() else "production"
                assert self.release_executor is not None
                expected_staging_digest = (
                    self._accepted_staging_digest(str(spec.task_contract["product_id"]))
                    if stage == "production"
                    else None
                )
                try:
                    authoritative = self.release_executor.execute(
                        stage=stage,
                        proposed=output,
                        product_id=str(spec.task_contract["product_id"]),
                        task_contract=spec.task_contract,
                        workspace=lease.path,
                        expected_staging_digest=expected_staging_digest,
                    )
                except ExternalBlocker:
                    self.attempts.finish(attempt, status="failed", reason_code="release_adapter_blocked")
                    route_action = self._route(spec, tier, success=False, reason_code="release_adapter_blocked")
                    result_path = self._attempt_artifact(
                        spec,
                        attempt,
                        selection,
                        status="blocked_external",
                        summary=f"Release side-effect adapter blocked the operation; routing={route_action}.",
                        prompt_digest=prompt_digest,
                        subject_sha=spec.subject_sha,
                        command_result="fail",
                        command_ref=str(context_path),
                        output_ref=None,
                        reason_code="release_adapter_blocked",
                    )
                    return WorkerResult(
                        str(spec.task_contract["task_id"]),
                        "blocked_external",
                        "release_adapter_blocked",
                        str(result_path),
                        attempt.attempt_id,
                    )
                except (OSError, RuntimeError, ValueError):
                    self.attempts.finish(attempt, status="failed", reason_code="release_adapter_error")
                    route_action = self._route(spec, tier, success=False, reason_code="release_adapter_error")
                    result_path = self._attempt_artifact(
                        spec,
                        attempt,
                        selection,
                        status="failed_safe",
                        summary=f"Release side-effect adapter failed; routing={route_action}.",
                        prompt_digest=prompt_digest,
                        subject_sha=spec.subject_sha,
                        command_result="fail",
                        command_ref=str(context_path),
                        output_ref=None,
                        reason_code="release_adapter_error",
                    )
                    return WorkerResult(
                        str(spec.task_contract["task_id"]),
                        "failed_safe",
                        "release_adapter_error",
                        str(result_path),
                        attempt.attempt_id,
                    )
                if not isinstance(authoritative, Mapping):
                    raise TypeError("release_adapter_result")
                output = dict(authoritative)
                self.schemas.validate(spec.output_schema, output)
                try:
                    validate_release_operation(
                        output,
                        stage=stage,
                        expected_staging_digest=expected_staging_digest,
                    )
                except ReleasePolicyError as error:
                    raise ValueError("release_policy_violation") from error
            after_snapshot = _workspace_snapshot(lease.path)
            actual_changed_paths = {
                path
                for path in set(before_snapshot) | set(after_snapshot)
                if before_snapshot.get(path) != after_snapshot.get(path)
            }
            reported_changed_files = output.get("changed_files", [])
            reported_changed_paths = {
                str(item.get("path"))
                for item in reported_changed_files
                if isinstance(item, dict) and item.get("path")
            }
            scope_violations = enforce_changed_paths(
                actual_changed_paths | reported_changed_paths,
                [str(path) for path in spec.task_contract["allowed_paths"]],
                [str(path) for path in spec.task_contract["forbidden_paths"]],
            )
            if scope_violations:
                self.attempts.finish(attempt, status="failed", reason_code="scope_violation")
                route_action = self._route(spec, tier, success=False, reason_code="scope_violation")
                result_path = self._attempt_artifact(
                    spec,
                    attempt,
                    selection,
                    status="failed_safe",
                    summary=(
                        "Workspace scope violation detected for "
                        f"{', '.join(sorted(scope_violations)[:20])}; routing={route_action}."
                    ),
                    prompt_digest=prompt_digest,
                    subject_sha=spec.subject_sha,
                    command_result="fail",
                    command_ref=str(context_path),
                    output_ref=None,
                    reason_code="scope_violation",
                    changed_files=reported_changed_files if isinstance(reported_changed_files, list) else None,
                )
                return WorkerResult(
                    str(spec.task_contract["task_id"]),
                    "failed_safe",
                    "scope_violation",
                    str(result_path),
                    attempt.attempt_id,
                )
            changed_files = reported_changed_files if isinstance(reported_changed_files, list) else None
            output_path = self.artifacts.write(
                spec.output_schema,
                output,
                filename=f"{spec.output_schema.removesuffix('.schema.json')}-{spec.task_contract['product_id']}-{attempt.attempt_id}.json",
            )
            quality_run = self.quality.run(
                cwd=lease.path,
                subject_sha=spec.subject_sha,
                task_id=str(spec.task_contract["task_id"]),
                attempt_id=attempt.attempt_id,
                gate_ids=[str(gate) for gate in spec.task_contract.get("quality_gates", [])],
            )
            if not quality_run.mandatory_passed:
                self.attempts.finish(attempt, status="failed", reason_code="mandatory_gate_failed")
                route_action = self._route(spec, tier, success=False, reason_code="mandatory_gate_failed")
                result_path = self._attempt_artifact(
                    spec,
                    attempt,
                    selection,
                    status="failed_safe",
                    summary=f"Mandatory quality gate failed; routing={route_action}.",
                    prompt_digest=prompt_digest,
                    subject_sha=spec.subject_sha,
                    command_result="fail",
                    command_ref=str(context_path),
                    output_ref=str(output_path),
                    reason_code="mandatory_gate_failed",
                    gate_results=list(quality_run.results),
                    changed_files=changed_files,
                )
                return WorkerResult(
                    str(spec.task_contract["task_id"]),
                    "failed_safe",
                    "mandatory_gate_failed",
                    str(result_path),
                    attempt.attempt_id,
                )
            output_status = str(output.get("status"))
            if output_status not in {"completed", "accepted"}:
                self.attempts.finish(attempt, status="repair_required", reason_code="model_requested_repair")
                route_action = self._route(spec, tier, success=False, reason_code="model_requested_repair")
                result_path = self._attempt_artifact(
                    spec,
                    attempt,
                    selection,
                    status="repair_required" if output_status == "repair_required" else "blocked_external",
                    summary=f"The provider returned a schema-valid non-completed result; routing={route_action}.",
                    prompt_digest=prompt_digest,
                    subject_sha=spec.subject_sha,
                    command_result="pass",
                    command_ref=str(context_path),
                    output_ref=str(output_path),
                    reason_code="model_requested_repair",
                    gate_results=list(quality_run.results),
                    changed_files=changed_files,
                )
                return WorkerResult(str(spec.task_contract["task_id"]), output_status, "model_requested_repair", str(result_path), attempt.attempt_id)
            self.attempts.finish(attempt, status="completed")
            self._route(spec, tier, success=True, reason_code=None)
            result_path = self._attempt_artifact(
                spec,
                attempt,
                selection,
                status="completed",
                summary=f"Hermes returned a schema-valid {spec.role} result.",
                prompt_digest=prompt_digest,
                subject_sha=spec.subject_sha,
                command_result="pass",
                command_ref=str(context_path),
                output_ref=str(output_path),
                reason_code=None,
                gate_results=list(quality_run.results),
                changed_files=changed_files,
            )
            task_row = self.state.get_task(str(spec.task_contract["task_id"]))
            if task_row is None:
                raise RuntimeError(f"Durable task disappeared: {spec.task_contract['task_id']}")
            self.pipeline.advance_after(task_row, output, output_path)
            return WorkerResult(str(spec.task_contract["task_id"]), "completed", None, str(result_path), attempt.attempt_id)
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            reason = str(error) if str(error) in {
                "secret_exposure",
                "malformed_transport",
                "release_policy_violation",
            } else "malformed_transport"
            self.attempts.finish(attempt, status="failed", reason_code=reason)
            route_action = self._route(spec, tier, success=False, reason_code=reason)
            result_path = self._attempt_artifact(
                spec,
                attempt,
                selection,
                status="failed_safe",
                summary=f"Hermes output was rejected before it could become an artifact; routing={route_action}.",
                prompt_digest=prompt_digest,
                subject_sha=spec.subject_sha,
                command_result="pass",
                command_ref=str(context_path),
                output_ref=None,
                reason_code=reason,
            )
            return WorkerResult(str(spec.task_contract["task_id"]), "failed_safe", reason, str(result_path), attempt.attempt_id)
        finally:
            self.workspace.release(lease)

    def run_once(self) -> WorkerResult | None:
        task = self.workflow.claim(self.worker_id)
        if task is None:
            return None
        task_id = str(task["task_id"])
        try:
            result = self.execute(self.default_spec(task))
        except ExternalBlocker as error:
            result = WorkerResult(task_id, "blocked_external", str(error))
        except (OSError, RuntimeError, TypeError, ValueError):
            result = WorkerResult(task_id, "failed_safe", "worker_internal_error")
        terminal = {
            "completed": "DONE",
            "accepted": "DONE",
            "blocked_external": "BLOCKED_EXTERNAL",
            "repair_required": "BLOCKED_EXTERNAL",
            "failed_safe": "FAILED_SAFE",
        }.get(result.status, "FAILED_SAFE")
        self.workflow.complete(task_id, self.worker_id, terminal)
        return result

    def run_forever(self) -> None:
        while True:
            result = self.run_once()
            if result is None:
                time.sleep(self.poll_seconds)


def main() -> int:
    parser = argparse.ArgumentParser(description="Hermes Software Factory provider-backed worker")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--worker-id", default="hermes-worker-1")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    config = load_config(args.config)
    state = StateStore(
        config.database_path,
        max_active_workers=config.max_active_workers,
        max_active_products=config.max_active_products,
    )
    state.recover_expired_leases()
    worker = AgentWorker(config, state, worker_id=args.worker_id)
    try:
        if args.once:
            result = worker.run_once()
            print(json.dumps({"status": "IDLE" if result is None else result.status, "task_id": result and result.task_id}))
            return 0 if result is None or result.status == "completed" else 2
        worker.run_forever()
    finally:
        state.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
