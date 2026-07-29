"""Deterministic lifecycle coordinator for the role/task delivery pipeline."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .artifacts import ArtifactStore, artifact_metadata
from .common import new_id, sha256_text
from .config import FactoryConfig
from .registry import SchemaRegistry
from .repair_brief import normalized_repair_findings, repair_requirements
from .state import StateStore
from .workflow import WorkflowEngine


@dataclass(frozen=True)
class StageDefinition:
    key: str
    title: str
    role: str
    output_schema: str
    model_floor: str
    risk_tier: str
    objective: str
    acceptance: str
    allowed_paths: tuple[str, ...]
    conflict_key: str
    priority: int
    quality_gates: tuple[str, ...] = ()


def _task_id(product_id: str, stage: str, cycle: int = 0) -> str:
    suffix = stage if cycle == 0 else f"{stage}:repair:{cycle}"
    return f"T-{sha256_text(f'{product_id}:{suffix}')[:12].upper()}"


def _external_github_repository(value: str) -> bool:
    return bool(
        re.fullmatch(
            r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?",
            value.strip(),
        )
    )


class PipelineCoordinator:
    """Create the next bounded task only after its predecessor is accepted."""

    def __init__(self, config: FactoryConfig, state: StateStore, artifacts: ArtifactStore | None = None) -> None:
        self.config = config
        self.state = state
        self.artifacts = artifacts or ArtifactStore(config)
        self.schemas = SchemaRegistry(config, self.artifacts)
        self.workflow = WorkflowEngine(state)

    @staticmethod
    def _safe_repository_path(value: object) -> str:
        text = str(value)
        path = PurePosixPath(text)
        if (
            not text
            or "\\" in text
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("PM task contains an unsafe repository path")
        return text

    def _pm_active_task(self, product_id: str) -> dict[str, Any] | None:
        product = self.state.get_product(product_id) or {}
        if not _external_github_repository(str(product.get("idea", ""))):
            return None
        workspace = (self.config.worktrees_dir / product_id / "repository").resolve()
        expected_parent = (self.config.worktrees_dir / product_id).resolve()
        if workspace.parent != expected_parent:
            raise ValueError("product workspace escaped the configured worktree root")
        path = workspace / "pm_acceptance" / "active_task.json"
        if not path.is_file() or path.is_symlink():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema") != "pm_active_task_v1":
            raise ValueError("active PM task has an unsupported schema")
        task_id = str(payload.get("task_id", ""))
        if not re.fullmatch(r"[A-Za-z0-9._-]{4,160}", task_id):
            raise ValueError("active PM task id is invalid")

        normalized: dict[str, list[str]] = {}
        for field in ("allowed_paths", "forbidden_paths", "required_paths"):
            values = payload.get(field)
            if (
                not isinstance(values, list)
                or (field != "forbidden_paths" and not values)
                or len(values) > 200
            ):
                raise ValueError(f"active PM task {field} is invalid")
            normalized[field] = list(
                dict.fromkeys(self._safe_repository_path(value) for value in values)
            )
        if not set(normalized["required_paths"]).issubset(normalized["allowed_paths"]):
            raise ValueError("active PM required paths are outside its allowed scope")
        return {"task_id": task_id, **normalized}

    def _restore_external_base_for_repair(
        self,
        product_id: str,
        failed_task: dict[str, Any],
    ) -> None:
        """Discard a failed published candidate before a new scoped repair."""

        product = self.state.get_product(product_id) or {}
        if not _external_github_repository(str(product.get("idea", ""))):
            return
        role = str(failed_task.get("role") or "")
        if role not in {"release-operator", "product-tester"}:
            return
        workspace = (self.config.worktrees_dir / product_id / "repository").resolve()
        expected_parent = (self.config.worktrees_dir / product_id).resolve()
        if workspace.parent != expected_parent:
            raise RuntimeError("external repair workspace is unavailable")
        if not (workspace / ".git").is_dir():
            return

        def run(argv: list[str], *, allowed: tuple[int, ...] = (0,)) -> str:
            try:
                result = subprocess.run(
                    ["git", "-C", str(workspace), *argv],
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=120,
                )
            except (OSError, subprocess.SubprocessError) as error:
                raise RuntimeError("external repair git operation is unavailable") from error
            if result.returncode not in allowed:
                raise RuntimeError("external repair git operation failed")
            return result.stdout.strip()

        run(["fetch", "--prune", "--no-tags", "origin"])
        symbolic = run(
            ["symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"],
            allowed=(0, 1),
        )
        base_branch = symbolic.removeprefix("origin/") if symbolic.startswith("origin/") else "main"
        if not re.fullmatch(r"[A-Za-z0-9._/-]+", base_branch):
            raise RuntimeError("external repair base branch is invalid")
        run(["switch", "--force", "-C", base_branch, f"origin/{base_branch}"])
        run(["reset", "--hard", f"origin/{base_branch}"])
        run(["clean", "-fd", "--", "artifacts", "release-artifacts"])
        branches = run(["branch", "--list", "codex/hermes-*", "--format=%(refname:short)"])
        for branch in branches.splitlines():
            if re.fullmatch(r"codex/hermes-[A-Za-z0-9._/-]+", branch):
                run(["branch", "-D", branch], allowed=(0, 1))
        self.state.record_event(
            product_id=product_id,
            task_id=str(failed_task["task_id"]),
            event_type="failed_candidate_discarded",
            payload={"base_branch": base_branch},
        )

    def _definition(self, product_id: str, stage: str) -> StageDefinition:
        workspace_conflict = f"product:{product_id}:workspace"
        product = self.state.get_product(product_id) or {}
        external_repository = _external_github_repository(str(product.get("idea", "")))
        implementation_gates = (
            (
                "target-environment",
                "target-tests",
                "target-compile",
                "target-lint",
                "target-secret-scan",
            )
            if external_repository
            else (
                "package-integrity",
                "unit-tests",
                "python-compile",
                "lint",
                "typecheck",
                "secret-scan",
                "manifest",
                "sbom",
            )
        )
        test_gates = (
            implementation_gates
            if external_repository
            else (
                "unit-tests",
                "pilot-tests",
                "python-compile",
                "lint",
                "typecheck",
                "secret-scan",
                "manifest",
                "sbom",
            )
        )
        security_gates = (
            (
                "target-sast",
                "target-dependency-audit",
                "target-license-check",
                "target-secret-scan",
            )
            if external_repository
            else ("secret-scan",)
        )
        definitions = {
            "product-director": StageDefinition(
                "product-director",
                "Draft Product Contract",
                "product-director",
                "product-contract.schema.json",
                "luna",
                "low",
                "Turn the owner's idea into a validated Product Contract.",
                "Validate the Product Contract against product-contract.schema.json.",
                ("artifacts/**",),
                workspace_conflict,
                100,
            ),
            "product-analyst": StageDefinition(
                "product-analyst",
                "Derive Requirements Package",
                "product-analyst",
                "requirements-package.schema.json",
                "luna",
                "low",
                "Derive traceable requirements and edge cases from the Product Contract.",
                "Validate the Requirements Package and its traceability against the Product Contract.",
                ("artifacts/**",),
                workspace_conflict,
                90,
            ),
            "solution-architect": StageDefinition(
                "solution-architect",
                "Design Architecture Package",
                "solution-architect",
                "architecture-package.schema.json",
                "terra",
                "medium",
                "Design the smallest deployable architecture satisfying the accepted requirements.",
                "Validate architecture boundaries, backup, rollback, capacity, and test strategy.",
                ("artifacts/**",),
                workspace_conflict,
                80,
            ),
            "task-specifier": StageDefinition(
                "task-specifier",
                "Create Backlog DAG",
                "task-specifier",
                "backlog-plan.schema.json",
                "luna",
                "low",
                "Turn the accepted architecture into a small dependency-aware backlog DAG.",
                "Validate task IDs, edges, parallel groups, and critical path in backlog-plan.schema.json.",
                ("artifacts/**",),
                workspace_conflict,
                70,
            ),
            "builder-core": StageDefinition(
                "builder-core",
                "Implement Core Vertical Slice",
                "builder",
                "attempt-result.schema.json",
                "luna",
                "low",
                "Implement the smallest user-visible vertical slice in the leased worktree.",
                "Run the task acceptance commands and report changed files and evidence.",
                ("src/**", "tests/**", "README.md"),
                workspace_conflict,
                60,
                implementation_gates,
            ),
            "test-engineer": StageDefinition(
                "test-engineer",
                "Add Critical Scenario Tests",
                "test-engineer",
                "test-package-result.schema.json",
                "luna",
                "low",
                "Add deterministic tests for the critical journeys and their negative paths.",
                "Validate traceability, mutation or negative check, and coverage expectation.",
                ("tests/**",),
                workspace_conflict,
                55,
                test_gates,
            ),
            "security-reviewer": StageDefinition(
                "security-reviewer",
                "Run Security Review",
                "security-reviewer",
                "security-review-result.schema.json",
                "terra",
                "medium",
                "Review the candidate slice for secrets, trust-boundary, and permission regressions.",
                "Validate the security review result and ensure no blocking finding is hidden.",
                ("artifacts/**",),
                workspace_conflict,
                50,
                security_gates,
            ),
            "independent-reviewer": StageDefinition(
                "independent-reviewer",
                "Perform Independent Review",
                "independent-reviewer",
                "review-result.schema.json",
                "terra",
                "medium",
                "Independently review the immutable candidate against contracts and gate evidence.",
                "Accept only when every mandatory criterion is proven and no blocking finding remains.",
                ("artifacts/**",),
                workspace_conflict,
                45,
            ),
            "release-staging": StageDefinition(
                "release-staging",
                "Prepare Staging Release",
                "release-operator",
                "release-operation-result.schema.json",
                "terra",
                "medium",
                "Prepare and verify the immutable candidate for staging without merging or deploying production.",
                "Record candidate SHA, release digest, staging checks, and rollback readiness.",
                ("artifacts/**", "release-artifacts/**"),
                workspace_conflict,
                40,
            ),
            "product-tester": StageDefinition(
                "product-tester",
                "Execute Staging Product Acceptance",
                "product-tester",
                "product-test-result.schema.json",
                "terra",
                "medium",
                "Exercise the critical user journeys against the isolated staging release.",
                "Accept only when every critical journey passes and release_blocked is false.",
                ("artifacts/**",),
                workspace_conflict,
                35,
            ),
            "release-production": StageDefinition(
                "release-production",
                "Promote Approved Release",
                "release-operator",
                "release-operation-result.schema.json",
                "terra",
                "medium",
                "Promote the exact accepted staging artifact under deployment and backup policy.",
                "Record production health, rollback evidence, and the final immutable release digest.",
                ("artifacts/**", "release-artifacts/**"),
                workspace_conflict,
                30,
            ),
            "observation": StageDefinition(
                "observation",
                "Complete Production Observation",
                "product-tester",
                "product-test-result.schema.json",
                "terra",
                "medium",
                "Verify production health after the configured observation interval.",
                "Confirm critical production journeys remain healthy and no rollback is required.",
                ("artifacts/**",),
                workspace_conflict,
                20,
            ),
        }
        try:
            return definitions[stage]
        except KeyError as error:
            raise ValueError(f"Unknown pipeline stage: {stage}") from error

    def create_task(
        self,
        product_id: str,
        stage: str,
        *,
        dependencies: tuple[str, ...] = (),
        cycle: int = 0,
        available_at: str | None = None,
    ) -> Path:
        definition = self._definition(product_id, stage)
        if cycle < 0:
            raise ValueError("repair cycle cannot be negative")
        task_id = _task_id(product_id, stage, cycle)
        filename = f"task-{task_id}.json"
        path = self.config.evidence_dir / filename
        existing = self.state.get_task(task_id)
        if existing is not None:
            if path.is_file():
                return path
            raise RuntimeError(f"Task {task_id} exists without its contract artifact")
        if path.is_file():
            contract = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(contract, dict):
                raise ValueError(f"Task contract is not an object: {path}")
        else:
            title = definition.title
            objective = definition.objective
            allowed_paths = list(definition.allowed_paths)
            forbidden_paths = ["secrets/**", "production/**", ".github/workflows/**"]
            acceptance = [
                {
                    "criterion_id": f"AC-{stage.upper().replace('-', '_')}-001",
                    "verification": definition.acceptance,
                    "mandatory": True,
                }
            ]
            complexity_features = (
                ["external_integration"] if definition.model_floor != "luna" else []
            )
            model_floor = definition.model_floor
            pm_task = self._pm_active_task(product_id)
            if pm_task is not None and stage in {"builder-core", "test-engineer"}:
                if stage == "builder-core":
                    allowed_paths = list(pm_task["allowed_paths"])
                    objective = (
                        f"Complete active repository PM task {pm_task['task_id']} exactly. "
                        "Modify every required path, preserve all forbidden paths, and make "
                        "the frozen local PM acceptance suite pass. The GitHub required check "
                        "runs later against the immutable candidate."
                    )
                    acceptance = [
                        {
                            "criterion_id": "AC-PM-SCOPE",
                            "verification": (
                                f"The frozen local PM acceptance suite passes for active task "
                                f"{pm_task['task_id']}; downstream GitHub pm-acceptance remains "
                                "the release-stage authority."
                            ),
                            "mandatory": True,
                        },
                        *[
                            {
                                "criterion_id": f"AC-PM-REQUIRED-{index:03d}",
                                "verification": f"Required path is included and correct: {required}",
                                "mandatory": True,
                            }
                            for index, required in enumerate(
                                pm_task["required_paths"],
                                start=1,
                            )
                        ],
                    ]
                else:
                    test_paths = [
                        item for item in pm_task["allowed_paths"] if item.startswith("tests/")
                    ]
                    allowed_paths = test_paths or list(pm_task["allowed_paths"])
                    objective = (
                        f"Validate and complete tests for active repository PM task "
                        f"{pm_task['task_id']} without leaving its exact allowed scope."
                    )
                forbidden_paths = list(
                    dict.fromkeys([*forbidden_paths, *pm_task["forbidden_paths"]])
                )
                complexity_features = ["external_integration", "prior_semantic_failure"]
            if cycle > 0:
                title = f"{definition.title} (repair cycle {cycle})"
                model_floor = "terra" if cycle == 1 else "sol"
                complexity_features = list(
                    dict.fromkeys([*complexity_features, "prior_semantic_failure"])
                )
            contract = {
                **artifact_metadata(self.config, "task-specifier", new_id("task_contract"), product_id),
                "task_id": task_id,
                "title": title,
                "objective": objective,
                "dependencies": list(dependencies),
                "conflict_keys": [definition.conflict_key],
                "allowed_paths": allowed_paths,
                "forbidden_paths": forbidden_paths,
                "acceptance": acceptance,
                "risk_tier": definition.risk_tier,
                "complexity_features": complexity_features,
                "model_floor": model_floor,
                "rollback": "Discard the immutable candidate and return the product to the previous safe lifecycle state.",
                "status": "ready",
            }
        if definition.quality_gates and not path.is_file():
            contract["quality_gates"] = list(definition.quality_gates)
        self.schemas.validate("task-contract.schema.json", contract)
        if not path.is_file():
            self.artifacts.write("task-contract.schema.json", contract, filename=filename)
        self.state.add_task(
            task_id=task_id,
            product_id=product_id,
            title=definition.title,
            role=definition.role,
            output_schema=definition.output_schema,
            contract_ref=f"evidence/{filename}",
            stage_key=stage,
            cycle=cycle,
            available_at=available_at,
            dependencies=list(dependencies),
            conflict_keys=[definition.conflict_key],
            priority=definition.priority,
        )
        return path

    def seed_initial(self, product_id: str) -> Path:
        return self.create_task(product_id, "product-director")

    def next_repair_cycle(self, product_id: str) -> int:
        return (
            max(
                (int(task.get("cycle") or 0) for task in self.state.list_tasks(product_id)),
                default=0,
            )
            + 1
        )

    def _repair_requirements(
        self,
        reason_code: str,
        evidence_refs: list[str],
        summary: str,
    ) -> tuple[list[str], list[str]]:
        failed = ["pm-acceptance"] if "pm_acceptance" in reason_code else []
        required_fixes: list[str] = []
        evidence_root = self.config.evidence_dir.resolve()
        pending_refs = list(evidence_refs)
        inspected_refs: set[str] = set()
        while pending_refs and len(inspected_refs) < 50:
            reference = pending_refs.pop(0)
            if reference in inspected_refs:
                continue
            inspected_refs.add(reference)
            candidate = Path(reference)
            if not candidate.is_absolute():
                candidate = evidence_root / candidate.name
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            if (
                resolved.parent != evidence_root
                or not resolved.is_file()
                or resolved.is_symlink()
            ):
                continue
            try:
                payload = json.loads(resolved.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            if (
                payload.get("gate_id")
                and payload.get("status") not in {"PASS", "NOT_RUN"}
            ):
                gate_id = str(payload["gate_id"])
                failed.append(gate_id)
                gate_summary = str(payload.get("summary") or "").strip()
                if gate_summary:
                    required_fixes.append(
                        f"Make controller gate {gate_id} pass. "
                        f"Observed failure: {gate_summary[:2500]}"
                    )
            if payload.get("status") in {
                "repair_required",
                "needs_replan",
                "blocked_external",
            }:
                findings = normalized_repair_findings(payload)
                failed.extend(item.finding_id for item in findings)
                required_fixes.extend(item.required_fix for item in findings)
            test_results = payload.get("test_results", [])
            if not isinstance(test_results, list):
                continue
            for item in test_results:
                if not isinstance(item, dict):
                    continue
                if (
                    item.get("gate_id")
                    and item.get("status") not in {"PASS", "NOT_RUN"}
                ):
                    failed.append(str(item["gate_id"]))
                if item.get("evidence_ref"):
                    pending_refs.append(str(item["evidence_ref"]))
        failed, fallback_fixes = repair_requirements(
            output=None,
            reason_code=reason_code,
            detail=summary,
            failed_gate_ids=failed,
        )
        return sorted(set(failed)), list(
            dict.fromkeys(required_fixes or fallback_fixes)
        )

    def begin_repair_cycle(
        self,
        failed_task: dict[str, Any],
        *,
        reason_code: str,
        summary: str,
        evidence_refs: list[str],
        attempt_id: str | None = None,
        director_replan: bool = False,
        director_instruction: str | None = None,
    ) -> Path | None:
        """Start a bounded build-to-staging repair cycle from the current state."""

        product_id = str(failed_task["product_id"])
        cycle = self.next_repair_cycle(product_id)
        if cycle > self.config.max_repair_cycles and not director_replan:
            return None
        product = self.state.get_product(product_id)
        if product is None:
            raise KeyError(product_id)
        self._restore_external_base_for_repair(product_id, failed_task)
        if str(product["status"]) != "REPAIRING":
            self.workflow.transition(product_id, "REPAIRING")
        task_path = self.create_task(
            product_id,
            "builder-core",
            cycle=cycle,
            available_at="9999-12-31T23:59:59Z",
        )
        contract = json.loads(task_path.read_text(encoding="utf-8"))
        task_id = str(contract["task_id"])
        tier = str(contract["model_floor"])
        failed_gate_ids, required_fixes = self._repair_requirements(
            reason_code,
            evidence_refs,
            summary,
        )
        if director_instruction:
            required_fixes = list(
                dict.fromkeys([director_instruction, *required_fixes])
            )
        brief = {
            **artifact_metadata(
                self.config,
                "repair-coordinator",
                new_id("repair-brief"),
                product_id,
            ),
            "producer": {
                "role": "repair-coordinator",
                "tier": "deterministic",
                "provider": None,
                "model": None,
            },
            "task_id": task_id,
            "attempt_id": attempt_id or new_id("reconcile"),
            "failure_class": reason_code,
            "failed_gate_ids": failed_gate_ids,
            "required_fixes": required_fixes,
            "allowed_paths": [str(value) for value in contract["allowed_paths"]],
            "relevant_log_fragment": summary[:4000],
            "expected_vs_actual": {
                "expected": "all mandatory product and repository acceptance checks pass",
                "actual": summary[:1000],
            },
            "changed_files": [],
            "forbidden_actions": [str(value) for value in contract["forbidden_paths"]],
            "previous_attempt_summary": summary[:2000],
            "definition_of_done": [
                str(item["verification"]) for item in contract["acceptance"]
            ],
            "evidence_refs": list(
                dict.fromkeys(value for value in evidence_refs if value)
            ),
        }
        try:
            brief_path = self.artifacts.write(
                "repair-brief.schema.json",
                brief,
                filename=f"repair-brief-{task_id}-{brief['attempt_id']}.json",
            )
            self.state.prepare_pending_repair(
                task_id,
                next_tier=tier,
                repair_context_ref=f"evidence/{brief_path.name}",
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            self.state.fail_waiting_task(
                task_id,
                reason_code="repair_brief_preparation_failed",
                detail="Repair task could not be activated with validated evidence.",
            )
            raise
        self.state.record_event(
            product_id=product_id,
            task_id=task_id,
            event_type="repair_cycle_started",
            payload={
                "cycle": cycle,
                "reason_code": reason_code,
                "failed_task_id": failed_task["task_id"],
                "director_replan": director_replan,
                "director_reassessment": bool(director_instruction),
            },
        )
        return task_path

    def _transition_if(self, product_id: str, current: str, target: str) -> None:
        product = self.state.get_product(product_id)
        if product is None:
            raise KeyError(product_id)
        status = str(product["status"])
        if status == current:
            self.workflow.transition(product_id, target)
        elif status != target:
            raise ValueError(f"Expected product {product_id} at {current}, got {status}")

    def _write_risk_assessment(self, product_id: str, contract: dict[str, Any], contract_ref: str) -> Path:
        path = self.config.evidence_dir / f"risk-{product_id}.json"
        if path.is_file():
            return path
        markers = sorted({str(marker) for marker in contract.get("risk_markers", [])})
        classification = str(contract.get("data_classification", "internal"))
        high_markers = {"payments", "real_money", "restricted_data", "irreversible_action"}
        tier = "high" if high_markers & set(markers) or classification == "restricted" else "medium" if classification == "confidential" else "low"
        controls = ["secret_scan", "independent_review", "backup_restore", "rollback"]
        if tier != "low":
            controls.append("security_review")
        visibility = str(contract.get("repository_visibility", "private"))
        production_policy = {
            "low": "auto_current_vps",
            "medium": "auto_if_capacity",
            "high": "staging_only",
        }[tier]
        artifact = {
            **artifact_metadata(self.config, "risk-engine", new_id("risk_assessment"), product_id),
            "tier": tier,
            "markers": markers,
            "data_classification": classification,
            "required_controls": sorted(set(controls)),
            "repository_visibility": visibility,
            "production_policy": production_policy,
            "summary": f"Deterministic risk classification: {tier}.",
            "evidence_refs": [contract_ref],
        }
        self.schemas.validate("risk-assessment.schema.json", artifact)
        self.artifacts.write("risk-assessment.schema.json", artifact, filename=path.name)
        return path

    def advance_after(self, task: dict[str, Any], output: dict[str, Any], output_path: Path) -> list[Path]:
        """Advance lifecycle and enqueue the next stage after a valid result."""
        if output.get("status") not in {"completed", "accepted"}:
            return []
        product_id = str(task["product_id"])
        role = str(task.get("role") or "")
        task_id = str(task["task_id"])
        stage_key = str(task.get("stage_key") or "")
        cycle = int(task.get("cycle") or 0)
        if role == "product-director":
            self._transition_if(product_id, "IDEA_RECEIVED", "CONTRACT_DRAFTED")
            self._transition_if(product_id, "CONTRACT_DRAFTED", "CONTRACT_VALIDATED")
            self._write_risk_assessment(product_id, output, f"evidence/{output_path.name}")
            self._transition_if(product_id, "CONTRACT_VALIDATED", "RISK_CLASSIFIED")
            return [self.create_task(product_id, "product-analyst", dependencies=(task_id,))]
        if role == "product-analyst":
            return [self.create_task(product_id, "solution-architect", dependencies=(task_id,))]
        if role == "solution-architect":
            self._transition_if(product_id, "RISK_CLASSIFIED", "ARCHITECTED")
            return [self.create_task(product_id, "task-specifier", dependencies=(task_id,))]
        if role == "task-specifier":
            self._transition_if(product_id, "ARCHITECTED", "BACKLOG_READY")
            return [self.create_task(product_id, "builder-core", dependencies=(task_id,))]
        if role == "builder":
            if cycle > 0:
                self._transition_if(product_id, "REPAIRING", "IMPLEMENTING")
            else:
                self._transition_if(product_id, "BACKLOG_READY", "IMPLEMENTING")
            return [
                self.create_task(
                    product_id,
                    "test-engineer",
                    dependencies=(task_id,),
                    cycle=cycle,
                )
            ]
        if role == "test-engineer":
            return [
                self.create_task(
                    product_id,
                    "security-reviewer",
                    dependencies=(task_id,),
                    cycle=cycle,
                )
            ]
        if role == "security-reviewer":
            return [
                self.create_task(
                    product_id,
                    "independent-reviewer",
                    dependencies=(task_id,),
                    cycle=cycle,
                )
            ]
        if role == "independent-reviewer":
            self._transition_if(product_id, "IMPLEMENTING", "INTEGRATING")
            return [
                self.create_task(
                    product_id,
                    "release-staging",
                    dependencies=(task_id,),
                    cycle=cycle,
                )
            ]
        if role == "release-operator" and str(task.get("title")) == "Prepare Staging Release":
            self._transition_if(product_id, "INTEGRATING", "STAGING_DEPLOYED")
            return [
                self.create_task(
                    product_id,
                    "product-tester",
                    dependencies=(task_id,),
                    cycle=cycle,
                )
            ]
        if stage_key == "release-staging":
            self._transition_if(product_id, "INTEGRATING", "STAGING_DEPLOYED")
            return [
                self.create_task(
                    product_id,
                    "product-tester",
                    dependencies=(task_id,),
                    cycle=cycle,
                )
            ]
        if role == "product-tester":
            if stage_key == "observation":
                self._transition_if(product_id, "OBSERVATION", "COMPLETED")
                return []
            if bool(output.get("release_blocked")):
                return []
            self._transition_if(product_id, "STAGING_DEPLOYED", "PRODUCT_ACCEPTANCE")
            self._transition_if(product_id, "PRODUCT_ACCEPTANCE", "RELEASE_READY")
            return [
                self.create_task(
                    product_id,
                    "release-production",
                    dependencies=(task_id,),
                    cycle=cycle,
                )
            ]
        if (
            role == "release-operator"
            and (
                str(task.get("title")) == "Promote Approved Release"
                or stage_key == "release-production"
            )
        ):
            self._transition_if(product_id, "RELEASE_READY", "PRODUCTION_DEPLOYED")
            self._transition_if(product_id, "PRODUCTION_DEPLOYED", "OBSERVATION")
        return []
