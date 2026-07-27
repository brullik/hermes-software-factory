"""Deterministic lifecycle coordinator for the role/task delivery pipeline."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .artifacts import ArtifactStore, artifact_metadata
from .common import new_id, sha256_text
from .config import FactoryConfig
from .registry import SchemaRegistry
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


def _task_id(product_id: str, stage: str) -> str:
    return f"T-{sha256_text(f'{product_id}:{stage}')[:12].upper()}"


class PipelineCoordinator:
    """Create the next bounded task only after its predecessor is accepted."""

    def __init__(self, config: FactoryConfig, state: StateStore, artifacts: ArtifactStore | None = None) -> None:
        self.config = config
        self.state = state
        self.artifacts = artifacts or ArtifactStore(config)
        self.schemas = SchemaRegistry(config, self.artifacts)
        self.workflow = WorkflowEngine(state)

    def _definition(self, product_id: str, stage: str) -> StageDefinition:
        planning_conflict = f"product:{product_id}:planning"
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
                planning_conflict,
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
                planning_conflict,
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
                planning_conflict,
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
                planning_conflict,
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
                f"product:{product_id}:src",
                60,
                ("package-integrity", "unit-tests", "python-compile", "lint", "typecheck", "secret-scan", "manifest", "sbom"),
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
                f"product:{product_id}:tests",
                55,
                ("unit-tests", "pilot-tests", "python-compile", "lint", "typecheck", "secret-scan", "manifest", "sbom"),
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
                f"product:{product_id}:assurance",
                50,
                ("secret-scan",),
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
                f"product:{product_id}:assurance",
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
                f"product:{product_id}:release",
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
                f"product:{product_id}:assurance",
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
                f"product:{product_id}:release",
                30,
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
    ) -> Path:
        definition = self._definition(product_id, stage)
        task_id = _task_id(product_id, stage)
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
            contract = {
                **artifact_metadata(self.config, "task-specifier", new_id("task_contract"), product_id),
                "task_id": task_id,
                "title": definition.title,
                "objective": definition.objective,
                "dependencies": list(dependencies),
                "conflict_keys": [definition.conflict_key],
                "allowed_paths": list(definition.allowed_paths),
                "forbidden_paths": ["secrets/**", "production/**", ".github/workflows/**"],
                "acceptance": [
                    {
                        "criterion_id": f"AC-{stage.upper().replace('-', '_')}-001",
                        "verification": definition.acceptance,
                        "mandatory": True,
                    }
                ],
                "risk_tier": definition.risk_tier,
                "complexity_features": ["external_integration"] if definition.model_floor != "luna" else [],
                "model_floor": definition.model_floor,
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
            dependencies=list(dependencies),
            conflict_keys=[definition.conflict_key],
            priority=definition.priority,
        )
        return path

    def seed_initial(self, product_id: str) -> Path:
        return self.create_task(product_id, "product-director")

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
            return [
                self.create_task(product_id, "builder-core", dependencies=(task_id,)),
                self.create_task(product_id, "test-engineer", dependencies=(task_id,)),
                self.create_task(product_id, "security-reviewer", dependencies=(task_id,)),
            ]
        if role in {"builder", "test-engineer", "security-reviewer"}:
            self._transition_if(product_id, "BACKLOG_READY", "IMPLEMENTING")
            roles = {"builder", "test-engineer", "security-reviewer"}
            completed_roles = {
                str(item.get("role"))
                for item in self.state.list_tasks(product_id)
                if item.get("status") == "DONE"
            }
            # The worker advances the DAG while the current task is still leased;
            # count the accepted current result without weakening the durable
            # dependency check used by the next claim.
            completed_roles.add(role)
            if roles <= completed_roles:
                dependencies = tuple(
                    str(item["task_id"])
                    for item in self.state.list_tasks(product_id)
                    if str(item.get("role")) in roles
                )
                return [self.create_task(product_id, "independent-reviewer", dependencies=dependencies)]
            return []
        if role == "independent-reviewer":
            self._transition_if(product_id, "IMPLEMENTING", "INTEGRATING")
            return [self.create_task(product_id, "release-staging", dependencies=(task_id,))]
        if role == "release-operator" and str(task.get("title")) == "Prepare Staging Release":
            self._transition_if(product_id, "INTEGRATING", "STAGING_DEPLOYED")
            return [self.create_task(product_id, "product-tester", dependencies=(task_id,))]
        if role == "product-tester":
            if bool(output.get("release_blocked")):
                return []
            self._transition_if(product_id, "STAGING_DEPLOYED", "PRODUCT_ACCEPTANCE")
            self._transition_if(product_id, "PRODUCT_ACCEPTANCE", "RELEASE_READY")
            return [self.create_task(product_id, "release-production", dependencies=(task_id,))]
        if role == "release-operator" and str(task.get("title")) == "Promote Approved Release":
            self._transition_if(product_id, "RELEASE_READY", "PRODUCTION_DEPLOYED")
            self._transition_if(product_id, "PRODUCTION_DEPLOYED", "OBSERVATION")
        return []
