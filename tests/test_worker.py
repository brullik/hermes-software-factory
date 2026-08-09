from __future__ import annotations

import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest
import yaml

from factory.artifacts import ArtifactStore, artifact_metadata
from factory.attempts import IdenticalAttemptError
from factory.autonomy import CAPABILITY_PROFILES, FailureData
from factory.common import sha256_text, stable_json
from factory.config import FactoryConfig
from factory.hermes_stdin import _invoke_hermes, read_stdin_prompt
from factory.intake import IntakeService
from factory.path_governor import PathGovernor, ResultLineageIdentityError
from factory.pipeline import PipelineCoordinator
from factory.plan_semantics import PlanContractViolation
from factory.policy import policy_digest
from factory.proof_obligations import RecoveryCertificateService, SideEffectProtocol
from factory.providers import ExternalBlocker, ModelSelection
from factory.quality import QualityGateRun
from factory.reconciler import PipelineReconciler
from factory.state import StateStore
from factory.worker import (
    AgentWorker,
    HermesRunResult,
    PromptInputLimitError,
    SubprocessHermesRunner,
    TaskExecutionSpec,
    WorkerResult,
    _current_replan_frontier,
    _external_target_execution_context,
    _host_capacity_snapshot,
    _local_file_reference,
    _mandatory_gate_failure_data,
    _normalized_output_status,
    _replanner_failure_inventory,
    _replanner_hypothesis_inventory,
    _replanner_scope_policy,
    _worker_result_digest,
    _workspace_snapshot,
    public_github_repository_url,
)

ROOT = Path(__file__).resolve().parents[1]


def test_worker_result_digest_never_dereferences_internal_uri() -> None:
    fallback = {
        "task_id": "T-INTERNAL-RESULT",
        "status": "completed",
        "reason_code": None,
        "detail": None,
    }

    with patch("factory.worker.Path.is_file") as is_file:
        digest = _worker_result_digest(
            "internal://task/T-INTERNAL-RESULT",
            fallback,
        )

    is_file.assert_not_called()
    assert digest == sha256_text(stable_json(fallback))


def test_failure_envelope_preserves_internal_evidence_uri() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(
            root,
            selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"),
        )
        state = StateStore(config.database_path)
        worker = AgentWorker(
            config,
            state,
            runner=FakeRunner("{}"),
            repository_root=ROOT,
        )
        internal_ref = "internal://task/T-INTERNAL-FAILURE"

        assert _local_file_reference(internal_ref) is None
        sanitized, path = worker._failure_envelope(
            {
                "product_id": "P-INTERNAL-FAILURE",
                "task_id": "T-INTERNAL-FAILURE",
            },
            FailureData(
                failure_class="controller",
                reason_code="controller_exception_permission_error",
                safe_message="Controller result persistence failed safely.",
                evidence_ref=internal_ref,
            ),
        )

        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["evidence_refs"] == [internal_ref]
        assert sanitized.evidence_ref == f"evidence/{path.name}"
        state.close()


def test_default_spec_falls_back_when_optional_subject_manifest_is_inaccessible() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(
            root,
            selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"),
        )
        state = StateStore(config.database_path)
        product_id = "P-OPAQUE-SUBJECT-FALLBACK"
        state.create_product(
            product_id=product_id,
            owner_id="owner",
            source="test",
            idea="Compile a task without relying on inherited cwd access",
            idempotency_key="opaque-subject-fallback",
        )
        PipelineCoordinator(config, state).seed_initial(product_id)
        task = state.list_tasks(product_id)[0]
        repository_root = root / "inaccessible-cwd"
        worker = AgentWorker(
            config,
            state,
            runner=FakeRunner("{}"),
            repository_root=repository_root,
        )

        with patch(
            "factory.worker._local_file_reference",
            return_value=None,
        ) as local_file:
            spec = worker.default_spec(task)

        local_file.assert_called_once_with(str(repository_root / "SHA256SUMS"))
        assert spec.subject_sha == sha256_text(stable_json(spec.task_contract))
        state.close()


def test_host_capacity_snapshot_reports_current_allocations() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(
            root,
            selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"),
        )
        meminfo = root / "meminfo"
        meminfo.write_text(
            "MemTotal:       16384000 kB\nMemAvailable:    8192000 kB\n",
            encoding="utf-8",
        )
        # Linux filesystems may reserve blocks: shutil.disk_usage() then
        # reports used + free < total even though every measurement is valid.
        disk = Mock(total=1_000_000, used=350_000, free=600_000)

        with (
            patch("factory.worker.os.cpu_count", return_value=8),
            patch(
                "factory.worker.os.getloadavg",
                return_value=(1.25, 0.75, 0.5),
                create=True,
            ),
            patch("factory.worker.shutil.disk_usage", return_value=disk),
        ):
            snapshot = _host_capacity_snapshot(config, meminfo_path=meminfo)

        assert snapshot["status"] == "AVAILABLE"
        assert snapshot["cpu"] == {
            "logical_count": 8,
            "load_1m": 1.25,
            "load_5m": 0.75,
            "load_15m": 0.5,
        }
        assert snapshot["memory_bytes"] == {
            "total": 16_777_216_000,
            "available": 8_388_608_000,
            "used": 8_388_608_000,
        }
        assert snapshot["controller_state_filesystem_bytes"] == {
            "total": 1_000_000,
            "used": 350_000,
            "free": 600_000,
        }
        assert snapshot["controller_limits"] == {
            "max_active_products": 2,
            "max_active_workers": 2,
        }
        assert snapshot["missing_fields"] == []


def test_host_capacity_snapshot_rejects_impossible_filesystem_measurements() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(
            root,
            selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"),
        )
        meminfo = root / "meminfo"
        meminfo.write_text(
            "MemTotal:       16384000 kB\nMemAvailable:    8192000 kB\n",
            encoding="utf-8",
        )
        disk = Mock(total=1_000_000, used=700_000, free=400_000)

        with (
            patch("factory.worker.os.cpu_count", return_value=8),
            patch(
                "factory.worker.os.getloadavg",
                return_value=(1.25, 0.75, 0.5),
                create=True,
            ),
            patch("factory.worker.shutil.disk_usage", return_value=disk),
        ):
            snapshot = _host_capacity_snapshot(config, meminfo_path=meminfo)

        assert snapshot["status"] == "PARTIAL"
        assert snapshot["missing_fields"] == ["filesystem"]


def test_solution_architect_gets_trusted_capacity_evidence() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(
            root,
            selected_registry(root / "registry.yaml", selected="gpt-5.6-terra"),
        )
        state = StateStore(config.database_path)
        product_id = "P-CAPACITY-CONTEXT"
        state.create_product(
            product_id=product_id,
            owner_id="owner",
            source="test",
            idea="Design a capacity-bound staging service",
            idempotency_key="capacity-context",
        )
        task_path = PipelineCoordinator(config, state, ArtifactStore(config)).create_task(
            product_id,
            "solution-architect",
        )
        task_id = json.loads(task_path.read_text(encoding="utf-8"))["task_id"]
        task = state.get_task(task_id)
        assert task is not None
        worker = AgentWorker(config, state, runner=FakeRunner("{}"), repository_root=ROOT)
        snapshot = {
            "schema_version": "1.0",
            "status": "AVAILABLE",
            "cpu": {"logical_count": 8, "load_1m": 1.0},
            "memory_bytes": {"total": 16_000, "available": 8_000, "used": 8_000},
            "controller_state_filesystem_bytes": {
                "total": 100_000,
                "used": 40_000,
                "free": 60_000,
            },
        }

        with patch("factory.worker._host_capacity_snapshot", return_value=snapshot):
            spec = worker.default_spec(task)

        capacity = next(item for item in spec.evidence if item["type"] == "controller-host-capacity")
        payload = stable_json(snapshot)
        assert payload in capacity["summary"]
        assert capacity["artifact_ref"] == "controller://host-capacity/" + sha256_text(payload)
        assert any(
            "Fail closed if their status is not AVAILABLE" in decision
            and "fresh pre-deployment capacity admission" in decision
            for decision in spec.decisions
        )
        state.close()


def test_external_planning_roles_and_builder_get_binding_python_contract() -> None:
    product = {"repository_url": "https://github.com/example/service"}
    for role in ("solution-architect", "task-specifier", "replanner", "builder"):
        evidence, decisions = _external_target_execution_context(product, role)
        assert len(evidence) == 1
        assert any("Do not select Go" in decision for decision in decisions)
    payload = json.loads(evidence[0]["summary"].removeprefix("TRUSTED_CONTROLLER_EVIDENCE: "))
    assert payload["language"] == "python"
    assert [item["command"] for item in payload["commands"]] == [
        "python3 -m pytest -q", "python3 -m compileall -q src tests",
        "python3 -m ruff check src tests",
    ]
    assert payload["required_implementation_scope"] == ["src/**", "tests/**"]
    assert payload["admitted_capabilities"] == [
        "toolchain.python", "toolchain.scanners", "toolchain.container_builder", "toolchain.make",
    ]
    assert evidence[0]["artifact_ref"].startswith("controller://target-execution-contract/")


def test_replanner_context_exposes_exact_remaining_execution_slots() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(root, selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"))
        state = StateStore(config.database_path)
        product_id, task_id = "P-REPLANNER-BUDGET", "T-REPLANNER-BUDGET"
        signature = "c" * 64
        state.create_product(
            product_id=product_id, owner_id="owner", source="test",
            idea="https://github.com/example/service",
            idempotency_key="replanner-budget-context",
        )
        contract = replanner_task_contract(config, product_id, task_id)
        contract_path = ArtifactStore(config).write(
            "task-contract-v2.schema.json", contract, filename=f"task-{task_id}.json",
        )
        state.add_task(
            task_id=task_id, product_id=product_id, title=str(contract["title"]), role="replanner",
            output_schema=str(contract["output_schema"]),
            contract_ref=f"evidence/{contract_path.name}",
            capability_profile="planning_readonly",
            required_capabilities=list(contract["required_capabilities"]),
            root_problem_signature=signature,
        )
        governor = PathGovernor(state._connection, policy_digest=policy_digest(config))
        with state._connection:
            assert governor.consume_budget(
                product_id=product_id,
                root_problem_signature=signature,
                action_kind="arbiter",
                progress=governor.progress_vector(product_id),
                evidence_digest="d" * 64,
            ) == "CONTINUE"
        worker = AgentWorker(config, state, runner=FakeRunner("{}"), repository_root=ROOT)
        task = state.get_task(task_id)
        assert task is not None
        spec = worker.default_spec(task)
        _, _, context_path = worker._context_and_prompt(spec)
        context = json.loads(context_path.read_text(encoding="utf-8"))
        assert context["plan_summary"]["path_governor_execution_budget"] == {
            "root_problem_signature": signature, "execution_slot_limit": 2,
            "execution_attempts_used": 0, "remaining_execution_slots": 2, "status": "ACTIVE",
        }
        assert any("remaining_execution_slots" in decision for decision in spec.decisions)
        assert any(item["type"] == "controller-target-execution-contract" for item in spec.evidence)
        state.close()


def test_plan_contract_violation_has_typed_worker_classification() -> None:
    error = PlanContractViolation("bounded recovery delta exceeds remaining slots")
    assert AgentWorker._exception_reason_code(error) == "plan_contract_violation"


def test_default_spec_uses_exact_revised_contract_ref_instead_of_stale_canonical() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(
            root,
            selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"),
        )
        state = StateStore(config.database_path)
        product_id = "P-REVISED-CONTRACT"
        state.create_product(
            product_id=product_id,
            owner_id="owner",
            source="test",
            idea="Execute the exact revised security review contract",
            idempotency_key="revised-contract-ref",
        )
        task_id = "T-REVISED-CONTRACT"
        canonical = replanner_task_contract(config, product_id, task_id)
        canonical["quality_gates"] = ["target-sast"]
        canonical_path = ArtifactStore(config).write(
            "task-contract-v2.schema.json",
            canonical,
            filename=f"task-{task_id}.json",
        )
        state.add_task(
            task_id=task_id,
            product_id=product_id,
            title=str(canonical["title"]),
            role="replanner",
            output_schema="backlog-plan-v2.schema.json",
            contract_ref=f"evidence/{canonical_path.name}",
            stage_key="replanner",
            conflict_keys=[f"{product_id}:planning"],
            capability_profile="planning_readonly",
            required_capabilities=list(canonical["required_capabilities"]),
        )
        revised = {
            **canonical,
            "task_revision": 2,
            "quality_gates": ["target-sast", "target-container-image-scan"],
        }
        revised_path = ArtifactStore(config).write(
            "task-contract-v2.schema.json",
            revised,
            filename=f"task-{task_id}-container-gate.json",
        )
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE tasks SET contract_ref=?, task_revision=? WHERE task_id=?",
                (
                    f"evidence/{revised_path.name}",
                    revised["task_revision"],
                    task_id,
                ),
            )
        durable = state.get_task(task_id)
        assert durable is not None
        worker = AgentWorker(
            config,
            state,
            runner=FakeRunner("{}"),
            health_probe=lambda _: True,
            repository_root=ROOT,
        )

        spec = worker.default_spec(durable)

        assert spec.task_contract["quality_gates"] == [
            "target-sast",
            "target-container-image-scan",
        ]
        state.close()


def test_default_spec_rejects_contract_ref_with_stale_revision() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(
            root,
            selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"),
        )
        state = StateStore(config.database_path)
        product_id = "P-STALE-CONTRACT"
        state.create_product(
            product_id=product_id,
            owner_id="owner",
            source="test",
            idea="Reject stale immutable task contract revisions",
            idempotency_key="stale-contract-ref",
        )
        task_id = "T-STALE-CONTRACT"
        contract = replanner_task_contract(config, product_id, task_id)
        contract_path = ArtifactStore(config).write(
            "task-contract-v2.schema.json",
            contract,
            filename=f"task-{task_id}.json",
        )
        state.add_task(
            task_id=task_id,
            product_id=product_id,
            title=str(contract["title"]),
            role="replanner",
            output_schema="backlog-plan-v2.schema.json",
            contract_ref=f"evidence/{contract_path.name}",
            stage_key="replanner",
            conflict_keys=[f"{product_id}:planning"],
            capability_profile="planning_readonly",
            required_capabilities=list(contract["required_capabilities"]),
        )
        with state._lock, state._connection:
            state._connection.execute(
                "UPDATE tasks SET task_revision=task_revision+1 WHERE task_id=?",
                (task_id,),
            )
        durable = state.get_task(task_id)
        assert durable is not None
        worker = AgentWorker(
            config,
            state,
            runner=FakeRunner("{}"),
            health_probe=lambda _: True,
            repository_root=ROOT,
        )

        with pytest.raises(ExternalBlocker) as error:
            worker.default_spec(durable)

        assert error.value.reason_code == "invalid_task_contract_reference"
        state.close()


def test_current_replan_frontier_excludes_only_historical_superseded_nodes() -> None:
    digest = "a" * 64
    affected = {
        "task_id": "T-AFFECTED",
        "node_key": "affected",
        "graph_status": "SUPERSEDED",
        "blocked_reason": "semantic_lifecycle_migration",
        "blocked_ref": digest,
    }
    nodes = [
        {
            "task_id": "T-ACCEPTED",
            "graph_status": "ACCEPTED",
        },
        {
            "task_id": "T-HISTORICAL",
            "graph_status": "SUPERSEDED",
            "blocked_reason": "semantic_lifecycle_migration",
            "blocked_ref": "b" * 64,
        },
        affected,
        {
            "task_id": "T-RECOVERY-PEER",
            "graph_status": "SUPERSEDED",
            "blocked_reason": "semantic_lifecycle_migration",
            "blocked_ref": digest,
        },
        {
            "task_id": "T-PRIOR-RECOVERY-PEER",
            "graph_status": "SUPERSEDED",
            "blocked_reason": "semantic_lifecycle_migration",
            "blocked_ref": "c" * 64,
        },
        {
            "task_id": "T-READY",
            "graph_status": "READY",
        },
        {
            "task_id": "T-CANCELLED",
            "graph_status": "CANCELLED",
        },
    ]

    frontier = _current_replan_frontier(
        nodes,
        recovery_plan_digests=(digest, "c" * 64),
        affected=affected,
    )

    assert [node["task_id"] for node in frontier] == [
        "T-AFFECTED",
        "T-RECOVERY-PEER",
        "T-PRIOR-RECOVERY-PEER",
        "T-READY",
    ]


def make_retry_due(state: StateStore, task_id: str) -> None:
    """Advance one durable retry timer without sleeping in a unit test."""

    with state._lock, state._connection:
        state._connection.execute(
            "UPDATE tasks SET available_at='2000-01-01T00:00:00Z' "
            "WHERE task_id=? AND graph_status='WAITING_TIME'",
            (task_id,),
        )


def make_config(root: Path, registry: Path | None = None) -> FactoryConfig:
    raw = yaml.safe_load(
        (ROOT / "config" / "factory-config.example.yaml").read_text(encoding="utf-8")
    )
    raw["paths"]["state"] = str(root)
    raw["paths"]["policies"] = str(ROOT / "policies")
    raw["paths"]["schemas"] = str(ROOT / "schemas")
    raw["paths"]["prompts"] = str(ROOT / "prompts")
    raw["paths"]["worktrees"] = str(root / "worktrees")
    raw["paths"]["logs"] = str(root / "logs")
    raw["controller"]["database_url"] = f"sqlite:///{(root / 'controller.db').as_posix()}"
    if registry is not None:
        raw["models"]["registry"] = str(registry)
    return FactoryConfig(raw, ROOT / "config" / "factory-config.example.yaml")


class FakeRunner:
    def __init__(self, output: str) -> None:
        self.output = output
        self.calls: list[tuple[str, str, Path]] = []

    def run(
        self,
        *,
        selection: Any,
        prompt: str,
        cwd: Path,
        usage_path: Path | None = None,
    ) -> HermesRunResult:
        self.calls.append((selection.model, selection.provider, cwd))
        return HermesRunResult(
            "PASS", self.output, "fake-output-digest", None, str(usage_path) if usage_path else None
        )


class SequenceRunner:
    def __init__(self, outputs: list[str]) -> None:
        self.outputs = list(outputs)
        self.prompts: list[str] = []

    def run(
        self,
        *,
        selection: Any,
        prompt: str,
        cwd: Path,
        usage_path: Path | None = None,
    ) -> HermesRunResult:
        del selection, cwd
        self.prompts.append(prompt)
        if not self.outputs:
            raise AssertionError("SequenceRunner was called more times than expected")
        output = self.outputs.pop(0)
        return HermesRunResult(
            "PASS", output, "sequence-output-digest", None, str(usage_path) if usage_path else None
        )


class UsageRunner(FakeRunner):
    def run(
        self,
        *,
        selection: Any,
        prompt: str,
        cwd: Path,
        usage_path: Path | None = None,
    ) -> HermesRunResult:
        if usage_path is not None:
            usage_path.write_text(
                json.dumps(
                    {
                        "input_tokens": 42,
                        "output_tokens": 7,
                        "cache_tokens": 3,
                        "tool_rounds": 1,
                        "wall_clock_seconds": 0.25,
                    }
                ),
                encoding="utf-8",
            )
        return super().run(selection=selection, prompt=prompt, cwd=cwd, usage_path=usage_path)


class ScopeViolatingRunner(FakeRunner):
    def run(
        self,
        *,
        selection: Any,
        prompt: str,
        cwd: Path,
        usage_path: Path | None = None,
    ) -> HermesRunResult:
        (cwd / "forbidden.txt").write_text("unexpected change\n", encoding="utf-8")
        return super().run(selection=selection, prompt=prompt, cwd=cwd, usage_path=usage_path)


class PassingQuality:
    def run(self, **_: object) -> QualityGateRun:
        return QualityGateRun(
            (
                {
                    "gate_id": "security-preflight",
                    "status": "PASS",
                    "evidence_ref": "evidence/security-preflight.json",
                },
            ),
            (),
            True,
        )


class RecordingReleaseExecutor:
    def __init__(self, result: dict[str, object]) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

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
        self.calls.append(
            {
                "stage": stage,
                "proposed": dict(proposed),
                "product_id": product_id,
                "task_contract": dict(task_contract),
                "workspace": workspace,
                "expected_staging_digest": expected_staging_digest,
            }
        )
        return self.result


def selected_registry(path: Path, *, selected: str | None) -> Path:
    data = yaml.safe_load(
        (ROOT / "config" / "model-routing" / "model-registry.template.yaml").read_text(
            encoding="utf-8"
        )
    )
    for alias in ("economy", "standard", "expert"):
        data["aliases"][alias]["selected"] = selected
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def product_contract(config: FactoryConfig, product_id: str) -> str:
    artifact = json.loads(
        (ROOT / "templates" / "product-contract.example.json").read_text(encoding="utf-8")
    )
    artifact["artifact_id"] = "product-contract-worker-test"
    artifact["product_id"] = product_id
    artifact["policy_digest"] = policy_digest(config)
    artifact["producer"] = {
        "role": "product-director",
        "tier": "luna",
        "provider": "openai_codex_subscription",
        "model": "gpt-5.6-luna",
    }
    artifact["status"] = "completed"
    artifact["created_at"] = "2026-01-01T00:00:00Z"
    return json.dumps(artifact, ensure_ascii=False)


def replanner_task_contract(
    config: FactoryConfig,
    product_id: str,
    task_id: str,
) -> dict[str, Any]:
    plan_id = f"PLAN-SYSTEM-{sha256_text(product_id)[:16].upper()}"
    return {
        "schema_version": "2.0",
        "artifact_id": f"task-contract-{task_id}",
        "product_id": product_id,
        "task_id": task_id,
        "root_task_id": task_id,
        "parent_task_id": None,
        "source_task_id": task_id,
        "plan_id": plan_id,
        "plan_node_id": "replanner",
        "task_revision": 1,
        "root_context_ref": f"evidence/intake-{product_id}.json",
        "active_context_ref": f"evidence/task-{task_id}.json",
        "failure_id": None,
        "hypothesis_id": None,
        "supersedes_task_id": None,
        "title": "Replan the product graph",
        "objective": "Create a corrected executable product graph revision",
        "role": "replanner",
        "output_schema": "backlog-plan-v2.schema.json",
        "dependencies": [],
        "conflict_keys": [f"{product_id}:planning"],
        "acceptance": [
            {
                "criterion_id": "accept-replan",
                "verification": "The corrected graph passes semantic validation",
                "mandatory": True,
            }
        ],
        "required_capabilities": [
            "artifact.read",
            "artifact.write",
            "repository.read_bounded",
            "state.read",
            "plan.propose",
        ],
        "capability_profile": "planning_readonly",
        "allowed_paths": ["artifacts/**"],
        "forbidden_paths": ["secrets/**"],
        "risk_tier": "medium",
        "model_floor": "luna",
        "idempotency_key": sha256_text(f"replanner:{product_id}:{task_id}"),
        "status": "READY",
        "priority": 100,
        "critical_path_rank": 0,
    }


def backlog_plan_with_missing_edge(
    config: FactoryConfig,
    product_id: str,
    replanner_task_id: str,
) -> dict[str, Any]:
    plan_id = "PLAN-SEMANTIC-REPAIR"
    child_task_id = "T-SEMANTIC-CHILD"
    child_contract = {
        **replanner_task_contract(config, product_id, child_task_id),
        "artifact_id": f"task-contract-{child_task_id}",
        "root_task_id": replanner_task_id,
        "parent_task_id": replanner_task_id,
        "source_task_id": replanner_task_id,
        "plan_id": plan_id,
        "plan_node_id": "node-a",
        "title": "Implement the corrected node",
        "objective": "Implement and verify the corrected product behavior",
        "role": "builder",
        "output_schema": "attempt-result.schema.json",
        "conflict_keys": [f"{product_id}:src"],
        "required_capabilities": [
            "artifact.read",
            "artifact.write",
            "repository.read",
            "repository.write_scoped",
            "command.execute_allowlisted",
            "test.execute",
        ],
        "capability_profile": "builder_workspace",
        "allowed_paths": ["src/**"],
        "idempotency_key": sha256_text(f"{plan_id}:node-a:{child_task_id}"),
        "priority": 50,
    }
    return {
        "schema_version": "2.0",
        "artifact_id": "backlog-plan-semantic-repair",
        "product_id": product_id,
        "created_at": "2026-07-29T00:00:00Z",
        "producer": {
            "role": "replanner",
            "tier": "luna",
            "provider": "openai_codex_subscription",
            "model": "gpt-5.6-luna",
        },
        "policy_digest": policy_digest(config),
        "status": "completed",
        "plan_id": plan_id,
        "revision": 1,
        "parent_plan_id": None,
        "source_failure_id": None,
        "goals": [
            {
                "goal_id": "root-goal",
                "statement": "Deliver the corrected product",
                "mandatory": True,
                "acceptance_ids": ["accept-replan"],
            }
        ],
        "nodes": [
            {
                "node_id": "node-a",
                "mandatory": True,
                "task_contract": child_contract,
            }
        ],
        "edges": [
            {
                "from": "node-a",
                "to": "missing-node",
                "edge_type": "depends_on",
                "required": True,
            }
        ],
        "completion_criteria": ["The mandatory corrected node has immutable PASS evidence"],
        "summary": "A schema-valid plan with one missing semantic edge endpoint",
    }


def requirements_package(config: FactoryConfig, product_id: str) -> str:
    artifact = {
        **artifact_metadata(config, "product-analyst", "requirements-worker-test", product_id),
        "status": "completed",
        "summary": "Traceable requirements derived from the accepted Product Contract.",
        "domain_terms": [{"term": "product", "definition": "The owner-scoped deliverable."}],
        "user_stories": [
            {
                "id": "US-001",
                "actor": "owner",
                "goal": "inspect the accepted deliverable",
                "benefit": "the result is verifiable",
                "acceptance_ids": ["AC-001"],
            }
        ],
        "edge_cases": [],
        "traceability": [
            {"requirement_id": "REQ-001", "story_ids": ["US-001"], "acceptance_ids": ["AC-001"]}
        ],
        "assumptions": ["The owner can inspect the result locally."],
        "findings": [],
        "evidence_refs": ["evidence/product-contract-worker-test.json"],
    }
    return json.dumps(artifact, ensure_ascii=False)


def release_operation(
    config: FactoryConfig,
    product_id: str,
    *,
    candidate_sha: str,
    image_digest: str,
) -> dict[str, object]:
    return {
        **artifact_metadata(config, "release-operator", "release-operation-test", product_id),
        "status": "completed",
        "repository": "brullik/hermes-software-factory",
        "candidate_sha": candidate_sha,
        "merge": {"performed": False, "merge_sha": None},
        "release": {"version": "0.1.0", "image_digest": image_digest},
        "staging": "deployed",
        "production": "not_started",
        "rollback": "not_tested",
        "summary": "Adapter-backed staging release fixture.",
        "findings": [],
        "evidence_refs": ["evidence/gates.json", "evidence/staging.json"],
    }


def staging_release_task(
    config: FactoryConfig, state: Any, artifacts: ArtifactStore
) -> tuple[str, Path]:
    product_id = "P-RELEASE-001"
    state.create_product(
        product_id=product_id,
        owner_id="owner",
        source="test",
        idea="Build a release-backed product",
        idempotency_key="release-test-001",
    )
    for status in (
        "CONTRACT_DRAFTED",
        "CONTRACT_VALIDATED",
        "RISK_CLASSIFIED",
        "ARCHITECTED",
        "BACKLOG_READY",
        "IMPLEMENTING",
        "INTEGRATING",
    ):
        state.transition_product(product_id, status)
    for capability in CAPABILITY_PROFILES["release_staging"]:
        state.grant_capability(
            product_id=product_id,
            task_id=None,
            capability=capability,
            provider="fake-controller",
            scope={"repository": "brullik/hermes-software-factory"},
            status="AVAILABLE",
        )
    return product_id, PipelineCoordinator(config, state, artifacts).create_task(
        product_id, "release-staging"
    )


class WorkerTests(unittest.TestCase):
    def test_mandatory_gate_failure_preserves_safe_actionable_diagnostic(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "gate-target-license-check.json"
            credential = "github_" + "pat_" + ("A" * 30)
            evidence_path.write_text(
                json.dumps(
                    {
                        "status": "ERROR",
                        "exit_code": None,
                        "summary": (
                            "pyproject.toml has no [project] dependency contract; "
                            f"provider diagnostic contained {credential}"
                        ),
                    }
                ),
                encoding="utf-8",
            )
            failure = _mandatory_gate_failure_data(
                QualityGateRun(
                    (
                        {
                            "gate_id": "target-license-check",
                            "status": "FAIL",
                            "evidence_ref": str(evidence_path),
                        },
                    ),
                    (evidence_path,),
                    False,
                ),
                detail="failed mandatory gates: target-license-check",
                evidence_ref="evidence/attempt.json",
                attempt_id="attempt-gate-diagnostic",
            )

        self.assertEqual(failure.failed_gate_ids, ("target-license-check",))
        self.assertIn(
            "pyproject.toml has no [project] dependency contract",
            failure.safe_message,
        )
        self.assertNotIn(credential, failure.safe_message)
        self.assertIn("[REDACTED:github_token]", failure.safe_message)
        self.assertIn("SAFE_REDACTION_COORDINATES", failure.safe_message)
        diagnostics = failure.actual["gate_diagnostics"]
        self.assertEqual(diagnostics[0]["gate_id"], "target-license-check")
        self.assertEqual(
            failure.expected["quality_gates"],
            [{"gate_id": "target-license-check", "status": "PASS"}],
        )

    def test_mandatory_gate_failure_preserves_scope_reassessment_signal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "gate-target-tests.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "status": "FAIL",
                        "exit_code": 1,
                        "summary": ("ComposeTopologyBlackBoxTests failed in compose.yml"),
                    }
                ),
                encoding="utf-8",
            )
            failure = _mandatory_gate_failure_data(
                QualityGateRun(
                    (
                        {
                            "gate_id": "target-tests",
                            "status": "FAIL",
                            "evidence_ref": str(evidence_path),
                        },
                    ),
                    (evidence_path,),
                    False,
                ),
                detail="failed mandatory gates: target-tests",
                evidence_ref="evidence/attempt.json",
                attempt_id="attempt-scope-reassessment",
                output={
                    "findings": [
                        {
                            "code": "FULL_SUITE_UNRELATED_FAILURE",
                            "severity": "medium",
                            "text": (
                                "tests/unit/test_image_security_verify.py fails "
                                "because scripts/image_security_verify.py returns "
                                "success for malformed scanner output; the production "
                                "file is outside allowed task scope."
                            ),
                        }
                    ]
                },
                allowed_paths=["tests/**"],
            )

        self.assertIs(
            failure.actual["scope_reassessment_required"],
            True,
        )
        self.assertEqual(
            failure.actual["blocked_allowed_paths"],
            ["tests/**"],
        )
        self.assertEqual(
            failure.actual["provider_scope_findings"][0]["code"],
            "FULL_SUITE_UNRELATED_FAILURE",
        )
        self.assertEqual(
            failure.actual["scope_required_paths"],
            ["scripts/image_security_verify.py"],
        )
        self.assertTrue(
            any(
                "allowed_paths expand beyond the failed task scope" in item
                for item in failure.actual["required_fixes"]
            )
        )

    def test_mandatory_gate_failure_detects_controller_path_outside_scope(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "gate-target-lint.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "status": "FAIL",
                        "exit_code": 1,
                        "summary": (
                            "E902 No such file or directory (os error 2)\n"
                            "--> src:1:1\n"
                            "tests/unit/test_safe.py:14:2: assertion context"
                        ),
                    }
                ),
                encoding="utf-8",
            )
            failure = _mandatory_gate_failure_data(
                QualityGateRun(
                    (
                        {
                            "gate_id": "target-lint",
                            "status": "FAIL",
                            "evidence_ref": str(evidence_path),
                        },
                    ),
                    (evidence_path,),
                    False,
                ),
                detail="failed mandatory gates: target-lint",
                evidence_ref="evidence/attempt.json",
                attempt_id="attempt-controller-scope-coordinate",
                output={
                    "findings": [
                        {
                            "code": "FRESH_VERIFICATION_PASS",
                            "severity": "info",
                            "text": "The task-local tests passed.",
                        }
                    ]
                },
                allowed_paths=["tests/**"],
            )

        self.assertIs(
            failure.actual["scope_reassessment_required"],
            True,
        )
        self.assertEqual(
            failure.actual["diagnostic_scope_coordinates"],
            ["src", "tests/unit/test_safe.py"],
        )
        self.assertEqual(
            failure.actual["outside_scope_coordinates"],
            ["src"],
        )
        self.assertEqual(
            failure.actual["provider_scope_findings"][0]["code"],
            "CONTROLLER_SCOPE_COORDINATE_OUTSIDE_ALLOWED_PATHS",
        )

    def test_mandatory_gate_failure_infers_unique_production_source(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            test_path = root / "tests" / "unit" / "test_server.py"
            test_path.parent.mkdir(parents=True)
            test_path.write_text(
                "from server import create_server\n\ndef test_ready():\n    assert create_server\n",
                encoding="utf-8",
            )
            source_path = root / "container" / "server.py"
            source_path.parent.mkdir()
            source_path.write_text(
                "def create_server():\n    return object()\n",
                encoding="utf-8",
            )
            evidence_path = root / "gate-target-tests.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "status": "FAIL",
                        "exit_code": 1,
                        "summary": (
                            "RuntimeTests.test_ready failed\n"
                            "tests/unit/test_server.py:31: AssertionError"
                        ),
                    }
                ),
                encoding="utf-8",
            )
            failure = _mandatory_gate_failure_data(
                QualityGateRun(
                    (
                        {
                            "gate_id": "target-tests",
                            "status": "FAIL",
                            "evidence_ref": str(evidence_path),
                        },
                    ),
                    (evidence_path,),
                    False,
                ),
                detail="failed mandatory gates: target-tests",
                evidence_ref="evidence/attempt.json",
                attempt_id="attempt-controller-source-coordinate",
                allowed_paths=["tests/**"],
                repository_root=root,
            )

        self.assertEqual(
            failure.actual["inferred_source_coordinates"],
            ["container/server.py"],
        )
        self.assertEqual(
            failure.actual["scope_required_paths"],
            ["container/server.py"],
        )
        self.assertTrue(
            any(
                finding["code"]
                == "CONTROLLER_UNIQUE_TEST_SOURCE_OUTSIDE_ALLOWED_PATHS"
                for finding in failure.actual["provider_scope_findings"]
            )
        )

    def test_replanner_inventory_preserves_safe_failure_coordinates_and_hypotheses(
        self,
    ) -> None:
        failures = _replanner_failure_inventory(
            [
                {
                    "failure_id": "failure-root",
                    "parent_failure_id": None,
                    "task_id": "T-ROOT",
                    "failure_class": "semantic",
                    "reason_code": "mandatory_gate_failed",
                    "status": "RESOLVED",
                    "safe_message": (
                        "target dependency audit failed closed: "
                        "pyproject.toml has no [project] dependency contract"
                    ),
                    "failed_gate_ids_json": '["target-dependency-audit"]',
                    "expected_json": (
                        '{"quality_gates":[{"gate_id":"target-dependency-audit","status":"PASS"}]}'
                    ),
                    "actual_json": (
                        '{"required_fixes":["Add an explicit [project] dependency contract."]}'
                    ),
                    "evidence_ref": "evidence/failure-root.json",
                },
                {
                    "failure_id": "failure-context",
                    "parent_failure_id": "failure-root",
                    "task_id": "T-CONTEXT",
                    "failure_class": "semantic",
                    "reason_code": "model_requested_repair",
                    "status": "ROUTED",
                    "safe_message": "Change escaped the bounded source scope.",
                    "failed_gate_ids_json": '["scope_violation"]',
                    "expected_json": '{"allowed_paths":["src/**"]}',
                    "actual_json": (
                        '{"violating_paths":["Dockerfile"],'
                        '"required_fixes":["Add the required path to a new plan."],'
                        '"scope_reassessment_required":true,'
                        '"blocked_allowed_paths":["src/**","tests/**"],'
                        '"provider_scope_findings":[{"code":"SCOPE_INSUFFICIENT",'
                        '"text":"tests/unit/test_image_security_verify.py fails '
                        "because scripts/image_security_verify.py is outside "
                        'allowed task scope."}]}'
                    ),
                    "evidence_ref": "evidence/failure-context.json",
                },
            ],
            source_failure_id="failure-context",
        )
        hypotheses = _replanner_hypothesis_inventory(
            [
                {
                    "hypothesis_id": "hypothesis-context",
                    "parent_hypothesis_id": None,
                    "failure_id": "failure-context",
                    "status": "EXHAUSTED",
                    "statement": "The original path scope was incomplete.",
                    "required_evidence_json": '["evidence/failure-context.json"]',
                    "semantic_budget": 3,
                    "attempts_used": 3,
                }
            ]
        )

        self.assertEqual(
            failures[0]["actual"]["violating_paths"],
            ["Dockerfile"],
        )
        self.assertEqual(
            failures[0]["scope_required_paths"],
            ["Dockerfile", "scripts/image_security_verify.py"],
        )
        self.assertEqual(
            failures[0]["expected"]["allowed_paths"],
            ["src/**"],
        )
        self.assertTrue(failures[0]["chain_seed"])
        self.assertEqual(failures[0]["causal_depth"], 0)
        self.assertEqual(failures[1]["status"], "RESOLVED")
        self.assertEqual(failures[1]["causal_depth"], 1)

        scope_policy = _replanner_scope_policy(
            [
                {
                    "failure_id": "failure-root",
                    "parent_failure_id": None,
                    "task_id": "T-ROOT",
                    "failure_class": "semantic",
                    "reason_code": "mandatory_gate_failed",
                    "status": "RESOLVED",
                    "safe_message": "target-tests failed",
                    "failed_gate_ids_json": '["target-tests"]',
                    "expected_json": "{}",
                    "actual_json": (
                        '{"scope_reassessment_required":true,'
                        '"blocked_allowed_paths":["src/**","tests/**"],'
                        '"provider_scope_findings":[{"code":"SCOPE_INSUFFICIENT",'
                        '"text":"scripts/image_security_verify.py is outside '
                        'allowed task scope."}]}'
                    ),
                    "evidence_ref": "evidence/failure-root.json",
                },
                {
                    "failure_id": "failure-child",
                    "parent_failure_id": "failure-root",
                    "task_id": "T-REPLANNER",
                    "failure_class": "semantic",
                    "reason_code": "needs_replan",
                    "status": "OPEN",
                    "safe_message": "planning scope remained contradictory",
                    "failed_gate_ids_json": '["needs_replan"]',
                    "expected_json": "{}",
                    "actual_json": "{}",
                    "evidence_ref": "evidence/failure-child.json",
                },
            ],
            source_failure_id="failure-child",
        )

        self.assertTrue(scope_policy["allow_bounded_expansion"])
        self.assertEqual(
            scope_policy["failed_allowed_paths"],
            ["src/**", "tests/**"],
        )
        self.assertEqual(
            scope_policy["required_scope_paths"],
            ["scripts/image_security_verify.py"],
        )
        self.assertIn("target-tests", scope_policy["failed_mandatory_gate_ids"])
        self.assertEqual(
            scope_policy["proposal_scope_field"],
            "slices[].scope",
        )
        self.assertIn(
            "pyproject.toml has no [project] dependency contract",
            failures[1]["safe_message"],
        )
        self.assertEqual(
            failures[1]["actual"]["required_fixes"],
            ["Add an explicit [project] dependency contract."],
        )
        self.assertEqual(hypotheses[0]["status"], "EXHAUSTED")
        self.assertEqual(hypotheses[0]["attempts_used"], 3)

    def test_replanner_context_keeps_only_causal_root_latest_and_hypotheses(
        self,
    ) -> None:
        failures = [
            {
                "failure_id": "failure-root",
                "parent_failure_id": None,
                "task_id": "T-ROOT",
                "failure_class": "semantic",
                "reason_code": "mandatory_gate_failed",
                "status": "RESOLVED",
                "safe_message": "root",
                "failed_gate_ids_json": '["target-tests"]',
                "expected_json": "{}",
                "actual_json": "{}",
                "evidence_ref": "evidence/root.json",
            },
            {
                "failure_id": "failure-middle",
                "parent_failure_id": "failure-root",
                "task_id": "T-MIDDLE",
                "failure_class": "semantic",
                "reason_code": "plan_contract_violation",
                "status": "RESOLVED",
                "safe_message": "middle",
                "failed_gate_ids_json": '["PLAN_CONTRACT_VIOLATION"]',
                "expected_json": "{}",
                "actual_json": "{}",
                "evidence_ref": "evidence/middle.json",
            },
            {
                "failure_id": "failure-latest",
                "parent_failure_id": "failure-middle",
                "task_id": "T-LATEST",
                "failure_class": "semantic",
                "reason_code": "needs_replan",
                "status": "OPEN",
                "safe_message": "latest",
                "failed_gate_ids_json": '["needs_replan"]',
                "expected_json": "{}",
                "actual_json": "{}",
                "evidence_ref": "evidence/latest.json",
            },
            {
                "failure_id": "failure-unrelated",
                "parent_failure_id": None,
                "task_id": "T-UNRELATED",
                "failure_class": "semantic",
                "reason_code": "unrelated",
                "status": "OPEN",
                "safe_message": "unrelated",
                "failed_gate_ids_json": "[]",
                "expected_json": "{}",
                "actual_json": "{}",
                "evidence_ref": "evidence/unrelated.json",
            },
        ]
        inventory = _replanner_failure_inventory(
            failures,
            source_failure_id="failure-latest",
        )
        self.assertEqual(
            [item["failure_id"] for item in inventory],
            ["failure-latest", "failure-root"],
        )

        hypotheses = _replanner_hypothesis_inventory(
            [
                {
                    "hypothesis_id": "hypothesis-causal",
                    "failure_id": "failure-middle",
                    "status": "ACTIVE",
                    "statement": "causal",
                    "required_evidence_json": "[]",
                    "semantic_budget": 3,
                    "attempts_used": 1,
                },
                {
                    "hypothesis_id": "hypothesis-unrelated",
                    "failure_id": "failure-unrelated",
                    "status": "ACTIVE",
                    "statement": "unrelated",
                    "required_evidence_json": "[]",
                    "semantic_budget": 3,
                    "attempts_used": 1,
                },
            ],
            failure_ids=("failure-latest", "failure-middle", "failure-root"),
        )
        self.assertEqual(
            [item["hypothesis_id"] for item in hypotheses],
            ["hypothesis-causal"],
        )

    def test_replanner_implementation_inventory_includes_accepted_result(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root,
                selected_registry(
                    root / "registry.yaml",
                    selected="gpt-5.6-luna",
                ),
            )
            state = StateStore(config.database_path)
            artifacts = ArtifactStore(config)
            product_id = "P-REPLAN-CONTEXT"
            task_id = "T-INVENTORY-BUILDER"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="test",
                idea="Build a context-complete service",
                idempotency_key="replanner-context-product",
            )
            product = state.get_product(product_id)
            assert product is not None
            plan_id = str(product["active_plan_id"])
            contract = {
                **replanner_task_contract(config, product_id, task_id),
                "plan_id": plan_id,
                "plan_node_id": "implementation-001-runtime",
                "title": "Implement runtime foundation",
                "objective": "Implement and verify the reusable runtime foundation",
                "role": "builder",
                "output_schema": "attempt-result.schema.json",
                "conflict_keys": [f"{product_id}:src"],
                "required_capabilities": list(CAPABILITY_PROFILES["builder_workspace"]),
                "capability_profile": "builder_workspace",
                "allowed_paths": ["src/**", "tests/**"],
                "semantic_node_key": "runtime-foundation",
                "goal_ids": ["root-goal"],
                "lifecycle_stage": "implementation-slice",
            }
            contract_path = artifacts.write(
                "task-contract-v2.schema.json",
                contract,
                filename=f"task-{task_id}.json",
            )
            state.add_task(
                task_id=task_id,
                product_id=product_id,
                title=str(contract["title"]),
                role="builder",
                output_schema="attempt-result.schema.json",
                contract_ref=f"evidence/{contract_path.name}",
                stage_key="implementation-001-runtime",
                plan_id=plan_id,
                plan_node_id="implementation-001-runtime",
                conflict_keys=[f"{product_id}:src"],
                capability_profile="builder_workspace",
                required_capabilities=list(CAPABILITY_PROFILES["builder_workspace"]),
            )
            result_path = config.evidence_dir / "accepted-runtime-result.json"
            result_path.write_text(
                json.dumps(
                    {
                        "summary": "Runtime foundation passed its local gates.",
                        "output_ref": "evidence/runtime-output.json",
                    }
                ),
                encoding="utf-8",
            )
            with state._lock, state._connection:
                state._connection.execute(
                    """UPDATE tasks
                          SET graph_status='ACCEPTED', status='SUCCEEDED',
                              result_ref=?, result_digest=?
                        WHERE task_id=?""",
                    (
                        f"evidence/{result_path.name}",
                        sha256_text("accepted-runtime-result"),
                        task_id,
                    ),
                )
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner("{}"),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            inventory = worker._replanner_implementation_inventory(
                product_id,
                plan_id,
            )

            self.assertEqual(len(inventory), 1)
            self.assertEqual(inventory[0]["node_key"], "runtime-foundation")
            self.assertEqual(inventory[0]["scope"], ["src/**", "tests/**"])
            self.assertEqual(inventory[0]["goal_ids"], ["root-goal"])
            self.assertEqual(
                inventory[0]["accepted_result"]["summary"],
                "Runtime foundation passed its local gates.",
            )
            state.close()

    def test_reused_accepted_task_resolves_immutable_source_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root,
                selected_registry(
                    root / "registry.yaml",
                    selected="gpt-5.6-luna",
                ),
            )
            state = StateStore(config.database_path)
            artifacts = ArtifactStore(config)
            intake = IntakeService(config, state, artifacts).submit(
                source="cli",
                owner_id="owner",
                idea="Build a reusable accepted-evidence lineage",
            )
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner(product_contract(config, intake.product_id)),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )
            result = worker.run_once()
            self.assertIsNotNone(result)
            original = next(
                task
                for task in state.list_tasks(intake.product_id)
                if task["role"] == "product-director"
            )
            self.assertEqual(original["graph_status"], "ACCEPTED")
            self.assertTrue(original["result_ref"])
            self.assertTrue(original["result_digest"])

            reused_id = "T-REUSED-PRODUCT-DIRECTOR"
            state.add_task(
                task_id=reused_id,
                product_id=intake.product_id,
                title="Reuse the accepted product contract",
                role="product-director",
                output_schema="product-contract.schema.json",
                contract_ref=f"evidence/task-{reused_id}.json",
                stage_key="product-director-reused",
                plan_id=str(original["plan_id"]),
                supersedes_task_id=str(original["task_id"]),
                graph_status="ACCEPTED",
            )
            with state._lock, state._connection:
                state._connection.execute(
                    """UPDATE tasks
                          SET result_ref=?, result_digest=?
                        WHERE task_id=?""",
                    (
                        original["result_ref"],
                        original["result_digest"],
                        reused_id,
                    ),
                )

            output_path, output, attempt = worker._accepted_task_artifacts(reused_id)

            self.assertTrue(output_path.is_file())
            self.assertEqual(output["status"], "completed")
            self.assertEqual(attempt["task_id"], original["task_id"])
            self.assertEqual(state.attempts_for_task(reused_id), [])

            with state._lock, state._connection:
                state._connection.execute(
                    "UPDATE tasks SET result_digest=? WHERE task_id=?",
                    ("f" * 64, reused_id),
                )
            # supersedes_task_id and the reused task's legacy attempt digest are
            # audit-only after direct binding materialisation.
            rebound_path, _, _ = worker._accepted_task_artifacts(reused_id)
            self.assertEqual(rebound_path, output_path)
            with state._lock, state._connection:
                state._connection.execute(
                    """UPDATE result_bindings SET result_digest=?
                        WHERE binding_id=(
                            SELECT result_binding_id FROM tasks WHERE task_id=?
                        )""",
                    ("f" * 64, reused_id),
                )
            with self.assertRaisesRegex(
                ResultLineageIdentityError,
                "artifact conflicts",
            ):
                worker._accepted_task_artifacts(reused_id)
            state.close()

    def test_superseded_dependency_resolves_accepted_repair_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root,
                selected_registry(
                    root / "registry.yaml",
                    selected="gpt-5.6-luna",
                ),
            )
            state = StateStore(config.database_path)
            artifacts = ArtifactStore(config)
            intake = IntakeService(config, state, artifacts).submit(
                source="cli",
                owner_id="owner",
                idea="Build a forward repair-evidence lineage",
            )
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner(product_contract(config, intake.product_id)),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )
            result = worker.run_once()
            self.assertIsNotNone(result)
            accepted_repair = next(
                task
                for task in state.list_tasks(intake.product_id)
                if task["role"] == "product-director"
            )
            self.assertEqual(accepted_repair["graph_status"], "ACCEPTED")

            failed_id = "T-SUPERSEDED-FAILED-DEPENDENCY"
            state.add_task(
                task_id=failed_id,
                product_id=intake.product_id,
                title="Failed dependency replaced by an accepted repair",
                role=str(accepted_repair["role"]),
                output_schema=str(accepted_repair["output_schema"]),
                contract_ref=f"evidence/task-{failed_id}.json",
                stage_key="test",
                root_task_id=str(accepted_repair["root_task_id"]),
                root_context_ref=str(accepted_repair["root_context_ref"]),
                graph_status="SUPERSEDED",
            )
            with state._lock, state._connection:
                state._connection.execute(
                    """UPDATE tasks
                          SET supersedes_task_id=?, parent_task_id=?,
                              source_task_id=?
                        WHERE task_id=?""",
                    (
                        failed_id,
                        failed_id,
                        failed_id,
                        accepted_repair["task_id"],
                    ),
                )

            output_path, output, attempt = worker._accepted_task_artifacts(failed_id)

            self.assertTrue(output_path.is_file())
            self.assertEqual(output["status"], "completed")
            self.assertEqual(attempt["task_id"], accepted_repair["task_id"])

            ambiguous_id = "T-SECOND-ACCEPTED-REPAIR"
            state.add_task(
                task_id=ambiguous_id,
                product_id=intake.product_id,
                title="Ambiguous accepted repair",
                role=str(accepted_repair["role"]),
                output_schema=str(accepted_repair["output_schema"]),
                contract_ref=f"evidence/task-{ambiguous_id}.json",
                stage_key="repair",
                root_task_id=str(accepted_repair["root_task_id"]),
                parent_task_id=failed_id,
                source_task_id=failed_id,
                root_context_ref=str(accepted_repair["root_context_ref"]),
                supersedes_task_id=failed_id,
                graph_status="ACCEPTED",
            )
            # Once the controller materialises a direct binding, later audit
            # lineage branches cannot make runtime result lookup ambiguous.
            stable_path, stable_output, stable_attempt = worker._accepted_task_artifacts(
                failed_id
            )
            self.assertEqual(stable_path, output_path)
            self.assertEqual(stable_output, output)
            self.assertEqual(stable_attempt, attempt)
            state.close()

    def test_incident_recovery_containment_requires_director_replan(self) -> None:
        output = {
            "containment": ["Provider retries were stopped."],
            "recovery": [],
            "root_cause": "Controller transport validation rejected the response.",
            "repair_task": "Retry the affected node from a new plan revision.",
            "data_integrity": "confirmed",
            "evidence_refs": ["evidence/controller-failure.json"],
        }
        for reported_status in ("recovered", "contained", "failed_safe"):
            self.assertEqual(
                _normalized_output_status(
                    "incident-recovery",
                    reported_status,
                    builder_gate_deferred=False,
                    output={**output, "status": reported_status},
                ),
                "needs_replan",
            )

    def test_incident_recovery_without_bounded_handoff_remains_failed_safe(
        self,
    ) -> None:
        self.assertEqual(
            _normalized_output_status(
                "incident-recovery",
                "failed_safe",
                builder_gate_deferred=False,
                output={
                    "status": "failed_safe",
                    "containment": ["Retries stopped."],
                    "recovery": [],
                    "root_cause": None,
                    "repair_task": None,
                    "data_integrity": "at_risk",
                    "evidence_refs": [],
                },
            ),
            "failed_safe",
        )

    def test_provider_output_secret_is_redacted_and_task_continues(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(
                root / "registry.yaml",
                selected="gpt-5.6-luna",
            )
            config = make_config(root, registry_path)
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
            )
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli",
                owner_id="owner",
                idea="Sanitize provider transport without blocking the product",
            )
            marker = "ghp_" + ("A" * 24)
            payload = json.loads(product_contract(config, intake_result.product_id))
            payload["summary"] = f"Example credential {marker}"
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner(json.dumps(payload)),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(
                result.status,
                "completed",
                msg=f"reason={result.reason_code}; detail={result.detail}",
            )
            self.assertIsNone(result.reason_code)
            self.assertIsNotNone(result.artifact_ref)
            attempt = json.loads(Path(str(result.artifact_ref)).read_text(encoding="utf-8"))
            self.assertIn(
                "$.summary (github_classic_token)",
                attempt["summary"],
            )
            output_ref = next(
                item["evidence_ref"]
                for item in attempt["test_results"]
                if item["gate_id"] == "schema-validation"
            )
            output = json.loads(Path(output_ref).read_text(encoding="utf-8"))
            self.assertEqual(
                output["summary"],
                "Example credential [REDACTED]",
            )
            self.assertNotIn(marker, attempt["summary"])
            self.assertTrue(
                all(
                    marker not in path.read_text(encoding="utf-8")
                    for path in config.evidence_dir.glob("*.json")
                )
            )
            state.close()

    def test_run_once_renews_lease_during_long_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root,
                selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"),
            )
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            state.create_product(
                product_id="P-LEASE-HEARTBEAT",
                owner_id="owner",
                source="test",
                idea="Verify long task lease renewal",
                idempotency_key="lease-heartbeat-test",
            )
            PipelineCoordinator(config, state).seed_initial("P-LEASE-HEARTBEAT")
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner("{}"),
                repository_root=ROOT,
                lease_seconds=1,
                heartbeat_interval_seconds=0.02,
            )

            def slow_execute(spec: TaskExecutionSpec) -> WorkerResult:
                time.sleep(0.08)
                return WorkerResult(
                    str(spec.task_contract["task_id"]),
                    "completed",
                    None,
                )

            with (
                patch.object(worker, "execute", side_effect=slow_execute),
                patch.object(state, "heartbeat", wraps=state.heartbeat) as heartbeat,
            ):
                result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(
                result.status,
                "completed",
                msg=f"{result.reason_code}: {result.detail}",
            )
            self.assertGreaterEqual(heartbeat.call_count, 2)
            tasks = state.list_tasks("P-LEASE-HEARTBEAT")
            self.assertEqual(tasks[0]["status"], "DONE")
            state.close()

    def test_TXN_P0_006_lost_lease_during_execution_never_commits_result(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root,
                selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"),
            )
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
            )
            try:
                state.create_product(
                    product_id="P-LEASE-LOST",
                    owner_id="owner",
                    source="test",
                    idea="Reject an outcome after lease ownership changes",
                    idempotency_key="lease-lost-during-execution",
                )
                PipelineCoordinator(config, state).seed_initial("P-LEASE-LOST")
                worker = AgentWorker(
                    config,
                    state,
                    runner=FakeRunner("{}"),
                    repository_root=ROOT,
                    lease_seconds=1,
                    heartbeat_interval_seconds=0.01,
                )
                lease_lost = threading.Event()

                def slow_execute(spec: TaskExecutionSpec) -> WorkerResult:
                    assert lease_lost.wait(timeout=1)
                    return WorkerResult(
                        str(spec.task_contract["task_id"]),
                        "completed",
                        None,
                    )

                def lose_lease(*_args: object, **_kwargs: object) -> None:
                    lease_lost.set()
                    raise ValueError("lease ownership changed")

                with (
                    patch.object(worker, "execute", side_effect=slow_execute),
                    patch.object(
                        worker.workflow,
                        "heartbeat",
                        side_effect=lose_lease,
                    ),
                ):
                    result = worker.run_once()

                assert result is not None
                self.assertEqual(result.status, "lease_lost")
                self.assertEqual(result.reason_code, "task_lease_lost")
                task = state.list_tasks("P-LEASE-LOST")[0]
                self.assertEqual(task["status"], "CLAIMED")
                self.assertEqual(
                    state._connection.execute(
                        "SELECT COUNT(*) FROM task_outcomes WHERE task_id=?",
                        (task["task_id"],),
                    ).fetchone()[0],
                    0,
                )
            finally:
                state.close()

    def test_direct_candidate_snapshot_evidence_skips_recursive_ancestry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root,
                selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"),
            )
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
            )
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner("{}"),
                repository_root=ROOT,
            )
            task = {
                "task_id": "T-PRODUCTION-TEST",
                "product_id": "P-PRODUCTION-CANARY",
                "plan_id": "PLAN-PRODUCTION-158",
                "candidate_snapshot_id": "CS-PRODUCTION-158",
            }
            snapshot = {
                "snapshot_id": "CS-PRODUCTION-158",
                "product_id": "P-PRODUCTION-CANARY",
                "plan_id": "PLAN-PRODUCTION-158",
                "status": "FROZEN",
                "result_binding_ids": [f"RB-{index:03d}" for index in range(79)],
            }

            with (
                patch.object(
                    state,
                    "dependency_ancestors",
                    side_effect=AssertionError("historical graph must not be traversed"),
                ) as ancestors,
                patch(
                    "factory.worker.PathGovernor.candidate_snapshot",
                    return_value=snapshot,
                ),
            ):
                evidence = worker._typed_dependency_evidence(
                    task,
                    required_types=["candidate_snapshot"],
                )

            ancestors.assert_not_called()
            self.assertEqual(len(evidence), 1)
            self.assertEqual(evidence[0]["type"], "typed-candidate_snapshot")
            self.assertEqual(
                evidence[0]["artifact_ref"],
                "internal://candidate-snapshot/CS-PRODUCTION-158",
            )
            self.assertIn("CS-PRODUCTION-158", evidence[0]["summary"])
            state.close()

    def test_schema_valid_repair_is_requeued_with_targeted_brief(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli", owner_id="owner", idea="Repairable provider task"
            )
            repair = json.loads(product_contract(config, intake_result.product_id))
            repair["status"] = "repair_required"
            repair["summary"] = "The provider needs one targeted repair before acceptance."
            completed = json.loads(product_contract(config, intake_result.product_id))
            runner = SequenceRunner([json.dumps(repair), json.dumps(completed)])
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            first = worker.run_once()

            self.assertIsNotNone(first)
            assert first is not None
            self.assertEqual(first.status, "repair_required")
            source_task = next(iter(state.list_tasks(intake_result.product_id)))
            self.assertEqual(source_task["status"], "FAILED_SAFE")
            self.assertEqual(source_task["graph_status"], "FAILED_SEMANTIC")
            self.assertEqual(len(state.list_failures(intake_result.product_id)), 1)

            recovery = PipelineReconciler(config, state).reconcile_once()

            self.assertEqual(recovery.repaired, 1)
            tasks = state.list_tasks(intake_result.product_id)
            self.assertEqual(len(tasks), 2)
            task = next(item for item in tasks if item["task_id"] != source_task["task_id"])
            self.assertEqual(task["status"], "PENDING")
            self.assertEqual(task["graph_status"], "READY")
            self.assertEqual(task["parent_task_id"], source_task["task_id"])
            self.assertEqual(task["source_task_id"], source_task["task_id"])
            self.assertEqual(task["root_task_id"], source_task["root_task_id"])
            self.assertEqual(task["next_attempt_kind"], "initial")
            brief_paths = list(config.evidence_dir.glob("repair-brief-*.json"))
            self.assertEqual(len(brief_paths), 1)
            brief = json.loads(brief_paths[0].read_text(encoding="utf-8"))
            self.assertEqual(brief["schema_version"], "2.0")
            self.assertEqual(brief["failed_task_id"], source_task["task_id"])
            self.assertEqual(brief["hypothesis_id"], task["hypothesis_id"])
            self.assertTrue(brief["failed_gate_ids"])
            self.assertTrue(brief["required_fixes"])
            self.assertEqual(brief["allowed_paths"], ["artifacts/**"])

            second = worker.run_once()

            self.assertIsNotNone(second)
            assert second is not None
            self.assertEqual(second.status, "completed", second.reason_code)
            repaired = state.get_task(str(task["task_id"]))
            self.assertIsNotNone(repaired)
            assert repaired is not None
            self.assertEqual(repaired["status"], "DONE")
            superseded = state.get_task(str(source_task["task_id"]))
            self.assertIsNotNone(superseded)
            assert superseded is not None
            self.assertEqual(superseded["graph_status"], "SUPERSEDED")
            self.assertEqual(len(state.attempts_for_task(str(task["task_id"]))), 1)
            self.assertIn("repair-brief-", runner.prompts[1])
            self.assertIn("UNTRUSTED_DATA targeted repair brief", runner.prompts[1])
            self.assertIn(str(brief["failure_id"]), runner.prompts[1])
            state.close()

    def test_partial_repair_brief_fails_internally_before_provider_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
            )
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli",
                owner_id="owner",
                idea="Reject an incomplete internal repair brief",
            )
            task = state.claim_task(worker_id="failed-worker")
            self.assertIsNotNone(task)
            assert task is not None
            state.complete_task(
                str(task["task_id"]),
                "failed-worker",
                "FAILED_SAFE",
                reason_code="worker_internal_error",
                detail="repair preparation failed",
                failure_kind="semantic",
            )
            bad_brief = {
                **artifact_metadata(
                    config,
                    "repair-coordinator",
                    "repair-brief-partial-test",
                    intake_result.product_id,
                ),
                "producer": {
                    "role": "repair-coordinator",
                    "tier": "deterministic",
                    "provider": None,
                    "model": None,
                },
                "task_id": str(task["task_id"]),
                "attempt_id": "attempt-partial-brief",
                "failure_class": "worker_internal_error",
                "failed_gate_ids": ["repair-brief-validation"],
                "required_fixes": ["Attach the exact allowed paths."],
                "relevant_log_fragment": "allowed_paths is missing",
                "expected_vs_actual": {
                    "expected": "a complete actionable brief",
                    "actual": "allowed_paths is missing",
                },
                "changed_files": [],
                "forbidden_actions": [],
                "previous_attempt_summary": "Repair preparation failed.",
                "definition_of_done": ["The brief passes schema validation."],
                "evidence_refs": [f"evidence/task-{task['task_id']}.json"],
            }
            brief_path = config.evidence_dir / (f"repair-brief-{task['task_id']}-partial.json")
            brief_path.write_text(json.dumps(bad_brief), encoding="utf-8")
            state.requeue_terminal_task(
                str(task["task_id"]),
                next_tier="luna",
                repair_context_ref=f"evidence/{brief_path.name}",
            )
            runner = FakeRunner(product_contract(config, intake_result.product_id))
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(
                result.reason_code,
                "controller_exception_value_error",
            )
            self.assertEqual(runner.calls, [])
            durable = state.get_task(str(task["task_id"]))
            self.assertIsNotNone(durable)
            assert durable is not None
            self.assertEqual(durable["status"], "FAILED_SAFE")
            self.assertEqual(
                durable["repair_context_ref"],
                f"evidence/{brief_path.name}",
            )
            failure = state.list_failures(intake_result.product_id)[-1]
            self.assertEqual(failure["exception_type"], "ValueError")
            self.assertTrue(failure["stack_fingerprint"])
            actual = json.loads(str(failure["actual_json"]))
            self.assertIn("traceback_excerpt", actual)
            state.close()

    def test_semantic_backlog_error_schedules_exact_repair_without_worker_crash(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root,
                selected_registry(
                    root / "registry.yaml",
                    selected="gpt-5.6-luna",
                ),
            )
            state = StateStore(config.database_path)
            artifacts = ArtifactStore(config)
            product_id = "P-SEMANTIC-PLAN"
            task_id = "T-SEMANTIC-REPLANNER"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="test",
                idea="Repair a semantically invalid BacklogPlan",
                idempotency_key="semantic-plan-product",
            )
            task_contract = replanner_task_contract(
                config,
                product_id,
                task_id,
            )
            contract_path = artifacts.write(
                "task-contract-v2.schema.json",
                task_contract,
                filename=f"task-{task_id}.json",
            )
            state.add_task(
                task_id=task_id,
                product_id=product_id,
                title=str(task_contract["title"]),
                role="replanner",
                output_schema="backlog-plan-v2.schema.json",
                contract_ref=f"evidence/{contract_path.name}",
                conflict_keys=[f"{product_id}:planning"],
                priority=100,
                capability_profile="planning_readonly",
                idempotency_key=str(task_contract["idempotency_key"]),
                required_capabilities=[
                    str(value) for value in task_contract["required_capabilities"]
                ],
            )
            plan = backlog_plan_with_missing_edge(
                config,
                product_id,
                task_id,
            )
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner(json.dumps(plan)),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )
            durable_task = state.get_task(task_id)
            self.assertIsNotNone(durable_task)
            assert durable_task is not None
            spec = worker.default_spec(durable_task)
            proposal_decision = next(
                item
                for item in spec.decisions
                if "Return semantic implementation slices only" in item
            )
            self.assertIn(
                "deterministic PlanCompiler",
                proposal_decision,
            )
            self.assertNotIn("output_schema=", proposal_decision)
            self.assertNotIn("idempotency_key", proposal_decision)
            handoff_decision = next(
                item
                for item in spec.decisions
                if "Replanner acceptance evaluates the PlanProposal handoff" in item
            )
            self.assertIn("future product gates have not run yet", handoff_decision)

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "repair_scheduled")
            self.assertEqual(result.reason_code, "schema_validation")
            expected = "replanner must return proposal_kind=replan_delta"
            self.assertEqual(
                result.detail,
                expected,
            )
            durable = state.get_task(task_id)
            self.assertIsNotNone(durable)
            assert durable is not None
            self.assertEqual(durable["status"], "PENDING")
            self.assertEqual(durable["graph_status"], "READY")
            self.assertEqual(durable["next_attempt_kind"], "repair")
            self.assertTrue(durable["repair_context_ref"])
            repair = json.loads(
                next(config.evidence_dir.glob(f"repair-brief-{task_id}-*.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                repair["failed_gate_ids"],
                ["BACKLOG_PLAN_SEMANTIC_VALIDATION"],
            )
            self.assertIn(
                expected,
                repair["expected_vs_actual"]["actual"],
            )
            diagnostic = json.loads(
                next(config.evidence_dir.glob("transport-diagnostic-*.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                diagnostic["parser_error_safe_message"],
                expected,
            )
            self.assertIn(
                f"evidence/transport-diagnostic-{result.attempt_id}.json",
                repair["evidence_refs"],
            )
            envelope = json.loads(
                next(config.evidence_dir.glob("failure-envelope-*.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                envelope["safe_message"],
                expected,
            )
            self.assertEqual(
                envelope["actual"]["validator_diagnostic"],
                expected,
            )
            self.assertEqual(
                envelope["failed_gate_ids"],
                ["BACKLOG_PLAN_SEMANTIC_VALIDATION"],
            )
            self.assertEqual(len(state.list_tasks(product_id)), 1)
            self.assertFalse((config.evidence_dir / "task-T-SEMANTIC-CHILD.json").exists())
            state.close()

    def test_output_schema_coordinate_reaches_repair_and_failure_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root,
                selected_registry(
                    root / "registry.yaml",
                    selected="gpt-5.6-luna",
                ),
            )
            state = StateStore(config.database_path)
            artifacts = ArtifactStore(config)
            product_id = "P-SCHEMA-PLAN"
            task_id = "T-SCHEMA-REPLANNER"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="test",
                idea="Repair an output-schema coordinate",
                idempotency_key="schema-plan-product",
            )
            task_contract = replanner_task_contract(
                config,
                product_id,
                task_id,
            )
            contract_path = artifacts.write(
                "task-contract-v2.schema.json",
                task_contract,
                filename=f"task-{task_id}.json",
            )
            state.add_task(
                task_id=task_id,
                product_id=product_id,
                title=str(task_contract["title"]),
                role="replanner",
                output_schema="backlog-plan-v2.schema.json",
                contract_ref=f"evidence/{contract_path.name}",
                conflict_keys=[f"{product_id}:planning"],
                priority=100,
                capability_profile="planning_readonly",
                idempotency_key=str(task_contract["idempotency_key"]),
                required_capabilities=[
                    str(value) for value in task_contract["required_capabilities"]
                ],
            )
            plan = backlog_plan_with_missing_edge(
                config,
                product_id,
                task_id,
            )
            del plan["nodes"][0]["task_contract"]["forbidden_paths"]
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner(json.dumps(plan)),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            expected = (
                "Invalid backlog-plan-v2.schema.json: 'forbidden_paths' is a required property"
            )
            self.assertEqual(result.status, "repair_scheduled")
            self.assertEqual(result.reason_code, "schema_validation")
            self.assertEqual(result.detail, expected)
            repair = json.loads(
                next(config.evidence_dir.glob(f"repair-brief-{task_id}-*.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(repair["expected_vs_actual"]["actual"], expected)
            self.assertIn(expected, repair["previous_attempt_summary"])
            envelope = json.loads(
                next(config.evidence_dir.glob("failure-envelope-*.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(envelope["safe_message"], expected)
            self.assertEqual(envelope["actual"]["validator_diagnostic"], expected)
            self.assertEqual(envelope["failed_gate_ids"], ["OUTPUT_SCHEMA_VALIDATION"])
            diagnostic_ref = f"evidence/transport-diagnostic-{result.attempt_id}.json"
            self.assertIn(diagnostic_ref, repair["evidence_refs"])
            attempt = json.loads(Path(str(result.artifact_ref)).read_text(encoding="utf-8"))
            self.assertIn(diagnostic_ref, attempt["evidence_refs"])
            state.close()

    def test_terminal_schema_failure_preserves_safe_coordinate_for_replanner(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root,
                selected_registry(
                    root / "registry.yaml",
                    selected="gpt-5.6-luna",
                ),
            )
            state = StateStore(config.database_path)
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli",
                owner_id="owner",
                idea="Preserve the final safe schema coordinate",
            )
            secret = "ghp_" + "A" * 24
            runner = SequenceRunner([json.dumps({"credential": secret})])
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )
            task = state.list_tasks(intake_result.product_id)[0]

            with patch.object(worker, "_route", return_value="stop"):
                result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(result.reason_code, "schema_validation")
            self.assertIsNotNone(result.detail)
            assert result.detail is not None
            self.assertIn(str(task["output_schema"]), result.detail)
            self.assertNotIn(secret, result.detail)
            failure = state.list_failures(intake_result.product_id)[-1]
            self.assertEqual(failure["safe_message"], result.detail)
            self.assertEqual(
                json.loads(failure["actual_json"])["validator_diagnostic"],
                result.detail,
            )
            self.assertEqual(
                json.loads(failure["failed_gate_ids_json"]),
                ["OUTPUT_SCHEMA_VALIDATION"],
            )
            attempt = json.loads(Path(str(result.artifact_ref)).read_text(encoding="utf-8"))
            self.assertIn(result.detail, attempt["summary"])
            diagnostic_ref = f"evidence/transport-diagnostic-{result.attempt_id}.json"
            self.assertIn(diagnostic_ref, attempt["evidence_refs"])
            self.assertNotIn(secret, "\n".join(runner.prompts))
            for path in config.evidence_dir.glob("*.json"):
                self.assertNotIn(secret, path.read_text(encoding="utf-8"))
            state.close()

    def test_AUT_P0_036_interrupted_attempt_replays_without_provider_call(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root,
                selected_registry(
                    root / "registry.yaml",
                    selected="gpt-5.6-luna",
                ),
            )
            state = StateStore(config.database_path)
            artifacts = ArtifactStore(config)
            product_id = "P-INTERRUPTED-PLAN"
            task_id = "T-INTERRUPTED-REPLANNER"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="test",
                idea="Resume an interrupted planning attempt",
                idempotency_key="interrupted-plan-product",
            )
            task_contract = replanner_task_contract(
                config,
                product_id,
                task_id,
            )
            contract_path = artifacts.write(
                "task-contract-v2.schema.json",
                task_contract,
                filename=f"task-{task_id}.json",
            )
            state.add_task(
                task_id=task_id,
                product_id=product_id,
                title=str(task_contract["title"]),
                role="replanner",
                output_schema="backlog-plan-v2.schema.json",
                contract_ref=f"evidence/{contract_path.name}",
                conflict_keys=[f"{product_id}:planning"],
                priority=100,
                capability_profile="planning_readonly",
                idempotency_key=str(task_contract["idempotency_key"]),
                required_capabilities=[
                    str(value) for value in task_contract["required_capabilities"]
                ],
            )
            plan = backlog_plan_with_missing_edge(
                config,
                product_id,
                task_id,
            )
            first_runner = FakeRunner(json.dumps(plan))
            first_worker = AgentWorker(
                config,
                state,
                runner=first_runner,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )
            task = state.get_task(task_id)
            self.assertIsNotNone(task)
            assert task is not None

            interrupted = first_worker.execute(first_worker.default_spec(task))

            self.assertEqual(interrupted.status, "repair_scheduled")
            attempts = state.attempts_for_task(task_id)
            self.assertEqual(len(attempts), 1)
            self.assertEqual(attempts[0]["status"], "started")
            attempt_path = Path(str(interrupted.artifact_ref))
            self.assertTrue(attempt_path.is_file())
            # Releases before the semantic-plan boundary fix could persist a
            # schema-valid provider result as completed and crash while
            # preparing the graph. Reproduce that exact restart window.
            legacy_attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
            legacy_attempt["status"] = "completed"
            legacy_attempt["summary"] = "Provider execution completed before graph validation."
            legacy_attempt["findings"] = []
            attempt_path.write_text(
                json.dumps(
                    legacy_attempt,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
                newline="\n",
            )

            second_runner = FakeRunner("{}")
            restarted_worker = AgentWorker(
                config,
                state,
                runner=second_runner,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )
            recovered = restarted_worker.run_once()

            self.assertIsNotNone(recovered)
            assert recovered is not None
            self.assertEqual(recovered.status, "repair_scheduled")
            self.assertEqual(recovered.reason_code, "schema_validation")
            self.assertEqual(recovered.artifact_ref, str(attempt_path))
            self.assertEqual(second_runner.calls, [])
            self.assertEqual(len(state.attempts_for_task(task_id)), 1)
            durable = state.get_task(task_id)
            self.assertIsNotNone(durable)
            assert durable is not None
            self.assertEqual(durable["status"], "PENDING")
            self.assertEqual(durable["graph_status"], "READY")
            self.assertEqual(durable["next_attempt_kind"], "repair")
            state.close()

    def test_outcome_commit_integrity_error_becomes_controller_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(
                root,
                selected_registry(
                    root / "registry.yaml",
                    selected="gpt-5.6-luna",
                ),
            )
            state = StateStore(config.database_path)
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli",
                owner_id="owner",
                idea="Persist a controller failure instead of crashing",
            )
            original_commit = state.commit_task_outcome
            commit_calls = 0

            def fail_first_commit(outcome: object) -> object:
                nonlocal commit_calls
                commit_calls += 1
                if commit_calls == 1:
                    raise sqlite3.IntegrityError("UNIQUE constraint failed: tasks.idempotency_key")
                return original_commit(outcome)

            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner(product_contract(config, intake_result.product_id)),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )
            with patch.object(
                state,
                "commit_task_outcome",
                side_effect=fail_first_commit,
            ):
                result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(
                result.reason_code,
                "controller_exception_integrity_error",
            )
            self.assertEqual(commit_calls, 2)
            task = state.list_tasks(intake_result.product_id)[0]
            self.assertEqual(task["status"], "FAILED_SAFE")
            self.assertEqual(task["graph_status"], "FAILED_SEMANTIC")
            failure = state.list_failures(intake_result.product_id)[-1]
            self.assertEqual(failure["failure_class"], "controller")
            self.assertEqual(
                failure["reason_code"],
                "controller_exception_integrity_error",
            )
            self.assertEqual(failure["exception_type"], "IntegrityError")
            state.close()

    def test_malformed_transport_is_requeued_at_same_tier_and_can_resume(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli", owner_id="owner", idea="Resume after transient provider failure"
            )
            runner = SequenceRunner(
                ["not-json", product_contract(config, intake_result.product_id)]
            )
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            first = worker.run_once()

            self.assertIsNotNone(first)
            assert first is not None
            self.assertEqual(first.status, "repair_scheduled")
            self.assertEqual(first.reason_code, "malformed_transport")
            task = next(iter(state.list_tasks(intake_result.product_id)))
            self.assertEqual(task["status"], "WAITING")
            self.assertEqual(task["graph_status"], "WAITING_TIME")
            self.assertTrue(task["available_at"])
            attempts = state.attempts_for_task(str(task["task_id"]))
            self.assertEqual(len(attempts), 1)
            self.assertEqual(attempts[0]["attempt_kind"], "initial")

            make_retry_due(state, str(task["task_id"]))
            second = worker.run_once()

            self.assertIsNotNone(second)
            assert second is not None
            self.assertEqual(second.status, "completed")
            attempts = state.attempts_for_task(str(task["task_id"]))
            self.assertEqual(len(attempts), 2)
            self.assertEqual(attempts[1]["attempt_kind"], "transient_retry")
            self.assertNotEqual(attempts[0]["prompt_digest"], attempts[1]["prompt_digest"])
            self.assertIn("repair-brief-", runner.prompts[1])
            state.close()

    def test_transient_retry_preserves_original_repair_hypothesis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(
                root / "registry.yaml",
                selected="gpt-5.6-luna",
            )
            config = make_config(root, registry_path)
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
            )
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli",
                owner_id="owner",
                idea="Preserve the diagnosed repair across a transient retry",
            )
            repair = json.loads(product_contract(config, intake_result.product_id))
            repair["status"] = "repair_required"
            repair["summary"] = "The original security hypothesis needs one repair."
            repair["findings"] = [
                {
                    "code": "SEC-ORIGINAL-HYPOTHESIS",
                    "severity": "high",
                    "text": "Add the exact original security regression.",
                }
            ]
            completed = json.loads(product_contract(config, intake_result.product_id))
            runner = SequenceRunner(
                [
                    json.dumps(repair),
                    "not-json",
                    json.dumps(completed),
                ]
            )
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            first = worker.run_once()

            self.assertIsNotNone(first)
            assert first is not None
            self.assertEqual(first.status, "repair_required")
            source_task = next(iter(state.list_tasks(intake_result.product_id)))
            recovery = PipelineReconciler(config, state).reconcile_once()
            self.assertEqual(recovery.repaired, 1)
            task = next(
                item
                for item in state.list_tasks(intake_result.product_id)
                if item["task_id"] != source_task["task_id"]
            )
            original_ref = str(task["repair_context_ref"])
            original_brief = json.loads(
                (config.evidence_dir / Path(original_ref).name).read_text(encoding="utf-8")
            )
            self.assertEqual(
                original_brief["failed_gate_ids"],
                ["SEC-ORIGINAL-HYPOTHESIS"],
            )

            second = worker.run_once()

            self.assertIsNotNone(second)
            assert second is not None
            self.assertEqual(second.status, "repair_scheduled")
            self.assertEqual(second.reason_code, "malformed_transport")
            task = state.get_task(str(task["task_id"]))
            self.assertIsNotNone(task)
            assert task is not None
            self.assertEqual(task["status"], "WAITING")
            self.assertEqual(task["graph_status"], "WAITING_TIME")
            transient_ref = str(task["repair_context_ref"])
            self.assertNotEqual(transient_ref, original_ref)
            transient_brief = json.loads(
                (config.evidence_dir / Path(transient_ref).name).read_text(encoding="utf-8")
            )
            self.assertEqual(
                transient_brief["failed_gate_ids"],
                ["SEC-ORIGINAL-HYPOTHESIS"],
            )
            self.assertEqual(
                transient_brief["required_fixes"],
                original_brief["required_fixes"],
            )
            self.assertEqual(
                transient_brief["hypothesis_id"],
                original_brief["hypothesis_id"],
            )
            self.assertIn(original_ref, transient_brief["evidence_refs"])

            make_retry_due(state, str(task["task_id"]))
            third = worker.run_once()

            self.assertIsNotNone(third)
            assert third is not None
            self.assertEqual(third.status, "completed", third.reason_code)
            self.assertIn("SEC-ORIGINAL-HYPOTHESIS", runner.prompts[2])
            self.assertIn(
                "Add the exact original security regression.",
                runner.prompts[2],
            )
            state.close()

    def test_release_task_blocks_before_model_without_side_effect_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            product_id, _ = staging_release_task(config, state, artifacts)
            runner = FakeRunner(
                json.dumps(
                    release_operation(
                        config,
                        product_id,
                        candidate_sha="a" * 40,
                        image_digest="sha256:" + "b" * 64,
                    )
                )
            )
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(result.reason_code, "release_adapter_missing")
            self.assertEqual(result.detail, "release side-effect adapter is not configured")
            self.assertEqual(runner.calls, [])
            task = next(iter(state.list_tasks(product_id)))
            self.assertEqual(task["status"], "FAILED_SAFE")
            self.assertEqual(task["graph_status"], "FAILED_SEMANTIC")
            self.assertEqual(state.attempts_for_task(str(task["task_id"])), [])
            failure = state.list_failures(product_id)[0]
            self.assertEqual(failure["failure_class"], "controller")
            self.assertEqual(
                list(config.evidence_dir.glob("owner-action-*.json")),
                [],
            )
            state.close()

    def test_completed_duplicate_prompt_is_internal_not_external(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli",
                owner_id="owner",
                idea="Classify a duplicate prompt safely",
            )
            runner = FakeRunner(product_contract(config, intake_result.product_id))
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            with patch.object(
                worker.attempts,
                "begin",
                side_effect=IdenticalAttemptError("Prompt digest already attempted"),
            ):
                result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(result.reason_code, "duplicate_prompt_attempt")
            task = next(iter(state.list_tasks(intake_result.product_id)))
            self.assertEqual(task["status"], "FAILED_SAFE")
            self.assertEqual(task["terminal_reason"], "duplicate_prompt_attempt")
            self.assertEqual(runner.calls, [])
            state.close()

    def test_release_task_persists_only_adapter_authoritative_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            product_id, _ = staging_release_task(config, state, artifacts)
            proposed = release_operation(
                config,
                product_id,
                candidate_sha="a" * 40,
                image_digest="sha256:" + "b" * 64,
            )
            authoritative = release_operation(
                config,
                product_id,
                candidate_sha="c" * 40,
                image_digest="sha256:" + "d" * 64,
            )
            executor = RecordingReleaseExecutor(authoritative)
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner(json.dumps(proposed)),
                release_executor=executor,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(
                result.status,
                "completed",
                msg=(
                    f"reason={result.reason_code}; detail={result.detail}; "
                    f"executor_calls={executor.calls}"
                ),
            )
            self.assertEqual(len(executor.calls), 1)
            self.assertEqual(executor.calls[0]["proposed"], proposed)
            output_paths = list(config.evidence_dir.glob("release-operation-result-*.json"))
            self.assertEqual(len(output_paths), 1)
            persisted = json.loads(output_paths[0].read_text(encoding="utf-8"))
            self.assertEqual(persisted["candidate_sha"], "c" * 40)
            self.assertEqual(persisted["release"]["image_digest"], "sha256:" + "d" * 64)
            self.assertEqual(state.get_product(product_id)["status"], "STAGING_DEPLOYED")
            state.close()

    def test_release_scope_is_checked_before_adapter_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            product_id, _ = staging_release_task(config, state, artifacts)
            proposed = release_operation(
                config,
                product_id,
                candidate_sha="a" * 40,
                image_digest="sha256:" + "b" * 64,
            )
            executor = RecordingReleaseExecutor(proposed)
            worker = AgentWorker(
                config,
                state,
                runner=ScopeViolatingRunner(json.dumps(proposed)),
                release_executor=executor,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(result.reason_code, "scope_violation")
            self.assertEqual(executor.calls, [])
            state.close()

    def test_TXN_P0_003_release_worker_reconciles_effect_before_receipt_after_crash(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            product_id, contract_path = staging_release_task(config, state, artifacts)
            task_contract = json.loads(contract_path.read_text(encoding="utf-8"))
            task = state.list_tasks(product_id)[0]
            postcondition = {
                "product_id": product_id,
                "task_id": str(task["task_id"]),
                "stage": "staging",
                "expected_staging_digest": "not-applicable",
            }
            side_effect_key = sha256_text(
                stable_json(
                    [
                        task_contract.get("idempotency_key"),
                        postcondition,
                        "release-adapter-v2",
                    ]
                )
            )
            with state._connection:
                protocol = SideEffectProtocol(state._connection)
                intent_id = protocol.prepare(
                    product_id=product_id,
                    operation="release:staging",
                    adapter="configured-release-executor",
                    idempotency_key=side_effect_key,
                    expected_postcondition=postcondition,
                )
                protocol.mark_executing(intent_id)

            authoritative = release_operation(
                config,
                product_id,
                candidate_sha="c" * 40,
                image_digest="sha256:" + "d" * 64,
            )

            class ReconcileOnlyExecutor:
                def __init__(self) -> None:
                    self.execute_calls = 0
                    self.reconcile_calls = 0

                def execute(self, **_: Any) -> Mapping[str, Any]:
                    self.execute_calls += 1
                    raise AssertionError("external effect must not be executed twice")

                def reconcile(self, **_: Any) -> Mapping[str, Any]:
                    self.reconcile_calls += 1
                    return authoritative

            executor = ReconcileOnlyExecutor()
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner(json.dumps(authoritative)),
                release_executor=executor,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            result = worker.run_once()

            assert result is not None
            self.assertEqual(result.status, "completed")
            self.assertEqual(executor.execute_calls, 0)
            self.assertEqual(executor.reconcile_calls, 1)
            self.assertEqual(SideEffectProtocol(state._connection).status(intent_id), "VERIFIED")
            state.close()

    def test_worker_runs_selected_provider_and_persists_contract_and_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            intake = IntakeService(config, state, artifacts)
            intake_result = intake.submit(
                source="cli", owner_id="owner", idea="Build a safe product"
            )
            runner = UsageRunner(product_contract(config, intake_result.product_id))
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda selection: selection.model == "gpt-5.6-luna",
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "completed")
            self.assertEqual(runner.calls[0][0:2], ("gpt-5.6-luna", "openai_codex_subscription"))
            self.assertTrue(runner.calls[0][2].is_relative_to(config.state_dir / "worktrees"))
            product = state.get_product(intake_result.product_id)
            self.assertIsNotNone(product)
            assert product is not None
            self.assertEqual(product["status"], "RISK_CLASSIFIED")
            task_files = list(config.evidence_dir.glob("task-T-*.json"))
            self.assertEqual(len(task_files), 2)
            tasks = state.list_tasks(intake_result.product_id)
            director_tasks = [task for task in tasks if task["role"] == "product-director"]
            analyst_tasks = [task for task in tasks if task["role"] == "product-analyst"]
            self.assertEqual(len(director_tasks), 1)
            self.assertEqual(len(analyst_tasks), 1)
            task_id = str(director_tasks[0]["task_id"])
            task = state.get_task(task_id)
            self.assertIsNotNone(task)
            assert task is not None
            self.assertEqual(task["status"], "DONE")
            self.assertEqual(analyst_tasks[0]["status"], "PENDING")
            attempts = state.attempts_for_task(task_id)
            self.assertEqual(len(attempts), 1)
            self.assertEqual(attempts[0]["status"], "completed")
            attempt_artifact = json.loads(
                Path(result.artifact_ref or "").read_text(encoding="utf-8")
            )
            self.assertEqual(artifacts.validate("attempt-result.schema.json", attempt_artifact), [])
            self.assertTrue(
                any(ref.startswith("evidence/usage-") for ref in attempt_artifact["evidence_refs"])
            )
            state.close()

    def test_completed_dependency_output_is_in_next_context_pack(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            intake_result = IntakeService(config, state, artifacts).submit(
                source="cli", owner_id="owner", idea="Build a dependency-aware product"
            )
            runner = SequenceRunner(
                [
                    product_contract(config, intake_result.product_id),
                    requirements_package(config, intake_result.product_id),
                ]
            )
            health_checks: list[str] = []

            def health_probe(selection: Any) -> bool:
                health_checks.append(selection.provider)
                return True

            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=health_probe,
                repository_root=ROOT,
            )

            first = worker.run_once()
            analyst_task = state.list_tasks(intake_result.product_id)[1]
            current_spec = worker.default_spec(analyst_task)
            stale_spec = replace(
                current_spec,
                evidence=tuple(
                    item
                    for item in current_spec.evidence
                    if item.get("type") != "dependency-result"
                ),
            )
            worker._context_and_prompt(stale_spec)
            second = worker.run_once()

            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            assert second is not None
            self.assertEqual(second.status, "completed")
            self.assertEqual(len(runner.prompts), 2)
            self.assertIn("UNTRUSTED_DATA accepted output for dependency", runner.prompts[1])
            self.assertIn("product-contract-worker-test", runner.prompts[1])
            self.assertIn(
                "Do not run repository commands such as pytest or make", runner.prompts[1]
            )
            completed_task = state.get_task(str(analyst_task["task_id"]))
            self.assertIsNotNone(completed_task)
            assert completed_task is not None
            self.assertEqual(completed_task["status"], "DONE")
            context_paths = list(
                config.evidence_dir.glob(f"context-{analyst_task['task_id']}*.json")
            )
            self.assertEqual(len(context_paths), 2)
            self.assertEqual(len(health_checks), 1)
            state.close()

    def test_independent_reviewer_gets_upstream_and_dependency_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(
                root / "registry.yaml",
                selected="gpt-5.6-terra",
            )
            config = make_config(root / "state", registry_path)
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
            )
            product_id = "P-INDEPENDENT-CONTEXT"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="test",
                idea="Review one immutable candidate",
                idempotency_key="independent-context-test",
            )
            task_path = PipelineCoordinator(
                config,
                state,
                ArtifactStore(config),
            ).create_task(product_id, "independent-reviewer")
            task_id = json.loads(task_path.read_text(encoding="utf-8"))["task_id"]
            task = state.get_task(task_id)
            assert task is not None
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner("{}"),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )
            upstream = {
                "type": "accepted-review-evidence",
                "summary": "complete upstream contracts and gates",
                "artifact_ref": "evidence/upstream.json",
            }
            dependency = {
                "type": "dependency-result",
                "summary": "accepted security review",
                "artifact_ref": "evidence/security.json",
            }

            with (
                patch.object(
                    worker,
                    "_completed_review_evidence",
                    return_value=[upstream],
                ) as completed,
                patch.object(
                    worker,
                    "_dependency_evidence",
                    return_value=[dependency],
                ) as dependencies,
            ):
                spec = worker.default_spec(task)

            completed.assert_called_once_with(
                task,
                include_security_dependency=True,
            )
            dependencies.assert_called_once_with(task)
            self.assertIn(upstream, spec.evidence)
            self.assertIn(dependency, spec.evidence)
            self.assertTrue(
                any(
                    "not a Git commit ID" in item and "git rev-parse HEAD" in item
                    for item in spec.decisions
                )
            )
            state.close()

    def test_deferred_builder_output_is_accepted_by_test_engineer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(
                root / "registry.yaml",
                selected="gpt-5.6-luna",
            )
            config = make_config(root, registry_path)
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
                max_active_products=2,
            )
            artifacts = ArtifactStore(config)
            product_id = "deferred-builder-worker-product"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="cli",
                idea="https://github.com/brullik/example-product",
                idempotency_key="deferred-builder-worker-key",
            )
            for status in (
                "CONTRACT_DRAFTED",
                "CONTRACT_VALIDATED",
                "RISK_CLASSIFIED",
                "ARCHITECTED",
                "BACKLOG_READY",
                "IMPLEMENTING",
                "REPAIRING",
            ):
                state.transition_product(product_id, status)
            pipeline = PipelineCoordinator(config, state, artifacts)
            builder_path = pipeline.create_task(
                product_id,
                "builder-core",
                cycle=3,
            )
            builder_id = str(json.loads(builder_path.read_text(encoding="utf-8"))["task_id"])
            attempt_id = "attempt-deferred-builder"
            changed_files = [
                {
                    "path": "src/product.py",
                    "change": "Completed the locally accepted implementation.",
                }
            ]
            output = {
                **artifact_metadata(
                    config,
                    "builder",
                    "builder-deferred-output",
                    product_id,
                ),
                "producer": {
                    "role": "builder",
                    "tier": "sol",
                    "provider": "openai_codex_subscription",
                    "model": "gpt-5.6-sol",
                },
                "task_id": builder_id,
                "attempt_id": attempt_id,
                "tier": "sol",
                "attempt_kind": "repair",
                "prompt_digest": "a" * 64,
                "subject_sha_before": "b" * 64,
                "status": "blocked_external",
                "summary": "Implementation and local PM acceptance are complete.",
                "changed_files": changed_files,
                "commands": [
                    {
                        "command_id": "local-acceptance",
                        "result": "pass",
                        "artifact_ref": "evidence/local-acceptance.json",
                    }
                ],
                "test_results": [
                    {
                        "gate_id": "target-tests",
                        "status": "PASS",
                        "evidence_ref": "pytest: pass",
                    },
                    {
                        "gate_id": "local-pm-acceptance",
                        "status": "PASS",
                        "evidence_ref": "pm: pass",
                    },
                    {
                        "gate_id": "AC-PM-SCOPE-GITHUB",
                        "status": "NOT_RUN",
                        "evidence_ref": None,
                    },
                ],
                "assumptions": [],
                "findings": [
                    {
                        "code": "GITHUB_REQUIRED_CHECK_NOT_RUN",
                        "severity": "medium",
                        "text": "The immutable candidate check belongs to staging.",
                    }
                ],
                "evidence_refs": [],
            }
            output_path = artifacts.write(
                "attempt-result.schema.json",
                output,
                filename="builder-deferred-output.json",
            )
            attempt_artifact = {
                **artifact_metadata(
                    config,
                    "builder",
                    "builder-deferred-attempt",
                    product_id,
                ),
                "producer": {
                    "role": "builder",
                    "tier": "sol",
                    "provider": "openai_codex_subscription",
                    "model": "gpt-5.6-sol",
                },
                "task_id": builder_id,
                "attempt_id": attempt_id,
                "tier": "sol",
                "attempt_kind": "repair",
                "prompt_digest": "a" * 64,
                "subject_sha_before": "b" * 64,
                "status": "blocked_external",
                "summary": "Provider reported a downstream-only blocker.",
                "changed_files": changed_files,
                "commands": [
                    {
                        "command_id": "hermes-oneshot",
                        "result": "pass",
                        "artifact_ref": "evidence/context.json",
                    }
                ],
                "test_results": [
                    {
                        "gate_id": "schema-validation",
                        "status": "PASS",
                        "evidence_ref": str(output_path),
                    },
                    {
                        "gate_id": "target-tests",
                        "status": "PASS",
                        "evidence_ref": "evidence/tests.json",
                    },
                    {
                        "gate_id": "target-lint",
                        "status": "FAIL",
                        "evidence_ref": "evidence/lint.json",
                    },
                ],
                "assumptions": [],
                "findings": [
                    {
                        "code": "model_requested_repair",
                        "severity": "medium",
                        "text": "Provider requested repair.",
                    }
                ],
                "evidence_refs": [str(output_path)],
            }
            attempt_path = artifacts.write(
                "attempt-result.schema.json",
                attempt_artifact,
                filename=f"attempt-{attempt_id}.json",
            )
            claimed = state.claim_task(worker_id="builder-worker")
            self.assertIsNotNone(claimed)
            self.assertTrue(
                state.record_attempt(
                    attempt_id=attempt_id,
                    task_id=builder_id,
                    tier="sol",
                    attempt_kind="repair",
                    prompt_digest="a" * 64,
                    status="repair_required",
                    semantic_counted=True,
                    reason_code="model_requested_repair",
                )
            )
            state.complete_task(
                builder_id,
                "builder-worker",
                "BLOCKED_EXTERNAL",
                reason_code="model_requested_repair",
                detail="GitHub required check was not run.",
                result_ref=str(attempt_path),
                failure_kind="semantic",
            )
            state.transition_product(product_id, "FAILED_SAFE")
            with state._lock, state._connection:
                RecoveryCertificateService(state._connection).issue(
                    product_id=product_id,
                    previous_epoch_key=sha256_text("worker-deferred-previous"),
                    new_epoch_key=sha256_text("worker-deferred-new"),
                    root_cause_key=sha256_text("worker-deferred-cause"),
                    controller_release_digest=state.controller_release_digest,
                    policy_schema_digest=policy_digest(config),
                    fixed_invariant_id="FIX-WORKER-DEFERRED-BUILDER",
                    regression_evidence_ref="evidence://regression/worker-deferred",
                    migration_dry_run_digest=sha256_text("worker-deferred-migration"),
                    backup_restore_proof_ref="evidence://backup/worker-deferred",
                )
            self.assertTrue(
                state.recover_deferred_builder_gate(
                    product_id=product_id,
                    task_id=builder_id,
                    resume_status="REPAIRING",
                )
            )
            test_path = pipeline.create_task(
                product_id,
                "test-engineer",
                dependencies=(builder_id,),
                cycle=3,
            )
            test_id = str(json.loads(test_path.read_text(encoding="utf-8"))["task_id"])
            test_task = state.get_task(test_id)
            self.assertIsNotNone(test_task)
            assert test_task is not None
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner("{}"),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            result_path, result_payload, controller_payload = worker._accepted_task_artifacts(
                builder_id
            )
            spec = worker.default_spec(test_task)

            self.assertEqual(result_path, output_path)
            self.assertEqual(result_payload["status"], "blocked_external")
            self.assertEqual(controller_payload["status"], "blocked_external")
            dependency = next(item for item in spec.evidence if item["type"] == "dependency-result")
            self.assertIn(
                "Implementation and local PM acceptance are complete.",
                dependency["summary"],
            )
            self.assertEqual(
                dependency["artifact_ref"],
                f"evidence/{output_path.name}",
            )

            adopted_product_id = "controller-adopted-builder-product"
            state.create_product(
                product_id=adopted_product_id,
                owner_id="owner",
                source="cli",
                idea="https://github.com/brullik/grid-bot",
                idempotency_key="controller-adopted-builder-key",
            )
            for status in (
                "CONTRACT_DRAFTED",
                "CONTRACT_VALIDATED",
                "RISK_CLASSIFIED",
                "ARCHITECTED",
                "BACKLOG_READY",
                "IMPLEMENTING",
            ):
                state.transition_product(adopted_product_id, status)
            adopted_builder_path = pipeline.create_task(
                adopted_product_id,
                "builder-core",
                cycle=2,
            )
            adopted_builder_id = str(
                json.loads(adopted_builder_path.read_text(encoding="utf-8"))["task_id"]
            )
            adopted_attempt_id = "attempt-controller-adopted-builder"
            adopted_changed_files = [
                {
                    "path": "src/grid_bot/core.py",
                    "change": "Implemented the offline grid simulation.",
                }
            ]
            adopted_output = {
                **artifact_metadata(
                    config,
                    "builder",
                    "builder-controller-adopted-output",
                    adopted_product_id,
                ),
                "producer": output["producer"],
                "task_id": adopted_builder_id,
                "attempt_id": adopted_attempt_id,
                "tier": "sol",
                "attempt_kind": "repair",
                "prompt_digest": "c" * 64,
                "subject_sha_before": "d" * 64,
                "status": "needs_replan",
                "summary": "Implementation passes; detector scope requires controller handling.",
                "changed_files": adopted_changed_files,
                "commands": [
                    {
                        "command_id": "repository-acceptance",
                        "result": "pass",
                        "artifact_ref": "evidence/repository-acceptance.json",
                    }
                ],
                "test_results": [
                    {"gate_id": "target-environment", "status": "PASS"},
                    {"gate_id": "target-tests", "status": "PASS"},
                    {"gate_id": "target-compile", "status": "PASS"},
                    {"gate_id": "target-lint", "status": "PASS"},
                    {"gate_id": "target-secret-scan", "status": "PASS"},
                    {
                        "gate_id": "canonical-command-detector",
                        "status": "NOT_RUN",
                        "evidence_ref": None,
                    },
                ],
                "assumptions": [],
                "findings": [
                    {
                        "code": "CANONICAL_DETECTOR_SCOPE_CONFLICT",
                        "severity": "medium",
                        "text": "A root manifest is outside the exact Builder write scope.",
                    },
                    {
                        "code": "UNTRACKED_BYTECODE_PRESENT",
                        "severity": "low",
                        "text": "Runtime bytecode is excluded from release candidates.",
                    },
                ],
                "evidence_refs": [],
            }
            adopted_output_path = artifacts.write(
                "attempt-result.schema.json",
                adopted_output,
                filename="builder-controller-adopted-output.json",
            )
            adopted_attempt_artifact = {
                **artifact_metadata(
                    config,
                    "builder",
                    "builder-controller-adopted-attempt",
                    adopted_product_id,
                ),
                "producer": output["producer"],
                "task_id": adopted_builder_id,
                "attempt_id": adopted_attempt_id,
                "tier": "sol",
                "attempt_kind": "repair",
                "prompt_digest": "c" * 64,
                "subject_sha_before": "d" * 64,
                "status": "blocked_external",
                "summary": "Controller gates prove the implementation is complete.",
                "changed_files": adopted_changed_files,
                "commands": [
                    {
                        "command_id": "hermes-oneshot",
                        "result": "pass",
                        "artifact_ref": "evidence/context.json",
                    }
                ],
                "test_results": [
                    {
                        "gate_id": "schema-validation",
                        "status": "PASS",
                        "evidence_ref": str(adopted_output_path),
                    },
                    {"gate_id": "target-environment", "status": "PASS"},
                    {"gate_id": "target-tests", "status": "PASS"},
                    {"gate_id": "target-compile", "status": "PASS"},
                    {"gate_id": "target-lint", "status": "PASS"},
                    {"gate_id": "target-secret-scan", "status": "PASS"},
                ],
                "assumptions": [],
                "findings": [
                    {
                        "code": "model_requested_repair",
                        "severity": "medium",
                        "text": "Provider requested controller replanning.",
                    }
                ],
                "evidence_refs": [str(adopted_output_path)],
            }
            adopted_attempt_path = artifacts.write(
                "attempt-result.schema.json",
                adopted_attempt_artifact,
                filename=f"attempt-{adopted_attempt_id}.json",
            )
            claimed_adopted = state.claim_task(worker_id="adopted-builder-worker")
            self.assertIsNotNone(claimed_adopted)
            assert claimed_adopted is not None
            self.assertEqual(claimed_adopted["task_id"], adopted_builder_id)
            self.assertTrue(
                state.record_attempt(
                    attempt_id=adopted_attempt_id,
                    task_id=adopted_builder_id,
                    tier="sol",
                    attempt_kind="repair",
                    prompt_digest="c" * 64,
                    status="repair_required",
                    semantic_counted=True,
                    reason_code="model_requested_repair",
                )
            )
            state.complete_task(
                adopted_builder_id,
                "adopted-builder-worker",
                "FAILED_SAFE",
                reason_code="model_requested_repair",
                detail="Canonical detector conflicts with exact Builder scope.",
                result_ref=str(adopted_attempt_path),
                failure_kind="semantic",
            )
            superseded_path = pipeline.create_task(
                adopted_product_id,
                "builder-core",
                cycle=3,
            )
            superseded_id = str(json.loads(superseded_path.read_text(encoding="utf-8"))["task_id"])
            claimed_fair_turn = state.claim_task(worker_id="deferred-test-worker")
            self.assertIsNotNone(claimed_fair_turn)
            assert claimed_fair_turn is not None
            self.assertEqual(claimed_fair_turn["task_id"], test_id)
            state.complete_task(
                test_id,
                "deferred-test-worker",
            )
            claimed_superseded = state.claim_task(worker_id="superseded-builder-worker")
            self.assertIsNotNone(claimed_superseded)
            assert claimed_superseded is not None
            self.assertEqual(claimed_superseded["task_id"], superseded_id)
            state.complete_task(
                superseded_id,
                "superseded-builder-worker",
                "FAILED_SAFE",
                reason_code="secret_exposure",
                detail="Later provider response was rejected.",
                failure_kind="semantic",
            )
            state.transition_product(adopted_product_id, "FAILED_SAFE")
            with state._lock, state._connection:
                RecoveryCertificateService(state._connection).issue(
                    product_id=adopted_product_id,
                    previous_epoch_key=sha256_text("worker-adopted-previous"),
                    new_epoch_key=sha256_text("worker-adopted-new"),
                    root_cause_key=sha256_text("worker-adopted-cause"),
                    controller_release_digest=state.controller_release_digest,
                    policy_schema_digest=policy_digest(config),
                    fixed_invariant_id="FIX-WORKER-ADOPTED-BUILDER",
                    regression_evidence_ref="evidence://regression/worker-adopted",
                    migration_dry_run_digest=sha256_text("worker-adopted-migration"),
                    backup_restore_proof_ref="evidence://backup/worker-adopted",
                )
            self.assertTrue(
                state.adopt_controller_valid_builder(
                    product_id=adopted_product_id,
                    task_id=adopted_builder_id,
                )
            )

            adopted_result_path, adopted_payload, adopted_controller = (
                worker._accepted_task_artifacts(adopted_builder_id)
            )

            self.assertEqual(adopted_result_path, adopted_output_path)
            self.assertEqual(adopted_payload["status"], "needs_replan")
            self.assertEqual(adopted_controller["status"], "blocked_external")
            state.close()

    def test_public_github_repository_url_accepts_only_exact_repository_urls(self) -> None:
        self.assertEqual(
            public_github_repository_url("https://github.com/brullik/bybit-grid-research"),
            "https://github.com/brullik/bybit-grid-research.git",
        )
        self.assertEqual(
            public_github_repository_url("https://github.com/brullik/bybit-grid-research.git/"),
            "https://github.com/brullik/bybit-grid-research.git",
        )
        self.assertIsNone(
            public_github_repository_url(
                "https://github.com/brullik/bybit-grid-research?token=not-allowed"
            )
        )
        self.assertIsNone(public_github_repository_url("https://example.com/brullik/repository"))

    def test_unselected_route_blocks_before_provider_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected=None)
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            intake_result = IntakeService(config, state, ArtifactStore(config)).submit(
                source="cli", owner_id="owner", idea="Build a blocked product"
            )
            runner = FakeRunner("{}")
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: False,
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(runner.calls, [])
            task_file = next(config.evidence_dir.glob("task-T-*.json"))
            task = state.get_task(json.loads(task_file.read_text(encoding="utf-8"))["task_id"])
            self.assertIsNotNone(task)
            assert task is not None
            self.assertEqual(task["status"], "FAILED_SAFE")
            self.assertEqual(task["graph_status"], "FAILED_SEMANTIC")
            self.assertEqual(state.attempts_for_task(str(task["task_id"])), [])
            self.assertEqual(result.reason_code, "model_route_unapproved")
            self.assertIn("not approved", result.detail or "")
            self.assertEqual(intake_result.product_id, task["product_id"])
            self.assertEqual(
                state.list_failures(intake_result.product_id)[0]["failure_class"],
                "controller",
            )
            owner_actions = list(config.evidence_dir.glob("owner-action-*.json"))
            self.assertEqual(len(owner_actions), 1)
            owner_action = json.loads(owner_actions[0].read_text(encoding="utf-8"))
            self.assertEqual(owner_action["reason"], "missing_credential")
            self.assertNotIn("model_route_unapproved", json.dumps(owner_action))
            state.close()

    def test_workspace_scope_violation_is_failed_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            intake_result = IntakeService(config, state, ArtifactStore(config)).submit(
                source="cli", owner_id="owner", idea="Build a scoped product"
            )
            runner = ScopeViolatingRunner(product_contract(config, intake_result.product_id))
            worker = AgentWorker(
                config, state, runner=runner, health_probe=lambda _: True, repository_root=ROOT
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(result.reason_code, "scope_violation")
            product = state.get_product(intake_result.product_id)
            self.assertIsNotNone(product)
            assert product is not None
            self.assertEqual(product["status"], "IDEA_RECEIVED")
            task = next(iter(state.list_tasks(intake_result.product_id)))
            self.assertEqual(task["status"], "FAILED_SAFE")
            failure = state.list_failures(intake_result.product_id)[0]
            self.assertIn("forbidden.txt", failure["safe_message"])
            actual = json.loads(failure["actual_json"])
            self.assertEqual(
                actual["violating_paths"],
                ["forbidden.txt"],
            )
            self.assertTrue(actual["scope_reassessment_required"])
            self.assertEqual(
                actual["blocked_allowed_paths"],
                json.loads(failure["expected_json"])["allowed_paths"],
            )
            self.assertEqual(actual["outside_scope_coordinates"], ["forbidden.txt"])
            self.assertEqual(actual["scope_required_paths"], ["forbidden.txt"])
            self.assertTrue(actual["required_fixes"])
            state.close()

    def test_local_audit_directories_do_not_cross_workspace_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            (repository / "README.md").write_text(
                "tracked product source\n",
                encoding="utf-8",
            )
            for local_name in ("audit_output", "audit_tools"):
                local_path = repository / local_name
                local_path.mkdir()
                (local_path / "local-only.txt").write_text(
                    "must not enter provider workspace\n",
                    encoding="utf-8",
                )
            registry_path = selected_registry(
                root / "registry.yaml",
                selected="gpt-5.6-luna",
            )
            config = make_config(root / "state", registry_path)
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
            )
            product_id = "P-LOCAL-AUDIT-BOUNDARY"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="test",
                idea="Build from the trusted source snapshot",
                idempotency_key="local-audit-boundary",
            )
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner("{}"),
                health_probe=lambda _: True,
                repository_root=repository,
            )
            destination = root / "destination"

            worker._initialize_product_workspace(product_id, destination)

            self.assertTrue((destination / "README.md").is_file())
            self.assertFalse((destination / "audit_output").exists())
            self.assertFalse((destination / "audit_tools").exists())
            state.close()

    def test_malformed_provider_output_is_requeued_and_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root, registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            intake_result = IntakeService(config, state, ArtifactStore(config)).submit(
                source="cli", owner_id="owner", idea="Build a malformed output product"
            )
            runner = FakeRunner("not-json")
            worker = AgentWorker(
                config, state, runner=runner, health_probe=lambda _: True, repository_root=ROOT
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, "repair_scheduled")
            self.assertEqual(result.reason_code, "malformed_transport")
            task_file = next(config.evidence_dir.glob("task-T-*.json"))
            task_id = str(json.loads(task_file.read_text(encoding="utf-8"))["task_id"])
            self.assertEqual(len(state.attempts_for_task(task_id)), 1)
            task = state.list_tasks(intake_result.product_id)[0]
            self.assertEqual(task["status"], "WAITING")
            self.assertEqual(task["graph_status"], "WAITING_TIME")
            self.assertTrue(task["available_at"])
            product = state.get_product(intake_result.product_id)
            self.assertIsNotNone(product)
            assert product is not None
            self.assertEqual(product["status"], "IDEA_RECEIVED")
            state.close()

    def test_unknown_persisted_quality_gate_routes_replan_not_transport_retry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            (repository / "README.md").write_text(
                "minimal workspace\n",
                encoding="utf-8",
            )
            registry_path = selected_registry(
                root / "registry.yaml",
                selected="gpt-5.6-luna",
            )
            config = make_config(root / "state", registry_path)
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
            )
            artifacts = ArtifactStore(config)
            product_id = "P-UNKNOWN-QUALITY-GATE"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="test",
                idea="Build a product from an older persisted plan",
                idempotency_key="unknown-quality-gate-product",
            )
            pipeline = PipelineCoordinator(config, state, artifacts)
            task_path = pipeline.create_task(product_id, "builder-core")
            contract = json.loads(task_path.read_text(encoding="utf-8"))
            contract["quality_gates"] = ["package_integrity"]
            output = {
                **artifact_metadata(
                    config,
                    "builder",
                    "unknown-quality-gate-output",
                    product_id,
                ),
                "producer": {
                    "role": "builder",
                    "tier": "luna",
                    "provider": "openai_codex_subscription",
                    "model": "gpt-5.6-luna",
                },
                "task_id": contract["task_id"],
                "attempt_id": "attempt-unknown-quality-gate",
                "tier": "luna",
                "attempt_kind": "initial",
                "prompt_digest": "a" * 64,
                "subject_sha_before": "b" * 64,
                "status": "completed",
                "summary": "The implementation is ready for controller gates.",
                "changed_files": [],
                "commands": [],
                "test_results": [],
                "assumptions": [],
                "findings": [],
                "evidence_refs": [],
            }
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner(json.dumps(output)),
                health_probe=lambda _: True,
                repository_root=repository,
            )
            spec = TaskExecutionSpec(
                task_contract=contract,
                role="builder",
                output_schema="attempt-result.schema.json",
                subject_sha="c" * 64,
            )

            result = worker.execute(spec)

            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(
                result.reason_code,
                "invalid_quality_gate_contract",
            )
            self.assertIn("package_integrity", result.detail or "")
            self.assertIsNotNone(result.failure_data)
            assert result.failure_data is not None
            self.assertEqual(
                result.failure_data.failed_gate_ids,
                ("package_integrity",),
            )
            self.assertNotEqual(result.reason_code, "malformed_transport")
            state.close()

    def test_subprocess_runner_rejects_secret_like_prompt_before_exec(self) -> None:
        runner = SubprocessHermesRunner(binary="does-not-exist")
        with self.assertRaises(ValueError):
            runner.run(
                selection=ModelSelection("openai-codex", "economy", "gpt-5.6-luna", "luna"),
                prompt="token " + "ghp_" + "abcdefghijklmnopqrstuvwxyz123456",
                cwd=Path.cwd(),
            )

    def test_subprocess_runner_separates_prompt_and_output_limits(self) -> None:
        runner = SubprocessHermesRunner(
            binary="hermes",
            max_prompt_chars=1_000,
            max_output_chars=10,
        )
        completed = subprocess.CompletedProcess(
            ["hermes"],
            0,
            stdout="0123456789extra",
            stderr="",
        )

        with patch("factory.worker.subprocess.run", return_value=completed) as run:
            result = runner.run(
                selection=ModelSelection(
                    "openai-codex",
                    "economy",
                    "gpt-5.6-luna",
                    "luna",
                ),
                prompt="p" * 200,
                cwd=Path.cwd(),
            )

        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.output, "0123456789")
        run.assert_called_once()
        call = run.call_args
        assert call is not None
        argv = call.args[0]
        self.assertNotIn("p" * 200, argv)
        self.assertTrue(str(argv[1]).endswith("hermes_stdin.py"))
        self.assertEqual(call.kwargs["input"], "p" * 200)

    def test_subprocess_runner_reports_bounded_agent_execution_timeout(self) -> None:
        runner = SubprocessHermesRunner(
            binary="hermes",
            timeout_seconds=1800,
        )

        with patch(
            "factory.worker.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["hermes"], 1800),
        ):
            result = runner.run(
                selection=ModelSelection(
                    "openai-codex",
                    "economy",
                    "gpt-5.6-luna",
                    "luna",
                ),
                prompt="bounded prompt",
                cwd=Path.cwd(),
            )

        self.assertEqual(result.status, "TIMEOUT")
        self.assertEqual(result.reason_code, "agent_execution_timeout")
        self.assertIn("1800 seconds", result.output)
        self.assertIn("not retained", result.output)

    def test_subprocess_runner_types_missing_hermes_oauth_without_exposing_it(self) -> None:
        runner = SubprocessHermesRunner(binary="hermes")
        completed = subprocess.CompletedProcess(
            ["hermes"],
            1,
            stdout="",
            stderr="No Codex credentials stored. Run `hermes auth` to authenticate.\n",
        )

        with patch("factory.worker.subprocess.run", return_value=completed):
            result = runner.run(
                selection=ModelSelection(
                    "openai_codex_subscription",
                    "economy",
                    "gpt-5.6-luna",
                    "luna",
                    "openai-codex",
                ),
                prompt="Return one safe JSON object.",
                cwd=Path.cwd(),
            )

        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.reason_code, "missing_credential")
        self.assertNotIn("sk-", result.output)
        self.assertNotIn("hermes_stdin", result.output)

    def test_worker_uses_distinct_bounded_execution_timeouts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(root)
            config.raw["controller"]["agent_execution_timeout_seconds"] = 2400
            config.raw["controller"]["planning_execution_timeout_seconds"] = 600
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
            )

            worker = AgentWorker(
                config,
                state,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            self.assertIsInstance(worker.runner, SubprocessHermesRunner)
            self.assertIsInstance(worker.planning_runner, SubprocessHermesRunner)
            assert isinstance(worker.runner, SubprocessHermesRunner)
            assert isinstance(worker.planning_runner, SubprocessHermesRunner)
            self.assertEqual(worker.runner.timeout_seconds, 2400)
            self.assertEqual(worker.planning_runner.timeout_seconds, 600)
            state.close()

    def test_hermes_stdin_prompt_reader_is_bounded_and_utf8_strict(self) -> None:
        prompt = "контекст"

        self.assertEqual(
            read_stdin_prompt(
                io.BytesIO(prompt.encode("utf-8")),
                max_input_bytes=64,
            ),
            prompt,
        )
        with self.assertRaisesRegex(ValueError, "exceeds"):
            read_stdin_prompt(
                io.BytesIO(b"x" * 11),
                max_input_bytes=10,
            )
        with self.assertRaisesRegex(ValueError, "valid UTF-8"):
            read_stdin_prompt(
                io.BytesIO(b"\xff"),
                max_input_bytes=10,
            )
        with self.assertRaisesRegex(ValueError, "empty"):
            read_stdin_prompt(
                io.BytesIO(b""),
                max_input_bytes=10,
            )

    def test_hermes_stdin_launcher_preserves_oneshot_contract(self) -> None:
        module = Mock()
        module._run_and_exit_oneshot.side_effect = SystemExit(0)

        with (
            patch(
                "factory.hermes_stdin.importlib.import_module",
                return_value=module,
            ),
            patch.dict(
                "factory.hermes_stdin.os.environ",
                {},
                clear=True,
            ),
            self.assertRaises(SystemExit),
        ):
            _invoke_hermes(
                "bounded prompt",
                model="gpt-5.6-luna",
                provider="openai-codex",
                toolsets="file,terminal",
                usage_file="/tmp/usage.json",
                ignore_rules=True,
            )

        startup = module._prepare_agent_startup.call_args.args[0]
        self.assertIsNone(startup.command)
        self.assertFalse(startup.yolo)
        self.assertTrue(startup.ignore_rules)
        module._run_and_exit_oneshot.assert_called_once_with(
            "bounded prompt",
            model="gpt-5.6-luna",
            provider="openai-codex",
            toolsets="file,terminal",
            usage_file="/tmp/usage.json",
        )

    def test_prompt_input_limit_is_controller_failure_not_transport_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(
                root / "registry.yaml",
                selected="gpt-5.6-luna",
            )
            config = make_config(root, registry_path)
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
            )
            intake_result = IntakeService(
                config,
                state,
                ArtifactStore(config),
            ).submit(
                source="cli",
                owner_id="owner",
                idea="Build a product with a bounded provider prompt",
            )
            runner = SubprocessHermesRunner(
                binary="must-not-run",
                max_prompt_chars=1,
            )
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            result = worker.run_once()

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(
                result.reason_code,
                "controller_exception_prompt_input_limit_error",
            )
            self.assertNotEqual(result.reason_code, "malformed_transport")
            task = state.list_tasks(intake_result.product_id)[0]
            self.assertNotEqual(task["graph_status"], "WAITING_TIME")
            failure = state.list_failures(intake_result.product_id)[0]
            self.assertEqual(failure["failure_class"], "controller")
            self.assertIn("prompt input size", failure["safe_message"])
            state.close()

    def test_high_fan_in_evidence_is_totally_bounded_without_losing_coordinates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(
                root / "registry.yaml",
                selected="gpt-5.6-luna",
            )
            config = make_config(root / "state", registry_path)
            state = StateStore(
                config.database_path,
                max_active_workers=config.max_active_workers,
            )
            intake_result = IntakeService(
                config,
                state,
                ArtifactStore(config),
            ).submit(
                source="cli",
                owner_id="owner",
                idea="Build a product from many independently accepted slices",
            )
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner("{}"),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )
            task = state.list_tasks(intake_result.product_id)[0]
            spec = worker.default_spec(task)
            evidence = tuple(
                {
                    "type": "dependency-result",
                    "summary": (
                        "TRUSTED_CONTROLLER_EVIDENCE "
                        f"dependency_id=T-FANIN-{index:02d}; "
                        f"mandatory_gate_id=target-gate-{index:02d};\n"
                        + ("accepted-output " * 2_000)
                        + f"\nsafe_coordinate=src/slice_{index:02d}.py"
                    ),
                    "artifact_ref": f"evidence/result-fanin-{index:02d}.json",
                }
                for index in range(32)
            )

            prompt, _, context_path = worker._context_and_prompt(replace(spec, evidence=evidence))

            self.assertLessEqual(len(prompt), 225_000)
            context = json.loads(context_path.read_text(encoding="utf-8"))
            summaries = context["evidence"]
            self.assertEqual(len(summaries), 32)
            self.assertLessEqual(
                sum(len(item["summary"]) for item in summaries),
                48_000,
            )
            for index in range(32):
                self.assertIn(f"T-FANIN-{index:02d}", prompt)
                self.assertIn(f"target-gate-{index:02d}", prompt)
                self.assertIn(f"result-fanin-{index:02d}.json", prompt)
                self.assertIn(f"src/slice_{index:02d}.py", prompt)
            state.close()

    def test_subprocess_runner_rejects_prompt_over_input_limit_before_exec(self) -> None:
        runner = SubprocessHermesRunner(
            binary="must-not-run",
            max_prompt_chars=10,
        )
        with (
            patch("factory.worker.subprocess.run") as run,
            self.assertRaises(PromptInputLimitError),
        ):
            runner.run(
                selection=ModelSelection(
                    "openai-codex",
                    "economy",
                    "gpt-5.6-luna",
                    "luna",
                ),
                prompt="p" * 11,
                cwd=Path.cwd(),
            )
        run.assert_not_called()

    def test_subprocess_runner_pins_tools_and_ignores_repository_rules(self) -> None:
        selection = ModelSelection("openai-codex", "economy", "gpt-5.6-luna", "luna")
        coding = SubprocessHermesRunner()
        planning = SubprocessHermesRunner(toolsets=("vision",))

        coding_argv = coding.build_argv(selection, "prompt", None)
        planning_argv = planning.build_argv(selection, "prompt", None)

        self.assertEqual(coding_argv[coding_argv.index("--toolsets") + 1], "file,terminal")
        self.assertEqual(planning_argv[planning_argv.index("--toolsets") + 1], "vision")
        self.assertIn("--ignore-rules", coding_argv)
        self.assertIn("--ignore-rules", planning_argv)

    def test_subprocess_runner_preserves_rootless_container_runtime_directory(self) -> None:
        runner = SubprocessHermesRunner()

        with patch.dict(
            "factory.worker.os.environ",
            {
                "HOME": "/var/lib/hermes-factory",
                "PATH": "/usr/local/bin:/usr/bin",
                "XDG_RUNTIME_DIR": "/run/hermes-factory",
                "UNTRUSTED_SECRET": "must-not-cross-the-provider-boundary",
            },
            clear=True,
        ):
            environment = runner._environment()

        self.assertEqual(environment["XDG_RUNTIME_DIR"], "/run/hermes-factory")
        self.assertNotIn("UNTRUSTED_SECRET", environment)

    def test_subprocess_runner_exposes_controller_python_toolchain(self) -> None:
        runner = SubprocessHermesRunner()

        with patch.dict(
            "factory.worker.os.environ",
            {"PATH": "/usr/local/bin:/usr/bin"},
            clear=True,
        ):
            environment = runner._environment(Path("/workspace/product"))

        self.assertEqual(
            environment["PATH"].split(os.pathsep)[0],
            str(Path(sys.executable).resolve().parent),
        )

    def test_AUT_P0_035_success_stdout_json_excludes_stderr_diagnostics(self) -> None:
        selection = ModelSelection(
            "openai-codex",
            "economy",
            "gpt-5.6-luna",
            "luna",
        )
        machine_output = '{"status":"completed","summary":"safe"}'
        completed = subprocess.CompletedProcess(
            args=["hermes"],
            returncode=0,
            stdout=machine_output + "\n",
            stderr="tool progress diagnostic\n",
        )
        runner = SubprocessHermesRunner()

        with patch("factory.worker.subprocess.run", return_value=completed):
            result = runner.run(
                selection=selection,
                prompt="Return the required JSON object.",
                cwd=Path.cwd(),
            )

        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.output, machine_output)
        self.assertEqual(result.output_digest, sha256_text(machine_output))
        self.assertNotIn("tool progress", result.output)

    def test_security_context_is_bound_to_candidate_diff_and_preflight_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
            source = repository / "source.py"
            source.write_text("value = 1\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "source.py"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "-c",
                    "user.name=Hermes Test",
                    "-c",
                    "user.email=hermes@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "baseline",
                ],
                check=True,
            )
            source.write_text("value = 2\n", encoding="utf-8")
            (repository / ".lease.json").write_text("{}\n", encoding="utf-8")
            generated = repository / "artifacts" / "security-review.json"
            generated.parent.mkdir()
            generated.write_text('{"status":"repair_required"}\n', encoding="utf-8")
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root / "state", registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner("{}"),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )
            subject_sha = sha256_text(stable_json(_workspace_snapshot(repository)))
            spec = TaskExecutionSpec(
                task_contract={
                    "product_id": "P-SECURITY-CONTEXT",
                    "task_id": "T-SECURITY-CONTEXT",
                    "quality_gates": ["target-secret-scan"],
                },
                role="security-reviewer",
                output_schema="security-review-result.schema.json",
                subject_sha=subject_sha,
            )
            preflight = worker.quality.run(
                cwd=repository,
                subject_sha=subject_sha,
                task_id="T-SECURITY-CONTEXT",
                attempt_id="preflight-test",
                gate_ids=["target-secret-scan"],
            )

            evidence, candidates, decisions = worker._security_review_context(
                spec,
                repository,
                preflight,
            )

            self.assertTrue(preflight.mandatory_passed)
            self.assertIn(f"subject_sha={subject_sha}", evidence["summary"])
            self.assertIn("source.py status=present", evidence["summary"])
            self.assertIn("+value = 2", evidence["summary"])
            self.assertIn('"status":"PASS"', evidence["summary"])
            self.assertIn("gate statuses above are authoritative", evidence["summary"])
            self.assertIn(
                ("source.py", "immutable review candidate changed from base"),
                candidates,
            )
            self.assertNotIn(".lease.json", evidence["summary"])
            self.assertNotIn("artifacts/security-review.json", evidence["summary"])
            self.assertTrue(any("Context Pack subject_sha" in item for item in decisions))

            independent_spec = replace(
                spec,
                role="independent-reviewer",
                output_schema="review-result.schema.json",
            )
            independent_evidence, independent_candidates, independent_decisions = (
                worker._independent_review_context(independent_spec, repository)
            )

            self.assertIn(
                f"subject_sha={subject_sha}",
                independent_evidence["summary"],
            )
            self.assertIn("+value = 2", independent_evidence["summary"])
            self.assertIn(
                ("source.py", "immutable review candidate changed from base"),
                independent_candidates,
            )
            self.assertTrue(
                any("exact read-only workspace" in item for item in independent_decisions)
            )
            state.close()

    def test_review_gate_evidence_preserves_optional_failure_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root / "state", registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            artifacts = ArtifactStore(config)
            gate_path = artifacts.write(
                "gate-evidence.schema.json",
                {
                    "schema_version": "1.0",
                    "gate_id": "target-lint",
                    "status": "FAIL",
                    "subject_sha": "a" * 64,
                    "command_digest": "b" * 64,
                    "started_at": "2026-01-01T00:00:00Z",
                    "finished_at": "2026-01-01T00:00:01Z",
                    "exit_code": 1,
                    "artifact_digest": "c" * 64,
                    "summary": "Baseline lint finding outside the candidate slice.",
                    "mandatory": False,
                },
                filename="gate-review-test-target-lint.json",
            )
            worker = AgentWorker(
                config,
                state,
                runner=FakeRunner("{}"),
                health_probe=lambda _: True,
                repository_root=ROOT,
            )

            results = worker._review_gate_results(
                {
                    "test_results": [
                        {
                            "gate_id": "target-lint",
                            "status": "FAIL",
                            "evidence_ref": str(gate_path),
                        }
                    ]
                }
            )

            self.assertEqual(
                results,
                [
                    {
                        "gate_id": "target-lint",
                        "status": "FAIL",
                        "mandatory": False,
                        "subject_sha": "a" * 64,
                        "command_digest": "b" * 64,
                        "started_at": "2026-01-01T00:00:00Z",
                        "finished_at": "2026-01-01T00:00:01Z",
                        "exit_code": 1,
                        "artifact_digest": "c" * 64,
                        "evidence_ref": "evidence/gate-review-test-target-lint.json",
                        "summary": "Baseline lint finding outside the candidate slice.",
                    }
                ],
            )
            state.close()

    def test_security_finding_hands_off_without_same_role_model_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            (repository / "README.md").write_text("minimal workspace\n", encoding="utf-8")
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root / "state", registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            product_id = "P-SECURITY-HANDOFF"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="test",
                idea="Review a candidate and hand findings to the builder",
                idempotency_key="security-handoff-test",
            )
            task_path = PipelineCoordinator(config, state, ArtifactStore(config)).create_task(
                product_id,
                "security-reviewer",
            )
            contract = json.loads(task_path.read_text(encoding="utf-8"))
            output = {
                **artifact_metadata(
                    config,
                    "security-reviewer",
                    "security-review-handoff-test",
                    product_id,
                ),
                "producer": {
                    "role": "security-reviewer",
                    "tier": "terra",
                    "provider": "openai_codex_subscription",
                    "model": "gpt-5.6-terra",
                },
                "task_id": contract["task_id"],
                "subject_sha": "b" * 64,
                "status": "repair_required",
                "changed_trust_boundaries": ["untrusted input boundary"],
                "findings": [
                    {
                        "id": "SEC-001",
                        "severity": "medium",
                        "category": "input-validation",
                        "description": "An input boundary needs a deterministic bound.",
                        "evidence": "source.py:1",
                        "required_fix": "Add the bound and a negative test.",
                    }
                ],
                "release_blocked": True,
                "assumptions": ["The candidate remains immutable during review."],
                "evidence_refs": ["evidence/security-preflight.json"],
            }
            runner = FakeRunner(json.dumps(output))
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=repository,
            )
            worker.quality = PassingQuality()  # type: ignore[assignment]
            spec = TaskExecutionSpec(
                task_contract=contract,
                role="security-reviewer",
                output_schema="security-review-result.schema.json",
                subject_sha="a" * 64,
            )

            result = worker.execute(spec)

            self.assertEqual(result.status, "repair_required")
            self.assertEqual(result.reason_code, "model_requested_repair")
            self.assertIn("SEC-001 [medium]", result.detail or "")
            self.assertIn("Add the bound and a negative test.", result.detail or "")
            self.assertEqual(len(runner.calls), 1)
            self.assertEqual(list(config.evidence_dir.glob("repair-brief-*.json")), [])
            attempt = json.loads(Path(result.artifact_ref or "").read_text(encoding="utf-8"))
            self.assertIn("builder_repair_handoff", attempt["summary"])
            self.assertIn("SEC-001 [medium]", attempt["summary"])
            state.close()

    def test_controller_runtime_finding_is_not_routed_as_product_repair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            (repository / "README.md").write_text("minimal workspace\n", encoding="utf-8")
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root / "state", registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            product_id = "P-CONTROLLER-RUNTIME-HANDOFF"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="test",
                idea="Keep controller runtime defects outside product repair",
                idempotency_key="controller-runtime-handoff-test",
            )
            task_path = PipelineCoordinator(config, state, ArtifactStore(config)).create_task(
                product_id,
                "security-reviewer",
            )
            contract = json.loads(task_path.read_text(encoding="utf-8"))
            output = {
                **artifact_metadata(
                    config,
                    "security-reviewer",
                    "controller-runtime-handoff-test",
                    product_id,
                ),
                "producer": {
                    "role": "security-reviewer",
                    "tier": "terra",
                    "provider": "openai_codex_subscription",
                    "model": "gpt-5.6-terra",
                },
                "task_id": contract["task_id"],
                "subject_sha": "b" * 64,
                "status": "repair_required",
                "changed_trust_boundaries": [],
                "findings": [
                    {
                        "id": "CONTROLLER_PODMAN_IPAM_DATABASE_MISSING",
                        "severity": "high",
                        "category": "controller-runtime",
                        "description": "The controller RunRoot has no initialized IPAM database.",
                        "evidence": "controller://podman/runroot/networks",
                        "required_fix": "Initialize and revalidate the controller-owned rootless runtime.",
                    },
                    {
                        "id": "FULL_PYTEST_BLOCKED_BY_CONTROLLER_RUNTIME",
                        "severity": "medium",
                        "category": "controller-runtime",
                        "description": "The full suite reached one runtime-dependent topology test.",
                        "evidence": "tests/container/test_compose_topology.py",
                        "required_fix": "Rerun the same immutable task after controller recovery.",
                    },
                ],
                "release_blocked": True,
                "assumptions": [],
                "evidence_refs": ["internal://capability/container-runtime"],
            }
            runner = FakeRunner(json.dumps(output))
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=repository,
            )
            worker.quality = PassingQuality()  # type: ignore[assignment]
            spec = TaskExecutionSpec(
                task_contract=contract,
                role="security-reviewer",
                output_schema="security-review-result.schema.json",
                subject_sha="a" * 64,
            )

            result = worker.execute(spec)

            self.assertEqual(result.status, "repair_required")
            self.assertEqual(result.reason_code, "controller_runtime_precondition_failed")
            self.assertIsNotNone(result.failure_data)
            assert result.failure_data is not None
            self.assertEqual(result.failure_data.failure_class, "controller")
            self.assertEqual(
                result.failure_data.failed_gate_ids,
                (
                    "CONTROLLER_PODMAN_IPAM_DATABASE_MISSING",
                    "FULL_PYTEST_BLOCKED_BY_CONTROLLER_RUNTIME",
                ),
            )
            attempt = json.loads(Path(result.artifact_ref or "").read_text(encoding="utf-8"))
            self.assertIn("controller_incident_handoff", attempt["summary"])
            state.close()

    def test_security_preflight_failure_skips_provider_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            (repository / "README.md").write_text("minimal workspace\n", encoding="utf-8")
            registry_path = selected_registry(root / "registry.yaml", selected="gpt-5.6-luna")
            config = make_config(root / "state", registry_path)
            state = StateStore(config.database_path, max_active_workers=config.max_active_workers)
            product_id = "P-SECURITY-PREFLIGHT"
            state.create_product(
                product_id=product_id,
                owner_id="owner",
                source="test",
                idea="Review an internal copied workspace",
                idempotency_key="security-preflight-test",
            )
            task_path = PipelineCoordinator(config, state, ArtifactStore(config)).create_task(
                product_id,
                "security-reviewer",
            )
            contract = json.loads(task_path.read_text(encoding="utf-8"))
            runner = FakeRunner("{}")
            worker = AgentWorker(
                config,
                state,
                runner=runner,
                health_probe=lambda _: True,
                repository_root=repository,
            )
            spec = TaskExecutionSpec(
                task_contract=contract,
                role="security-reviewer",
                output_schema="security-review-result.schema.json",
                subject_sha="a" * 64,
            )

            result = worker.execute(spec)

            self.assertEqual(result.status, "failed_safe")
            self.assertEqual(result.reason_code, "mandatory_gate_failed")
            self.assertEqual(result.detail, "failed mandatory gates: secret-scan")
            self.assertIsNotNone(result.failure_data)
            assert result.failure_data is not None
            self.assertEqual(result.failure_data.failed_gate_ids, ("secret-scan",))
            diagnostics = result.failure_data.actual["gate_diagnostics"]
            self.assertEqual(diagnostics[0]["gate_id"], "secret-scan")
            self.assertTrue(diagnostics[0]["summary"])
            self.assertTrue(diagnostics[0]["evidence_ref"].startswith("evidence/gate-"))
            self.assertEqual(runner.calls, [])
            attempt = json.loads(Path(result.artifact_ref or "").read_text(encoding="utf-8"))
            self.assertEqual(attempt["commands"][0]["result"], "not_run")
            self.assertTrue(
                any(
                    item["gate_id"] == "secret-scan" and item["status"] == "FAIL"
                    for item in attempt["test_results"]
                )
            )
            state.close()

    def test_git_workspace_snapshot_ignores_generated_files_but_tracks_source_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
            (repository / ".gitignore").write_text(".pytest_cache/\n", encoding="utf-8")
            source = repository / "source.py"
            source.write_text("value = 1\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(repository), "add", ".gitignore", "source.py"],
                check=True,
            )
            baseline = _workspace_snapshot(repository)

            ignored = repository / ".pytest_cache" / "cache"
            ignored.parent.mkdir()
            ignored.write_text("generated\n", encoding="utf-8")
            self.assertEqual(_workspace_snapshot(repository), baseline)

            source.write_text("value = 2\n", encoding="utf-8")
            changed = _workspace_snapshot(repository)
            self.assertNotEqual(changed["source.py"], baseline["source.py"])
            untracked = repository / "new.py"
            untracked.write_text("new = True\n", encoding="utf-8")
            self.assertIn("new.py", _workspace_snapshot(repository))


if __name__ == "__main__":
    unittest.main()
