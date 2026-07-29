"""Durable Product Execution Graph, outcomes, failures, and completion reducer."""

from __future__ import annotations

import json
import re
import sqlite3
import traceback
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from scripts.prompt_compiler import (
    find_secret_candidate_diagnostics,
    redact_secret_candidates,
)

from .common import redact_text, sha256_text, stable_json, utc_now

if TYPE_CHECKING:
    from .state import StateStore


TASK_STATUSES = {
    "DRAFT",
    "BLOCKED_DEPENDENCY",
    "BLOCKED_CAPABILITY",
    "READY",
    "CLAIMED",
    "WAITING_TIME",
    "WAITING_EXTERNAL",
    "SUCCEEDED",
    "ACCEPTED",
    "REJECTED",
    "FAILED_TRANSIENT",
    "FAILED_SEMANTIC",
    "SUPERSEDED",
    "CANCELLED",
}
TERMINAL_SUCCESS = {"ACCEPTED", "SUPERSEDED"}
TERMINAL_FAILURE = {"REJECTED", "CANCELLED"}
ACTIVE_GRAPH_STATUSES = {
    "BLOCKED_DEPENDENCY",
    "BLOCKED_CAPABILITY",
    "READY",
    "CLAIMED",
    "WAITING_TIME",
    "WAITING_EXTERNAL",
    "FAILED_TRANSIENT",
    "FAILED_SEMANTIC",
}
PLANNING_ONLY_ROLES = {
    "product-director",
    "product-analyst",
    "solution-architect",
    "task-specifier",
    "replanner",
    "incident-recovery",
}
IMMUTABLE_SCHEMA_ROOT = Path(__file__).resolve().parent.parent / "schemas"

CANONICAL_ROLE_OUTPUT_SCHEMAS: dict[str, str] = {
    "product-director": "product-contract.schema.json",
    "product-analyst": "requirements-package.schema.json",
    "solution-architect": "architecture-package.schema.json",
    "task-specifier": "backlog-plan-v2.schema.json",
    "replanner": "backlog-plan-v2.schema.json",
    "incident-recovery": "incident-result.schema.json",
    "builder": "attempt-result.schema.json",
    "test-engineer": "test-package-result.schema.json",
    "security-reviewer": "security-review-result.schema.json",
    "independent-reviewer": "review-result.schema.json",
    "release-operator": "release-operation-result.schema.json",
    "product-tester": "product-test-result.schema.json",
}

CANONICAL_QUALITY_GATE_IDS = frozenset(
    {
        "package-integrity",
        "unit-tests",
        "python-compile",
        "pilot-tests",
        "lint",
        "typecheck",
        "secret-scan",
        "manifest",
        "sbom",
        "target-environment",
        "target-tests",
        "target-compile",
        "target-lint",
        "target-sast",
        "target-dependency-audit",
        "target-license-check",
        "target-secret-scan",
    }
)

CAPABILITY_PROFILES: dict[str, tuple[str, ...]] = {
    "planning_readonly": (
        "artifact.read",
        "artifact.write",
        "repository.read_bounded",
        "state.read",
        "plan.propose",
    ),
    "builder_workspace": (
        "artifact.read",
        "artifact.write",
        "repository.read",
        "repository.write_scoped",
        "command.execute_allowlisted",
        "test.execute",
    ),
    "test_workspace": (
        "artifact.read",
        "artifact.write",
        "repository.read",
        "repository.write_tests_scoped",
        "command.execute_allowlisted",
        "test.execute",
    ),
    "reviewer_readonly": (
        "artifact.read",
        "repository.read",
        "diff.read",
        "gate_evidence.read",
    ),
    "repository_bootstrap": (
        "github.repository.create",
        "github.repository.configure",
        "github.workflow.write",
        "git.initial_commit",
        "git.push_branch",
    ),
    "release_staging": (
        "git.commit_candidate",
        "git.push_branch",
        "github.pull_request.create",
        "github.checks.read",
        "staging.deploy",
    ),
    "release_production": (
        "github.pull_request.verify",
        "github.pull_request.merge",
        "backup.verify",
        "production.deploy_transactional",
        "rollback.execute",
    ),
    "controller_incident": (
        "artifact.read",
        "artifact.write",
        "state.read",
        "state.repair",
    ),
}

ALL_CAPABILITIES = frozenset(
    capability
    for capabilities in CAPABILITY_PROFILES.values()
    for capability in capabilities
)

BUILTIN_CAPABILITIES = {
    capability
    for profile in (
        "planning_readonly",
        "builder_workspace",
        "test_workspace",
        "reviewer_readonly",
        "controller_incident",
    )
    for capability in CAPABILITY_PROFILES[profile]
}

_PLANNING_PROFILE_ROLES = {
    "product-director",
    "product-analyst",
    "solution-architect",
    "task-specifier",
    "replanner",
}
_TEST_PROFILE_ROLES = {"test-engineer", "product-tester"}
_REVIEW_PROFILE_ROLES = {"security-reviewer", "independent-reviewer"}
_CONTROLLER_PROFILE_ROLES = {"incident-recovery", "controller-recovery"}
_REPOSITORY_BOOTSTRAP_ROLES = {"repository-bootstrap", "repository_bootstrap"}


def canonical_plan_identity_catalog() -> str:
    """Return the controller-owned executable role contract for planning prompts."""

    identities = (
        ("builder", "attempt-result.schema.json", "builder_workspace"),
        ("test-engineer", "test-package-result.schema.json", "test_workspace"),
        (
            "security-reviewer",
            "security-review-result.schema.json",
            "reviewer_readonly",
        ),
        ("independent-reviewer", "review-result.schema.json", "reviewer_readonly"),
        (
            "release-operator@release-staging",
            "release-operation-result.schema.json",
            "release_staging",
        ),
        ("product-tester", "product-test-result.schema.json", "test_workspace"),
        (
            "release-operator@release-production",
            "release-operation-result.schema.json",
            "release_production",
        ),
    )
    catalog = "\n".join(
        (
            f"{role}: output_schema={output_schema}; "
            f"capability_profile={profile}; "
            "required_capabilities=["
            + ", ".join(CAPABILITY_PROFILES[profile])
            + "]"
        )
        for role, output_schema, profile in identities
    )
    invariants = (
        "PLAN_IDENTITY_INVARIANTS:\n"
        "- Use a new plan_id for every proposed immutable revision; never reuse a "
        "plan_id present in context or failure evidence.\n"
        "- Every task_id must be new and unique across the proposed DAG and supplied "
        "context.\n"
        "- Every idempotency_key must be exactly 64 lowercase hexadecimal characters, "
        "unique across all proposed nodes, and absent from supplied context. Do not "
        "copy one template key between nodes.\n"
        "- Every acceptance criterion_id must be unique across the proposed DAG. "
        "Every mandatory goal acceptance_ids list must be non-empty and contain only "
        "criterion IDs that exist in proposed node task_contract.acceptance arrays.\n"
        "- Every task_contract.quality_gates entry must be copied exactly from "
        "CANONICAL_QUALITY_GATE_IDS below; do not translate hyphens to underscores "
        "or invent repository-local gate names."
    )
    quality_gates = ", ".join(sorted(CANONICAL_QUALITY_GATE_IDS))
    return f"{catalog}\nCANONICAL_QUALITY_GATE_IDS=[{quality_gates}]\n{invariants}"


def minimum_capability_profile(
    role: str | None,
    stage_key: str | None = None,
    *,
    requested_profile: str | None = None,
) -> str:
    """Return the controller-owned minimum profile for a task identity."""

    normalized_role = str(role or "builder").strip().lower().replace("_", "-")
    normalized_stage = str(stage_key or "").strip().lower().replace("_", "-")
    if normalized_role in _PLANNING_PROFILE_ROLES:
        return "planning_readonly"
    if normalized_role in _CONTROLLER_PROFILE_ROLES:
        return "controller_incident"
    if normalized_role in _REPOSITORY_BOOTSTRAP_ROLES:
        return "repository_bootstrap"
    if normalized_role == "builder":
        return "builder_workspace"
    if normalized_role in _TEST_PROFILE_ROLES:
        return "test_workspace"
    if normalized_role in _REVIEW_PROFILE_ROLES:
        return "reviewer_readonly"
    if normalized_role == "release-operator":
        if normalized_stage in {"release-production", "production"}:
            return "release_production"
        if normalized_stage in {"release-staging", "staging"}:
            return "release_staging"
        # Legacy controller-created release tasks predate canonical stage keys.
        # Their persisted profile is accepted, but a canonical v2 plan must use
        # a release stage key and is checked separately below.
        if requested_profile in {"release_staging", "release_production"}:
            return str(requested_profile)
        raise ValueError("release-operator requires a canonical release stage")
    return "builder_workspace"


def validate_task_capability_contract(
    *,
    role: str | None,
    stage_key: str | None,
    capability_profile: str,
    required_capabilities: list[str],
    require_canonical_stage: bool = False,
    coordinate: str = "task",
) -> None:
    """Reject profile downgrades and incomplete declarations before mutation."""

    if capability_profile not in CAPABILITY_PROFILES:
        raise ValueError(f"unknown capability profile: {capability_profile}")
    normalized_role = str(role or "builder").strip().lower().replace("_", "-")
    normalized_stage = str(stage_key or "").strip().lower().replace("_", "-")
    if (
        require_canonical_stage
        and normalized_role == "release-operator"
        and normalized_stage
        not in {"release-staging", "staging", "release-production", "production"}
    ):
        raise ValueError(
            f"{coordinate}.role release-operator requires release-staging "
            "or release-production stage"
        )
    minimum = minimum_capability_profile(
        role,
        stage_key,
        requested_profile=capability_profile,
    )
    if capability_profile != minimum:
        raise ValueError(
            f"{coordinate}.capability_profile cannot downgrade controller "
            f"minimum {minimum}"
        )
    declared = {str(value) for value in required_capabilities}
    unknown = declared - ALL_CAPABILITIES
    if unknown:
        raise ValueError(
            f"{coordinate}.required_capabilities contains unknown capability: "
            f"{min(unknown)}"
        )
    canonical = set(CAPABILITY_PROFILES[capability_profile])
    omitted = sorted(canonical - declared)
    if omitted:
        raise ValueError(
            f"{coordinate}.required_capabilities omits canonical capability: "
            f"{omitted[0]}"
        )


OWNER_ACTION_REASONS = {
    "missing_credential",
    "oauth_device_code",
    "two_factor_authentication",
    "captcha",
    "external_account_creation",
    "paid_resource_purchase",
    "dns_action_without_access",
    "legal_decision",
    "unapproved_irreversible_production_action",
}


class FaultInjector(Protocol):
    def __call__(self, point: str) -> None: ...


@dataclass(frozen=True)
class FailureData:
    failure_class: str
    reason_code: str
    safe_message: str
    evidence_ref: str
    attempt_id: str | None = None
    parent_failure_id: str | None = None
    exception_type: str | None = None
    stack_fingerprint: str | None = None
    expected: dict[str, Any] = field(default_factory=dict)
    actual: dict[str, Any] = field(default_factory=dict)
    failed_gate_ids: tuple[str, ...] = ()
    retryable: bool = False
    owner_action_eligible: bool = False
    fingerprint: str | None = None

    def normalized_fingerprint(self, task_id: str) -> str:
        return self.fingerprint or sha256_text(
            stable_json(
                {
                    "task_id": task_id,
                    "failure_class": self.failure_class,
                    "reason_code": self.reason_code,
                    "safe_message": self.safe_message,
                    "failed_gate_ids": self.failed_gate_ids,
                    "stack_fingerprint": self.stack_fingerprint,
                }
            )
        )


@dataclass(frozen=True)
class HypothesisData:
    statement: str
    signature: str
    required_evidence: tuple[str, ...]
    semantic_budget: int = 3
    parent_hypothesis_id: str | None = None


@dataclass(frozen=True)
class TaskOutcome:
    task_id: str
    worker_id: str
    idempotency_key: str
    result_ref: str
    result_digest: str
    status: str
    expected_task_revision: int = 1
    expected_plan_revision: int | None = None
    lease_token: str | None = None
    attempt_id: str | None = None
    attempt_status: str | None = None
    available_at: str | None = None
    next_tier: str | None = None
    next_attempt_kind: str | None = None
    repair_context_ref: str | None = None
    product_status: str | None = None
    successors: tuple[dict[str, Any], ...] = ()
    edges: tuple[dict[str, Any], ...] = ()
    failure: FailureData | None = None
    hypothesis: HypothesisData | None = None
    plan: dict[str, Any] | None = None
    outbox_events: tuple[dict[str, Any], ...] = ()

    def validate(self) -> None:
        if self.status not in TASK_STATUSES:
            raise ValueError(f"unsupported task outcome status: {self.status}")
        if not self.idempotency_key:
            raise ValueError("outcome idempotency key is required")
        if not re.fullmatch(r"[a-f0-9]{64}", self.result_digest):
            raise ValueError("outcome result digest must be a lowercase SHA-256")
        if (
            self.status in {"FAILED_TRANSIENT", "FAILED_SEMANTIC", "REJECTED"}
            and self.failure is None
        ):
            raise ValueError("unsuccessful outcome requires FailureData")
        if self.failure is not None and (
            self.failure.owner_action_eligible
            and self.failure.reason_code not in OWNER_ACTION_REASONS
        ):
            raise ValueError("owner action is not allowed for this reason")
        if self.status == "WAITING_TIME":
            if self.next_attempt_kind not in {"transient_retry", "repair"}:
                raise ValueError("WAITING_TIME requires a bounded retry kind")
            if not self.repair_context_ref:
                raise ValueError("WAITING_TIME requires repair context evidence")


@dataclass(frozen=True)
class OutcomeCommitResult:
    outcome_id: str
    task_id: str
    status: str
    successor_ids: tuple[str, ...]
    failure_id: str | None
    replayed: bool


@dataclass(frozen=True)
class CompletionDecision:
    completed: bool
    unmet_conditions: tuple[str, ...]
    completion_evidence_ref: str | None


def safe_exception_diagnostic(error: BaseException) -> dict[str, Any]:
    """Return bounded causal diagnostics without environment or secret values."""

    raw_message = str(error)
    raw_trace = "".join(
        traceback.format_exception(type(error), error, error.__traceback__, limit=12)
    )
    diagnostics = find_secret_candidate_diagnostics(
        stable_json({"message": raw_message, "traceback": raw_trace})
    )
    message, _ = redact_text(raw_message)
    message, _ = redact_secret_candidates(message)
    trace, _ = redact_text(raw_trace)
    trace, _ = redact_secret_candidates(trace)
    normalized_frames = [
        line.strip()
        for line in trace.splitlines()
        if line.lstrip().startswith('File "')
    ]
    return {
        "exception_type": type(error).__name__,
        "safe_message": message[:1000] or type(error).__name__,
        "stack_fingerprint": sha256_text("\n".join(normalized_frames)),
        "traceback_excerpt": trace[-6000:],
        "redactions": diagnostics,
    }


class AutonomyStore:
    """Transactional v2 facade over the existing single-node StateStore."""

    def __init__(self, state: StateStore) -> None:
        self.state = state
        self.connection = state._connection
        self.lock = state._lock

    @staticmethod
    def _legacy_status(graph_status: str) -> str:
        return {
            "READY": "PENDING",
            "BLOCKED_DEPENDENCY": "PENDING",
            "BLOCKED_CAPABILITY": "WAITING",
            "WAITING_TIME": "WAITING",
            "WAITING_EXTERNAL": "BLOCKED_EXTERNAL",
            "CLAIMED": "CLAIMED",
            "SUCCEEDED": "DONE",
            "ACCEPTED": "DONE",
            "SUPERSEDED": "DONE",
            "FAILED_TRANSIENT": "FAILED_SAFE",
            "FAILED_SEMANTIC": "FAILED_SAFE",
            "REJECTED": "FAILED_SAFE",
            "CANCELLED": "FAILED_SAFE",
            "DRAFT": "WAITING",
        }[graph_status]

    def create_product(
        self,
        *,
        product_id: str,
        owner_id: str,
        source: str,
        goal_text: str,
        delivery_mode: str,
        repository_url: str | None,
        repository_name: str | None,
        repository_visibility: str,
        root_goal_ref: str,
        constraints_ref: str | None,
        owner_defaults_ref: str | None,
        idempotency_key: str,
        rate_limit: tuple[int, int] | None,
    ) -> tuple[dict[str, Any], bool]:
        if delivery_mode not in {"new_repository", "existing_repository"}:
            raise ValueError("delivery_mode is invalid")
        if delivery_mode == "existing_repository" and not repository_url:
            raise ValueError("existing_repository requires repository_url")
        if delivery_mode == "new_repository" and repository_url is not None:
            raise ValueError("new_repository forbids repository_url")
        if repository_visibility not in {"private", "public"}:
            raise ValueError("repository_visibility is invalid")
        now = utc_now()
        with self.lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self.connection.execute(
                    "SELECT * FROM products WHERE idempotency_key=?",
                    (idempotency_key,),
                ).fetchone()
                if existing is not None:
                    self.connection.commit()
                    return dict(existing), False
                if rate_limit is not None:
                    limit, window_seconds = rate_limit
                    import time

                    now_epoch = int(time.time())
                    self.connection.execute(
                        "DELETE FROM intake_requests WHERE created_at_epoch < ?",
                        (now_epoch - window_seconds,),
                    )
                    recent = int(
                        self.connection.execute(
                            "SELECT COUNT(*) FROM intake_requests "
                            "WHERE source=? AND owner_id=? AND created_at_epoch>=?",
                            (source, owner_id, now_epoch - window_seconds),
                        ).fetchone()[0]
                    )
                    if recent >= limit:
                        from .state import IntakeRateLimitError

                        raise IntakeRateLimitError("intake rate limit exceeded")
                    self.connection.execute(
                        "INSERT INTO intake_requests "
                        "(source, owner_id, idempotency_key, created_at_epoch) "
                        "VALUES (?, ?, ?, ?)",
                        (source, owner_id, idempotency_key, now_epoch),
                    )
                self.connection.execute(
                    """INSERT INTO products
                       (product_id, status, owner_id, source, idea, idempotency_key,
                        created_at, updated_at, goal_text, repository_url,
                        repository_name, delivery_mode, repository_visibility,
                        root_goal_ref, constraints_ref, owner_defaults_ref,
                        repository_bootstrap_state)
                       VALUES (?, 'IDEA_RECEIVED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                               ?, ?, ?, ?)""",
                    (
                        product_id,
                        owner_id,
                        source,
                        goal_text,
                        idempotency_key,
                        now,
                        now,
                        goal_text,
                        repository_url,
                        repository_name,
                        delivery_mode,
                        repository_visibility,
                        root_goal_ref,
                        constraints_ref,
                        owner_defaults_ref,
                        "PENDING",
                    ),
                )
                self.state._record_event(
                    product_id,
                    None,
                    "product_created_v2",
                    {
                        "source": source,
                        "delivery_mode": delivery_mode,
                        "repository_visibility": repository_visibility,
                    },
                )
                row = self.connection.execute(
                    "SELECT * FROM products WHERE product_id=?", (product_id,)
                ).fetchone()
                assert row is not None
                self.connection.commit()
                return dict(row), True
            except Exception:
                self.connection.rollback()
                raise

    def grant_capability(
        self,
        *,
        capability: str,
        provider: str,
        scope: dict[str, Any],
        product_id: str | None = None,
        task_id: str | None = None,
        status: str = "AVAILABLE",
        expires_at: str | None = None,
        grant_id: str | None = None,
    ) -> str:
        if status not in {"AVAILABLE", "MISSING_EXTERNAL", "DENIED_POLICY", "EXPIRED"}:
            raise ValueError("capability grant status is invalid")
        identifier = grant_id or f"grant-{sha256_text(stable_json([product_id, task_id, capability, provider, scope]))[:20]}"
        with self.lock, self.connection:
            self.connection.execute(
                """INSERT OR REPLACE INTO capability_grants
                   (grant_id, product_id, task_id, capability, scope_json, provider,
                    status, expires_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    identifier,
                    product_id,
                    task_id,
                    capability,
                    stable_json(scope),
                    provider,
                    status,
                    expires_at,
                    utc_now(),
                ),
            )
            if (
                status == "AVAILABLE"
                and product_id is not None
                and capability.startswith(("github.", "git."))
            ):
                now = utc_now()
                resumed = self.connection.execute(
                    """UPDATE tasks
                       SET graph_status='READY', status='PENDING',
                           blocked_reason=NULL, blocked_ref=NULL,
                           terminal_reason=NULL, terminal_detail=NULL,
                           updated_at=?
                       WHERE product_id=? AND graph_status='WAITING_EXTERNAL'
                         AND terminal_reason='missing_credential'""",
                    (now, product_id),
                ).rowcount
                if resumed:
                    self.connection.execute(
                        """UPDATE failures SET status='ROUTED', last_seen_at=?
                           WHERE product_id=? AND reason_code='missing_credential'
                             AND status IN ('OPEN','OWNER_BLOCKED')""",
                        (now, product_id),
                    )
                    self.state._record_event(
                        product_id,
                        task_id,
                        "capability_resume",
                        {
                            "capability": capability,
                            "resumed_tasks": resumed,
                        },
                    )
            if product_id:
                self._recompute_frontier(self.connection, product_id)
        return identifier

    def _missing_capabilities(
        self,
        connection: sqlite3.Connection,
        product_id: str,
        task_id: str,
        required: list[str],
    ) -> list[str]:
        missing: list[str] = []
        now = utc_now()
        for capability in required:
            if capability in BUILTIN_CAPABILITIES:
                continue
            row = connection.execute(
                """SELECT 1 FROM capability_grants
                   WHERE capability=? AND status='AVAILABLE'
                     AND (product_id IS NULL OR product_id=?)
                     AND (task_id IS NULL OR task_id=?)
                     AND (expires_at IS NULL OR expires_at>?)
                   LIMIT 1""",
                (capability, product_id, task_id, now),
            ).fetchone()
            if row is None:
                missing.append(capability)
        return missing

    @staticmethod
    def validate_plan(plan: dict[str, Any]) -> None:
        nodes = plan.get("nodes")
        edges = plan.get("edges")
        if not isinstance(nodes, list) or not nodes:
            raise ValueError("BacklogPlan v2 requires non-empty nodes")
        if not isinstance(edges, list):
            raise TypeError("BacklogPlan v2 edges must be an array")
        node_ids: list[str] = []
        task_ids: set[str] = set()
        idempotency_keys: set[str] = set()
        acceptance_ids: set[str] = set()
        execution_roles: set[str] = set()
        for node_index, node in enumerate(nodes):
            if not isinstance(node, dict):
                raise TypeError(
                    f"BacklogPlan nodes[{node_index}] must be an object"
                )
            node_id = str(node.get("node_id", ""))
            contract = node.get("task_contract")
            if not node_id or not isinstance(contract, dict):
                raise ValueError(
                    f"BacklogPlan nodes[{node_index}] requires node_id and task_contract"
                )
            if node_id in node_ids:
                raise ValueError(
                    f"BacklogPlan nodes[{node_index}].node_id is duplicated"
                )
            node_ids.append(node_id)
            task_id = str(contract.get("task_id", ""))
            if task_id in task_ids:
                raise ValueError(
                    f"BacklogPlan nodes[{node_index}].task_contract.task_id is duplicated"
                )
            task_ids.add(task_id)
            normalized_role = (
                str(contract.get("role", "")).strip().lower().replace("_", "-")
            )
            execution_roles.add(normalized_role)
            output_schema = str(contract.get("output_schema", ""))
            if (
                not output_schema
                or Path(output_schema).name != output_schema
                or not output_schema.endswith(".schema.json")
                or not (IMMUTABLE_SCHEMA_ROOT / output_schema).is_file()
            ):
                raise ValueError(
                    "BacklogPlan "
                    f"nodes[{node_index}].task_contract.output_schema "
                    f"is not registered: {output_schema or '<missing>'}"
                )
            canonical_output_schema = CANONICAL_ROLE_OUTPUT_SCHEMAS.get(
                normalized_role
            )
            if canonical_output_schema is None:
                raise ValueError(
                    "BacklogPlan "
                    f"nodes[{node_index}].task_contract.role "
                    f"is not supported: {normalized_role or '<missing>'}"
                )
            if output_schema != canonical_output_schema:
                raise ValueError(
                    "BacklogPlan "
                    f"nodes[{node_index}].task_contract.output_schema "
                    f"must be {canonical_output_schema} for role "
                    f"{normalized_role}; got {output_schema}"
                )
            quality_gates = contract.get("quality_gates", [])
            if not isinstance(quality_gates, list):
                raise TypeError(
                    "BacklogPlan "
                    f"nodes[{node_index}].task_contract.quality_gates "
                    "must be an array"
                )
            for gate_index, gate_id_value in enumerate(quality_gates):
                gate_id = str(gate_id_value)
                if gate_id not in CANONICAL_QUALITY_GATE_IDS:
                    raise ValueError(
                        "BacklogPlan "
                        f"nodes[{node_index}].task_contract."
                        f"quality_gates[{gate_index}] is not registered: "
                        f"{gate_id or '<missing>'}"
                    )
            idempotency_key = str(contract.get("idempotency_key", ""))
            if idempotency_key in idempotency_keys:
                raise ValueError(
                    "BacklogPlan "
                    f"nodes[{node_index}].task_contract.idempotency_key is duplicated"
                )
            idempotency_keys.add(idempotency_key)
            for criterion in contract.get("acceptance", []):
                if isinstance(criterion, dict) and criterion.get("criterion_id"):
                    acceptance_ids.add(str(criterion["criterion_id"]))
            profile = str(contract.get("capability_profile", ""))
            required = contract.get("required_capabilities", [])
            if not isinstance(required, list):
                raise TypeError(
                    "BacklogPlan "
                    f"nodes[{node_index}].task_contract.required_capabilities "
                    "must be an array"
                )
            validate_task_capability_contract(
                role=str(contract.get("role", "")),
                stage_key=str(
                    contract.get("stage_key")
                    or contract.get("plan_node_id")
                    or node_id
                ),
                capability_profile=profile,
                required_capabilities=[str(value) for value in required],
                require_canonical_stage=True,
                coordinate=f"nodes[{node_index}].task_contract",
            )
        if execution_roles.issubset(PLANNING_ONLY_ROLES):
            raise ValueError(
                "BacklogPlan nodes must include a non-planning execution task"
            )
        for goal in plan.get("goals", []):
            if not isinstance(goal, dict):
                raise TypeError("BacklogPlan goal must be an object")
            required_acceptance = {
                str(value) for value in goal.get("acceptance_ids", [])
            }
            if bool(goal.get("mandatory", True)) and (
                not required_acceptance
                or not required_acceptance.issubset(acceptance_ids)
            ):
                raise ValueError(
                    "mandatory goal is not traceable to task acceptance"
                )
        adjacency: dict[str, list[str]] = {node_id: [] for node_id in node_ids}
        indegree = {node_id: 0 for node_id in node_ids}
        for edge_index, edge in enumerate(edges):
            if not isinstance(edge, dict):
                raise TypeError(
                    f"BacklogPlan edges[{edge_index}] must be an object"
                )
            source = str(edge.get("from", ""))
            target = str(edge.get("to", ""))
            if source not in adjacency or target not in adjacency:
                missing = (
                    "from and to"
                    if source not in adjacency and target not in adjacency
                    else "from"
                    if source not in adjacency
                    else "to"
                )
                raise ValueError(
                    f"BacklogPlan edges[{edge_index}].{missing} endpoint is missing"
                )
            adjacency[source].append(target)
            indegree[target] += 1
        frontier = [node for node, degree in indegree.items() if degree == 0]
        visited = 0
        while frontier:
            node = frontier.pop()
            visited += 1
            for target in adjacency[node]:
                indegree[target] -= 1
                if indegree[target] == 0:
                    frontier.append(target)
        if visited != len(node_ids):
            raise ValueError("BacklogPlan must be acyclic")

    def validate_plan_candidate(self, plan: dict[str, Any]) -> None:
        """Validate semantic identities without mutating durable graph state."""

        self.validate_plan(plan)
        plan_id = str(plan.get("plan_id", ""))
        with self.lock:
            existing_plan = self.connection.execute(
                "SELECT plan_digest FROM plans WHERE plan_id=?",
                (plan_id,),
            ).fetchone()
            if existing_plan is not None:
                candidate_digest = sha256_text(stable_json(plan))
                if str(existing_plan["plan_digest"]) != candidate_digest:
                    raise ValueError(
                        "BacklogPlan plan_id already exists with a different "
                        "immutable digest"
                    )
                return
            for node_index, node in enumerate(plan["nodes"]):
                contract = dict(node["task_contract"])
                task_id = str(contract["task_id"])
                idempotency_key = str(contract["idempotency_key"])
                existing_task = self.connection.execute(
                    "SELECT 1 FROM tasks WHERE task_id=?",
                    (task_id,),
                ).fetchone()
                if existing_task is not None:
                    raise ValueError(
                        "BacklogPlan "
                        f"nodes[{node_index}].task_contract.task_id already exists"
                    )
                existing_key = self.connection.execute(
                    "SELECT 1 FROM tasks WHERE idempotency_key=?",
                    (idempotency_key,),
                ).fetchone()
                if existing_key is not None:
                    raise ValueError(
                        "BacklogPlan "
                        f"nodes[{node_index}].task_contract.idempotency_key "
                        "already exists"
                    )

    def ingest_plan(
        self,
        plan: dict[str, Any],
        *,
        plan_artifact_ref: str,
        plan_digest: str,
        created_by_task_id: str,
    ) -> tuple[str, ...]:
        self.validate_plan(plan)
        with self.lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                task_ids = self._ingest_plan(
                    self.connection,
                    plan,
                    plan_artifact_ref=plan_artifact_ref,
                    plan_digest=plan_digest,
                    created_by_task_id=created_by_task_id,
                )
                self.connection.commit()
                return task_ids
            except Exception:
                self.connection.rollback()
                raise

    def _ingest_plan(
        self,
        connection: sqlite3.Connection,
        plan: dict[str, Any],
        *,
        plan_artifact_ref: str,
        plan_digest: str,
        created_by_task_id: str,
    ) -> tuple[str, ...]:
        self.validate_plan(plan)
        plan_id = str(plan["plan_id"])
        product_id = str(plan["product_id"])
        revision = int(plan["revision"])
        parent_plan_id = plan.get("parent_plan_id")
        source_failure_id = plan.get("source_failure_id")
        now = utc_now()
        if not re.fullmatch(r"[a-f0-9]{64}", plan_digest):
            raise ValueError("plan digest must be a lowercase SHA-256")
        current_plan = connection.execute(
            """SELECT plans.plan_id, plans.revision
               FROM products
               LEFT JOIN plans ON plans.plan_id=products.active_plan_id
               WHERE products.product_id=?""",
            (product_id,),
        ).fetchone()
        if current_plan is None:
            raise KeyError(product_id)
        current_plan_id = (
            str(current_plan[0]) if current_plan[0] is not None else None
        )
        current_revision = int(current_plan[1] or 0)
        if revision != current_revision + 1:
            raise ValueError("plan revision must increment the active revision")
        if revision > 1 and str(parent_plan_id or "") != str(current_plan_id or ""):
            raise ValueError("replan must name the active parent plan")
        existing = connection.execute(
            "SELECT plan_digest FROM plans WHERE plan_id=?", (plan_id,)
        ).fetchone()
        if existing is not None:
            if str(existing[0]) != plan_digest:
                raise ValueError("immutable plan digest conflict")
            rows = connection.execute(
                "SELECT task_id FROM tasks WHERE plan_id=? ORDER BY plan_node_id",
                (plan_id,),
            ).fetchall()
            return tuple(str(row[0]) for row in rows)
        self.validate_plan_candidate(plan)
        active = connection.execute(
            "SELECT plan_id FROM plans WHERE product_id=? AND status='ACTIVE'",
            (product_id,),
        ).fetchall()
        for row in active:
            old_plan_id = str(row[0])
            if old_plan_id == plan_id:
                continue
            connection.execute(
                "UPDATE plans SET status='SUPERSEDED', completed_at=? WHERE plan_id=?",
                (now, old_plan_id),
            )
            connection.execute(
                """UPDATE tasks
                   SET graph_status='SUPERSEDED', status='DONE', updated_at=?
                   WHERE plan_id=? AND graph_status IN
                        ('DRAFT','READY','BLOCKED_DEPENDENCY','BLOCKED_CAPABILITY',
                         'WAITING_TIME','WAITING_EXTERNAL','FAILED_TRANSIENT',
                         'FAILED_SEMANTIC','REJECTED')""",
                (now, old_plan_id),
            )
        connection.execute(
            """INSERT INTO plans
               (plan_id, product_id, revision, parent_plan_id, source_failure_id,
                status, plan_artifact_ref, plan_digest, goals_json,
                completion_criteria_json, created_by_task_id, created_at, activated_at)
               VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?, ?)""",
            (
                plan_id,
                product_id,
                revision,
                parent_plan_id,
                source_failure_id,
                plan_artifact_ref,
                plan_digest,
                stable_json(plan.get("goals", [])),
                stable_json(plan.get("completion_criteria", [])),
                created_by_task_id,
                now,
                now,
            ),
        )
        product = connection.execute(
            "SELECT root_goal_ref FROM products WHERE product_id=?", (product_id,)
        ).fetchone()
        if product is None:
            raise KeyError(product_id)
        creator = connection.execute(
            "SELECT root_task_id FROM tasks WHERE task_id=?", (created_by_task_id,)
        ).fetchone()
        root_task_id = (
            str(creator[0])
            if creator is not None and creator[0]
            else created_by_task_id
        )
        node_to_task: dict[str, str] = {}
        for rank, node in enumerate(plan["nodes"]):
            node_id = str(node["node_id"])
            contract = dict(node["task_contract"])
            task_id = str(
                contract.get("task_id")
                or f"T-{sha256_text(f'{product_id}:{plan_id}:{node_id}:{revision}')[:16].upper()}"
            )
            node_to_task[node_id] = task_id
            required = [
                str(value)
                for value in contract.get(
                    "required_capabilities",
                    CAPABILITY_PROFILES.get(
                        str(contract.get("capability_profile", "builder_workspace")),
                        (),
                    ),
                )
            ]
            contract_ref = str(
                node.get("task_contract_ref")
                or contract.get("active_context_ref")
                or f"evidence/task-{task_id}.json"
            )
            supersedes_task_id = contract.get("supersedes_task_id")
            reused_result_ref: str | None = None
            reused_result_digest: str | None = None
            initial_graph_status = "DRAFT"
            initial_legacy_status = "WAITING"
            if supersedes_task_id:
                superseded = connection.execute(
                    """SELECT product_id, graph_status, result_ref, result_digest
                       FROM tasks WHERE task_id=?""",
                    (str(supersedes_task_id),),
                ).fetchone()
                if superseded is None or str(superseded["product_id"]) != product_id:
                    raise ValueError("supersedes_task_id is outside this product")
                if str(superseded["graph_status"]) == "ACCEPTED":
                    initial_graph_status = "ACCEPTED"
                    initial_legacy_status = "DONE"
                    reused_result_ref = str(superseded["result_ref"] or "") or None
                    reused_result_digest = (
                        str(superseded["result_digest"] or "") or None
                    )
            connection.execute(
                """INSERT INTO tasks
                   (task_id, product_id, title, role, output_schema, contract_ref,
                     priority, status, dependencies_json, conflict_keys_json,
                    created_at, updated_at, stage_key, cycle, root_task_id,
                    parent_task_id, source_task_id, plan_id, plan_node_id,
                     task_revision, root_context_ref, active_context_ref,
                     failure_id, hypothesis_id, capability_profile,
                     idempotency_key, supersedes_task_id,
                     graph_status, required_capabilities_json, mandatory,
                     critical_path_rank, result_ref, result_digest)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                           ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    task_id,
                    product_id,
                    str(contract["title"]),
                    str(contract.get("role", "builder")),
                    str(contract.get("output_schema", "attempt-result.schema.json")),
                    contract_ref,
                    int(contract.get("priority", 0)),
                    initial_legacy_status,
                    stable_json([]),
                    stable_json(contract.get("conflict_keys", [])),
                    now,
                    now,
                    str(contract.get("stage_key", node_id)),
                    0,
                    str(contract.get("root_task_id", root_task_id)),
                    contract.get("parent_task_id") or created_by_task_id,
                    contract.get("source_task_id") or created_by_task_id,
                    plan_id,
                    node_id,
                    int(contract.get("task_revision", 1)),
                    str(contract.get("root_context_ref") or product[0]),
                    contract_ref,
                    contract.get("failure_id") or source_failure_id,
                    contract.get("hypothesis_id"),
                    str(contract.get("capability_profile", "builder_workspace")),
                    str(
                        contract.get("idempotency_key")
                        or sha256_text(f"{plan_id}:{node_id}:{revision}")
                    ),
                    supersedes_task_id,
                    initial_graph_status,
                    stable_json(required),
                    int(bool(node.get("mandatory", True))),
                    int(contract.get("critical_path_rank", rank)),
                    reused_result_ref,
                    reused_result_digest,
                ),
            )
            if supersedes_task_id:
                connection.execute(
                    """INSERT OR IGNORE INTO task_edges
                       (plan_id, from_task_id, to_task_id, edge_type,
                        required, created_at)
                       VALUES (?, ?, ?, 'supersedes', 0, ?)""",
                    (plan_id, str(supersedes_task_id), task_id, now),
                )
        incoming: dict[str, list[str]] = {node: [] for node in node_to_task}
        for edge in plan["edges"]:
            source_node = str(edge["from"])
            target_node = str(edge["to"])
            source_task = node_to_task[source_node]
            target_task = node_to_task[target_node]
            incoming[target_node].append(source_task)
            connection.execute(
                """INSERT INTO task_edges
                   (plan_id, from_task_id, to_task_id, edge_type, required, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    plan_id,
                    source_task,
                    target_task,
                    str(edge.get("edge_type", "depends_on")),
                    int(bool(edge.get("required", True))),
                    now,
                ),
            )
        for node_id, dependencies in incoming.items():
            connection.execute(
                "UPDATE tasks SET dependencies_json=? WHERE task_id=?",
                (stable_json(dependencies), node_to_task[node_id]),
            )
        connection.execute(
            """UPDATE products
               SET active_plan_id=?, active_plan_revision=?, updated_at=?
               WHERE product_id=?""",
            (plan_id, revision, now, product_id),
        )
        self._recompute_frontier(connection, product_id)
        self.state._record_event(
            product_id,
            created_by_task_id,
            "plan_activated",
            {
                "plan_id": plan_id,
                "revision": revision,
                "node_count": len(node_to_task),
                "edge_count": len(plan["edges"]),
            },
        )
        return tuple(node_to_task.values())

    def _recompute_frontier(
        self, connection: sqlite3.Connection, product_id: str
    ) -> None:
        product = connection.execute(
            "SELECT active_plan_id FROM products WHERE product_id=?", (product_id,)
        ).fetchone()
        if product is None or not product[0]:
            return
        plan_id = str(product[0])
        rows = connection.execute(
            """SELECT task_id, graph_status, required_capabilities_json
               FROM tasks WHERE plan_id=?""",
            (plan_id,),
        ).fetchall()
        now = utc_now()
        for row in rows:
            task_id = str(row[0])
            current = str(row[1] or "DRAFT")
            # Failure and external-wait states are routing inputs, not frontier
            # candidates. Re-enabling them here erases the failure before the
            # reconciler can create a repair or a revised plan.
            if current in (
                TERMINAL_SUCCESS
                | TERMINAL_FAILURE
                | {
                    "CLAIMED",
                    "FAILED_TRANSIENT",
                    "FAILED_SEMANTIC",
                    "WAITING_EXTERNAL",
                }
            ):
                continue
            incoming = connection.execute(
                """SELECT upstream.graph_status, edge.required, upstream.failure_id
                   FROM task_edges AS edge
                   JOIN tasks AS upstream ON upstream.task_id=edge.from_task_id
                   WHERE edge.plan_id=? AND edge.to_task_id=?""",
                (plan_id, task_id),
            ).fetchall()
            failed = next(
                (
                    str(dependency[2] or "")
                    for dependency in incoming
                    if int(dependency[1]) and str(dependency[0]) not in TERMINAL_SUCCESS
                    and str(dependency[0])
                    in {
                        "FAILED_TRANSIENT",
                        "FAILED_SEMANTIC",
                        "REJECTED",
                        "CANCELLED",
                    }
                ),
                None,
            )
            unresolved = [
                dependency
                for dependency in incoming
                if int(dependency[1]) and str(dependency[0]) not in TERMINAL_SUCCESS
            ]
            try:
                required = json.loads(str(row[2] or "[]"))
            except json.JSONDecodeError:
                required = []
            missing = self._missing_capabilities(
                connection, product_id, task_id, [str(value) for value in required]
            )
            if failed is not None:
                next_status = "BLOCKED_DEPENDENCY"
                blocked_reason = "upstream_failure"
                blocked_ref = failed or None
            elif unresolved:
                next_status = "BLOCKED_DEPENDENCY"
                blocked_reason = "waiting_for_dependencies"
                blocked_ref = None
            elif missing:
                next_status = "BLOCKED_CAPABILITY"
                blocked_reason = "missing_capability"
                blocked_ref = stable_json(missing)
            elif current == "WAITING_TIME":
                available = connection.execute(
                    "SELECT available_at FROM tasks WHERE task_id=?", (task_id,)
                ).fetchone()
                if available is not None and available[0] and str(available[0]) > now:
                    continue
                next_status = "READY"
                blocked_reason = None
                blocked_ref = None
            else:
                next_status = "READY"
                blocked_reason = None
                blocked_ref = None
            connection.execute(
                """UPDATE tasks
                   SET graph_status=?, status=?, blocked_reason=?, blocked_ref=?,
                       updated_at=?
                   WHERE task_id=?""",
                (
                    next_status,
                    self._legacy_status(next_status),
                    blocked_reason,
                    blocked_ref,
                    now,
                    task_id,
                ),
            )

    def runnable_tasks(self, product_id: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.connection.execute(
                """SELECT * FROM tasks
                   WHERE product_id=? AND graph_status='READY'
                   ORDER BY priority DESC, critical_path_rank, created_at""",
                (product_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def has_bounded_progress_path(self, product_id: str) -> bool:
        with self.lock:
            row = self.connection.execute(
                """SELECT 1
                     FROM tasks
                     JOIN products
                       ON products.product_id=tasks.product_id
                     JOIN plans
                       ON plans.plan_id=tasks.plan_id
                      AND plans.product_id=tasks.product_id
                    WHERE tasks.product_id=?
                      AND plans.status='ACTIVE'
                      AND products.active_plan_id=tasks.plan_id
                      AND (
                       tasks.graph_status IN ('READY','CLAIMED')
                       OR (
                           tasks.graph_status='WAITING_TIME'
                           AND tasks.available_at IS NOT NULL
                       )
                       OR (
                           tasks.graph_status='WAITING_EXTERNAL'
                           AND tasks.blocked_ref IS NOT NULL
                       )
                   ) LIMIT 1""",
                (product_id,),
            ).fetchone()
            return row is not None

    def _insert_successor(
        self,
        connection: sqlite3.Connection,
        predecessor: sqlite3.Row,
        successor: dict[str, Any],
    ) -> str:
        task_id = str(successor["task_id"])
        graph_status = str(successor.get("graph_status", "DRAFT"))
        if graph_status not in TASK_STATUSES:
            raise ValueError("successor graph status is invalid")
        now = utc_now()
        connection.execute(
            """INSERT OR IGNORE INTO tasks
               (task_id, product_id, title, role, output_schema, contract_ref,
                priority, status, dependencies_json, conflict_keys_json,
                created_at, updated_at, stage_key, cycle, available_at,
                root_task_id, parent_task_id, source_task_id, plan_id,
                plan_node_id, task_revision, root_context_ref,
                active_context_ref, failure_id, hypothesis_id,
                capability_profile, idempotency_key, supersedes_task_id,
                 graph_status, required_capabilities_json, mandatory,
                 critical_path_rank, required_predecessor_digest)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                       ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                task_id,
                str(predecessor["product_id"]),
                str(successor["title"]),
                str(successor.get("role", "builder")),
                str(successor.get("output_schema", "attempt-result.schema.json")),
                str(successor["contract_ref"]),
                int(successor.get("priority", 0)),
                self._legacy_status(graph_status),
                stable_json(successor.get("dependencies", [str(predecessor["task_id"])])),
                stable_json(successor.get("conflict_keys", [])),
                now,
                now,
                str(successor.get("stage_key", successor.get("plan_node_id", task_id))),
                int(successor.get("cycle", 0)),
                successor.get("available_at"),
                str(successor.get("root_task_id") or predecessor["root_task_id"]),
                str(successor.get("parent_task_id") or predecessor["task_id"]),
                str(successor.get("source_task_id") or predecessor["task_id"]),
                str(successor.get("plan_id") or predecessor["plan_id"]),
                str(successor.get("plan_node_id") or task_id),
                int(successor.get("task_revision", 1)),
                str(successor.get("root_context_ref") or predecessor["root_context_ref"]),
                str(successor.get("active_context_ref") or successor["contract_ref"]),
                successor.get("failure_id"),
                successor.get("hypothesis_id"),
                str(successor.get("capability_profile", "builder_workspace")),
                str(
                    successor.get("idempotency_key")
                    or sha256_text(
                        f"successor:{predecessor['task_id']}:{task_id}:"
                        f"{successor.get('task_revision', 1)}"
                    )
                ),
                successor.get("supersedes_task_id"),
                graph_status,
                stable_json(successor.get("required_capabilities", [])),
                int(bool(successor.get("mandatory", True))),
                int(successor.get("critical_path_rank", 0)),
                successor.get("required_predecessor_digest"),
            ),
        )
        for dependency_id in successor.get(
            "dependencies",
            [str(predecessor["task_id"])],
        ):
            connection.execute(
                """INSERT OR IGNORE INTO task_edges
                   (plan_id, from_task_id, to_task_id, edge_type,
                    required, created_at)
                   VALUES (?, ?, ?, 'depends_on', 1, ?)""",
                (
                    str(successor.get("plan_id") or predecessor["plan_id"]),
                    str(dependency_id),
                    task_id,
                    now,
                ),
            )
        return task_id

    def _upsert_failure(
        self,
        connection: sqlite3.Connection,
        task: sqlite3.Row,
        failure: FailureData,
    ) -> str:
        fingerprint = failure.normalized_fingerprint(str(task["task_id"]))
        existing = connection.execute(
            """SELECT failure_id FROM failures
               WHERE task_id=? AND fingerprint=? AND status IN ('OPEN','ROUTED')
               ORDER BY first_seen_at LIMIT 1""",
            (str(task["task_id"]), fingerprint),
        ).fetchone()
        now = utc_now()
        if existing is not None:
            failure_id = str(existing[0])
            connection.execute(
                """UPDATE failures SET occurrence_count=occurrence_count+1,
                       last_seen_at=?, safe_message=?, evidence_ref=?
                   WHERE failure_id=?""",
                (now, failure.safe_message, failure.evidence_ref, failure_id),
            )
            return failure_id
        failure_id = f"failure-{fingerprint[:20]}"
        connection.execute(
            """INSERT INTO failures
               (failure_id, product_id, task_id, attempt_id, parent_failure_id,
                failure_class, reason_code, fingerprint, safe_message,
                exception_type, stack_fingerprint, evidence_ref, status,
                retryable, owner_action_eligible, expected_json, actual_json,
                failed_gate_ids_json, first_seen_at, last_seen_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?,
                       ?, ?)""",
            (
                failure_id,
                str(task["product_id"]),
                str(task["task_id"]),
                failure.attempt_id,
                failure.parent_failure_id,
                failure.failure_class,
                failure.reason_code,
                fingerprint,
                failure.safe_message[:4000],
                failure.exception_type,
                failure.stack_fingerprint,
                failure.evidence_ref,
                int(failure.retryable),
                int(failure.owner_action_eligible),
                stable_json(failure.expected),
                stable_json(failure.actual),
                stable_json(failure.failed_gate_ids),
                now,
                now,
            ),
        )
        return failure_id

    @staticmethod
    def _resolve_failure_chain(
        connection: sqlite3.Connection,
        failure_id: str,
        *,
        resolved_at: str,
    ) -> tuple[str, ...]:
        rows = connection.execute(
            """
            WITH RECURSIVE causal_failures(failure_id) AS (
                SELECT failure_id FROM failures WHERE failure_id=?
                UNION
                SELECT parent.parent_failure_id
                  FROM failures AS parent
                  JOIN causal_failures AS child
                    ON parent.failure_id=child.failure_id
                 WHERE parent.parent_failure_id IS NOT NULL
            )
            SELECT failure_id FROM causal_failures
            """,
            (failure_id,),
        ).fetchall()
        failure_ids = tuple(str(row[0]) for row in rows)
        if not failure_ids:
            return ()
        placeholders = ",".join("?" for _ in failure_ids)
        connection.execute(
            f"""
            UPDATE failures
               SET status='RESOLVED', last_seen_at=?
             WHERE failure_id IN ({placeholders})
            """,
            (resolved_at, *failure_ids),
        )
        connection.execute(
            f"""
            UPDATE hypotheses
               SET status='RESOLVED', closed_at=COALESCE(closed_at, ?)
             WHERE failure_id IN ({placeholders})
               AND status='ACTIVE'
            """,
            (resolved_at, *failure_ids),
        )
        connection.execute(
            f"""
            UPDATE controller_incidents
               SET status='RESOLVED', resolved_at=?
             WHERE status='OPEN'
               AND task_id IN (
                   SELECT task_id FROM failures
                    WHERE failure_id IN ({placeholders})
               )
            """,
            (resolved_at, *failure_ids),
        )
        return failure_ids

    def commit_task_outcome(
        self,
        outcome: TaskOutcome,
        *,
        fault_injector: FaultInjector | None = None,
    ) -> OutcomeCommitResult:
        outcome.validate()

        def inject(point: str) -> None:
            if fault_injector is not None:
                fault_injector(point)

        inject("before_transaction")
        with self.lock:
            self.connection.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                existing = self.connection.execute(
                    "SELECT * FROM task_outcomes WHERE idempotency_key=?",
                    (outcome.idempotency_key,),
                ).fetchone()
                if existing is not None:
                    if str(existing["result_digest"]) != outcome.result_digest:
                        raise ValueError("outcome idempotency digest conflict")
                    payload = json.loads(str(existing["payload_json"]))
                    self.connection.commit()
                    return OutcomeCommitResult(
                        str(existing["outcome_id"]),
                        outcome.task_id,
                        str(existing["status"]),
                        tuple(payload.get("successor_ids", [])),
                        payload.get("failure_id"),
                        True,
                    )
                task = self.connection.execute(
                    "SELECT * FROM tasks WHERE task_id=?", (outcome.task_id,)
                ).fetchone()
                if task is None:
                    raise KeyError(outcome.task_id)
                if str(task["status"]) != "CLAIMED" or str(task["lease_owner"]) != outcome.worker_id:
                    raise ValueError("Task lease is missing or owned by another worker")
                if outcome.lease_token is not None and str(task["lease_token"] or "") != outcome.lease_token:
                    raise ValueError("Task lease token changed")
                if int(task["task_revision"] or 1) != outcome.expected_task_revision:
                    raise ValueError("Task revision changed")
                if outcome.expected_plan_revision is not None:
                    plan = self.connection.execute(
                        """SELECT plans.revision, plans.status,
                                  products.active_plan_id
                           FROM plans
                           JOIN products ON products.product_id=plans.product_id
                           WHERE plans.plan_id=?""",
                        (str(task["plan_id"]),),
                    ).fetchone()
                    if (
                        plan is None
                        or int(plan["revision"]) != outcome.expected_plan_revision
                        or str(plan["status"]) != "ACTIVE"
                        or str(plan["active_plan_id"]) != str(task["plan_id"])
                    ):
                        raise ValueError("Task plan revision is no longer active")
                connection_status = self._legacy_status(outcome.status)
                now = utc_now()
                self.connection.execute(
                    """UPDATE tasks
                       SET graph_status=?, status=?, result_ref=?, result_digest=?,
                            lease_owner=NULL, lease_until=NULL, heartbeat_at=NULL,
                            lease_token=NULL, available_at=?, next_tier=?,
                            next_attempt_kind=?, repair_context_ref=?,
                            updated_at=?
                        WHERE task_id=?""",
                    (
                        outcome.status,
                        connection_status,
                        outcome.result_ref,
                        outcome.result_digest,
                        outcome.available_at,
                        outcome.next_tier,
                        outcome.next_attempt_kind or "initial",
                        outcome.repair_context_ref,
                        now,
                        outcome.task_id,
                    ),
                )
                inject("after_task_write")
                if outcome.attempt_id is not None and outcome.attempt_status is not None:
                    self.connection.execute(
                        """UPDATE attempts SET status=?, completed_at=?,
                               result_digest=?
                           WHERE attempt_id=?""",
                        (
                            outcome.attempt_status,
                            now,
                            outcome.result_digest,
                            outcome.attempt_id,
                        ),
                    )
                failure_id: str | None = None
                hypothesis_id: str | None = None
                if outcome.failure is not None:
                    failure_id = self._upsert_failure(
                        self.connection, task, outcome.failure
                    )
                    self.connection.execute(
                        """UPDATE tasks SET failure_id=?, terminal_reason=?,
                               terminal_detail=?, failure_kind=?
                           WHERE task_id=?""",
                        (
                            failure_id,
                            outcome.failure.reason_code,
                            outcome.failure.safe_message[:4000],
                            outcome.failure.failure_class,
                            outcome.task_id,
                        ),
                    )
                    if outcome.attempt_id is not None:
                        self.connection.execute(
                            "UPDATE attempts SET failure_id=? WHERE attempt_id=?",
                            (failure_id, outcome.attempt_id),
                        )
                    if outcome.hypothesis is not None:
                        if not 1 <= outcome.hypothesis.semantic_budget <= 3:
                            raise ValueError("semantic hypothesis budget is invalid")
                        hypothesis_id = (
                            f"hypothesis-{sha256_text(stable_json([task['product_id'], outcome.hypothesis.signature, failure_id]))[:20]}"
                        )
                        self.connection.execute(
                            """INSERT OR IGNORE INTO hypotheses
                               (hypothesis_id, product_id, failure_id,
                                parent_hypothesis_id, signature, statement,
                                required_evidence_json, status, semantic_budget,
                                attempts_used, created_at)
                               VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, 0, ?)""",
                            (
                                hypothesis_id,
                                str(task["product_id"]),
                                failure_id,
                                outcome.hypothesis.parent_hypothesis_id,
                                outcome.hypothesis.signature,
                                outcome.hypothesis.statement,
                                stable_json(outcome.hypothesis.required_evidence),
                                outcome.hypothesis.semantic_budget,
                                now,
                            ),
                        )
                        self.connection.execute(
                            "UPDATE tasks SET hypothesis_id=? WHERE task_id=?",
                            (hypothesis_id, outcome.task_id),
                        )
                    self.connection.execute(
                        """UPDATE tasks SET graph_status='BLOCKED_DEPENDENCY',
                               status='PENDING', blocked_reason='upstream_failure',
                               blocked_ref=?, failure_id=COALESCE(failure_id, ?),
                               updated_at=?
                           WHERE task_id IN (
                               SELECT to_task_id FROM task_edges
                               WHERE from_task_id=? AND required=1
                           )
                           AND graph_status NOT IN
                               ('ACCEPTED','SUPERSEDED','REJECTED','CANCELLED')""",
                        (failure_id, failure_id, now, outcome.task_id),
                    )
                inject("after_failure_write")
                successor_ids: list[str] = []
                for successor in outcome.successors:
                    successor_ids.append(
                        self._insert_successor(self.connection, task, successor)
                    )
                for edge in outcome.edges:
                    self.connection.execute(
                        """INSERT OR IGNORE INTO task_edges
                           (plan_id, from_task_id, to_task_id, edge_type,
                            required, created_at)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (
                            str(edge.get("plan_id") or task["plan_id"]),
                            str(edge["from_task_id"]),
                            str(edge["to_task_id"]),
                            str(edge.get("edge_type", "depends_on")),
                            int(bool(edge.get("required", True))),
                            now,
                        ),
                    )
                if outcome.plan is not None:
                    successor_ids.extend(
                        self._ingest_plan(
                            self.connection,
                            outcome.plan,
                            plan_artifact_ref=str(
                                outcome.plan["plan_artifact_ref"]
                            ),
                            plan_digest=str(outcome.plan["plan_digest"]),
                            created_by_task_id=outcome.task_id,
                        )
                    )
                inject("after_successor_write")
                if outcome.status in TERMINAL_SUCCESS and failure_id is None:
                    prior_failure_id = str(task["failure_id"] or "")
                    if prior_failure_id:
                        self._resolve_failure_chain(
                            self.connection,
                            prior_failure_id,
                            resolved_at=now,
                        )
                    supersedes_task_id = str(task["supersedes_task_id"] or "")
                    if supersedes_task_id:
                        self.connection.execute(
                            """UPDATE tasks
                               SET graph_status='SUPERSEDED', status='DONE',
                                   updated_at=?
                               WHERE task_id=? AND product_id=?
                                 AND graph_status NOT IN ('ACCEPTED','CANCELLED')""",
                            (
                                now,
                                supersedes_task_id,
                                str(task["product_id"]),
                            ),
                        )
                        self.connection.execute(
                            """INSERT OR IGNORE INTO task_edges
                               (plan_id, from_task_id, to_task_id, edge_type,
                                required, created_at)
                               VALUES (?, ?, ?, 'supersedes', 0, ?)""",
                            (
                                str(task["plan_id"]),
                                supersedes_task_id,
                                outcome.task_id,
                                now,
                            ),
                        )
                self._recompute_frontier(
                    self.connection, str(task["product_id"])
                )
                inject("after_frontier_recompute")
                if outcome.product_status is not None:
                    self.connection.execute(
                        "UPDATE products SET status=?, updated_at=? WHERE product_id=?",
                        (outcome.product_status, now, str(task["product_id"])),
                    )
                logical_events: list[dict[str, Any]] = [
                    {
                        "event_type": "task_result_committed",
                        "payload": {
                            "task_id": outcome.task_id,
                            "status": outcome.status,
                            "result_ref": outcome.result_ref,
                            "result_digest": outcome.result_digest,
                        },
                    }
                ]
                if successor_ids:
                    logical_events.append(
                        {
                            "event_type": "successors_created",
                            "payload": {
                                "task_id": outcome.task_id,
                                "successor_ids": successor_ids,
                            },
                        }
                    )
                if failure_id:
                    logical_events.append(
                        {
                            "event_type": "failure_routed",
                            "payload": {
                                "task_id": outcome.task_id,
                                "failure_id": failure_id,
                                "hypothesis_id": hypothesis_id,
                            },
                        }
                    )
                logical_events.extend(outcome.outbox_events)
                for index, event in enumerate(logical_events):
                    event_type = str(event["event_type"])
                    payload = dict(event.get("payload", {}))
                    self.state._record_event(
                        str(task["product_id"]),
                        outcome.task_id,
                        event_type,
                        payload,
                    )
                    outbox_key = sha256_text(
                        f"{outcome.idempotency_key}:{event_type}:{index}"
                    )
                    self.connection.execute(
                        """INSERT OR IGNORE INTO outbox
                           (outbox_id, idempotency_key, event_type, payload_json,
                            status, created_at)
                           VALUES (?, ?, ?, ?, 'PENDING', ?)""",
                        (
                            f"outbox-{outbox_key[:20]}",
                            outbox_key,
                            event_type,
                            stable_json(payload),
                            now,
                        ),
                    )
                inject("after_outbox_write")
                outcome_id = f"outcome-{sha256_text(outcome.idempotency_key)[:20]}"
                payload = {
                    "successor_ids": successor_ids,
                    "failure_id": failure_id,
                    "hypothesis_id": hypothesis_id,
                }
                self.connection.execute(
                    """INSERT INTO task_outcomes
                       (outcome_id, task_id, idempotency_key, result_digest,
                        status, payload_json, committed_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        outcome_id,
                        outcome.task_id,
                        outcome.idempotency_key,
                        outcome.result_digest,
                        outcome.status,
                        stable_json(payload),
                        now,
                    ),
                )
                self.connection.commit()
                committed = True
                inject("after_commit_before_return")
                return OutcomeCommitResult(
                    outcome_id,
                    outcome.task_id,
                    outcome.status,
                    tuple(successor_ids),
                    failure_id,
                    False,
                )
            except Exception:
                if not committed:
                    self.connection.rollback()
                raise

    def record_product_evidence(
        self,
        *,
        product_id: str,
        evidence_type: str,
        artifact_ref: str,
        artifact_digest: str,
        status: str = "PASS",
        goal_id: str | None = None,
    ) -> str:
        if not re.fullmatch(r"[a-f0-9]{64}", artifact_digest):
            raise ValueError("evidence digest must be a lowercase SHA-256")
        evidence_id = f"product-evidence-{sha256_text(stable_json([product_id, evidence_type, goal_id, artifact_digest]))[:20]}"
        with self.lock, self.connection:
            self.connection.execute(
                """INSERT OR IGNORE INTO product_evidence
                   (evidence_id, product_id, evidence_type, goal_id, artifact_ref,
                    artifact_digest, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    evidence_id,
                    product_id,
                    evidence_type,
                    goal_id,
                    artifact_ref,
                    artifact_digest,
                    status,
                    utc_now(),
                ),
            )
        return evidence_id

    def reduce_completion(
        self,
        product_id: str,
        *,
        artifacts: Any | None = None,
    ) -> CompletionDecision:
        with self.lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                product = self.connection.execute(
                    "SELECT * FROM products WHERE product_id=?", (product_id,)
                ).fetchone()
                if product is None:
                    raise KeyError(product_id)
                if str(product["status"]) == "COMPLETED":
                    self.connection.commit()
                    return CompletionDecision(
                        True,
                        (),
                        str(product["completion_evidence_ref"] or ""),
                    )
                plan_id = str(product["active_plan_id"] or "")
                unmet: list[str] = []
                if not plan_id:
                    unmet.append("active_plan_missing")
                else:
                    mandatory_open = self.connection.execute(
                        """SELECT plan_node_id, graph_status FROM tasks
                           WHERE plan_id=? AND mandatory=1
                             AND graph_status NOT IN ('ACCEPTED','SUPERSEDED')""",
                        (plan_id,),
                    ).fetchall()
                    unmet.extend(
                        f"mandatory_node:{row[0]}:{row[1]}"
                        for row in mandatory_open
                    )
                    node_rows = self.connection.execute(
                        """SELECT task_id, result_ref FROM tasks
                           WHERE plan_id=? AND mandatory=1
                             AND graph_status IN ('ACCEPTED','SUPERSEDED')""",
                        (plan_id,),
                    ).fetchall()
                    node_evidence = [
                        str(row["result_ref"])
                        for row in node_rows
                        if row["result_ref"]
                    ]
                    if len(node_evidence) != len(node_rows):
                        unmet.append("mandatory_node_evidence_missing")
                    invalid_superseded = self.connection.execute(
                        """SELECT task_id FROM tasks AS old
                           WHERE old.plan_id=? AND old.graph_status='SUPERSEDED'
                             AND NOT EXISTS (
                                 SELECT 1 FROM task_edges AS edge
                                 WHERE edge.from_task_id=old.task_id
                                   AND edge.edge_type='supersedes'
                             )""",
                        (plan_id,),
                    ).fetchall()
                    unmet.extend(
                        f"superseded_without_replacement:{row[0]}"
                        for row in invalid_superseded
                    )
                open_failures = self.connection.execute(
                    "SELECT failure_id FROM failures WHERE product_id=? "
                    "AND status IN ('OPEN','ROUTED','OWNER_BLOCKED')",
                    (product_id,),
                ).fetchall()
                unmet.extend(f"open_failure:{row[0]}" for row in open_failures)
                open_incidents = self.connection.execute(
                    """
                    SELECT incident_id
                      FROM controller_incidents
                     WHERE product_id=? AND status='OPEN'
                    """,
                    (product_id,),
                ).fetchall()
                unmet.extend(
                    f"open_controller_incident:{row[0]}"
                    for row in open_incidents
                )
                try:
                    plan_goals_row = self.connection.execute(
                        "SELECT goals_json FROM plans WHERE plan_id=?", (plan_id,)
                    ).fetchone()
                    goals = (
                        json.loads(str(plan_goals_row[0]))
                        if plan_goals_row is not None
                        else []
                    )
                except json.JSONDecodeError:
                    goals = []
                goal_evidence_refs: list[str] = []
                for goal in goals:
                    if not isinstance(goal, dict) or not bool(goal.get("mandatory", True)):
                        continue
                    goal_id = str(goal.get("goal_id", ""))
                    evidence = self.connection.execute(
                        """SELECT artifact_ref FROM product_evidence
                           WHERE product_id=? AND evidence_type='goal'
                              AND goal_id=? AND status='PASS' LIMIT 1""",
                        (product_id, goal_id),
                    ).fetchone()
                    if evidence is None:
                        unmet.append(f"goal_without_pass_evidence:{goal_id}")
                    else:
                        goal_evidence_refs.append(str(evidence[0]))
                release_rows = {
                    str(row[0]): (
                        str(row[1]),
                        str(row[2]),
                        str(row[3]),
                        str(row[4]),
                    )
                    for row in self.connection.execute(
                        """SELECT evidence_type, artifact_digest, status,
                                  artifact_ref, created_at
                           FROM product_evidence WHERE product_id=?
                             AND evidence_type IN
                               ('independent_review','required_checks','staging',
                                'production','rollback','observation')""",
                        (product_id,),
                    ).fetchall()
                    if str(row[2]) == "PASS"
                }
                for required in (
                    "independent_review",
                    "required_checks",
                    "staging",
                    "production",
                    "rollback",
                    "observation",
                ):
                    if required not in release_rows:
                        unmet.append(f"evidence_missing:{required}")
                if (
                    "staging" in release_rows
                    and "production" in release_rows
                    and release_rows["staging"][0] != release_rows["production"][0]
                ):
                    unmet.append("staging_production_digest_mismatch")
                if unmet:
                    self.connection.commit()
                    return CompletionDecision(False, tuple(sorted(unmet)), None)
                completed_at = max(
                    [value[3] for value in release_rows.values()]
                    or [utc_now()]
                )
                completion_artifact = {
                    "schema_version": "2.0",
                    "artifact_id": (
                        "completion-evidence-"
                        + sha256_text(
                            stable_json(
                                [
                                    product_id,
                                    plan_id,
                                    goal_evidence_refs,
                                    node_evidence,
                                    release_rows,
                                ]
                            )
                        )[:20]
                    ),
                    "product_id": product_id,
                    "plan_id": plan_id,
                    "completed_at": completed_at,
                    "goal_evidence": sorted(goal_evidence_refs),
                    "node_evidence": sorted(node_evidence),
                    "release_digest": release_rows["production"][0],
                    "observation_ref": release_rows["observation"][2],
                }
                digest = sha256_text(stable_json(completion_artifact))
                completion_ref = (
                    f"evidence/completion-{product_id}-{digest[:12]}.json"
                )
                if artifacts is not None:
                    completion_path = artifacts.write(
                        "completion-evidence.schema.json",
                        completion_artifact,
                        filename=completion_ref.removeprefix("evidence/"),
                    )
                    completion_ref = f"evidence/{completion_path.name}"
                now = utc_now()
                self.connection.execute(
                    """UPDATE products SET status='COMPLETED',
                           completion_evidence_ref=?, terminal_reason=NULL,
                           updated_at=? WHERE product_id=?""",
                    (completion_ref, now, product_id),
                )
                key = sha256_text(f"completion:{product_id}:{digest}")
                self.connection.execute(
                    """INSERT OR IGNORE INTO outbox
                       (outbox_id, idempotency_key, event_type, payload_json,
                        status, created_at)
                       VALUES (?, ?, 'product_completed', ?, 'PENDING', ?)""",
                    (
                        f"outbox-{key[:20]}",
                        key,
                        stable_json(
                            {
                                "product_id": product_id,
                                "completion_evidence_ref": completion_ref,
                            }
                        ),
                        now,
                    ),
                )
                self.state._record_event(
                    product_id,
                    None,
                    "product_completed",
                    {"completion_evidence_ref": completion_ref},
                )
                self.connection.commit()
                return CompletionDecision(True, (), completion_ref)
            except Exception:
                self.connection.rollback()
                raise

    def list_plans(self, product_id: str) -> list[dict[str, Any]]:
        with self.lock:
            return [
                dict(row)
                for row in self.connection.execute(
                    "SELECT * FROM plans WHERE product_id=? ORDER BY revision",
                    (product_id,),
                ).fetchall()
            ]

    def list_edges(self, plan_id: str) -> list[dict[str, Any]]:
        with self.lock:
            return [
                dict(row)
                for row in self.connection.execute(
                    "SELECT * FROM task_edges WHERE plan_id=? "
                    "ORDER BY from_task_id, to_task_id",
                    (plan_id,),
                ).fetchall()
            ]

    def list_failures(self, product_id: str) -> list[dict[str, Any]]:
        with self.lock:
            return [
                dict(row)
                for row in self.connection.execute(
                    "SELECT * FROM failures WHERE product_id=? ORDER BY first_seen_at",
                    (product_id,),
                ).fetchall()
            ]

    def list_hypotheses(self, product_id: str) -> list[dict[str, Any]]:
        with self.lock:
            return [
                dict(row)
                for row in self.connection.execute(
                    "SELECT * FROM hypotheses WHERE product_id=? ORDER BY created_at",
                    (product_id,),
                ).fetchall()
            ]


def outcome_payload(outcome: TaskOutcome) -> dict[str, Any]:
    """Schema-friendly representation useful in deterministic tests."""

    return asdict(outcome)
