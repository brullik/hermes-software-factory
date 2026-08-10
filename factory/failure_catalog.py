"""Closed-world failure taxonomy for Hermes 2.4.

Every routable reason code has one controller-owned domain and action.  The
fallback is deliberately a controller quarantine; product agents never get an
unknown failure as speculative repair work.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final


class FailureDomain(StrEnum):
    CONTROLLER = "CONTROLLER"
    PLAN = "PLAN"
    PRODUCT_IMPLEMENTATION = "PRODUCT_IMPLEMENTATION"
    PRODUCT_ASSURANCE = "PRODUCT_ASSURANCE"
    TRANSIENT_PROVIDER = "TRANSIENT_PROVIDER"
    CAPABILITY_INTERNAL = "CAPABILITY_INTERNAL"
    EXTERNAL_OWNER = "EXTERNAL_OWNER"
    DEPLOYMENT = "DEPLOYMENT"
    SECURITY = "SECURITY"
    DATA_INTEGRITY = "DATA_INTEGRITY"


class FailureAction(StrEnum):
    CONTINUE = "CONTINUE"
    RETRY_TRANSIENT = "RETRY_TRANSIENT"
    REPAIR_NODE_VERSION = "REPAIR_NODE_VERSION"
    RECOMPILE_AFFECTED_SUBGRAPH = "RECOMPILE_AFFECTED_SUBGRAPH"
    CONTROLLER_QUARANTINE = "CONTROLLER_QUARANTINE"
    WAIT_EXTERNAL = "WAIT_EXTERNAL"
    ROLLBACK = "ROLLBACK"
    FAIL_SAFE = "FAIL_SAFE"
    COMPLETE = "COMPLETE"


@dataclass(frozen=True)
class FailureDisposition:
    reason_code: str
    domain: FailureDomain
    action: FailureAction
    registered: bool = True

    @property
    def owner(self) -> str:
        if self.domain is FailureDomain.EXTERNAL_OWNER:
            return "external"
        if self.domain in {
            FailureDomain.PRODUCT_IMPLEMENTATION,
            FailureDomain.PRODUCT_ASSURANCE,
            FailureDomain.PLAN,
        }:
            return "product"
        return "controller"

    @property
    def model_allowed(self) -> bool:
        return self.domain in {
            FailureDomain.PRODUCT_IMPLEMENTATION,
            FailureDomain.PRODUCT_ASSURANCE,
            FailureDomain.PLAN,
            FailureDomain.TRANSIENT_PROVIDER,
        }


def _entries(
    domain: FailureDomain,
    action: FailureAction,
    *reason_codes: str,
) -> dict[str, FailureDisposition]:
    return {
        reason: FailureDisposition(reason, domain, action)
        for reason in reason_codes
    }


# This is the only runtime ownership registry.  Entries are intentionally
# exact: prefix matching would silently turn newly invented reasons into known
# behavior and reopen the failure mode found by the audit.
FAILURE_CATALOG: Final[dict[str, FailureDisposition]] = {
    **_entries(
        FailureDomain.TRANSIENT_PROVIDER,
        FailureAction.RETRY_TRANSIENT,
        "provider_unavailable",
        "provider_timeout",
        "provider_rate_limited",
        "network_timeout",
        "agent_execution_timeout",
        "github_checks_pending",
        "sqlite_busy",
        "transient_transport",
        "process_crash_before_result",
        "transient_retry",
    ),
    **_entries(
        FailureDomain.PRODUCT_IMPLEMENTATION,
        FailureAction.REPAIR_NODE_VERSION,
        "mandatory_gate_failed",
        "model_requested_repair",
        "scope_violation",
        "schema_validation",
        "malformed_transport",
        "target_test_failed",
        "target_compile_failed",
        "target_lint_failed",
        "unit_test_failed",
        "product_acceptance_blocked",
    ),
    **_entries(
        FailureDomain.PRODUCT_ASSURANCE,
        FailureAction.REPAIR_NODE_VERSION,
        "security_gate_failed",
        "product_acceptance_failed",
        "review_rejected",
        "quality_gate_failed",
        "pm_acceptance_failed",
    ),
    **_entries(
        FailureDomain.PLAN,
        FailureAction.RECOMPILE_AFFECTED_SUBGRAPH,
        "needs_replan",
        "scope_contradiction",
        "architecture_impossible",
        "invalid_capability_contract",
        "invalid_quality_gate_contract",
        "plan_contract_violation",
        "missing_declared_predecessor",
        "evidence_profile_mismatch",
        "completion_unreachable",
        "repeated_hypothesis",
    ),
    **_entries(
        FailureDomain.EXTERNAL_OWNER,
        FailureAction.WAIT_EXTERNAL,
        "missing_credential",
        "oauth_device_code",
        "two_factor_authentication",
        "captcha",
        "external_account_creation",
        "paid_resource_purchase",
        "dns_action_without_access",
        "legal_decision",
        "unapproved_irreversible_production_action",
    ),
    **_entries(
        FailureDomain.DEPLOYMENT,
        FailureAction.ROLLBACK,
        "release_adapter_error",
        "deployment_health_failed",
        "production_observation_failed",
        "rollback_required",
    ),
    **_entries(
        FailureDomain.SECURITY,
        FailureAction.CONTROLLER_QUARANTINE,
        "secret_exposure",
        "artifact_integrity_violation",
        "credential_exposure",
        "signature_verification_failed",
    ),
    **_entries(
        FailureDomain.DATA_INTEGRITY,
        FailureAction.CONTROLLER_QUARANTINE,
        "invalid_task_contract_reference",
        "missing_task_contract",
        "invalid_task_contract",
        "invalid_capability_proof",
        "contract_digest_conflict",
        "result_digest_conflict",
        "candidate_digest_conflict",
        "unknown_transition",
        "side_effect_outcome_indeterminate",
    ),
    **_entries(
        FailureDomain.CAPABILITY_INTERNAL,
        FailureAction.CONTROLLER_QUARANTINE,
        "controller_toolchain_unavailable",
        "controller_toolchain_python_missing",
        "controller_toolchain_make_missing",
        "controller_toolchain_container_builder_unavailable",
        "controller_toolchain_container_storage_scope_mismatch",
        "controller_toolchain_container_network_uninitialized",
        "controller_toolchain_container_network_unavailable",
        "controller_toolchain_scanner_missing",
        "controller_staging_unwritable",
        "controller_production_boundary_unavailable",
        "controller_backup_proof_unavailable",
        "controller_capability_unknown",
        "release_adapter_missing",
        "toolchain_capability_missing",
    ),
    **_entries(
        FailureDomain.CONTROLLER,
        FailureAction.CONTROLLER_QUARANTINE,
        "controller_result_lineage_cycle",
        "controller_result_lineage_depth_exceeded",
        "controller_result_lineage_identity_conflict",
        "controller_result_provenance_invalid",
        "controller_envelope_conflict",
        "canonical_fault_gate_missing",
        "controller_schema_corruption",
        "controller_exception_runtime_error",
        "controller_exception_permission_error",
        "controller_exception_file_not_found_error",
        "controller_plan_compilation_invariant",
        "controller_zero_dependency_audit_invariant",
        "controller_repair_context_binding_invariant",
        "controller_reviewer_revalidation_lineage_invariant",
        "cross_role_supersession_invalid",
        "active_result_binding_conflict",
        "controller_product_reconcile_isolated",
        "path_governor_problem_budget_exhausted",
        "liveness_invariant_violation",
        "internal_task_route",
        "model_route_unapproved",
        "repair_brief_preparation_failed",
        "repair_requeue_invariant",
        "artifact_task_contract_reconstructed",
        "migration_invariant_violation",
        "causal_leaf_only",
        "invalid_output_schema",
        "persistent_workspace_claim_collision",
        "controller_runtime_precondition_failed",
        "canary_controller_incident",
        "internal_blocker",
        "worker_internal_error",
    ),
}

UNKNOWN_FAILURE: Final = FailureDisposition(
    reason_code="unknown_reason_code",
    domain=FailureDomain.DATA_INTEGRITY,
    action=FailureAction.CONTROLLER_QUARANTINE,
    registered=False,
)


def failure_disposition(reason_code: str) -> FailureDisposition:
    """Return an exact catalog entry or the fail-closed unknown disposition."""

    normalized = str(reason_code or "").strip()
    return FAILURE_CATALOG.get(
        normalized,
        FailureDisposition(
            reason_code=normalized or UNKNOWN_FAILURE.reason_code,
            domain=UNKNOWN_FAILURE.domain,
            action=UNKNOWN_FAILURE.action,
            registered=False,
        ),
    )


def assert_catalog_total(reason_codes: set[str]) -> None:
    """Fail static qualification when emitted runtime reasons are unregistered."""

    missing = sorted(reason_codes - set(FAILURE_CATALOG))
    if missing:
        raise ValueError(f"unregistered failure reason: {missing[0]}")


def discover_runtime_reason_literals(package_root: Path) -> set[str]:
    """Extract literal runtime reason emissions for static catalog totality."""

    found: set[str] = set()

    def literal_strings(value: ast.AST | None) -> set[str]:
        if value is None:
            return set()
        return {
            str(item.value)
            for item in ast.walk(value)
            if isinstance(item, ast.Constant)
            and isinstance(item.value, str)
            and item.value
        }

    for path in sorted(package_root.rglob("*.py")):
        if path.name == "failure_catalog.py" or "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            value: ast.expr | None = None
            if isinstance(node, ast.keyword) and node.arg == "reason_code":
                value = node.value
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(
                    (isinstance(target, ast.Name) and target.id == "reason_code")
                    or (isinstance(target, ast.Attribute) and target.attr == "reason_code")
                    for target in targets
                ):
                    value = node.value
            elif isinstance(node, ast.Dict):
                for key, candidate in zip(node.keys, node.values, strict=True):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "reason_code"
                        and isinstance(candidate, ast.Constant)
                        and isinstance(candidate.value, str)
                    ):
                        found.add(candidate.value)
            if value is not None:
                found.update(literal_strings(value))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                positional = [*node.args.posonlyargs, *node.args.args]
                defaults = [None] * (len(positional) - len(node.args.defaults)) + [
                    *node.args.defaults
                ]
                for argument, default in zip(positional, defaults, strict=True):
                    if argument.arg == "reason_code":
                        found.update(literal_strings(default))
                for argument, default in zip(
                    node.args.kwonlyargs, node.args.kw_defaults, strict=True
                ):
                    if argument.arg == "reason_code":
                        found.update(literal_strings(default))
    return found - {"reason_code", "failure_class", UNKNOWN_FAILURE.reason_code}
