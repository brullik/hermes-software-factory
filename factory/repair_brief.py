"""Normalized, actionable repair evidence shared by pipeline components."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

_BLOCKING_SEVERITIES = {"low", "medium", "high", "critical"}
_BUILDER_DEFERRED_FINDINGS = {
    "GITHUB_REQUIRED_CHECK_NOT_RUN",
    "OUT_OF_SCOPE_RUFF_BASELINE",
}
_BUILDER_CONTROLLER_COMPLETE_FINDINGS = {
    "CANONICAL_DETECTOR_SCOPE_CONFLICT",
    "UNTRACKED_BYTECODE_PRESENT",
}


@dataclass(frozen=True)
class RepairFinding:
    finding_id: str
    severity: str
    description: str
    required_fix: str


def normalized_repair_findings(output: Mapping[str, Any] | None) -> tuple[RepairFinding, ...]:
    """Adapt both reviewer and attempt-result finding shapes without losing detail."""

    if output is None:
        return ()
    raw_findings = output.get("findings", [])
    if not isinstance(raw_findings, list):
        return ()
    findings: list[RepairFinding] = []
    for item in raw_findings:
        if not isinstance(item, Mapping):
            continue
        severity = str(item.get("severity") or "unknown").strip().lower()
        if severity not in _BLOCKING_SEVERITIES:
            continue
        finding_id = str(item.get("id") or item.get("code") or "unnamed-finding").strip()
        description = str(
            item.get("description") or item.get("text") or "repair required"
        ).strip()
        required_fix = str(
            item.get("required_fix") or item.get("text") or description
        ).strip()
        findings.append(
            RepairFinding(
                finding_id=finding_id or "unnamed-finding",
                severity=severity,
                description=description or "repair required",
                required_fix=required_fix or "apply the required repair",
            )
        )
    return tuple(findings)


def repair_requirements(
    *,
    output: Mapping[str, Any] | None,
    reason_code: str,
    detail: str,
    failed_gate_ids: Iterable[str] = (),
) -> tuple[list[str], list[str]]:
    """Return non-empty blocker IDs and concrete required fixes for a repair brief."""

    findings = normalized_repair_findings(output)
    blocker_ids = [
        str(value).strip()
        for value in failed_gate_ids
        if str(value).strip()
    ]
    blocker_ids.extend(item.finding_id for item in findings)
    if not blocker_ids:
        blocker_ids.append(reason_code.strip() or "internal_blocker")

    required_fixes = [item.required_fix for item in findings if item.required_fix]
    if not required_fixes:
        safe_detail = detail.strip() or reason_code.strip() or "internal blocker"
        required_fixes.append(
            f"Resolve blocker {blocker_ids[0]} and make the observed result match "
            f"the task acceptance contract: {safe_detail}"
        )
    return list(dict.fromkeys(blocker_ids)), list(dict.fromkeys(required_fixes))


def repair_finding_detail(output: Mapping[str, Any]) -> str:
    """Render exact cross-schema finding diagnostics for routing and notifications."""

    findings = normalized_repair_findings(output)
    if findings:
        rendered = [
            (
                f"{item.finding_id} [{item.severity}]: {item.description}; "
                f"required fix: {item.required_fix}"
            )
            for item in findings
        ]
        return ("blocking findings: " + " | ".join(rendered))[:4000]
    if bool(output.get("release_blocked")):
        return "provider marked the release as blocked without a structured blocking finding"
    return f"provider requested repair with status={output.get('status', 'unknown')}"


def builder_result_is_locally_complete(output: Mapping[str, Any]) -> bool:
    """Accept a Builder result that is blocked only by explicitly downstream gates."""

    if str(output.get("status")) != "blocked_external":
        return False
    findings = normalized_repair_findings(output)
    finding_ids = {item.finding_id for item in findings}
    if (
        "GITHUB_REQUIRED_CHECK_NOT_RUN" not in finding_ids
        or not finding_ids.issubset(_BUILDER_DEFERRED_FINDINGS)
    ):
        return False
    test_results = output.get("test_results", [])
    if not isinstance(test_results, list):
        return False
    local_pm_passed = False
    for item in test_results:
        if not isinstance(item, Mapping):
            return False
        gate_id = str(item.get("gate_id") or "")
        status = str(item.get("status") or "")
        if status == "FAIL":
            return False
        if gate_id == "local-pm-acceptance" and status == "PASS":
            local_pm_passed = True
    changed_files = output.get("changed_files", [])
    return local_pm_passed and isinstance(changed_files, list) and bool(changed_files)


def builder_result_is_controller_complete(output: Mapping[str, Any]) -> bool:
    """Accept a replan request caused only by controller-owned detector scope."""

    if str(output.get("status")) != "needs_replan":
        return False
    findings = normalized_repair_findings(output)
    finding_ids = {item.finding_id for item in findings}
    if (
        "CANONICAL_DETECTOR_SCOPE_CONFLICT" not in finding_ids
        or not finding_ids.issubset(_BUILDER_CONTROLLER_COMPLETE_FINDINGS)
    ):
        return False
    test_results = output.get("test_results", [])
    if not isinstance(test_results, list) or not test_results:
        return False
    passed_gates: set[str] = set()
    for item in test_results:
        if not isinstance(item, Mapping):
            return False
        status = str(item.get("status") or "")
        if status == "FAIL":
            return False
        if status == "PASS":
            passed_gates.add(str(item.get("gate_id") or ""))
    required_provider_gates = {
        "target-environment",
        "target-tests",
        "target-compile",
        "target-lint",
        "target-secret-scan",
    }
    changed_files = output.get("changed_files", [])
    return (
        required_provider_gates.issubset(passed_gates)
        and isinstance(changed_files, list)
        and bool(changed_files)
    )


def product_goals_are_proven(output: Mapping[str, Any]) -> bool:
    """Require passing, evidenced critical journeys before product acceptance."""

    if str(output.get("status")) != "accepted" or bool(output.get("release_blocked")):
        return False
    journeys = output.get("journeys", [])
    if not isinstance(journeys, list) or not journeys:
        return False
    return all(
        isinstance(item, Mapping)
        and item.get("result") == "PASS"
        and isinstance(item.get("evidence_refs"), list)
        and bool(item["evidence_refs"])
        for item in journeys
    )
