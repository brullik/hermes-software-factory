#!/usr/bin/env python3
"""Fail-closed static audit for known Hermes PRE-Q8 orchestration blockers."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final

EXPECTED_ORDER: Final[tuple[str, ...]] = (
    "zero-dependency-cli",
    "small-python-service",
    "telegram-bot",
    "existing-repository-repair",
    "high-fan-in",
    "external-blocker-resume",
    "provider-timeout-restart",
    "failed-product-test-one-repair",
    "package-only",
    "deploy-rollback",
)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    severity: str
    status: str
    path: str
    summary: str
    remediation: str


class Audit:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.findings: list[Finding] = []

    def text(self, relative: str) -> str:
        path = self.root / relative
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            self.add(
                f"MISSING-{relative}",
                "BLOCKER",
                "FAIL",
                relative,
                "Required source file is unavailable.",
                "Restore the tracked file and rerun the audit.",
            )
            return ""

    def add(
        self,
        finding_id: str,
        severity: str,
        status: str,
        path: str,
        summary: str,
        remediation: str,
    ) -> None:
        self.findings.append(
            Finding(finding_id, severity, status, path, summary, remediation)
        )

    def run(self) -> dict[str, object]:
        scenario_runner = self.text("scripts/qualification/run-pre-q8-scenario.sh")
        dynamic_idle_markers = (
            "worker_is_idle",
            "worker_idle=",
            "WORKER_IDLE",
            "pre_q8_runtime",
            "unit-snapshot",
        )
        unconditional_idle = (
            "--worker-idle" in scenario_runner
            and not any(marker in scenario_runner for marker in dynamic_idle_markers)
        )
        self.add(
            "PREQ8-P0-001",
            "BLOCKER",
            "FAIL" if unconditional_idle else "PASS",
            "scripts/qualification/run-pre-q8-scenario.sh",
            "The runner must not assert worker idle unconditionally.",
            "Derive idle from typed systemd/restart/lease/frontier state.",
        )

        builder = self.text("scripts/bootstrap/build-canary-configs.py")
        self.add(
            "PREQ8-P0-002",
            "BLOCKER",
            "FAIL" if "enumerate(sorted(catalog))" in builder else "PASS",
            "scripts/bootstrap/build-canary-configs.py",
            "Scenario generation must preserve the closed canonical order.",
            "Iterate the validated catalog order and compare it to PRE_Q8_SCENARIOS.",
        )

        readiness = self.text("factory/functional_readiness.py")
        failure_model = all(
            token in readiness
            for token in (
                "pre_q8_fail",
                "record_pre_q8_failure",
            )
        )
        self.add(
            "PREQ8-P0-003",
            "BLOCKER",
            "PASS" if failure_model else "FAIL",
            "factory/functional_readiness.py",
            "Official PRE-Q8 needs durable failure state and an atomic API.",
            "Add append-only failure/run tables and record_pre_q8_failure.",
        )

        functional_cli = self.text("scripts/functional_qualification.py")
        self.add(
            "PREQ8-P0-004",
            "BLOCKER",
            "PASS" if "pre-q8-fail" in functional_cli else "FAIL",
            "scripts/functional_qualification.py",
            "The verifier CLI needs a typed official failure command.",
            "Implement idempotent pre-q8-fail and expose it to the orchestrator.",
        )

        all_runner = self.text("scripts/qualification/run-all-pre-q8.sh")
        fail_fast = (
            "systemctl start --wait" in all_runner
            and "for scenario_id" in all_runner
            and not any(
                token in all_runner
                for token in ("failure_matrix", "FAILURES=", "run_results", "convergence")
            )
        )
        self.add(
            "PREQ8-P0-005",
            "BLOCKER",
            "FAIL" if fail_fast else "PASS",
            "scripts/qualification/run-all-pre-q8.sh",
            "Discovery must not stop after the first scenario failure.",
            "Use a separate all-ten convergence sweep and reserve fail-fast for official terminalization.",
        )

        reconcile = self.text("scripts/qualification/reconcile-functional.sh")
        timer_safe = (
            "pre-q8-fail" in reconcile
            or "QUALIFICATION_FAILED" in reconcile
            or "pre_q8_runtime" in reconcile
        )
        self.add(
            "PREQ8-P0-006",
            "BLOCKER",
            "PASS" if timer_safe else "FAIL",
            "scripts/qualification/reconcile-functional.sh",
            "A failed aggregate service must terminalize the Candidate before the next timer tick.",
            "Catch the failure, commit immutable failure evidence, and stop same-epoch retries.",
        )

        bootstrap = self.text("scripts/bootstrap/prepare-candidate-plane.sh")
        required_patterns = (
            "hermes-factory-pre-q8-controller@*",
            "hermes-factory-pre-q8-worker@*",
            "hermes-factory-pre-q8@*",
        )
        missing_patterns = [value for value in required_patterns if value not in bootstrap]
        self.add(
            "PREQ8-P0-007",
            "BLOCKER",
            "FAIL" if missing_patterns else "PASS",
            "scripts/bootstrap/prepare-candidate-plane.sh",
            f"Epoch switch lacks full PRE-Q8 template coverage: {missing_patterns}.",
            "Stop/check/archive/reset every PRE-Q8, convergence and Golden instance.",
        )

        support_unit = self.text("config/systemd/hermes-factory-support-bundle@.service")
        support_script = self.text("scripts/support_bundle.py")
        support_complete = all(
            token in (support_unit + "\n" + support_script)
            for token in (
                "/var/lib/hermes-factory-pre-q8",
                "/var/log/hermes-factory-pre-q8",
            )
        )
        self.add(
            "PREQ8-P0-008",
            "BLOCKER",
            "PASS" if support_complete else "FAIL",
            "scripts/support_bundle.py",
            "Failure bundles must include allowlisted PRE-Q8 state/log/unit evidence.",
            "Extend sanitized roots and invoke bundle creation on every terminal failure.",
        )

        candidate = self.text("scripts/canary_candidate.py")
        namespace_tokens = ("qualification_plane", "run_id", "plane_namespace")
        namespaced = any(token in candidate for token in namespace_tokens)
        self.add(
            "PREQ8-P0-009",
            "BLOCKER",
            "PASS" if namespaced else "FAIL",
            "scripts/canary_candidate.py",
            "External repository/idempotency identities need plane and run namespaces.",
            "Include convergence/PRE-Q8/Q8 plane and sealed run ID.",
        )

        clean_runner = self.text("scripts/qualification/run-clean-canary.sh")
        hardcoded_q8 = (
            'CANARY_DATABASE="/var/lib/hermes-factory-canaries/${SCENARIO_ID}/controller.db"'
            in clean_runner
        )
        self.add(
            "PREQ8-P0-010",
            "BLOCKER",
            "FAIL" if hardcoded_q8 else "PASS",
            "scripts/qualification/run-clean-canary.sh",
            "Q8 must derive its database path from the root-owned scenario config.",
            "Parse YAML and validate the resolved path inside the exact epoch root.",
        )

        epoch_evidence = 'state_root / "pre-q8-evidence" / scenario_id' not in functional_cli
        self.add(
            "PREQ8-P0-011",
            "BLOCKER",
            "PASS" if epoch_evidence else "FAIL",
            "scripts/functional_qualification.py",
            "PRE-Q8 evidence must be epoch/run scoped.",
            "Use <state>/pre-q8-evidence/<epoch>/<scenario>.",
        )

        observation = self.text("factory/canary_qualification.py")
        nondeterministic = bool(
            re.search(
                r'payload\s*=\s*\{.*?"observed_at"\s*:\s*utc_now\(\).*?_write_evidence',
                observation,
                re.DOTALL,
            )
        )
        self.add(
            "PREQ8-P0-012",
            "BLOCKER",
            "FAIL" if nondeterministic else "PASS",
            "factory/canary_qualification.py",
            "Wall-clock time must not change the identity digest of the same terminal state.",
            "Hash a deterministic body and place observation time in a separate envelope.",
        )

        convergence_files = (
            self.root / "factory/pre_q8_convergence.py",
            self.root / "scripts/pre_q8_convergence.py",
        )
        self.add(
            "PREQ8-P0-013",
            "BLOCKER",
            "PASS" if any(path.is_file() for path in convergence_files) else "FAIL",
            "factory/pre_q8_convergence.py",
            "An isolated all-ten convergence lane is required before official admission.",
            "Implement convergence state, matrix, fresh runs and a seal.",
        )

        seal_tokens = ("PREQ8_CONVERGENCE_SEAL", "pre_q8_seal", "convergence_seal")
        corpus = readiness + functional_cli + builder
        self.add(
            "PREQ8-P0-014",
            "BLOCKER",
            "PASS" if any(token in corpus for token in seal_tokens) else "FAIL",
            "factory/pre_q8_seal.py",
            "Official admission must bind exact bytes to a 10/10 convergence seal.",
            "Add signed seal construction and fail-closed admission verification.",
        )

        blockers = [
            finding
            for finding in self.findings
            if finding.severity == "BLOCKER" and finding.status != "PASS"
        ]
        return {
            "schema_version": "1.0",
            "status": "PASS" if not blockers else "FAIL",
            "repository_root": str(self.root),
            "expected_scenario_order": list(EXPECTED_ORDER),
            "blocking_count": len(blockers),
            "findings": [asdict(finding) for finding in self.findings],
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    report = Audit(args.repo).run()
    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    print(encoded, end="")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(encoded, encoding="utf-8")
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
