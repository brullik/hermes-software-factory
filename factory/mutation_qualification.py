"""Deterministic source mutation gate for the closed-world safety kernel."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .common import sha256_text, stable_json


class MutationQualificationError(RuntimeError):
    """The mutation harness or its baseline is invalid."""


@dataclass(frozen=True)
class MutationSpec:
    mutation_id: str
    relative_path: str
    original: str
    replacement: str
    detector: str


@dataclass(frozen=True)
class MutationResult:
    mutation_id: str
    relative_path: str
    detector: str
    killed: bool
    returncode: int
    duration_milliseconds: int


@dataclass(frozen=True)
class MutationReport:
    mutation_count: int
    killed_count: int
    survived_count: int
    mutation_score_percent: int
    baseline_passed: bool
    report_digest: str
    results: tuple[MutationResult, ...]


MUTATIONS = (
    MutationSpec(
        "MUT-UNKNOWN-TO-PRODUCT",
        "factory/failure_catalog.py",
        """UNKNOWN_FAILURE: Final = FailureDisposition(
    reason_code="unknown_reason_code",
    domain=FailureDomain.DATA_INTEGRITY,
    action=FailureAction.CONTROLLER_QUARANTINE,
    registered=False,
)""",
        """UNKNOWN_FAILURE: Final = FailureDisposition(
    reason_code="unknown_reason_code",
    domain=FailureDomain.PRODUCT_IMPLEMENTATION,
    action=FailureAction.REPAIR_NODE_VERSION,
    registered=False,
)""",
        "tests/test_error_free_process.py::test_p0_unknown_reason_is_controller_quarantine",
    ),
    MutationSpec(
        "MUT-CAPABILITY-UNION",
        "factory/proof_obligations.py",
        """        if capability not in canonical_capabilities:
            continue""",
        """        if capability not in canonical_capabilities:
            pass""",
        "tests/test_error_free_properties.py::test_capability_proof_never_unions_parent_or_model_capabilities",
    ),
    MutationSpec(
        "MUT-SKIP-EVIDENCE-CHECK",
        "factory/transition_kernel.py",
        """        if missing:
            raise TransitionProofError(""",
        """        if False and missing:
            raise TransitionProofError(""",
        "tests/test_error_free_process.py::test_catalog_transition_without_required_evidence_is_rejected",
    ),
    MutationSpec(
        "MUT-REMOVE-TRANSACTION-ROLLBACK",
        "factory/deployment.py",
        """        if had_previous:
            os_replace(previous, current)
            if self.activate is not None:
                try:
                    self.activate()""",
        """        if False and had_previous:
            os_replace(previous, current)
            if self.activate is not None:
                try:
                    self.activate()""",
        "tests/test_factory_runtime.py::FactoryRuntimeTests::test_transactional_deployer_rolls_back_failed_health_and_keeps_failed_release",
    ),
    MutationSpec(
        "MUT-ALTER-OCCURRENCE-EPOCH",
        "factory/path_governor.py",
        """        "contract_digest",
        "toolchain_manifest_digest",
    )""",
        """        "contract_digest",
    )""",
        "tests/test_error_free_properties.py::test_occurrence_identity_changes_when_any_epoch_coordinate_changes",
    ),
    MutationSpec(
        "MUT-PERMIT-WILDCARD-SCOPE",
        "factory/proof_obligations.py",
        "_FORBIDDEN_WILDCARDS = {" + '"*", "**", "**/*"' + "}",
        "_FORBIDDEN_WILDCARDS: set[str] = set()",
        "tests/test_error_free_properties.py::test_every_unbounded_capability_scope_is_rejected",
    ),
    MutationSpec(
        "MUT-REMOVE-CANDIDATE-DIGEST-CHECK",
        "factory/release_qualification.py",
        """        if exact_staging_production_digest != str(epoch["candidate_digest"]):
            raise QualificationError("staging/production digest does not match candidate")""",
        """        if False and exact_staging_production_digest != str(epoch["candidate_digest"]):
            raise QualificationError("staging/production digest does not match candidate")""",
        "tests/test_error_free_process.py::test_promotion_rejects_digest_other_than_exact_candidate",
    ),
    MutationSpec(
        "MUT-ALLOW-DUPLICATE-SIDE-EFFECT",
        "factory/proof_obligations.py",
        """            if tuple(str(value) for value in existing) != receipt_values:
                raise ProofObligationError("duplicate side-effect receipt conflicts")""",
        """            if False and tuple(str(value) for value in existing) != receipt_values:
                raise ProofObligationError("duplicate side-effect receipt conflicts")""",
        "tests/test_error_free_process.py::test_side_effect_intent_receipt_is_replay_safe_and_conflict_closed",
    ),
    MutationSpec(
        "MUT-DISABLE-RANKING-CHECK",
        "factory/model_check.py",
        """        if not any(item.ranking_function for item in internal):
            labels = ",".join(sorted(state.value for state in component))""",
        """        if False and not any(item.ranking_function for item in internal):
            labels = ",".join(sorted(state.value for state in component))""",
        "tests/test_error_free_process.py::test_model_checker_rejects_a_cycle_without_ranking_function",
    ),
)


def _copy_candidate(source: Path, destination: Path) -> None:
    ignored = shutil.ignore_patterns(
        ".git",
        ".deployment",
        ".venv",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "artifacts",
        "build",
        "dist",
        "evidence",
        "*.egg-info",
    )
    shutil.copytree(source, destination, ignore=ignored)


def _run_detector(candidate: Path, detector: str, timeout_seconds: int) -> tuple[int, int]:
    started = time.monotonic()
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(candidate)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", detector],
            cwd=candidate,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
        return result.returncode, int((time.monotonic() - started) * 1000)
    except subprocess.TimeoutExpired:
        return 124, int((time.monotonic() - started) * 1000)


def run_mutation_suite(
    repository_root: Path,
    work_root: Path,
    *,
    timeout_seconds: int = 120,
) -> MutationReport:
    """Mutate exact source coordinates and require every detector to fail."""

    repository_root = repository_root.resolve()
    if not (repository_root / "factory" / "__init__.py").is_file():
        raise MutationQualificationError("repository root is invalid")
    work_root.mkdir(parents=True, exist_ok=False)
    detectors = tuple(dict.fromkeys(item.detector for item in MUTATIONS))
    baseline = work_root / "baseline"
    _copy_candidate(repository_root, baseline)
    baseline_code = 0
    for detector in detectors:
        code, _duration = _run_detector(baseline, detector, timeout_seconds)
        if code != 0:
            baseline_code = code
            break
    if baseline_code != 0:
        raise MutationQualificationError("mutation detector baseline is not green")

    results: list[MutationResult] = []
    for mutation in MUTATIONS:
        candidate = work_root / mutation.mutation_id.lower()
        _copy_candidate(repository_root, candidate)
        path = candidate / mutation.relative_path
        source = path.read_text(encoding="utf-8")
        if source.count(mutation.original) != 1:
            raise MutationQualificationError(
                f"mutation coordinate is not unique: {mutation.mutation_id}"
            )
        path.write_text(
            source.replace(mutation.original, mutation.replacement, 1),
            encoding="utf-8",
            newline="\n",
        )
        returncode, duration = _run_detector(
            candidate,
            mutation.detector,
            timeout_seconds,
        )
        results.append(
            MutationResult(
                mutation_id=mutation.mutation_id,
                relative_path=mutation.relative_path,
                detector=mutation.detector,
                killed=returncode not in {0, 124},
                returncode=returncode,
                duration_milliseconds=duration,
            )
        )
    killed = sum(int(item.killed) for item in results)
    payload = [asdict(item) for item in results]
    return MutationReport(
        mutation_count=len(results),
        killed_count=killed,
        survived_count=len(results) - killed,
        mutation_score_percent=(100 * killed) // len(results),
        baseline_passed=True,
        report_digest=sha256_text(stable_json(payload)),
        results=tuple(results),
    )
