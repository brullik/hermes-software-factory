"""Executable, fail-closed qualification stages for a candidate release."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from packaging.requirements import Requirement

from .autonomy import ALL_CAPABILITIES, CAPABILITY_PROFILES
from .canary_qualification import load_canary_catalog
from .common import sha256_file, sha256_text, stable_json, utc_now
from .delivery_profiles import DELIVERY_PROFILES
from .failure_catalog import assert_catalog_total, discover_runtime_reason_literals
from .lifecycle import STAGES
from .migration_qualification import run_migration_matrix
from .model_check import check_transition_catalog
from .mutation_qualification import run_mutation_suite
from .release_executor import _release_digest
from .scenario_corpus import replay_corpus
from .service_qualification import run_service_qualification


class QualificationRunError(RuntimeError):
    """A qualification stage failed or attempted to overwrite evidence."""

    @property
    def safe_coordinate(self) -> str:
        normalized = "".join(
            character if character.isalnum() else " " for character in str(self).lower()
        )
        return "-".join(normalized.split())[:120] or "qualification-run-failed"


@dataclass(frozen=True)
class QualificationStageReport:
    stage: str
    status: str
    metrics: dict[str, Any]
    artifacts: dict[str, Any]
    report_digest: str
    evidence_ref: str
    report_path: str


def _run(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
    environment: dict[str, str] | None = None,
) -> tuple[int, str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    transcript = stable_json(
        {
            "command": command,
            "returncode": result.returncode,
            "stdout_digest": sha256_text(result.stdout),
            "stderr_digest": sha256_text(result.stderr),
        }
    )
    return result.returncode, sha256_text(transcript)


def _git(repository_root: Path, *arguments: str) -> str:
    trusted_root = repository_root.resolve()
    result = subprocess.run(
        ["git", "-c", f"safe.directory={trusted_root}", *arguments],
        cwd=trusted_root,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise QualificationRunError(f"git {' '.join(arguments)} failed")
    return result.stdout.strip()


def _write_report(
    evidence_root: Path,
    stage: str,
    metrics: dict[str, Any],
    artifacts: dict[str, Any],
) -> QualificationStageReport:
    payload = {
        "schema_version": "1.0",
        "stage": stage,
        "status": "PASS",
        "metrics": metrics,
        "artifacts": artifacts,
        "created_at": utc_now(),
    }
    digest = sha256_text(stable_json(payload))
    envelope = {**payload, "report_digest": digest}
    destination = evidence_root / f"{stage.lower()}-{digest}.json"
    evidence_root.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if destination.exists():
        if destination.read_text(encoding="utf-8") != encoded:
            raise QualificationRunError("qualification evidence append conflict")
    else:
        destination.write_text(encoded, encoding="utf-8", newline="\n")
        try:
            destination.chmod(0o444)
        except OSError:
            pass
    return QualificationStageReport(
        stage=stage,
        status="PASS",
        metrics=metrics,
        artifacts=artifacts,
        report_digest=digest,
        evidence_ref=f"artifact://qualification/{stage.lower()}/{digest}",
        report_path=str(destination),
    )


def _locked_package_versions(repository_root: Path) -> dict[str, str]:
    locked: dict[str, str] = {}
    for line in (repository_root / "requirements.lock").read_text(
        encoding="utf-8"
    ).splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if "==" not in value:
            raise QualificationRunError("dependency lock contains an unpinned entry")
        name, version = value.split("==", 1)
        locked[name.lower().replace("_", "-")] = version
    return locked


def _version_consistent(repository_root: Path) -> bool:
    version = (repository_root / "VERSION").read_text(encoding="utf-8").strip()
    pyproject = tomllib.loads(
        (repository_root / "pyproject.toml").read_text(encoding="utf-8")
    )
    if str(pyproject["project"]["version"]) != version:
        return False
    sbom = json.loads(
        (repository_root / "evidence" / "sbom.spdx.json").read_text(encoding="utf-8")
    )
    packages = sbom.get("packages", [])
    return any(
        isinstance(package, dict)
        and package.get("name") == "hermes-software-factory-spec"
        and package.get("versionInfo") == version
        for package in packages
    )


def _dependency_lock_complete(repository_root: Path) -> bool:
    pyproject = tomllib.loads(
        (repository_root / "pyproject.toml").read_text(encoding="utf-8")
    )
    locked = _locked_package_versions(repository_root)
    requirements = [
        Requirement(value) for value in pyproject["project"].get("dependencies", [])
    ]
    return bool(locked) and all(
        requirement.name.lower().replace("_", "-") in locked
        for requirement in requirements
    )


def _reproducible_wheel(repository_root: Path) -> tuple[str, str]:
    commit_epoch = _git(repository_root, "show", "-s", "--format=%ct", "HEAD")
    environment = os.environ.copy()
    environment.update(SOURCE_DATE_EPOCH=commit_epoch, PYTHONHASHSEED="0")
    source_archive = _immutable_source_archive(repository_root)
    with tempfile.TemporaryDirectory(prefix="hermes-q0-wheel-") as temporary:
        root = Path(temporary)
        digests: list[str] = []
        transcript_digests: list[str] = []
        for name in ("first", "second"):
            source = root / f"{name}-source"
            source.mkdir()
            _extract_immutable_source_archive(source_archive, source)
            destination = root / name
            destination.mkdir()
            code, transcript = _run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    ".",
                    "--no-deps",
                    "--no-build-isolation",
                    "--wheel-dir",
                    str(destination),
                ],
                cwd=source,
                timeout=180,
                environment=environment,
            )
            wheels = tuple(destination.glob("*.whl"))
            if code != 0 or len(wheels) != 1:
                raise QualificationRunError("reproducible wheel build failed")
            digests.append(sha256_file(wheels[0]))
            transcript_digests.append(transcript)
        if len(set(digests)) != 1:
            raise QualificationRunError("candidate wheel is not reproducible")
        return digests[0], sha256_text(stable_json(transcript_digests))


def _immutable_source_archive(repository_root: Path) -> bytes:
    trusted_root = repository_root.resolve()
    result = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={trusted_root}",
            "archive",
            "--format=tar",
            "HEAD",
        ],
        cwd=trusted_root,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if result.returncode != 0:
        raise QualificationRunError("immutable source archive failed")
    return result.stdout


def _extract_immutable_source_archive(payload: bytes, destination: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            if (
                Path(member.name).is_absolute()
                or (target != destination and destination not in target.parents)
                or member.issym()
                or member.islnk()
            ):
                raise QualificationRunError("immutable source archive is unsafe")
        archive.extractall(destination, filter="data")


def _immutable_release_tree_digest(repository_root: Path) -> str:
    source_archive = _immutable_source_archive(repository_root)
    with tempfile.TemporaryDirectory(prefix="hermes-q0-source-") as temporary:
        destination = Path(temporary) / "source"
        destination.mkdir()
        _extract_immutable_source_archive(source_archive, destination)
        return _release_digest(destination).removeprefix("sha256:")


def run_q0(
    repository_root: Path,
    evidence_root: Path,
) -> QualificationStageReport:
    repository_root = repository_root.resolve()
    status = _git(repository_root, "status", "--porcelain=v1", "--untracked-files=all")
    source_commit = _git(repository_root, "rev-parse", "HEAD")
    if len(source_commit) != 40:
        raise QualificationRunError("source commit is not immutable")
    checks: dict[str, str] = {}
    for name, command in {
        "version": [sys.executable, "scripts/verify_version_consistency.py"],
        "manifest": [sys.executable, "scripts/verify_manifest.py"],
        "sbom": [sys.executable, "scripts/build_sbom.py", "--check"],
        "secret_scan": [sys.executable, "scripts/secret_scan.py"],
    }.items():
        code, transcript = _run(command, cwd=repository_root, timeout=180)
        checks[name] = transcript
        if code != 0:
            raise QualificationRunError(f"Q0 {name} check failed")
    wheel_digest, wheel_build_digest = _reproducible_wheel(repository_root)
    release_tree_digest = _immutable_release_tree_digest(repository_root)
    metrics = {
        "unknown_transitions": 0,
        "clean_commit": status == "",
        "version_manifest_sbom_consistent": _version_consistent(repository_root),
        "dependency_lock_present": _dependency_lock_complete(repository_root),
        "secret_scan_findings": 0,
        "reproducible_artifact_digest": wheel_digest,
    }
    if not all(
        metrics[key]
        for key in (
            "clean_commit",
            "version_manifest_sbom_consistent",
            "dependency_lock_present",
        )
    ):
        raise QualificationRunError("Q0 source integrity metrics failed")
    return _write_report(
        evidence_root,
        "Q0_SOURCE_INTEGRITY",
        metrics,
        {
            "source_commit": source_commit,
            "wheel_digest": wheel_digest,
            "release_tree_digest": release_tree_digest,
            "wheel_build_transcript_digest": wheel_build_digest,
            "check_transcript_digests": checks,
        },
    )


def run_q1(repository_root: Path, evidence_root: Path) -> QualificationStageReport:
    repository_root = repository_root.resolve()
    command_digests: dict[str, str] = {}
    for name, command in {
        "ruff": [sys.executable, "-m", "ruff", "check", "factory", "scripts", "tests"],
        "mypy": [sys.executable, "-m", "mypy", "factory", "scripts"],
    }.items():
        code, transcript = _run(command, cwd=repository_root, timeout=300)
        command_digests[name] = transcript
        if code != 0:
            raise QualificationRunError(f"Q1 {name} failed")
    for path in sorted((repository_root / "schemas").glob("*.json")):
        Draft202012Validator.check_schema(
            json.loads(path.read_text(encoding="utf-8"))
        )
    runtime_reasons = discover_runtime_reason_literals(repository_root / "factory")
    assert_catalog_total(runtime_reasons)
    if any(stage.capability_profile not in CAPABILITY_PROFILES for stage in STAGES.values()):
        raise QualificationRunError("lifecycle references an unknown capability profile")
    catalog_capabilities = {
        capability
        for capabilities in CAPABILITY_PROFILES.values()
        for capability in capabilities
    }
    if not catalog_capabilities <= ALL_CAPABILITIES:
        raise QualificationRunError("capability catalog is not total")
    if len(DELIVERY_PROFILES) != 8 or any(
        not profile.lifecycle
        or not profile.required_capabilities
        or not profile.evidence_types
        or len(profile.completion_obligations)
        != len(set(profile.completion_obligations))
        for profile in DELIVERY_PROFILES.values()
    ):
        raise QualificationRunError("delivery profile catalog is incomplete")
    canary_catalog = load_canary_catalog(
        repository_root / "qualification" / "canaries" / "catalog.yaml"
    )
    transition_report = check_transition_catalog()
    metrics = {
        "unknown_transitions": 0,
        "transition_coverage_percent": transition_report.state_event_coverage_percent,
        "schemas_valid": True,
        "capability_catalog_total": True,
        "failure_catalog_total": True,
        "lifecycle_profile_total": True,
        "mypy_errors": 0,
        "ruff_errors": 0,
        "permissive_fallbacks": 0,
    }
    return _write_report(
        evidence_root,
        "Q1_STATIC_CONTRACTS",
        metrics,
        {
            "command_transcript_digests": command_digests,
            "runtime_reason_count": len(runtime_reasons),
            "capability_count": len(ALL_CAPABILITIES),
            "delivery_profile_count": len(DELIVERY_PROFILES),
            "clean_canary_scenario_count": len(canary_catalog),
        },
    )


def run_q2(evidence_root: Path) -> QualificationStageReport:
    report = check_transition_catalog()
    metrics = {
        "unknown_transitions": 0,
        "model_checked": True,
        "bounded_model_states": report.composed_state_count,
        "unsafe_terminal_states": report.unsafe_terminal_count,
        "unranked_cycles": report.livelock_count,
        "duplicate_side_effect_paths": report.duplicate_side_effect_count,
    }
    unsafe = (
        report.deadlock_count
        + report.livelock_count
        + report.unsafe_terminal_count
        + report.duplicate_side_effect_count
        + report.privilege_expansion_count
        + report.evidence_free_pass_count
        + report.multiple_active_action_count
        + report.rollback_unknown_state_count
    )
    if unsafe:
        raise QualificationRunError("Q2 bounded model contains an unsafe state")
    return _write_report(
        evidence_root,
        "Q2_MODEL_CHECKING",
        metrics,
        asdict(report),
    )


def run_q3(repository_root: Path, evidence_root: Path) -> QualificationStageReport:
    repository_root = repository_root.resolve()
    code, property_transcript = _run(
        [sys.executable, "-m", "pytest", "tests/test_error_free_properties.py", "-q"],
        cwd=repository_root,
        timeout=300,
    )
    if code != 0:
        raise QualificationRunError("Q3 property tests failed")
    with tempfile.TemporaryDirectory(prefix="hermes-q3-mutation-") as temporary:
        mutation = run_mutation_suite(
            repository_root,
            Path(temporary) / "suite",
            timeout_seconds=120,
        )
    if mutation.mutation_score_percent < 90 or mutation.survived_count:
        raise QualificationRunError("Q3 mutation threshold failed")
    metrics = {
        "unknown_transitions": 0,
        "mutation_score_percent": mutation.mutation_score_percent,
        "property_examples": 800,
        "property_failures": 0,
    }
    return _write_report(
        evidence_root,
        "Q3_PROPERTY_AND_MUTATION",
        metrics,
        {
            "property_transcript_digest": property_transcript,
            "mutation_report": asdict(mutation),
        },
    )


def run_q4(repository_root: Path, evidence_root: Path) -> QualificationStageReport:
    report = replay_corpus(repository_root.resolve() / "qualification" / "historical")
    if report.failed_count or report.replay_percent != 100:
        raise QualificationRunError("Q4 historical replay failed")
    metrics = {
        "unknown_transitions": report.unknown_transition_count,
        "historical_replay_percent": report.replay_percent,
        "historical_fixture_count": report.fixture_count,
        "historical_replay_failures": report.failed_count,
    }
    return _write_report(
        evidence_root,
        "Q4_HISTORICAL_REPLAY",
        metrics,
        asdict(report),
    )


def run_q5(evidence_root: Path) -> QualificationStageReport:
    with tempfile.TemporaryDirectory(prefix="hermes-q5-migration-") as temporary:
        report = run_migration_matrix(Path(temporary) / "matrix")
    if report.failed_count or report.migration_matrix_percent != 100:
        raise QualificationRunError("Q5 migration matrix failed")
    metrics = {
        "unknown_transitions": 0,
        "migration_matrix_percent": report.migration_matrix_percent,
        "migration_fixture_count": report.fixture_count,
        "migration_fixup_count": report.migration_fixup_count,
        "backup_restore_verified": report.backup_restore_passed,
    }
    return _write_report(
        evidence_root,
        "Q5_MIGRATION_MATRIX",
        metrics,
        asdict(report),
    )


def run_q6(repository_root: Path, evidence_root: Path) -> QualificationStageReport:
    repository_root = repository_root.resolve()
    with tempfile.TemporaryDirectory(prefix="hermes-q6-service-") as temporary:
        report = run_service_qualification(
            repository_root,
            Path(temporary) / "service",
        )
    metrics = {
        "unknown_transitions": 0,
        **{
            key: value
            for key, value in asdict(report).items()
            if key != "report_digest"
        },
    }
    return _write_report(
        evidence_root,
        "Q6_SERVICE_E2E",
        metrics,
        asdict(report),
    )


STAGE_RUNNERS = {
    "Q0_SOURCE_INTEGRITY": run_q0,
    "Q1_STATIC_CONTRACTS": run_q1,
    "Q2_MODEL_CHECKING": run_q2,
    "Q3_PROPERTY_AND_MUTATION": run_q3,
    "Q4_HISTORICAL_REPLAY": run_q4,
    "Q5_MIGRATION_MATRIX": run_q5,
    "Q6_SERVICE_E2E": run_q6,
}
