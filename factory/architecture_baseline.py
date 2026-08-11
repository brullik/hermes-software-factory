"""Controller-owned architecture facts for PRE-Q8 Candidate products."""

from __future__ import annotations

import importlib.metadata
import json
import platform
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .common import sha256_file, sha256_text, stable_json
from .config import FactoryConfig
from .delivery_profile_obligations import DeliveryObligationSet

_PIN = re.compile(r"(?P<name>[A-Za-z0-9_.-]+)==(?P<version>[^\s;]+)")
_REQUIRED_DISTRIBUTIONS: Final = (
    "setuptools",
    "pip",
    "pytest",
    "ruff",
    "cryptography",
)
_EXACT_BUILD_REQUIREMENT = "setuptools==83.0.0"
_PRIVATE_LICENSE = (
    "Hermes Private Qualification License\n\n"
    "Copyright (c) Hermes qualification owner. All rights reserved.\n\n"
    "This software may be used only for isolated Hermes qualification and audit. "
    "No permission is granted for production distribution, sublicensing, or public "
    "deployment.\n"
)
_README_CHECKLIST: Final = (
    "installation",
    "invocation_or_api",
    "deterministic_errors",
    "validation_commands",
    "operator_actions",
    "rollback_or_recovery_when_applicable",
)


class ArchitectureBaselineToolchainMismatch(RuntimeError):
    """Live Candidate toolchain differs from the immutable pinned baseline."""


@dataclass(frozen=True)
class DistributionAttestation:
    name: str
    version: str
    aggregate_file_digest: str
    optional: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "aggregate_file_digest": self.aggregate_file_digest,
            "optional": self.optional,
        }


@dataclass(frozen=True)
class ArchitectureBaseline:
    interpreter_path: str
    interpreter_version: str
    interpreter_binary_sha256: str
    requirements_lock_sha256: str
    distributions: tuple[DistributionAttestation, ...]
    commands: tuple[tuple[str, tuple[str, ...]], ...]
    build_system_requires: tuple[str, ...]
    build_backend: str
    project_dependencies: tuple[str, ...]
    license_expression: str
    license_file: str
    license_content: str
    license_content_sha256: str
    readme_checklist: tuple[str, ...]
    profile_protocol_blueprint_json: str
    fault_lifecycle_blueprint_json: str
    obligation_set_digest: str
    toolchain_manifest_digest: str
    baseline_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "interpreter": {
                "path": self.interpreter_path,
                "version": self.interpreter_version,
                "binary_sha256": self.interpreter_binary_sha256,
            },
            "requirements_lock_sha256": self.requirements_lock_sha256,
            "distributions": [item.as_dict() for item in self.distributions],
            "commands": {
                name: list(argv) for name, argv in self.commands
            },
            "pyproject": {
                "build_system": {
                    "requires": list(self.build_system_requires),
                    "build_backend": self.build_backend,
                },
                "project_dependencies": list(self.project_dependencies),
                "license": self.license_expression,
            },
            "license": {
                "expression": self.license_expression,
                "file": self.license_file,
                "content": self.license_content,
                "content_sha256": self.license_content_sha256,
            },
            "readme_checklist": list(self.readme_checklist),
            "profile_protocol_blueprint": json.loads(
                self.profile_protocol_blueprint_json
            ),
            "fault_lifecycle_blueprint": json.loads(
                self.fault_lifecycle_blueprint_json
            ),
            "obligation_set_digest": self.obligation_set_digest,
            "toolchain_manifest_digest": self.toolchain_manifest_digest,
            "baseline_digest": self.baseline_digest,
        }

    def as_artifact(self, product_id: str) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "artifact_id": f"architecture-baseline-{self.baseline_digest[:24]}",
            "product_id": product_id,
            **self.as_dict(),
        }


def _locked_versions(requirements_lock: Path) -> dict[str, str]:
    versions: dict[str, str] = {}
    for raw_line in requirements_lock.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _PIN.fullmatch(line)
        if match is not None:
            versions[match.group("name").casefold().replace("_", "-")] = match.group(
                "version"
            )
    return versions


def _distribution_attestation(
    name: str,
    *,
    expected_version: str | None,
    optional: bool,
) -> DistributionAttestation:
    try:
        distribution = importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError as error:
        if optional:
            return DistributionAttestation(name, "NOT_INSTALLED", sha256_text("[]"), True)
        raise ArchitectureBaselineToolchainMismatch(
            f"architecture_baseline_toolchain_mismatch: {name} is not installed"
        ) from error
    version = str(distribution.version)
    if expected_version is not None and version != expected_version:
        raise ArchitectureBaselineToolchainMismatch(
            "architecture_baseline_toolchain_mismatch: "
            f"{name} {version} != lock {expected_version}"
        )
    files: list[tuple[str, str]] = []
    for item in sorted(distribution.files or (), key=str):
        relative = str(item).replace("\\", "/")
        if "__pycache__" in relative or relative.endswith((".pyc", ".pyo")):
            continue
        candidate = Path(str(distribution.locate_file(item)))
        if candidate.is_file() and not candidate.is_symlink():
            files.append((relative, sha256_file(candidate)))
    if not files:
        raise ArchitectureBaselineToolchainMismatch(
            "architecture_baseline_toolchain_mismatch: "
            f"{name} has no attestable installed files"
        )
    return DistributionAttestation(
        name=name,
        version=version,
        aggregate_file_digest=sha256_text(stable_json(files)),
        optional=optional,
    )


def _profile_protocol_blueprint(obligations: DeliveryObligationSet) -> dict[str, Any]:
    profiles: dict[str, dict[str, Any]] = {
        "CLI_PACKAGE": {
            "package": "deterministic-cli",
            "import_name": "deterministic_cli",
            "console_script": "deterministic-cli",
            "command_shape": ["deterministic-cli", "run", "TEXT"],
            "exact_positional_count": 1,
            "usage_exit": 2,
            "usage_stderr": "E_USAGE: expected exactly one TEXT argument\n",
            "valid_stdout": "strict UTF-8 TEXT plus newline",
            "invalid_stdout": "",
            "deterministic_options": ["--help", "--version"],
            "structured_policy": {
                "strict_utf8": True,
                "duplicate_keys": "reject",
                "non_finite": "reject",
                "floats": "forbidden",
                "canonical_json": "sorted_compact",
            },
        },
        "DEPLOYED_SERVICE": {
            "server": "python_standard_library_http",
            "healthz_get_status": 200,
            "healthz_body": "deterministic_json_bytes",
            "http_head_body_bytes": 0,
            "http_head_statuses": ["success", "error", 405],
            "lifecycle_receipt_fields": [
                "schema_version",
                "transition_id",
                "lifecycle_id",
                "stage",
                "subject_digest",
                "prior_digest",
                "next_digest",
                "health_result",
                "outcome",
                "previous_receipt_digest",
                "created_at",
            ],
        },
        "TELEGRAM_BOT": {
            "initial_state": "NEW",
            "states": [
                "CLAIMED",
                "SENT",
                "FAILED_BEFORE_SEND",
                "AMBIGUOUS",
            ],
            "retry_only": "FAILED_BEFORE_SEND",
            "ambiguous_terminal": True,
            "crash_after_possible_send": "AMBIGUOUS",
            "transitions": [
                "NEW->CLAIMED",
                "CLAIMED->SENT",
                "CLAIMED->FAILED_BEFORE_SEND",
                "CLAIMED->AMBIGUOUS",
                "FAILED_BEFORE_SEND->CLAIMED",
            ],
            "race_test": {
                "database_preinitialized": True,
                "barrier_timeout_seconds": 5,
                "join_timeout_seconds": 10,
                "expected_results": [False, True],
            },
        },
        "OFFLINE_BATCH": {
            "max_definition_bytes": 8_388_608,
            "max_nodes": 256,
            "max_fan_in": 64,
            "max_input_file_bytes": 16_777_216,
            "max_output_bytes": 16_777_216,
            "max_node_memory_bytes": 2_097_152,
            "node_fixed_overhead_bytes": 131_072,
            "exact_boundary_node_spec_bytes": 1_966_080,
            "plus_one_node_spec_bytes": 1_966_081,
            "plus_one_error": "BATCH_LIMIT_NODE_MEMORY",
            "validation_order": [
                "definition_bytes",
                "json_canonical_form",
                "node_count",
                "fan_in",
                "per_node_accounted_memory",
                "path_containment",
                "open_inputs",
                "create_outputs",
            ],
            "limit_failure_opens_inputs": False,
            "limit_failure_creates_outputs": False,
        },
        "GITHUB_AUTOMATION": {
            "authority": "github_git_refs",
            "ref_prefix": "refs/hermes/claims/",
            "initial_atomic_operation": "create_ref",
            "update_operation": "non_force_fast_forward_ref_update",
            "automatic_resume": "scheduled_sweeper_every_5_minutes",
            "correlation_pattern": "^[a-f0-9]{64}$",
            "probe_none": "INVALID",
            "concurrent_create_successes": 1,
            "transition_force": False,
            "sibling_stale_update": "reject",
            "fencing_token": "monotonic_integer",
            "downstream_idempotency_key": "correlation_sha256",
        },
        "LIBRARY_PACKAGE": {
            "package": "artifactproof",
            "validate_artifact_type_before_sort": True,
            "invalid_type_exception": "MalformedEvidenceError",
            "signing": "controller_baseline_ed25519",
            "algorithm": "Ed25519",
            "implementation": "cryptography==46.0.7",
            "signature_encoding": "base64url_raw_64_bytes_no_padding",
            "signature_file": "release-manifest.sig",
            "canonical_manifest": "utf8_sorted_compact_json_no_floats",
            "manifest_value_types": [
                "string",
                "integer",
                "boolean",
                "array",
                "object",
            ],
            "trust_root": "public_ed25519_key_plus_sha256_fingerprint",
            "key_id": "first_16_lowercase_hex_of_public_key_sha256",
            "manifest_bindings": [
                "subject_sha",
                "sdist_digest",
                "wheel_digest",
                "issued_at",
                "expires_at",
                "key_id",
                "revocation_list_digest",
            ],
            "private_key_in_repository": False,
            "product_test_key": "isolated_fixture_key",
            "qualification_signer": "controller_release_adapter",
            "require_issued_at_before_expires_at": True,
            "verification_failure_matrix": [
                "missing",
                "malformed",
                "mismatch",
                "expired",
                "revoked",
                "stale",
            ],
            "clean_consumer_offline": True,
            "clean_consumer_install_args": ["--no-index", "--no-deps"],
            "clean_consumer_smoke": ["import_package", "public_api"],
        },
    }
    selected = dict(profiles.get(obligations.delivery_profile, {}))
    selected["python_requires"] = ">=3.12,<3.13"
    selected["source_layout"] = "src/<normalized_package>/"
    selected["test_layout"] = "tests/"
    selected["gitignore_entries"] = [
        "__pycache__/",
        "*.py[cod]",
        ".pytest_cache/",
        ".ruff_cache/",
        "build/",
        "dist/",
        "*.egg-info/",
    ]
    if obligations.delivery_mode == "existing_repository":
        selected["changed_path_ignores"] = [
            "**/__pycache__/**",
            "**/*.pyc",
            "**/*.pyo",
            ".pytest_cache/**",
            ".ruff_cache/**",
            "build/**",
            "dist/**",
            "**/*.egg-info/**",
        ]
        selected["behavioral_defects_fixed"] = 1
        selected["mandatory_metadata_not_counted_as_behavioral_defect"] = True
        selected["generated_cache_not_changed_path"] = True
    return selected


def _fault_lifecycle_blueprint(obligations: DeliveryObligationSet) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    for fault in obligations.declared_faults:
        if fault == "ONE_PROVIDER_TIMEOUT":
            facts[fault] = {
                "retry_intent_unique": True,
                "create_only_from_state": "TIMED_OUT",
                "same_request_same_intent": "idempotent",
                "other_request_same_intent": "sqlite3.IntegrityError",
                "durable_before_restart": True,
                "consume_once_after_restart": True,
            }
        elif fault == "ONE_PROCESS_RESTART":
            facts[fault] = {
                "intent_is_durable": True,
                "intent_consumptions": 1,
            }
        elif fault == "ONE_PRODUCT_TEST_FAILURE":
            facts[fault] = {
                "injected_gate": "target-tests",
                "injected_count": 1,
                "repair_role": "builder",
                "builder_repairs": 1,
                "fresh_test_required": True,
            }
        elif fault == "ONE_POST_DEPLOY_HEALTH_FAILURE":
            facts[fault] = {
                "target": "isolated_candidate_production_semantics",
                "fault_stage": "production",
                "fault_disabled_by_default": True,
                "fault_token_bound_to": [
                    "plane",
                    "run_id",
                    "scenario_id",
                    "candidate_digest",
                    "lifecycle_id",
                    "production_stage",
                ],
                "fault_consumptions": 1,
                "rollback_count": 1,
                "repair_ref_requires_distinct_candidate_digest": True,
                "repaired_redeploy_required": True,
                "final_receipt": "healthy_production_semantic_target",
                "production_server_rejects_staging_control": True,
            }
    return facts


def build_architecture_baseline(
    config: FactoryConfig,
    product: Mapping[str, Any],
    target_contract: Mapping[str, Any],
    obligation_set: DeliveryObligationSet,
) -> ArchitectureBaseline:
    """Attest exact Candidate facts and compile immutable product blueprints."""

    if (
        str(product.get("delivery_profile") or obligation_set.delivery_profile)
        != obligation_set.delivery_profile
        or str(product.get("delivery_mode") or obligation_set.delivery_mode)
        != obligation_set.delivery_mode
    ):
        raise ArchitectureBaselineToolchainMismatch(
            "architecture_baseline_toolchain_mismatch: delivery obligation drift"
        )
    for field, expected in (
        ("delivery_profile", obligation_set.delivery_profile),
        ("delivery_mode", obligation_set.delivery_mode),
    ):
        supplied = str(target_contract.get(field) or "")
        if supplied and supplied != expected:
            raise ArchitectureBaselineToolchainMismatch(
                "architecture_baseline_toolchain_mismatch: target contract drift"
            )

    package_root = Path(__file__).resolve().parents[1]
    requirements_lock = package_root / "requirements.lock"
    interpreter = Path(sys.executable).resolve(strict=True)
    if (
        not requirements_lock.is_file()
        or requirements_lock.is_symlink()
        or interpreter.is_symlink()
        or not interpreter.is_file()
    ):
        raise ArchitectureBaselineToolchainMismatch(
            "architecture_baseline_toolchain_mismatch: immutable inputs are missing"
        )
    locked = _locked_versions(requirements_lock)
    if locked.get("setuptools") != "83.0.0":
        raise ArchitectureBaselineToolchainMismatch(
            "architecture_baseline_toolchain_mismatch: setuptools pin is not 83.0.0"
        )
    distributions = tuple(
        _distribution_attestation(
            name,
            expected_version=(None if name == "pip" else locked.get(name)),
            optional=name == "ruff",
        )
        for name in _REQUIRED_DISTRIBUTIONS
    )
    python = str(interpreter)
    commands = (
        ("test", (python, "-m", "pytest", "-q")),
        ("compile", (python, "-m", "compileall", "-q", "src", "tests")),
        ("lint", (python, "-m", "ruff", "check", "src", "tests")),
        (
            "build",
            (
                python,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                "dist",
                ".",
            ),
        ),
    )
    interpreter_binary_sha256 = sha256_file(interpreter)
    requirements_lock_sha256 = sha256_file(requirements_lock)
    toolchain_payload: dict[str, Any] = {
        "interpreter_path": python,
        "interpreter_version": platform.python_version(),
        "interpreter_binary_sha256": interpreter_binary_sha256,
        "requirements_lock_sha256": requirements_lock_sha256,
        "distributions": [item.as_dict() for item in distributions],
        "commands": {name: list(argv) for name, argv in commands},
    }
    toolchain_digest = sha256_text(stable_json(toolchain_payload))
    profile_blueprint = _profile_protocol_blueprint(obligation_set)
    fault_blueprint = _fault_lifecycle_blueprint(obligation_set)
    body = {
        **toolchain_payload,
        "build_system_requires": [_EXACT_BUILD_REQUIREMENT],
        "build_backend": "setuptools.build_meta",
        "project_dependencies": [],
        "license_expression": "LicenseRef-Hermes-Private-Qualification",
        "license_file": "LICENSE",
        "license_content_sha256": sha256_text(_PRIVATE_LICENSE),
        "readme_checklist": list(_README_CHECKLIST),
        "profile_protocol_blueprint": profile_blueprint,
        "fault_lifecycle_blueprint": fault_blueprint,
        "obligation_set_digest": obligation_set.digest,
        "toolchain_manifest_digest": toolchain_digest,
    }
    baseline_digest = sha256_text(stable_json(body))
    return ArchitectureBaseline(
        interpreter_path=python,
        interpreter_version=platform.python_version(),
        interpreter_binary_sha256=interpreter_binary_sha256,
        requirements_lock_sha256=requirements_lock_sha256,
        distributions=distributions,
        commands=commands,
        build_system_requires=(_EXACT_BUILD_REQUIREMENT,),
        build_backend="setuptools.build_meta",
        project_dependencies=(),
        license_expression="LicenseRef-Hermes-Private-Qualification",
        license_file="LICENSE",
        license_content=_PRIVATE_LICENSE,
        license_content_sha256=sha256_text(_PRIVATE_LICENSE),
        readme_checklist=_README_CHECKLIST,
        profile_protocol_blueprint_json=stable_json(profile_blueprint),
        fault_lifecycle_blueprint_json=stable_json(fault_blueprint),
        obligation_set_digest=obligation_set.digest,
        toolchain_manifest_digest=toolchain_digest,
        baseline_digest=baseline_digest,
    )
