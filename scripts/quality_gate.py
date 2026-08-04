#!/usr/bin/env python3
"""Execute allowlisted quality commands without a shell and emit gate evidence."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.metadata
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.policy_guard import command_allowed

_TARGET_SECRET_ADAPTER = "target_changed_secret_scan"
_TARGET_SECRET_COMMAND = "controller:target-changed-secret-scan"
_TARGET_SAST_ADAPTER = "target_changed_sast"
_TARGET_SAST_COMMAND = "controller:target-changed-sast"
_TARGET_DEPENDENCY_ADAPTER = "target_dependency_audit"
_TARGET_DEPENDENCY_COMMAND = "controller:target-dependency-audit"
_TARGET_LICENSE_ADAPTER = "target_license_check"
_TARGET_LICENSE_COMMAND = "controller:target-license-check"
_TARGET_CONTAINER_IMAGE_ADAPTER = "target_container_image_scan"
_TARGET_CONTAINER_IMAGE_COMMAND = "controller:target-container-image-scan"
_TARGET_SECRET_PATTERN = re.compile(
    rb"(?:ghp_|github_pat_|(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}|"
    rb"BEGIN\s+(?:(?:RSA|EC|OPENSSH)\s+)?PRIVATE\s+KEY)"
)
_DENIED_LICENSE_PATTERN = re.compile(
    r"(?:^|[^A-Z])(?:AGPL|GPL|SSPL)(?:[^A-Z]|$)|GNU\s+(?:AFFERO\s+)?GENERAL\s+PUBLIC\s+LICENSE",
    re.IGNORECASE,
)

_NON_RUNTIME_SOURCE_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "docs",
    "examples",
    "test",
    "tests",
    "venv",
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _runtime_python_sources(cwd: Path) -> list[Path]:
    """Return package/runtime Python sources, excluding tests and build trees."""

    roots: list[Path] = []
    src = cwd / "src"
    if src.is_dir():
        roots.append(src)
    roots.extend(
        path
        for path in cwd.iterdir()
        if path.is_dir()
        and not path.name.startswith(".")
        and path.name not in _NON_RUNTIME_SOURCE_DIRECTORIES
        and any(path.rglob("*.py"))
    )
    paths = [
        path
        for path in cwd.glob("*.py")
        if not path.name.startswith("test_") and path.name != "setup.py"
    ]
    for root in roots:
        paths.extend(
            path
            for path in root.rglob("*.py")
            if not any(
                part in _NON_RUNTIME_SOURCE_DIRECTORIES
                for part in path.relative_to(cwd).parts[:-1]
            )
        )
    return sorted(set(paths), key=lambda path: path.relative_to(cwd).as_posix())


def _explicit_zero_dependency_attestation(cwd: Path, subject_sha: str) -> str:
    """Prove that an explicit empty dependency contract matches runtime imports."""

    pyproject_path = cwd / "pyproject.toml"
    if not pyproject_path.is_file():
        raise RuntimeError("pyproject.toml is required for zero-dependency attestation")
    pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    project = pyproject.get("project")
    if not isinstance(project, dict) or "dependencies" not in project:
        raise RuntimeError("project.dependencies must explicitly attest an empty list")
    if project.get("dependencies") != []:
        raise RuntimeError("empty inventory does not match project.dependencies")

    sources = _runtime_python_sources(cwd)
    local_roots = {path.stem for path in cwd.glob("*.py")}
    local_roots.update(
        path.name
        for path in cwd.iterdir()
        if path.is_dir()
        and not path.name.startswith(".")
        and path.name not in _NON_RUNTIME_SOURCE_DIRECTORIES
        and any(path.rglob("*.py"))
    )
    src = cwd / "src"
    if src.is_dir():
        local_roots.update(path.stem for path in src.glob("*.py"))
        local_roots.update(
            path.name
            for path in src.iterdir()
            if path.is_dir() and any(path.rglob("*.py"))
        )

    imported_roots: set[str] = set()
    source_records: list[dict[str, str]] = []
    for path in sources:
        relative = path.relative_to(cwd).as_posix()
        source_records.append({"path": relative, "sha256": digest_file(path)})
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        except (OSError, SyntaxError, UnicodeError) as error:
            raise RuntimeError(f"cannot analyze runtime source {relative}: {error}") from error
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported_roots.add(node.module.split(".", 1)[0])

    undeclared = sorted(
        name
        for name in imported_roots
        if name not in sys.stdlib_module_names and name not in local_roots
    )
    if undeclared:
        raise RuntimeError(
            "undeclared third-party runtime imports: " + ", ".join(undeclared)
        )
    attestation = {
        "schema_version": "1.0",
        "subject_sha": subject_sha,
        "project_dependencies": [],
        "runtime_import_roots": sorted(imported_roots),
        "source_files": source_records,
    }
    return digest_text(json.dumps(attestation, sort_keys=True, separators=(",", ":")))


def load_catalog(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("Gate catalog must be a mapping")
    return data


def _git_changed_paths(cwd: Path) -> list[str]:
    commands: list[list[str]] = [
        ["git", "diff", "--name-only", "-z", "--diff-filter=ACMR", "HEAD", "--"],
        ["git", "ls-files", "-z", "--others", "--exclude-standard"],
    ]
    remote_head = subprocess.run(
        ["git", "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"],
        cwd=cwd,
        capture_output=True,
        timeout=120,
        check=False,
    )
    if remote_head.returncode == 0:
        base_ref = os.fsdecode(remote_head.stdout).strip()
        if not re.fullmatch(r"origin/[A-Za-z0-9._/-]+", base_ref):
            raise RuntimeError("git remote default branch is unsafe")
        commands.append(
            [
                "git",
                "diff",
                "--name-only",
                "-z",
                "--diff-filter=ACMR",
                f"{base_ref}...HEAD",
                "--",
            ]
        )
    paths: set[str] = set()
    for argv in commands:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            timeout=120,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("git could not enumerate changed target files")
        paths.update(
            os.fsdecode(raw_path)
            for raw_path in completed.stdout.split(b"\0")
            if raw_path
        )
    return sorted(paths)


def _file_contains_secret(path: Path) -> bool:
    overlap = b""
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            content = overlap + chunk
            if _TARGET_SECRET_PATTERN.search(content):
                return True
            overlap = content[-256:]
    return False


def _changed_file_secret_scan(gate: dict[str, Any], cwd: Path, subject_sha: str) -> dict[str, Any]:
    command = str(gate.get("command", ""))
    prefixes = gate.get("allowlist_prefixes", [])
    allowed, reason = command_allowed(command, prefixes)
    started = utc_now()
    exit_code: int | None = None
    if (
        gate.get("adapter") != _TARGET_SECRET_ADAPTER
        or command != _TARGET_SECRET_COMMAND
        or not allowed
    ):
        output = f"target secret adapter rejected: {reason or 'invalid adapter configuration'}"
        status = "ERROR"
    else:
        try:
            root = cwd.resolve()
            matches: list[str] = []
            for relative_path in _git_changed_paths(root):
                unresolved = root / relative_path
                if unresolved.is_symlink():
                    raise RuntimeError("changed target path is a symbolic link")
                candidate = unresolved.resolve()
                candidate.relative_to(root)
                if not candidate.is_file():
                    continue
                if _file_contains_secret(candidate):
                    matches.append(relative_path)
            if matches:
                output = "secret-like content detected in changed target file(s): " + ", ".join(matches)
                exit_code = 1
                status = "FAIL"
            else:
                output = "no secret-like content detected in changed target files"
                exit_code = 0
                status = "PASS"
        except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
            output = f"target secret scan failed closed: {error}"
            status = "ERROR"
    return {
        "schema_version": "1.0",
        "gate_id": gate["id"],
        "status": status,
        "subject_sha": subject_sha,
        "command_digest": digest_text(command),
        "started_at": started,
        "finished_at": utc_now(),
        "exit_code": exit_code,
        "artifact_digest": digest_text(output),
        "summary": output[:4000],
        "mandatory": bool(gate.get("mandatory", True)),
    }


def _adapter_configuration_valid(
    gate: dict[str, Any],
    *,
    adapter: str,
    command: str,
) -> tuple[bool, str]:
    prefixes = gate.get("allowlist_prefixes", [])
    allowed, reason = command_allowed(str(gate.get("command", "")), prefixes)
    valid = gate.get("adapter") == adapter and gate.get("command") == command and allowed
    return valid, reason or "invalid adapter configuration"


def _adapter_evidence(
    gate: dict[str, Any],
    subject_sha: str,
    *,
    command: str,
    started: str,
    status: str,
    output: str,
    exit_code: int | None,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "gate_id": gate["id"],
        "status": status,
        "subject_sha": subject_sha,
        "command_digest": digest_text(command),
        "started_at": started,
        "finished_at": utc_now(),
        "exit_code": exit_code,
        "artifact_digest": digest_text(output),
        "summary": output[:4000],
        "mandatory": bool(gate.get("mandatory", True)),
    }


def _changed_file_sast(
    gate: dict[str, Any],
    cwd: Path,
    subject_sha: str,
    python_executable: str | None,
) -> dict[str, Any]:
    command = str(gate.get("command", ""))
    started = utc_now()
    valid, reason = _adapter_configuration_valid(
        gate,
        adapter=_TARGET_SAST_ADAPTER,
        command=_TARGET_SAST_COMMAND,
    )
    if not valid:
        return _adapter_evidence(
            gate,
            subject_sha,
            command=command,
            started=started,
            status="ERROR",
            output=f"target SAST adapter rejected: {reason}",
            exit_code=None,
        )

    try:
        root = cwd.resolve()
        source_paths: list[str] = []
        for relative_path in _git_changed_paths(root):
            normalized = relative_path.replace("\\", "/")
            if not normalized.startswith("src/") or not normalized.endswith(".py"):
                continue
            unresolved = root / relative_path
            if unresolved.is_symlink():
                raise RuntimeError("changed target path is a symbolic link")
            candidate = unresolved.resolve()
            candidate.relative_to(root)
            if candidate.is_file():
                source_paths.append(normalized)
        if not source_paths:
            output = "target SAST not applicable: no changed Python source files under src/"
            return _adapter_evidence(
                gate,
                subject_sha,
                command=command,
                started=started,
                status="PASS",
                output=output,
                exit_code=0,
            )

        interpreter = python_executable or sys.executable
        completed = subprocess.run(
            [
                interpreter,
                "-m",
                "ruff",
                "check",
                "--isolated",
                "--no-cache",
                "--select",
                "S",
                "--ignore-noqa",
                "--output-format",
                "concise",
                *source_paths,
            ],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=int(gate.get("timeout_seconds", 300)),
            check=False,
        )
        raw_output = (completed.stdout + "\n" + completed.stderr).strip()
        output = (
            f"changed_python_files={len(source_paths)}; "
            + (raw_output or "no Ruff security findings in changed Python source files")
        )
        status = "PASS" if completed.returncode == 0 else "FAIL"
        return _adapter_evidence(
            gate,
            subject_sha,
            command=command,
            started=started,
            status=status,
            output=output,
            exit_code=completed.returncode,
        )
    except subprocess.TimeoutExpired as error:
        output = f"target SAST timed out: {error}"
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        output = f"target SAST failed closed: {error}"
    return _adapter_evidence(
        gate,
        subject_sha,
        command=command,
        started=started,
        status="ERROR",
        output=output,
        exit_code=None,
    )


def _target_site_packages(python_executable: str, cwd: Path) -> Path:
    completed = subprocess.run(
        [
            python_executable,
            "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))",
        ],
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("target interpreter could not resolve its package directory")
    raw_path = completed.stdout.strip()
    if not raw_path:
        raise RuntimeError("target interpreter returned an empty package directory")
    site_packages = Path(raw_path).resolve()
    if not site_packages.is_dir():
        raise RuntimeError("target package directory does not exist")
    return site_packages


def _trusted_gate_file(
    path: Path,
    *,
    label: str,
    require_root_owned: bool,
) -> tuple[Path, os.stat_result]:
    if not path.is_absolute():
        raise RuntimeError(f"{label} path must be absolute")
    if path.is_symlink():
        raise RuntimeError(f"{label} must not be a symbolic link")
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise RuntimeError(f"{label} is not a regular file")
    metadata = resolved.stat()
    if require_root_owned and os.name != "nt":
        if metadata.st_uid != 0:
            raise RuntimeError(f"{label} must be root-owned")
        if metadata.st_mode & 0o022:
            raise RuntimeError(f"{label} must not be group/world writable")
    return resolved, metadata


def _dependency_audit(
    gate: dict[str, Any],
    cwd: Path,
    subject_sha: str,
    python_executable: str | None,
) -> dict[str, Any]:
    command = str(gate.get("command", ""))
    started = utc_now()
    valid, reason = _adapter_configuration_valid(
        gate,
        adapter=_TARGET_DEPENDENCY_ADAPTER,
        command=_TARGET_DEPENDENCY_COMMAND,
    )
    if not valid:
        return _adapter_evidence(
            gate,
            subject_sha,
            command=command,
            started=started,
            status="ERROR",
            output=f"target dependency audit adapter rejected: {reason}",
            exit_code=None,
        )
    if not python_executable:
        output = "target dependency audit failed closed: target interpreter is unavailable"
        return _adapter_evidence(
            gate,
            subject_sha,
            command=command,
            started=started,
            status="ERROR",
            output=output,
            exit_code=None,
        )

    try:
        site_packages = _target_site_packages(python_executable, cwd)
        records, reachable = _runtime_dependency_records(cwd, site_packages)
        if not records:
            attestation_digest = _explicit_zero_dependency_attestation(cwd, subject_sha)
            inventory_digest = digest_text("")
            return _adapter_evidence(
                gate,
                subject_sha,
                command=command,
                started=started,
                status="PASS",
                output=(
                    "audited_runtime_packages=0; "
                    f"inventory_sha256={inventory_digest}; "
                    f"zero_dependency_attestation_sha256={attestation_digest}; "
                    "scanner_mode=not_applicable; network_mode=offline; "
                    "known_vulnerabilities=none"
                ),
                exit_code=0,
            )

        require_root_owned = bool(gate.get("require_root_owned", False))
        scanner, _ = _trusted_gate_file(
            Path(str(gate.get("scanner_path", ""))),
            label="OSV-Scanner executable",
            require_root_owned=require_root_owned,
        )
        expected_scanner_digest = str(gate.get("scanner_sha256", "")).lower()
        if not re.fullmatch(r"[a-f0-9]{64}", expected_scanner_digest):
            raise RuntimeError("OSV-Scanner digest pin is invalid")
        scanner_digest = digest_file(scanner)
        if scanner_digest != expected_scanner_digest:
            raise RuntimeError("OSV-Scanner executable digest mismatch")

        cache_directory = Path(str(gate.get("database_cache_directory", "")))
        database, database_metadata = _trusted_gate_file(
            cache_directory / "osv-scanner" / "PyPI" / "all.zip",
            label="OSV PyPI database",
            require_root_owned=require_root_owned,
        )
        maximum_age = int(gate.get("database_max_age_seconds", 259_200))
        if maximum_age < 1:
            raise RuntimeError("OSV database maximum age must be positive")
        database_age = time.time() - database_metadata.st_mtime
        if database_age < -300:
            raise RuntimeError("OSV database timestamp is in the future")
        if database_age > maximum_age:
            raise RuntimeError("OSV PyPI database is stale")
        database_digest = digest_file(database)

        inventory = sorted(
            f"{record['name']}=={record['version']}"
            for record in records
        )
        inventory_digest = digest_text("\n".join(inventory))
        scanner_input = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {
                                "name": record["name"],
                                "version": record["version"],
                                "ecosystem": "PyPI",
                            }
                        }
                        for record in records
                    ]
                }
            ]
        }
        with tempfile.TemporaryDirectory(prefix="hermes-osv-audit-") as directory:
            inventory_path = Path(directory) / "osv-scanner.json"
            inventory_path.write_text(
                json.dumps(scanner_input, sort_keys=True),
                encoding="utf-8",
            )
            os.chmod(inventory_path, 0o600)
            scanner_environment = os.environ.copy()
            scanner_environment["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = str(
                cache_directory
            )
            completed = subprocess.run(
                [
                    str(scanner),
                    "--offline",
                    "--no-resolve",
                    "--verbosity=error",
                    "--format=json",
                    f"--lockfile=osv-scanner:{inventory_path}",
                ],
                cwd=cwd,
                env=scanner_environment,
                text=True,
                capture_output=True,
                timeout=int(gate.get("timeout_seconds", 300)),
                check=False,
            )

        payload = json.loads(completed.stdout)
        results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(results, list):
            raise TypeError("OSV-Scanner returned an invalid result envelope")
        vulnerabilities: list[str] = []
        for result in results:
            if not isinstance(result, dict):
                continue
            packages = result.get("packages", [])
            if not isinstance(packages, list):
                continue
            for package_result in packages:
                if not isinstance(package_result, dict):
                    continue
                package = package_result.get("package", {})
                package_name = (
                    str(package.get("name", "unknown"))
                    if isinstance(package, dict)
                    else "unknown"
                )
                findings = package_result.get("vulnerabilities", [])
                if not isinstance(findings, list):
                    continue
                vulnerabilities.extend(
                    f"{package_name}:{finding.get('id', 'unknown')}"
                    for finding in findings
                    if isinstance(finding, dict)
                )
        vulnerabilities.sort()
        details = ", ".join(vulnerabilities[:50]) if vulnerabilities else "none"
        output = (
            f"audited_runtime_packages={len(reachable)}; "
            f"inventory_sha256={inventory_digest}; "
            f"osv_scanner_sha256={scanner_digest}; "
            f"osv_pypi_database_sha256={database_digest}; "
            f"osv_pypi_database_age_seconds={max(0, int(database_age))}; "
            f"network_mode=offline; known_vulnerabilities={details}"
        )
        if completed.stderr.strip():
            diagnostics = " ".join(completed.stderr.strip().splitlines())
            output += "; diagnostics=" + diagnostics[:1000]
        if completed.returncode == 0 and not vulnerabilities:
            status = "PASS"
        elif completed.returncode == 1 or vulnerabilities:
            status = "FAIL"
        else:
            status = "ERROR"
        return _adapter_evidence(
            gate,
            subject_sha,
            command=command,
            started=started,
            status=status,
            output=output,
            exit_code=completed.returncode,
        )
    except subprocess.TimeoutExpired as error:
        output = f"target dependency audit timed out: {error}"
    except (
        json.JSONDecodeError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as error:
        output = f"target dependency audit failed closed: {error}"
    return _adapter_evidence(
        gate,
        subject_sha,
        command=command,
        started=started,
        status="ERROR",
        output=output,
        exit_code=None,
    )


def _runtime_dependency_records(
    cwd: Path,
    site_packages: Path,
) -> tuple[list[dict[str, str]], list[str]]:
    pyproject_path = cwd / "pyproject.toml"
    if not pyproject_path.is_file():
        raise RuntimeError("pyproject.toml is required for deterministic license scope")
    pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    project = pyproject.get("project")
    if not isinstance(project, dict):
        raise TypeError("pyproject.toml has no [project] dependency contract")
    declared = project.get("dependencies", [])
    if not isinstance(declared, list) or not all(isinstance(item, str) for item in declared):
        raise RuntimeError("project.dependencies must be a list of requirement strings")

    distributions: dict[str, importlib.metadata.Distribution] = {}
    for distribution in importlib.metadata.distributions(path=[str(site_packages)]):
        name = distribution.metadata.get("Name")
        if name:
            distributions[canonicalize_name(name)] = distribution

    pending: list[str] = []
    for raw_requirement in declared:
        try:
            requirement = Requirement(raw_requirement)
        except InvalidRequirement as error:
            raise RuntimeError(f"invalid runtime dependency requirement: {raw_requirement}") from error
        if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
            pending.append(canonicalize_name(requirement.name))

    visited: set[str] = set()
    missing: set[str] = set()
    records: list[dict[str, str]] = []
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        resolved_distribution = distributions.get(name)
        if resolved_distribution is None:
            missing.add(name)
            continue
        metadata = resolved_distribution.metadata
        license_values = [
            str(metadata.get("License-Expression") or "").strip(),
            str(metadata.get("License") or "").strip(),
        ]
        license_values.extend(
            classifier.removeprefix("License :: ").strip()
            for classifier in metadata.get_all("Classifier", [])
            if classifier.startswith("License :: ")
        )
        license_value = next(
            (value for value in license_values if value and value.upper() != "UNKNOWN"),
            "",
        )
        records.append(
            {
                "name": str(metadata.get("Name", name)),
                "version": resolved_distribution.version,
                "license": license_value or "MISSING",
            }
        )
        for raw_child in resolved_distribution.requires or []:
            try:
                child = Requirement(raw_child)
            except InvalidRequirement as error:
                raise RuntimeError(f"invalid installed dependency metadata for {name}") from error
            if child.marker is None or child.marker.evaluate({"extra": ""}):
                pending.append(canonicalize_name(child.name))
    if missing:
        raise RuntimeError(
            "declared runtime dependencies are not installed: " + ", ".join(sorted(missing))
        )
    return sorted(records, key=lambda item: canonicalize_name(item["name"])), sorted(visited)


def _license_check(
    gate: dict[str, Any],
    cwd: Path,
    subject_sha: str,
    python_executable: str | None,
) -> dict[str, Any]:
    command = str(gate.get("command", ""))
    started = utc_now()
    valid, reason = _adapter_configuration_valid(
        gate,
        adapter=_TARGET_LICENSE_ADAPTER,
        command=_TARGET_LICENSE_COMMAND,
    )
    if not valid:
        return _adapter_evidence(
            gate,
            subject_sha,
            command=command,
            started=started,
            status="ERROR",
            output=f"target license adapter rejected: {reason}",
            exit_code=None,
        )
    if not python_executable:
        output = "target license check failed closed: target interpreter is unavailable"
        return _adapter_evidence(
            gate,
            subject_sha,
            command=command,
            started=started,
            status="ERROR",
            output=output,
            exit_code=None,
        )

    try:
        site_packages = _target_site_packages(python_executable, cwd)
        records, reachable = _runtime_dependency_records(cwd, site_packages)
        formatted_records = [
            f"{record['name']}=={record['version']} license={record['license']}"
            for record in records
        ]
        missing = [
            record
            for record in formatted_records
            if record.endswith("license=MISSING")
        ]
        denied = [
            record
            for record in formatted_records
            if _DENIED_LICENSE_PATTERN.search(record)
        ]
        inventory_digest = digest_text("\n".join(formatted_records))
        output = (
            f"runtime_dependency_packages={len(reachable)}; "
            f"license_inventory_sha256={inventory_digest}; "
            f"missing_license_metadata={', '.join(missing) if missing else 'none'}; "
            f"policy_denied_licenses={', '.join(denied) if denied else 'none'}; "
            "policy=missing metadata and GPL/AGPL/SSPL require explicit owner/legal review"
        )
        status = "FAIL" if missing or denied else "PASS"
        exit_code = 1 if missing or denied else 0
        return _adapter_evidence(
            gate,
            subject_sha,
            command=command,
            started=started,
            status=status,
            output=output,
            exit_code=exit_code,
        )
    except (
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        tomllib.TOMLDecodeError,
        TypeError,
    ) as error:
        output = f"target license check failed closed: {error}"
    return _adapter_evidence(
        gate,
        subject_sha,
        command=command,
        started=started,
        status="ERROR",
        output=output,
        exit_code=None,
    )


def _container_image_scan(
    gate: dict[str, Any],
    cwd: Path,
    subject_sha: str,
    python_executable: str | None,
) -> dict[str, Any]:
    """Build and scan the exact candidate image under controller ownership."""

    command = str(gate.get("command", ""))
    started = utc_now()
    valid, reason = _adapter_configuration_valid(
        gate,
        adapter=_TARGET_CONTAINER_IMAGE_ADAPTER,
        command=_TARGET_CONTAINER_IMAGE_COMMAND,
    )
    if not valid:
        return _adapter_evidence(
            gate,
            subject_sha,
            command=command,
            started=started,
            status="ERROR",
            output=f"target container image adapter rejected: {reason}",
            exit_code=None,
        )
    if not python_executable:
        return _adapter_evidence(
            gate,
            subject_sha,
            command=command,
            started=started,
            status="ERROR",
            output="target container image scan failed closed: target interpreter unavailable",
            exit_code=None,
        )

    root = cwd.resolve()
    container_coordinates = (
        Path("container/Containerfile"),
        Path("Containerfile"),
        Path("Dockerfile"),
        Path("compose.yml"),
        Path("compose.yaml"),
        Path("docker-compose.yml"),
        Path("docker-compose.yaml"),
    )
    if not any((root / coordinate).is_file() for coordinate in container_coordinates):
        return _adapter_evidence(
            gate,
            subject_sha,
            command=command,
            started=started,
            status="PASS",
            output="container_image_scan=not_applicable; container_coordinates=none",
            exit_code=0,
        )

    image_ref = f"localhost/hermes-quality-{subject_sha[:16]}:scan"
    builder = "podman"
    image_built = False
    status = "ERROR"
    exit_code: int | None = None
    output = "target container image scan failed closed"
    try:
        verifier = root / "scripts" / "image_security_verify.py"
        if verifier.is_symlink():
            raise RuntimeError("image security verifier must not be a symbolic link")
        verifier = verifier.resolve(strict=True)
        verifier.relative_to(root)
        if not verifier.is_file():
            raise RuntimeError("image security verifier is not a regular file")

        require_root_owned = bool(gate.get("require_root_owned", False))
        scanner, _ = _trusted_gate_file(
            Path(str(gate.get("scanner_path", ""))),
            label="OSV-Scanner executable",
            require_root_owned=require_root_owned,
        )
        expected_scanner_digest = str(gate.get("scanner_sha256", "")).lower()
        if not re.fullmatch(r"[a-f0-9]{64}", expected_scanner_digest):
            raise RuntimeError("OSV-Scanner digest pin is invalid")
        scanner_digest = digest_file(scanner)
        if scanner_digest != expected_scanner_digest:
            raise RuntimeError("OSV-Scanner executable digest mismatch")

        timeout = int(gate.get("timeout_seconds", 900))
        if timeout < 1:
            raise RuntimeError("container image scan timeout must be positive")
        with tempfile.TemporaryDirectory(prefix="hermes-container-gate-") as directory:
            temporary = Path(directory)
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            environment["PYTHONPYCACHEPREFIX"] = str(temporary / "pycache")
            build_output = temporary / "image-build.json"
            build_command = [
                python_executable,
                str(verifier),
                "build",
                "--root",
                str(root),
                "--image-ref",
                image_ref,
                "--subject-sha",
                subject_sha,
                "--output",
                str(build_output),
                "--builder",
                builder,
            ]
            built = subprocess.run(
                build_command,
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
            exit_code = built.returncode
            if built.returncode != 0 or not build_output.is_file():
                raise RuntimeError(
                    f"image build command failed with exit code {built.returncode}"
                )
            build_payload = json.loads(build_output.read_text(encoding="utf-8"))
            image_digest = str(build_payload.get("image_digest", ""))
            immutable_ref = str(build_payload.get("immutable_image_ref", ""))
            if (
                build_payload.get("status") != "pass"
                or build_payload.get("subject_sha") != subject_sha
                or build_payload.get("image_ref") != image_ref
                or not re.fullmatch(r"sha256:[a-f0-9]{64}", image_digest)
                or immutable_ref != f"{image_ref}@{image_digest}"
            ):
                raise RuntimeError("image build evidence is not subject-bound and immutable")
            image_built = True

            scan_output = temporary / "container-scan.json"
            scan_command = [
                python_executable,
                str(verifier),
                "scan",
                "--root",
                str(root),
                "--image-digest",
                immutable_ref,
                "--subject-sha",
                subject_sha,
                "--output",
                str(scan_output),
                "--scanner",
                str(scanner),
                "--builder",
                builder,
            ]
            scanned = subprocess.run(
                scan_command,
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
            exit_code = scanned.returncode
            if not scan_output.is_file():
                raise RuntimeError("container scanner did not retain an evidence record")
            scan_payload = json.loads(scan_output.read_text(encoding="utf-8"))
            binding_valid = bool(
                scan_payload.get("subject_sha") == subject_sha
                and scan_payload.get("image_ref") == immutable_ref
                and scan_payload.get("image_digest") == image_digest
                and scan_payload.get("scanner") == str(scanner)
                and scan_payload.get("evidence_valid") is True
                and isinstance(scan_payload.get("blocking_findings"), int)
                and not isinstance(scan_payload.get("blocking_findings"), bool)
                and isinstance(scan_payload.get("scanner_exit_code"), int)
            )
            if not binding_valid:
                raise RuntimeError("container scan evidence is malformed or unbound")
            blocking = int(scan_payload["blocking_findings"])
            scanner_exit = int(scan_payload["scanner_exit_code"])
            raw_findings = scan_payload.get("findings", [])
            if not isinstance(raw_findings, list) or any(
                not isinstance(finding, dict) for finding in raw_findings
            ):
                raise RuntimeError("container scan findings are malformed")
            finding_coordinates = sorted(
                {
                    ":".join(
                        (
                            str(finding.get("id", "unknown")),
                            str(finding.get("severity", "unknown")),
                            str(finding.get("package", "unknown")),
                        )
                    )
                    for finding in raw_findings
                }
            )
            passed = (
                scanned.returncode == 0
                and scan_payload.get("status") == "pass"
                and scanner_exit == 0
                and blocking == 0
            )
            status = "PASS" if passed else "FAIL"
            output = (
                f"container_image_scan={'pass' if passed else 'fail'}; "
                f"subject_sha={subject_sha}; image_digest={image_digest}; "
                f"osv_scanner_sha256={scanner_digest}; "
                f"scanner_evidence_sha256={digest_file(scan_output)}; "
                f"scanner_exit_code={scanner_exit}; blocking_findings={blocking}; "
                "finding_coordinates="
                + (",".join(finding_coordinates[:50]) or "none")
            )
    except subprocess.TimeoutExpired as error:
        output = f"target container image scan timed out: {error}"
        status = "ERROR"
        exit_code = None
    except (
        json.JSONDecodeError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as error:
        output = f"target container image scan failed closed: {error}"
        status = "ERROR"
        exit_code = None
    finally:
        if image_built:
            cleanup: subprocess.CompletedProcess[str] | None
            try:
                cleanup = subprocess.run(
                    [builder, "image", "rm", "--force", image_ref],
                    cwd=root,
                    text=True,
                    capture_output=True,
                    timeout=120,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                cleanup = None
            if cleanup is None or cleanup.returncode != 0:
                status = "ERROR"
                exit_code = None if cleanup is None else cleanup.returncode
                output += "; image_cleanup=failed"
            else:
                output += "; image_cleanup=pass"
    return _adapter_evidence(
        gate,
        subject_sha,
        command=command,
        started=started,
        status=status,
        output=output,
        exit_code=exit_code,
    )


def run_gate(
    gate: dict[str, Any],
    cwd: Path,
    subject_sha: str,
    *,
    python_executable: str | None = None,
) -> dict[str, Any]:
    adapter = gate.get("adapter")
    if adapter == _TARGET_SECRET_ADAPTER:
        return _changed_file_secret_scan(gate, cwd, subject_sha)
    if adapter == _TARGET_SAST_ADAPTER:
        return _changed_file_sast(gate, cwd, subject_sha, python_executable)
    if adapter == _TARGET_DEPENDENCY_ADAPTER:
        return _dependency_audit(gate, cwd, subject_sha, python_executable)
    if adapter == _TARGET_LICENSE_ADAPTER:
        return _license_check(gate, cwd, subject_sha, python_executable)
    if adapter == _TARGET_CONTAINER_IMAGE_ADAPTER:
        return _container_image_scan(gate, cwd, subject_sha, python_executable)
    if adapter is not None:
        return _adapter_evidence(
            gate,
            subject_sha,
            command=str(gate.get("command", "")),
            started=utc_now(),
            status="ERROR",
            output=f"unknown controller quality adapter: {adapter}",
            exit_code=None,
        )
    command = str(gate["command"])
    prefixes = gate.get("allowlist_prefixes", [])
    allowed, reason = command_allowed(command, prefixes)
    started = utc_now()
    if not allowed:
        output = f"command rejected: {reason}"
        exit_code = None
        status = "ERROR"
    else:
        try:
            argv = shlex.split(command)
            if python_executable and argv and argv[0].lower() in {"python", "python3", "python.exe"}:
                argv[0] = python_executable
            with tempfile.TemporaryDirectory(
                prefix="hermes-gate-pycache-"
            ) as pycache_directory:
                gate_environment = os.environ.copy()
                gate_environment["PYTHONPYCACHEPREFIX"] = pycache_directory
                gate_environment["PYTHONDONTWRITEBYTECODE"] = "1"
                completed = subprocess.run(
                    argv,
                    cwd=cwd,
                    env=gate_environment,
                    text=True,
                    capture_output=True,
                    timeout=int(gate.get("timeout_seconds", 600)),
                    check=False,
                )
            output = (completed.stdout + "\n" + completed.stderr).strip()
            exit_code = completed.returncode
            success_exit_codes = gate.get("success_exit_codes", [0])
            if not isinstance(success_exit_codes, list) or not all(
                isinstance(item, int) for item in success_exit_codes
            ):
                raise TypeError("success_exit_codes must be a list of integers")
            status = "PASS" if completed.returncode in success_exit_codes else "FAIL"
        except subprocess.TimeoutExpired as error:
            output = f"gate timed out after {gate.get('timeout_seconds', 600)} seconds: {error}"
            exit_code = None
            status = "ERROR"
        except OSError as error:
            output = f"gate process could not start: {error}"
            exit_code = None
            status = "ERROR"
    finished = utc_now()
    return {
        "schema_version": "1.0",
        "gate_id": gate["id"],
        "status": status,
        "subject_sha": subject_sha,
        "command_digest": digest_text(command),
        "started_at": started,
        "finished_at": finished,
        "exit_code": exit_code,
        "artifact_digest": digest_text(output),
        "summary": output[:4000],
        "mandatory": bool(gate.get("mandatory", True)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--cwd", type=Path, required=True)
    parser.add_argument("--subject-sha", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    catalog = load_catalog(args.catalog)
    selected = next((gate for gate in catalog["gates"] if gate["id"] == args.gate), None)
    if selected is None:
        raise SystemExit(f"Unknown gate: {args.gate}")
    result = run_gate(selected, args.cwd, args.subject_sha, python_executable=sys.executable)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(result["status"])
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
