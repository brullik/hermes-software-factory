#!/usr/bin/env python3
"""Execute allowlisted quality commands without a shell and emit gate evidence."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import shlex
import subprocess
import sys
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
_TARGET_SECRET_PATTERN = re.compile(
    rb"(?:ghp_|github_pat_|sk-[A-Za-z0-9_-]{20,}|"
    rb"BEGIN\s+(?:(?:RSA|EC|OPENSSH)\s+)?PRIVATE\s+KEY)"
)
_DENIED_LICENSE_PATTERN = re.compile(
    r"(?:^|[^A-Z])(?:AGPL|GPL|SSPL)(?:[^A-Z]|$)|GNU\s+(?:AFFERO\s+)?GENERAL\s+PUBLIC\s+LICENSE",
    re.IGNORECASE,
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_catalog(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("Gate catalog must be a mapping")
    return data


def _git_changed_paths(cwd: Path) -> list[str]:
    commands = (
        ["git", "diff", "--name-only", "-z", "--diff-filter=ACMR", "HEAD", "--"],
        ["git", "ls-files", "-z", "--others", "--exclude-standard"],
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
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip_audit",
                "--path",
                str(site_packages),
                "--progress-spinner",
                "off",
                "--format",
                "json",
                "--timeout",
                "30",
            ],
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=int(gate.get("timeout_seconds", 300)),
            check=False,
        )
        payload = json.loads(completed.stdout)
        dependencies = payload.get("dependencies", []) if isinstance(payload, dict) else payload
        if not isinstance(dependencies, list) or not dependencies:
            raise RuntimeError("pip-audit returned no dependency inventory")
        inventory = sorted(
            f"{item.get('name', 'unknown')}=={item.get('version', 'unknown')}"
            for item in dependencies
            if isinstance(item, dict)
        )
        vulnerabilities = sorted(
            f"{item.get('name', 'unknown')}:{vulnerability.get('id', 'unknown')}"
            for item in dependencies
            if isinstance(item, dict)
            for vulnerability in item.get("vulns", [])
            if isinstance(vulnerability, dict)
        )
        skipped = payload.get("fixes", []) if isinstance(payload, dict) else []
        inventory_digest = digest_text("\n".join(inventory))
        details = ", ".join(vulnerabilities[:50]) if vulnerabilities else "none"
        output = (
            f"audited_packages={len(inventory)}; inventory_sha256={inventory_digest}; "
            f"known_vulnerabilities={details}; auxiliary_records={len(skipped)}"
        )
        if completed.stderr.strip():
            output += "; diagnostics=" + completed.stderr.strip()
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
    except (json.JSONDecodeError, OSError, RuntimeError, subprocess.SubprocessError) as error:
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


def _runtime_dependency_inventory(cwd: Path, site_packages: Path) -> tuple[list[str], list[str]]:
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
    records: list[str] = []
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
            f"{metadata.get('Name', name)}=={resolved_distribution.version} "
            f"license={license_value or 'MISSING'}"
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
    return sorted(records), sorted(visited)


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
        records, reachable = _runtime_dependency_inventory(cwd, site_packages)
        missing = [record for record in records if record.endswith("license=MISSING")]
        denied = [record for record in records if _DENIED_LICENSE_PATTERN.search(record)]
        inventory_digest = digest_text("\n".join(records))
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
            completed = subprocess.run(
                argv,
                cwd=cwd,
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
