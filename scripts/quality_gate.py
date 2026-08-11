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
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
from dataclasses import dataclass
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
_CONTROLLER_IMAGE_SECURITY_VERIFIER_SHA256 = (
    "247cc0b6f8f55e081c2188ec1f5f50a45cf358923c02117a8a15a6d3e9760f8f"
)
_OS_KILL_PROCESS_GROUP = os.__dict__.get("killpg")
_SIGKILL = signal.__dict__.get("SIGKILL", signal.SIGTERM)
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


@dataclass(frozen=True)
class _BoundedProcessResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    process_tree: tuple[dict[str, Any], ...]
    dump_requested: bool


def _signal_process_group(process_id: int, selected_signal: int) -> None:
    if not callable(_OS_KILL_PROCESS_GROUP):
        raise OSError("process-group signalling is unavailable")
    _OS_KILL_PROCESS_GROUP(process_id, selected_signal)


def _bounded_process_tree(root_pid: int, *, limit: int = 128) -> tuple[dict[str, Any], ...]:
    """Capture a bounded Linux process tree without invoking another shell."""

    records: dict[int, tuple[int, str]] = {}
    proc = Path("/proc")
    if proc.is_dir():
        for entry in sorted(proc.iterdir(), key=lambda path: path.name):
            if not entry.name.isdigit() or len(records) >= 4096:
                continue
            try:
                status = (entry / "status").read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            fields = {
                key: value.strip()
                for raw in status.splitlines()
                if ":" in raw
                for key, value in [raw.split(":", 1)]
            }
            try:
                records[int(entry.name)] = (
                    int(fields.get("PPid", "0")),
                    fields.get("Name", "unknown")[:80],
                )
            except ValueError:
                continue
    selected: set[int] = {root_pid}
    changed = True
    while changed and len(selected) < limit:
        changed = False
        for pid, (parent, _name) in records.items():
            if parent in selected and pid not in selected:
                selected.add(pid)
                changed = True
                if len(selected) >= limit:
                    break
    return tuple(
        {
            "pid": pid,
            "ppid": records.get(pid, (0, "unknown"))[0],
            "name": records.get(pid, (0, "unknown"))[1],
        }
        for pid in sorted(selected)[:limit]
    )


def _run_bounded_python_gate(
    argv: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
) -> _BoundedProcessResult:
    """Run a Python gate in its own process group and kill the full group."""

    kwargs: dict[str, Any] = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **kwargs,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return _BoundedProcessResult(
            process.returncode,
            stdout,
            stderr,
            False,
            (),
            False,
        )
    except subprocess.TimeoutExpired:
        process_tree = _bounded_process_tree(process.pid)
        dump_requested = False
        try:
            if os.name == "nt" and hasattr(signal, "CTRL_BREAK_EVENT"):
                process.send_signal(signal.CTRL_BREAK_EVENT)
                dump_requested = True
            elif os.name != "nt":
                _signal_process_group(process.pid, signal.SIGABRT)
                dump_requested = True
            process.wait(timeout=1)
        except (OSError, subprocess.SubprocessError):
            pass
        if process.poll() is None:
            try:
                if os.name == "nt":
                    process.terminate()
                else:
                    _signal_process_group(process.pid, signal.SIGTERM)
                process.wait(timeout=3)
            except (OSError, subprocess.SubprocessError):
                pass
        if process.poll() is None:
            try:
                if os.name == "nt":
                    process.kill()
                else:
                    _signal_process_group(process.pid, _SIGKILL)
            except OSError:
                pass
        stdout, stderr = process.communicate()
        return _BoundedProcessResult(
            None,
            stdout,
            stderr,
            True,
            process_tree,
            dump_requested,
        )


def _gate_workspace_fingerprint(root: Path) -> str:
    records: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if _disposable_workspace_path(relative) or ".git" in relative.parts:
            continue
        if path.is_symlink():
            records.append((relative.as_posix(), f"SYMLINK:{path.resolve()}"))
        elif path.is_file():
            records.append((relative.as_posix(), digest_file(path)))
    return digest_text(json.dumps(records, separators=(",", ":")))


def _disposable_workspace_path(relative: Path) -> bool:
    return bool(
        any(part == "__pycache__" for part in relative.parts)
        or relative.suffix in {".pyc", ".pyo"}
        or relative.parts
        and relative.parts[0] in {".pytest_cache", ".ruff_cache", "build", "dist"}
        or any(part.endswith(".egg-info") for part in relative.parts)
    )


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
    repository = cwd.resolve(strict=True)
    git = ["git", "-c", f"safe.directory={repository.as_posix()}"]
    commands: list[list[str]] = [
        [
            *git,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--name-only",
            "-z",
            "--diff-filter=ACMR",
            "HEAD",
            "--",
        ],
        [*git, "ls-files", "-z", "--others", "--exclude-standard"],
    ]
    remote_head = subprocess.run(
        [*git, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"],
        cwd=repository,
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
                *git,
                "diff",
                "--no-ext-diff",
                "--no-textconv",
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
            cwd=repository,
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
    temporary_root: Path,
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
        with tempfile.TemporaryDirectory(
            prefix="hermes-osv-audit-",
            dir=temporary_root,
        ) as directory:
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
    temporary_root: Path,
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
        with tempfile.TemporaryDirectory(
            prefix="hermes-container-gate-",
            dir=temporary_root,
        ) as directory:
            temporary = Path(directory)
            verifier = _controller_image_security_verifier(temporary)
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


def _controller_image_security_verifier(temporary_root: Path) -> Path:
    """Materialize the digest-pinned controller verifier outside the product."""

    root = temporary_root.resolve(strict=True)
    source = Path(__file__).resolve().with_name(
        "controller_image_security_verify.py"
    )
    try:
        packaged_scripts = Path(__file__).resolve().parent
        resolved_source = source.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(
            "controller_container_scan_helper_invalid: packaged helper is missing"
        ) from error
    if (
        source.is_symlink()
        or resolved_source.parent != packaged_scripts
        or not resolved_source.is_file()
        or digest_file(resolved_source)
        != _CONTROLLER_IMAGE_SECURITY_VERIFIER_SHA256
    ):
        raise RuntimeError(
            "controller_container_scan_helper_invalid: packaged helper digest mismatch"
        )
    destination = root / (
        "image-security-verify-"
        f"{_CONTROLLER_IMAGE_SECURITY_VERIFIER_SHA256[:16]}.py"
    )
    if destination.exists() or destination.is_symlink():
        if (
            destination.is_symlink()
            or not destination.is_file()
            or digest_file(destination)
            != _CONTROLLER_IMAGE_SECURITY_VERIFIER_SHA256
        ):
            raise RuntimeError(
                "controller_container_scan_helper_invalid: temporary helper conflicts"
            )
        return destination
    try:
        destination.write_bytes(resolved_source.read_bytes())
        destination.chmod(0o500)
    except OSError as error:
        raise RuntimeError(
            "controller_container_scan_helper_invalid: helper copy failed"
        ) from error
    if digest_file(destination) != _CONTROLLER_IMAGE_SECURITY_VERIFIER_SHA256:
        raise RuntimeError(
            "controller_container_scan_helper_invalid: copied helper digest mismatch"
        )
    return destination


def run_gate(
    gate: dict[str, Any],
    cwd: Path,
    subject_sha: str,
    *,
    python_executable: str | None = None,
    temporary_root: Path | None = None,
) -> dict[str, Any]:
    workspace = cwd.resolve(strict=True)
    if temporary_root is not None:
        return _run_gate_with_controller_temp(
            gate,
            workspace,
            subject_sha,
            python_executable=python_executable,
            controller_temp_root=temporary_root,
        )
    with tempfile.TemporaryDirectory(
        prefix=".hermes-controller-tmp-",
        dir=workspace.parent,
    ) as directory:
        return _run_gate_with_controller_temp(
            gate,
            workspace,
            subject_sha,
            python_executable=python_executable,
            controller_temp_root=Path(directory),
        )


def _run_gate_with_controller_temp(
    gate: dict[str, Any],
    workspace: Path,
    subject_sha: str,
    *,
    python_executable: str | None,
    controller_temp_root: Path,
) -> dict[str, Any]:
    controller_temp_root = controller_temp_root.resolve()
    try:
        controller_temp_root.relative_to(workspace)
    except ValueError:
        pass
    else:
        raise ValueError("controller quality-gate temp root must be outside the workspace")
    controller_temp_root.mkdir(parents=True, exist_ok=True)
    adapter = gate.get("adapter")
    if adapter == _TARGET_SECRET_ADAPTER:
        return _changed_file_secret_scan(gate, workspace, subject_sha)
    if adapter == _TARGET_SAST_ADAPTER:
        return _changed_file_sast(gate, workspace, subject_sha, python_executable)
    if adapter == _TARGET_DEPENDENCY_ADAPTER:
        return _dependency_audit(
            gate,
            workspace,
            subject_sha,
            python_executable,
            controller_temp_root,
        )
    if adapter == _TARGET_LICENSE_ADAPTER:
        return _license_check(gate, workspace, subject_sha, python_executable)
    if adapter == _TARGET_CONTAINER_IMAGE_ADAPTER:
        return _container_image_scan(
            gate,
            workspace,
            subject_sha,
            python_executable,
            controller_temp_root,
        )
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
        completed: _BoundedProcessResult | subprocess.CompletedProcess[str] | None = (
            None
        )
        try:
            argv = shlex.split(command)
            if python_executable and argv and argv[0].lower() in {"python", "python3", "python.exe"}:
                argv[0] = python_executable
            with tempfile.TemporaryDirectory(
                prefix="hermes-gate-pycache-",
                dir=controller_temp_root,
            ) as pycache_directory:
                gate_environment = os.environ.copy()
                gate_environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
                gate_environment["PYTHONNOUSERSITE"] = "1"
                gate_environment["PYTHONHASHSEED"] = "0"
                gate_environment["PYTHONDONTWRITEBYTECODE"] = "1"
                gate_environment["PYTHONPYCACHEPREFIX"] = pycache_directory
                gate_environment["PYTHONFAULTHANDLER"] = "1"
                timeout = int(gate.get("timeout_seconds", 600))
                python_gate = bool(
                    argv
                    and (
                        Path(argv[0]).name.casefold()
                        in {"python", "python3", "python.exe"}
                        or python_executable is not None
                        and Path(argv[0]).resolve()
                        == Path(python_executable).resolve()
                    )
                )
                if python_gate:
                    before_fingerprint = _gate_workspace_fingerprint(workspace)
                    bounded = _run_bounded_python_gate(
                        argv,
                        cwd=workspace,
                        environment=gate_environment,
                        timeout=timeout,
                    )
                    retry_count = 0
                    if bounded.timed_out:
                        after_fingerprint = _gate_workspace_fingerprint(workspace)
                        if after_fingerprint == before_fingerprint:
                            retry_count = 1
                            bounded = _run_bounded_python_gate(
                                argv,
                                cwd=workspace,
                                environment=gate_environment,
                                timeout=timeout,
                            )
                    if bounded.timed_out:
                        diagnostic = json.dumps(
                            {
                                "reason_code": "python_gate_timeout",
                                "subject_sha": subject_sha,
                                "infrastructure_retries": retry_count,
                                "process_tree": list(bounded.process_tree),
                                "faulthandler_dump_requested": bounded.dump_requested,
                                "product_execution_slot_cost": 0,
                            },
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        output = (
                            diagnostic
                            + "\n"
                            + bounded.stdout
                            + "\n"
                            + bounded.stderr
                        ).strip()
                        exit_code = None
                        status = "ERROR"
                        completed = None
                    else:
                        output = (bounded.stdout + "\n" + bounded.stderr).strip()
                        exit_code = bounded.returncode
                        completed = bounded
                else:
                    regular = subprocess.run(
                        argv,
                        cwd=workspace,
                        env=gate_environment,
                        text=True,
                        capture_output=True,
                        timeout=timeout,
                        check=False,
                    )
                    output = (regular.stdout + "\n" + regular.stderr).strip()
                    exit_code = regular.returncode
                    completed = regular
            success_exit_codes = gate.get("success_exit_codes", [0])
            if not isinstance(success_exit_codes, list) or not all(
                isinstance(item, int) for item in success_exit_codes
            ):
                raise TypeError("success_exit_codes must be a list of integers")
            if completed is not None:
                status = "PASS" if exit_code in success_exit_codes else "FAIL"
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
