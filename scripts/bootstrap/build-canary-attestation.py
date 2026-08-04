#!/usr/bin/env python3
"""Create exact isolated capability attestations without credential values."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

_SHA40 = re.compile(r"^[a-f0-9]{40}$")


def _run_as_user(
    service_user: str,
    state_dir: Path,
    runtime_dir: Path,
    argv: list[str],
) -> str:
    scoped_argv = list(argv)
    if scoped_argv and scoped_argv[0] == "podman":
        scoped_argv[1:1] = ["--cgroup-manager=cgroupfs"]
    result = subprocess.run(
        [
            "runuser",
            "-u",
            service_user,
            "--",
            "env",
            f"HOME={state_dir}",
            f"XDG_RUNTIME_DIR={runtime_dir}",
            *scoped_argv,
        ],
        text=True,
        capture_output=True,
        check=False,
        cwd=state_dir,
        timeout=60,
    )
    if result.returncode != 0:
        raise ValueError("isolated Q6 Podman attestation probe failed")
    return result.stdout.strip()


def build_q6_payload(
    *,
    service_user: str,
    state_dir: Path,
    runtime_dir: Path,
    source_commit: str,
    command_runner: Callable[[str, Path, Path, list[str]], str] = _run_as_user,
    expected_uid: int | None = None,
) -> dict[str, Any]:
    if (
        not re.fullmatch(r"[a-z_][a-z0-9_-]*", service_user)
        or not state_dir.is_absolute()
        or not runtime_dir.is_absolute()
        or _SHA40.fullmatch(source_commit) is None
    ):
        raise ValueError("isolated Q6 Podman attestation scope is invalid")
    runroot = command_runner(
        service_user,
        state_dir,
        runtime_dir,
        ["podman", "info", "--format", "{{.Store.RunRoot}}"],
    ).splitlines()[-1]
    expected_runroot = str(runtime_dir / "containers")
    if os.path.normpath(runroot) != os.path.normpath(expected_runroot):
        raise ValueError("isolated Q6 Podman RunRoot differs")
    ipam_database = Path(expected_runroot) / "networks" / "ipam.db"
    metadata = ipam_database.stat()
    if expected_uid is None:
        uid_result = subprocess.run(
            ["id", "-u", service_user],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        if uid_result.returncode != 0:
            raise ValueError("isolated Q6 Podman subject is unavailable")
        expected_uid = int(uid_result.stdout.strip())
    if (
        not ipam_database.is_file()
        or ipam_database.is_symlink()
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError("isolated Q6 Podman IPAM proof is invalid")
    network_name = f"hermes-q6-attestation-{os.getpid()}"
    created = False
    try:
        command_runner(
            service_user,
            state_dir,
            runtime_dir,
            ["podman", "network", "create", network_name],
        )
        created = True
    finally:
        if created:
            command_runner(
                service_user,
                state_dir,
                runtime_dir,
                ["podman", "network", "rm", network_name],
            )
    version = command_runner(
        service_user,
        state_dir,
        runtime_dir,
        ["podman", "--version"],
    )
    if not version.startswith("podman version "):
        raise ValueError("isolated Q6 Podman version is invalid")
    capability = "toolchain.container_builder"
    return {
        "schema_version": "1.0",
        "plane": "ISOLATED_Q6",
        "capabilities": {
            capability: {
                "status": "AVAILABLE",
                "scope": {
                    "allowed_operations": [capability],
                    "runtime": "podman",
                    "runroot": expected_runroot,
                    "network_preflight": "passed",
                    "exact_version": version,
                    "subject_user": service_user,
                    "source_commit": source_commit,
                },
            }
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--plane",
        choices=("CLEAN_CANARY", "ISOLATED_Q6"),
        default="CLEAN_CANARY",
    )
    parser.add_argument("--service-user", default="")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--runtime-dir", type=Path)
    parser.add_argument("--source-commit", default="")
    args = parser.parse_args()
    if not args.output.is_absolute():
        raise ValueError("isolated capability attestation path must be absolute")
    if args.plane == "ISOLATED_Q6":
        effective_uid = getattr(os, "geteuid", lambda: -1)()
        if os.name == "nt" or effective_uid != 0:
            raise ValueError("isolated Q6 attestation must run as root on POSIX")
        if args.state_dir is None or args.runtime_dir is None:
            raise ValueError("isolated Q6 Podman paths are required")
        payload = build_q6_payload(
            service_user=args.service_user,
            state_dir=args.state_dir,
            runtime_dir=args.runtime_dir,
            source_commit=args.source_commit,
        )
    else:
        payload = {
            "schema_version": "1.0",
            "plane": "CLEAN_CANARY",
            # Empty is deliberate: GitHub/provider access must pass the live
            # Candidate B probes and cannot be asserted by this file.
            "capabilities": {},
        }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    if args.output.exists():
        if args.output.is_symlink() or args.output.read_text(encoding="utf-8") != encoded:
            raise ValueError("isolated capability attestation conflicts")
        return 0
    args.output.write_text(encoded, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
