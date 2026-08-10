#!/usr/bin/env python3
"""Fail-closed path and liveness helpers for Q8 and official PRE-Q8."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol


class RuntimeControlError(RuntimeError):
    """Runtime inputs do not belong to the admitted qualification namespace."""


def stable_json(value: Any) -> str:
    """Encode guard results without importing the dependency-bearing factory package."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_config(path: Path) -> Any:
    """Load full config lazily; epoch switching itself remains stdlib-only."""

    from factory.config import load_config as factory_load_config

    return factory_load_config(path)


_EPOCH_SERVICE_PATTERNS = (
    "hermes-factory-candidate-*",
    "hermes-factory-canary-*",
    "hermes-factory-clean-canary@*",
    "hermes-factory-shadow-*",
    "hermes-factory-pre-q8.service",
    "hermes-factory-pre-q8-official.service",
    "hermes-factory-pre-q8@*.service",
    "hermes-factory-pre-q8-controller@*.service",
    "hermes-factory-pre-q8-worker@*.service",
    "hermes-factory-pre-q8-convergence@*.service",
    "hermes-factory-pre-q8-convergence-controller@*.service",
    "hermes-factory-pre-q8-convergence-worker@*.service",
    "hermes-factory-pre-q8-convergence-scenario@*.service",
    "hermes-factory-golden-*.service",
)
_EPOCH_JOB = re.compile(
    r"hermes-factory-(?:candidate|canary|clean-canary|shadow|pre-q8|golden-)"
)


class SystemctlRunner(Protocol):
    def __call__(
        self,
        command: list[str],
        *,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]: ...


def _run_systemctl(
    command: list[str],
    *,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def epoch_switch_guard(
    *,
    runner: SystemctlRunner = _run_systemctl,
) -> dict[str, Any]:
    """Stop every old-epoch unit and reject active units or queued restarts."""

    runner(
        ["systemctl", "stop", *_EPOCH_SERVICE_PATTERNS],
        timeout=60,
    )
    active = runner(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=active,activating,reloading,deactivating",
            "--no-legend",
            "--plain",
            *_EPOCH_SERVICE_PATTERNS,
        ],
        timeout=30,
    )
    if active.returncode != 0:
        raise RuntimeControlError("previous Candidate unit inventory failed")
    active_units = tuple(line.strip() for line in active.stdout.splitlines() if line.strip())
    if active_units:
        raise RuntimeControlError("previous Candidate units are still active")
    jobs = runner(
        ["systemctl", "list-jobs", "--no-legend", "--plain"],
        timeout=30,
    )
    if jobs.returncode not in {0, 1}:
        raise RuntimeControlError("previous Candidate restart-job inventory failed")
    restart_jobs = tuple(
        line.strip()
        for line in jobs.stdout.splitlines()
        if _EPOCH_JOB.search(line)
    )
    if restart_jobs:
        raise RuntimeControlError("previous Candidate restart jobs are still scheduled")
    return {"stopped_patterns": list(_EPOCH_SERVICE_PATTERNS), "active_units": []}


def release_epoch_from_governor(
    governor_database: Path, *, source_commit: str, candidate_digest: str
) -> str:
    """Read the one real release epoch from the checkpointed governor DB."""

    if (
        not governor_database.is_absolute()
        or not governor_database.is_file()
        or governor_database.is_symlink()
    ):
        raise RuntimeControlError("Candidate release governor database is unavailable")
    connection = sqlite3.connect(
        f"file:{governor_database.resolve().as_posix()}?mode=ro&immutable=1",
        uri=True,
        timeout=20,
    )
    try:
        connection.execute("PRAGMA query_only=ON")
        rows = connection.execute(
            "SELECT epoch_id FROM controller_release_epochs "
            "WHERE source_commit=? AND candidate_digest=?",
            (source_commit, candidate_digest),
        ).fetchall()
    finally:
        connection.close()
    if len(rows) != 1 or re.fullmatch(r"RE-[A-F0-9]{24}", str(rows[0][0])) is None:
        raise RuntimeControlError("exact Candidate release epoch is unavailable")
    return str(rows[0][0])


def build_identity(
    *,
    control_path: Path,
    candidate_config: Path,
    candidate_root: Path,
    systemd_root: Path,
    capability_attestation: Path,
) -> dict[str, str]:
    import yaml

    from factory.pre_q8_fixture import fixture_manifest
    from factory.pre_q8_seal import systemd_bundle_digest

    control = yaml.safe_load(control_path.read_text(encoding="utf-8"))
    base = yaml.safe_load(candidate_config.read_text(encoding="utf-8"))
    if not isinstance(control, Mapping) or not isinstance(base, Mapping):
        raise RuntimeControlError("PRE-Q8 identity config is invalid")
    git_tree_result = subprocess.run(
        ["git", "-C", str(candidate_root), "rev-parse", "HEAD^{tree}"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if git_tree_result.returncode != 0:
        raise RuntimeControlError("Candidate Git tree is unavailable")
    values = {
        "source_commit": str(control["source_commit"]),
        "stable_release_digest": str(control["stable_release_digest"]),
        "controller_release_digest": str(control["controller_release_digest"]),
        "candidate_digest": str(control["candidate_digest"]),
        "policy_digest": str(control["policy_digest"]),
        "toolchain_digest": str(control["toolchain_manifest_digest"]),
        "git_tree": git_tree_result.stdout.strip(),
        "release_tree_digest": str(control["candidate_digest"]),
        "requirements_lock_digest": sha256_file(candidate_root / "requirements.lock"),
        "systemd_bundle_digest": systemd_bundle_digest(systemd_root),
        "capability_attestation_path": str(capability_attestation),
        "capability_attestation_digest": sha256_file(capability_attestation),
        "fixture_seed_digest": str(fixture_manifest()["fixture_seed_digest"]),
    }
    values["epoch_id"] = release_epoch_from_governor(
        Path(str(control["governor_database"])),
        source_commit=values["source_commit"],
        candidate_digest=values["candidate_digest"],
    )
    values["identity_digest"] = sha256_text(stable_json(values))
    return values


def resolve_convergence_instance(instance: str) -> tuple[str, str, Path]:
    from factory.pre_q8_convergence import PreQ8ConvergenceError, validate_run_id

    if instance.count("--") != 1:
        raise RuntimeControlError("convergence unit instance is invalid")
    run_id, scenario_id = instance.split("--", 1)
    try:
        validate_run_id(run_id)
    except PreQ8ConvergenceError as error:
        raise RuntimeControlError("convergence run id is invalid") from error
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", scenario_id) is None:
        raise RuntimeControlError("convergence scenario id is invalid")
    config = Path("/etc/hermes-factory/pre-q8-convergence") / run_id / f"{scenario_id}.yaml"
    if not config.is_file() or config.is_symlink():
        raise RuntimeControlError("convergence scenario config is unavailable")
    return run_id, scenario_id, config


def exec_convergence_unit(role: str, instance: str) -> None:
    _run_id, _scenario_id, config = resolve_convergence_instance(instance)
    if role == "controller":
        command = [sys.executable, "-m", "factory.controller", "--config", str(config)]
    elif role == "worker":
        command = [
            sys.executable,
            "-m",
            "scripts.canary_candidate",
            "--config",
            str(config),
            "worker",
            "--worker-id",
            f"convergence-{instance}-worker-1",
        ]
    else:
        raise RuntimeControlError("convergence unit role is invalid")
    os.execv(sys.executable, command)


def config_identity(
    config_path: Path,
    *,
    expected_plane: str,
    expected_scenario: str,
    allowed_root: Path,
) -> dict[str, str]:
    from factory.canary_faults import CanaryFaultContract

    config = load_config(config_path)
    contract = CanaryFaultContract.from_config(config)
    database = config.database_path.resolve()
    root = allowed_root.resolve()
    exact_root = (
        root
        / contract.epoch_id
        / contract.run_id
        / contract.scenario_id
    ).resolve()
    if (
        contract.qualification_plane != expected_plane
        or contract.scenario_id != expected_scenario
        or database != exact_root / "controller.db"
        or exact_root == root
        or root not in exact_root.parents
    ):
        raise RuntimeControlError("qualification config path identity differs")
    return {
        "qualification_plane": contract.qualification_plane,
        "run_id": contract.run_id,
        "epoch_id": contract.epoch_id,
        "scenario_id": contract.scenario_id,
        "database_path": str(database),
        "state_root": str(exact_root),
    }


def _systemctl_show(unit: str) -> str:
    result = subprocess.run(
        [
            "systemctl",
            "show",
            unit,
            "--property=ActiveState,SubState,Result,NRestarts,MainPID,ExecMainCode,ExecMainStatus",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if result.returncode != 0:
        raise RuntimeControlError("systemd worker snapshot failed")
    return result.stdout


def _restart_pending(unit: str) -> bool:
    result = subprocess.run(
        ["systemctl", "list-jobs", "--no-legend", "--plain", unit],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if result.returncode not in {0, 1}:
        raise RuntimeControlError("systemd restart-job snapshot failed")
    return bool(result.stdout.strip())


def worker_observation(
    database: Path,
    *,
    unit: str,
    no_progress_window_elapsed: bool,
    intentional_restart_expected: bool,
    intentional_restart_receipt_verified: bool,
) -> dict[str, Any]:
    from factory.pre_q8_runtime import (
        PreQ8RuntimeError,
        assessment_json,
        classify_worker,
        parse_systemctl_show,
        progress_snapshot,
    )

    try:
        progress = progress_snapshot(database)
        unit_snapshot = parse_systemctl_show(_systemctl_show(unit))
        frontier = [
            status
            for status, count in dict(progress["task_statuses"]).items()
            if int(count) > 0
        ]
        assessment = classify_worker(
            unit_snapshot,
            restart_job_pending=_restart_pending(unit),
            active_lease=int(progress["active_lease_count"]) > 0,
            frontier_statuses=frontier,
            no_progress_window_elapsed=no_progress_window_elapsed,
            intentional_restart_expected=intentional_restart_expected,
            intentional_restart_receipt_verified=intentional_restart_receipt_verified,
        )
    except PreQ8RuntimeError as error:
        raise RuntimeControlError("PRE-Q8 worker state is invalid") from error
    return {
        "assessment": json.loads(assessment_json(assessment)),
        "unit": {
            "ActiveState": unit_snapshot.active_state,
            "SubState": unit_snapshot.sub_state,
            "Result": unit_snapshot.result,
            "NRestarts": unit_snapshot.n_restarts,
            "MainPID": unit_snapshot.main_pid,
            "ExecMainCode": unit_snapshot.exec_main_code,
            "ExecMainStatus": unit_snapshot.exec_main_status,
        },
        "progress": progress,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    identity = commands.add_parser("config-identity")
    identity.add_argument("--config", type=Path, required=True)
    identity.add_argument("--expected-plane", choices=("CONVERGENCE", "PRE_Q8", "Q8"), required=True)
    identity.add_argument("--expected-scenario", required=True)
    identity.add_argument("--allowed-root", type=Path, required=True)
    build = commands.add_parser("build-identity")
    build.add_argument("--control", type=Path, required=True)
    build.add_argument("--candidate-config", type=Path, required=True)
    build.add_argument("--candidate-root", type=Path, required=True)
    build.add_argument("--systemd-root", type=Path, required=True)
    build.add_argument("--capability-attestation", type=Path, required=True)
    unit = commands.add_parser("unit-exec")
    unit.add_argument("role", choices=("controller", "worker"))
    unit.add_argument("instance")
    worker = commands.add_parser("worker-observation")
    worker.add_argument("--database", type=Path, required=True)
    worker.add_argument("--unit", required=True)
    worker.add_argument("--no-progress-window-elapsed", action="store_true")
    worker.add_argument("--intentional-restart-expected", action="store_true")
    worker.add_argument("--intentional-restart-receipt-verified", action="store_true")
    worker.add_argument("--output", type=Path)
    worker.add_argument("--progress-output", type=Path)
    commands.add_parser("epoch-switch-guard")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "config-identity":
            result = config_identity(
                args.config,
                expected_plane=args.expected_plane,
                expected_scenario=args.expected_scenario,
                allowed_root=args.allowed_root,
            )
        elif args.command == "build-identity":
            result = build_identity(
                control_path=args.control,
                candidate_config=args.candidate_config,
                candidate_root=args.candidate_root,
                systemd_root=args.systemd_root,
                capability_attestation=args.capability_attestation,
            )
        elif args.command == "unit-exec":
            exec_convergence_unit(args.role, args.instance)
            raise RuntimeControlError("convergence unit exec returned")
        elif args.command == "worker-observation":
            result = worker_observation(
                args.database,
                unit=args.unit,
                no_progress_window_elapsed=args.no_progress_window_elapsed,
                intentional_restart_expected=args.intentional_restart_expected,
                intentional_restart_receipt_verified=args.intentional_restart_receipt_verified,
            )
            encoded = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            if args.output is not None:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                if args.output.is_symlink():
                    raise RuntimeControlError("runtime observation path is unsafe")
                args.output.write_text(encoded, encoding="utf-8", newline="\n")
            if args.progress_output is not None:
                args.progress_output.parent.mkdir(parents=True, exist_ok=True)
                if args.progress_output.is_symlink():
                    raise RuntimeControlError("runtime progress path is unsafe")
                args.progress_output.write_text(
                    json.dumps(
                        result["progress"],
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
        else:
            result = epoch_switch_guard()
    except (OSError, RuntimeControlError, ValueError) as error:
        print(stable_json({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    print(stable_json({"status": "PASS", **result}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
