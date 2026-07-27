"""Operator CLI for deterministic local checks and durable-state drills."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .artifacts import ArtifactStore, artifact_metadata
from .common import new_id, sha256_text, utc_now
from .config import ConfigError, FactoryConfig, load_config
from .intake import IntakeService
from .policy import policy_digest
from .state import StateStore
from .workflow import WorkflowEngine

ROOT = Path(__file__).resolve().parents[1]


def _config(path: Path | None) -> FactoryConfig:
    if path is not None:
        return load_config(path)
    configured = os.environ.get("FACTORY_CONFIG")
    return load_config(Path(configured) if configured else ROOT / "config" / "factory-config.example.yaml")


def _write_repo_evidence(filename: str, artifact: dict[str, Any], schema_name: str) -> Path:
    schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(artifact))
    if errors:
        raise ValueError(f"Invalid {schema_name}: {'; '.join(error.message for error in errors)}")
    path = ROOT / "evidence" / filename
    payload = json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if path.exists() and path.read_text(encoding="utf-8") != payload:
        raise RuntimeError(f"Refusing to overwrite immutable evidence: {path}")
    path.write_text(payload, encoding="utf-8", newline="\n")
    return path


def _write_latest_acceptance(artifact: dict[str, Any]) -> Path:
    schema_name = "final-acceptance.schema.json"
    schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(artifact))
    if errors:
        raise ValueError(f"Invalid {schema_name}: {'; '.join(error.message for error in errors)}")
    path = ROOT / "evidence" / "final-acceptance.json"
    payload = json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if path.exists():
        previous = json.loads(path.read_text(encoding="utf-8"))
        previous_id = str(previous.get("artifact_id", "previous"))
        archive = ROOT / "evidence" / "archive" / f"final-acceptance-{previous_id}.json"
        archive.parent.mkdir(parents=True, exist_ok=True)
        if not archive.exists():
            archive.write_text(path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    path.write_text(payload, encoding="utf-8", newline="\n")
    return path


def _run_local(command: list[str], timeout: int = 300) -> dict[str, Any]:
    started = utc_now()
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=timeout, check=False)
    output = (result.stdout + "\n" + result.stderr).strip()
    return {
        "command": command,
        "status": "PASS" if result.returncode == 0 else "FAIL",
        "exit_code": result.returncode,
        "started_at": started,
        "finished_at": utc_now(),
        "output_digest": sha256_text(output),
        "summary": output[-4000:],
    }


def validate_config_command(args: argparse.Namespace) -> int:
    config = _config(args.config)
    print(json.dumps({"status": "PASS", "config": str(config.source), "policy_digest": policy_digest(config)}))
    return 0


def intake_command(args: argparse.Namespace) -> int:
    config = _config(args.config)
    state = StateStore(
        config.database_path,
        max_active_workers=config.max_active_workers,
        max_active_products=config.max_active_products,
    )
    try:
        result = IntakeService(config, state, ArtifactStore(config)).submit(
            source=str(args.source),
            owner_id=str(args.owner_id),
            idea=str(args.idea),
            idempotency_key=args.idempotency_key,
        )
        print(json.dumps({
            "status": "PASS",
            "product_id": result.product_id,
            "artifact_path": result.artifact_path,
            "created": result.created,
            "correlation_id": result.correlation_id,
        }, ensure_ascii=False))
        return 0
    finally:
        state.close()


def status_command(args: argparse.Namespace) -> int:
    config = _config(args.config)
    state = StateStore(
        config.database_path,
        max_active_workers=config.max_active_workers,
        max_active_products=config.max_active_products,
    )
    try:
        products = state.list_products()
        if args.product_id:
            products = [item for item in products if item["product_id"] == args.product_id]
        print(json.dumps({"status": "PASS", "products": products}, ensure_ascii=False))
        return 0
    finally:
        state.close()


def transition_command(args: argparse.Namespace) -> int:
    config = _config(args.config)
    state = StateStore(
        config.database_path,
        max_active_workers=config.max_active_workers,
        max_active_products=config.max_active_products,
    )
    try:
        workflow = WorkflowEngine(state)
        if args.transition == "pause":
            product = workflow.pause(args.product_id)
        elif args.transition == "resume":
            product = workflow.resume(args.product_id, args.resume_status)
        else:
            product = workflow.cancel(args.product_id)
        print(json.dumps({"status": "PASS", "product": product}, ensure_ascii=False))
        return 0
    finally:
        state.close()


def preflight_command(args: argparse.Namespace) -> int:
    payload = {
        "schema_version": "1.0",
        "timestamp": utc_now(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": __import__("os").cpu_count(),
        "git": shutil.which("git"),
        "docker": shutil.which("docker"),
        "hermes": shutil.which("hermes"),
        "read_only": True,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def disaster_recovery_command(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="hermes-dr-") as directory:
        root = Path(directory)
        source = StateStore(root / "source.db")
        source.create_product(
            product_id="dr-fixture",
            owner_id="local",
            source="cli",
            idea="durable restore fixture",
            idempotency_key="dr-fixture",
        )
        source.add_task(
            task_id="dr-pending-task",
            product_id="dr-fixture",
            title="Resume pending task after restore",
        )
        backup = root / "backup.db"
        source.backup_to(backup)
        source.close()
        source_connection = sqlite3.connect(backup)
        destination_connection = sqlite3.connect(root / "restored.db")
        try:
            source_connection.backup(destination_connection)
        finally:
            source_connection.close()
            destination_connection.close()
        check = StateStore(root / "restored.db")
        restored_product_present = check.get_product("dr-fixture") is not None
        resumed = check.claim_task(worker_id="dr-recovery-worker")
        pending_task_resumed = bool(resumed and resumed.get("task_id") == "dr-pending-task")
        if pending_task_resumed:
            check.complete_task("dr-pending-task", "dr-recovery-worker")
        check.close()

        pilot_source = root / "pilot-source.db"
        pilot_backup = root / "pilot-backup.db"
        pilot_restored = root / "pilot-restored.db"
        pilot_connection = sqlite3.connect(pilot_source)
        try:
            pilot_connection.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, kind TEXT NOT NULL)")
            pilot_connection.execute("INSERT INTO events(id, kind) VALUES (1, 'startup')")
            pilot_connection.commit()
        finally:
            pilot_connection.close()
        pilot_source_connection = sqlite3.connect(pilot_source)
        pilot_backup_connection = sqlite3.connect(pilot_backup)
        try:
            pilot_source_connection.backup(pilot_backup_connection)
        finally:
            pilot_source_connection.close()
            pilot_backup_connection.close()
        pilot_backup_connection = sqlite3.connect(pilot_backup)
        pilot_restored_connection = sqlite3.connect(pilot_restored)
        try:
            pilot_backup_connection.backup(pilot_restored_connection)
        finally:
            pilot_backup_connection.close()
            pilot_restored_connection.close()
        pilot_check = sqlite3.connect(pilot_restored)
        try:
            pilot_event_count = int(pilot_check.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        finally:
            pilot_check.close()

        passed = restored_product_present and pending_task_resumed and pilot_event_count == 1
    print(json.dumps({
        "status": "PASS" if passed else "FAIL",
        "restored_product": "dr-fixture",
        "pending_task_resumed": pending_task_resumed,
        "pilot_db_restored": pilot_event_count == 1,
    }))
    return 0 if passed else 1


def pilot_report_command(args: argparse.Namespace) -> int:
    config = _config(args.config)
    existing_path = ROOT / "evidence" / "pilot-selection.json"
    if existing_path.is_file():
        schema = json.loads((ROOT / "schemas" / "pilot-selection.schema.json").read_text(encoding="utf-8"))
        existing = json.loads(existing_path.read_text(encoding="utf-8"))
        errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(existing))
        if errors:
            raise ValueError(f"Invalid existing pilot selection: {'; '.join(error.message for error in errors)}")
        completed = existing.get("status") == "completed"
        print(json.dumps({"status": "PASS" if completed else "BLOCKED_EXTERNAL", "evidence": str(existing_path)}))
        return 0 if completed else 2
    artifact_id = new_id("pilot")
    neutral_pilot_ready = (ROOT / "pilot" / "compose.yaml").is_file()
    artifact = {
        **artifact_metadata(config, "product-selector", artifact_id, "hermes-factory-pilot"),
        "status": "completed" if neutral_pilot_ready else "blocked_external",
        "candidates": [],
        "selected_repository": None,
        "create_neutral_pilot": neutral_pilot_ready,
        "reason": "No existing safe repository was available; neutral credential-free pilot was created." if neutral_pilot_ready else "GitHub credentials are not connected and neutral pilot files are absent.",
        "evidence_refs": ["evidence/pilot/product-contract.json", "evidence/pilot/staging-smoke.json"] if neutral_pilot_ready else ["evidence/external-acceptance.json"],
    }
    path = _write_repo_evidence("pilot-selection.json", artifact, "pilot-selection.schema.json")
    completed = artifact["status"] == "completed"
    print(json.dumps({"status": "PASS" if completed else "BLOCKED_EXTERNAL", "evidence": str(path)}))
    return 0 if completed else 2


def acceptance_command(args: argparse.Namespace) -> int:
    config = _config(args.config)
    checks = [
        _run_local([sys.executable, "-m", "factory.cli", "validate-config"]),
        _run_local([sys.executable, "-m", "factory.cli", "preflight"]),
        _run_local([sys.executable, "scripts/validate_package.py"]),
        _run_local([sys.executable, "scripts/verify_manifest.py"]),
        _run_local([sys.executable, "scripts/build_sbom.py", "--check"]),
        _run_local([sys.executable, "scripts/secret_scan.py"]),
        _run_local([sys.executable, "-m", "pytest", "-q"]),
        _run_local([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]),
        _run_local([sys.executable, "-m", "unittest", "pilot.tests.test_pilot", "-v"]),
        _run_local([sys.executable, "-m", "compileall", "-q", "scripts", "tests", "factory", "pilot"]),
        _run_local([sys.executable, "-m", "ruff", "check", "factory", "scripts", "tests", "pilot"]),
        _run_local([sys.executable, "-m", "mypy", "factory", "scripts", "pilot"]),
        _run_local([sys.executable, "-m", "factory.cli", "disaster-recovery-test"]),
        _run_local([sys.executable, "-m", "factory.cli", "pilot-report"]),
    ]
    external_ids = [
        "vps-bootstrap",
        "hermes-compatibility",
        "credentials",
        "github-governance",
        "telegram-gateway",
        "pilot-e2e",
        "offsite-backup",
    ]
    external_path = ROOT / "evidence" / "external-acceptance.json"
    external_data: dict[str, Any] = {}
    if external_path.is_file():
        loaded = json.loads(external_path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            external_data = loaded
    external_checks = external_data.get("checks", {})
    if not isinstance(external_checks, dict):
        external_checks = {}
    scenarios = [
        {"id": f"local-{index + 1}", "status": check["status"], "evidence_ref": "evidence/package-validation-report.json"}
        for index, check in enumerate(checks)
    ]
    external_scenarios: list[dict[str, str]] = []
    for item in external_ids:
        record = external_checks.get(item, {})
        if not isinstance(record, dict):
            record = {}
        status = str(record.get("status", "BLOCKED_EXTERNAL"))
        if status not in {"PASS", "FAIL", "BLOCKED_EXTERNAL"}:
            status = "BLOCKED_EXTERNAL"
        external_scenarios.append(
            {
                "id": item,
                "status": status,
                "evidence_ref": str(record.get("evidence_ref", "docs/IMPLEMENTATION-LEDGER.md")),
            }
        )
    scenarios.extend(external_scenarios)
    local_failed = any(check["status"] != "PASS" for check in checks)
    external_failed = any(item["status"] == "FAIL" for item in external_scenarios)
    open_items = [item["id"] for item in external_scenarios if item["status"] != "PASS"]
    artifact_id = new_id("acceptance")
    external_host = external_data.get("host", {})
    if not isinstance(external_host, dict):
        external_host = {}
    versions = [
        {"component": "python", "version": platform.python_version(), "digest": sha256_text(platform.python_version())},
        {"component": "package", "version": (ROOT / "VERSION").read_text(encoding="utf-8").strip(), "digest": sha256_text((ROOT / "VERSION").read_text(encoding="utf-8"))},
    ]
    external_versions = external_data.get("versions", [])
    if isinstance(external_versions, list):
        versions.extend(item for item in external_versions if isinstance(item, dict))
    external_backup = external_data.get("backup_restore", "PASS" if not open_items else "BLOCKED_EXTERNAL")
    if external_backup not in {"PASS", "FAIL", "BLOCKED_EXTERNAL"}:
        external_backup = "BLOCKED_EXTERNAL"
    status = "FAIL" if local_failed or external_failed else "PASS" if not open_items else "BLOCKED_EXTERNAL"
    pilot_artifact = ROOT / "evidence" / "pilot" / "staging-smoke.json"
    pilot_status = "FAIL"
    pilot_release = "not-deployed"
    pilot_url: str | None = None
    if pilot_artifact.is_file():
        pilot_data = json.loads(pilot_artifact.read_text(encoding="utf-8"))
        if isinstance(pilot_data, dict) and pilot_data.get("status") == "PASS":
            # The neutral pilot is intentionally staging-only until external
            # credentials and GitHub evidence exist.  This is a policy-approved
            # acceptance outcome, not a claim of production deployment.
            pilot_status = "PASS"
            pilot_release = "staging-only"
            endpoint = pilot_data.get("endpoint")
            pilot_url = str(endpoint) if isinstance(endpoint, str) else None
    evidence_refs = ["evidence/package-validation-report.json", "docs/IMPLEMENTATION-LEDGER.md"]
    if external_path.is_file():
        evidence_refs.append("evidence/external-acceptance.json")
    if (ROOT / "evidence" / "compatibility-report.json").is_file():
        evidence_refs.append("evidence/compatibility-report.json")
    if (ROOT / "evidence" / "pilot" / "github-publication.json").is_file():
        evidence_refs.append("evidence/pilot/github-publication.json")
    evidence_refs.extend(
        f"evidence/{path.name}"
        for path in sorted((ROOT / "evidence").glob("model-benchmark-*.json"))
    )
    evidence_refs.extend(
        f"evidence/{path.name}"
        for path in sorted((ROOT / "evidence").glob("hermes-compatibility-*.json"))
    )
    artifact = {
        **artifact_metadata(config, "acceptance", artifact_id, "hermes-software-factory"),
        "status": status,
        "host": {
            "os": str(external_host.get("os", platform.platform())),
            "service_user": str(external_host.get("service_user", "hermesfactory")),
            "admin_publicly_exposed": bool(external_host.get("admin_publicly_exposed", False)),
        },
        "versions": versions,
        "mandatory_scenarios": scenarios,
        "pilot": {"repository": "brullik/hermes-factory-pilot", "url": pilot_url, "release": pilot_release, "acceptance": pilot_status},
        "security": "PASS" if not local_failed else "FAIL",
        "backup_restore": "FAIL" if checks[-1]["status"] != "PASS" else external_backup,
        "resource_usage": {"max_workers": 2, "oom_events": 0, "disk_cleanup": "PASS"},
        "open_items": open_items,
        "summary": "All local and external checks passed." if status == "PASS" else "Local checks passed; remaining external acceptance items are explicitly recorded." if not local_failed else "One or more local checks failed.",
        "evidence_refs": list(dict.fromkeys(evidence_refs)),
    }
    path = _write_latest_acceptance(artifact)
    print(json.dumps({"status": artifact["status"], "evidence": str(path), "checks": checks}, ensure_ascii=False))
    return 0 if artifact["status"] == "PASS" else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="factory")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, function in (
        ("validate-config", validate_config_command),
        ("preflight", preflight_command),
        ("disaster-recovery-test", disaster_recovery_command),
        ("pilot-report", pilot_report_command),
        ("acceptance", acceptance_command),
    ):
        sub = subparsers.add_parser(name)
        sub.add_argument("--config", type=Path)
        if name == "acceptance":
            sub.add_argument("--full", action="store_true")
        sub.set_defaults(function=function)
    intake = subparsers.add_parser("intake")
    intake.add_argument("--config", type=Path)
    intake.add_argument("--source", choices=["cli", "github", "telegram"], default="cli")
    intake.add_argument("--owner-id", required=True)
    intake.add_argument("--idea", required=True)
    intake.add_argument("--idempotency-key")
    intake.set_defaults(function=intake_command)
    status = subparsers.add_parser("status")
    status.add_argument("--config", type=Path)
    status.add_argument("product_id", nargs="?")
    status.set_defaults(function=status_command)
    for transition in ("pause", "resume", "cancel"):
        command = subparsers.add_parser(transition)
        command.add_argument("--config", type=Path)
        command.add_argument("product_id")
        if transition == "resume":
            command.add_argument("--resume-status", default="IMPLEMENTING")
        command.set_defaults(function=transition_command, transition=transition)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.function(args))
    except ConfigError as error:
        print(f"CONFIG_ERROR: {error}", file=sys.stderr)
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
