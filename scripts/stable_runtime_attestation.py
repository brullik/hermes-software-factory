#!/usr/bin/env python3
"""Produce a sanitized read-only attestation of permanent Stable controller truth."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from factory.common import sha256_text, stable_json, utc_now


class StableAttestationError(RuntimeError):
    """Stable internal truth is incomplete or unsafe."""


_WORKER_UNITS = (
    "hermes-factory-worker.service",
    "hermes-factory-worker-2.service",
)
_STABLE_RUNTIME_UNITS = (
    "hermes-factory-controller.service",
    "hermes-factory-gateway.service",
    *_WORKER_UNITS,
)
_SANDBOX_ENVIRONMENT = {
    "TERMINAL_ENV=docker",
    "HERMES_DOCKER_BINARY=/usr/bin/podman",
    "TERMINAL_DOCKER_FORWARD_ENV=[]",
    "TERMINAL_DOCKER_MOUNT_CWD_TO_WORKSPACE=true",
    "TERMINAL_DOCKER_PERSIST_ACROSS_PROCESSES=false",
    "TERMINAL_DOCKER_RUN_AS_HOST_USER=true",
}


def _worker_sandbox_violations() -> int:
    violations = 0
    for unit in _WORKER_UNITS:
        result = subprocess.run(
            [
                "systemctl",
                "show",
                unit,
                "--property=ActiveState,Environment,NoNewPrivileges,ProtectHome,ProtectSystem",
            ],
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        try:
            environment = set(shlex.split(properties.get("Environment", "")))
        except ValueError:
            environment = set()
        if (
            result.returncode != 0
            or properties.get("ActiveState") != "active"
            or properties.get("NoNewPrivileges") != "yes"
            or properties.get("ProtectHome") != "yes"
            or properties.get("ProtectSystem") != "strict"
            or not _SANDBOX_ENVIRONMENT <= environment
        ):
            violations += 1
    return violations


def _codex_runtime_dependency_violations() -> int:
    violations = 0
    for unit in _STABLE_RUNTIME_UNITS:
        result = subprocess.run(
            [
                "systemctl",
                "show",
                unit,
                "--property=ActiveState,WorkingDirectory,Environment,ExecStart",
            ],
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        joined = "\n".join(properties.values())
        if (
            result.returncode != 0
            or properties.get("ActiveState") != "active"
            or properties.get("WorkingDirectory") != "/opt/hermes-factory/current"
            or "/opt/hermes-codex-runtime" in joined
        ):
            violations += 1
    return violations


def _control(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise StableAttestationError("qualification control is unavailable")
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not re.fullmatch(
        r"[a-f0-9]{64}", str(value.get("candidate_digest") or "")
    ):
        raise StableAttestationError("qualification control identity is invalid")
    return {str(key): item for key, item in value.items()}


def _write_once(path: Path, value: dict[str, Any]) -> None:
    encoded = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_text(encoding="utf-8") != encoded:
            raise StableAttestationError("immutable Stable attestation conflicts")
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())


def _uncertain_notifications(root: Path) -> int:
    receipts = root / "notifications" / "receipts"
    if not receipts.exists():
        return 0
    if receipts.is_symlink() or not receipts.is_dir():
        raise StableAttestationError("notification receipt root is unsafe")
    uncertain = 0
    for path in receipts.glob("*.json"):
        if path.is_symlink() or not path.is_file():
            raise StableAttestationError("notification receipt is unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise StableAttestationError("notification receipt is invalid")
        if value.get("status") == "DELIVERY_UNCERTAIN":
            uncertain += 1
    return uncertain


def run(args: argparse.Namespace) -> dict[str, Any]:
    control = _control(args.control)
    output = args.output or (
        args.functional_root / "ready" / f"stable-runtime-{control['candidate_digest']!s}.json"
    )
    database = args.database.resolve()
    if not database.is_file() or database.is_symlink():
        raise StableAttestationError("Stable database is unavailable")
    connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True, timeout=30)
    try:
        connection.execute("PRAGMA query_only=ON")
        quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        required = {
            "products",
            "controller_incidents",
            "side_effect_intents",
            "side_effect_receipts",
            "completion_manifests",
            "outbox",
        }
        if quick_check != "ok" or not required <= tables:
            raise StableAttestationError("Stable database integrity is incomplete")
        open_incidents = int(
            connection.execute(
                "SELECT COUNT(*) FROM controller_incidents WHERE status!='RESOLVED'"
            ).fetchone()[0]
        )
        duplicate_intents = int(
            connection.execute(
                "SELECT COUNT(*) FROM (SELECT idempotency_key FROM side_effect_intents "
                "GROUP BY idempotency_key HAVING COUNT(*)>1)"
            ).fetchone()[0]
        )
        unverified_effects = int(
            connection.execute(
                """SELECT COUNT(*) FROM side_effect_intents AS intent
                     LEFT JOIN side_effect_receipts AS receipt USING(intent_id)
                    WHERE (intent.status='VERIFIED' AND receipt.intent_id IS NULL)
                       OR (intent.status!='VERIFIED' AND receipt.intent_id IS NOT NULL)"""
            ).fetchone()[0]
        )
        completed_without_manifest = int(
            connection.execute(
                """SELECT COUNT(*) FROM products AS product
                     LEFT JOIN completion_manifests AS manifest USING(product_id)
                    WHERE product.status='COMPLETED' AND manifest.product_id IS NULL"""
            ).fetchone()[0]
        )
        manifest_without_completed = int(
            connection.execute(
                """SELECT COUNT(*) FROM completion_manifests AS manifest
                     JOIN products AS product USING(product_id)
                    WHERE product.status!='COMPLETED'"""
            ).fetchone()[0]
        )
        open_owner_outbox = connection.execute(
            """SELECT payload_json FROM outbox
                WHERE event_type='telegram.owner_notification'
                  AND status!='DONE'"""
        ).fetchall()
        invalid_open_owner_notifications = 0
        for row in open_owner_outbox:
            try:
                value = json.loads(str(row[0]))
            except json.JSONDecodeError:
                invalid_open_owner_notifications += 1
                continue
            if not isinstance(value, dict) or value.get("kind") not in {
                "owner_action",
                "product_completed",
            }:
                invalid_open_owner_notifications += 1
    finally:
        connection.close()
    uncertain_notifications = _uncertain_notifications(args.functional_root)
    unsandboxed_provider_workers = _worker_sandbox_violations()
    routine_codex_runtime_dependencies = _codex_runtime_dependency_violations()
    metrics = {
        "database_quick_check": quick_check,
        "open_controller_incidents": open_incidents,
        "duplicate_side_effects": duplicate_intents,
        "unverified_side_effects": unverified_effects,
        "completed_without_manifest": completed_without_manifest,
        "manifest_without_completed_product": manifest_without_completed,
        "uncertain_owner_notifications": uncertain_notifications,
        "unsandboxed_provider_workers": unsandboxed_provider_workers,
        "routine_codex_runtime_dependencies": routine_codex_runtime_dependencies,
        "pending_owner_notifications": len(open_owner_outbox),
        "invalid_open_owner_notifications": invalid_open_owner_notifications,
    }
    if any(value != 0 for key, value in metrics.items() if key != "database_quick_check"):
        raise StableAttestationError("Stable internal and external state differs")
    payload = {
        "schema_version": "1.0",
        "proof_type": "STABLE_RUNTIME_INTERNAL_STATE",
        "status": "PASS",
        "candidate_digest": str(control["candidate_digest"]),
        "metrics": metrics,
        "observed_at": utc_now(),
    }
    digest = sha256_text(stable_json(payload))
    envelope = {**payload, "proof_digest": digest}
    _write_once(output, envelope)
    return {"status": "PASS", "proof_digest": digest}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--control",
        type=Path,
        default=Path("/etc/hermes-factory/qualification-control.yaml"),
    )
    parser.add_argument(
        "--database", type=Path, default=Path("/var/lib/hermes-factory/controller.db")
    )
    parser.add_argument(
        "--functional-root",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        result = run(_parser().parse_args(argv))
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
        sqlite3.Error,
        StableAttestationError,
    ) as error:
        print(stable_json({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    print(stable_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
