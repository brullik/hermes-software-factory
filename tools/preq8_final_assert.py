#!/usr/bin/env python3
"""Independently assert exact Q6.5 18/18 and official PRE-Q8 10/10."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from factory.functional_readiness import MANDATORY_Q6_5_OPERATIONS, PRE_Q8_SCENARIOS

_SHA40 = re.compile(r"^[a-f0-9]{40}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SEAL_IDENTITY = (
    "git_tree",
    "release_tree_digest",
    "requirements_lock_digest",
    "toolchain_digest",
    "systemd_bundle_digest",
    "catalog_digest",
    "base_config_digest",
    "capability_attestation_digest",
    "fixture_seed_digest",
    "matrix_digest",
)


def _stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _mapping(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} is unavailable or unsafe")
    value = (
        yaml.safe_load(path.read_text(encoding="utf-8"))
        if path.suffix in {".yaml", ".yml"}
        else json.loads(path.read_text(encoding="utf-8"))
    )
    if not isinstance(value, dict):
        raise TypeError(f"{label} is not an object")
    return {str(key): item for key, item in value.items()}


def _verify_seal(
    seal: dict[str, Any],
    *,
    control: dict[str, Any],
    index: dict[str, Any],
) -> str:
    if (
        seal.get("schema_version") != "1.0"
        or seal.get("seal_type") != "PREQ8_CONVERGENCE_SEAL"
        or seal.get("status") != "10/10 PASS"
        or tuple(str(item) for item in seal.get("ordered_scenarios", ()))
        != PRE_Q8_SCENARIOS
    ):
        raise ValueError("convergence seal contract differs")
    unsigned = {
        key: value
        for key, value in seal.items()
        if key not in {"seal_digest", "verifier_signature", "signed_at"}
    }
    seal_digest = hashlib.sha256(_stable_json(unsigned).encode("utf-8")).hexdigest()
    if seal.get("seal_digest") != seal_digest:
        raise ValueError("convergence seal digest differs")
    public = base64.b64decode(str(control["verifier_public_key"]), validate=True)
    signature = base64.b64decode(str(seal["verifier_signature"]), validate=True)
    trust = hashlib.sha256(public).hexdigest()
    if (
        len(public) != 32
        or trust != control.get("trusted_verifier_public_key_digest")
        or trust != seal.get("verifier_public_key_digest")
    ):
        raise ValueError("convergence seal trust root differs")
    signed_body = {**unsigned, "seal_digest": seal_digest}
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature,
            _stable_json(signed_body).encode("utf-8"),
        )
    except InvalidSignature as error:
        raise ValueError("convergence seal signature differs") from error
    if seal.get("run_id") != index.get("run_id"):
        raise ValueError("convergence seal run differs from official index")
    for field in _SEAL_IDENTITY:
        if seal.get(field) != index.get(field):
            raise ValueError(f"convergence seal identity differs: {field}")
    entries = index.get("scenarios")
    if not isinstance(entries, list):
        raise TypeError("official PRE-Q8 scenario index is invalid")
    generated = {
        str(entry.get("scenario_id")): str(entry.get("seal_config_digest"))
        for entry in entries
        if isinstance(entry, dict)
    }
    if generated != seal.get("generated_config_digests"):
        raise ValueError("convergence seal generated configs differ")
    evidence = seal.get("evidence_digests")
    if (
        not isinstance(evidence, dict)
        or tuple(str(key) for key in evidence) != PRE_Q8_SCENARIOS
        or any(_SHA256.fullmatch(str(value)) is None for value in evidence.values())
    ):
        raise ValueError("convergence seal evidence set differs")
    return seal_digest


def _scenario_metrics(database: Path, product_id: str) -> dict[str, int | str]:
    if not database.is_absolute() or not database.is_file() or database.is_symlink():
        raise ValueError("official scenario database is unavailable or unsafe")
    connection = sqlite3.connect(
        f"file:{database.resolve().as_posix()}?mode=ro",
        uri=True,
        timeout=20,
    )
    try:
        connection.execute("PRAGMA query_only=ON")
        quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        incidents = int(
            connection.execute(
                "SELECT COUNT(*) FROM controller_incidents WHERE product_id=?",
                (product_id,),
            ).fetchone()[0]
        )
        recoveries = int(
            connection.execute(
                "SELECT COUNT(*) FROM recovery_applications WHERE product_id=?",
                (product_id,),
            ).fetchone()[0]
        )
        trajectory = connection.execute(
            "SELECT routine_owner_actions,recovery_applications "
            "FROM trajectory_counters WHERE product_id=?",
            (product_id,),
        ).fetchone()
        owner_actions = int(trajectory[0]) if trajectory is not None else 0
        recoveries = max(recoveries, int(trajectory[1]) if trajectory is not None else 0)
        receipts = connection.execute(
            "SELECT COUNT(*),COUNT(DISTINCT intent_id) FROM side_effect_receipts "
            "WHERE intent_id IN (SELECT intent_id FROM side_effect_intents "
            "WHERE product_id=?)",
            (product_id,),
        ).fetchone()
        duplicates = int(receipts[0]) - int(receipts[1])
        unverified = int(
            connection.execute(
                "SELECT COUNT(*) FROM side_effect_intents AS intent "
                "LEFT JOIN side_effect_receipts AS receipt "
                "ON receipt.intent_id=intent.intent_id WHERE intent.product_id=? "
                "AND (intent.status!='VERIFIED' OR receipt.intent_id IS NULL)",
                (product_id,),
            ).fetchone()[0]
        )
    finally:
        connection.close()
    return {
        "quick_check": quick_check,
        "controller_incidents": incidents,
        "recovery_applications": recoveries,
        "routine_owner_actions": owner_actions,
        "duplicate_side_effects": duplicates,
        "unverified_side_effects": unverified,
    }


def assert_final(
    *,
    functional_db: Path,
    control_config: Path,
    pre_q8_index: Path,
    seal_path: Path,
    expected_source_commit: str | None,
) -> dict[str, Any]:
    failures: list[str] = []
    control = _mapping(control_config, "control config")
    index = _mapping(pre_q8_index, "PRE-Q8 index")
    seal = _mapping(seal_path, "convergence seal")
    seal_digest = _verify_seal(seal, control=control, index=index)
    source_commit = str(control.get("source_commit") or "")
    candidate_digest = str(control.get("candidate_digest") or "")
    if _SHA40.fullmatch(source_commit) is None:
        failures.append("control source_commit is invalid")
    if _SHA256.fullmatch(candidate_digest) is None:
        failures.append("control candidate_digest is invalid")
    if expected_source_commit and source_commit != expected_source_commit:
        failures.append("source_commit differs from expected value")
    if index.get("candidate_digest") != candidate_digest:
        failures.append("PRE-Q8 index Candidate differs")
    scenarios = index.get("scenarios")
    index_order = (
        tuple(str(item.get("scenario_id") or "") for item in scenarios)
        if isinstance(scenarios, list)
        and all(isinstance(item, dict) for item in scenarios)
        else ()
    )
    if index_order != PRE_Q8_SCENARIOS:
        failures.append("PRE-Q8 index order differs")
    if not functional_db.is_file() or functional_db.is_symlink():
        raise ValueError("functional database is unavailable or unsafe")
    connection = sqlite3.connect(
        f"file:{functional_db.resolve().as_posix()}?mode=ro",
        uri=True,
        timeout=20,
    )
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        if quick_check != "ok":
            failures.append("functional database quick_check failed")
        epochs = connection.execute(
            "SELECT * FROM functional_epochs WHERE source_commit=? AND candidate_digest=?",
            (source_commit, candidate_digest),
        ).fetchall()
        if len(epochs) != 1:
            failures.append("exact functional epoch count is not one")
            epoch: dict[str, Any] = {}
            epoch_id = ""
        else:
            epoch = dict(epochs[0])
            epoch_id = str(epoch["epoch_id"])
        capability_rows = connection.execute(
            "SELECT operation,status,report_digest FROM capability_handshake_reports "
            "WHERE epoch_id=? ORDER BY operation",
            (epoch_id,),
        ).fetchall()
        capability_map = {str(row[0]): str(row[1]) for row in capability_rows}
        if set(capability_map) != set(MANDATORY_Q6_5_OPERATIONS) or any(
            capability_map.get(operation) != "AVAILABLE"
            for operation in MANDATORY_Q6_5_OPERATIONS
        ):
            failures.append("Q6.5 is not exact 18/18 AVAILABLE")
        if any(_SHA256.fullmatch(str(row[2])) is None for row in capability_rows):
            failures.append("Q6.5 report digest is invalid")
        open_actions = int(
            connection.execute(
                "SELECT COUNT(*) FROM functional_owner_actions "
                "WHERE epoch_id=? AND status='OPEN'",
                (epoch_id,),
            ).fetchone()[0]
        )
        if open_actions:
            failures.append(f"open owner actions={open_actions}")
        admission_rows = connection.execute(
            "SELECT run_id,seal_digest,git_tree,release_tree_digest,candidate_digest "
            "FROM pre_q8_admissions WHERE epoch_id=?",
            (epoch_id,),
        ).fetchall()
        if len(admission_rows) != 1:
            failures.append("exact PRE-Q8 admission count is not one")
        else:
            admission = admission_rows[0]
            expected_admission = (
                str(index.get("run_id") or ""),
                seal_digest,
                str(index.get("git_tree") or ""),
                str(index.get("release_tree_digest") or ""),
                candidate_digest,
            )
            if tuple(str(value) for value in admission) != expected_admission:
                failures.append("durable PRE-Q8 admission identity differs")
        runs = connection.execute(
            "SELECT scenario_id,attempt,status,product_id,database_path,config_digest "
            "FROM pre_q8_runs "
            "WHERE epoch_id=? ORDER BY rowid",
            (epoch_id,),
        ).fetchall()
        run_identity = tuple((str(row[0]), int(row[1]), str(row[2])) for row in runs)
        expected = tuple((scenario, 1, "PASS") for scenario in PRE_Q8_SCENARIOS)
        if run_identity != expected or any(not str(row[3] or "") for row in runs):
            failures.append("official PRE-Q8 runs are not canonical 10/10 attempt=1")
        passes = connection.execute(
            "SELECT scenario_id,attempt,status,product_id,completion_manifest_ref,"
            "evidence_digest FROM pre_q8_scenarios "
            "WHERE epoch_id=?",
            (epoch_id,),
        ).fetchall()
        if (
            len(passes) != 10
            or {str(row[0]) for row in passes} != set(PRE_Q8_SCENARIOS)
            or any(
                int(row[1]) != 1
                or str(row[2]) != "PASS"
                or not str(row[3] or "")
                or not str(row[4] or "")
                or _SHA256.fullmatch(str(row[5])) is None
                for row in passes
            )
        ):
            failures.append("official PRE-Q8 PASS evidence is incomplete")
        failure_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM pre_q8_failures WHERE epoch_id=?", (epoch_id,)
            ).fetchone()[0]
        )
        if failure_count:
            failures.append(f"official failure count={failure_count}")
        pass_map = {str(row[0]): row for row in passes}
        index_map = {
            str(item.get("scenario_id")): item
            for item in scenarios
            if isinstance(item, dict)
        } if isinstance(scenarios, list) else {}
        for row in runs:
            entry = index_map.get(str(row[0]))
            if entry is None or (
                str(row[4]) != str(entry.get("database_path") or "")
                or str(row[5]) != str(entry.get("config_digest") or "")
            ):
                failures.append(f"{row[0]}: durable run config identity differs")
        scenario_metrics: dict[str, dict[str, int | str]] = {}
        for scenario_id in PRE_Q8_SCENARIOS:
            row = pass_map.get(scenario_id)
            entry = index_map.get(scenario_id)
            if row is None or entry is None:
                continue
            metrics = _scenario_metrics(Path(str(entry["database_path"])), str(row[3]))
            scenario_metrics[scenario_id] = metrics
            if metrics["quick_check"] != "ok" or any(
                int(metrics[key]) != 0
                for key in (
                    "controller_incidents",
                    "recovery_applications",
                    "routine_owner_actions",
                    "duplicate_side_effects",
                    "unverified_side_effects",
                )
            ):
                failures.append(f"{scenario_id}: scenario evidence is not zero-incident")
        accepted = {
            "GOLDEN_PRODUCT_PENDING",
            "READY_EVALUATION",
            "FUNCTIONALLY_READY",
        }
        if (
            epoch.get("q6_5_status") != "PASS"
            or epoch.get("pre_q8_status") != "10/10 PASS"
            or epoch.get("status") not in accepted
            or epoch.get("q7_started_at") is not None
        ):
            failures.append("functional epoch did not reach accepted PRE-Q8 terminal stage")
    finally:
        connection.close()
    return {
        "schema_version": "1.0",
        "status": "PASS" if not failures else "FAIL",
        "source_commit": source_commit,
        "candidate_digest": candidate_digest,
        "seal_digest": seal_digest,
        "epoch_id": epoch_id,
        "epoch_status": epoch.get("status") if epoch else None,
        "q6_5_available_count": sum(
            status == "AVAILABLE" for status in capability_map.values()
        ),
        "open_owner_actions": open_actions,
        "pre_q8_pass_count": sum(str(row[2]) == "PASS" for row in passes),
        "scenario_metrics": scenario_metrics,
        "official_failure_count": failure_count,
        "database_quick_check": quick_check,
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--functional-db",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional/functional.db"),
    )
    parser.add_argument(
        "--control-config",
        type=Path,
        default=Path("/etc/hermes-factory/qualification-control.yaml"),
    )
    parser.add_argument(
        "--preq8-index", type=Path, default=Path("/etc/hermes-factory/pre-q8/index.json")
    )
    parser.add_argument(
        "--seal",
        type=Path,
        default=Path("/var/lib/hermes-factory-convergence/admitted/seal.json"),
    )
    parser.add_argument("--expected-source-commit")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    try:
        report = assert_final(
            functional_db=args.functional_db,
            control_config=args.control_config,
            pre_q8_index=args.preq8_index,
            seal_path=args.seal,
            expected_source_commit=args.expected_source_commit,
        )
    except (
        OSError,
        TypeError,
        ValueError,
        KeyError,
        sqlite3.Error,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as error:
        report = {
            "schema_version": "1.0",
            "status": "FAIL",
            "failures": [f"{type(error).__name__}: {error}"],
        }
    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    print(encoded, end="")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(encoded, encoding="utf-8", newline="\n")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
