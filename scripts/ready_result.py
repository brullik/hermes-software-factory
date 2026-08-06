#!/usr/bin/env python3
"""Build, sign, independently verify, and dispatch functional ready results."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

import yaml

from factory.common import sha256_text, stable_json
from factory.functional_readiness import (
    FunctionalQualificationGovernor,
    FunctionalReadinessError,
    ReadyResultManifest,
    verify_ready_result_manifest,
)
from factory.notifications import NotificationOutbox, NotificationRequest
from scripts.qualification_control import authorize_shadow
from scripts.release_qualify import _load_private_key


class ReadyControlError(RuntimeError):
    """A functional ready result is incomplete or not independently bound."""


def _config(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReadyControlError("qualification config is invalid")
    return {str(key): item for key, item in value.items()}


def _write_once(path: Path, value: dict[str, Any], *, mode: int = 0o440) -> None:
    encoded = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_text(encoding="utf-8") != encoded:
            raise ReadyControlError("immutable ready result conflicts")
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())


def _epoch(connection: sqlite3.Connection, config: dict[str, Any]) -> sqlite3.Row:
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        "SELECT * FROM functional_epochs WHERE source_commit=? AND candidate_digest=?",
        (str(config["source_commit"]), str(config["candidate_digest"])),
    ).fetchall()
    if len(rows) != 1:
        raise ReadyControlError("functional ready epoch is ambiguous")
    row: sqlite3.Row = rows[0]
    return row


def build_request(config: dict[str, Any], *, state_root: Path, output: Path) -> dict[str, Any]:
    functional = sqlite3.connect(state_root / "functional.db")
    functional.row_factory = sqlite3.Row
    qualification = sqlite3.connect(Path(str(config["governor_database"])))
    qualification.row_factory = sqlite3.Row
    try:
        epoch = _epoch(functional, config)
        if str(epoch["status"]) != "FUNCTIONALLY_READY":
            raise ReadyControlError("factory is not functionally ready")
        release = qualification.execute(
            "SELECT epoch_id FROM controller_release_epochs "
            "WHERE source_commit=? AND candidate_digest=?",
            (str(config["source_commit"]), str(config["candidate_digest"])),
        ).fetchall()
        if len(release) != 1:
            raise ReadyControlError("release epoch binding is ambiguous")
        q0_q6 = qualification.execute(
            "SELECT stage,status,evidence_ref FROM qualification_runs "
            "WHERE epoch_id=? ORDER BY created_at",
            (str(release[0][0]),),
        ).fetchall()
        if len(q0_q6) != 7 or any(str(row[1]) != "PASS" for row in q0_q6):
            raise ReadyControlError("Q0-Q6 exact PASS evidence is incomplete")
        capabilities = functional.execute(
            "SELECT operation,status,report_digest FROM capability_handshake_reports "
            "WHERE epoch_id=? ORDER BY operation",
            (str(epoch["epoch_id"]),),
        ).fetchall()
        pre_q8 = functional.execute(
            "SELECT scenario_id,status,evidence_digest FROM pre_q8_scenarios "
            "WHERE epoch_id=? ORDER BY scenario_id",
            (str(epoch["epoch_id"]),),
        ).fetchall()
        golden = functional.execute(
            "SELECT * FROM golden_products WHERE epoch_id=?", (str(epoch["epoch_id"]),)
        ).fetchone()
        if len(capabilities) != 18 or any(str(row[1]) != "AVAILABLE" for row in capabilities):
            raise ReadyControlError("Q6.5 exact PASS evidence is incomplete")
        if len(pre_q8) != 10 or any(str(row[1]) != "PASS" for row in pre_q8):
            raise ReadyControlError("PRE-Q8 exact 10/10 evidence is incomplete")
        if golden is None or str(golden["status"]) != "COMPLETED":
            raise ReadyControlError("Golden Product completion evidence is missing")
        obligations = [
            {
                "obligation_id": f"qualification.{row[0]}",
                "status": "PASS",
                "evidence_ref": str(row[2]),
            }
            for row in q0_q6
        ]
        obligations.extend(
            {
                "obligation_id": f"q6_5.{row[0]}",
                "status": "PASS",
                "evidence_ref": f"sha256:{row[2]}",
            }
            for row in capabilities
        )
        obligations.extend(
            {
                "obligation_id": f"pre_q8.{row[0]}",
                "status": "PASS",
                "evidence_ref": f"sha256:{row[2]}",
            }
            for row in pre_q8
        )
        obligations.append(
            {
                "obligation_id": "golden_product.completed",
                "status": "PASS",
                "evidence_ref": str(golden["completion_manifest_ref"]),
            }
        )
        evidence_refs = tuple(str(item["evidence_ref"]) for item in obligations)
        version = (Path(str(config["candidate_repository_root"])) / "VERSION").read_text(
            encoding="utf-8"
        ).strip()
        request = {
            "schema_version": "1.0",
            "manifest_type": "FACTORY_FUNCTIONALLY_READY",
            "status": "PASS",
            "subject": {
                "epoch_id": str(epoch["epoch_id"]),
                "q6_5": "PASS",
                "pre_q8": "10/10 PASS",
                "golden_product": "COMPLETED",
            },
            "release_identity": {
                "version": version,
                "commit": str(config["source_commit"]),
                "digest": str(config["candidate_digest"]),
            },
            "mandatory_obligations": obligations,
            "evidence_refs": list(evidence_refs),
            "open_blockers": [],
            "verifier": {"digest": str(config["verifier_digest"])},
        }
        _write_once(output, request)
        return request
    finally:
        functional.close()
        qualification.close()


def sign_request(config: dict[str, Any], *, request: Path, output: Path) -> dict[str, Any]:
    value = json.loads(request.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("verifier") != {
        "digest": str(config["verifier_digest"])
    }:
        raise ReadyControlError("ready request verifier identity differs")
    key = _load_private_key(Path(str(config["verifier_private_key_path"])))
    public = key.public_key().public_bytes_raw()
    if hashlib.sha256(public).hexdigest() != str(config["trusted_verifier_public_key_digest"]):
        raise ReadyControlError("ready signing key differs from trust root")
    signature = base64.b64encode(key.sign(stable_json(value).encode("utf-8"))).decode("ascii")
    release = value["release_identity"]
    manifest = ReadyResultManifest.create(
        manifest_type=str(value["manifest_type"]),
        subject=dict(value["subject"]),
        version=str(release["version"]),
        commit=str(release["commit"]),
        digest=str(release["digest"]),
        mandatory_obligations=tuple(value["mandatory_obligations"]),
        evidence_refs=tuple(str(item) for item in value["evidence_refs"]),
        verifier_digest=str(value["verifier"]["digest"]),
        verifier_signature=signature,
    )
    envelope = manifest.as_dict()
    _write_once(output, envelope)
    return envelope


def dispatch(
    config: dict[str, Any], *, state_root: Path, signed: Path
) -> dict[str, Any]:
    value = json.loads(signed.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReadyControlError("signed ready result is invalid")
    digest = verify_ready_result_manifest(
        value,
        verifier_public_key=str(config["verifier_public_key"]),
        trusted_public_key_digest=str(config["trusted_verifier_public_key_digest"]),
    )
    connection = sqlite3.connect(state_root / "functional.db")
    governor = FunctionalQualificationGovernor(connection)
    try:
        epoch = _epoch(connection, config)
        effect = governor.authorize_q7(str(epoch["epoch_id"]))
    finally:
        connection.close()
    release_epoch, _ = authorize_shadow(config, digest)
    NotificationOutbox(
        state_root / "notifications",
        attachment_roots=(state_root, Path("/var/lib/hermes-factory-verifier")),
    ).enqueue(
        NotificationRequest(
            request_id="Q7-START-" + sha256_text(release_epoch)[:32],
            kind="Q7_STARTED",
            text=(
                "Hermes Q7 started only after Q6.5 PASS, PRE-Q8 10/10 PASS, and "
                "Golden Product COMPLETED."
            ),
        )
    )
    return {"status": "Q7_AUTHORIZED", "epoch_id": release_epoch, "effect": effect, "manifest_digest": digest}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=Path("/etc/hermes-factory/qualification-control.yaml")
    )
    parser.add_argument(
        "--state-root", type=Path, default=Path("/var/lib/hermes-factory-functional")
    )
    commands = parser.add_subparsers(dest="command", required=True)
    request = commands.add_parser("request")
    request.add_argument("output", type=Path)
    sign = commands.add_parser("sign")
    sign.add_argument("request", type=Path)
    sign.add_argument("output", type=Path)
    dispatch_parser = commands.add_parser("dispatch")
    dispatch_parser.add_argument("signed", type=Path)
    args = parser.parse_args(argv)
    try:
        config = _config(args.config)
        if args.command == "request":
            result = build_request(config, state_root=args.state_root, output=args.output)
        elif args.command == "sign":
            result = sign_request(config, request=args.request, output=args.output)
        else:
            result = dispatch(config, state_root=args.state_root, signed=args.signed)
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
        sqlite3.Error,
        FunctionalReadinessError,
        ReadyControlError,
    ) as error:
        print(stable_json({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    print(stable_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
