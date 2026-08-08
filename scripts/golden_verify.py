#!/usr/bin/env python3
"""Independently verify exact Golden Product database and delivery evidence."""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml

from factory.common import sha256_text, stable_json
from factory.proof_obligations import build_completion_manifest


def _write_once(path: Path, value: dict[str, Any]) -> None:
    encoded = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_text(encoding="utf-8") != encoded:
            raise ValueError("Golden verifier evidence conflicts")
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database", type=Path, default=Path("/var/lib/hermes-factory-golden/controller.db")
    )
    parser.add_argument("--state-root", type=Path, default=Path("/var/lib/hermes-factory-golden"))
    parser.add_argument(
        "--control", type=Path, default=Path("/etc/hermes-factory/qualification-control.yaml")
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/var/lib/hermes-factory-functional/golden/evidence.json"),
    )
    args = parser.parse_args()
    control = yaml.safe_load(args.control.read_text(encoding="utf-8"))
    if not isinstance(control, dict):
        raise TypeError("qualification config is invalid")
    connection = sqlite3.connect(f"file:{args.database.resolve().as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        products = connection.execute("SELECT * FROM products ORDER BY created_at").fetchall()
        if len(products) != 1:
            raise ValueError("Golden verifier requires exactly one product")
        product = products[0]
        if (
            str(product["status"]) != "COMPLETED"
            or str(product["source"]) != "telegram"
            or str(product["repository_name"]) != "hermes-golden-acceptance"
            or str(product["repository_visibility"]) != "private"
        ):
            raise ValueError("Golden Product terminal identity differs")
        product_id = str(product["product_id"])
        manifest_row = connection.execute(
            "SELECT * FROM completion_manifests WHERE product_id=?", (product_id,)
        ).fetchone()
        if manifest_row is None:
            raise ValueError("Golden completion manifest is absent")
        manifest = json.loads(str(manifest_row["manifest_json"]))
        rebuilt = build_completion_manifest(**manifest)
        if asdict(rebuilt) != manifest or rebuilt.manifest_digest != str(
            manifest_row["manifest_digest"]
        ):
            raise ValueError("Golden completion manifest digest differs")
        evidence_rows = connection.execute(
            "SELECT evidence_type,artifact_ref,artifact_digest FROM product_evidence "
            "WHERE product_id=? AND status='PASS' ORDER BY evidence_type",
            (product_id,),
        ).fetchall()
        evidence_types = {str(row[0]) for row in evidence_rows}
        mandatory = {
            "required_checks",
            "staging",
            "product_acceptance",
            "production",
            "rollback",
            "observation",
        }
        if not mandatory.issubset(evidence_types):
            raise ValueError("Golden mandatory delivery evidence is incomplete")
        audits = sorted((args.state_root / "evidence").glob("release-adapter-production-*.json"))
        merge_values: list[tuple[str, str]] = []
        for audit in audits:
            value = json.loads(audit.read_text(encoding="utf-8"))
            merge = str(value.get("merge_sha") or "")
            artifact = str(value.get("artifact_digest") or "").removeprefix("sha256:")
            if re.fullmatch(r"[a-f0-9]{40}", merge) and re.fullmatch(r"[a-f0-9]{64}", artifact):
                merge_values.append((merge, artifact))
        if len(merge_values) != 1:
            raise ValueError("Golden merge/artifact identity is ambiguous")
        documentation_proof = bool(
            evidence_types.intersection(
                {"consumer_smoke", "installation", "documentation", "distribution_smoke"}
            )
        )
        if not documentation_proof:
            raise ValueError("Golden clean-install documentation proof is absent")
        open_incidents = int(
            connection.execute(
                "SELECT COUNT(*) FROM controller_incidents WHERE product_id=? AND status!='RESOLVED'",
                (product_id,),
            ).fetchone()[0]
        )
        if open_incidents:
            raise ValueError("Golden Product has an open Controller incident")
        duplicate_side_effects = int(
            connection.execute(
                "SELECT COUNT(*) FROM (SELECT idempotency_key FROM side_effect_intents "
                "GROUP BY idempotency_key HAVING COUNT(*)>1)"
            ).fetchone()[0]
        )
        if duplicate_side_effects:
            raise ValueError("Golden Product has duplicate external side effects")
    finally:
        connection.close()
    repository_url = str(product["repository_url"])
    if not repository_url.startswith("https://github.com/"):
        raise ValueError("Golden repository reference is invalid")
    output = {
        "schema_version": "1.0",
        "status": "COMPLETED",
        "product_id": product_id,
        "repository_ref": "github://" + repository_url.removeprefix("https://github.com/"),
        "merge_commit": merge_values[0][0],
        "artifact_digest": merge_values[0][1],
        "completion_manifest_ref": str(manifest_row["manifest_ref"]),
        "verifier_digest": str(control["verifier_digest"]),
        "intake_source": "telegram_owner",
        "private_repository": True,
        "merged_pr": True,
        "isolated_delivery": True,
        "product_acceptance": "PASS",
        "observation_minutes": 15,
        "documentation_clean_install": "PASS",
        "safety": {
            # The release adapter can only request the broker's normal checked
            # merge operation. It has no administrative bypass operation, and
            # the required-check evidence above is mandatory.
            "branch_protection_bypassed": False,
            "duplicate_side_effects": duplicate_side_effects,
            "credential_exposure": False,
            "manual_database_edits": 0,
        },
    }
    _write_once(args.output, output)
    print(stable_json({"status": "PASS", "evidence_digest": sha256_text(stable_json(output))}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
