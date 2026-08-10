#!/usr/bin/env python3
"""Operate the isolated all-ten PRE-Q8 convergence lane and signed seal."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from factory.canary_faults import CanaryFaultContract
from factory.canary_qualification import (
    load_canary_catalog,
    observe_completion,
    prove_fresh_state,
)
from factory.common import sha256_file, sha256_text, stable_json, utc_now
from factory.config import load_config
from factory.pre_q8_convergence import (
    ConvergenceScenarioResult,
    ConvergenceStore,
    matrix_body,
    write_matrix,
)
from factory.pre_q8_seal import (
    build_seal_payload,
    sign_seal,
    verify_seal,
    write_seal,
)
from factory.support_bundle import build_support_bundle


class ConvergenceControlError(RuntimeError):
    """Convergence evidence or release identity is incomplete or conflicting."""


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ConvergenceControlError(f"{label} must be an object")
    return {str(key): item for key, item in value.items()}


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    encoded = json.dumps(dict(value), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_text(encoding="utf-8") != encoded:
            raise ConvergenceControlError("immutable convergence result conflicts")
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _failure_evidence(
    *,
    config_path: Path,
    failure_class: str,
    evidence_root: Path,
    support_sources: tuple[Path, ...],
) -> ConvergenceScenarioResult:
    config = load_config(config_path)
    contract = CanaryFaultContract.from_config(config)
    if contract.qualification_plane != "CONVERGENCE" or re.fullmatch(
        r"[A-Z][A-Z0-9_]{2,63}", failure_class
    ) is None:
        raise ConvergenceControlError("convergence failure identity is invalid")
    body = {
        "schema_version": "1.0",
        "evidence_type": "PREQ8_CONVERGENCE_FAILURE",
        "run_id": contract.run_id,
        "epoch_id": contract.epoch_id,
        "scenario_id": contract.scenario_id,
        "candidate_digest": contract.candidate_digest,
        "failure_class": failure_class,
        "config_digest": sha256_text(stable_json(config.raw)),
        "support_source_digests": {
            source.name: sha256_file(source) for source in support_sources
        },
    }
    digest = sha256_text(stable_json(body))
    observed_at = utc_now()
    evidence = evidence_root / f"failure-{digest}.json"
    _write_json(
        evidence,
        {**body, "evidence_digest": digest, "observed_at": observed_at},
    )
    bundle, _bundle_digest = build_support_bundle(
        incident_id=f"convergence-{contract.run_id}-{contract.scenario_id}",
        source_files=(evidence, *support_sources),
        allowed_roots=(
            evidence_root.parent.parent,
            Path("/var/lib/hermes-factory-pre-q8-convergence"),
            Path("/var/log/hermes-factory-pre-q8-convergence"),
        ),
        output_root=evidence_root.parent.parent / "support-bundles",
        metadata={
            "status": "CONVERGENCE_SCENARIO_FAILED",
            "run_id": contract.run_id,
            "scenario_id": contract.scenario_id,
            "failure_class": failure_class,
        },
        created_at=observed_at,
    )
    return ConvergenceScenarioResult(
        scenario_id=contract.scenario_id,
        status="FAIL",
        evidence_digest=digest,
        config_digest=str(body["config_digest"]),
        failure_class=failure_class,
        support_bundle_ref=str(bundle),
    )


def _observe(
    *, config_path: Path, product_id: str, evidence_root: Path
) -> ConvergenceScenarioResult:
    config = load_config(config_path)
    contract = CanaryFaultContract.from_config(config)
    if contract.qualification_plane != "CONVERGENCE":
        raise ConvergenceControlError("convergence config is on another plane")
    catalog = load_canary_catalog(Path(str(config.raw["paths"]["canary_catalog"])))
    scenario = catalog[contract.scenario_id]
    observation = observe_completion(
        config.database_path,
        evidence_root,
        product_id=product_id,
        expected_controller_release_digest=contract.controller_release_digest,
        scenario=scenario,
        fault_receipt_root=contract.receipt_root,
        expected_candidate_digest=contract.candidate_digest,
        fault_contract=contract,
    )
    if any(
        (
            observation.controller_incidents,
            observation.recovery_applications,
            observation.routine_owner_actions,
            observation.duplicate_side_effects,
            observation.unverified_side_effects,
        )
    ):
        raise ConvergenceControlError("convergence intervention counters are non-zero")
    return ConvergenceScenarioResult(
        scenario_id=contract.scenario_id,
        status="PASS",
        evidence_digest=observation.observation_digest,
        config_digest=sha256_text(stable_json(config.raw)),
    )


def _result(path: Path) -> ConvergenceScenarioResult:
    value = _mapping(json.loads(path.read_text(encoding="utf-8")), "convergence result")
    return ConvergenceScenarioResult(
        scenario_id=str(value["scenario_id"]),
        status=str(value["status"]),
        evidence_digest=str(value["evidence_digest"]),
        config_digest=str(value["config_digest"]),
        failure_class=(str(value["failure_class"]) if value.get("failure_class") else None),
        support_bundle_ref=(
            str(value["support_bundle_ref"]) if value.get("support_bundle_ref") else None
        ),
    )


def _seal(
    *,
    store: ConvergenceStore,
    run_id: str,
    official_index_path: Path,
    matrix_path: Path,
    private_key_path: Path,
    output: Path,
) -> str:
    index = _mapping(
        json.loads(official_index_path.read_text(encoding="utf-8")),
        "official PRE-Q8 index",
    )
    index_digest = str(index.pop("index_digest", ""))
    if sha256_text(stable_json(index)) != index_digest:
        raise ConvergenceControlError("official PRE-Q8 index digest differs")
    matrix = _mapping(json.loads(matrix_path.read_text(encoding="utf-8")), "matrix")
    matrix_digest = str(matrix.get("matrix_digest", ""))
    if (
        matrix.get("status") != "10/10 PASS"
        or matrix.get("run_id") != run_id
        or index.get("run_id") != run_id
        or index.get("qualification_plane") != "CONVERGENCE"
    ):
        raise ConvergenceControlError("seal inputs do not prove one 10/10 run")
    scenarios = index.get("scenarios")
    if not isinstance(scenarios, list):
        raise ConvergenceControlError("convergence config index scenarios are invalid")
    generated = {
        str(item["scenario_id"]): str(item["seal_config_digest"])
        for item in scenarios
        if isinstance(item, Mapping)
    }
    results = store.results(run_id)
    evidence = {result.scenario_id: result.evidence_digest for result in results}
    raw_private = private_key_path.read_bytes()
    if len(raw_private) != 32:
        raise ConvergenceControlError("convergence signing key is invalid")
    public = Ed25519PrivateKey.from_private_bytes(raw_private).public_key().public_bytes_raw()
    payload = build_seal_payload(
        run_id=run_id,
        source_commit=str(index["source_commit"]),
        git_tree=str(index["git_tree"]),
        release_tree_digest=str(index["release_tree_digest"]),
        requirements_lock_digest=str(index["requirements_lock_digest"]),
        toolchain_digest=str(index["toolchain_digest"]),
        systemd_bundle_digest=str(index["systemd_bundle_digest"]),
        catalog_digest=str(index["catalog_digest"]),
        base_config_digest=str(index["base_config_digest"]),
        generated_config_digests=generated,
        capability_attestation_digest=str(index["capability_attestation_digest"]),
        fixture_seed_digest=str(index["fixture_seed_digest"]),
        evidence_digests=evidence,
        matrix_digest=matrix_digest,
        public_key_digest=hashlib.sha256(public).hexdigest(),
    )
    if output.exists():
        if not output.is_file() or output.is_symlink():
            raise ConvergenceControlError("convergence seal output is unsafe")
        existing = _mapping(json.loads(output.read_text(encoding="utf-8")), "seal")
        existing_payload = {
            key: value
            for key, value in existing.items()
            if key not in {"seal_digest", "verifier_signature", "signed_at"}
        }
        if existing_payload != payload:
            raise ConvergenceControlError("immutable convergence seal conflicts")
        seal_digest = verify_seal(
            existing,
            verifier_public_key=base64.b64encode(public).decode("ascii"),
            trusted_public_key_digest=hashlib.sha256(public).hexdigest(),
            expected_identity=payload,
            expected_generated_config_digests=generated,
        )
    else:
        seal_digest, _path = write_seal(output, sign_seal(payload, private_key_path))
    store.mark_sealed(run_id)
    return seal_digest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--candidate-digest", required=True)
    init.add_argument("--git-tree", required=True)
    init.add_argument("--release-tree-digest", required=True)
    init.add_argument("--toolchain-digest", required=True)
    observe = commands.add_parser("observe")
    observe.add_argument("--config", type=Path, required=True)
    observe.add_argument("--product-id", required=True)
    observe.add_argument("--evidence-root", type=Path, required=True)
    observe.add_argument("--output", type=Path, required=True)
    fresh = commands.add_parser("fresh")
    fresh.add_argument("--config", type=Path, required=True)
    fresh.add_argument("--evidence-root", type=Path, required=True)
    failure = commands.add_parser("failure")
    failure.add_argument("--config", type=Path, required=True)
    failure.add_argument("--failure-class", required=True)
    failure.add_argument("--evidence-root", type=Path, required=True)
    failure.add_argument("--support-source", type=Path, action="append", default=[])
    failure.add_argument("--output", type=Path, required=True)
    record = commands.add_parser("record")
    record.add_argument("result", type=Path)
    matrix = commands.add_parser("matrix")
    matrix.add_argument("--output", type=Path, required=True)
    seal = commands.add_parser("seal")
    seal.add_argument("--official-index", type=Path, required=True)
    seal.add_argument("--matrix", type=Path, required=True)
    seal.add_argument("--private-key", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    store = ConvergenceStore(args.database.resolve())
    try:
        if args.command == "init":
            result: dict[str, Any] = {
                "created": store.start(
                    run_id=args.run_id,
                    candidate_digest=args.candidate_digest,
                    git_tree=args.git_tree,
                    release_tree_digest=args.release_tree_digest,
                    toolchain_digest=args.toolchain_digest,
                )
            }
        elif args.command == "fresh":
            config = load_config(args.config)
            contract = CanaryFaultContract.from_config(config)
            if contract.qualification_plane != "CONVERGENCE":
                raise ConvergenceControlError("fresh proof belongs to another plane")
            proof = prove_fresh_state(config.database_path, args.evidence_root)
            result = {
                "scenario_id": contract.scenario_id,
                "initial_state_digest": proof.initial_state_digest,
                "evidence_ref": proof.evidence_ref,
            }
        elif args.command == "observe":
            observed = _observe(
                config_path=args.config,
                product_id=args.product_id,
                evidence_root=args.evidence_root,
            )
            _write_json(args.output, observed.as_dict())
            result = observed.as_dict()
        elif args.command == "failure":
            failed = _failure_evidence(
                config_path=args.config,
                failure_class=args.failure_class,
                evidence_root=args.evidence_root,
                support_sources=tuple(args.support_source),
            )
            _write_json(args.output, failed.as_dict())
            result = failed.as_dict()
        elif args.command == "record":
            recorded = _result(args.result)
            result = {"created": store.record(args.run_id, recorded), **recorded.as_dict()}
        elif args.command == "matrix":
            status = store.finalize(args.run_id)
            run = store.connection.execute(
                "SELECT git_tree,release_tree_digest,toolchain_digest "
                "FROM convergence_runs WHERE run_id=?",
                (args.run_id,),
            ).fetchone()
            if run is None:
                raise ConvergenceControlError("convergence run is unavailable")
            body = matrix_body(
                run_id=args.run_id,
                git_tree=str(run[0]),
                release_tree_digest=str(run[1]),
                toolchain_digest=str(run[2]),
                results=store.results(args.run_id),
            )
            digest, path = write_matrix(args.output, body)
            result = {"status": status, "matrix_digest": digest, "matrix": str(path)}
        else:
            digest = _seal(
                store=store,
                run_id=args.run_id,
                official_index_path=args.official_index,
                matrix_path=args.matrix,
                private_key_path=args.private_key,
                output=args.output,
            )
            result = {"status": "CONVERGENCE_SEALED", "seal_digest": digest}
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
        print(stable_json({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    finally:
        store.close()
    print(stable_json({"status": "PASS", **result}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
