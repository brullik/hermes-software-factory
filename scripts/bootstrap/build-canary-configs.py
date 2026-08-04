#!/usr/bin/env python3
"""Build immutable root-owned configs for the exact ten clean canaries."""

from __future__ import annotations

import argparse
import copy
import json
import re
from pathlib import Path
from typing import Any

import yaml

from factory.canary_qualification import load_canary_catalog
from factory.common import sha256_text, stable_json
from factory.config import FactoryConfig, validate_config

_SHA256 = re.compile(r"^[a-f0-9]{64}$")


def _write_immutable(path: Path, content: str) -> None:
    if path.exists():
        if path.is_symlink() or path.read_text(encoding="utf-8") != content:
            raise ValueError(f"clean canary config conflicts: {path.name}")
        return
    path.write_text(content, encoding="utf-8", newline="\n")


def build_configs(
    base: dict[str, Any],
    *,
    catalog_path: Path,
    output_root: Path,
    state_root: Path,
    log_root: Path,
    candidate_digest: str,
    controller_release_digest: str,
    capability_attestation_path: Path,
    capability_attestation_digest: str,
    existing_repository_url: str,
    first_port: int,
) -> dict[str, Any]:
    catalog = load_canary_catalog(catalog_path)
    if not all(
        _SHA256.fullmatch(value)
        for value in (
            candidate_digest,
            controller_release_digest,
            capability_attestation_digest,
        )
    ):
        raise ValueError("clean canary digest argument is invalid")
    if not all(
        path.is_absolute()
        for path in (
            catalog_path,
            output_root,
            state_root,
            log_root,
            capability_attestation_path,
        )
    ):
        raise ValueError("clean canary paths must be absolute")
    if first_port < 1024 or first_port + len(catalog) - 1 > 65535:
        raise ValueError("clean canary port range is invalid")
    output_root.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    for index, scenario_id in enumerate(sorted(catalog)):
        scenario = catalog[scenario_id]
        scenario_state = state_root / scenario_id
        payload = copy.deepcopy(base)
        payload["controller"].update(
            {
                "database_url": f"sqlite:///{(scenario_state / 'controller.db').as_posix()}",
                "max_active_products": 1,
                "max_active_workers": 1,
                "observation_seconds": 60,
            }
        )
        payload["paths"].update(
            {
                "state": str(scenario_state),
                "worktrees": str(scenario_state / "worktrees"),
                "logs": str(log_root / scenario_id),
                "canary_catalog": str(catalog_path),
            }
        )
        payload["network"].update(
            {"admin_bind": "127.0.0.1", "admin_port": first_port + index}
        )
        payload["telegram"]["allowed_user_ids"] = []
        payload["deployment"].update(
            {
                "current_vps_high_risk_production": False,
                "staging_root": str(scenario_state / "staging"),
                "production_helper": "",
                "rollback_helper": "",
                "qualification_manifest_root": "",
                "verifier_public_key_digest": "",
                "health_probe_url": f"http://127.0.0.1:{first_port + index}/healthz",
                "production_target": {
                    "mode": "isolated_candidate",
                    "host": "clean-canary.invalid",
                    "install_root": str(scenario_state / "isolated-target"),
                    "entrypoint": "disabled",
                },
            }
        )
        payload["backup"].update(
            {
                "offsite_configured": False,
                "proof_path": str(scenario_state / "qualification" / "backup-proof.json"),
            }
        )
        payload["qualification"] = {
            "plane": "CLEAN_CANARY",
            "capability_attestation_path": str(capability_attestation_path),
            "capability_attestation_digest": capability_attestation_digest,
            "scenario_id": scenario.scenario_id,
            "scenario_digest": scenario.scenario_digest,
            "controller_release_digest": controller_release_digest,
            "candidate_digest": candidate_digest,
            "faults": list(scenario.injected_faults),
            "fault_receipt_root": str(scenario_state / "fault-receipts"),
            "isolated_target_root": str(scenario_state / "isolated-target"),
            "existing_repository_url": (
                existing_repository_url
                if scenario.delivery_mode == "existing_repository"
                else ""
            ),
        }
        destination = output_root / f"{scenario_id}.yaml"
        errors = validate_config(FactoryConfig(payload, destination))
        if errors:
            raise ValueError(f"{scenario_id}: {errors[0]}")
        encoded = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
        _write_immutable(destination, encoded)
        config_digest = sha256_text(stable_json(payload))
        entries.append(
            {
                "scenario_id": scenario_id,
                "scenario_digest": scenario.scenario_digest,
                "config_path": str(destination),
                "config_digest": config_digest,
                "database_path": str(scenario_state / "controller.db"),
                "fault_receipt_root": str(scenario_state / "fault-receipts"),
                "port": first_port + index,
            }
        )
    index_payload = {
        "schema_version": "1.0",
        "candidate_digest": candidate_digest,
        "controller_release_digest": controller_release_digest,
        "catalog_digest": sha256_text(
            stable_json(
                {
                    key: value.scenario_digest
                    for key, value in sorted(catalog.items())
                }
            )
        ),
        "scenarios": entries,
    }
    index_payload["index_digest"] = sha256_text(stable_json(index_payload))
    _write_immutable(
        output_root / "index.json",
        json.dumps(index_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    return index_payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-config", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--log-root", type=Path, required=True)
    parser.add_argument("--candidate-digest", required=True)
    parser.add_argument("--controller-release-digest", required=True)
    parser.add_argument("--capability-attestation-path", type=Path, required=True)
    parser.add_argument("--capability-attestation-digest", required=True)
    parser.add_argument("--existing-repository-url", default="")
    parser.add_argument("--first-port", type=int, default=8800)
    args = parser.parse_args()
    raw = yaml.safe_load(args.base_config.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError("base Candidate B config must be an object")
    result = build_configs(
        raw,
        catalog_path=args.catalog,
        output_root=args.output_root,
        state_root=args.state_root,
        log_root=args.log_root,
        candidate_digest=args.candidate_digest,
        controller_release_digest=args.controller_release_digest,
        capability_attestation_path=args.capability_attestation_path,
        capability_attestation_digest=args.capability_attestation_digest,
        existing_repository_url=args.existing_repository_url,
        first_port=args.first_port,
    )
    print(stable_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
