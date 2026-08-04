#!/usr/bin/env python3
"""Derive a capability-minimal Candidate B config from the public template."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


def build_candidate_config(
    source: Path,
    *,
    install_root: Path,
    state_root: Path,
    log_root: Path,
    admin_port: int,
) -> dict[str, Any]:
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError("factory config template must be an object")
    controller = raw["controller"]
    paths = raw["paths"]
    telegram = raw["telegram"]
    network = raw["network"]
    deployment = raw["deployment"]
    backup = raw["backup"]
    models = raw["models"]
    if not all(
        isinstance(value, dict)
        for value in (controller, paths, telegram, network, deployment, backup, models)
    ):
        raise ValueError("factory config template sections are invalid")
    current = install_root / "current"
    controller["database_url"] = f"sqlite:///{(state_root / 'controller.db').as_posix()}"
    paths.update(
        {
            "policies": str(current / "policies"),
            "schemas": str(current / "schemas"),
            "prompts": str(current / "prompts"),
            "state": str(state_root),
            "worktrees": str(state_root / "worktrees"),
            "logs": str(log_root),
        }
    )
    telegram["allowed_user_ids"] = []
    telegram["token_credential_name"] = "candidate-telegram-token"
    network["admin_bind"] = "127.0.0.1"
    network["admin_port"] = admin_port
    deployment.update(
        {
            "current_vps_high_risk_production": False,
            "staging_root": str(state_root / "staging"),
            "production_helper": "",
            "qualification_manifest_root": "",
            "verifier_public_key_digest": "",
            "rollback_helper": "",
            "health_probe_url": f"http://127.0.0.1:{admin_port}/healthz",
            "production_target": {
                "mode": "isolated_candidate",
                "host": "candidate.invalid",
                "install_root": str(state_root / "isolated-target"),
                "entrypoint": "disabled",
            },
        }
    )
    backup.update(
        {
            "offsite_configured": False,
            "proof_path": str(state_root / "qualification" / "backup-proof.json"),
        }
    )
    models["registry"] = "/etc/hermes-factory/candidate-model-registry.yaml"
    return raw


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--log-root", type=Path, required=True)
    parser.add_argument("--admin-port", type=int, default=8788)
    args = parser.parse_args()
    if not all(
        path.is_absolute()
        for path in (args.output, args.install_root, args.state_root, args.log_root)
    ):
        raise ValueError("candidate paths must be absolute")
    if not 1024 <= args.admin_port <= 65535:
        raise ValueError("candidate admin port is invalid")
    payload = build_candidate_config(
        args.source,
        install_root=args.install_root,
        state_root=args.state_root,
        log_root=args.log_root,
        admin_port=args.admin_port,
    )
    encoded = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    if args.output.exists() and args.output.read_text(encoding="utf-8") != encoded:
        raise ValueError("candidate config already exists with different content")
    args.output.write_text(encoded, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
