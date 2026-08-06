#!/usr/bin/env python3
"""Build the root-owned isolated Golden Product runtime configuration."""

from __future__ import annotations

import argparse
import copy
import os
import re
import stat
from pathlib import Path
from typing import Any

import yaml

from factory.config import FactoryConfig, validate_config

_TELEGRAM_OWNER_PATTERN = re.compile(r"[1-9][0-9]{0,19}")


def _validated_owner_id(value: object) -> str:
    owner_id = str(value).strip()
    if _TELEGRAM_OWNER_PATTERN.fullmatch(owner_id) is None:
        raise ValueError("Telegram owner id must be one positive numeric identifier")
    return owner_id


def _resolve_owner_ids(stable: dict[str, Any], environment_path: Path) -> list[str]:
    configured = stable.get("telegram", {}).get("allowed_user_ids", [])
    if not isinstance(configured, list):
        raise TypeError("Stable Telegram owner ids must be a list")
    owner_ids = {_validated_owner_id(value) for value in configured}

    if environment_path.is_symlink():
        raise ValueError("Stable Telegram environment file must not be a symlink")
    if environment_path.exists():
        if not environment_path.is_file():
            raise ValueError("Stable Telegram environment path must be a regular file")
        mode = environment_path.stat().st_mode
        if os.name != "nt" and mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError("Stable Telegram environment file is writable by non-owner")
        environment_owners: list[str] = []
        for raw_line in environment_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            key, separator, raw_value = line.partition("=")
            if not separator or key.strip() != "FACTORY_TELEGRAM_OWNER_ID":
                continue
            value = raw_value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            environment_owners.append(_validated_owner_id(value))
        if len(environment_owners) > 1:
            raise ValueError("Stable Telegram environment defines owner more than once")
        owner_ids.update(environment_owners)

    if len(owner_ids) != 1:
        raise ValueError("Golden intake requires exactly one configured Telegram owner")
    return sorted(owner_ids)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-config", type=Path, required=True)
    parser.add_argument("--stable-config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--log-root", type=Path, required=True)
    parser.add_argument(
        "--stable-telegram-environment",
        type=Path,
        default=Path("/etc/hermes-factory/telegram.env"),
    )
    parser.add_argument("--admin-port", type=int, default=8990)
    args = parser.parse_args()
    candidate = yaml.safe_load(args.candidate_config.read_text(encoding="utf-8"))
    stable = yaml.safe_load(args.stable_config.read_text(encoding="utf-8"))
    if not isinstance(candidate, dict) or not isinstance(stable, dict):
        raise TypeError("Golden config sources must be objects")
    payload: dict[str, Any] = copy.deepcopy(candidate)
    owner_ids = _resolve_owner_ids(stable, args.stable_telegram_environment)
    payload["controller"].update(
        {
            "database_url": f"sqlite:///{(args.state_root / 'controller.db').as_posix()}",
            "max_active_products": 1,
            "max_active_workers": 1,
            "observation_seconds": 900,
        }
    )
    payload["paths"].update(
        {
            "state": str(args.state_root),
            "worktrees": str(args.state_root / "worktrees"),
            "logs": str(args.log_root),
        }
    )
    payload["telegram"].update(
        {"allowed_user_ids": [str(owner_ids[0])], "token_credential_name": "telegram-token"}
    )
    payload["network"].update({"admin_bind": "127.0.0.1", "admin_port": args.admin_port})
    payload["deployment"].update(
        {
            "current_vps_high_risk_production": False,
            "staging_root": str(args.state_root / "staging"),
            "production_helper": "/opt/hermes-factory-candidate/current/scripts/deploy/hermes-factory-golden-release.py",
            "rollback_helper": "",
            "qualification_manifest_root": "",
            "verifier_public_key_digest": "",
            "health_probe_url": f"http://127.0.0.1:{args.admin_port}/healthz",
            "production_target": {
                "mode": "isolated_candidate",
                "host": "golden-candidate.invalid",
                "install_root": str(args.state_root / "isolated-target"),
                "entrypoint": "disabled",
            },
        }
    )
    payload["backup"].update(
        {"offsite_configured": True, "proof_path": str(args.state_root / "backup-proof.json")}
    )
    errors = validate_config(FactoryConfig(payload, args.output))
    if errors:
        raise ValueError(errors[0])
    encoded = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    if args.output.exists() and args.output.read_text(encoding="utf-8") != encoded:
        raise ValueError("Golden config already exists with different content")
    args.output.write_text(encoded, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
