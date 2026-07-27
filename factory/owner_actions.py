"""Schema-valid OWNER_ACTION creation with duplicate suppression."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .common import new_id, sha256_text, utc_now
from .config import FactoryConfig
from .policy import owner_action_allowed


class OwnerActionService:
    def __init__(self, config: FactoryConfig) -> None:
        self.config = config
        self.root = config.evidence_dir
        self.root.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        *,
        reason: str,
        title: str,
        why_blocked: str,
        single_action: str,
        safe_instruction: list[str],
        unblock_probe: str,
        unblock_expected: str,
        independent_work_continues: list[str],
    ) -> Path:
        if not owner_action_allowed(self.config, reason):
            raise ValueError(f"OWNER_ACTION reason is not allowed by policy: {reason}")
        if len(safe_instruction) < 1 or not single_action.strip():
            raise ValueError("OWNER_ACTION needs exactly one action and a safe instruction")
        deduplication_key = sha256_text(f"{reason}:{single_action}:{unblock_probe}")
        path = self.root / f"owner-action-{deduplication_key[:16]}.json"
        schema = json.loads((self.config.schema_root() / "owner-action.schema.json").read_text(encoding="utf-8"))
        secret_warning = str(schema["properties"]["secret_warning"]["const"])
        artifact: dict[str, Any] = {
            "schema_version": "1.0",
            "action_id": new_id("owner-action"),
            "reason": reason,
            "title": title,
            "why_blocked": why_blocked,
            "single_action": single_action,
            "safe_instruction": safe_instruction,
            "unblock_condition": {"probe": unblock_probe, "expected": unblock_expected},
            "independent_work_continues": independent_work_continues,
            "secret_warning": secret_warning,
            "created_at": utc_now(),
            "deduplication_key": deduplication_key,
        }
        payload = json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if path.exists():
            existing = json.loads(path.read_text(encoding="utf-8"))
            if existing.get("deduplication_key") == deduplication_key:
                return path
            raise RuntimeError("OWNER_ACTION deduplication key already has different immutable content")
        path.write_text(payload, encoding="utf-8", newline="\n")
        return path
