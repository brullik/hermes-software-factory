#!/usr/bin/env python3
"""Run one durable Codex VPS supervisor instance from a strict JSON config."""

from __future__ import annotations

import argparse
from pathlib import Path

from factory.codex_owner_actions import CodexOwnerActionStore
from factory.codex_supervisor import CodexSupervisor, SupervisorConfig


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    config = SupervisorConfig.load(args.config.resolve(strict=True))
    notifications = CodexOwnerActionStore(config.owner_action_db)
    try:
        return CodexSupervisor(config, notification_store=notifications).run_until_stable()
    finally:
        notifications.close()


if __name__ == "__main__":
    raise SystemExit(main())
