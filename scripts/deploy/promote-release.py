#!/usr/bin/env python3
"""Promote a validated Hermes release through the transactional deploy adapter."""

# The source-tree import below is intentionally after the path bootstrap so
# this script works both from a checkout and from /opt/hermes-factory/current.
# ruff: noqa: I001

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from factory.deployment import DeploymentError, TransactionalDeployer


SERVICES = (
    "hermes-factory-controller.service",
    "hermes-factory-gateway.service",
    "hermes-factory-worker.service",
)
OPTIONAL_SERVICES = ("hermes-factory-worker-2.service",)


def validate_health_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("health URL must be an HTTP loopback URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("health URL must not contain credentials or query data")
    return value


def run_checked(argv: list[str], *, cwd: Path | None = None) -> None:
    completed = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"allowlisted command failed: {argv[0]}")


def validate_source(source: Path) -> None:
    if not source.is_dir() or source.is_symlink():
        raise DeploymentError("release source directory is missing or unsafe")
    checks = (
        ("verify_version_consistency.py", "--factory-source"),
        ("verify_manifest.py",),
        ("validate_package.py",),
    )
    for command in checks:
        name = command[0]
        script = source / "scripts" / name
        if not script.is_file() or script.is_symlink():
            raise DeploymentError(f"release validation script is missing: {name}")
        run_checked(
            [sys.executable, str(script), *command[1:]],
            cwd=source,
        )


def restart_services() -> None:
    installed_optional = tuple(
        service
        for service in OPTIONAL_SERVICES
        if (Path("/etc/systemd/system") / service).is_file()
    )
    run_checked(["systemctl", "restart", *SERVICES, *installed_optional])


def health_probe(url: str, attempts: int, delay_seconds: float) -> Callable[[Path], bool]:
    if attempts < 1:
        raise ValueError("health attempts must be positive")
    if delay_seconds < 0:
        raise ValueError("health delay cannot be negative")

    def probe(_current: Path) -> bool:
        for attempt in range(attempts):
            try:
                with urlopen(url, timeout=5) as response:
                    status = getattr(response, "status", None)
                    if isinstance(status, int) and 200 <= status < 400:
                        return True
            except (OSError, URLError, TimeoutError):
                pass
            if attempt + 1 < attempts:
                time.sleep(delay_seconds)
        return False

    return probe


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--install-root", default="/opt/hermes-factory", type=Path)
    parser.add_argument("--health-url", default="http://127.0.0.1:8787/healthz")
    parser.add_argument("--health-attempts", default=12, type=int)
    parser.add_argument("--health-delay", default=2.0, type=float)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        health_url = validate_health_url(args.health_url)
        source = args.source.resolve()
        validate_source(source)
        run_checked(["systemctl", "start", "hermes-factory-backup.service"])
        result = TransactionalDeployer(
            args.install_root,
            health_probe(health_url, args.health_attempts, args.health_delay),
            activate=restart_services,
        ).promote(args.release_id, source)
    except (DeploymentError, OSError, RuntimeError, ValueError) as error:
        print(json.dumps({"status": "FAILED_SAFE", "reason": type(error).__name__}))
        return 78
    print(json.dumps(result.__dict__, sort_keys=True))
    return 0 if result.status == "PROMOTED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
