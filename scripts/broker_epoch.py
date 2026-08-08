#!/usr/bin/env python3
"""Bind one broker credential copy to a non-secret stable epoch identifier."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from pathlib import Path


class BrokerEpochError(RuntimeError):
    """The broker credential copy or epoch target is unsafe."""


def install_epoch(source: Path, destination: Path) -> str:
    resolved = source.resolve()
    if (
        source.is_symlink()
        or not source.is_file()
        or not str(resolved).startswith("/run/credentials/")
        or source.stat().st_size < 8
        or source.stat().st_size > 64 * 1024
    ):
        raise BrokerEpochError("systemd credential copy is unsafe")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    epoch = "CE-" + digest[:32].upper()
    encoded = epoch + "\n"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.is_symlink():
            raise BrokerEpochError("broker epoch target is unsafe")
        if destination.read_text(encoding="ascii") == encoded:
            return epoch
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return epoch


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        epoch = install_epoch(args.input, args.output)
    except (OSError, UnicodeError, BrokerEpochError) as error:
        print(type(error).__name__, file=sys.stderr)
        return 1
    if not re.fullmatch(r"CE-[A-F0-9]{32}", epoch):
        return 1
    print("broker epoch installed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
