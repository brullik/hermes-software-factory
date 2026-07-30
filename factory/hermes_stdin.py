"""Bounded stdin launcher for the pinned Hermes one-shot runtime."""

from __future__ import annotations

import argparse
import importlib
import os
import re
import sys
from collections.abc import Callable
from typing import BinaryIO, NoReturn, cast

_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.:/-]+$")
_SAFE_TOOLSETS = re.compile(r"^[A-Za-z0-9_.:/-]+(?:,[A-Za-z0-9_.:/-]+)*$")


def read_stdin_prompt(stream: BinaryIO, *, max_input_bytes: int) -> str:
    """Read one UTF-8 prompt without allowing an unbounded stdin allocation."""

    if max_input_bytes < 1:
        raise ValueError("max_input_bytes must be positive")
    raw = stream.read(max_input_bytes + 1)
    if len(raw) > max_input_bytes:
        raise ValueError("stdin prompt exceeds the configured input byte limit")
    if not raw:
        raise ValueError("stdin prompt is empty")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("stdin prompt is not valid UTF-8") from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--toolsets", required=True)
    parser.add_argument("--usage-file")
    parser.add_argument("--max-input-bytes", required=True, type=int)
    parser.add_argument("--ignore-rules", action="store_true")
    return parser


def _invoke_hermes(
    prompt: str,
    *,
    model: str,
    provider: str,
    toolsets: str,
    usage_file: str | None,
    ignore_rules: bool,
) -> NoReturn:
    """Invoke the same pinned one-shot API used by the Hermes CLI."""

    if not _SAFE_NAME.fullmatch(model) or not _SAFE_NAME.fullmatch(provider):
        raise ValueError("provider and model identifiers contain unsafe characters")
    if not _SAFE_TOOLSETS.fullmatch(toolsets):
        raise ValueError("toolsets contain unsafe characters")
    if ignore_rules:
        os.environ["HERMES_IGNORE_RULES"] = "1"

    module = importlib.import_module("hermes_cli.main")
    prepare = cast(
        Callable[[argparse.Namespace], None],
        module._prepare_agent_startup,
    )
    run_oneshot = cast(
        Callable[..., NoReturn],
        module._run_and_exit_oneshot,
    )
    args = argparse.Namespace(
        command=None,
        yolo=False,
        safe_mode=False,
        accept_hooks=False,
        tui=False,
        cli=True,
        ignore_rules=ignore_rules,
        toolsets=toolsets,
    )
    prepare(args)
    run_oneshot(
        prompt,
        model=model,
        provider=provider,
        toolsets=toolsets,
        usage_file=usage_file,
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        prompt = read_stdin_prompt(
            sys.stdin.buffer,
            max_input_bytes=int(args.max_input_bytes),
        )
        _invoke_hermes(
            prompt,
            model=str(args.model),
            provider=str(args.provider),
            toolsets=str(args.toolsets),
            usage_file=str(args.usage_file) if args.usage_file else None,
            ignore_rules=bool(args.ignore_rules),
        )
    except (AttributeError, ImportError, OSError, TypeError, ValueError) as error:
        print(
            f"Hermes stdin launcher failed safely: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
