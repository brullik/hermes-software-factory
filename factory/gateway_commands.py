"""Pure Telegram command parser; no secrets or arbitrary shell input accepted."""

from __future__ import annotations

from dataclasses import dataclass

from .common import SECRET_PATTERNS


@dataclass(frozen=True)
class GatewayCommand:
    name: str
    argument: str | None


class GatewayCommandError(ValueError):
    pass


ALLOWED_COMMANDS = {"idea", "status", "projects", "pause", "resume", "cancel", "owner_action", "help"}


def parse_command(text: str) -> GatewayCommand:
    stripped = text.strip()
    if not stripped.startswith("/"):
        raise GatewayCommandError("Only structured slash commands are accepted")
    parts = stripped[1:].split(maxsplit=1)
    name = parts[0].split("@", maxsplit=1)[0].lower()
    if name not in ALLOWED_COMMANDS:
        raise GatewayCommandError(f"Unknown command: {name}")
    argument = parts[1].strip() if len(parts) == 2 else None
    candidate_text = argument or ""
    if any(pattern.search(candidate_text) for _, pattern in SECRET_PATTERNS):
        raise GatewayCommandError("Secret-like content is not accepted by the gateway")
    if name in {"status", "projects", "owner_action", "help"} and argument:
        raise GatewayCommandError(f"/{name} takes no argument")
    if name in {"pause", "resume", "cancel"} and not argument:
        raise GatewayCommandError(f"/{name} requires a product id")
    if name == "idea" and not argument:
        raise GatewayCommandError("/idea requires text")
    return GatewayCommand(name, argument)
