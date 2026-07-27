"""Durable local runtime primitives for Hermes Software Factory.

The package deliberately keeps integrations behind adapters.  The controller can
therefore be started on a clean host before credentials for GitHub, Telegram, or
model providers are connected.
"""

from .config import FactoryConfig, load_config

__all__ = ["FactoryConfig", "load_config"]
