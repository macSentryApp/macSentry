"""Security check implementations for macOS security audit."""
from __future__ import annotations

from importlib import import_module
from typing import Iterable

from .base import CheckRegistry, SecurityCheck

_CHECK_MODULES: tuple[str, ...] = (
    "encryption",
    "firewall",
    "system_integrity",
    "authentication",
    "privacy",
    "applications",
    "configuration",
)


def load_checks() -> Iterable[type[SecurityCheck]]:
    """Import all check modules to populate the registry."""

    for module_name in _CHECK_MODULES:
        import_module(f"{__name__}.{module_name}")
    return CheckRegistry.get_all()
