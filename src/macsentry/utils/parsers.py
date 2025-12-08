"""Parsers and helpers for interpreting macOS command outputs."""
from __future__ import annotations

import json
import plistlib
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

BOOLEAN_TRUE = {"1", "true", "yes", "on", "enabled"}
BOOLEAN_FALSE = {"0", "false", "no", "off", "disabled"}


def parse_defaults_bool(value: str | None) -> bool | None:
    """Interpret a defaults plist boolean-style output."""

    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in BOOLEAN_TRUE:
        return True
    if normalized in BOOLEAN_FALSE:
        return False
    return None


def parse_key_value_output(output: str) -> Mapping[str, str]:
    """Parse simple "Key: Value" outputs."""

    data: dict[str, str] = {}
    pattern = re.compile(r"^\s*([^:]+):\s*(.+)$")
    for line in output.splitlines():
        match = pattern.match(line)
        if match:
            key, value = match.groups()
            data[key.strip()] = value.strip()
    return data


def load_plist(path: Path) -> dict[str, Any] | None:
    """Load plist file if accessible."""

    try:
        if not path.exists():
            return None
        with path.open("rb") as handle:
            return plistlib.load(handle)
    except (plistlib.InvalidFileException, OSError):
        return None


def safe_json_loads(data: str) -> Any | None:
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return None


def pick_first(iterable: Iterable[Any]) -> Any | None:
    for item in iterable:
        return item
    return None
