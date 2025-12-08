"""Compatibility helpers for Python version differences."""
from __future__ import annotations

import sys
from dataclasses import dataclass as _dataclass
from typing import Any, Callable, TypeVar

_F = TypeVar("_F", bound=Callable[..., Any])


def dataclass(*args: Any, **kwargs: Any) -> Callable[[ _F], _F]:
    """Wrapper for dataclasses.dataclass that ignores slots on <3.10."""

    if sys.version_info < (3, 10):
        kwargs.pop("slots", None)
    return _dataclass(*args, **kwargs)
