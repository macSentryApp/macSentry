"""Core types for security checks - no external dependencies."""
from __future__ import annotations

import sys
from dataclasses import field
from enum import Enum
from typing import Any, Dict

# Python 3.9 compatible dataclass wrapper
if sys.version_info >= (3, 10):
    from dataclasses import dataclass
else:
    from dataclasses import dataclass as _dataclass

    def dataclass(*args: Any, **kwargs: Any):
        kwargs.pop("slots", None)
        return _dataclass(*args, **kwargs)


class Severity(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(str, Enum):
    """Execution status for a security check."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    SKIP = "SKIP"
    ERROR = "ERROR"


# Category display names for human-readable output
CATEGORY_DISPLAY_NAMES: Dict[str, str] = {
    "system_integrity": "System Integrity",
    "authentication": "Authentication & Access",
    "encryption": "Encryption & Data Protection",
    "firewall": "Firewall & Network",
    "privacy": "Privacy & Permissions",
    "applications": "Applications",
    "configuration": "System Configuration",
    "general": "General",
}


@dataclass(slots=True)
class CheckResult:
    """Result object returned by every security check."""

    check_name: str
    status: Status
    severity: Severity
    message: str
    remediation: str
    details: Dict[str, Any] = field(default_factory=dict)
    category: str = "general"  # Check category for grouping in output
    
    @property
    def category_display_name(self) -> str:
        """Get human-readable category name."""
        return CATEGORY_DISPLAY_NAMES.get(self.category, self.category.replace("_", " ").title())
