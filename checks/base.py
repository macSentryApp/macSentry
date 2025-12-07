"""Base classes and utilities for macOS security checks."""
from __future__ import annotations

import abc
import logging
import platform
import sys
from typing import Any, ClassVar, Dict, Iterable, List, Optional, Tuple, Type

from .types import CheckResult, Severity, Status

logger = logging.getLogger(__name__)

# Late import to avoid circular dependency
_hardware_info = None
_environment_info = None


def _get_hardware_info():
    """Lazy load hardware info to avoid circular imports."""
    global _hardware_info
    if _hardware_info is None:
        from utils.system_info import get_hardware_info
        _hardware_info = get_hardware_info()
    return _hardware_info


def _get_environment_info():
    """Lazy load environment info to avoid circular imports."""
    global _environment_info
    if _environment_info is None:
        from utils.system_info import get_environment_info
        _environment_info = get_environment_info()
    return _environment_info


class CheckRegistry:
    """Registry for all security checks."""

    _registry: ClassVar[Dict[str, Type["SecurityCheck"]]] = {}

    @classmethod
    def register(cls, check_cls: Type["SecurityCheck"]) -> None:
        name = check_cls.name
        if not name:
            raise ValueError(f"Security check {check_cls.__name__} must define a name")
        if name in cls._registry:
            raise ValueError(f"Duplicate check name registered: {name}")
        cls._registry[name] = check_cls
        logger.debug("Registered security check: %s", name)

    @classmethod
    def get_all(cls) -> Iterable[Type["SecurityCheck"]]:
        return cls._registry.values()

    @classmethod
    def by_category(cls, categories: Iterable[str]) -> Iterable[Type["SecurityCheck"]]:
        selected = {cat.lower().strip() for cat in categories}
        for check_cls in cls._registry.values():
            if check_cls.category.lower() in selected:
                yield check_cls

    @classmethod
    def clear(cls) -> None:
        cls._registry.clear()


class SecurityCheckMeta(abc.ABCMeta):
    """Metaclass that auto-registers concrete security checks."""

    def __new__(mcls, name: str, bases: Tuple[type, ...], namespace: Dict[str, Any]):
        cls = super().__new__(mcls, name, bases, namespace)
        auto_register = getattr(cls, "auto_register", True)
        if auto_register and not inspect_is_abstract(cls):
            CheckRegistry.register(cls)
        return cls


def inspect_is_abstract(cls: Type["SecurityCheck"]) -> bool:
    """Helper to determine whether a class is abstract."""

    abstract_methods = getattr(cls, "__abstractmethods__", set())
    return bool(abstract_methods)


class SecurityCheck(metaclass=SecurityCheckMeta):
    """Base class for all macOS security checks."""

    auto_register: ClassVar[bool] = True
    name: str = ""
    description: str = ""
    category: str = "general"
    severity: Severity = Severity.INFO
    remediation: str = "Review system configuration."
    requires_sudo: bool = False
    min_version: Optional[Tuple[int, int, int]] = None
    max_version: Optional[Tuple[int, int, int]] = None  # Exclude checks for newer OS
    timeout: int = 5
    
    # Hardware requirements
    requires_apple_silicon: bool = False  # Only run on Apple Silicon
    requires_intel: bool = False  # Only run on Intel Macs
    requires_t2_or_secure_enclave: bool = False  # Requires T2 chip or Apple Silicon
    requires_portable: bool = False  # Only for laptops (MacBooks)
    requires_builtin_camera: bool = False  # Only if device has built-in camera
    requires_builtin_mic: bool = False  # Only if device has built-in mic
    
    # Environment requirements
    requires_network: bool = False  # Requires network connectivity
    skip_if_mdm: bool = False  # Skip on MDM-managed Macs (policies may override)

    def __init__(self) -> None:
        self._macos_version = self._get_macos_version()

    @staticmethod
    def _get_macos_version() -> Tuple[int, int, int]:
        version_str = platform.mac_ver()[0]
        if not version_str:
            return (0, 0, 0)
        parts = version_str.split(".")
        try:
            major, minor, *rest = parts
            patch = rest[0] if rest else "0"
            return (int(major), int(minor), int(patch))
        except (ValueError, IndexError):
            logger.debug("Failed to parse macOS version from '%s'", version_str)
            return (0, 0, 0)

    def is_applicable(self) -> bool:
        """Check if this check is applicable to the current system.
        
        Validates macOS version, hardware requirements, and environment.
        """
        # Version checks
        if self.min_version and self._macos_version < self.min_version:
            return False
        if self.max_version and self._macos_version > self.max_version:
            return False
        
        # Hardware checks
        hw = _get_hardware_info()
        if self.requires_apple_silicon and hw.chip_type != "apple_silicon":
            return False
        if self.requires_intel and hw.chip_type != "intel":
            return False
        if self.requires_t2_or_secure_enclave and not hw.has_secure_enclave:
            return False
        if self.requires_portable and not hw.is_portable:
            return False
        if self.requires_builtin_camera and not hw.has_builtin_camera:
            return False
        if self.requires_builtin_mic and not hw.has_builtin_mic:
            return False
        
        # Environment checks
        env = _get_environment_info()
        if self.requires_network and not env.is_network_available:
            return False
        if self.skip_if_mdm and env.is_mdm_enrolled:
            return False
        
        return True
    
    def get_skip_reason(self) -> Optional[str]:
        """Get reason why check would be skipped, if any."""
        if self.min_version and self._macos_version < self.min_version:
            return f"Requires macOS {'.'.join(map(str, self.min_version))} or later"
        if self.max_version and self._macos_version > self.max_version:
            return f"Not applicable for macOS versions after {'.'.join(map(str, self.max_version))}"
        
        hw = _get_hardware_info()
        if self.requires_apple_silicon and hw.chip_type != "apple_silicon":
            return "Requires Apple Silicon Mac"
        if self.requires_intel and hw.chip_type != "intel":
            return "Requires Intel Mac"
        if self.requires_t2_or_secure_enclave and not hw.has_secure_enclave:
            return "Requires Mac with T2 chip or Apple Silicon"
        if self.requires_portable and not hw.is_portable:
            return "Only applicable to MacBook laptops"
        if self.requires_builtin_camera and not hw.has_builtin_camera:
            return "Requires built-in camera (not available on this Mac)"
        if self.requires_builtin_mic and not hw.has_builtin_mic:
            return "Requires built-in microphone (not available on this Mac)"
        
        env = _get_environment_info()
        if self.requires_network and not env.is_network_available:
            return "Requires network connectivity"
        if self.skip_if_mdm and env.is_mdm_enrolled:
            return f"Skipped on MDM-managed Mac ({env.mdm_server or 'MDM enrolled'})"
        
        return None

    @abc.abstractmethod
    def run(self) -> CheckResult:
        """Execute the security check."""

    def execute(self) -> CheckResult:
        logger.debug("Executing check %s", self.name)
        if not self.is_applicable():
            skip_reason = self.get_skip_reason() or "Check not applicable for this system"
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message=skip_reason,
                remediation=self.remediation,
                details={
                    "current_version": ".".join(map(str, self._macos_version)),
                    "min_version": ".".join(map(str, self.min_version)) if self.min_version else None,
                    "max_version": ".".join(map(str, self.max_version)) if self.max_version else None,
                },
                category=self.category,
            )

        if self.requires_sudo and not self._is_root():
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Requires elevated privileges. Re-run with sudo or --elevated flag.",
                remediation=self.remediation,
                details={"requires_sudo": True},
                category=self.category,
            )

        try:
            result = self.run()
            if result.check_name != self.name:
                result.check_name = self.name
            # Always populate category from the check class
            result.category = self.category
            return result
        except Exception as exc:  # noqa: BLE001 - broad to ensure resiliency
            logger.exception("Unhandled error during check %s", self.name)
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message=str(exc),
                remediation=self.remediation,
                details={"exception_type": type(exc).__name__},
                category=self.category,
            )

    @staticmethod
    def _is_root() -> bool:
        if hasattr(sys, "getuid"):
            try:
                return sys.getuid() == 0
            except OSError:
                return False
        return False

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r}, severity={self.severity.value})"
