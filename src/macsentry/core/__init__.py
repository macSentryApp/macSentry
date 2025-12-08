"""Core architectural components for macos-security-audit.

This module provides:
- Strict layer separation (detection, reporting, remediation)
- Dependency injection for OS interactions
- Circuit breakers for resource protection
- Graceful degradation patterns
"""

from .interfaces import (
    DetectionLayer,
    ReportingLayer,
    RemediationLayer,
    OSInterface,
)
from .injection import DependencyContainer, get_container
from .circuit_breaker import CircuitBreaker, CircuitState
from .resilience import with_graceful_degradation, CheckExecutor

__all__ = [
    # Interfaces
    "DetectionLayer",
    "ReportingLayer",
    "RemediationLayer",
    "OSInterface",
    # Dependency Injection
    "DependencyContainer",
    "get_container",
    # Circuit Breaker
    "CircuitBreaker",
    "CircuitState",
    # Resilience
    "with_graceful_degradation",
    "CheckExecutor",
]
