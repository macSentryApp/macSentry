"""Core architectural components for macos-security-audit.

This module provides:
- Strict layer separation (detection, reporting, remediation)
- Dependency injection for OS interactions
- Circuit breakers for resource protection
- Graceful degradation patterns
"""

from core.interfaces import (
    DetectionLayer,
    ReportingLayer,
    RemediationLayer,
    OSInterface,
)
from core.injection import DependencyContainer, get_container
from core.circuit_breaker import CircuitBreaker, CircuitState
from core.resilience import with_graceful_degradation, CheckExecutor

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
