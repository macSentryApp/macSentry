"""Resilience patterns for graceful degradation.

This module provides utilities to ensure the audit script continues
running even when individual checks fail. Key principles:

1. No single check failure should crash the entire audit
2. Errors are captured and reported, not propagated
3. Resource limits (time, memory) are enforced
4. Clear distinction between expected failures and bugs

Usage:
    executor = CheckExecutor(circuit_breaker=breaker, container=container)
    results = executor.execute_all(checks)
    # All checks run, failures are captured in results
"""
from __future__ import annotations

import functools
import logging
import signal
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, TypeVar

from .circuit_breaker import CircuitBreaker, CircuitState, get_circuit_breaker
from .injection import DependencyContainer, get_container
from .interfaces import DetectionLayer, Finding

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class ExecutionResult:
    """Result of executing a check with resilience wrapper."""

    finding: Optional[Finding]
    execution_time_ms: float
    error: Optional[str] = None
    error_type: Optional[str] = None
    traceback: Optional[str] = None
    timed_out: bool = False
    circuit_open: bool = False


@dataclass
class ExecutorConfig:
    """Configuration for check execution."""

    # Timeout for individual checks (seconds)
    check_timeout: float = 30.0

    # Whether to use parallel execution
    parallel: bool = False

    # Maximum parallel workers
    max_workers: int = 4

    # Whether to continue on check errors
    continue_on_error: bool = True

    # Whether to use circuit breaker
    use_circuit_breaker: bool = True

    # Categories to skip entirely
    skip_categories: List[str] = field(default_factory=list)

    # Specific check IDs to skip
    skip_checks: List[str] = field(default_factory=list)


def with_graceful_degradation(
    default_return: T,
    log_errors: bool = True,
    error_message: str = "Operation failed",
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator for graceful degradation on errors.

    Wraps a function to catch all exceptions and return a default
    value instead of propagating the error.

    Args:
        default_return: Value to return on error
        log_errors: Whether to log caught errors
        error_message: Message to log with errors

    Returns:
        Decorated function that won't raise exceptions
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                if log_errors:
                    logger.error(
                        "%s: %s - %s",
                        error_message,
                        type(exc).__name__,
                        str(exc),
                    )
                    logger.debug("Traceback: %s", traceback.format_exc())
                return default_return

        return wrapper

    return decorator


def with_timeout(
    timeout_seconds: float,
    default_return: Optional[T] = None,
) -> Callable[[Callable[..., T]], Callable[..., Optional[T]]]:
    """Decorator to enforce timeout on a function.

    Uses threading to implement timeout (signal-based doesn't work
    in all contexts).

    Args:
        timeout_seconds: Maximum execution time
        default_return: Value to return on timeout

    Returns:
        Decorated function with timeout enforcement
    """

    def decorator(func: Callable[..., T]) -> Callable[..., Optional[T]]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Optional[T]:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(func, *args, **kwargs)
                try:
                    return future.result(timeout=timeout_seconds)
                except FuturesTimeout:
                    logger.warning(
                        "Function %s timed out after %.1fs",
                        func.__name__,
                        timeout_seconds,
                    )
                    return default_return

        return wrapper

    return decorator


class CheckExecutor:
    """Executes security checks with resilience patterns.

    This executor ensures:
    1. Individual check failures don't crash the audit
    2. Timeouts are enforced
    3. Circuit breakers protect against repeated failures
    4. All errors are captured and reported
    """

    def __init__(
        self,
        config: Optional[ExecutorConfig] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
        container: Optional[DependencyContainer] = None,
    ) -> None:
        """Initialize the executor.

        Args:
            config: Execution configuration
            circuit_breaker: Circuit breaker instance (uses global if None)
            container: Dependency container (uses global if None)
        """
        self.config = config or ExecutorConfig()
        self.circuit_breaker = circuit_breaker or get_circuit_breaker()
        self.container = container or get_container()
        self._results: List[ExecutionResult] = []

    def execute_check(self, check: DetectionLayer) -> ExecutionResult:
        """Execute a single check with all resilience patterns.

        Args:
            check: The check to execute

        Returns:
            ExecutionResult with finding or error details
        """
        import time

        check_id = check.check_id
        start_time = time.time()

        # Check if we should skip this check
        if check_id in self.config.skip_checks:
            return ExecutionResult(
                finding=Finding(
                    check_id=check_id,
                    check_name=check.check_name,
                    passed=False,
                    severity=check.severity,
                    message="Check skipped by configuration",
                    skipped=True,
                    skip_reason="Configured to skip",
                ),
                execution_time_ms=0,
            )

        if check.category in self.config.skip_categories:
            return ExecutionResult(
                finding=Finding(
                    check_id=check_id,
                    check_name=check.check_name,
                    passed=False,
                    severity=check.severity,
                    message=f"Category '{check.category}' skipped",
                    skipped=True,
                    skip_reason=f"Category {check.category} disabled",
                ),
                execution_time_ms=0,
            )

        # Check circuit breaker
        if self.config.use_circuit_breaker:
            if not self.circuit_breaker.can_execute(check_id):
                elapsed = (time.time() - start_time) * 1000
                return ExecutionResult(
                    finding=Finding(
                        check_id=check_id,
                        check_name=check.check_name,
                        passed=False,
                        severity=check.severity,
                        message="Check temporarily disabled due to repeated failures",
                        skipped=True,
                        skip_reason="Circuit breaker open",
                    ),
                    execution_time_ms=elapsed,
                    circuit_open=True,
                )

        # Execute with timeout
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(check.detect, self.container.os)
                try:
                    finding = future.result(timeout=self.config.check_timeout)
                    elapsed = (time.time() - start_time) * 1000

                    # Record success with circuit breaker
                    if self.config.use_circuit_breaker:
                        self.circuit_breaker.record_success(check_id)

                    return ExecutionResult(
                        finding=finding,
                        execution_time_ms=elapsed,
                    )

                except FuturesTimeout:
                    elapsed = (time.time() - start_time) * 1000

                    # Record timeout with circuit breaker
                    if self.config.use_circuit_breaker:
                        self.circuit_breaker.record_failure(check_id, is_timeout=True)

                    return ExecutionResult(
                        finding=Finding(
                            check_id=check_id,
                            check_name=check.check_name,
                            passed=False,
                            severity=check.severity,
                            message=f"Check timed out after {self.config.check_timeout}s",
                            error=f"Timeout after {self.config.check_timeout}s",
                        ),
                        execution_time_ms=elapsed,
                        timed_out=True,
                        error="Timeout",
                        error_type="TimeoutError",
                    )

        except Exception as exc:
            elapsed = (time.time() - start_time) * 1000

            # Record failure with circuit breaker
            if self.config.use_circuit_breaker:
                self.circuit_breaker.record_failure(check_id, is_timeout=False)

            return ExecutionResult(
                finding=Finding(
                    check_id=check_id,
                    check_name=check.check_name,
                    passed=False,
                    severity=check.severity,
                    message=f"Check failed with error: {exc}",
                    error=str(exc),
                ),
                execution_time_ms=elapsed,
                error=str(exc),
                error_type=type(exc).__name__,
                traceback=traceback.format_exc(),
            )

    def execute_all(
        self,
        checks: Iterable[DetectionLayer],
    ) -> List[ExecutionResult]:
        """Execute all checks with graceful degradation.

        All checks will be attempted regardless of individual failures.

        Args:
            checks: Checks to execute

        Returns:
            List of ExecutionResults for all checks
        """
        results: List[ExecutionResult] = []
        checks_list = list(checks)

        if self.config.parallel and len(checks_list) > 1:
            # Parallel execution
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                futures = {
                    executor.submit(self.execute_check, check): check
                    for check in checks_list
                }
                for future in futures:
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as exc:
                        # This shouldn't happen since execute_check catches all errors
                        check = futures[future]
                        results.append(
                            ExecutionResult(
                                finding=Finding(
                                    check_id=check.check_id,
                                    check_name=check.check_name,
                                    passed=False,
                                    severity=check.severity,
                                    message=f"Unexpected executor error: {exc}",
                                    error=str(exc),
                                ),
                                execution_time_ms=0,
                                error=str(exc),
                                error_type=type(exc).__name__,
                            )
                        )
        else:
            # Sequential execution
            for check in checks_list:
                result = self.execute_check(check)
                results.append(result)

                # Log progress
                if result.finding:
                    status = "PASS" if result.finding.passed else "FAIL"
                    if result.finding.skipped:
                        status = "SKIP"
                    if result.finding.error:
                        status = "ERROR"
                    logger.debug(
                        "[%s] %s - %.1fms",
                        status,
                        result.finding.check_name,
                        result.execution_time_ms,
                    )

        self._results = results
        return results

    def get_summary(self) -> Dict[str, Any]:
        """Get execution summary statistics.

        Returns:
            Dictionary with execution statistics
        """
        total = len(self._results)
        passed = sum(1 for r in self._results if r.finding and r.finding.passed)
        failed = sum(
            1
            for r in self._results
            if r.finding and not r.finding.passed and not r.finding.skipped and not r.finding.error
        )
        skipped = sum(1 for r in self._results if r.finding and r.finding.skipped)
        errors = sum(1 for r in self._results if r.finding and r.finding.error)
        timeouts = sum(1 for r in self._results if r.timed_out)
        circuit_opens = sum(1 for r in self._results if r.circuit_open)

        total_time = sum(r.execution_time_ms for r in self._results)

        return {
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "errors": errors,
            "timeouts": timeouts,
            "circuit_breaker_skips": circuit_opens,
            "total_execution_time_ms": total_time,
            "average_time_ms": total_time / total if total > 0 else 0,
        }
