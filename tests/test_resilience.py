"""Unit tests for resilience patterns."""
from __future__ import annotations

import time
import unittest
from dataclasses import dataclass
from typing import Optional
from unittest.mock import MagicMock, patch

from macsentry.core.circuit_breaker import CircuitBreaker
from macsentry.core.injection import (
    CommandResult,
    DependencyContainer,
    MockOSInterface,
)
from macsentry.core.interfaces import DetectionLayer, Finding, OSInterface
from macsentry.core.resilience import (
    CheckExecutor,
    ExecutorConfig,
    with_graceful_degradation,
    with_timeout,
)


class MockCheck(DetectionLayer):
    """Mock check for testing."""

    def __init__(
        self,
        check_id: str = "mock_check",
        name: str = "Mock Check",
        should_pass: bool = True,
        should_raise: bool = False,
        delay: float = 0,
        category: str = "test",
    ) -> None:
        self._check_id = check_id
        self._name = name
        self._should_pass = should_pass
        self._should_raise = should_raise
        self._delay = delay
        self._category = category

    @property
    def check_id(self) -> str:
        return self._check_id

    @property
    def check_name(self) -> str:
        return self._name

    @property
    def severity(self) -> str:
        return "MEDIUM"

    @property
    def category(self) -> str:
        return self._category

    def detect(self, os_interface: OSInterface) -> Finding:
        if self._delay > 0:
            time.sleep(self._delay)

        if self._should_raise:
            raise RuntimeError("Simulated check failure")

        return Finding(
            check_id=self._check_id,
            check_name=self._name,
            passed=self._should_pass,
            severity="MEDIUM",
            message="Mock check completed",
        )


class TestGracefulDegradation(unittest.TestCase):
    """Test graceful degradation decorator."""

    def test_returns_value_on_success(self) -> None:
        """Should return function result on success."""

        @with_graceful_degradation(default_return="default")
        def successful_func() -> str:
            return "success"

        result = successful_func()
        self.assertEqual(result, "success")

    def test_returns_default_on_exception(self) -> None:
        """Should return default value on exception."""

        @with_graceful_degradation(default_return="default")
        def failing_func() -> str:
            raise ValueError("Test error")

        result = failing_func()
        self.assertEqual(result, "default")

    def test_logs_error_by_default(self) -> None:
        """Should log errors by default."""

        @with_graceful_degradation(default_return=None, log_errors=True)
        def failing_func() -> None:
            raise ValueError("Test error")

        with patch("core.resilience.logger") as mock_logger:
            failing_func()
            mock_logger.error.assert_called()


class TestTimeoutDecorator(unittest.TestCase):
    """Test timeout decorator."""

    def test_returns_value_within_timeout(self) -> None:
        """Should return value if function completes in time."""

        @with_timeout(timeout_seconds=1.0)
        def fast_func() -> str:
            return "fast"

        result = fast_func()
        self.assertEqual(result, "fast")

    def test_returns_default_on_timeout(self) -> None:
        """Should return default on timeout."""

        @with_timeout(timeout_seconds=0.1, default_return="timeout")
        def slow_func() -> str:
            time.sleep(1.0)
            return "slow"

        result = slow_func()
        self.assertEqual(result, "timeout")


class TestCheckExecutor(unittest.TestCase):
    """Test CheckExecutor functionality."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.mock_os = MockOSInterface()
        self.container = DependencyContainer(os_interface=self.mock_os)
        self.breaker = CircuitBreaker(failure_threshold=3)
        self.config = ExecutorConfig(
            check_timeout=5.0,
            parallel=False,
            use_circuit_breaker=True,
        )
        self.executor = CheckExecutor(
            config=self.config,
            circuit_breaker=self.breaker,
            container=self.container,
        )

    def test_execute_passing_check(self) -> None:
        """Should execute passing check successfully."""
        check = MockCheck(should_pass=True)

        result = self.executor.execute_check(check)

        self.assertIsNotNone(result.finding)
        self.assertTrue(result.finding.passed)
        self.assertIsNone(result.error)
        self.assertFalse(result.timed_out)

    def test_execute_failing_check(self) -> None:
        """Should execute failing check and capture result."""
        check = MockCheck(should_pass=False)

        result = self.executor.execute_check(check)

        self.assertIsNotNone(result.finding)
        self.assertFalse(result.finding.passed)

    def test_execute_erroring_check(self) -> None:
        """Should capture errors from checks."""
        check = MockCheck(should_raise=True)

        result = self.executor.execute_check(check)

        self.assertIsNotNone(result.finding)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.error_type, "RuntimeError")

    def test_execute_timeout(self) -> None:
        """Should handle check timeout."""
        config = ExecutorConfig(check_timeout=0.1)
        executor = CheckExecutor(
            config=config,
            circuit_breaker=self.breaker,
            container=self.container,
        )
        check = MockCheck(delay=1.0)

        result = executor.execute_check(check)

        self.assertTrue(result.timed_out)
        self.assertIn("timed out", result.finding.message.lower())

    def test_skip_by_check_id(self) -> None:
        """Should skip checks by ID."""
        config = ExecutorConfig(skip_checks=["skip_me"])
        executor = CheckExecutor(
            config=config,
            circuit_breaker=self.breaker,
            container=self.container,
        )
        check = MockCheck(check_id="skip_me")

        result = executor.execute_check(check)

        self.assertTrue(result.finding.skipped)
        self.assertIn("skipped", result.finding.message.lower())

    def test_skip_by_category(self) -> None:
        """Should skip checks by category."""
        config = ExecutorConfig(skip_categories=["dangerous"])
        executor = CheckExecutor(
            config=config,
            circuit_breaker=self.breaker,
            container=self.container,
        )
        check = MockCheck(category="dangerous")

        result = executor.execute_check(check)

        self.assertTrue(result.finding.skipped)

    def test_circuit_breaker_integration(self) -> None:
        """Should skip checks when circuit is open."""
        check = MockCheck(check_id="flaky_check", should_raise=True)

        # Trigger circuit breaker
        for _ in range(3):
            self.executor.execute_check(check)

        # Circuit should be open, check should be skipped
        result = self.executor.execute_check(check)

        self.assertTrue(result.circuit_open)
        self.assertTrue(result.finding.skipped)

    def test_execute_all_continues_on_error(self) -> None:
        """Should continue executing all checks even if some fail."""
        checks = [
            MockCheck(check_id="check1", should_pass=True),
            MockCheck(check_id="check2", should_raise=True),
            MockCheck(check_id="check3", should_pass=True),
        ]

        results = self.executor.execute_all(checks)

        self.assertEqual(len(results), 3)
        self.assertTrue(results[0].finding.passed)
        self.assertIsNotNone(results[1].error)
        self.assertTrue(results[2].finding.passed)

    def test_execute_all_parallel(self) -> None:
        """Should execute checks in parallel when configured."""
        config = ExecutorConfig(parallel=True, max_workers=2)
        executor = CheckExecutor(
            config=config,
            circuit_breaker=self.breaker,
            container=self.container,
        )
        checks = [
            MockCheck(check_id=f"check{i}", delay=0.1)
            for i in range(4)
        ]

        start = time.time()
        results = executor.execute_all(checks)
        elapsed = time.time() - start

        self.assertEqual(len(results), 4)
        # Parallel should be faster than sequential (4 * 0.1 = 0.4s)
        self.assertLess(elapsed, 0.35)

    def test_get_summary(self) -> None:
        """Should generate accurate summary statistics."""
        checks = [
            MockCheck(check_id="pass1", should_pass=True),
            MockCheck(check_id="pass2", should_pass=True),
            MockCheck(check_id="fail1", should_pass=False),
            MockCheck(check_id="error1", should_raise=True),
        ]

        self.executor.execute_all(checks)
        summary = self.executor.get_summary()

        self.assertEqual(summary["total_checks"], 4)
        self.assertEqual(summary["passed"], 2)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["errors"], 1)


class TestExecutorConfigDefaults(unittest.TestCase):
    """Test ExecutorConfig default values."""

    def test_default_timeout(self) -> None:
        """Default timeout should be reasonable."""
        config = ExecutorConfig()
        self.assertEqual(config.check_timeout, 30.0)

    def test_default_not_parallel(self) -> None:
        """Should default to sequential execution."""
        config = ExecutorConfig()
        self.assertFalse(config.parallel)

    def test_default_continue_on_error(self) -> None:
        """Should default to continuing on errors."""
        config = ExecutorConfig()
        self.assertTrue(config.continue_on_error)


if __name__ == "__main__":
    unittest.main()
