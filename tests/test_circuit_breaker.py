"""Unit tests for circuit breaker implementation."""
from __future__ import annotations

import time
import unittest
from unittest.mock import MagicMock

from macsentry.core.circuit_breaker import CircuitBreaker, CircuitState, CircuitStats


class TestCircuitBreaker(unittest.TestCase):
    """Test circuit breaker functionality."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.breaker = CircuitBreaker(
            failure_threshold=3,
            reset_timeout=1.0,  # Short for testing
            success_threshold=1,
        )

    def test_initial_state_is_closed(self) -> None:
        """Circuit should start in closed state."""
        state = self.breaker.get_state("test_circuit")
        self.assertEqual(state, CircuitState.CLOSED)

    def test_can_execute_when_closed(self) -> None:
        """Should allow execution when circuit is closed."""
        self.assertTrue(self.breaker.can_execute("test_circuit"))

    def test_opens_after_failure_threshold(self) -> None:
        """Circuit should open after consecutive failures."""
        circuit_id = "failing_check"

        # Record failures up to threshold
        for _ in range(3):
            self.breaker.record_failure(circuit_id)

        state = self.breaker.get_state(circuit_id)
        self.assertEqual(state, CircuitState.OPEN)
        self.assertFalse(self.breaker.can_execute(circuit_id))

    def test_success_resets_failure_count(self) -> None:
        """Success should reset consecutive failure count."""
        circuit_id = "mixed_check"

        # Two failures
        self.breaker.record_failure(circuit_id)
        self.breaker.record_failure(circuit_id)

        # One success resets
        self.breaker.record_success(circuit_id)

        # Two more failures shouldn't open circuit (only 2 consecutive)
        self.breaker.record_failure(circuit_id)
        self.breaker.record_failure(circuit_id)

        state = self.breaker.get_state(circuit_id)
        self.assertEqual(state, CircuitState.CLOSED)

    def test_transitions_to_half_open_after_timeout(self) -> None:
        """Circuit should transition to half-open after reset timeout."""
        circuit_id = "timeout_check"

        # Open the circuit
        for _ in range(3):
            self.breaker.record_failure(circuit_id)

        self.assertEqual(self.breaker.get_state(circuit_id), CircuitState.OPEN)

        # Wait for reset timeout
        time.sleep(1.1)

        # Should now be half-open
        self.assertEqual(self.breaker.get_state(circuit_id), CircuitState.HALF_OPEN)
        self.assertTrue(self.breaker.can_execute(circuit_id))

    def test_closes_after_success_in_half_open(self) -> None:
        """Circuit should close after success in half-open state."""
        circuit_id = "recovery_check"

        # Open the circuit
        for _ in range(3):
            self.breaker.record_failure(circuit_id)

        # Wait for half-open
        time.sleep(1.1)
        self.assertEqual(self.breaker.get_state(circuit_id), CircuitState.HALF_OPEN)

        # Record success
        self.breaker.record_success(circuit_id)

        # Should be closed now
        self.assertEqual(self.breaker.get_state(circuit_id), CircuitState.CLOSED)

    def test_reopens_on_failure_in_half_open(self) -> None:
        """Circuit should reopen on failure in half-open state."""
        circuit_id = "relapse_check"

        # Open the circuit
        for _ in range(3):
            self.breaker.record_failure(circuit_id)

        # Wait for half-open
        time.sleep(1.1)
        self.assertEqual(self.breaker.get_state(circuit_id), CircuitState.HALF_OPEN)

        # Record failure
        self.breaker.record_failure(circuit_id)

        # Should be open again
        self.assertEqual(self.breaker.get_state(circuit_id), CircuitState.OPEN)

    def test_execute_with_success(self) -> None:
        """Execute should run operation and record success."""
        circuit_id = "execute_success"

        result = self.breaker.execute(
            circuit_id,
            operation=lambda: "success",
        )

        self.assertEqual(result, "success")
        stats = self.breaker.get_stats(circuit_id)
        self.assertEqual(stats.successes, 1)

    def test_execute_with_failure_and_fallback(self) -> None:
        """Execute should use fallback on failure."""
        circuit_id = "execute_fallback"

        def failing_operation() -> str:
            raise ValueError("Test error")

        result = self.breaker.execute(
            circuit_id,
            operation=failing_operation,
            fallback=lambda: "fallback_value",
        )

        self.assertEqual(result, "fallback_value")
        stats = self.breaker.get_stats(circuit_id)
        self.assertEqual(stats.failures, 1)

    def test_execute_returns_none_when_open_without_fallback(self) -> None:
        """Execute should return None when circuit is open and no fallback."""
        circuit_id = "open_no_fallback"

        # Open the circuit
        for _ in range(3):
            self.breaker.record_failure(circuit_id)

        result = self.breaker.execute(
            circuit_id,
            operation=lambda: "should_not_run",
        )

        self.assertIsNone(result)

    def test_stats_tracking(self) -> None:
        """Should track statistics correctly."""
        circuit_id = "stats_check"

        self.breaker.record_success(circuit_id)
        self.breaker.record_success(circuit_id)
        self.breaker.record_failure(circuit_id)

        stats = self.breaker.get_stats(circuit_id)
        self.assertEqual(stats.successes, 2)
        self.assertEqual(stats.failures, 1)
        self.assertEqual(stats.total_calls, 3)
        self.assertEqual(stats.consecutive_failures, 1)
        self.assertEqual(stats.consecutive_successes, 0)

    def test_reset_circuit(self) -> None:
        """Reset should clear circuit state."""
        circuit_id = "reset_check"

        # Add some state
        for _ in range(3):
            self.breaker.record_failure(circuit_id)

        self.assertEqual(self.breaker.get_state(circuit_id), CircuitState.OPEN)

        # Reset
        self.breaker.reset(circuit_id)

        # Should be back to initial state
        self.assertEqual(self.breaker.get_state(circuit_id), CircuitState.CLOSED)
        stats = self.breaker.get_stats(circuit_id)
        self.assertEqual(stats.failures, 0)


class TestCircuitBreakerTimeout(unittest.TestCase):
    """Test circuit breaker timeout handling."""

    def test_timeout_counts_as_failure_by_default(self) -> None:
        """Timeouts should count toward failure threshold by default."""
        breaker = CircuitBreaker(
            failure_threshold=2,
            timeout_counts_as_failure=True,
        )

        breaker.record_failure("test", is_timeout=True)
        breaker.record_failure("test", is_timeout=True)

        self.assertEqual(breaker.get_state("test"), CircuitState.OPEN)

    def test_timeout_can_be_excluded(self) -> None:
        """Timeouts can be configured to not count as failures."""
        breaker = CircuitBreaker(
            failure_threshold=2,
            timeout_counts_as_failure=False,
        )

        breaker.record_failure("test", is_timeout=True)
        breaker.record_failure("test", is_timeout=True)

        # Should still be closed since timeouts don't count
        self.assertEqual(breaker.get_state("test"), CircuitState.CLOSED)


if __name__ == "__main__":
    unittest.main()
