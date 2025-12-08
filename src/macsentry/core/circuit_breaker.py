"""Circuit breaker pattern for protecting against hanging or resource-heavy checks.

The circuit breaker prevents cascading failures by:
1. Tracking failures for each check
2. "Opening" the circuit after too many failures (skipping the check)
3. Periodically allowing a test request to see if the issue is resolved
4. "Closing" the circuit when the check succeeds again

States:
- CLOSED: Normal operation, requests pass through
- OPEN: Circuit tripped, requests fail immediately
- HALF_OPEN: Testing if the issue is resolved

Usage:
    breaker = CircuitBreaker(failure_threshold=3, reset_timeout=60.0)

    if breaker.can_execute("filevault_check"):
        try:
            result = run_check()
            breaker.record_success("filevault_check")
        except Exception as e:
            breaker.record_failure("filevault_check")
    else:
        # Circuit is open, skip this check
        pass
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, Optional, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitState(Enum):
    """State of a circuit breaker."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, rejecting requests
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitStats:
    """Statistics for a single circuit."""

    failures: int = 0
    successes: int = 0
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None
    state: CircuitState = CircuitState.CLOSED
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    total_calls: int = 0
    total_timeouts: int = 0


@dataclass
class CircuitBreaker:
    """Circuit breaker for protecting checks against cascading failures.

    Attributes:
        failure_threshold: Number of consecutive failures before opening circuit
        reset_timeout: Seconds to wait before testing if circuit can close
        success_threshold: Successes needed in half-open state to close circuit
        timeout_counts_as_failure: Whether timeouts count toward failure threshold
    """

    failure_threshold: int = 3
    reset_timeout: float = 60.0
    success_threshold: int = 1
    timeout_counts_as_failure: bool = True

    _circuits: Dict[str, CircuitStats] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _get_circuit(self, circuit_id: str) -> CircuitStats:
        """Get or create circuit stats for an ID."""
        if circuit_id not in self._circuits:
            self._circuits[circuit_id] = CircuitStats()
        return self._circuits[circuit_id]

    def get_state(self, circuit_id: str) -> CircuitState:
        """Get the current state of a circuit.

        Args:
            circuit_id: Identifier for the circuit

        Returns:
            Current CircuitState
        """
        with self._lock:
            circuit = self._get_circuit(circuit_id)
            self._update_state(circuit)
            return circuit.state

    def _update_state(self, circuit: CircuitStats) -> None:
        """Update circuit state based on current conditions."""
        if circuit.state == CircuitState.OPEN:
            # Check if we should transition to half-open
            if circuit.last_failure_time is not None:
                elapsed = time.time() - circuit.last_failure_time
                if elapsed >= self.reset_timeout:
                    circuit.state = CircuitState.HALF_OPEN
                    circuit.consecutive_successes = 0
                    logger.debug("Circuit transitioning to HALF_OPEN")

    def can_execute(self, circuit_id: str) -> bool:
        """Check if a request can be executed.

        Args:
            circuit_id: Identifier for the circuit

        Returns:
            True if the request should be allowed
        """
        with self._lock:
            circuit = self._get_circuit(circuit_id)
            self._update_state(circuit)

            if circuit.state == CircuitState.CLOSED:
                return True
            elif circuit.state == CircuitState.OPEN:
                return False
            else:  # HALF_OPEN
                # Allow one test request
                return True

    def record_success(self, circuit_id: str) -> None:
        """Record a successful execution.

        Args:
            circuit_id: Identifier for the circuit
        """
        with self._lock:
            circuit = self._get_circuit(circuit_id)
            circuit.successes += 1
            circuit.total_calls += 1
            circuit.consecutive_successes += 1
            circuit.consecutive_failures = 0
            circuit.last_success_time = time.time()

            if circuit.state == CircuitState.HALF_OPEN:
                if circuit.consecutive_successes >= self.success_threshold:
                    circuit.state = CircuitState.CLOSED
                    logger.info("Circuit %s closed after recovery", circuit_id)

    def record_failure(self, circuit_id: str, is_timeout: bool = False) -> None:
        """Record a failed execution.

        Args:
            circuit_id: Identifier for the circuit
            is_timeout: Whether this failure was due to timeout
        """
        with self._lock:
            circuit = self._get_circuit(circuit_id)
            circuit.failures += 1
            circuit.total_calls += 1
            circuit.consecutive_failures += 1
            circuit.consecutive_successes = 0
            circuit.last_failure_time = time.time()

            if is_timeout:
                circuit.total_timeouts += 1
                if not self.timeout_counts_as_failure:
                    return

            if circuit.state == CircuitState.HALF_OPEN:
                # Failed during recovery test, go back to open
                circuit.state = CircuitState.OPEN
                logger.warning("Circuit %s re-opened after failed recovery", circuit_id)
            elif circuit.consecutive_failures >= self.failure_threshold:
                circuit.state = CircuitState.OPEN
                logger.warning(
                    "Circuit %s opened after %d consecutive failures",
                    circuit_id,
                    circuit.consecutive_failures,
                )

    def get_stats(self, circuit_id: str) -> CircuitStats:
        """Get statistics for a circuit.

        Args:
            circuit_id: Identifier for the circuit

        Returns:
            CircuitStats for the circuit
        """
        with self._lock:
            return self._get_circuit(circuit_id)

    def reset(self, circuit_id: str) -> None:
        """Reset a circuit to initial state.

        Args:
            circuit_id: Identifier for the circuit
        """
        with self._lock:
            self._circuits[circuit_id] = CircuitStats()

    def reset_all(self) -> None:
        """Reset all circuits to initial state."""
        with self._lock:
            self._circuits.clear()

    def execute(
        self,
        circuit_id: str,
        operation: Callable[[], T],
        fallback: Optional[Callable[[], T]] = None,
    ) -> Optional[T]:
        """Execute an operation with circuit breaker protection.

        Args:
            circuit_id: Identifier for the circuit
            operation: The operation to execute
            fallback: Optional fallback if circuit is open

        Returns:
            Result of operation, fallback, or None

        Raises:
            Exception: Re-raises if no fallback and operation fails
        """
        if not self.can_execute(circuit_id):
            logger.debug("Circuit %s is open, using fallback", circuit_id)
            if fallback:
                return fallback()
            return None

        try:
            result = operation()
            self.record_success(circuit_id)
            return result
        except TimeoutError:
            self.record_failure(circuit_id, is_timeout=True)
            if fallback:
                return fallback()
            raise
        except Exception:
            self.record_failure(circuit_id, is_timeout=False)
            if fallback:
                return fallback()
            raise


# Global circuit breaker instance
_global_breaker: Optional[CircuitBreaker] = None


def get_circuit_breaker() -> CircuitBreaker:
    """Get the global circuit breaker instance."""
    global _global_breaker
    if _global_breaker is None:
        _global_breaker = CircuitBreaker()
    return _global_breaker


def set_circuit_breaker(breaker: CircuitBreaker) -> None:
    """Set the global circuit breaker (for testing)."""
    global _global_breaker
    _global_breaker = breaker
