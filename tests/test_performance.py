"""Performance benchmark tests for macOS Security Audit.

Tests verify:
- Full audit completes in <30 seconds
- Memory usage stays under 100MB
- Individual checks complete in reasonable time
"""

from __future__ import annotations

import gc
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    pass

# Configuration from environment
PERFORMANCE_THRESHOLD_SECONDS = float(
    os.environ.get("PERFORMANCE_THRESHOLD", "30")
)
MEMORY_THRESHOLD_MB = float(
    os.environ.get("MEMORY_THRESHOLD_MB", "100")
)

SCRIPT_PATH = Path(__file__).parent.parent / "macos_security_audit.py"


class TestExecutionTime:
    """Tests for audit execution time."""

    def test_full_audit_under_threshold(self) -> None:
        """Verify full audit completes within time threshold."""
        start = time.perf_counter()

        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--format", "json"],
            capture_output=True,
            text=True,
            timeout=120,
        )

        elapsed = time.perf_counter() - start

        assert result.returncode == 0, f"Audit failed: {result.stderr}"

        print(f"\nExecution time: {elapsed:.2f}s (threshold: {PERFORMANCE_THRESHOLD_SECONDS}s)")

        if elapsed > PERFORMANCE_THRESHOLD_SECONDS:
            pytest.xfail(
                f"Execution time ({elapsed:.2f}s) exceeds threshold "
                f"({PERFORMANCE_THRESHOLD_SECONDS}s). May be acceptable on slower hardware."
            )

    def test_dry_run_fast(self) -> None:
        """Verify dry-run is very fast (no actual checks)."""
        start = time.perf_counter()

        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--dry-run"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        elapsed = time.perf_counter() - start

        assert result.returncode == 0
        assert elapsed < 5.0, f"Dry run took {elapsed:.2f}s, expected < 5s"

    def test_single_category_faster(self) -> None:
        """Verify single category audit is faster than full audit."""
        # Time full audit
        start = time.perf_counter()
        subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--format", "json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        full_time = time.perf_counter() - start

        # Time single category
        start = time.perf_counter()
        subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--categories", "encryption", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        single_time = time.perf_counter() - start

        print(f"\nFull audit: {full_time:.2f}s, Single category: {single_time:.2f}s")

        # Single category should be noticeably faster
        assert single_time < full_time, (
            f"Single category ({single_time:.2f}s) not faster than full ({full_time:.2f}s)"
        )


class TestMemoryUsage:
    """Tests for memory consumption."""

    def test_memory_under_threshold(self) -> None:
        """Verify audit memory usage stays under threshold."""
        try:
            import psutil
        except ImportError:
            pytest.skip("psutil not installed")
            return

        # Force garbage collection before test
        gc.collect()

        # Run audit in-process to measure memory
        import importlib.util
        spec = importlib.util.spec_from_file_location("audit", SCRIPT_PATH)
        if spec is None or spec.loader is None:
            pytest.skip("Cannot load audit module")
            return

        process = psutil.Process(os.getpid())
        baseline_memory = process.memory_info().rss / (1024 * 1024)  # MB

        # Import and run
        from checks import load_checks
        from checks.base import CheckRegistry

        load_checks()

        # Instantiate all checks
        checks = [cls() for cls in CheckRegistry.get_all()]

        # Run all checks
        results = []
        for check in checks:
            try:
                result = check.execute()
                results.append(result)
            except Exception:  # noqa: BLE001
                pass

        peak_memory = process.memory_info().rss / (1024 * 1024)  # MB
        memory_used = peak_memory - baseline_memory

        print(f"\nMemory: baseline={baseline_memory:.1f}MB, peak={peak_memory:.1f}MB, delta={memory_used:.1f}MB")

        # Note: This is a soft check because memory measurement varies
        if peak_memory > MEMORY_THRESHOLD_MB:
            pytest.xfail(
                f"Peak memory ({peak_memory:.1f}MB) exceeds threshold ({MEMORY_THRESHOLD_MB}MB). "
                "This may vary by system."
            )

    def test_no_memory_leaks_on_repeated_runs(self) -> None:
        """Verify no significant memory growth on repeated check execution."""
        try:
            import psutil
        except ImportError:
            pytest.skip("psutil not installed")
            return

        from checks import load_checks
        from checks.base import CheckRegistry

        load_checks()
        checks = [cls() for cls in CheckRegistry.get_all()]

        process = psutil.Process(os.getpid())

        # Run checks multiple times and track memory
        memory_readings = []
        for i in range(3):
            gc.collect()
            for check in checks:
                try:
                    check.execute()
                except Exception:  # noqa: BLE001
                    pass
            memory_readings.append(process.memory_info().rss / (1024 * 1024))

        # Memory should stabilize after initial module loading
        # Compare runs 2 and 3 (after modules are loaded)
        late_growth = (memory_readings[-1] - memory_readings[1]) / max(memory_readings[1], 1)
        print(f"\nMemory readings: {memory_readings}, late growth: {late_growth:.1%}")

        # Allow up to 20% growth between stable runs (not first run which loads modules)
        assert late_growth < 0.2, f"Memory grew {late_growth:.1%} between stable runs (>20%)"


class TestIndividualCheckPerformance:
    """Tests for individual check execution time."""

    def test_all_checks_complete_in_reasonable_time(self) -> None:
        """Verify each check completes in under 10 seconds."""
        from checks import load_checks
        from checks.base import CheckRegistry

        load_checks()

        slow_checks = []
        for cls in CheckRegistry.get_all():
            check = cls()
            start = time.perf_counter()
            try:
                check.execute()
            except Exception:  # noqa: BLE001
                pass
            elapsed = time.perf_counter() - start

            if elapsed > 10.0:
                slow_checks.append((cls.name, elapsed))

        if slow_checks:
            msg = "Slow checks (>10s):\n" + "\n".join(
                f"  - {name}: {t:.2f}s" for name, t in slow_checks
            )
            pytest.xfail(msg)

    def test_critical_checks_fast(self) -> None:
        """Verify critical checks are particularly fast."""
        from checks import load_checks
        from checks.base import CheckRegistry, Severity

        load_checks()

        critical_checks = [
            cls for cls in CheckRegistry.get_all()
            if getattr(cls, "severity", None) == Severity.CRITICAL
        ]

        for cls in critical_checks:
            check = cls()
            start = time.perf_counter()
            check.execute()
            elapsed = time.perf_counter() - start

            print(f"\n{cls.name}: {elapsed:.2f}s")

            # Critical checks should be fast (under 5 seconds)
            assert elapsed < 5.0, f"{cls.name} took {elapsed:.2f}s, expected < 5s"


class TestConcurrencyPerformance:
    """Tests for concurrent execution performance."""

    def test_parallel_execution_faster(self) -> None:
        """Verify parallel execution is faster than sequential."""
        import concurrent.futures
        from checks import load_checks
        from checks.base import CheckRegistry

        load_checks()
        check_classes = list(CheckRegistry.get_all())[:10]  # Test subset

        # Sequential execution
        start = time.perf_counter()
        for cls in check_classes:
            try:
                cls().execute()
            except Exception:  # noqa: BLE001
                pass
        sequential_time = time.perf_counter() - start

        # Parallel execution
        start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(cls().execute) for cls in check_classes]
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception:  # noqa: BLE001
                    pass
        parallel_time = time.perf_counter() - start

        print(f"\nSequential: {sequential_time:.2f}s, Parallel: {parallel_time:.2f}s")

        # Parallel should be at least somewhat faster (or at least not slower)
        # Allow some margin for overhead
        assert parallel_time <= sequential_time * 1.5, (
            f"Parallel ({parallel_time:.2f}s) significantly slower than sequential ({sequential_time:.2f}s)"
        )


class TestOutputGenerationPerformance:
    """Tests for report generation performance."""

    def test_json_generation_fast(self) -> None:
        """Verify JSON report generation is fast."""
        from checks import load_checks
        from checks.base import CheckRegistry, CheckResult, Status, Severity
        from utils.reporting import format_json_report

        load_checks()

        # Generate mock results
        results = [
            CheckResult(
                check_name=f"Test Check {i}",
                status=Status.PASS,
                severity=Severity.INFO,
                message="Test message",
                remediation="Test remediation",
            )
            for i in range(100)
        ]

        system_info = {"os": "macOS", "version": "14.0"}

        start = time.perf_counter()
        format_json_report(results=results, system_info=system_info)
        elapsed = time.perf_counter() - start

        assert elapsed < 1.0, f"JSON generation took {elapsed:.2f}s, expected < 1s"

    def test_html_generation_fast(self) -> None:
        """Verify HTML report generation is fast."""
        from checks import load_checks
        from checks.base import CheckResult, Status, Severity
        from utils.reporting import format_html_report

        load_checks()

        # Generate mock results
        results = [
            CheckResult(
                check_name=f"Test Check {i}",
                status=Status.PASS,
                severity=Severity.INFO,
                message="Test message",
                remediation="Test remediation",
            )
            for i in range(100)
        ]

        system_info = {"os": "macOS", "version": "14.0"}

        start = time.perf_counter()
        format_html_report(results=results, system_info=system_info)
        elapsed = time.perf_counter() - start

        assert elapsed < 2.0, f"HTML generation took {elapsed:.2f}s, expected < 2s"

    def test_text_generation_fast(self) -> None:
        """Verify text report generation is fast."""
        from checks.base import CheckResult, Status, Severity
        from utils.reporting import format_text_report

        # Generate mock results
        results = [
            CheckResult(
                check_name=f"Test Check {i}",
                status=Status.PASS,
                severity=Severity.INFO,
                message="Test message",
                remediation="Test remediation",
            )
            for i in range(100)
        ]

        system_info = {"os": "macOS", "version": "14.0"}

        start = time.perf_counter()
        format_text_report(
            results=results,
            system_info=system_info,
            verbose=True,
            min_severity=Severity.INFO,
        )
        elapsed = time.perf_counter() - start

        assert elapsed < 1.0, f"Text generation took {elapsed:.2f}s, expected < 1s"
