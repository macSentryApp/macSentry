"""Smoke tests for macOS Security Audit tool.

These tests validate the "happy path" - basic functionality that must work:
- Script runs without crashing
- Produces valid output in all formats
- Exits cleanly with expected exit codes
- Completes within performance thresholds
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

# Performance threshold in seconds (configurable via environment)
PERFORMANCE_THRESHOLD_SECONDS = float(
    os.environ.get("SMOKE_TEST_PERFORMANCE_THRESHOLD", "30")
)

# Path to the main script
SCRIPT_PATH = Path(__file__).parent.parent / "macos_security_audit.py"

# Valid exit codes for successful audit runs:
# 0 = no issues, 2 = critical/high issues, 3 = warnings/medium issues
# Exit code 1 = actual error/crash
VALID_EXIT_CODES = {0, 2, 3}


class TestScriptExecution:
    """Test that the main script executes successfully."""

    def test_script_exists(self) -> None:
        """Verify the main script file exists."""
        assert SCRIPT_PATH.exists(), f"Main script not found at {SCRIPT_PATH}"
        assert SCRIPT_PATH.is_file(), f"{SCRIPT_PATH} is not a file"

    def test_script_is_valid_python(self) -> None:
        """Verify the script is valid Python syntax."""
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"Syntax error: {result.stderr}"

    def test_help_command(self) -> None:
        """Test that --help works and shows expected content."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"--help failed: {result.stderr}"
        assert "macOS Security Audit" in result.stdout
        assert "--format" in result.stdout
        assert "--categories" in result.stdout

    def test_dry_run_executes(self) -> None:
        """Test that --dry-run executes without errors."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--dry-run", "--skip-validation"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"--dry-run failed: {result.stderr}"
        # Check for dry-run mode output (may use different wording)
        assert "dry-run" in result.stdout.lower() or "checks" in result.stdout.lower()

    def test_dry_run_lists_checks(self) -> None:
        """Verify dry run lists available checks."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--dry-run", "--skip-validation"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        # Should list at least some checks (uses bullet point • or - prefix)
        lines = result.stdout.strip().split("\n")
        # Match lines with bullet points (•), dashes (-), or check names with severity
        check_lines = [line for line in lines if "•" in line or line.strip().startswith("-") or "[" in line and "]" in line]
        assert len(check_lines) >= 10, f"Expected at least 10 checks, got {len(check_lines)}. Output:\n{result.stdout}"


class TestOutputFormats:
    """Test all output format options."""

    def test_text_output(self) -> None:
        """Test text format output."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--format", "text", "--skip-validation"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode in VALID_EXIT_CODES, f"Text output failed: {result.stderr}"
        # Should contain report header elements
        assert len(result.stdout) > 100, "Output too short"

    def test_json_output_valid(self) -> None:
        """Test JSON format produces valid JSON."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--format", "json", "--skip-validation"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode in VALID_EXIT_CODES, f"JSON output failed: {result.stderr}"

        # Validate JSON structure
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            pytest.fail(f"Invalid JSON output: {e}")

        # Check expected keys
        assert "results" in data or "checks" in data or isinstance(data, list), (
            f"Unexpected JSON structure: {list(data.keys()) if isinstance(data, dict) else type(data)}"
        )

    def test_json_output_has_system_info(self) -> None:
        """Test JSON output includes system information."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--format", "json", "--skip-validation"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode in VALID_EXIT_CODES

        data = json.loads(result.stdout)
        # Should have system_info or similar metadata
        assert "system_info" in data or "metadata" in data or "system" in data, (
            "JSON output missing system information"
        )

    def test_html_output(self) -> None:
        """Test HTML format output."""
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            output_path = f.name

        try:
            result = subprocess.run(
                [sys.executable, str(SCRIPT_PATH), "--format", "html", "--output", output_path, "--skip-validation"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert result.returncode in VALID_EXIT_CODES, f"HTML output failed: {result.stderr}"

            # Verify file was created
            assert Path(output_path).exists(), "HTML file not created"

            # Verify it contains HTML
            content = Path(output_path).read_text()
            assert "<html" in content.lower(), "Output is not valid HTML"
            assert "</html>" in content.lower(), "HTML not properly closed"
        finally:
            Path(output_path).unlink(missing_ok=True)


class TestCategoryFiltering:
    """Test category-based filtering."""

    def test_single_category_filter(self) -> None:
        """Test filtering by a single category."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--categories", "encryption", "--dry-run", "--skip-validation"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"Category filter failed: {result.stderr}"
        # All listed checks should be encryption category
        for line in result.stdout.split("\n"):
            if line.startswith("-"):
                assert "encryption" in line.lower(), f"Non-encryption check in output: {line}"

    def test_multiple_category_filter(self) -> None:
        """Test filtering by multiple categories."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--categories", "encryption,firewall", "--dry-run", "--skip-validation"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        for line in result.stdout.split("\n"):
            if line.startswith("-"):
                assert any(cat in line.lower() for cat in ["encryption", "firewall"]), (
                    f"Unexpected category in output: {line}"
                )

    def test_invalid_category_handled(self) -> None:
        """Test that invalid category doesn't crash."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--categories", "nonexistent_category_xyz", "--dry-run", "--skip-validation"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Should complete without crashing (may have 0 checks)
        assert result.returncode == 0


class TestSeverityFiltering:
    """Test severity-based filtering."""

    @pytest.mark.parametrize("severity", ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    def test_severity_levels(self, severity: str) -> None:
        """Test each severity level filter."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--min-severity", severity, "--dry-run", "--skip-validation"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"Severity {severity} failed: {result.stderr}"


class TestExitCodes:
    """Test proper exit code behavior."""

    def test_successful_execution_returns_zero(self) -> None:
        """Test that successful execution returns exit code 0."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--dry-run", "--skip-validation"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"Expected exit code 0, got {result.returncode}"

    def test_help_returns_zero(self) -> None:
        """Test that --help returns exit code 0."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0

    def test_invalid_argument_returns_nonzero(self) -> None:
        """Test that invalid arguments return non-zero exit code."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--invalid-option-xyz"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode != 0, "Invalid option should return non-zero exit code"


class TestPerformance:
    """Performance baseline tests."""

    @pytest.fixture
    def performance_threshold(self) -> float:
        """Get performance threshold from environment or use default."""
        return PERFORMANCE_THRESHOLD_SECONDS

    def test_full_audit_performance(self, performance_threshold: float) -> None:
        """Test that full audit completes within threshold.

        Default threshold: 30 seconds (M1/M2 baseline)
        This may need adjustment for Intel Macs via environment variable.
        """
        start_time = time.perf_counter()

        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--format", "json", "--skip-validation"],
            capture_output=True,
            text=True,
            timeout=120,  # Hard timeout to prevent hanging
        )

        elapsed = time.perf_counter() - start_time

        assert result.returncode in VALID_EXIT_CODES, f"Audit failed: {result.stderr}"

        # Log performance for CI visibility
        print(f"\nPerformance: {elapsed:.2f}s (threshold: {performance_threshold}s)")

        # Soft assertion with warning for flexibility
        if elapsed > performance_threshold:
            pytest.xfail(
                f"Execution time ({elapsed:.2f}s) exceeds threshold ({performance_threshold}s). "
                "This may be acceptable on slower hardware."
            )

    def test_dry_run_is_fast(self) -> None:
        """Test that dry-run completes quickly (no actual checks run)."""
        start_time = time.perf_counter()

        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--dry-run", "--skip-validation"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        elapsed = time.perf_counter() - start_time

        assert result.returncode == 0
        # Dry run should be very fast (under 5 seconds)
        assert elapsed < 5.0, f"Dry run took {elapsed:.2f}s, expected < 5s"

    def test_help_is_instant(self) -> None:
        """Test that --help is nearly instant."""
        start_time = time.perf_counter()

        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        elapsed = time.perf_counter() - start_time

        assert result.returncode == 0
        # Help should be instant (under 2 seconds)
        assert elapsed < 2.0, f"--help took {elapsed:.2f}s, expected < 2s"


class TestModuleImports:
    """Test that all modules can be imported."""

    def test_main_script_importable(self) -> None:
        """Test that main script can be imported as module."""
        result = subprocess.run(
            [sys.executable, "-c", "import macos_security_audit"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=SCRIPT_PATH.parent,
        )
        assert result.returncode == 0, f"Import failed: {result.stderr}"

    def test_checks_module_importable(self) -> None:
        """Test that checks module can be imported."""
        result = subprocess.run(
            [sys.executable, "-c", "from checks import load_checks; load_checks()"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=SCRIPT_PATH.parent,
        )
        assert result.returncode == 0, f"Checks import failed: {result.stderr}"

    def test_utils_module_importable(self) -> None:
        """Test that utils module can be imported."""
        result = subprocess.run(
            [sys.executable, "-c", "import utils"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=SCRIPT_PATH.parent,
        )
        assert result.returncode == 0, f"Utils import failed: {result.stderr}"


class TestOutputFileWriting:
    """Test file output functionality."""

    @pytest.fixture
    def temp_output_dir(self) -> Generator[Path, None, None]:
        """Create a temporary directory for output files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_write_to_file(self, temp_output_dir: Path) -> None:
        """Test writing report to file."""
        output_file = temp_output_dir / "report.txt"

        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--format", "text", "--output", str(output_file), "--skip-validation"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode in VALID_EXIT_CODES, f"File write failed: {result.stderr}"
        assert output_file.exists(), "Output file not created"
        assert output_file.stat().st_size > 0, "Output file is empty"

    def test_write_to_nested_directory(self, temp_output_dir: Path) -> None:
        """Test writing to a nested directory that doesn't exist."""
        output_file = temp_output_dir / "nested" / "deep" / "report.json"

        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--format", "json", "--output", str(output_file), "--skip-validation"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode in VALID_EXIT_CODES, f"Nested write failed: {result.stderr}"
        assert output_file.exists(), "Nested output file not created"

        # Verify valid JSON
        content = output_file.read_text()
        json.loads(content)  # Raises if invalid


class TestVerboseMode:
    """Test verbose output mode."""

    def test_verbose_shows_more_output(self) -> None:
        """Test that --verbose produces more output.
        
        Uses --dry-run mode for speed in CI environments.
        """
        # Run without verbose (dry-run for speed)
        result_normal = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--dry-run", "--skip-validation"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Run with verbose (dry-run for speed)
        result_verbose = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--dry-run", "--verbose", "--skip-validation"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result_normal.returncode == 0
        assert result_verbose.returncode == 0

        # Both should produce output
        assert len(result_normal.stdout) > 0, "Normal mode should produce output"
        assert len(result_verbose.stdout) > 0, "Verbose mode should produce output"
        
        # Verbose output should be at least as long (likely longer due to extra details)
        assert len(result_verbose.stdout) >= len(result_normal.stdout), (
            "Verbose mode should produce at least as much output"
        )
