"""Integration tests for CRITICAL severity security checks.

These tests verify that critical checks:
1. Execute without crashing on real macOS systems
2. Return valid CheckResult objects
3. Handle edge cases gracefully
4. Produce actionable output

Critical checks (must have 100% integration test coverage):
- FileVault Encryption (encryption.py)
- System Integrity Protection (system_integrity.py)
"""

from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    pass

# Skip all tests if not on macOS
pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="Integration tests require macOS"
)


class TestFileVaultIntegration:
    """Integration tests for FileVault encryption check."""

    def test_filevault_check_executes(self) -> None:
        """Verify FileVault check runs without errors."""
        from macsentry.checks.encryption import FileVaultStatusCheck as FileVaultCheck
        from macsentry.checks.base import Status

        check = FileVaultCheck()
        result = check.execute()

        assert result is not None
        assert result.check_name == "FileVault Encryption"
        assert result.status in (Status.PASS, Status.FAIL, Status.WARNING, Status.SKIP, Status.ERROR)
        assert result.message is not None
        assert len(result.message) > 0

    def test_filevault_check_returns_valid_severity(self) -> None:
        """Verify FileVault check returns critical severity."""
        from macsentry.checks.encryption import FileVaultStatusCheck as FileVaultCheck
        from macsentry.checks.base import Severity

        check = FileVaultCheck()
        result = check.execute()

        assert result.severity == Severity.CRITICAL

    def test_filevault_check_has_remediation(self) -> None:
        """Verify FileVault check provides remediation guidance."""
        from macsentry.checks.encryption import FileVaultStatusCheck as FileVaultCheck

        check = FileVaultCheck()
        result = check.execute()

        assert result.remediation is not None
        assert "FileVault" in result.remediation or "encryption" in result.remediation.lower()

    def test_filevault_matches_system_state(self) -> None:
        """Verify FileVault check result matches actual system state."""
        from macsentry.checks.encryption import FileVaultStatusCheck as FileVaultCheck
        from macsentry.checks.base import Status

        # Get actual FileVault status from system
        try:
            proc = subprocess.run(
                ["fdesetup", "status"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            system_enabled = "FileVault is On" in proc.stdout
        except (subprocess.SubprocessError, FileNotFoundError):
            pytest.skip("Cannot determine system FileVault status")
            return

        check = FileVaultCheck()
        result = check.execute()

        # Result should match system state
        if system_enabled:
            assert result.status == Status.PASS, (
                f"FileVault is ON but check returned {result.status}"
            )
        else:
            assert result.status in (Status.FAIL, Status.WARNING), (
                f"FileVault is OFF but check returned {result.status}"
            )

    def test_filevault_execution_time(self) -> None:
        """Verify FileVault check completes quickly."""
        import time
        from macsentry.checks.encryption import FileVaultStatusCheck as FileVaultCheck

        check = FileVaultCheck()
        
        start = time.perf_counter()
        check.execute()
        elapsed = time.perf_counter() - start

        # Should complete in under 5 seconds
        assert elapsed < 5.0, f"FileVault check took {elapsed:.2f}s, expected < 5s"


class TestSIPIntegration:
    """Integration tests for System Integrity Protection check."""

    def test_sip_check_executes(self) -> None:
        """Verify SIP check runs without errors."""
        from macsentry.checks.system_integrity import SystemIntegrityProtectionCheck as SIPCheck
        from macsentry.checks.base import Status

        check = SIPCheck()
        result = check.execute()

        assert result is not None
        assert result.check_name == "System Integrity Protection"
        assert result.status in (Status.PASS, Status.FAIL, Status.WARNING, Status.SKIP, Status.ERROR)
        assert result.message is not None
        assert len(result.message) > 0

    def test_sip_check_returns_valid_severity(self) -> None:
        """Verify SIP check returns critical severity."""
        from macsentry.checks.system_integrity import SystemIntegrityProtectionCheck as SIPCheck
        from macsentry.checks.base import Severity

        check = SIPCheck()
        result = check.execute()

        assert result.severity == Severity.CRITICAL

    def test_sip_check_has_remediation(self) -> None:
        """Verify SIP check provides remediation guidance."""
        from macsentry.checks.system_integrity import SystemIntegrityProtectionCheck as SIPCheck

        check = SIPCheck()
        result = check.execute()

        assert result.remediation is not None
        assert "SIP" in result.remediation or "csrutil" in result.remediation

    def test_sip_matches_system_state(self) -> None:
        """Verify SIP check result matches actual system state."""
        from macsentry.checks.system_integrity import SystemIntegrityProtectionCheck as SIPCheck
        from macsentry.checks.base import Status

        # Get actual SIP status from system
        try:
            proc = subprocess.run(
                ["csrutil", "status"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            system_enabled = "enabled" in proc.stdout.lower()
        except (subprocess.SubprocessError, FileNotFoundError):
            pytest.skip("Cannot determine system SIP status")
            return

        check = SIPCheck()
        result = check.execute()

        # Result should match system state
        if system_enabled:
            assert result.status == Status.PASS, (
                f"SIP is enabled but check returned {result.status}"
            )
        else:
            assert result.status in (Status.FAIL, Status.WARNING), (
                f"SIP is disabled but check returned {result.status}"
            )

    def test_sip_execution_time(self) -> None:
        """Verify SIP check completes quickly."""
        import time
        from macsentry.checks.system_integrity import SystemIntegrityProtectionCheck as SIPCheck

        check = SIPCheck()
        
        start = time.perf_counter()
        check.execute()
        elapsed = time.perf_counter() - start

        # Should complete in under 5 seconds
        assert elapsed < 5.0, f"SIP check took {elapsed:.2f}s, expected < 5s"


class TestCriticalChecksRegistry:
    """Tests for critical check registration and discovery."""

    def test_all_critical_checks_registered(self) -> None:
        """Verify all critical checks are properly registered."""
        from macsentry.checks import load_checks
        from macsentry.checks.base import CheckRegistry, Severity

        load_checks()

        critical_checks = [
            cls for cls in CheckRegistry.get_all()
            if getattr(cls, "severity", None) == Severity.CRITICAL
        ]

        # We should have exactly 2 critical checks
        assert len(critical_checks) == 2, (
            f"Expected 2 critical checks, found {len(critical_checks)}: "
            f"{[c.name for c in critical_checks]}"
        )

        # Verify expected checks are present
        check_names = {cls.name for cls in critical_checks}
        assert "FileVault Encryption" in check_names
        assert "System Integrity Protection" in check_names

    def test_critical_checks_have_required_attributes(self) -> None:
        """Verify critical checks have all required attributes."""
        from macsentry.checks import load_checks
        from macsentry.checks.base import CheckRegistry, Severity

        load_checks()

        critical_checks = [
            cls for cls in CheckRegistry.get_all()
            if getattr(cls, "severity", None) == Severity.CRITICAL
        ]

        required_attrs = ["name", "description", "category", "severity", "remediation"]

        for cls in critical_checks:
            for attr in required_attrs:
                assert hasattr(cls, attr), f"{cls.__name__} missing required attribute: {attr}"
                value = getattr(cls, attr)
                assert value is not None, f"{cls.__name__}.{attr} is None"
                if isinstance(value, str):
                    assert len(value) > 0, f"{cls.__name__}.{attr} is empty string"

    def test_critical_checks_instantiable(self) -> None:
        """Verify all critical checks can be instantiated."""
        from macsentry.checks import load_checks
        from macsentry.checks.base import CheckRegistry, Severity

        load_checks()

        critical_checks = [
            cls for cls in CheckRegistry.get_all()
            if getattr(cls, "severity", None) == Severity.CRITICAL
        ]

        for cls in critical_checks:
            try:
                instance = cls()
                assert instance is not None
            except Exception as e:
                pytest.fail(f"Failed to instantiate {cls.__name__}: {e}")

    def test_all_critical_checks_execute_successfully(self) -> None:
        """Verify all critical checks execute without crashing."""
        from macsentry.checks import load_checks
        from macsentry.checks.base import CheckRegistry, Severity, CheckResult

        load_checks()

        critical_checks = [
            cls for cls in CheckRegistry.get_all()
            if getattr(cls, "severity", None) == Severity.CRITICAL
        ]

        for cls in critical_checks:
            check = cls()
            try:
                result = check.execute()
                assert isinstance(result, CheckResult), (
                    f"{cls.name} did not return CheckResult"
                )
            except Exception as e:
                pytest.fail(f"{cls.name} raised exception: {e}")


class TestCriticalCheckOutput:
    """Tests for critical check output format and content."""

    def test_critical_checks_json_serializable(self) -> None:
        """Verify critical check results can be serialized to JSON."""
        import json
        from macsentry.checks import load_checks
        from macsentry.checks.base import CheckRegistry, Severity

        load_checks()

        critical_checks = [
            cls for cls in CheckRegistry.get_all()
            if getattr(cls, "severity", None) == Severity.CRITICAL
        ]

        for cls in critical_checks:
            check = cls()
            result = check.execute()

            # Convert to dict and verify JSON serialization
            result_dict = {
                "check_name": result.check_name,
                "status": result.status.value,
                "severity": result.severity.value,
                "message": result.message,
                "remediation": result.remediation,
                "details": result.details,
            }

            try:
                json_str = json.dumps(result_dict)
                parsed = json.loads(json_str)
                assert parsed["check_name"] == result.check_name
            except (TypeError, json.JSONDecodeError) as e:
                pytest.fail(f"{cls.name} result not JSON serializable: {e}")

    def test_critical_checks_message_descriptive(self) -> None:
        """Verify critical check messages are descriptive."""
        from macsentry.checks import load_checks
        from macsentry.checks.base import CheckRegistry, Severity

        load_checks()

        critical_checks = [
            cls for cls in CheckRegistry.get_all()
            if getattr(cls, "severity", None) == Severity.CRITICAL
        ]

        for cls in critical_checks:
            check = cls()
            result = check.execute()

            # Message should be meaningful
            assert result.message is not None
            assert len(result.message) >= 10, (
                f"{cls.name} message too short: '{result.message}'"
            )


class TestCriticalCheckErrorHandling:
    """Tests for critical check error handling."""

    def test_filevault_handles_missing_command(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify FileVault check handles missing fdesetup gracefully."""
        from macsentry.checks import encryption
        from macsentry.checks.encryption import FileVaultStatusCheck as FileVaultCheck
        from macsentry.checks.base import Status

        def mock_run_command(*args, **kwargs):  # noqa: ANN002, ANN003
            raise FileNotFoundError("Command not found: fdesetup")

        # Patch in the module namespace where it's imported
        monkeypatch.setattr(encryption.commands, "run_command", mock_run_command)

        check = FileVaultCheck()
        result = check.execute()

        # Should handle gracefully, not crash
        assert result is not None
        assert result.status in (Status.ERROR, Status.SKIP, Status.WARNING)

    def test_sip_handles_missing_command(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify SIP check handles missing csrutil gracefully."""
        from macsentry.checks import system_integrity
        from macsentry.checks.system_integrity import SystemIntegrityProtectionCheck as SIPCheck
        from macsentry.checks.base import Status

        def mock_run_command(*args, **kwargs):  # noqa: ANN002, ANN003
            raise FileNotFoundError("Command not found: csrutil")

        # Patch in the module namespace where it's imported
        monkeypatch.setattr(system_integrity, "run_command", mock_run_command)

        check = SIPCheck()
        result = check.execute()

        # Should handle gracefully, not crash
        assert result is not None
        assert result.status in (Status.ERROR, Status.SKIP, Status.WARNING)
