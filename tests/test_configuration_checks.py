"""Unit tests for system configuration security checks."""
from __future__ import annotations

import plistlib
import pytest
from pathlib import Path
from subprocess import TimeoutExpired
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, mock_open

from checks.configuration import (
    FirmwarePasswordCheck,
    SecureBootCheck,
    TimeMachineEncryptionCheck,
    CrashReportingCheck,
    DiagnosticsSharingCheck,
)
from checks.types import Status, Severity


class TestFirmwarePasswordCheck:
    """Test cases for FirmwarePasswordCheck."""

    def test_requires_sudo_attribute(self):
        """Test that check requires sudo."""
        check = FirmwarePasswordCheck()
        assert check.requires_sudo is True

    @patch("checks.configuration.run_command")
    def test_firmware_password_enabled_returns_pass(self, mock_run):
        """Test PASS when firmware password is enabled."""
        mock_run.return_value = SimpleNamespace(
            stdout="Password Enabled: Yes",
            stderr="",
            returncode=0
        )
        
        check = FirmwarePasswordCheck()
        result = check.run()
        
        assert result.status == Status.PASS
        assert "enabled" in result.message.lower()
        assert result.severity == Severity.HIGH

    @patch("checks.configuration.run_command")
    def test_firmware_password_disabled_returns_fail(self, mock_run):
        """Test FAIL when firmware password is not enabled."""
        mock_run.return_value = SimpleNamespace(
            stdout="Password Enabled: No",
            stderr="",
            returncode=0
        )
        
        check = FirmwarePasswordCheck()
        result = check.run()
        
        assert result.status == Status.FAIL
        assert "not enabled" in result.message.lower()

    @patch("checks.configuration.run_command")
    def test_requires_sudo_returns_skip(self, mock_run):
        """Test SKIP when sudo is required but not available."""
        mock_run.return_value = SimpleNamespace(
            stdout="",
            stderr="requires root",
            returncode=5
        )
        
        check = FirmwarePasswordCheck()
        result = check.run()
        
        assert result.status == Status.SKIP
        assert "sudo" in result.message.lower()

    @patch("checks.configuration.run_command")
    def test_command_not_found_returns_error(self, mock_run):
        """Test ERROR when firmwarepasswd command not found."""
        mock_run.side_effect = FileNotFoundError()
        
        check = FirmwarePasswordCheck()
        result = check.run()
        
        assert result.status == Status.ERROR
        assert "not found" in result.message.lower()

    @patch("checks.configuration.run_command")
    def test_timeout_returns_error(self, mock_run):
        """Test ERROR when command times out."""
        mock_run.side_effect = TimeoutExpired(cmd="firmwarepasswd", timeout=5)
        
        check = FirmwarePasswordCheck()
        result = check.run()
        
        assert result.status == Status.ERROR

    @patch("checks.configuration.run_command")
    def test_unknown_output_returns_warning(self, mock_run):
        """Test WARNING when output cannot be parsed."""
        mock_run.return_value = SimpleNamespace(
            stdout="unexpected output format",
            stderr="",
            returncode=0
        )
        
        check = FirmwarePasswordCheck()
        result = check.run()
        
        assert result.status == Status.WARNING


class TestSecureBootCheck:
    """Test cases for SecureBootCheck."""

    def test_requires_sudo_attribute(self):
        """Test that check requires sudo."""
        check = SecureBootCheck()
        assert check.requires_sudo is True

    @patch("checks.configuration.run_command")
    def test_secure_boot_enabled_returns_pass(self, mock_run):
        """Test PASS when authenticated root is enabled."""
        mock_run.return_value = SimpleNamespace(
            stdout="Authenticated Root status: enabled",
            stderr="",
            returncode=0
        )
        
        check = SecureBootCheck()
        result = check.run()
        
        assert result.status == Status.PASS
        assert "enabled" in result.message.lower()
        assert result.severity == Severity.HIGH

    @patch("checks.configuration.run_command")
    def test_secure_boot_disabled_returns_fail(self, mock_run):
        """Test FAIL when authenticated root is disabled."""
        mock_run.return_value = SimpleNamespace(
            stdout="Authenticated Root status: disabled",
            stderr="",
            returncode=0
        )
        
        check = SecureBootCheck()
        result = check.run()
        
        assert result.status == Status.FAIL
        assert "disabled" in result.message.lower()

    @patch("checks.configuration.run_command")
    def test_command_not_found_returns_error(self, mock_run):
        """Test ERROR when csrutil not available."""
        mock_run.side_effect = FileNotFoundError()
        
        check = SecureBootCheck()
        result = check.run()
        
        assert result.status == Status.ERROR

    @patch("checks.configuration.run_command")
    def test_timeout_returns_error(self, mock_run):
        """Test ERROR when command times out."""
        mock_run.side_effect = TimeoutExpired(cmd="csrutil", timeout=5)
        
        check = SecureBootCheck()
        result = check.run()
        
        assert result.status == Status.ERROR

    @patch("checks.configuration.run_command")
    def test_unknown_status_returns_warning(self, mock_run):
        """Test WARNING when status cannot be determined."""
        mock_run.return_value = SimpleNamespace(
            stdout="some unexpected output",
            stderr="",
            returncode=0
        )
        
        check = SecureBootCheck()
        result = check.run()
        
        assert result.status == Status.WARNING


class TestTimeMachineEncryptionCheck:
    """Test cases for TimeMachineEncryptionCheck."""

    @patch("checks.configuration.run_command")
    def test_no_destinations_returns_skip(self, mock_run):
        """Test SKIP when no Time Machine destinations configured."""
        mock_run.return_value = SimpleNamespace(
            stdout="No destinations configured",
            stderr="",
            returncode=0
        )
        
        check = TimeMachineEncryptionCheck()
        result = check.run()
        
        assert result.status == Status.SKIP
        assert "no time machine" in result.message.lower()

    @patch("checks.configuration.run_command")
    def test_empty_output_returns_skip(self, mock_run):
        """Test SKIP when tmutil returns empty output."""
        mock_run.return_value = SimpleNamespace(
            stdout="",
            stderr="",
            returncode=0
        )
        
        check = TimeMachineEncryptionCheck()
        result = check.run()
        
        assert result.status == Status.SKIP

    @patch.object(TimeMachineEncryptionCheck, "_check_volume_encryption")
    @patch("checks.configuration.run_command")
    def test_encrypted_destination_returns_pass(self, mock_run, mock_check_vol):
        """Test PASS when Time Machine destination is encrypted."""
        mock_run.return_value = SimpleNamespace(
            stdout="Name          : Backup\nMount Point   : /Volumes/Backup",
            stderr="",
            returncode=0
        )
        mock_check_vol.return_value = True
        
        check = TimeMachineEncryptionCheck()
        result = check.run()
        
        assert result.status == Status.PASS
        assert "encrypted" in result.message.lower()

    @patch.object(TimeMachineEncryptionCheck, "_check_volume_encryption")
    @patch("checks.configuration.run_command")
    def test_unencrypted_destination_returns_warning(self, mock_run, mock_check_vol):
        """Test WARNING when Time Machine destination is not encrypted."""
        mock_run.return_value = SimpleNamespace(
            stdout="Name          : Backup\nMount Point   : /Volumes/Backup",
            stderr="",
            returncode=0
        )
        mock_check_vol.return_value = False
        
        check = TimeMachineEncryptionCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert "not encrypted" in result.message.lower()

    @patch("checks.configuration.run_command")
    def test_command_not_found_returns_error(self, mock_run):
        """Test ERROR when tmutil not available."""
        mock_run.side_effect = FileNotFoundError()
        
        check = TimeMachineEncryptionCheck()
        result = check.run()
        
        assert result.status == Status.ERROR

    @patch("checks.configuration.run_command")
    def test_timeout_returns_error(self, mock_run):
        """Test ERROR when tmutil times out."""
        mock_run.side_effect = TimeoutExpired(cmd="tmutil", timeout=10)
        
        check = TimeMachineEncryptionCheck()
        result = check.run()
        
        assert result.status == Status.ERROR

    @patch("checks.configuration.run_command")
    def test_destination_not_mounted_returns_skip(self, mock_run):
        """Test SKIP when destination configured but drive not mounted (disconnected)."""
        # tmutil output when drive is configured but disconnected
        mock_run.return_value = SimpleNamespace(
            stdout="====================================================\nName          : TM-Backups\nKind          : Local\nID            : 9274B1BA-E1FE-462D-B93F-B5F71BDD81B5",
            stderr="",
            returncode=0
        )
        
        check = TimeMachineEncryptionCheck()
        result = check.run()
        
        assert result.status == Status.SKIP
        assert "not mounted" in result.message.lower()

    @patch("checks.configuration.run_command")
    def test_unparseable_output_returns_warning(self, mock_run):
        """Test WARNING when output has no parseable destination info."""
        mock_run.return_value = SimpleNamespace(
            stdout="Some unexpected output format",
            stderr="",
            returncode=0
        )
        
        check = TimeMachineEncryptionCheck()
        result = check.run()
        
        assert result.status == Status.WARNING


class TestTimeMachineVolumeEncryptionCheck:
    """Test _check_volume_encryption helper method."""

    @patch("checks.configuration.run_command")
    def test_encrypted_volume_returns_true(self, mock_run):
        """Test True returned for encrypted APFS volume."""
        plist_data = {
            "Containers": [{
                "Volumes": [{
                    "MountPoint": "/Volumes/Backup",
                    "Name": "Backup",
                    "FileVault": True,
                }]
            }]
        }
        mock_run.return_value = SimpleNamespace(
            stdout=plistlib.dumps(plist_data).decode("utf-8"),
            stderr="",
            returncode=0
        )
        
        check = TimeMachineEncryptionCheck()
        result = check._check_volume_encryption("/Volumes/Backup")
        
        assert result is True

    @patch("checks.configuration.run_command")
    def test_unencrypted_volume_returns_false(self, mock_run):
        """Test False returned for unencrypted volume."""
        plist_data = {
            "Containers": [{
                "Volumes": [{
                    "MountPoint": "/Volumes/Backup",
                    "Name": "Backup",
                    "FileVault": False,
                }]
            }]
        }
        mock_run.return_value = SimpleNamespace(
            stdout=plistlib.dumps(plist_data).decode("utf-8"),
            stderr="",
            returncode=0
        )
        
        check = TimeMachineEncryptionCheck()
        result = check._check_volume_encryption("/Volumes/Backup")
        
        assert result is False

    @patch("checks.configuration.run_command")
    def test_volume_not_found_returns_false(self, mock_run):
        """Test False when volume not in APFS list."""
        plist_data = {"Containers": []}
        mock_run.return_value = SimpleNamespace(
            stdout=plistlib.dumps(plist_data).decode("utf-8"),
            stderr="",
            returncode=0
        )
        
        check = TimeMachineEncryptionCheck()
        result = check._check_volume_encryption("/Volumes/NonExistent")
        
        assert result is False

    @patch("checks.configuration.run_command")
    def test_exception_returns_false(self, mock_run):
        """Test False returned on exception."""
        mock_run.side_effect = Exception("unexpected error")
        
        check = TimeMachineEncryptionCheck()
        result = check._check_volume_encryption("/Volumes/Backup")
        
        assert result is False


class TestCrashReportingCheck:
    """Test cases for CrashReportingCheck."""

    def test_plist_not_found_returns_pass(self, tmp_path):
        """Test PASS when crash reporter plist doesn't exist (defaults to disabled)."""
        with patch.object(CrashReportingCheck, "_load_plist") as mock_load:
            mock_load.return_value = {}  # Empty dict means file exists but empty
            
            check = CrashReportingCheck()
            result = check.run()
            
            assert result.status == Status.PASS

    def test_auto_submit_enabled_returns_warning(self):
        """Test WARNING when crash reports are auto-submitted."""
        with patch.object(CrashReportingCheck, "_load_plist") as mock_load:
            mock_load.return_value = {"AutoSubmit": True}
            
            check = CrashReportingCheck()
            result = check.run()
            
            assert result.status == Status.WARNING
            assert "automatically submitted" in result.message.lower()

    def test_auto_submit_disabled_returns_pass(self):
        """Test PASS when auto-submit is disabled."""
        with patch.object(CrashReportingCheck, "_load_plist") as mock_load:
            mock_load.return_value = {"AutoSubmit": False}
            
            check = CrashReportingCheck()
            result = check.run()
            
            assert result.status == Status.PASS
            assert "disabled" in result.message.lower()

    def test_plist_unreadable_returns_warning(self):
        """Test WARNING when plist cannot be read."""
        with patch.object(CrashReportingCheck, "_load_plist") as mock_load:
            mock_load.return_value = None
            
            check = CrashReportingCheck()
            result = check.run()
            
            assert result.status == Status.WARNING
            assert "unable to read" in result.message.lower()

    def test_load_plist_helper(self, temp_plist_file):
        """Test _load_plist helper with real plist file."""
        plist_path = temp_plist_file({"AutoSubmit": True, "SomeKey": "value"})
        
        result = CrashReportingCheck._load_plist(plist_path)
        
        assert result is not None
        assert result.get("AutoSubmit") is True

    def test_load_plist_nonexistent_returns_empty(self, tmp_path):
        """Test _load_plist returns empty dict for nonexistent file."""
        nonexistent = tmp_path / "nonexistent.plist"
        
        result = CrashReportingCheck._load_plist(nonexistent)
        
        assert result == {}


class TestDiagnosticsSharingCheck:
    """Test cases for DiagnosticsSharingCheck."""

    def test_all_sharing_disabled_returns_pass(self):
        """Test PASS when all sharing is disabled."""
        with patch.object(CrashReportingCheck, "_load_plist") as mock_load:
            mock_load.return_value = {
                "ThirdPartyDataSubmit": False,
                "AutoSubmitWithiCloud": False,
            }
            
            check = DiagnosticsSharingCheck()
            result = check.run()
            
            assert result.status == Status.PASS
            assert "disabled" in result.message.lower()

    def test_analytics_enabled_returns_warning(self):
        """Test WARNING when analytics sharing is enabled."""
        with patch.object(CrashReportingCheck, "_load_plist") as mock_load:
            mock_load.return_value = {
                "ThirdPartyDataSubmit": True,
                "AutoSubmitWithiCloud": False,
            }
            
            check = DiagnosticsSharingCheck()
            result = check.run()
            
            assert result.status == Status.WARNING
            assert result.details.get("analytics") is True

    def test_icloud_sharing_enabled_returns_warning(self):
        """Test WARNING when iCloud diagnostics sharing is enabled."""
        with patch.object(CrashReportingCheck, "_load_plist") as mock_load:
            mock_load.return_value = {
                "ThirdPartyDataSubmit": False,
                "AutoSubmitWithiCloud": True,
            }
            
            check = DiagnosticsSharingCheck()
            result = check.run()
            
            assert result.status == Status.WARNING
            assert result.details.get("icloud") is True

    def test_both_sharing_enabled_returns_warning(self):
        """Test WARNING when both types of sharing are enabled."""
        with patch.object(CrashReportingCheck, "_load_plist") as mock_load:
            mock_load.return_value = {
                "ThirdPartyDataSubmit": True,
                "AutoSubmitWithiCloud": True,
            }
            
            check = DiagnosticsSharingCheck()
            result = check.run()
            
            assert result.status == Status.WARNING
            assert result.details.get("analytics") is True
            assert result.details.get("icloud") is True

    def test_plist_unreadable_returns_warning(self):
        """Test WARNING when preferences cannot be read."""
        with patch.object(CrashReportingCheck, "_load_plist") as mock_load:
            mock_load.return_value = None
            
            check = DiagnosticsSharingCheck()
            result = check.run()
            
            assert result.status == Status.WARNING

    def test_missing_keys_returns_pass(self):
        """Test PASS when sharing keys are not present (default disabled)."""
        with patch.object(CrashReportingCheck, "_load_plist") as mock_load:
            mock_load.return_value = {}
            
            check = DiagnosticsSharingCheck()
            result = check.run()
            
            assert result.status == Status.PASS


class TestConfigurationCheckMetadata:
    """Test configuration check metadata."""

    def test_firmware_password_metadata(self):
        """Test FirmwarePasswordCheck metadata."""
        check = FirmwarePasswordCheck()
        assert check.name == "Firmware Password"
        assert check.category == "configuration"
        assert check.severity == Severity.HIGH
        assert check.requires_sudo is True

    def test_secure_boot_metadata(self):
        """Test SecureBootCheck metadata."""
        check = SecureBootCheck()
        assert check.name == "Secure Boot"
        assert check.category == "configuration"
        assert check.severity == Severity.HIGH
        assert check.requires_sudo is True

    def test_time_machine_metadata(self):
        """Test TimeMachineEncryptionCheck metadata."""
        check = TimeMachineEncryptionCheck()
        assert check.name == "Time Machine Encryption"
        assert check.category == "configuration"
        assert check.severity == Severity.MEDIUM
        assert not check.requires_sudo

    def test_crash_reporting_metadata(self):
        """Test CrashReportingCheck metadata."""
        check = CrashReportingCheck()
        assert check.name == "Crash Reporting"
        assert check.category == "configuration"
        assert check.severity == Severity.LOW

    def test_diagnostics_sharing_metadata(self):
        """Test DiagnosticsSharingCheck metadata."""
        check = DiagnosticsSharingCheck()
        assert check.name == "Analytics Sharing"
        assert check.category == "configuration"
        assert check.severity == Severity.LOW
