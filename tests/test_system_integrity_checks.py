"""Unit tests for system integrity security checks."""
from __future__ import annotations

import datetime as dt
import plistlib
import pytest
from pathlib import Path
from subprocess import TimeoutExpired
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, PropertyMock

from macsentry.checks.system_integrity import (
    SystemIntegrityProtectionCheck,
    GatekeeperCheck,
    XProtectUpdateCheck,
    MalwareRemovalToolUpdateCheck,
    SoftwareUpdatePendingCheck,
    AutomaticUpdatesCheck,
)
from macsentry.checks.types import Status, Severity
from macsentry.utils.commands import CommandExecutionError


class TestSystemIntegrityProtectionCheck:
    """Test cases for SystemIntegrityProtectionCheck."""

    @pytest.mark.parametrize("macos_version,output", [
        ("13.0", "System Integrity Protection status: enabled."),
        ("14.0", "System Integrity Protection status: enabled."),
        ("15.0", "System Integrity Protection status: enabled."),
    ])
    @patch("checks.system_integrity.run_command")
    def test_sip_enabled_returns_pass(self, mock_run, macos_version, output):
        """Test PASS when SIP is enabled across macOS versions."""
        mock_run.return_value = SimpleNamespace(stdout=output, stderr="", returncode=0)
        
        check = SystemIntegrityProtectionCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert "enabled" in result.message.lower()
        assert result.severity == Severity.CRITICAL

    @patch("checks.system_integrity.run_command")
    def test_sip_disabled_returns_fail(self, mock_run):
        """Test FAIL when SIP is disabled."""
        mock_run.return_value = SimpleNamespace(
            stdout="System Integrity Protection status: disabled.",
            stderr="",
            returncode=0
        )
        
        check = SystemIntegrityProtectionCheck()
        result = check.execute()
        
        assert result.status == Status.FAIL
        assert "disabled" in result.message.lower()

    @patch("checks.system_integrity.run_command")
    def test_sip_custom_config_returns_warning(self, mock_run):
        """Test WARNING when SIP has custom configuration."""
        mock_run.return_value = SimpleNamespace(
            stdout="System Integrity Protection status: unknown (Custom Configuration).",
            stderr="",
            returncode=0
        )
        
        check = SystemIntegrityProtectionCheck()
        result = check.execute()
        
        assert result.status == Status.WARNING

    @patch("checks.system_integrity.run_command")
    def test_command_not_found_returns_error(self, mock_run):
        """Test ERROR when csrutil is not available."""
        mock_run.side_effect = FileNotFoundError()
        
        check = SystemIntegrityProtectionCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR
        assert "not available" in result.message.lower()

    @patch("checks.system_integrity.run_command")
    def test_command_timeout_returns_error(self, mock_run):
        """Test ERROR when command times out."""
        mock_run.side_effect = TimeoutExpired(cmd="csrutil", timeout=5)
        
        check = SystemIntegrityProtectionCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR


class TestGatekeeperCheck:
    """Test cases for GatekeeperCheck."""

    @pytest.mark.parametrize("output", [
        "assessments enabled",
        "Gatekeeper enabled",
    ])
    @patch("checks.system_integrity.run_command")
    def test_gatekeeper_enabled_returns_pass(self, mock_run, output):
        """Test PASS when Gatekeeper is enabled."""
        mock_run.return_value = SimpleNamespace(stdout=output, stderr="", returncode=0)
        
        check = GatekeeperCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert "enabled" in result.message.lower()
        assert result.severity == Severity.HIGH

    @patch("checks.system_integrity.run_command")
    def test_gatekeeper_disabled_returns_fail(self, mock_run):
        """Test FAIL when Gatekeeper is disabled."""
        mock_run.return_value = SimpleNamespace(
            stdout="assessments disabled",
            stderr="",
            returncode=0
        )
        
        check = GatekeeperCheck()
        result = check.execute()
        
        assert result.status == Status.FAIL
        assert "disabled" in result.message.lower()

    @patch("checks.system_integrity.run_command")
    def test_unknown_state_returns_warning(self, mock_run):
        """Test WARNING when state cannot be determined."""
        mock_run.return_value = SimpleNamespace(
            stdout="unexpected output",
            stderr="",
            returncode=0
        )
        
        check = GatekeeperCheck()
        result = check.execute()
        
        assert result.status == Status.WARNING

    @patch("checks.system_integrity.run_command")
    def test_command_not_found_returns_error(self, mock_run):
        """Test ERROR when spctl is not available."""
        mock_run.side_effect = FileNotFoundError()
        
        check = GatekeeperCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR

    @patch("checks.system_integrity.run_command")
    def test_timeout_returns_error(self, mock_run):
        """Test ERROR when command times out."""
        mock_run.side_effect = TimeoutExpired(cmd="spctl", timeout=5)
        
        check = GatekeeperCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR


class TestXProtectUpdateCheck:
    """Test cases for XProtectUpdateCheck."""

    @patch("checks.system_integrity.load_plist")
    @patch.object(Path, "stat")
    def test_recent_update_returns_pass(self, mock_stat, mock_load_plist):
        """Test PASS when XProtect was updated recently (within 30 days)."""
        mock_load_plist.return_value = {
            "CFBundleShortVersionString": "2195",
            "CFBundleVersion": "2195",
        }
        # Set mtime to 5 days ago
        mock_stat.return_value = MagicMock(
            st_mtime=(dt.datetime.now() - dt.timedelta(days=5)).timestamp()
        )
        
        check = XProtectUpdateCheck()
        result = check.run()
        
        assert result.status == Status.PASS
        assert "5 day" in result.message
        assert result.details.get("version") == "2195"

    @patch("checks.system_integrity.load_plist")
    @patch.object(Path, "stat")
    def test_stale_update_returns_warning(self, mock_stat, mock_load_plist):
        """Test WARNING when XProtect is 30-60 days old (may indicate disabled auto-updates)."""
        mock_load_plist.return_value = {
            "CFBundleShortVersionString": "2100",
        }
        # Set mtime to 45 days ago (between 30 and 60)
        mock_stat.return_value = MagicMock(
            st_mtime=(dt.datetime.now() - dt.timedelta(days=45)).timestamp()
        )
        
        check = XProtectUpdateCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert "45 days old" in result.message
        assert result.details.get("age_days") == 45

    @patch("checks.system_integrity.load_plist")
    @patch.object(Path, "stat")
    def test_critically_outdated_returns_fail(self, mock_stat, mock_load_plist):
        """Test FAIL when XProtect is 60+ days old (serious security risk)."""
        mock_load_plist.return_value = {
            "CFBundleShortVersionString": "2000",
        }
        # Set mtime to 75 days ago (beyond 60 day threshold)
        mock_stat.return_value = MagicMock(
            st_mtime=(dt.datetime.now() - dt.timedelta(days=75)).timestamp()
        )
        
        check = XProtectUpdateCheck()
        result = check.run()
        
        assert result.status == Status.FAIL
        assert "critically outdated" in result.message.lower()
        assert result.details.get("age_days") == 75

    @patch("checks.system_integrity.load_plist")
    def test_plist_not_found_returns_fail(self, mock_load_plist):
        """Test FAIL when XProtect plist cannot be read (missing protection)."""
        mock_load_plist.return_value = None
        
        check = XProtectUpdateCheck()
        result = check.run()
        
        assert result.status == Status.FAIL
        assert "not found" in result.message.lower()

    @patch("checks.system_integrity.load_plist")
    @patch.object(Path, "stat")
    def test_edge_case_exactly_fresh_threshold(self, mock_stat, mock_load_plist):
        """Test PASS when age equals fresh_threshold_days exactly (30 days)."""
        mock_load_plist.return_value = {"CFBundleVersion": "2195"}
        mock_stat.return_value = MagicMock(
            st_mtime=(dt.datetime.now() - dt.timedelta(days=30)).timestamp()
        )
        
        check = XProtectUpdateCheck()
        result = check.run()
        
        assert result.status == Status.PASS

    @patch("checks.system_integrity.load_plist")
    @patch.object(Path, "stat")
    def test_edge_case_exactly_stale_threshold(self, mock_stat, mock_load_plist):
        """Test WARNING when age equals stale_threshold_days exactly (60 days)."""
        mock_load_plist.return_value = {"CFBundleVersion": "2195"}
        mock_stat.return_value = MagicMock(
            st_mtime=(dt.datetime.now() - dt.timedelta(days=60)).timestamp()
        )
        
        check = XProtectUpdateCheck()
        result = check.run()
        
        assert result.status == Status.WARNING


class TestMalwareRemovalToolUpdateCheck:
    """Test cases for MalwareRemovalToolUpdateCheck."""

    @patch("checks.system_integrity.load_plist")
    @patch.object(Path, "stat")
    def test_xprotect_remediator_recent_returns_pass(self, mock_stat, mock_load_plist):
        """Test PASS when XProtect Remediator is recent (within 30 days)."""
        mock_load_plist.return_value = {
            "CFBundleShortVersionString": "140",
        }
        mock_stat.return_value = MagicMock(
            st_mtime=(dt.datetime.now() - dt.timedelta(days=10)).timestamp()
        )
        
        check = MalwareRemovalToolUpdateCheck()
        result = check.run()
        
        assert result.status == Status.PASS
        assert "10 day" in result.message

    @patch("checks.system_integrity.load_plist")
    @patch.object(Path, "stat")
    def test_fallback_to_legacy_mrt(self, mock_stat, mock_load_plist):
        """Test fallback to legacy MRT when XProtect not found."""
        # First call returns None (XProtect not found), second returns MRT
        mock_load_plist.side_effect = [
            None,
            {"CFBundleShortVersionString": "1.95"},
        ]
        mock_stat.return_value = MagicMock(
            st_mtime=(dt.datetime.now() - dt.timedelta(days=20)).timestamp()
        )
        
        check = MalwareRemovalToolUpdateCheck()
        result = check.run()
        
        assert result.status == Status.PASS
        assert "MRT" in result.message

    @patch("checks.system_integrity.load_plist")
    def test_neither_found_returns_fail(self, mock_load_plist):
        """Test FAIL when neither XProtect nor MRT found (missing protection)."""
        mock_load_plist.return_value = None
        
        check = MalwareRemovalToolUpdateCheck()
        result = check.run()
        
        assert result.status == Status.FAIL
        assert "not found" in result.message.lower()

    @patch("checks.system_integrity.load_plist")
    @patch.object(Path, "stat")
    def test_stale_returns_warning(self, mock_stat, mock_load_plist):
        """Test WARNING when MRT is 30-60 days old."""
        mock_load_plist.return_value = {"CFBundleVersion": "130"}
        mock_stat.return_value = MagicMock(
            st_mtime=(dt.datetime.now() - dt.timedelta(days=45)).timestamp()
        )
        
        check = MalwareRemovalToolUpdateCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert "45 days old" in result.message

    @patch("checks.system_integrity.load_plist")
    @patch.object(Path, "stat")
    def test_critically_outdated_returns_fail(self, mock_stat, mock_load_plist):
        """Test FAIL when MRT is 60+ days old."""
        mock_load_plist.return_value = {"CFBundleVersion": "130"}
        mock_stat.return_value = MagicMock(
            st_mtime=(dt.datetime.now() - dt.timedelta(days=75)).timestamp()
        )
        
        check = MalwareRemovalToolUpdateCheck()
        result = check.run()
        
        assert result.status == Status.FAIL
        assert "critically outdated" in result.message.lower()


class TestSoftwareUpdatePendingCheck:
    """Test cases for SoftwareUpdatePendingCheck."""

    @patch("checks.system_integrity.load_plist")
    def test_no_updates_via_plist_returns_pass(self, mock_load_plist):
        """Test PASS when plist shows no recommended updates."""
        mock_load_plist.return_value = {"RecommendedUpdates": []}
        
        check = SoftwareUpdatePendingCheck()
        result = check.run()
        
        assert result.status == Status.PASS
        assert "no pending" in result.message.lower()

    @patch("checks.system_integrity.load_plist")
    def test_updates_available_via_plist_returns_fail(self, mock_load_plist):
        """Test FAIL when plist shows updates available."""
        mock_load_plist.return_value = {
            "RecommendedUpdates": [
                {"Display Name": "macOS Sonoma 14.2"},
                {"Display Name": "Safari 17.2"},
            ]
        }
        
        check = SoftwareUpdatePendingCheck()
        result = check.run()
        
        assert result.status == Status.FAIL
        assert "2 software update" in result.message
        assert "macOS Sonoma 14.2" in result.details.get("updates", [])

    @patch("checks.system_integrity.load_plist")
    @patch("checks.system_integrity.run_command")
    def test_fallback_to_softwareupdate_no_updates(self, mock_run, mock_load_plist):
        """Test fallback to softwareupdate command when plist unavailable."""
        mock_load_plist.return_value = None
        mock_run.return_value = SimpleNamespace(
            stdout="Software Update Tool\nNo new software available.",
            stderr="",
            returncode=0
        )
        
        check = SoftwareUpdatePendingCheck()
        result = check.run()
        
        assert result.status == Status.PASS

    @patch("checks.system_integrity.load_plist")
    @patch("checks.system_integrity.run_command")
    def test_fallback_updates_available(self, mock_run, mock_load_plist):
        """Test FAIL when softwareupdate shows updates available."""
        mock_load_plist.return_value = None
        mock_run.return_value = SimpleNamespace(
            stdout="Software Update found the following new or updated software:\n* macOS 14.2",
            stderr="",
            returncode=0
        )
        
        check = SoftwareUpdatePendingCheck()
        result = check.run()
        
        assert result.status == Status.FAIL

    @patch("checks.system_integrity.load_plist")
    @patch("checks.system_integrity.run_command")
    def test_softwareupdate_timeout_returns_warning(self, mock_run, mock_load_plist):
        """Test WARNING when softwareupdate command times out."""
        mock_load_plist.return_value = None
        mock_run.side_effect = TimeoutExpired(cmd="softwareupdate", timeout=30)
        
        check = SoftwareUpdatePendingCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert "timed out" in result.message.lower()

    @patch("checks.system_integrity.load_plist")
    @patch("checks.system_integrity.run_command")
    def test_command_not_found_returns_error(self, mock_run, mock_load_plist):
        """Test ERROR when softwareupdate is not available."""
        mock_load_plist.return_value = None
        mock_run.side_effect = FileNotFoundError()
        
        check = SoftwareUpdatePendingCheck()
        result = check.run()
        
        assert result.status == Status.ERROR

    @patch("checks.system_integrity.load_plist")
    @patch("checks.system_integrity.run_command")
    def test_command_execution_error_with_updates(self, mock_run, mock_load_plist):
        """Test FAIL when CommandExecutionError contains update info."""
        mock_load_plist.return_value = None
        mock_run.side_effect = CommandExecutionError(
            ["softwareupdate", "-l"],
            "Software update found the following",
            "",
            1
        )
        
        check = SoftwareUpdatePendingCheck()
        result = check.run()
        
        assert result.status == Status.FAIL


class TestAutomaticUpdatesCheck:
    """Test cases for AutomaticUpdatesCheck."""

    @patch("checks.system_integrity.load_plist")
    def test_all_enabled_returns_pass(self, mock_load_plist):
        """Test PASS when all automatic update preferences are enabled."""
        mock_load_plist.return_value = {
            "AutomaticDownload": True,
            "CriticalUpdateInstall": True,
            "ConfigDataInstall": True,
        }
        
        check = AutomaticUpdatesCheck()
        result = check.run()
        
        assert result.status == Status.PASS
        assert "enabled" in result.message.lower()

    @patch("checks.system_integrity.load_plist")
    def test_missing_keys_returns_pass(self, mock_load_plist):
        """Test PASS when keys are missing (default to enabled on modern macOS)."""
        mock_load_plist.return_value = {}
        
        check = AutomaticUpdatesCheck()
        result = check.run()
        
        assert result.status == Status.PASS

    @pytest.mark.parametrize("disabled_key", [
        "AutomaticDownload",
        "CriticalUpdateInstall",
        "ConfigDataInstall",
    ])
    @patch("checks.system_integrity.load_plist")
    def test_single_disabled_returns_warning(self, mock_load_plist, disabled_key):
        """Test WARNING when any update preference is explicitly disabled."""
        prefs = {
            "AutomaticDownload": True,
            "CriticalUpdateInstall": True,
            "ConfigDataInstall": True,
        }
        prefs[disabled_key] = False
        mock_load_plist.return_value = prefs
        
        check = AutomaticUpdatesCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert disabled_key in result.details.get("disabled", [])

    @patch("checks.system_integrity.load_plist")
    def test_multiple_disabled_returns_warning(self, mock_load_plist):
        """Test WARNING when multiple preferences are disabled."""
        mock_load_plist.return_value = {
            "AutomaticDownload": False,
            "CriticalUpdateInstall": False,
            "ConfigDataInstall": True,
        }
        
        check = AutomaticUpdatesCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        disabled = result.details.get("disabled", [])
        assert len(disabled) == 2

    @patch("checks.system_integrity.load_plist")
    def test_plist_not_found_returns_warning(self, mock_load_plist):
        """Test WARNING when preferences plist cannot be read."""
        mock_load_plist.return_value = None
        
        check = AutomaticUpdatesCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert "unable to read" in result.message.lower()


class TestSystemIntegrityCheckMetadata:
    """Test system integrity check metadata."""

    def test_sip_check_metadata(self):
        """Test SystemIntegrityProtectionCheck metadata."""
        check = SystemIntegrityProtectionCheck()
        assert check.name == "System Integrity Protection"
        assert check.category == "system_integrity"
        assert check.severity == Severity.CRITICAL
        assert not check.requires_sudo

    def test_gatekeeper_check_metadata(self):
        """Test GatekeeperCheck metadata."""
        check = GatekeeperCheck()
        assert check.name == "Gatekeeper"
        assert check.category == "system_integrity"
        assert check.severity == Severity.HIGH

    def test_xprotect_check_metadata(self):
        """Test XProtectUpdateCheck metadata."""
        check = XProtectUpdateCheck()
        assert check.name == "XProtect Definitions"
        assert check.category == "system_integrity"
        assert check.severity == Severity.MEDIUM
        assert check.fresh_threshold_days == 30
        assert check.stale_threshold_days == 60

    def test_mrt_check_metadata(self):
        """Test MalwareRemovalToolUpdateCheck metadata."""
        check = MalwareRemovalToolUpdateCheck()
        assert check.name == "Malware Removal Tool"
        assert check.category == "system_integrity"
        assert check.fresh_threshold_days == 30
        assert check.stale_threshold_days == 60

    def test_software_update_check_metadata(self):
        """Test SoftwareUpdatePendingCheck metadata."""
        check = SoftwareUpdatePendingCheck()
        assert check.name == "Software Updates Pending"
        assert check.category == "system_integrity"
        assert check.severity == Severity.MEDIUM

    def test_automatic_updates_check_metadata(self):
        """Test AutomaticUpdatesCheck metadata."""
        check = AutomaticUpdatesCheck()
        assert check.name == "Automatic Updates"
        assert check.category == "system_integrity"
        assert check.severity == Severity.MEDIUM
