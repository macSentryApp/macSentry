"""Unit tests for firewall and network security checks."""
from __future__ import annotations

import pytest
from subprocess import TimeoutExpired
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from macsentry.checks.firewall import (
    FirewallEnabledCheck,
    FirewallStealthModeCheck,
    RemoteLoginCheck,
    ScreenSharingCheck,
    RemoteManagementCheck,
    AirDropDiscoverabilityCheck,
)
from macsentry.checks.types import Status, Severity
from macsentry.utils.commands import CommandExecutionError


class TestFirewallEnabledCheck:
    """Test cases for FirewallEnabledCheck."""

    @pytest.mark.parametrize("output", [
        "Firewall is enabled. (State = 1)",
        "Firewall enabled",
        "State = 1",
    ])
    @patch("checks.firewall.run_command")
    def test_firewall_enabled_returns_pass(self, mock_run, output):
        """Test PASS when firewall is enabled."""
        mock_run.return_value = SimpleNamespace(stdout=output, stderr="", returncode=0)
        
        check = FirewallEnabledCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert "enabled" in result.message.lower()
        assert result.severity == Severity.HIGH

    @pytest.mark.parametrize("output", [
        "Firewall is disabled. (State = 0)",
        "Firewall disabled",
        "State = 0",
    ])
    @patch("checks.firewall.run_command")
    def test_firewall_disabled_returns_fail(self, mock_run, output):
        """Test FAIL when firewall is disabled."""
        mock_run.return_value = SimpleNamespace(stdout=output, stderr="", returncode=0)
        
        check = FirewallEnabledCheck()
        result = check.execute()
        
        assert result.status == Status.FAIL
        assert "disabled" in result.message.lower()

    @patch("checks.firewall.run_command")
    def test_unexpected_output_returns_warning(self, mock_run):
        """Test WARNING when output cannot be parsed."""
        mock_run.return_value = SimpleNamespace(
            stdout="some unknown format",
            stderr="",
            returncode=0
        )
        
        check = FirewallEnabledCheck()
        result = check.execute()
        
        assert result.status == Status.WARNING
        assert "unable to determine" in result.message.lower()

    @patch("checks.firewall.run_command")
    def test_command_not_found_returns_error(self, mock_run):
        """Test ERROR when socketfilterfw is not available."""
        mock_run.side_effect = FileNotFoundError()
        
        check = FirewallEnabledCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR
        assert "not available" in result.message.lower()

    @patch("checks.firewall.run_command")
    def test_command_timeout_returns_error(self, mock_run):
        """Test ERROR when command times out."""
        mock_run.side_effect = TimeoutExpired(cmd="socketfilterfw", timeout=5)
        
        check = FirewallEnabledCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR
        assert "timed out" in result.message.lower()


class TestFirewallStealthModeCheck:
    """Test cases for FirewallStealthModeCheck."""

    @pytest.mark.parametrize("output", [
        "Stealth mode enabled",
        "Stealth mode is on",
    ])
    @patch("checks.firewall.run_command")
    def test_stealth_enabled_returns_pass(self, mock_run, output):
        """Test PASS when stealth mode is enabled."""
        mock_run.return_value = SimpleNamespace(stdout=output, stderr="", returncode=0)
        
        check = FirewallStealthModeCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert "enabled" in result.message.lower()

    @pytest.mark.parametrize("output", [
        "Stealth mode disabled",
        "Stealth mode is off",
    ])
    @patch("checks.firewall.run_command")
    def test_stealth_disabled_returns_warning(self, mock_run, output):
        """Test WARNING when stealth mode is disabled."""
        mock_run.return_value = SimpleNamespace(stdout=output, stderr="", returncode=0)
        
        check = FirewallStealthModeCheck()
        result = check.execute()
        
        assert result.status == Status.WARNING
        assert "disabled" in result.message.lower()

    @patch("checks.firewall.run_command")
    def test_unknown_state_returns_warning(self, mock_run):
        """Test WARNING when state cannot be determined."""
        mock_run.return_value = SimpleNamespace(
            stdout="unexpected output",
            stderr="",
            returncode=0
        )
        
        check = FirewallStealthModeCheck()
        result = check.execute()
        
        assert result.status == Status.WARNING

    @patch("checks.firewall.run_command")
    def test_command_not_found_returns_error(self, mock_run):
        """Test ERROR when command not found."""
        mock_run.side_effect = FileNotFoundError()
        
        check = FirewallStealthModeCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR

    @patch("checks.firewall.run_command")
    def test_timeout_returns_error(self, mock_run):
        """Test ERROR when command times out."""
        mock_run.side_effect = TimeoutExpired(cmd="socketfilterfw", timeout=5)
        
        check = FirewallStealthModeCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR


class TestRemoteLoginCheck:
    """Test cases for RemoteLoginCheck."""

    @patch("checks.firewall.run_command")
    def test_ssh_disabled_via_systemsetup_returns_pass(self, mock_run):
        """Test PASS when SSH is disabled via systemsetup."""
        mock_run.return_value = SimpleNamespace(
            stdout="Remote Login: Off",
            stderr="",
            returncode=0
        )
        
        check = RemoteLoginCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert "disabled" in result.message.lower()

    @patch("checks.firewall.run_command")
    def test_ssh_enabled_via_systemsetup_returns_fail(self, mock_run):
        """Test FAIL when SSH is enabled."""
        mock_run.return_value = SimpleNamespace(
            stdout="Remote Login: On",
            stderr="",
            returncode=0
        )
        
        check = RemoteLoginCheck()
        result = check.execute()
        
        assert result.status == Status.FAIL
        assert "enabled" in result.message.lower()

    @patch("checks.firewall.run_command")
    def test_fallback_to_launchctl_service_not_found(self, mock_run):
        """Test fallback to launchctl when systemsetup fails, service not found."""
        mock_run.side_effect = [
            FileNotFoundError("systemsetup not found"),
            SimpleNamespace(
                stdout="",
                stderr="Could not find service",
                returncode=113
            ),
        ]
        
        check = RemoteLoginCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert "disabled" in result.message.lower()

    @patch("checks.firewall.run_command")
    def test_fallback_launchctl_service_found_returns_fail(self, mock_run):
        """Test FAIL when launchctl shows SSH service running."""
        mock_run.side_effect = [
            FileNotFoundError("systemsetup not found"),
            SimpleNamespace(
                stdout="com.openssh.sshd = {\n    state = running\n}",
                stderr="",
                returncode=0
            ),
        ]
        
        check = RemoteLoginCheck()
        result = check.execute()
        
        assert result.status == Status.FAIL

    @patch("checks.firewall.run_command")
    def test_launchctl_command_error_service_not_found(self, mock_run):
        """Test PASS when launchctl raises error with 'service not found'."""
        mock_run.side_effect = [
            FileNotFoundError("systemsetup not found"),
            CommandExecutionError(
                ["launchctl", "print"],
                "",
                "Could not find service",
                113
            ),
        ]
        
        check = RemoteLoginCheck()
        result = check.execute()
        
        assert result.status == Status.PASS

    @patch("checks.firewall.run_command")
    def test_all_methods_fail_returns_warning(self, mock_run):
        """Test WARNING when all detection methods fail."""
        mock_run.side_effect = [
            FileNotFoundError("systemsetup not found"),
            FileNotFoundError("launchctl not found"),
        ]
        
        check = RemoteLoginCheck()
        result = check.execute()
        
        assert result.status == Status.WARNING
        assert "unable to determine" in result.message.lower()


class TestScreenSharingCheck:
    """Test cases for ScreenSharingCheck."""

    @patch("checks.firewall.run_command")
    def test_screen_sharing_disabled_returns_pass(self, mock_run):
        """Test PASS when screen sharing service is not found."""
        mock_run.return_value = SimpleNamespace(
            stdout="",
            stderr="Could not find service",
            returncode=113
        )
        
        check = ScreenSharingCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert "disabled" in result.message.lower()

    @patch("checks.firewall.run_command")
    def test_screen_sharing_enabled_returns_fail(self, mock_run):
        """Test FAIL when screen sharing service is running."""
        mock_run.return_value = SimpleNamespace(
            stdout="com.apple.screensharing = {\n    state = running\n}",
            stderr="",
            returncode=0
        )
        
        check = ScreenSharingCheck()
        result = check.execute()
        
        assert result.status == Status.FAIL
        assert "enabled" in result.message.lower()

    @patch("checks.firewall.run_command")
    def test_command_error_service_not_found_returns_pass(self, mock_run):
        """Test PASS when CommandExecutionError indicates service not found."""
        mock_run.side_effect = CommandExecutionError(
            ["launchctl", "print"],
            "",
            "Could not find service \"com.apple.screensharing\" in domain",
            113
        )
        
        check = ScreenSharingCheck()
        result = check.execute()
        
        assert result.status == Status.PASS

    @patch("checks.firewall.run_command")
    def test_command_error_other_returns_skip(self, mock_run):
        """Test SKIP when CommandExecutionError for other reasons."""
        mock_run.side_effect = CommandExecutionError(
            ["launchctl", "print"],
            "",
            "Permission denied",
            1
        )
        
        check = ScreenSharingCheck()
        result = check.execute()
        
        assert result.status == Status.SKIP

    @patch("checks.firewall.run_command")
    def test_command_not_found_returns_error(self, mock_run):
        """Test ERROR when launchctl is not available."""
        mock_run.side_effect = FileNotFoundError()
        
        check = ScreenSharingCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR

    @patch("checks.firewall.run_command")
    def test_timeout_returns_error(self, mock_run):
        """Test ERROR when command times out."""
        mock_run.side_effect = TimeoutExpired(cmd="launchctl", timeout=5)
        
        check = ScreenSharingCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR


class TestRemoteManagementCheck:
    """Test cases for RemoteManagementCheck."""

    @patch("checks.firewall.run_command")
    def test_ard_disabled_returns_pass(self, mock_run):
        """Test PASS when ARD service is not found."""
        mock_run.return_value = SimpleNamespace(
            stdout="",
            stderr="Could not find service",
            returncode=113
        )
        
        check = RemoteManagementCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert "disabled" in result.message.lower()
        assert result.severity == Severity.HIGH

    @patch("checks.firewall.run_command")
    def test_ard_enabled_returns_fail(self, mock_run):
        """Test FAIL when ARD service is running."""
        mock_run.return_value = SimpleNamespace(
            stdout="com.apple.RemoteDesktop.agent = {\n    state = running\n}",
            stderr="",
            returncode=0
        )
        
        check = RemoteManagementCheck()
        result = check.execute()
        
        assert result.status == Status.FAIL
        assert "enabled" in result.message.lower()

    @patch("checks.firewall.run_command")
    def test_command_error_service_not_found_returns_pass(self, mock_run):
        """Test PASS when error indicates service not found."""
        mock_run.side_effect = CommandExecutionError(
            ["launchctl", "print"],
            "",
            "Could not find service",
            113
        )
        
        check = RemoteManagementCheck()
        result = check.execute()
        
        assert result.status == Status.PASS


class TestAirDropDiscoverabilityCheck:
    """Test cases for AirDropDiscoverabilityCheck."""

    @pytest.mark.parametrize("mode", ["Contacts Only", "Contacts", "contacts only", "contacts"])
    @patch("checks.firewall.run_command")
    def test_contacts_only_returns_pass(self, mock_run, mode):
        """Test PASS when AirDrop is set to Contacts Only."""
        mock_run.return_value = SimpleNamespace(stdout=mode, stderr="", returncode=0)
        
        check = AirDropDiscoverabilityCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert "contacts" in result.message.lower()

    @pytest.mark.parametrize("mode", ["Off", "Disabled", "off", "disabled"])
    @patch("checks.firewall.run_command")
    def test_airdrop_off_returns_pass(self, mock_run, mode):
        """Test PASS when AirDrop is disabled."""
        mock_run.return_value = SimpleNamespace(stdout=mode, stderr="", returncode=0)
        
        check = AirDropDiscoverabilityCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert "disabled" in result.message.lower()

    @pytest.mark.parametrize("mode", ["Everyone", "everyone"])
    @patch("checks.firewall.run_command")
    def test_everyone_returns_warning(self, mock_run, mode):
        """Test WARNING when AirDrop is set to Everyone."""
        mock_run.return_value = SimpleNamespace(stdout=mode, stderr="", returncode=0)
        
        check = AirDropDiscoverabilityCheck()
        result = check.execute()
        
        assert result.status == Status.WARNING
        assert "everyone" in result.message.lower()

    @patch("checks.firewall.run_command")
    def test_unexpected_mode_returns_warning(self, mock_run):
        """Test WARNING for unknown AirDrop mode."""
        mock_run.return_value = SimpleNamespace(
            stdout="Unknown Mode",
            stderr="",
            returncode=0
        )
        
        check = AirDropDiscoverabilityCheck()
        result = check.execute()
        
        assert result.status == Status.WARNING
        assert "unexpected" in result.message.lower()

    @patch("checks.firewall.run_command")
    def test_fallback_to_second_command(self, mock_run):
        """Test fallback to second defaults domain when first fails."""
        mock_run.side_effect = [
            CommandExecutionError(["defaults"], "", "does not exist", 1),
            SimpleNamespace(stdout="Contacts Only", stderr="", returncode=0),
        ]
        
        check = AirDropDiscoverabilityCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert mock_run.call_count == 2

    @patch("checks.firewall.run_command")
    def test_all_commands_fail_returns_skip(self, mock_run):
        """Test SKIP when all commands fail."""
        mock_run.side_effect = [
            CommandExecutionError(["defaults"], "", "does not exist", 1),
            CommandExecutionError(["defaults"], "", "does not exist", 1),
        ]
        
        check = AirDropDiscoverabilityCheck()
        result = check.execute()
        
        assert result.status == Status.SKIP

    @patch("checks.firewall.run_command")
    def test_command_not_found_returns_error(self, mock_run):
        """Test ERROR when defaults command is not available."""
        mock_run.side_effect = FileNotFoundError()
        
        check = AirDropDiscoverabilityCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR


class TestFirewallCheckMetadata:
    """Test firewall check metadata and attributes."""

    def test_firewall_enabled_metadata(self):
        """Test FirewallEnabledCheck metadata."""
        check = FirewallEnabledCheck()
        assert check.name == "Application Firewall"
        assert check.category == "firewall"
        assert check.severity == Severity.HIGH
        assert not check.requires_sudo

    def test_stealth_mode_metadata(self):
        """Test FirewallStealthModeCheck metadata."""
        check = FirewallStealthModeCheck()
        assert check.name == "Firewall Stealth Mode"
        assert check.category == "firewall"
        assert check.severity == Severity.MEDIUM

    def test_remote_login_metadata(self):
        """Test RemoteLoginCheck metadata."""
        check = RemoteLoginCheck()
        assert check.name == "Remote Login (SSH)"
        assert check.category == "firewall"
        assert check.severity == Severity.MEDIUM

    def test_screen_sharing_metadata(self):
        """Test ScreenSharingCheck metadata."""
        check = ScreenSharingCheck()
        assert check.name == "Screen Sharing"
        assert check.category == "firewall"
        assert check.severity == Severity.MEDIUM

    def test_remote_management_metadata(self):
        """Test RemoteManagementCheck metadata."""
        check = RemoteManagementCheck()
        assert check.name == "Remote Management"
        assert check.category == "firewall"
        assert check.severity == Severity.HIGH

    def test_airdrop_metadata(self):
        """Test AirDropDiscoverabilityCheck metadata."""
        check = AirDropDiscoverabilityCheck()
        assert check.name == "AirDrop Discoverability"
        assert check.category == "firewall"
        assert check.severity == Severity.MEDIUM
