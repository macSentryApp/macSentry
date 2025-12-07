"""Unit tests for authentication security checks."""
from __future__ import annotations

import pytest
from pathlib import Path
from subprocess import TimeoutExpired
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, mock_open

from checks.authentication import (
    AutoLoginDisabledCheck,
    GuestAccountDisabledCheck,
    ScreenSaverPasswordCheck,
    SudoTimeoutCheck,
    PasswordPolicyCheck,
)
from checks.types import Status, Severity


class TestAutoLoginDisabledCheck:
    """Test cases for AutoLoginDisabledCheck."""

    @pytest.mark.parametrize("macos_version", ["13.0", "14.0", "15.0"])
    @patch("checks.authentication.run_command")
    def test_autologin_disabled_returns_pass(self, mock_run, macos_version):
        """Test PASS when automatic login is not configured."""
        mock_run.return_value = SimpleNamespace(
            stdout="",
            stderr="The domain/default pair does not exist",
            returncode=1
        )
        
        check = AutoLoginDisabledCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert "not configured" in result.message.lower()

    @pytest.mark.parametrize("username", ["admin", "testuser", "root"])
    @patch("checks.authentication.run_command")
    def test_autologin_enabled_returns_fail(self, mock_run, username):
        """Test FAIL when automatic login is enabled for any user."""
        mock_run.return_value = SimpleNamespace(
            stdout=username,
            stderr="",
            returncode=0
        )
        
        check = AutoLoginDisabledCheck()
        result = check.execute()
        
        assert result.status == Status.FAIL
        assert username in result.message
        assert result.details.get("username") == username
        assert result.severity == Severity.HIGH

    @patch("checks.authentication.run_command")
    def test_command_not_found_returns_error(self, mock_run):
        """Test ERROR when defaults command is not available."""
        mock_run.side_effect = FileNotFoundError("defaults not found")
        
        check = AutoLoginDisabledCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR
        assert "not available" in result.message.lower()

    @patch("checks.authentication.run_command")
    def test_command_timeout_returns_error(self, mock_run):
        """Test ERROR when command times out."""
        mock_run.side_effect = TimeoutExpired(cmd="defaults", timeout=5)
        
        check = AutoLoginDisabledCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR
        assert "timed out" in result.message.lower()


class TestGuestAccountDisabledCheck:
    """Test cases for GuestAccountDisabledCheck."""

    @pytest.mark.parametrize("disabled_value", ["0", "false", "no", "off"])
    @patch("checks.authentication.run_command")
    def test_guest_disabled_returns_pass(self, mock_run, disabled_value):
        """Test PASS when guest account is disabled with various formats."""
        mock_run.return_value = SimpleNamespace(
            stdout=disabled_value,
            stderr="",
            returncode=0
        )
        
        check = GuestAccountDisabledCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert "disabled" in result.message.lower()

    @pytest.mark.parametrize("enabled_value", ["1", "true", "yes", "on"])
    @patch("checks.authentication.run_command")
    def test_guest_enabled_returns_fail(self, mock_run, enabled_value):
        """Test FAIL when guest account is enabled."""
        mock_run.return_value = SimpleNamespace(
            stdout=enabled_value,
            stderr="",
            returncode=0
        )
        
        check = GuestAccountDisabledCheck()
        result = check.execute()
        
        assert result.status == Status.FAIL
        assert "enabled" in result.message.lower()
        assert result.severity == Severity.MEDIUM

    @patch("checks.authentication.run_command")
    def test_guest_not_configured_returns_pass(self, mock_run):
        """Test PASS when guest account preference doesn't exist."""
        mock_run.return_value = SimpleNamespace(
            stdout="",
            stderr="does not exist",
            returncode=1
        )
        
        check = GuestAccountDisabledCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert "not configured" in result.message.lower()

    @patch("checks.authentication.run_command")
    def test_command_not_found_returns_error(self, mock_run):
        """Test ERROR when defaults command is not available."""
        mock_run.side_effect = FileNotFoundError()
        
        check = GuestAccountDisabledCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR

    @patch("checks.authentication.run_command")
    def test_command_timeout_returns_error(self, mock_run):
        """Test ERROR when command times out."""
        mock_run.side_effect = TimeoutExpired(cmd="defaults", timeout=5)
        
        check = GuestAccountDisabledCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR
        assert "timed out" in result.message.lower()


class TestScreenSaverPasswordCheck:
    """Test cases for ScreenSaverPasswordCheck."""

    @pytest.mark.parametrize("macos_version,output", [
        ("13.0", "screenLock is immediate"),
        ("14.0", "screenLock is immediate"),
        ("15.0", "screenLock is immediate"),
    ])
    @patch("checks.authentication.run_command")
    def test_immediate_password_returns_pass(self, mock_run, macos_version, output):
        """Test PASS when password is required immediately across macOS versions."""
        mock_run.return_value = SimpleNamespace(
            stdout=output,
            stderr="",
            returncode=0
        )
        
        check = ScreenSaverPasswordCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert "immediately" in result.message.lower()

    @pytest.mark.parametrize("delay_seconds", [5, 10, 60, 300])
    @patch("checks.authentication.run_command")
    def test_delayed_password_returns_warning(self, mock_run, delay_seconds):
        """Test WARNING when password has a delay configured."""
        mock_run.return_value = SimpleNamespace(
            stdout=f"screenLock delay is {delay_seconds} seconds",
            stderr="",
            returncode=0
        )
        
        check = ScreenSaverPasswordCheck()
        result = check.execute()
        
        assert result.status == Status.WARNING
        assert str(delay_seconds) in result.message
        assert result.details.get("delay_seconds") == delay_seconds

    @pytest.mark.parametrize("disabled_output", [
        "screenLock is off",
        "screenLock is disabled",
    ])
    @patch("checks.authentication.run_command")
    def test_disabled_password_returns_fail(self, mock_run, disabled_output):
        """Test FAIL when screen lock password is disabled."""
        mock_run.return_value = SimpleNamespace(
            stdout=disabled_output,
            stderr="",
            returncode=0
        )
        
        check = ScreenSaverPasswordCheck()
        result = check.execute()
        
        assert result.status == Status.FAIL
        assert "disabled" in result.message.lower()

    @patch("checks.authentication.run_command")
    def test_fallback_to_defaults_when_sysadminctl_missing(self, mock_run):
        """Test fallback to defaults command when sysadminctl is not found."""
        # First call (sysadminctl) raises FileNotFoundError
        # Second call (defaults fallback) returns password enabled
        mock_run.side_effect = [
            FileNotFoundError("sysadminctl not found"),
            SimpleNamespace(stdout="1", stderr="", returncode=0),
        ]
        
        check = ScreenSaverPasswordCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert mock_run.call_count == 2

    @patch("checks.authentication.run_command")
    def test_fallback_defaults_disabled_returns_fail(self, mock_run):
        """Test fallback defaults check returns FAIL when password not required."""
        mock_run.side_effect = [
            FileNotFoundError("sysadminctl not found"),
            SimpleNamespace(stdout="0", stderr="", returncode=0),
        ]
        
        check = ScreenSaverPasswordCheck()
        result = check.execute()
        
        assert result.status == Status.FAIL

    @patch("checks.authentication.run_command")
    def test_timeout_returns_error(self, mock_run):
        """Test ERROR when command times out."""
        mock_run.side_effect = TimeoutExpired(cmd="sysadminctl", timeout=5)
        
        check = ScreenSaverPasswordCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR

    @patch("checks.authentication.run_command")
    def test_unexpected_output_returns_warning(self, mock_run):
        """Test WARNING when output cannot be parsed."""
        mock_run.return_value = SimpleNamespace(
            stdout="some unexpected output format",
            stderr="",
            returncode=0
        )
        
        check = ScreenSaverPasswordCheck()
        result = check.execute()
        
        assert result.status == Status.WARNING
        assert "unable to determine" in result.message.lower()


class TestSudoTimeoutCheck:
    """Test cases for SudoTimeoutCheck."""

    def test_requires_sudo_attribute(self):
        """Test that check requires sudo."""
        check = SudoTimeoutCheck()
        assert check.requires_sudo is True

    @patch("checks.authentication.Path.read_text")
    def test_default_timeout_returns_warning(self, mock_read):
        """Test WARNING when timestamp_timeout is not explicitly set."""
        mock_read.return_value = "# Default sudoers file\nroot ALL=(ALL) ALL\n"
        
        check = SudoTimeoutCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert "not explicitly set" in result.message.lower()

    @pytest.mark.parametrize("timeout_value", [1, 3, 5, 10, 15])
    @patch("checks.authentication.Path.read_text")
    def test_reasonable_timeout_returns_pass(self, mock_read, timeout_value):
        """Test PASS when timeout is between 1-15 minutes."""
        mock_read.return_value = f"Defaults timestamp_timeout = {timeout_value}\n"
        
        check = SudoTimeoutCheck()
        result = check.run()
        
        assert result.status == Status.PASS
        assert str(timeout_value) in result.message
        assert result.details.get("timeout") == timeout_value

    @pytest.mark.parametrize("timeout_value", [-1, 0])
    @patch("checks.authentication.Path.read_text")
    def test_disabled_timeout_returns_fail(self, mock_read, timeout_value):
        """Test FAIL when timeout is disabled (0 or negative)."""
        mock_read.return_value = f"Defaults timestamp_timeout={timeout_value}\n"
        
        check = SudoTimeoutCheck()
        result = check.run()
        
        assert result.status == Status.FAIL
        assert "disabled" in result.message.lower() or "unlimited" in result.message.lower()

    @pytest.mark.parametrize("timeout_value", [20, 30, 60, 120])
    @patch("checks.authentication.Path.read_text")
    def test_high_timeout_returns_warning(self, mock_read, timeout_value):
        """Test WARNING when timeout is too long (>15 minutes)."""
        mock_read.return_value = f"Defaults timestamp_timeout = {timeout_value}\n"
        
        check = SudoTimeoutCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert str(timeout_value) in result.message

    @patch("checks.authentication.Path.read_text")
    def test_file_not_found_returns_error(self, mock_read):
        """Test ERROR when /etc/sudoers doesn't exist."""
        mock_read.side_effect = FileNotFoundError()
        
        check = SudoTimeoutCheck()
        result = check.run()
        
        assert result.status == Status.ERROR
        assert "not found" in result.message.lower()

    @patch("checks.authentication.Path.read_text")
    def test_permission_denied_returns_skip(self, mock_read):
        """Test SKIP when lacking permission to read sudoers."""
        mock_read.side_effect = PermissionError()
        
        check = SudoTimeoutCheck()
        result = check.run()
        
        assert result.status == Status.SKIP
        assert "privileges" in result.message.lower()


class TestPasswordPolicyCheck:
    """Test cases for PasswordPolicyCheck."""

    def test_requires_sudo_attribute(self):
        """Test that check requires sudo."""
        check = PasswordPolicyCheck()
        assert check.requires_sudo is True

    @patch("checks.authentication.run_command")
    def test_strong_policy_returns_pass(self, mock_run):
        """Test PASS when password policy is strong."""
        mock_run.return_value = SimpleNamespace(
            stdout='minLength = 14\nmaxFailedAttempts = 5',
            stderr="",
            returncode=0
        )
        
        check = PasswordPolicyCheck()
        result = check.run()
        
        assert result.status == Status.PASS
        assert "enforces" in result.message.lower()

    @pytest.mark.parametrize("min_length", [4, 6, 8, 10, 11])
    @patch("checks.authentication.run_command")
    def test_weak_min_length_returns_warning(self, mock_run, min_length):
        """Test WARNING when minimum password length is less than 12."""
        mock_run.return_value = SimpleNamespace(
            stdout=f'minLength = {min_length}\nmaxFailedAttempts = 5',
            stderr="",
            returncode=0
        )
        
        check = PasswordPolicyCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert "lax" in result.message.lower()
        assert "findings" in result.details

    @pytest.mark.parametrize("max_failed", [15, 20, 50, 100])
    @patch("checks.authentication.run_command")
    def test_high_max_failed_returns_warning(self, mock_run, max_failed):
        """Test WARNING when max failed attempts is too high."""
        mock_run.return_value = SimpleNamespace(
            stdout=f'minLength = 14\nmaxFailedAttempts = {max_failed}',
            stderr="",
            returncode=0
        )
        
        check = PasswordPolicyCheck()
        result = check.run()
        
        assert result.status == Status.WARNING

    @patch("checks.authentication.run_command")
    def test_no_min_length_returns_warning(self, mock_run):
        """Test WARNING when minimum length requirement not found."""
        mock_run.return_value = SimpleNamespace(
            stdout='maxFailedAttempts = 5',
            stderr="",
            returncode=0
        )
        
        check = PasswordPolicyCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        findings = result.details.get("findings", [])
        assert any("not found" in f.lower() for f in findings)

    @patch("checks.authentication.run_command")
    def test_empty_policy_returns_warning(self, mock_run):
        """Test WARNING when policy output is empty."""
        mock_run.return_value = SimpleNamespace(
            stdout="",
            stderr="",
            returncode=0
        )
        
        check = PasswordPolicyCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert "unable to parse" in result.message.lower()

    @patch("checks.authentication.run_command")
    def test_command_not_found_returns_error(self, mock_run):
        """Test ERROR when pwpolicy command is not available."""
        mock_run.side_effect = FileNotFoundError()
        
        check = PasswordPolicyCheck()
        result = check.run()
        
        assert result.status == Status.ERROR
        assert "not available" in result.message.lower()

    @patch("checks.authentication.run_command")
    def test_command_timeout_returns_error(self, mock_run):
        """Test ERROR when pwpolicy command times out."""
        mock_run.side_effect = TimeoutExpired(cmd="pwpolicy", timeout=10)
        
        check = PasswordPolicyCheck()
        result = check.run()
        
        assert result.status == Status.ERROR
        assert "timed out" in result.message.lower()

    @patch("checks.authentication.run_command")
    def test_json_style_policy_output(self, mock_run):
        """Test parsing JSON-style policy output (macOS 14+)."""
        mock_run.return_value = SimpleNamespace(
            stdout='minLength": 16\nmaxFailedAttempts": 3',
            stderr="",
            returncode=0
        )
        
        check = PasswordPolicyCheck()
        result = check.run()
        
        assert result.status == Status.PASS


class TestAuthenticationCheckMetadata:
    """Test check metadata and attributes."""

    def test_autologin_check_metadata(self):
        """Test AutoLoginDisabledCheck has correct metadata."""
        check = AutoLoginDisabledCheck()
        assert check.name == "Automatic Login"
        assert check.category == "authentication"
        assert check.severity == Severity.HIGH
        assert not check.requires_sudo

    def test_guest_check_metadata(self):
        """Test GuestAccountDisabledCheck has correct metadata."""
        check = GuestAccountDisabledCheck()
        assert check.name == "Guest Account"
        assert check.category == "authentication"
        assert check.severity == Severity.MEDIUM

    def test_screensaver_check_metadata(self):
        """Test ScreenSaverPasswordCheck has correct metadata."""
        check = ScreenSaverPasswordCheck()
        assert check.name == "Screen Saver Password"
        assert check.category == "authentication"
        assert check.severity == Severity.MEDIUM

    def test_sudo_timeout_check_metadata(self):
        """Test SudoTimeoutCheck has correct metadata."""
        check = SudoTimeoutCheck()
        assert check.name == "Sudo Session Timeout"
        assert check.category == "authentication"
        assert check.requires_sudo is True

    def test_password_policy_check_metadata(self):
        """Test PasswordPolicyCheck has correct metadata."""
        check = PasswordPolicyCheck()
        assert check.name == "Password Policy"
        assert check.category == "authentication"
        assert check.requires_sudo is True
