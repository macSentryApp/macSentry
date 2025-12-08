"""Unit tests for application security checks."""
from __future__ import annotations

import pytest
from pathlib import Path
from subprocess import TimeoutExpired
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, PropertyMock

from macsentry.checks.applications import (
    UnsignedApplicationsCheck,
    DangerousEntitlementsCheck,
    QuarantineEnforcementCheck,
    _iter_app_bundles,
    _APPLICATIONS_DIRS,
    _MAX_APPS_TO_SCAN,
)
from macsentry.checks.types import Status, Severity


class TestIterAppBundles:
    """Test the _iter_app_bundles helper function."""

    @patch("checks.applications.Path.home")
    def test_iterates_app_directories(self, mock_home, tmp_path):
        """Test that function iterates .app bundles in expected directories."""
        # Create mock Applications directories
        sys_apps = tmp_path / "Applications"
        user_apps = tmp_path / "UserApps"
        sys_apps.mkdir()
        user_apps.mkdir()
        
        # Create mock apps
        (sys_apps / "Safari.app").mkdir()
        (sys_apps / "Terminal.app").mkdir()
        (user_apps / "CustomApp.app").mkdir()
        (sys_apps / "NotAnApp").mkdir()  # Should be ignored
        
        mock_home.return_value = tmp_path
        
        with patch("checks.applications._APPLICATIONS_DIRS", (sys_apps, user_apps)):
            apps = list(_iter_app_bundles())
        
        assert len(apps) == 3
        app_names = [a.name for a in apps]
        assert "Safari.app" in app_names
        assert "Terminal.app" in app_names
        assert "CustomApp.app" in app_names
        assert "NotAnApp" not in app_names

    @patch("checks.applications.Path.home")
    def test_respects_max_apps_limit(self, mock_home, tmp_path):
        """Test that iteration stops at _MAX_APPS_TO_SCAN."""
        apps_dir = tmp_path / "Applications"
        apps_dir.mkdir()
        
        # Create more apps than the limit
        for i in range(50):
            (apps_dir / f"App{i:02d}.app").mkdir()
        
        mock_home.return_value = tmp_path
        
        with patch("checks.applications._APPLICATIONS_DIRS", (apps_dir,)):
            with patch("checks.applications._MAX_APPS_TO_SCAN", 10):
                apps = list(_iter_app_bundles())
        
        assert len(apps) == 10

    @patch("checks.applications.Path.home")
    def test_handles_missing_directories(self, mock_home, tmp_path):
        """Test graceful handling when directories don't exist."""
        mock_home.return_value = tmp_path
        nonexistent = tmp_path / "NonExistent"
        
        with patch("checks.applications._APPLICATIONS_DIRS", (nonexistent,)):
            apps = list(_iter_app_bundles())
        
        assert apps == []

    @patch("checks.applications.Path.home")
    def test_deduplicates_symlinked_apps(self, mock_home, tmp_path):
        """Test that symlinked apps are deduplicated."""
        apps_dir = tmp_path / "Applications"
        apps_dir.mkdir()
        
        real_app = apps_dir / "RealApp.app"
        real_app.mkdir()
        
        # Create symlink to same app
        symlink = apps_dir / "SymlinkApp.app"
        symlink.symlink_to(real_app)
        
        mock_home.return_value = tmp_path
        
        with patch("checks.applications._APPLICATIONS_DIRS", (apps_dir,)):
            apps = list(_iter_app_bundles())
        
        # Should only count once despite symlink
        assert len(apps) == 1


class TestUnsignedApplicationsCheck:
    """Test cases for UnsignedApplicationsCheck."""

    @patch("shutil.which")
    def test_codesign_not_present_returns_skip(self, mock_which):
        """Test SKIP when codesign tool is not available."""
        mock_which.return_value = None
        
        check = UnsignedApplicationsCheck()
        result = check.run()
        
        assert result.status == Status.SKIP
        assert "not present" in result.message.lower()

    @patch("shutil.which")
    @patch("checks.applications._iter_app_bundles")
    @patch("checks.applications.run_command")
    def test_all_signed_returns_pass(self, mock_run, mock_iter, mock_which):
        """Test PASS when all scanned applications are signed."""
        mock_which.return_value = "/usr/bin/codesign"
        mock_iter.return_value = [
            Path("/Applications/Safari.app"),
            Path("/Applications/Terminal.app"),
        ]
        mock_run.return_value = SimpleNamespace(stdout="", stderr="", returncode=0)
        
        check = UnsignedApplicationsCheck()
        result = check.run()
        
        assert result.status == Status.PASS
        assert "signed" in result.message.lower()

    @patch("shutil.which")
    @patch("checks.applications._iter_app_bundles")
    @patch("checks.applications.run_command")
    def test_unsigned_app_returns_warning(self, mock_run, mock_iter, mock_which):
        """Test WARNING when unsigned applications are detected."""
        mock_which.return_value = "/usr/bin/codesign"
        mock_iter.return_value = [
            Path("/Applications/Signed.app"),
            Path("/Applications/Unsigned.app"),
        ]
        # First app signed, second truly unsigned (not just validation failure)
        mock_run.side_effect = [
            SimpleNamespace(stdout="", stderr="", returncode=0),
            SimpleNamespace(stdout="", stderr="code object is not signed at all", returncode=3),
        ]
        
        check = UnsignedApplicationsCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert "unsigned" in result.message.lower()
        apps = result.details.get("applications", [])
        assert "/Applications/Unsigned.app" in apps

    @patch("shutil.which")
    @patch("checks.applications._iter_app_bundles")
    @patch("checks.applications.run_command")
    def test_timeout_logged_as_error(self, mock_run, mock_iter, mock_which):
        """Test that timeout errors are captured but don't fail the check."""
        mock_which.return_value = "/usr/bin/codesign"
        mock_iter.return_value = [
            Path("/Applications/SlowApp.app"),
            Path("/Applications/NormalApp.app"),
        ]
        mock_run.side_effect = [
            TimeoutExpired(cmd="codesign", timeout=15),
            SimpleNamespace(stdout="", stderr="", returncode=0),
        ]
        
        check = UnsignedApplicationsCheck()
        result = check.run()
        
        # Should return WARNING due to errors, not PASS
        assert result.status == Status.WARNING
        assert "unable to assess" in result.message.lower()

    @patch("shutil.which")
    @patch("checks.applications._iter_app_bundles")
    @patch("checks.applications.run_command")
    def test_codesign_not_found_during_scan_returns_skip(self, mock_run, mock_iter, mock_which):
        """Test SKIP when codesign disappears during scan."""
        mock_which.return_value = "/usr/bin/codesign"
        mock_iter.return_value = [Path("/Applications/Test.app")]
        mock_run.side_effect = FileNotFoundError("codesign not found")
        
        check = UnsignedApplicationsCheck()
        result = check.run()
        
        assert result.status == Status.SKIP

    @patch("shutil.which")
    @patch("checks.applications._iter_app_bundles")
    @patch("checks.applications.run_command")
    def test_validation_failure_not_flagged_as_unsigned(self, mock_run, mock_iter, mock_which):
        """Test that apps with validation failures (not truly unsigned) are not flagged."""
        mock_which.return_value = "/usr/bin/codesign"
        mock_iter.return_value = [
            Path("/Applications/Comet.app"),
            Path("/Applications/Google Chrome.app"),
        ]
        # Both apps are signed but fail strict validation (e.g., resource envelope issues)
        mock_run.side_effect = [
            SimpleNamespace(stdout="", stderr="a sealed resource is missing or invalid", returncode=3),
            SimpleNamespace(stdout="", stderr="resource envelope is obsolete", returncode=3),
        ]
        
        check = UnsignedApplicationsCheck()
        result = check.run()
        
        # Should PASS since no apps are truly unsigned
        assert result.status == Status.PASS
        assert "signed" in result.message.lower()


class TestDangerousEntitlementsCheck:
    """Test cases for DangerousEntitlementsCheck."""

    @patch("checks.applications._iter_app_bundles")
    @patch("checks.applications.run_command")
    def test_no_dangerous_entitlements_returns_pass(self, mock_run, mock_iter):
        """Test PASS when no dangerous entitlements detected."""
        mock_iter.return_value = [
            Path("/Applications/SafeApp.app"),
        ]
        mock_run.return_value = SimpleNamespace(
            stdout="<plist><dict></dict></plist>",
            stderr="",
            returncode=0
        )
        
        check = DangerousEntitlementsCheck()
        result = check.run()
        
        assert result.status == Status.PASS
        assert "no dangerous" in result.message.lower()

    @pytest.mark.parametrize("entitlement,expected_msg", [
        ("com.apple.security.cs.disable-library-validation", "dangerous entitlements"),
        ("com.apple.security.get-task-allow", "get-task-allow"),  # Critical message for this
    ])
    @patch("checks.applications._iter_app_bundles")
    @patch("checks.applications.run_command")
    def test_dangerous_entitlement_returns_fail(self, mock_run, mock_iter, entitlement, expected_msg):
        """Test FAIL when dangerous entitlements detected."""
        mock_iter.return_value = [Path("/Applications/RiskyApp.app")]
        mock_run.return_value = SimpleNamespace(
            stdout=f"<key>{entitlement}</key><true/>",
            stderr="",
            returncode=0
        )
        
        check = DangerousEntitlementsCheck()
        result = check.run()
        
        assert result.status == Status.FAIL
        assert expected_msg in result.message.lower()
        assert "/Applications/RiskyApp.app" in result.details.get("applications", [])
        assert result.severity == Severity.HIGH

    @patch("checks.applications._iter_app_bundles")
    @patch("checks.applications.run_command")
    def test_timeout_handled_gracefully(self, mock_run, mock_iter):
        """Test that timeout errors don't crash the check."""
        mock_iter.return_value = [
            Path("/Applications/SlowApp.app"),
            Path("/Applications/FastApp.app"),
        ]
        mock_run.side_effect = [
            TimeoutExpired(cmd="codesign", timeout=15),
            SimpleNamespace(stdout="", stderr="", returncode=0),
        ]
        
        check = DangerousEntitlementsCheck()
        result = check.run()
        
        # Should return WARNING due to errors
        assert result.status == Status.WARNING

    @patch("checks.applications._iter_app_bundles")
    @patch("checks.applications.run_command")
    def test_codesign_not_found_returns_skip(self, mock_run, mock_iter):
        """Test SKIP when codesign is not available."""
        mock_iter.return_value = [Path("/Applications/Test.app")]
        mock_run.side_effect = FileNotFoundError()
        
        check = DangerousEntitlementsCheck()
        result = check.run()
        
        assert result.status == Status.SKIP

    def test_risky_entitlements_list(self):
        """Test that risky entitlements are properly defined."""
        check = DangerousEntitlementsCheck()
        assert "com.apple.security.cs.disable-library-validation" in check.risky_entitlements
        assert "com.apple.security.get-task-allow" in check.risky_entitlements
        # Verify each entitlement has required metadata
        for ent_key, ent_info in check.risky_entitlements.items():
            assert "short_name" in ent_info
            assert "risk_level" in ent_info
            assert "explanation" in ent_info

    def test_expected_entitlements_defined(self):
        """Test that expected entitlements list includes known legitimate apps."""
        check = DangerousEntitlementsCheck()
        # VPN apps should be in the expected list
        assert "Mullvad VPN.app" in check.expected_entitlements
        assert "Tailscale.app" in check.expected_entitlements
        # Dev tools should be in the expected list
        assert "Xcode.app" in check.expected_entitlements

    def test_get_task_allow_marked_critical(self):
        """Test that get-task-allow is marked as critical risk."""
        check = DangerousEntitlementsCheck()
        ent_info = check.risky_entitlements.get("com.apple.security.get-task-allow")
        assert ent_info is not None
        assert ent_info["risk_level"] == "critical"


class TestQuarantineEnforcementCheck:
    """Test cases for QuarantineEnforcementCheck."""

    @pytest.mark.parametrize("enabled_value", ["1", "true", "yes"])
    @patch("utils.commands.run_defaults_for_user")
    def test_quarantine_enabled_returns_pass(self, mock_run, enabled_value):
        """Test PASS when quarantine enforcement is enabled."""
        mock_run.return_value = SimpleNamespace(
            stdout=enabled_value,
            stderr="",
            returncode=0
        )
        
        check = QuarantineEnforcementCheck()
        result = check.run()
        
        assert result.status == Status.PASS
        assert "enabled" in result.message.lower()

    @pytest.mark.parametrize("disabled_value", ["0", "false", "no"])
    @patch("utils.commands.run_defaults_for_user")
    def test_quarantine_disabled_returns_fail(self, mock_run, disabled_value):
        """Test FAIL when quarantine enforcement is disabled."""
        mock_run.return_value = SimpleNamespace(
            stdout=disabled_value,
            stderr="",
            returncode=0
        )
        
        check = QuarantineEnforcementCheck()
        result = check.run()
        
        assert result.status == Status.FAIL
        assert "disabled" in result.message.lower()

    @patch("utils.commands.run_defaults_for_user")
    def test_unknown_value_returns_warning(self, mock_run):
        """Test WARNING when value cannot be parsed."""
        mock_run.return_value = SimpleNamespace(
            stdout="unexpected value",
            stderr="",
            returncode=0
        )
        
        check = QuarantineEnforcementCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert "unable to determine" in result.message.lower()

    @patch("utils.commands.run_defaults_for_user")
    def test_command_not_found_returns_error(self, mock_run):
        """Test ERROR when defaults command not available."""
        mock_run.side_effect = FileNotFoundError()
        
        check = QuarantineEnforcementCheck()
        result = check.run()
        
        assert result.status == Status.ERROR

    @patch("utils.commands.run_defaults_for_user")
    def test_timeout_returns_error(self, mock_run):
        """Test ERROR when command times out."""
        mock_run.side_effect = TimeoutExpired(cmd="defaults", timeout=5)
        
        check = QuarantineEnforcementCheck()
        result = check.run()
        
        assert result.status == Status.ERROR
        assert "timed out" in result.message.lower()


class TestApplicationsCheckMetadata:
    """Test applications check metadata."""

    def test_unsigned_apps_metadata(self):
        """Test UnsignedApplicationsCheck metadata."""
        check = UnsignedApplicationsCheck()
        assert check.name == "Unsigned Applications"
        assert check.category == "applications"
        assert check.severity == Severity.MEDIUM
        assert not check.requires_sudo

    def test_dangerous_entitlements_metadata(self):
        """Test DangerousEntitlementsCheck metadata."""
        check = DangerousEntitlementsCheck()
        assert check.name == "Dangerous Application Entitlements"
        assert check.category == "applications"
        assert check.severity == Severity.HIGH

    def test_quarantine_metadata(self):
        """Test QuarantineEnforcementCheck metadata."""
        check = QuarantineEnforcementCheck()
        assert check.name == "Quarantine Enforcement"
        assert check.category == "applications"
        assert check.severity == Severity.MEDIUM


class TestApplicationsCheckEdgeCases:
    """Edge case tests for applications checks."""

    @patch("shutil.which")
    @patch("checks.applications._iter_app_bundles")
    def test_no_apps_to_scan_returns_pass(self, mock_iter, mock_which):
        """Test PASS when no applications to scan."""
        mock_which.return_value = "/usr/bin/codesign"
        mock_iter.return_value = []
        
        check = UnsignedApplicationsCheck()
        result = check.run()
        
        assert result.status == Status.PASS

    @patch("shutil.which")
    @patch("checks.applications._iter_app_bundles")
    @patch("checks.applications.run_command")
    def test_multiple_unsigned_apps(self, mock_run, mock_iter, mock_which):
        """Test correct handling of multiple unsigned apps."""
        mock_which.return_value = "/usr/bin/codesign"
        mock_iter.return_value = [
            Path("/Applications/Unsigned1.app"),
            Path("/Applications/Unsigned2.app"),
            Path("/Applications/Signed.app"),
        ]
        # Use "not signed" or "code signature not found" to trigger unsigned detection
        mock_run.side_effect = [
            SimpleNamespace(stdout="", stderr="code object is not signed at all", returncode=3),
            SimpleNamespace(stdout="", stderr="code signature not found", returncode=3),
            SimpleNamespace(stdout="", stderr="", returncode=0),
        ]
        
        check = UnsignedApplicationsCheck()
        result = check.run()
        
        apps = result.details.get("applications", [])
        assert len(apps) == 2
        assert "/Applications/Unsigned1.app" in apps
        assert "/Applications/Unsigned2.app" in apps
