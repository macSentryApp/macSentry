"""Unit tests for privacy and permissions security checks."""
from __future__ import annotations

import sqlite3
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from checks.privacy import (
    CameraPermissionsCheck,
    ScreenRecordingPermissionsCheck,
    MicrophonePermissionsCheck,
    AccessibilityPermissionsCheck,
    FullDiskAccessPermissionsCheck,
    LocationPermissionsCheck,
    TCCAccessCheck,
    _TCCPermissionMixin,
    _reset_tcc_access_state,
)
from checks.types import Status, Severity


@pytest.fixture(autouse=True)
def reset_tcc_state():
    """Reset TCC access state before and after each test."""
    _reset_tcc_access_state()
    yield
    _reset_tcc_access_state()


class TestTCCPermissionMixin:
    """Test cases for the shared TCC permission mixin."""

    def test_filter_third_party_excludes_apple(self):
        """Test that Apple apps are filtered out."""
        bundle_ids = [
            "com.apple.Safari",
            "com.apple.finder",
            "com.example.thirdparty",
            "org.mozilla.firefox",
            "com.apple.mail",
        ]
        
        result = _TCCPermissionMixin._filter_third_party(bundle_ids)
        
        assert result == ["com.example.thirdparty", "org.mozilla.firefox"]
        assert not any(b.startswith("com.apple.") for b in result)

    def test_filter_third_party_empty_list(self):
        """Test filtering empty list returns empty."""
        result = _TCCPermissionMixin._filter_third_party([])
        assert result == []

    def test_filter_third_party_all_apple(self):
        """Test filtering all Apple apps returns empty."""
        bundle_ids = ["com.apple.Safari", "com.apple.finder", "com.apple.mail"]
        result = _TCCPermissionMixin._filter_third_party(bundle_ids)
        assert result == []


class TestCameraPermissionsCheck:
    """Test cases for CameraPermissionsCheck."""

    @patch.object(CameraPermissionsCheck, "_read_tcc_entries")
    def test_no_third_party_access_returns_pass(self, mock_read):
        """Test PASS when no third-party apps have camera access."""
        mock_read.return_value = (Status.PASS, ["com.apple.Safari", "com.apple.FaceTime"], "OK")
        
        check = CameraPermissionsCheck()
        result = check.run()
        
        assert result.status == Status.PASS
        assert "no third-party" in result.message.lower()

    @patch.object(CameraPermissionsCheck, "_read_tcc_entries")
    def test_third_party_access_returns_warning(self, mock_read):
        """Test WARNING when third-party apps have camera access."""
        mock_read.return_value = (
            Status.PASS,
            ["com.apple.Safari", "us.zoom.xos", "com.skype.skype"],
            "OK"
        )
        
        check = CameraPermissionsCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert "third-party" in result.message.lower()
        apps = result.details.get("applications", [])
        assert "us.zoom.xos" in apps
        assert "com.skype.skype" in apps
        assert "com.apple.Safari" not in apps

    @patch.object(CameraPermissionsCheck, "_read_tcc_entries")
    def test_tcc_read_skip_returns_skip(self, mock_read):
        """Test SKIP when TCC database cannot be read."""
        mock_read.return_value = (Status.SKIP, [], "Unable to open TCC database")
        
        check = CameraPermissionsCheck()
        result = check.run()
        
        assert result.status == Status.SKIP
        assert "unable to open" in result.message.lower()

    @patch.object(CameraPermissionsCheck, "_read_tcc_entries")
    def test_max_reported_apps_limit(self, mock_read):
        """Test that reported apps are limited to max_reported_apps."""
        apps = [f"com.example.app{i}" for i in range(20)]
        mock_read.return_value = (Status.PASS, apps, "OK")
        
        check = CameraPermissionsCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        reported = result.details.get("applications", [])
        assert len(reported) <= check.max_reported_apps

    def test_tcc_service_value(self):
        """Test correct TCC service identifier."""
        check = CameraPermissionsCheck()
        assert check.tcc_service == "kTCCServiceCamera"


class TestScreenRecordingPermissionsCheck:
    """Test cases for ScreenRecordingPermissionsCheck."""

    @patch.object(ScreenRecordingPermissionsCheck, "_read_tcc_entries")
    def test_no_third_party_returns_pass(self, mock_read):
        """Test PASS when no third-party screen recording access."""
        mock_read.return_value = (Status.PASS, [], "OK")
        
        check = ScreenRecordingPermissionsCheck()
        result = check.run()
        
        assert result.status == Status.PASS

    @patch.object(ScreenRecordingPermissionsCheck, "_read_tcc_entries")
    def test_third_party_access_returns_warning(self, mock_read):
        """Test WARNING when third-party apps have screen recording access."""
        mock_read.return_value = (
            Status.PASS,
            ["com.loom.desktop", "org.obs-project.obs-studio"],
            "OK"
        )
        
        check = ScreenRecordingPermissionsCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert result.severity == Severity.HIGH

    def test_tcc_service_value(self):
        """Test correct TCC service identifier."""
        check = ScreenRecordingPermissionsCheck()
        assert check.tcc_service == "kTCCServiceScreenCapture"


class TestMicrophonePermissionsCheck:
    """Test cases for MicrophonePermissionsCheck."""

    @patch.object(MicrophonePermissionsCheck, "_read_tcc_entries")
    def test_no_third_party_returns_pass(self, mock_read):
        """Test PASS when no third-party microphone access."""
        mock_read.return_value = (Status.PASS, ["com.apple.Safari"], "OK")
        
        check = MicrophonePermissionsCheck()
        result = check.run()
        
        assert result.status == Status.PASS

    @patch.object(MicrophonePermissionsCheck, "_read_tcc_entries")
    def test_third_party_access_returns_warning(self, mock_read):
        """Test WARNING when third-party apps have microphone access."""
        mock_read.return_value = (
            Status.PASS,
            ["us.zoom.xos", "com.spotify.client"],
            "OK"
        )
        
        check = MicrophonePermissionsCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert "microphone" in result.message.lower()

    def test_tcc_service_value(self):
        """Test correct TCC service identifier."""
        check = MicrophonePermissionsCheck()
        assert check.tcc_service == "kTCCServiceMicrophone"


class TestAccessibilityPermissionsCheck:
    """Test cases for AccessibilityPermissionsCheck."""

    @patch.object(AccessibilityPermissionsCheck, "_read_tcc_entries")
    def test_no_third_party_returns_pass(self, mock_read):
        """Test PASS when no third-party accessibility access."""
        mock_read.return_value = (Status.PASS, [], "OK")
        
        check = AccessibilityPermissionsCheck()
        result = check.run()
        
        assert result.status == Status.PASS

    @patch.object(AccessibilityPermissionsCheck, "_read_tcc_entries")
    def test_third_party_access_returns_warning(self, mock_read):
        """Test WARNING when third-party apps have accessibility access."""
        mock_read.return_value = (
            Status.PASS,
            ["com.1password.1password", "com.raycast.macos"],
            "OK"
        )
        
        check = AccessibilityPermissionsCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert result.severity == Severity.HIGH
        assert "accessibility" in result.message.lower()

    def test_tcc_service_value(self):
        """Test correct TCC service identifier."""
        check = AccessibilityPermissionsCheck()
        assert check.tcc_service == "kTCCServiceAccessibility"


class TestFullDiskAccessPermissionsCheck:
    """Test cases for FullDiskAccessPermissionsCheck."""

    @patch.object(FullDiskAccessPermissionsCheck, "_read_tcc_entries")
    def test_no_third_party_returns_pass(self, mock_read):
        """Test PASS when no third-party Full Disk Access."""
        mock_read.return_value = (Status.PASS, [], "OK")
        
        check = FullDiskAccessPermissionsCheck()
        result = check.run()
        
        assert result.status == Status.PASS
        assert "no third-party" in result.message.lower()

    @patch.object(FullDiskAccessPermissionsCheck, "_read_tcc_entries")
    def test_third_party_access_returns_warning(self, mock_read):
        """Test WARNING when third-party apps have FDA."""
        mock_read.return_value = (
            Status.PASS,
            ["com.crowdstrike.falcon", "com.malwarebytes.mbam"],
            "OK"
        )
        
        check = FullDiskAccessPermissionsCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert result.severity == Severity.HIGH

    def test_tcc_service_value(self):
        """Test correct TCC service identifier."""
        check = FullDiskAccessPermissionsCheck()
        assert check.tcc_service == "kTCCServiceSystemPolicyAllFiles"


class TestLocationPermissionsCheck:
    """Test cases for LocationPermissionsCheck."""

    @patch.object(LocationPermissionsCheck, "_read_tcc_entries")
    def test_no_third_party_returns_pass(self, mock_read):
        """Test PASS when no third-party location access."""
        mock_read.return_value = (Status.PASS, [], "OK")
        
        check = LocationPermissionsCheck()
        result = check.run()
        
        assert result.status == Status.PASS

    @patch.object(LocationPermissionsCheck, "_read_tcc_entries")
    def test_third_party_access_returns_warning(self, mock_read):
        """Test WARNING when third-party apps have location access."""
        mock_read.return_value = (
            Status.PASS,
            ["com.weather.wunderground", "com.google.Chrome"],
            "OK"
        )
        
        check = LocationPermissionsCheck()
        result = check.run()
        
        assert result.status == Status.WARNING
        assert "location" in result.message.lower()

    def test_tcc_service_value(self):
        """Test correct TCC service identifier."""
        check = LocationPermissionsCheck()
        assert check.tcc_service == "kTCCServiceLocation"


class TestTCCDatabaseReading:
    """Test TCC database reading functionality with real SQLite."""

    @patch("checks.privacy._check_tcc_access")
    def test_read_tcc_with_allowed_entries(self, mock_access, temp_tcc_db, monkeypatch):
        """Test reading TCC database with allowed entries."""
        mock_access.return_value = (True, "OK")
        db_path = temp_tcc_db([
            ("kTCCServiceCamera", "us.zoom.xos", 2),
            ("kTCCServiceCamera", "com.apple.Safari", 2),
            ("kTCCServiceCamera", "com.denied.app", 0),
            ("kTCCServiceMicrophone", "us.zoom.xos", 2),
        ])
        
        # Mock _tcc_db_paths to return our temp db
        check = CameraPermissionsCheck()
        monkeypatch.setattr(check, "_tcc_db_paths", lambda: [db_path])
        
        status, allowed, message = check._read_tcc_entries()
        
        assert status == Status.PASS
        assert "us.zoom.xos" in allowed
        assert "com.apple.Safari" in allowed
        assert "com.denied.app" not in allowed  # auth_value != 2

    @patch("checks.privacy._check_tcc_access")
    def test_read_tcc_database_not_found(self, mock_access, tmp_path, monkeypatch):
        """Test handling when TCC database doesn't exist."""
        mock_access.return_value = (True, "OK")  # Access check passes but db not found
        nonexistent = tmp_path / "nonexistent" / "TCC.db"
        
        check = CameraPermissionsCheck()
        monkeypatch.setattr(check, "_tcc_db_paths", lambda: [nonexistent])
        
        status, allowed, message = check._read_tcc_entries()
        
        assert status == Status.SKIP
        assert "not found" in message.lower()

    @patch("checks.privacy._check_tcc_access")
    def test_read_tcc_deduplicates_entries(self, mock_access, temp_tcc_db, monkeypatch):
        """Test that duplicate entries are deduplicated."""
        mock_access.return_value = (True, "OK")
        # Create two databases with overlapping entries
        db_path = temp_tcc_db([
            ("kTCCServiceCamera", "us.zoom.xos", 2),
            ("kTCCServiceCamera", "us.zoom.xos", 2),  # Duplicate
        ])
        
        check = CameraPermissionsCheck()
        monkeypatch.setattr(check, "_tcc_db_paths", lambda: [db_path])
        
        status, allowed, message = check._read_tcc_entries()
        
        # Should only have one entry despite duplicates
        assert allowed.count("us.zoom.xos") == 1

    def test_read_tcc_via_python_success(self, temp_tcc_db):
        """Test _read_tcc_via_python with accessible database."""
        db_path = temp_tcc_db([
            ("kTCCServiceCamera", "us.zoom.xos", 2),
            ("kTCCServiceCamera", "com.denied.app", 0),
        ])
        
        check = CameraPermissionsCheck()
        ok, allowed, message = check._read_tcc_via_python(db_path)
        
        assert ok is True
        assert "us.zoom.xos" in allowed
        assert "com.denied.app" not in allowed
        assert message == "OK"

    def test_read_tcc_via_python_nonexistent_db(self, tmp_path):
        """Test _read_tcc_via_python with nonexistent database."""
        db_path = tmp_path / "nonexistent.db"
        
        check = CameraPermissionsCheck()
        ok, allowed, message = check._read_tcc_via_python(db_path)
        
        assert ok is False
        assert allowed == []
        assert "full disk access" in message.lower()

    @patch("checks.privacy.subprocess.run")
    @patch("checks.privacy.shutil.which")
    def test_read_tcc_via_subprocess_success(self, mock_which, mock_run, tmp_path):
        """Test _read_tcc_via_subprocess with successful query."""
        mock_which.return_value = "/usr/bin/sqlite3"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='["us.zoom.xos","com.skype.skype"]',
            stderr=""
        )
        
        db_path = tmp_path / "test.db"
        db_path.touch()
        
        check = CameraPermissionsCheck()
        ok, allowed, message = check._read_tcc_via_subprocess(db_path)
        
        assert ok is True
        assert "us.zoom.xos" in allowed
        assert "com.skype.skype" in allowed
        assert message == "OK"

    @patch("checks.privacy.subprocess.run")
    @patch("checks.privacy.shutil.which")
    def test_read_tcc_via_subprocess_access_denied(self, mock_which, mock_run, tmp_path):
        """Test _read_tcc_via_subprocess with access denied error."""
        mock_which.return_value = "/usr/bin/sqlite3"
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Error: unable to open database file"
        )
        
        db_path = tmp_path / "test.db"
        db_path.touch()
        
        check = CameraPermissionsCheck()
        ok, allowed, message = check._read_tcc_via_subprocess(db_path)
        
        assert ok is False
        assert allowed == []
        assert "full disk access" in message.lower()

    @patch("checks.privacy.shutil.which")
    def test_read_tcc_via_subprocess_sqlite3_not_found(self, mock_which, tmp_path):
        """Test _read_tcc_via_subprocess when sqlite3 is not available."""
        mock_which.return_value = None
        
        db_path = tmp_path / "test.db"
        db_path.touch()
        
        check = CameraPermissionsCheck()
        ok, allowed, message = check._read_tcc_via_subprocess(db_path)
        
        assert ok is False
        assert "sqlite3 command not found" in message

    @patch("checks.privacy._check_tcc_access")
    def test_access_denied_skips_with_reference(self, mock_access, monkeypatch, tmp_path):
        """Test that access denied results in skip with reference to TCC Access Check."""
        mock_access.return_value = (False, "TCC database access denied. Grant Full Disk Access...")
        
        check = CameraPermissionsCheck()
        
        status, allowed, message = check._read_tcc_entries()
        
        assert status == Status.SKIP
        # Message should reference TCCAccessCheck instead of repeating the full error
        assert "tcc" in message.lower()
        assert "access" in message.lower()


class TestPrivacyCheckMetadata:
    """Test privacy check metadata."""

    def test_camera_check_metadata(self):
        """Test CameraPermissionsCheck metadata."""
        check = CameraPermissionsCheck()
        assert check.name == "Camera Permissions"
        assert check.category == "privacy"
        assert check.severity == Severity.MEDIUM
        assert check.tcc_service == "kTCCServiceCamera"

    def test_screen_recording_check_metadata(self):
        """Test ScreenRecordingPermissionsCheck metadata."""
        check = ScreenRecordingPermissionsCheck()
        assert check.name == "Screen Recording Permissions"
        assert check.category == "privacy"
        assert check.severity == Severity.HIGH

    def test_microphone_check_metadata(self):
        """Test MicrophonePermissionsCheck metadata."""
        check = MicrophonePermissionsCheck()
        assert check.name == "Microphone Permissions"
        assert check.category == "privacy"
        assert check.severity == Severity.MEDIUM

    def test_accessibility_check_metadata(self):
        """Test AccessibilityPermissionsCheck metadata."""
        check = AccessibilityPermissionsCheck()
        assert check.name == "Accessibility Permissions"
        assert check.category == "privacy"
        assert check.severity == Severity.HIGH

    def test_fda_check_metadata(self):
        """Test FullDiskAccessPermissionsCheck metadata."""
        check = FullDiskAccessPermissionsCheck()
        assert check.name == "Full Disk Access Permissions"
        assert check.category == "privacy"
        assert check.severity == Severity.HIGH

    def test_location_check_metadata(self):
        """Test LocationPermissionsCheck metadata."""
        check = LocationPermissionsCheck()
        assert check.name == "Location Permissions"
        assert check.category == "privacy"
        assert check.severity == Severity.MEDIUM


class TestTCCAccessCheck:
    """Test cases for TCCAccessCheck."""

    @patch("checks.privacy._check_tcc_access")
    def test_accessible_returns_pass(self, mock_check):
        """Test PASS when TCC database is accessible."""
        mock_check.return_value = (True, "OK")

        check = TCCAccessCheck()
        result = check.run()

        assert result.status == Status.PASS
        assert "accessible" in result.message.lower()
        assert result.severity == Severity.INFO

    @patch("checks.privacy._check_tcc_access")
    def test_denied_returns_warning(self, mock_check):
        """Test WARNING when TCC database access is denied."""
        mock_check.return_value = (False, "TCC database access denied. Grant Full Disk Access...")

        check = TCCAccessCheck()
        result = check.run()

        assert result.status == Status.WARNING
        assert result.severity == Severity.MEDIUM
        assert "full disk access" in result.message.lower()
        assert "note" in result.details

    def test_check_metadata(self):
        """Test TCCAccessCheck metadata."""
        check = TCCAccessCheck()
        assert check.name == "TCC Database Access"
        assert check.category == "privacy"
        assert check.severity == Severity.INFO


class TestTCCAccessCaching:
    """Test TCC access state caching."""

    @patch("checks.privacy._check_tcc_access")
    def test_cache_prevents_repeated_checks(self, mock_check):
        """Test that access state is cached after first check."""
        mock_check.return_value = (True, "OK")

        # First call should trigger the check
        check1 = TCCAccessCheck()
        check1.run()

        # Second call should use cached state
        check2 = TCCAccessCheck()
        check2.run()

        # _check_tcc_access should only be called once
        assert mock_check.call_count == 1

    @patch("checks.privacy._check_tcc_access")
    def test_individual_checks_skip_when_access_denied(self, mock_check):
        """Test that individual TCC checks skip silently when access is denied."""
        mock_check.return_value = (False, "TCC database access denied...")

        # First trigger the access check
        access_check = TCCAccessCheck()
        access_result = access_check.run()
        assert access_result.status == Status.WARNING

        # Now camera check should skip silently
        camera_check = CameraPermissionsCheck()
        result = camera_check.run()

        assert result.status == Status.SKIP
        assert "tcc access check" in result.message.lower()


class TestPrivacyCheckEdgeCases:
    """Edge case tests for privacy checks."""

    @patch.object(CameraPermissionsCheck, "_read_tcc_entries")
    def test_empty_allowed_list_returns_pass(self, mock_read):
        """Test PASS when allowed list is empty."""
        mock_read.return_value = (Status.PASS, [], "OK")
        
        check = CameraPermissionsCheck()
        result = check.run()
        
        assert result.status == Status.PASS

    @patch.object(CameraPermissionsCheck, "_read_tcc_entries")
    def test_only_apple_apps_returns_pass(self, mock_read):
        """Test PASS when only Apple apps have access."""
        mock_read.return_value = (
            Status.PASS,
            ["com.apple.Safari", "com.apple.FaceTime", "com.apple.iChat"],
            "OK"
        )
        
        check = CameraPermissionsCheck()
        result = check.run()
        
        assert result.status == Status.PASS

    @patch.object(CameraPermissionsCheck, "_read_tcc_entries")
    def test_mixed_apps_reports_only_third_party(self, mock_read):
        """Test that only third-party apps are reported in details."""
        mock_read.return_value = (
            Status.PASS,
            ["com.apple.Safari", "us.zoom.xos", "com.apple.FaceTime", "com.skype.skype"],
            "OK"
        )
        
        check = CameraPermissionsCheck()
        result = check.run()
        
        apps = result.details.get("applications", [])
        assert "us.zoom.xos" in apps
        assert "com.skype.skype" in apps
        assert "com.apple.Safari" not in apps
        assert "com.apple.FaceTime" not in apps
