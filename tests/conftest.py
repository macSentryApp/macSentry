"""Pytest configuration and shared fixtures for security check tests."""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


@dataclass
class MockCommandResult:
    """Mock command result matching CommandResult interface."""
    stdout: str
    stderr: str
    returncode: int


@dataclass
class MacOSVersionFixture:
    """Fixture data for a specific macOS version."""
    version: str  # e.g., "13.0", "14.0", "15.0"
    version_tuple: tuple  # e.g., (13, 0, 0)
    outputs: Dict[str, MockCommandResult]


# ==============================================================================
# macOS Version-Specific Output Fixtures
# ==============================================================================

MACOS_13_OUTPUTS = {
    # FileVault
    "fdesetup_on": MockCommandResult("FileVault is On.", "", 0),
    "fdesetup_off": MockCommandResult("FileVault is Off.", "", 0),
    
    # Firewall
    "firewall_enabled": MockCommandResult("Firewall is enabled. (State = 1)", "", 0),
    "firewall_disabled": MockCommandResult("Firewall is disabled. (State = 0)", "", 0),
    "stealth_on": MockCommandResult("Stealth mode enabled", "", 0),
    "stealth_off": MockCommandResult("Stealth mode disabled", "", 0),
    
    # SIP
    "sip_enabled": MockCommandResult("System Integrity Protection status: enabled.", "", 0),
    "sip_disabled": MockCommandResult("System Integrity Protection status: disabled.", "", 0),
    
    # Gatekeeper
    "gatekeeper_enabled": MockCommandResult("assessments enabled", "", 0),
    "gatekeeper_disabled": MockCommandResult("assessments disabled", "", 0),
    
    # SSH
    "ssh_off": MockCommandResult("Remote Login: Off", "", 0),
    "ssh_on": MockCommandResult("Remote Login: On", "", 0),
    
    # Screen saver password (sysadminctl)
    "screenlock_immediate": MockCommandResult("screenLock is immediate", "", 0),
    "screenlock_delayed": MockCommandResult("screenLock delay is 5 seconds", "", 0),
    "screenlock_off": MockCommandResult("screenLock is off", "", 0),
    
    # Auto login
    "autologin_none": MockCommandResult("", "The domain/default pair of (/Library/Preferences/com.apple.loginwindow, autoLoginUser) does not exist", 1),
    "autologin_user": MockCommandResult("testuser", "", 0),
    
    # Guest account
    "guest_disabled": MockCommandResult("0", "", 0),
    "guest_enabled": MockCommandResult("1", "", 0),
    
    # Firmware password
    "firmware_enabled": MockCommandResult("Password Enabled: Yes", "", 0),
    "firmware_disabled": MockCommandResult("Password Enabled: No", "", 0),
    
    # Secure boot
    "secureboot_enabled": MockCommandResult("Authenticated Root status: enabled", "", 0),
    "secureboot_disabled": MockCommandResult("Authenticated Root status: disabled", "", 0),
    
    # AirDrop
    "airdrop_contacts": MockCommandResult("Contacts Only", "", 0),
    "airdrop_everyone": MockCommandResult("Everyone", "", 0),
    "airdrop_off": MockCommandResult("Off", "", 0),
    
    # Quarantine
    "quarantine_enabled": MockCommandResult("1", "", 0),
    "quarantine_disabled": MockCommandResult("0", "", 0),
    
    # Software update
    "softwareupdate_none": MockCommandResult("Software Update Tool\nNo new software available.", "", 0),
    "softwareupdate_available": MockCommandResult("Software Update found the following new or updated software:\n* macOS Ventura 13.1", "", 0),
    
    # Password policy
    "pwpolicy_good": MockCommandResult('minLength = 14\nmaxFailedAttempts = 5', "", 0),
    "pwpolicy_weak": MockCommandResult('minLength = 8\nmaxFailedAttempts = 15', "", 0),
    "pwpolicy_empty": MockCommandResult("", "", 0),
    
    # Time Machine
    "tmutil_nodest": MockCommandResult("No destinations configured", "", 0),
    "tmutil_encrypted": MockCommandResult("Name          : Backup\nMount Point   : /Volumes/Backup", "", 0),
    
    # Codesign
    "codesign_valid": MockCommandResult("", "", 0),
    "codesign_invalid": MockCommandResult("", "/Applications/Test.app: code signature invalid", 1),
    
    # launchctl service checks
    "service_not_found": MockCommandResult("", "Could not find service", 113),
    "service_found": MockCommandResult("com.apple.screensharing = {\n    state = running\n}", "", 0),
}

MACOS_14_OUTPUTS = {
    # FileVault - slightly different format in Sonoma
    "fdesetup_on": MockCommandResult("FileVault is On.", "", 0),
    "fdesetup_off": MockCommandResult("FileVault is Off.", "", 0),
    
    # Firewall - new output format
    "firewall_enabled": MockCommandResult("Firewall is enabled. (State = 1)", "", 0),
    "firewall_disabled": MockCommandResult("Firewall is disabled. (State = 0)", "", 0),
    "stealth_on": MockCommandResult("Stealth mode is on", "", 0),
    "stealth_off": MockCommandResult("Stealth mode is off", "", 0),
    
    # SIP
    "sip_enabled": MockCommandResult("System Integrity Protection status: enabled.", "", 0),
    "sip_disabled": MockCommandResult("System Integrity Protection status: disabled.", "", 0),
    
    # Gatekeeper
    "gatekeeper_enabled": MockCommandResult("assessments enabled", "", 0),
    "gatekeeper_disabled": MockCommandResult("assessments disabled", "", 0),
    
    # SSH - Sonoma format
    "ssh_off": MockCommandResult("Remote Login: Off", "", 0),
    "ssh_on": MockCommandResult("Remote Login: On", "", 0),
    
    # Screen saver password
    "screenlock_immediate": MockCommandResult("screenLock is immediate", "", 0),
    "screenlock_delayed": MockCommandResult("screenLock delay is 10 seconds", "", 0),
    "screenlock_off": MockCommandResult("screenLock is disabled", "", 0),
    
    # Auto login
    "autologin_none": MockCommandResult("", "The domain/default pair does not exist", 1),
    "autologin_user": MockCommandResult("admin", "", 0),
    
    # Guest account
    "guest_disabled": MockCommandResult("false", "", 0),
    "guest_enabled": MockCommandResult("true", "", 0),
    
    # Firmware password (Apple Silicon)
    "firmware_enabled": MockCommandResult("Password Enabled: Yes", "", 0),
    "firmware_disabled": MockCommandResult("Password Enabled: No", "", 0),
    
    # Secure boot
    "secureboot_enabled": MockCommandResult("Authenticated Root status: enabled", "", 0),
    "secureboot_disabled": MockCommandResult("Authenticated Root status: disabled", "", 0),
    
    # AirDrop
    "airdrop_contacts": MockCommandResult("Contacts", "", 0),
    "airdrop_everyone": MockCommandResult("Everyone", "", 0),
    "airdrop_off": MockCommandResult("Disabled", "", 0),
    
    # Quarantine
    "quarantine_enabled": MockCommandResult("true", "", 0),
    "quarantine_disabled": MockCommandResult("false", "", 0),
    
    # Software update
    "softwareupdate_none": MockCommandResult("Software Update Tool\nNo new software available.", "", 0),
    "softwareupdate_available": MockCommandResult("Software Update found the following new or updated software:\n* macOS Sonoma 14.2", "", 0),
    
    # Password policy
    "pwpolicy_good": MockCommandResult('minLength": 14\nmaxFailedAttempts": 5', "", 0),
    "pwpolicy_weak": MockCommandResult('minLength": 6\nmaxFailedAttempts": 20', "", 0),
    "pwpolicy_empty": MockCommandResult("Getting account policies for user\n", "", 0),
    
    # Time Machine
    "tmutil_nodest": MockCommandResult("", "", 0),
    "tmutil_encrypted": MockCommandResult("====================================================\nName          : Time Machine Backup\nMount Point   : /Volumes/TMBackup\n", "", 0),
    
    # Codesign
    "codesign_valid": MockCommandResult("", "", 0),
    "codesign_invalid": MockCommandResult("", "/Applications/Unsafe.app: a sealed resource is missing or invalid", 1),
    
    # launchctl
    "service_not_found": MockCommandResult("", "Could not find service \"com.apple.screensharing\" in domain", 113),
    "service_found": MockCommandResult("com.apple.screensharing = {\n    active count = 1\n    state = running\n}", "", 0),
}

MACOS_15_OUTPUTS = {
    # FileVault - Sequoia
    "fdesetup_on": MockCommandResult("FileVault is On.", "", 0),
    "fdesetup_off": MockCommandResult("FileVault is Off.", "", 0),
    
    # Firewall
    "firewall_enabled": MockCommandResult("Firewall is enabled. (State = 1)", "", 0),
    "firewall_disabled": MockCommandResult("Firewall is disabled. (State = 0)", "", 0),
    "stealth_on": MockCommandResult("Stealth mode is on", "", 0),
    "stealth_off": MockCommandResult("Stealth mode is off", "", 0),
    
    # SIP
    "sip_enabled": MockCommandResult("System Integrity Protection status: enabled.", "", 0),
    "sip_disabled": MockCommandResult("System Integrity Protection status: disabled.", "", 0),
    "sip_custom": MockCommandResult("System Integrity Protection status: unknown (Custom Configuration).", "", 0),
    
    # Gatekeeper
    "gatekeeper_enabled": MockCommandResult("assessments enabled", "", 0),
    "gatekeeper_disabled": MockCommandResult("assessments disabled", "", 0),
    
    # SSH
    "ssh_off": MockCommandResult("Remote Login: Off", "", 0),
    "ssh_on": MockCommandResult("Remote Login: On", "", 0),
    
    # Screen saver password
    "screenlock_immediate": MockCommandResult("screenLock is immediate", "", 0),
    "screenlock_delayed": MockCommandResult("screenLock delay is 300 seconds", "", 0),
    "screenlock_off": MockCommandResult("screenLock is disabled", "", 0),
    
    # Auto login
    "autologin_none": MockCommandResult("", "does not exist", 1),
    "autologin_user": MockCommandResult("sequoiauser", "", 0),
    
    # Guest account
    "guest_disabled": MockCommandResult("no", "", 0),
    "guest_enabled": MockCommandResult("yes", "", 0),
    
    # Firmware password (Apple Silicon specific)
    "firmware_enabled": MockCommandResult("Password Enabled: Yes", "", 0),
    "firmware_disabled": MockCommandResult("Password Enabled: No", "", 0),
    
    # Secure boot
    "secureboot_enabled": MockCommandResult("Authenticated Root status: enabled", "", 0),
    "secureboot_disabled": MockCommandResult("Authenticated Root status: disabled", "", 0),
    
    # AirDrop
    "airdrop_contacts": MockCommandResult("Contacts Only", "", 0),
    "airdrop_everyone": MockCommandResult("Everyone", "", 0),
    "airdrop_off": MockCommandResult("Off", "", 0),
    
    # Quarantine
    "quarantine_enabled": MockCommandResult("yes", "", 0),
    "quarantine_disabled": MockCommandResult("no", "", 0),
    
    # Software update
    "softwareupdate_none": MockCommandResult("Software Update Tool\nNo new software available.", "", 0),
    "softwareupdate_available": MockCommandResult("Software Update found the following new or updated software:\n* macOS Sequoia 15.1", "", 0),
    
    # Password policy
    "pwpolicy_good": MockCommandResult('minLength = 16\nmaxFailedAttempts = 3', "", 0),
    "pwpolicy_weak": MockCommandResult('minLength = 4', "", 0),
    "pwpolicy_empty": MockCommandResult("", "", 0),
    
    # Time Machine
    "tmutil_nodest": MockCommandResult("No destinations configured", "", 0),
    "tmutil_encrypted": MockCommandResult("Name          : MacBook Backup\nMount Point   : /Volumes/Backup-Drive", "", 0),
    
    # Codesign
    "codesign_valid": MockCommandResult("", "", 0),
    "codesign_invalid": MockCommandResult("", "/Applications/Malware.app: invalid signature (code or signature have been modified)", 1),
    
    # launchctl
    "service_not_found": MockCommandResult("", "Could not find service", 113),
    "service_found": MockCommandResult("com.apple.screensharing = {\n    state = running\n}", "", 0),
}

MACOS_26_OUTPUTS = {
    # FileVault - Tahoe
    "fdesetup_on": MockCommandResult("FileVault is On.", "", 0),
    "fdesetup_off": MockCommandResult("FileVault is Off.", "", 0),
    
    # Firewall
    "firewall_enabled": MockCommandResult("Firewall is enabled. (State = 1)", "", 0),
    "firewall_disabled": MockCommandResult("Firewall is disabled. (State = 0)", "", 0),
    "stealth_on": MockCommandResult("Stealth mode is on", "", 0),
    "stealth_off": MockCommandResult("Stealth mode is off", "", 0),
    
    # SIP
    "sip_enabled": MockCommandResult("System Integrity Protection status: enabled.", "", 0),
    "sip_disabled": MockCommandResult("System Integrity Protection status: disabled.", "", 0),
    "sip_custom": MockCommandResult("System Integrity Protection status: unknown (Custom Configuration).", "", 0),
    
    # Gatekeeper
    "gatekeeper_enabled": MockCommandResult("assessments enabled", "", 0),
    "gatekeeper_disabled": MockCommandResult("assessments disabled", "", 0),
    
    # SSH
    "ssh_off": MockCommandResult("Remote Login: Off", "", 0),
    "ssh_on": MockCommandResult("Remote Login: On", "", 0),
    
    # Screen saver password
    "screenlock_immediate": MockCommandResult("screenLock is immediate", "", 0),
    "screenlock_delayed": MockCommandResult("screenLock delay is 300 seconds", "", 0),
    "screenlock_off": MockCommandResult("screenLock is disabled", "", 0),
    
    # Auto login
    "autologin_none": MockCommandResult("", "does not exist", 1),
    "autologin_user": MockCommandResult("tahoeuser", "", 0),
    
    # Guest account
    "guest_disabled": MockCommandResult("no", "", 0),
    "guest_enabled": MockCommandResult("yes", "", 0),
    
    # Firmware password (Apple Silicon specific)
    "firmware_enabled": MockCommandResult("Password Enabled: Yes", "", 0),
    "firmware_disabled": MockCommandResult("Password Enabled: No", "", 0),
    
    # Secure boot
    "secureboot_enabled": MockCommandResult("Authenticated Root status: enabled", "", 0),
    "secureboot_disabled": MockCommandResult("Authenticated Root status: disabled", "", 0),
    
    # AirDrop
    "airdrop_contacts": MockCommandResult("Contacts Only", "", 0),
    "airdrop_everyone": MockCommandResult("Everyone", "", 0),
    "airdrop_off": MockCommandResult("Off", "", 0),
    
    # Quarantine
    "quarantine_enabled": MockCommandResult("yes", "", 0),
    "quarantine_disabled": MockCommandResult("no", "", 0),
    
    # Software update
    "softwareupdate_none": MockCommandResult("Software Update Tool\nNo new software available.", "", 0),
    "softwareupdate_available": MockCommandResult("Software Update found the following new or updated software:\n* macOS Tahoe 26.1", "", 0),
    
    # Password policy
    "pwpolicy_good": MockCommandResult('minLength = 16\nmaxFailedAttempts = 3', "", 0),
    "pwpolicy_weak": MockCommandResult('minLength = 4', "", 0),
    "pwpolicy_empty": MockCommandResult("", "", 0),
    
    # Time Machine
    "tmutil_nodest": MockCommandResult("No destinations configured", "", 0),
    "tmutil_encrypted": MockCommandResult("Name          : MacBook Backup\nMount Point   : /Volumes/Backup-Drive", "", 0),
    
    # Codesign
    "codesign_valid": MockCommandResult("", "", 0),
    "codesign_invalid": MockCommandResult("", "/Applications/Malware.app: invalid signature (code or signature have been modified)", 1),
    
    # launchctl
    "service_not_found": MockCommandResult("", "Could not find service", 113),
    "service_found": MockCommandResult("com.apple.screensharing = {\n    state = running\n}", "", 0),
}


# ==============================================================================
# Fixtures
# ==============================================================================

@pytest.fixture
def macos_13_fixture() -> MacOSVersionFixture:
    """Fixture for macOS Ventura (13.x) outputs."""
    return MacOSVersionFixture(
        version="13.0",
        version_tuple=(13, 0, 0),
        outputs=MACOS_13_OUTPUTS,
    )


@pytest.fixture
def macos_14_fixture() -> MacOSVersionFixture:
    """Fixture for macOS Sonoma (14.x) outputs."""
    return MacOSVersionFixture(
        version="14.0",
        version_tuple=(14, 0, 0),
        outputs=MACOS_14_OUTPUTS,
    )


@pytest.fixture
def macos_15_fixture() -> MacOSVersionFixture:
    """Fixture for macOS Sequoia (15.x) outputs."""
    return MacOSVersionFixture(
        version="15.0",
        version_tuple=(15, 0, 0),
        outputs=MACOS_15_OUTPUTS,
    )


@pytest.fixture
def macos_26_fixture() -> MacOSVersionFixture:
    """Fixture for macOS Tahoe (26.x) outputs."""
    return MacOSVersionFixture(
        version="26.0",
        version_tuple=(26, 0, 0),
        outputs=MACOS_26_OUTPUTS,
    )


@pytest.fixture(params=["13.0", "14.0", "15.0", "26.0"])
def all_macos_versions(request) -> MacOSVersionFixture:
    """Parameterized fixture for all macOS versions."""
    version_map = {
        "13.0": MacOSVersionFixture("13.0", (13, 0, 0), MACOS_13_OUTPUTS),
        "14.0": MacOSVersionFixture("14.0", (14, 0, 0), MACOS_14_OUTPUTS),
        "15.0": MacOSVersionFixture("15.0", (15, 0, 0), MACOS_15_OUTPUTS),
        "26.0": MacOSVersionFixture("26.0", (26, 0, 0), MACOS_26_OUTPUTS),
    }
    return version_map[request.param]


@pytest.fixture
def mock_command_result():
    """Factory fixture for creating MockCommandResult instances."""
    def _create(stdout: str = "", stderr: str = "", returncode: int = 0):
        return MockCommandResult(stdout=stdout, stderr=stderr, returncode=returncode)
    return _create


@pytest.fixture
def temp_plist_file(tmp_path):
    """Factory fixture for creating temporary plist files."""
    import plistlib
    
    def _create(data: Dict[str, Any], filename: str = "test.plist") -> Path:
        plist_path = tmp_path / filename
        with plist_path.open("wb") as f:
            plistlib.dump(data, f)
        return plist_path
    return _create


@pytest.fixture
def temp_tcc_db(tmp_path):
    """Factory fixture for creating temporary TCC database."""
    import sqlite3
    
    def _create(entries: List[tuple]) -> Path:
        """Create TCC.db with given entries.
        
        Args:
            entries: List of (service, client, auth_value) tuples
        """
        db_path = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE access (
                service TEXT NOT NULL,
                client TEXT NOT NULL,
                auth_value INTEGER NOT NULL
            )
        """)
        for service, client, auth_value in entries:
            cursor.execute(
                "INSERT INTO access (service, client, auth_value) VALUES (?, ?, ?)",
                (service, client, auth_value)
            )
        conn.commit()
        conn.close()
        return db_path
    return _create


@pytest.fixture
def clear_check_registry():
    """Clear the check registry before and after each test."""
    from checks.base import CheckRegistry
    CheckRegistry.clear()
    yield
    CheckRegistry.clear()
