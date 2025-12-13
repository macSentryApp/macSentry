"""Privacy and permissions related checks."""
from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from .base import CheckResult, SecurityCheck, Severity, Status

# Permission denied message with guidance
_TCC_ACCESS_DENIED_MSG = (
    "TCC database access denied. Grant Full Disk Access to your terminal app "
    "in System Settings > Privacy & Security > Full Disk Access"
)

# Module-level cache to avoid repeated access denied messages
_tcc_access_state: Optional[bool] = None  # None = not checked, True = ok, False = denied


def _reset_tcc_access_state() -> None:
    """Reset cached TCC access state. Used for testing."""
    global _tcc_access_state
    _tcc_access_state = None


def _check_tcc_access() -> Tuple[bool, str]:
    """Check if TCC database is accessible. Returns (accessible, error_msg)."""
    db_paths = [
        Path.home() / "Library/Application Support/com.apple.TCC/TCC.db",
        Path("/Library/Application Support/com.apple.TCC/TCC.db"),
    ]

    for db_path in db_paths:
        if not db_path.exists():
            continue

        # Try Python sqlite3 first
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.execute("SELECT 1 FROM access LIMIT 1")
            conn.close()
            return (True, "OK")
        except sqlite3.Error as exc:
            err_msg = str(exc).lower()
            if "unable to open database" in err_msg:
                # Try subprocess as fallback
                sqlite3_path = shutil.which("sqlite3")
                if sqlite3_path:
                    try:
                        result = subprocess.run(
                            [sqlite3_path, "-readonly", str(db_path), "SELECT 1 FROM access LIMIT 1;"],
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        if result.returncode == 0:
                            return (True, "OK")
                    except (subprocess.TimeoutExpired, OSError):
                        pass
                return (False, _TCC_ACCESS_DENIED_MSG)

    return (False, "TCC database not found")


def _get_tcc_access_state() -> Tuple[bool, str]:
    """Get cached TCC access state, checking if not yet determined."""
    global _tcc_access_state
    if _tcc_access_state is None:
        accessible, msg = _check_tcc_access()
        _tcc_access_state = accessible
        return (accessible, msg)
    return (_tcc_access_state, "" if _tcc_access_state else _TCC_ACCESS_DENIED_MSG)


class _TCCPermissionMixin:
    """Reusable helpers for TCC database checks."""

    tcc_service: str = ""
    severity: Severity = Severity.MEDIUM
    max_reported_apps: int = 10

    def _tcc_db_paths(self) -> List[Path]:
        """Return TCC database paths to try (user and system)."""
        return [
            Path.home() / "Library/Application Support/com.apple.TCC/TCC.db",
            Path("/Library/Application Support/com.apple.TCC/TCC.db"),
        ]

    def _read_tcc_via_subprocess(self, db_path: Path) -> Tuple[bool, List[str], str]:
        """Try reading TCC database using sqlite3 CLI (may have different permissions)."""
        sqlite3_path = shutil.which("sqlite3")
        if not sqlite3_path:
            return (False, [], "sqlite3 command not found")

        query = (
            f"SELECT json_group_array(client) FROM access "
            f"WHERE service='{self.tcc_service}' AND auth_value=2;"
        )

        try:
            result = subprocess.run(
                [sqlite3_path, "-readonly", str(db_path), query],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                stderr = result.stderr.strip()
                if "unable to open database" in stderr.lower():
                    return (False, [], _TCC_ACCESS_DENIED_MSG)
                return (False, [], stderr or "sqlite3 query failed")

            output = result.stdout.strip()
            if output:
                clients = json.loads(output)
                return (True, clients, "OK")
            return (True, [], "OK")
        except subprocess.TimeoutExpired:
            return (False, [], "sqlite3 query timed out")
        except (json.JSONDecodeError, ValueError) as exc:
            return (False, [], f"Failed to parse sqlite3 output: {exc}")
        except OSError as exc:
            return (False, [], f"Failed to run sqlite3: {exc}")

    def _read_tcc_via_python(self, db_path: Path) -> Tuple[bool, List[str], str]:
        """Try reading TCC database using Python sqlite3 module."""
        try:
            # Use URI to open read-only
            connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        except sqlite3.Error as exc:
            err_msg = str(exc).lower()
            if "unable to open database" in err_msg:
                return (False, [], _TCC_ACCESS_DENIED_MSG)
            return (False, [], f"Unable to open TCC database: {exc}")

        try:
            cursor = connection.cursor()
            cursor.execute(
                "SELECT client, auth_value FROM access WHERE service=?", (self.tcc_service,)
            )
            rows = cursor.fetchall()
            allowed = [
                row[0]
                for row in rows
                if len(row) >= 2 and isinstance(row[1], (int, float)) and int(row[1]) == 2
            ]
            return (True, allowed, "OK")
        except sqlite3.OperationalError as exc:
            return (False, [], f"Unable to query TCC database: {exc}")
        finally:
            connection.close()

    def _read_tcc_entries(self) -> Tuple[Status, List[str], str]:
        # Check cached access state first - if already denied, skip silently
        # The TCCAccessCheck will have already reported the access issue
        accessible, access_msg = _get_tcc_access_state()
        if not accessible:
            # Return empty skip - the TCCAccessCheck handles the user-facing message
            return (Status.SKIP, [], "Requires TCC database access (see TCC Access Check)")

        all_allowed: List[str] = []
        last_error = "TCC database not found"
        success = False

        for db_path in self._tcc_db_paths():
            if not db_path.exists():
                continue

            # Try Python sqlite3 first
            ok, allowed, err = self._read_tcc_via_python(db_path)
            if ok:
                all_allowed.extend(allowed)
                success = True
                continue

            # Try subprocess as fallback
            ok, allowed, err = self._read_tcc_via_subprocess(db_path)
            if ok:
                all_allowed.extend(allowed)
                success = True
                continue

            last_error = err

        if not success:
            return (Status.SKIP, [], last_error)

        # De-duplicate while preserving order
        seen = set()
        unique_allowed = []
        for item in all_allowed:
            if item not in seen:
                seen.add(item)
                unique_allowed.append(item)

        return (Status.PASS, unique_allowed, "OK")

    @staticmethod
    def _filter_third_party(bundle_ids: Iterable[str]) -> List[str]:
        return [bundle for bundle in bundle_ids if not bundle.startswith("com.apple.")]


class TCCAccessCheck(SecurityCheck):
    """Verify TCC database access for privacy permission audits."""

    name = "TCC Database Access"
    description = "Checks if the terminal has Full Disk Access to read TCC permissions database."
    category = "privacy"
    severity = Severity.INFO
    remediation = (
        "Grant Full Disk Access to your terminal app in "
        "System Settings > Privacy & Security > Full Disk Access"
    )

    def run(self) -> CheckResult:
        accessible, msg = _get_tcc_access_state()

        if accessible:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="TCC database is accessible - privacy permission checks enabled",
                remediation=self.remediation,
                details={},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=Severity.MEDIUM,
            message=msg,
            remediation=self.remediation,
            details={
                "note": "Privacy permission checks (Camera, Microphone, Screen Recording, etc.) "
                "will be skipped until Full Disk Access is granted."
            },
        )


class CameraPermissionsCheck(_TCCPermissionMixin, SecurityCheck):
    """Warn when third-party apps have camera access."""

    name = "Camera Permissions"
    description = "Audits camera access rights granted via TCC."
    category = "privacy"
    severity = Severity.MEDIUM
    remediation = "Review camera permissions in System Settings > Privacy & Security > Camera."
    tcc_service = "kTCCServiceCamera"

    def run(self) -> CheckResult:
        # Check if device has built-in camera
        from macsentry.utils.system_info import get_hardware_info
        hw = get_hardware_info()
        
        if not hw.has_builtin_camera:
            # Still check permissions as external cameras may be used
            status, allowed, message = self._read_tcc_entries()
            if status == Status.SKIP:
                return CheckResult(
                    check_name=self.name,
                    status=Status.SKIP,
                    severity=self.severity,
                    message=message,
                    remediation=self.remediation,
                    details={"device_type": hw.device_type.value},
                )
            
            third_party = self._filter_third_party(allowed)
            if third_party:
                return CheckResult(
                    check_name=self.name,
                    status=Status.WARNING,
                    severity=self.severity,
                    message="Third-party apps have camera access (external camera may be connected)",
                    remediation=self.remediation,
                    details={
                        "applications": third_party[: self.max_reported_apps],
                        "note": f"This {hw.device_type.value.replace('_', ' ')} has no built-in camera",
                    },
                )
            
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message=f"No camera permissions detected ({hw.device_type.value.replace('_', ' ')} has no built-in camera)",
                remediation=self.remediation,
                details={"device_type": hw.device_type.value},
            )
        
        # Device has built-in camera - standard check
        status, allowed, message = self._read_tcc_entries()
        if status == Status.SKIP:
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message=message,
                remediation=self.remediation,
                details={},
            )

        third_party = self._filter_third_party(allowed)
        if third_party:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Third-party applications have camera access",
                remediation=self.remediation,
                details={"applications": third_party[: self.max_reported_apps]},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="No third-party camera permissions detected",
            remediation=self.remediation,
            details={},
        )


class ScreenRecordingPermissionsCheck(_TCCPermissionMixin, SecurityCheck):
    """Warn when third-party apps can capture the screen."""

    name = "Screen Recording Permissions"
    description = "Audits screen recording permissions granted via TCC."
    category = "privacy"
    severity = Severity.HIGH
    remediation = "Review screen recording permissions in System Settings > Privacy & Security > Screen Recording."
    tcc_service = "kTCCServiceScreenCapture"

    def run(self) -> CheckResult:
        status, allowed, message = self._read_tcc_entries()
        if status == Status.SKIP:
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message=message,
                remediation=self.remediation,
                details={},
            )

        third_party = self._filter_third_party(allowed)
        if third_party:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Third-party applications have screen recording access",
                remediation=self.remediation,
                details={"applications": third_party[: self.max_reported_apps]},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="No third-party screen recording permissions detected",
            remediation=self.remediation,
            details={},
        )


class MicrophonePermissionsCheck(_TCCPermissionMixin, SecurityCheck):
    """Warn when third-party apps have microphone access."""

    name = "Microphone Permissions"
    description = "Audits microphone access rights granted via TCC."
    category = "privacy"
    severity = Severity.MEDIUM
    remediation = "Review microphone permissions in System Settings > Privacy & Security > Microphone."
    tcc_service = "kTCCServiceMicrophone"

    def run(self) -> CheckResult:
        # Check if device has built-in microphone
        from macsentry.utils.system_info import get_hardware_info
        hw = get_hardware_info()
        
        if not hw.has_builtin_mic:
            # Still check permissions as external microphones may be used
            status, allowed, message = self._read_tcc_entries()
            if status == Status.SKIP:
                return CheckResult(
                    check_name=self.name,
                    status=Status.SKIP,
                    severity=self.severity,
                    message=message,
                    remediation=self.remediation,
                    details={"device_type": hw.device_type.value},
                )
            
            third_party = self._filter_third_party(allowed)
            if third_party:
                return CheckResult(
                    check_name=self.name,
                    status=Status.WARNING,
                    severity=self.severity,
                    message="Third-party apps have microphone access (external mic may be connected)",
                    remediation=self.remediation,
                    details={
                        "applications": third_party[: self.max_reported_apps],
                        "note": f"This {hw.device_type.value.replace('_', ' ')} has no built-in microphone",
                    },
                )
            
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message=f"No microphone permissions detected ({hw.device_type.value.replace('_', ' ')} has no built-in mic)",
                remediation=self.remediation,
                details={"device_type": hw.device_type.value},
            )
        
        # Device has built-in microphone - standard check
        status, allowed, message = self._read_tcc_entries()
        if status == Status.SKIP:
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message=message,
                remediation=self.remediation,
                details={},
            )

        third_party = self._filter_third_party(allowed)
        if third_party:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Third-party applications have microphone access",
                remediation=self.remediation,
                details={"applications": third_party[: self.max_reported_apps]},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="No third-party microphone permissions detected",
            remediation=self.remediation,
            details={},
        )


class AccessibilityPermissionsCheck(_TCCPermissionMixin, SecurityCheck):
    """Warn when third-party apps have accessibility control."""

    name = "Accessibility Permissions"
    description = "Audits accessibility permissions granted via TCC."
    category = "privacy"
    severity = Severity.HIGH
    remediation = "Review accessibility permissions in System Settings > Privacy & Security > Accessibility."
    tcc_service = "kTCCServiceAccessibility"

    def run(self) -> CheckResult:
        status, allowed, message = self._read_tcc_entries()
        if status == Status.SKIP:
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message=message,
                remediation=self.remediation,
                details={},
            )

        third_party = self._filter_third_party(allowed)
        if third_party:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Third-party applications have Accessibility control",
                remediation=self.remediation,
                details={"applications": third_party[: self.max_reported_apps]},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="No third-party accessibility permissions detected",
            remediation=self.remediation,
            details={},
        )


class FullDiskAccessPermissionsCheck(_TCCPermissionMixin, SecurityCheck):
    """Warn when third-party apps have Full Disk Access."""

    name = "Full Disk Access Permissions"
    description = "Audits Full Disk Access permissions granted via TCC."
    category = "privacy"
    severity = Severity.HIGH
    remediation = "Review Full Disk Access permissions in System Settings > Privacy & Security > Full Disk Access."
    tcc_service = "kTCCServiceSystemPolicyAllFiles"

    def run(self) -> CheckResult:
        status, allowed, message = self._read_tcc_entries()
        if status == Status.SKIP:
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message=message,
                remediation=self.remediation,
                details={},
            )

        third_party = self._filter_third_party(allowed)
        if third_party:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Third-party applications have Full Disk Access",
                remediation=self.remediation,
                details={"applications": third_party[: self.max_reported_apps]},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="No third-party Full Disk Access permissions detected",
            remediation=self.remediation,
            details={},
        )


class LocationPermissionsCheck(_TCCPermissionMixin, SecurityCheck):
    """Warn when third-party apps have location access."""

    name = "Location Permissions"
    description = "Audits location services permissions granted via TCC."
    category = "privacy"
    severity = Severity.MEDIUM
    remediation = "Review location permissions in System Settings > Privacy & Security > Location Services."
    tcc_service = "kTCCServiceLocation"

    def run(self) -> CheckResult:
        status, allowed, message = self._read_tcc_entries()
        if status == Status.SKIP:
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message=message,
                remediation=self.remediation,
                details={},
            )

        third_party = self._filter_third_party(allowed)
        if third_party:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Third-party applications have location access",
                remediation=self.remediation,
                details={"applications": third_party[: self.max_reported_apps]},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="No third-party location permissions detected",
            remediation=self.remediation,
            details={},
        )
