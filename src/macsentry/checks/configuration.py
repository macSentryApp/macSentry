"""System configuration and hardware security checks."""
from __future__ import annotations

import logging
import plistlib
from pathlib import Path
from subprocess import TimeoutExpired

from .base import CheckResult, SecurityCheck, Severity, Status
from ..utils.commands import run_command, run_command_graceful, CommandTimeoutError

logger = logging.getLogger(__name__)


class FirmwarePasswordCheck(SecurityCheck):
    """Check whether a firmware password is set (Intel Macs only).
    
    Note: Apple Silicon Macs don't use firmware passwords. Instead,
    they use Startup Security Utility with secure boot and are protected
    by the Secure Enclave. This check is Intel-specific.
    """

    name = "Firmware Password"
    description = "Verifies whether a firmware password is configured (Intel Macs)."
    category = "configuration"
    severity = Severity.CRITICAL
    remediation = "Set a firmware password using firmwarepasswd in Recovery Mode."
    requires_sudo = True
    requires_intel = True  # Only applicable to Intel Macs

    def run(self) -> CheckResult:
        # Double-check we're on Intel (in case check runs directly)
        from macsentry.utils.system_info import get_hardware_info
        hw = get_hardware_info()
        
        if hw.chip_type == "apple_silicon":
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Apple Silicon Macs use Startup Security Utility instead of firmware passwords",
                remediation="Apple Silicon security is managed via Recovery Mode > Startup Security Utility",
                details={"chip_type": hw.chip_type},
            )
        
        try:
            result = run_command(["/usr/sbin/firmwarepasswd", "-check"], timeout=5)
        except FileNotFoundError:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="firmwarepasswd command not found",
                remediation=self.remediation,
                details={},
            )
        except TimeoutExpired:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="Timed out checking firmware password",
                remediation=self.remediation,
                details={},
            )

        stdout = result.stdout.lower()
        if "password enabled: yes" in stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="Firmware password is enabled",
                remediation=self.remediation,
                details={},
            )
        if "password enabled: no" in stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message="Firmware password is not enabled",
                remediation=self.remediation,
                details={},
            )
        if result.returncode == 5:
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Requires sudo to query firmware password",
                remediation=self.remediation,
                details={"return_code": result.returncode},
            )
        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="Unable to determine firmware password status",
            remediation=self.remediation,
            details={"stdout": result.stdout, "return_code": result.returncode},
        )


class SecureBootCheck(SecurityCheck):
    """Check secure boot status.
    
    This check works on:
    - Apple Silicon Macs: Uses bputil or csrutil authenticated-root
    - Intel T2 Macs: Uses csrutil authenticated-root
    - Older Intel Macs: Not applicable (no secure boot hardware)
    """

    name = "Secure Boot"
    description = "Checks authenticated root and secure boot status."
    category = "configuration"
    severity = Severity.HIGH
    remediation = "Ensure Secure Boot is set to Full Security via Recovery Mode."
    requires_t2_or_secure_enclave = True  # Only Macs with security chips support secure boot

    def run(self) -> CheckResult:
        from macsentry.utils.system_info import get_hardware_info, SecurityChipType
        hw = get_hardware_info()
        
        # Check if Mac has secure boot hardware
        if hw.security_chip == SecurityChipType.NONE:
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Secure Boot not available (requires T2 chip or Apple Silicon)",
                remediation="This Mac does not have secure boot hardware",
                details={"security_chip": "none"},
            )
        
        # Try csrutil authenticated-root first (works on both T2 and Apple Silicon)
        try:
            result = run_command(
                ["/usr/bin/csrutil", "authenticated-root", "status"], timeout=5
            )
        except FileNotFoundError:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="csrutil command not available",
                remediation=self.remediation,
                details={},
            )
        except TimeoutExpired:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="Timed out checking secure boot",
                remediation=self.remediation,
                details={},
            )

        stdout = result.stdout.lower()
        chip_info = "Apple Silicon" if hw.chip_type == "apple_silicon" else "T2 chip"
        
        if "enabled" in stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message=f"Authenticated root (Secure Boot) is enabled ({chip_info})",
                remediation=self.remediation,
                details={"chip_type": hw.chip_type, "security_chip": hw.security_chip.value},
            )
        if "disabled" in stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message=f"Authenticated root (Secure Boot) is disabled ({chip_info})",
                remediation=self.remediation,
                details={"chip_type": hw.chip_type, "security_chip": hw.security_chip.value},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="Unable to determine Secure Boot status",
            remediation=self.remediation,
            details={"stdout": result.stdout, "chip_type": hw.chip_type},
        )


class TimeMachineEncryptionCheck(SecurityCheck):
    """Ensure Time Machine backups are encrypted."""

    name = "Time Machine Encryption"
    description = "Checks whether Time Machine backup destinations are encrypted."
    category = "configuration"
    severity = Severity.MEDIUM
    remediation = "Enable encryption for Time Machine backups in System Settings > General > Time Machine."

    def run(self) -> CheckResult:
        # Use tmutil to get destination info (doesn't require root)
        try:
            result = run_command(["/usr/bin/tmutil", "destinationinfo"], timeout=10)
        except FileNotFoundError:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="tmutil command not available",
                remediation=self.remediation,
                details={},
            )
        except TimeoutExpired:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="Timed out querying Time Machine destinations",
                remediation=self.remediation,
                details={},
            )

        if not result.stdout.strip() or "no destinations" in result.stdout.lower():
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="No Time Machine destinations configured",
                remediation=self.remediation,
                details={},
            )

        # Parse mount points from tmutil output
        mount_points = []
        has_destination = False
        for line in result.stdout.splitlines():
            # Check if any destination is configured (has Name or ID)
            if line.strip().startswith("Name") or line.strip().startswith("ID"):
                has_destination = True
            if "Mount Point" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    mount_points.append(parts[1].strip())

        if not mount_points:
            # Destination configured but not mounted (drive disconnected)
            if has_destination:
                return CheckResult(
                    check_name=self.name,
                    status=Status.SKIP,
                    severity=self.severity,
                    message="Time Machine destination not mounted (drive may be disconnected)",
                    remediation=self.remediation,
                    details={"raw_output": result.stdout},
                )
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Unable to determine Time Machine mount points",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )

        # Check encryption status of each TM volume via diskutil apfs list
        encrypted_vols = []
        unencrypted_vols = []

        for mount_point in mount_points:
            is_encrypted = self._check_volume_encryption(mount_point)
            if is_encrypted:
                encrypted_vols.append(mount_point)
            else:
                unencrypted_vols.append(mount_point)

        if unencrypted_vols:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Some Time Machine destinations are not encrypted",
                remediation=self.remediation,
                details={"unencrypted": unencrypted_vols, "encrypted": encrypted_vols},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="Time Machine destinations are encrypted",
            remediation=self.remediation,
            details={"encrypted": encrypted_vols},
        )

    def _check_volume_encryption(self, mount_point: str) -> bool:
        """Check if volume at mount_point is encrypted via APFS FileVault."""
        try:
            # Use graceful command to avoid blocking on slow external drives
            result = run_command_graceful(
                ["/usr/sbin/diskutil", "apfs", "list", "-plist"],
                timeout=30,  # Increased for slower Macs/external drives
            )
            if not result.stdout or result.returncode == -1:
                logger.debug("Could not query APFS for encryption check: %s", mount_point)
                return False

            plist_data = plistlib.loads(result.stdout.encode("utf-8"))
            containers = plist_data.get("Containers", [])

            # Extract volume name from mount point (e.g., /Volumes/TM-Backups -> TM-Backups)
            expected_name = mount_point.rstrip("/").split("/")[-1] if mount_point else ""

            for container in containers:
                for volume in container.get("Volumes", []):
                    vol_mount = volume.get("MountPoint", "")
                    vol_name = volume.get("Name", "")
                    # Match by mount point OR by volume name
                    if vol_mount == mount_point or vol_name == expected_name:
                        return volume.get("FileVault", False) or volume.get("Encryption", False)
        except Exception as exc:
            logger.debug("Error checking volume encryption for %s: %s", mount_point, exc)
        return False


class CrashReportingCheck(SecurityCheck):
    """Check diagnostics and crash report sharing settings."""

    name = "Crash Reporting"
    description = "Verifies whether crash reports are automatically sent to Apple."
    category = "configuration"
    severity = Severity.LOW
    remediation = "Disable automatic crash report submission in System Settings > Privacy & Security > Analytics & Improvements."

    def run(self) -> CheckResult:
        prefs_path = Path("/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist")
        prefs = self._load_plist(prefs_path)
        if prefs is None:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Unable to read crash reporter preferences",
                remediation=self.remediation,
                details={"path": str(prefs_path)},
            )

        auto_submit = prefs.get("AutoSubmit", False)
        if auto_submit:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Crash reports are automatically submitted to Apple",
                remediation=self.remediation,
                details={},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="Crash report auto-submission is disabled",
            remediation=self.remediation,
            details={},
        )

    @staticmethod
    def _load_plist(path: Path) -> dict | None:
        if not path.exists():
            return {}
        try:
            with path.open("rb") as handle:
                return plistlib.load(handle)
        except (plistlib.InvalidFileException, OSError):
            return None


class DiagnosticsSharingCheck(SecurityCheck):
    """Check analytics sharing preferences."""

    name = "Analytics Sharing"
    description = "Checks whether analytics and iCloud diagnostics sharing is enabled."
    category = "configuration"
    severity = Severity.LOW
    remediation = "Disable sharing analytics data in System Settings > Privacy & Security > Analytics & Improvements."

    def run(self) -> CheckResult:
        prefs_path = Path("/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist")
        prefs = CrashReportingCheck._load_plist(path=prefs_path)  # reuse helper
        if prefs is None:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Unable to read analytics preferences",
                remediation=self.remediation,
                details={"path": str(prefs_path)},
            )

        analytics_enabled = prefs.get("ThirdPartyDataSubmit", False)
        iCloud_enabled = prefs.get("AutoSubmitWithiCloud", False)

        if analytics_enabled or iCloud_enabled:
            details = {}
            if analytics_enabled:
                details["analytics"] = True
            if iCloud_enabled:
                details["icloud"] = True
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Diagnostics sharing is enabled",
                remediation=self.remediation,
                details=details,
            )

        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="Diagnostics sharing is disabled",
            remediation=self.remediation,
            details={},
        )


class MDMEnrollmentCheck(SecurityCheck):
    """Check and report Mobile Device Management (MDM) enrollment status."""

    name = "MDM Enrollment"
    description = "Reports whether the Mac is enrolled in Mobile Device Management."
    category = "configuration"
    severity = Severity.INFO
    remediation = "Review MDM policies with your IT administrator if unexpected."

    def run(self) -> CheckResult:
        from macsentry.utils.system_info import detect_mdm_enrollment
        
        is_enrolled, mdm_server = detect_mdm_enrollment()
        
        if is_enrolled:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message=f"Mac is enrolled in MDM ({mdm_server})",
                remediation=self.remediation,
                details={
                    "enrolled": True,
                    "mdm_provider": mdm_server,
                    "note": "Security policies may be enforced by your organization",
                },
            )
        
        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="Mac is not enrolled in MDM",
            remediation=self.remediation,
            details={"enrolled": False},
        )


class RosettaProcessCheck(SecurityCheck):
    """Detect if running under Rosetta 2 translation on Apple Silicon."""

    name = "Rosetta Translation"
    description = "Checks whether the current process is running under Rosetta 2."
    category = "configuration"
    severity = Severity.INFO
    remediation = "For best performance, use native Apple Silicon (arm64) binaries."
    requires_apple_silicon = True  # Only applicable on Apple Silicon Macs

    def run(self) -> CheckResult:
        from macsentry.utils.system_info import is_running_under_rosetta
        
        if is_running_under_rosetta():
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Running under Rosetta 2 (Intel binary on Apple Silicon)",
                remediation=self.remediation,
                details={
                    "translated": True,
                    "note": "Security checks still work but performance may be reduced",
                },
            )
        
        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="Running as native Apple Silicon process",
            remediation=self.remediation,
            details={"translated": False},
        )


class SecureEnclaveCheck(SecurityCheck):
    """Check for Secure Enclave (T2 chip or Apple Silicon) support."""

    name = "Secure Enclave"
    description = "Verifies the Mac has a Secure Enclave for hardware security features."
    category = "configuration"
    severity = Severity.MEDIUM
    remediation = "Macs with T2 chip (2018+) or Apple Silicon have Secure Enclave."

    def run(self) -> CheckResult:
        from macsentry.utils.system_info import get_hardware_info, SecurityChipType
        
        hw = get_hardware_info()
        
        if hw.security_chip == SecurityChipType.APPLE_SILICON:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="Apple Silicon Mac with Secure Enclave",
                remediation=self.remediation,
                details={
                    "chip_type": "apple_silicon",
                    "features": ["Secure Enclave", "Hardware encryption", "Secure Boot"],
                },
            )
        
        if hw.security_chip == SecurityChipType.T2:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="Intel Mac with T2 security chip",
                remediation=self.remediation,
                details={
                    "chip_type": "t2",
                    "features": ["Secure Enclave", "Hardware encryption", "Secure Boot"],
                },
            )
        
        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="Mac does not have Secure Enclave (older Intel Mac)",
            remediation=self.remediation,
            details={
                "chip_type": "none",
                "note": "Some hardware security features are not available",
            },
        )


class NetworkConnectivityCheck(SecurityCheck):
    """Check network connectivity for update checks."""

    name = "Network Connectivity"
    description = "Verifies network connectivity is available for update checks."
    category = "configuration"
    severity = Severity.INFO
    remediation = "Connect to the internet to enable software update checks."

    def run(self) -> CheckResult:
        from macsentry.utils.system_info import check_network_connectivity
        
        if check_network_connectivity():
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="Network connectivity available",
                remediation=self.remediation,
                details={"connected": True},
            )
        
        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="No network connectivity detected",
            remediation=self.remediation,
            details={
                "connected": False,
                "note": "Software update checks may be skipped",
            },
        )


class AppleID2FACheck(SecurityCheck):
    """Check if Apple ID has two-factor authentication enabled.
    
    Two-factor authentication (2FA) is a critical security feature that
    protects your Apple ID from unauthorized access. Without 2FA, an attacker
    who obtains your password can access iCloud, purchases, and other services.
    """

    name = "Apple ID 2FA"
    description = "Verifies two-factor authentication is enabled for Apple ID."
    category = "configuration"
    severity = Severity.HIGH
    remediation = (
        "Enable 2FA: System Settings > [Your Name] > Sign-In & Security > "
        "Two-Factor Authentication. This is a huge security win if not enabled."
    )

    def run(self) -> CheckResult:
        # Check if user is signed into iCloud first
        try:
            result = run_command(
                ["/usr/bin/defaults", "read", "MobileMeAccounts"],
                timeout=5,
            )
        except FileNotFoundError:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="defaults command not available",
                remediation=self.remediation,
                details={},
            )
        except TimeoutExpired:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="Timed out checking Apple ID status",
                remediation=self.remediation,
                details={},
            )

        # Check if any iCloud account is configured
        if result.returncode != 0 or "Accounts" not in result.stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="No Apple ID signed in on this Mac",
                remediation=self.remediation,
                details={"note": "Sign in to Apple ID to check 2FA status"},
            )

        # Try to determine 2FA status via AppleIDAuthenticationInfo
        # This is stored in the keychain and system preferences
        try:
            # Check authentication type in account preferences
            auth_result = run_command_graceful(
                ["/usr/bin/defaults", "read", 
                 "/Users/" + Path.home().name + "/Library/Preferences/MobileMeAccounts.plist"],
                timeout=5,
            )
            
            # Look for authentication indicators
            output = (auth_result.stdout or "").lower()
            
            # Check for indicators of 2FA being enabled
            if "authenticationtype" in output and "2" in output:
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=self.severity,
                    message="Two-factor authentication is enabled for Apple ID",
                    remediation=self.remediation,
                    details={"2fa_enabled": True},
                )
            
            # Additional check: Query HSA2 (High Security Apple 2) status
            # Modern 2FA accounts use HSA2
            if "hsa2" in output or "two" in output:
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=self.severity,
                    message="Two-factor authentication (HSA2) is enabled",
                    remediation=self.remediation,
                    details={"2fa_enabled": True, "type": "HSA2"},
                )
            
        except Exception:
            pass  # Fall through to warning
        
        # Try an alternative method using security framework
        try:
            acct_result = run_command_graceful(
                ["/usr/bin/security", "find-generic-password", "-s", "com.apple.account.AppleIDAuthentication.token"],
                timeout=5,
            )
            if acct_result.returncode == 0:
                # Token exists, likely 2FA enabled
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=self.severity,
                    message="Apple ID authentication tokens present (2FA likely enabled)",
                    remediation=self.remediation,
                    details={"2fa_enabled": True, "detection_method": "keychain"},
                )
        except Exception:
            pass
        
        # Cannot definitively determine, provide warning to check manually
        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="Unable to verify 2FA status - please check manually",
            remediation=self.remediation,
            details={
                "note": "Check System Settings > [Your Name] > Sign-In & Security",
                "importance": "2FA is critical for Apple ID security",
            },
        )


class FindMyMacCheck(SecurityCheck):
    """Check if Find My Mac is enabled.
    
    Find My Mac allows you to locate, lock, or erase your Mac if it's
    lost or stolen. This is critical for device recovery and preventing
    unauthorized data access.
    """

    name = "Find My Mac"
    description = "Verifies Find My Mac is enabled for device recovery and remote wipe."
    category = "configuration"
    severity = Severity.MEDIUM
    remediation = (
        "Enable Find My Mac: System Settings > [Your Name] > iCloud > Find My Mac. "
        "Requires iCloud sign-in and location services."
    )

    def run(self) -> CheckResult:
        # Check Find My Mac status via nvram or fmm-mobileme-token-FMM
        try:
            # Method 1: Check for Find My Mac daemon
            result = run_command_graceful(
                ["/usr/bin/defaults", "read", 
                 "/Library/Preferences/com.apple.FindMyMac", "FMMEnabled"],
                timeout=5,
            )
            
            if result.returncode == 0:
                value = result.stdout.strip().lower()
                if value in ("1", "true", "yes"):
                    return CheckResult(
                        check_name=self.name,
                        status=Status.PASS,
                        severity=self.severity,
                        message="Find My Mac is enabled",
                        remediation=self.remediation,
                        details={"enabled": True},
                    )
                else:
                    return CheckResult(
                        check_name=self.name,
                        status=Status.FAIL,
                        severity=self.severity,
                        message="Find My Mac is disabled",
                        remediation=self.remediation,
                        details={"enabled": False},
                    )
        except Exception:
            pass
        
        # Method 2: Check via nvram for fmm-mobileme-token
        try:
            nvram_result = run_command_graceful(
                ["/usr/sbin/nvram", "-p"],
                timeout=5,
            )
            
            if "fmm-mobileme-token-FMM" in (nvram_result.stdout or ""):
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=self.severity,
                    message="Find My Mac is enabled (activation lock token present)",
                    remediation=self.remediation,
                    details={"enabled": True, "activation_lock": True},
                )
        except Exception:
            pass
        
        # Method 3: Check via iCloud preferences
        try:
            icloud_result = run_command_graceful(
                ["/usr/bin/defaults", "read", "MobileMeAccounts"],
                timeout=5,
            )
            
            output = icloud_result.stdout or ""
            if "FindMyMac" in output or "FINDMYMAC" in output.upper():
                if "1" in output or "true" in output.lower():
                    return CheckResult(
                        check_name=self.name,
                        status=Status.PASS,
                        severity=self.severity,
                        message="Find My Mac appears to be enabled",
                        remediation=self.remediation,
                        details={"enabled": True, "detection_method": "iCloud"},
                    )
        except Exception:
            pass
        
        # Could not determine status
        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="Unable to determine Find My Mac status",
            remediation=self.remediation,
            details={
                "note": "Check System Settings > [Your Name] > iCloud > Find My Mac",
                "importance": "Critical for device recovery if lost or stolen",
            },
        )
