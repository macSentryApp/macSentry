"""Encryption and storage related security checks."""
from __future__ import annotations

import logging
import plistlib
from subprocess import TimeoutExpired
from pathlib import Path
from typing import Any, Dict, List

from checks.base import CheckResult, SecurityCheck, Severity, Status
from utils import commands, parsers
from utils.commands import CommandTimeoutError, run_command_graceful

logger = logging.getLogger(__name__)


class FileVaultStatusCheck(SecurityCheck):
    """Verify that FileVault full-disk encryption is enabled."""

    name = "FileVault Encryption"
    description = "Checks whether FileVault full-disk encryption is enabled."
    category = "encryption"
    severity = Severity.CRITICAL
    remediation = (
        "Enable FileVault: System Settings > Privacy & Security > FileVault > Turn On."
    )

    def run(self) -> CheckResult:
        try:
            result = commands.run_command(["/usr/bin/fdesetup", "status"], timeout=10)
        except FileNotFoundError:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="fdesetup command not available on this system",
                remediation=self.remediation,
                details={},
            )
        except TimeoutExpired:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="Timed out while checking FileVault status",
                remediation=self.remediation,
                details={},
            )

        stdout = result.stdout.lower()
        if "filevault is on" in stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="FileVault full-disk encryption is enabled",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )
        if "filevault is off" in stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message="FileVault full-disk encryption is disabled",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )
        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="Unable to determine FileVault status",
            remediation=self.remediation,
            details={"raw_output": result.stdout},
        )


class ExternalDiskEncryptionCheck(SecurityCheck):
    """Verify external disks are encrypted or not mounted read/write."""

    name = "External Disk Encryption"
    description = "Audits external volumes for encryption status."
    category = "encryption"
    severity = Severity.HIGH
    remediation = (
        "Encrypt external drives via Disk Utility or use APFS encrypted volumes."
    )

    def run(self) -> CheckResult:
        # Use diskutil apfs list to get accurate encryption status for APFS volumes
        try:
            result = commands.run_command(
                ["/usr/sbin/diskutil", "apfs", "list", "-plist"],
                timeout=30,  # Increased for slower Macs/SSDs
                raise_on_timeout=True,
            )
        except FileNotFoundError:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="diskutil command not available",
                remediation=self.remediation,
                details={},
            )
        except CommandTimeoutError as exc:
            # Graceful degradation: SKIP instead of ERROR for timeout
            logger.warning("diskutil timeout in ExternalDiskEncryptionCheck: %s", exc)
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Could not enumerate APFS containers (disk operation timed out)",
                remediation="Try disconnecting external/network drives and retry",
                details={
                    "timeout": exc.timeout,
                    "suggestion": exc.suggestion,
                },
            )
        except TimeoutExpired:
            # Fallback for subprocess.TimeoutExpired if raised directly
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Could not enumerate APFS containers (disk operation timed out)",
                remediation="Try disconnecting external/network drives and retry",
                details={},
            )

        if not result.stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="No APFS containers found",
                remediation=self.remediation,
                details={},
            )

        try:
            plist_data = plistlib.loads(result.stdout.encode("utf-8"))
        except (plistlib.InvalidFileException, UnicodeDecodeError) as exc:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message=f"Failed to parse diskutil output: {exc}",
                remediation=self.remediation,
                details={},
            )

        containers = plist_data.get("Containers", [])
        external_unencrypted: List[str] = []
        external_encrypted: List[str] = []

        for container in containers:
            # Check if this container has an external physical store
            physical_stores = container.get("PhysicalStores", [])
            is_external = False
            for store in physical_stores:
                device_id = store.get("DeviceIdentifier", "")
                # Check if this physical store is external
                if self._is_external_disk(device_id):
                    is_external = True
                    break

            if not is_external:
                continue

            # Check volumes in this container for encryption
            volumes = container.get("Volumes", [])
            container_ref = container.get("ContainerReference", "unknown")

            for volume in volumes:
                volume_name = volume.get("Name", "Unknown")
                # FileVault key indicates encryption status
                filevault = volume.get("FileVault", False)
                encryption = volume.get("Encryption", False)

                if filevault or encryption:
                    external_encrypted.append(volume_name)
                else:
                    external_unencrypted.append(volume_name)

        if not external_encrypted and not external_unencrypted:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="No external APFS volumes detected",
                remediation=self.remediation,
                details={},
            )

        if external_unencrypted:
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message="Unencrypted external volumes detected",
                remediation=self.remediation,
                details={"unencrypted": external_unencrypted, "encrypted": external_encrypted},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="All external volumes are encrypted",
            remediation=self.remediation,
            details={"encrypted": external_encrypted},
        )

    def _is_external_disk(self, device_identifier: str) -> bool:
        """Check if a device identifier refers to an external disk."""
        if not device_identifier:
            return False
        try:
            # Use graceful command execution to avoid blocking on slow disks
            result = run_command_graceful(
                ["/usr/sbin/diskutil", "info", "-plist", f"/dev/{device_identifier}"],
                timeout=10,
            )
            if result.stdout and result.returncode != -1:
                info = plistlib.loads(result.stdout.encode("utf-8"))
                return info.get("Removable", False) or info.get("RemovableMedia", False) or \
                       info.get("External", False) or not info.get("Internal", True)
        except Exception as exc:
            logger.debug("Could not check if disk %s is external: %s", device_identifier, exc)
        return False


class SecureEmptyTrashCheck(SecurityCheck):
    """Inform about deprecated secure empty trash functionality."""

    auto_register = False
    name = "Secure Empty Trash"
    description = "Checks whether Secure Empty Trash (legacy Finder feature) is enabled."
    category = "encryption"
    severity = Severity.INFO
    remediation = "Use FileVault and secure erase tools for sensitive data disposal."

    def run(self) -> CheckResult:
        finder_plist = Path.home() / "Library/Preferences/com.apple.finder.plist"
        if not finder_plist.exists():
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Finder preferences not found; likely first-run state",
                remediation=self.remediation,
                details={},
            )

        result = commands.run_command(
            [
                "/usr/bin/defaults",
                "read",
                str(finder_plist.with_suffix("")),
                "EmptyTrashSecurely",
            ],
            timeout=5,
        )

        secure_enabled = parsers.parse_defaults_bool(result.stdout)
        if secure_enabled is None:
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Secure Empty Trash no longer supported on modern macOS",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )

        if secure_enabled:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="Secure Empty Trash is enabled (legacy configuration)",
                remediation=self.remediation,
                details={},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="Secure Empty Trash disabled; feature deprecated",
            remediation=self.remediation,
            details={},
        )
