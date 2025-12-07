"""System integrity and update related checks."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from subprocess import TimeoutExpired
from typing import Dict, Optional

from checks.base import CheckResult, SecurityCheck, Severity, Status
from utils.commands import CommandExecutionError, run_command
from utils.parsers import load_plist, parse_defaults_bool


class SystemIntegrityProtectionCheck(SecurityCheck):
    """Validate System Integrity Protection (SIP) status."""

    name = "System Integrity Protection"
    description = "Verifies that SIP is enabled to protect system files."
    category = "system_integrity"
    severity = Severity.CRITICAL
    remediation = "Boot to Recovery and enable SIP via 'csrutil enable'."

    def run(self) -> CheckResult:
        try:
            result = run_command(["/usr/bin/csrutil", "status"], timeout=5)
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
                message="Timed out querying SIP status",
                remediation=self.remediation,
                details={},
            )

        stdout = result.stdout.lower()
        if "enabled" in stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="System Integrity Protection is enabled",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )
        if "disabled" in stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message="System Integrity Protection is disabled",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )
        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="Unable to determine SIP status",
            remediation=self.remediation,
            details={"raw_output": result.stdout},
        )


class GatekeeperCheck(SecurityCheck):
    """Ensure Gatekeeper is active."""

    name = "Gatekeeper"
    description = "Checks whether Gatekeeper is enforcing app notarization."
    category = "system_integrity"
    severity = Severity.HIGH
    remediation = "Enable Gatekeeper via 'spctl --master-enable' or System Settings > Privacy & Security."

    def run(self) -> CheckResult:
        try:
            result = run_command(["/usr/sbin/spctl", "--status"], timeout=5)
        except FileNotFoundError:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="spctl command not available",
                remediation=self.remediation,
                details={},
            )
        except TimeoutExpired:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="Timed out querying Gatekeeper",
                remediation=self.remediation,
                details={},
            )

        stdout = result.stdout.lower()
        if "assessments enabled" in stdout or "enabled" in stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="Gatekeeper is enabled",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )
        if "disabled" in stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message="Gatekeeper is disabled",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )
        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="Unable to determine Gatekeeper status",
            remediation=self.remediation,
            details={"raw_output": result.stdout},
        )


class XProtectUpdateCheck(SecurityCheck):
    """Check recent update timestamp for XProtect signatures.
    
    Apple typically updates XProtect monthly. Staleness thresholds:
    - PASS: Updated within 30 days
    - WARNING: 30-60 days old (may indicate disabled auto-updates)
    - FAIL: 60+ days old (or never updated - security risk)
    """

    name = "XProtect Definitions"
    description = "Validates that XProtect signatures have been updated recently."
    category = "system_integrity"
    severity = Severity.MEDIUM
    remediation = (
        "Enable automatic security updates: System Settings > General > Software Update > "
        "Automatic Updates > 'Install Security Responses and system files'. "
        "Then run 'softwareupdate --background' to check for updates."
    )

    signature_path = Path(
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
    )
    # Tiered thresholds based on Apple's typical monthly update cadence
    fresh_threshold_days = 30  # PASS if within this
    stale_threshold_days = 60  # WARNING if between fresh and stale, FAIL if beyond

    def run(self) -> CheckResult:
        info = load_plist(self.signature_path)
        if info is None:
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message="XProtect signatures not found - malware protection may be compromised",
                remediation=self.remediation,
                details={"path": str(self.signature_path), "reason": "plist_not_found"},
            )

        version = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
        mtime = self.signature_path.stat().st_mtime
        last_modified = dt.datetime.fromtimestamp(mtime)
        age_days = (dt.datetime.now() - last_modified).days

        base_details = {
            "version": version,
            "last_modified": last_modified.isoformat(),
            "age_days": age_days,
            "fresh_threshold": self.fresh_threshold_days,
            "stale_threshold": self.stale_threshold_days,
        }

        # PASS: Updated within 30 days
        if age_days <= self.fresh_threshold_days:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message=f"XProtect signatures are current (updated {age_days} day(s) ago)",
                remediation=self.remediation,
                details=base_details,
            )

        # WARNING: 30-60 days old - may indicate disabled auto-updates
        if age_days <= self.stale_threshold_days:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message=f"XProtect signatures are {age_days} days old - automatic updates may be disabled",
                remediation=self.remediation,
                details={
                    **base_details,
                    "note": "Apple typically updates XProtect monthly. Age > 30 days suggests automatic updates may be disabled.",
                },
            )

        # FAIL: 60+ days old - serious security risk
        return CheckResult(
            check_name=self.name,
            status=Status.FAIL,
            severity=self.severity,
            message=f"XProtect signatures critically outdated ({age_days} days old) - malware protection at risk",
            remediation=self.remediation,
            details={
                **base_details,
                "note": "XProtect has not been updated in over 60 days. This leaves your Mac vulnerable to known malware threats.",
            },
        )


class MalwareRemovalToolUpdateCheck(SecurityCheck):
    """Check XProtect Remediator (replaces legacy MRT) update timestamp.
    
    Apple typically updates the malware removal tool monthly. Staleness thresholds:
    - PASS: Updated within 30 days
    - WARNING: 30-60 days old (may indicate disabled auto-updates)
    - FAIL: 60+ days old (or never updated - security risk)
    """

    name = "Malware Removal Tool"
    description = "Ensures Apple's malware removal tool has been updated recently."
    category = "system_integrity"
    severity = Severity.MEDIUM
    remediation = (
        "Enable automatic security updates: System Settings > General > Software Update > "
        "Automatic Updates > 'Install Security Responses and system files'. "
        "Apple automatically updates malware protection in the background."
    )

    # Modern path (macOS Ventura+): XProtect Remediator replaced MRT
    xprotect_remediator_path = Path(
        "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist"
    )
    # Legacy path (pre-Ventura)
    legacy_mrt_path = Path(
        "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist"
    )
    # Tiered thresholds based on Apple's typical monthly update cadence
    fresh_threshold_days = 30  # PASS if within this
    stale_threshold_days = 60  # WARNING if between fresh and stale, FAIL if beyond

    def run(self) -> CheckResult:
        # Try XProtect Remediator first (modern macOS)
        info = load_plist(self.xprotect_remediator_path)
        tool_name = "XProtect Remediator"
        plist_path = self.xprotect_remediator_path

        # Fall back to legacy MRT if XProtect not found
        if info is None:
            info = load_plist(self.legacy_mrt_path)
            tool_name = "MRT (legacy)"
            plist_path = self.legacy_mrt_path

        if info is None:
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message="Malware removal tool not found - malware cleanup capability missing",
                remediation=self.remediation,
                details={"reason": "tool_not_found"},
            )

        version = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
        mtime = plist_path.stat().st_mtime
        last_modified = dt.datetime.fromtimestamp(mtime)
        age_days = (dt.datetime.now() - last_modified).days

        base_details = {
            "tool": tool_name,
            "version": version,
            "last_modified": last_modified.isoformat(),
            "age_days": age_days,
            "fresh_threshold": self.fresh_threshold_days,
            "stale_threshold": self.stale_threshold_days,
        }

        # PASS: Updated within 30 days
        if age_days <= self.fresh_threshold_days:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message=f"{tool_name} is current (updated {age_days} day(s) ago)",
                remediation=self.remediation,
                details=base_details,
            )

        # WARNING: 30-60 days old - may indicate disabled auto-updates
        if age_days <= self.stale_threshold_days:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message=f"{tool_name} is {age_days} days old - automatic updates may be disabled",
                remediation=self.remediation,
                details={
                    **base_details,
                    "note": "Apple typically updates MRT monthly. Age > 30 days suggests automatic updates may be disabled.",
                },
            )

        # FAIL: 60+ days old - serious security risk
        return CheckResult(
            check_name=self.name,
            status=Status.FAIL,
            severity=self.severity,
            message=f"{tool_name} critically outdated ({age_days} days old) - malware cleanup at risk",
            remediation=self.remediation,
            details={
                **base_details,
                "note": "MRT has not been updated in over 60 days. Your Mac may not be able to remove known malware.",
            },
        )


class SoftwareUpdatePendingCheck(SecurityCheck):
    """Detect pending macOS software updates."""

    name = "Software Updates Pending"
    description = "Checks whether macOS reports pending software updates."
    category = "system_integrity"
    severity = Severity.MEDIUM
    remediation = "Apply outstanding updates via System Settings > General > Software Update."

    preference_path = Path("/Library/Preferences/com.apple.SoftwareUpdate.plist")

    def run(self) -> CheckResult:
        # Check network connectivity first for live update check
        from utils.system_info import check_network_connectivity
        is_online = check_network_connectivity()
        
        # First try the fast method: check RecommendedUpdates in plist
        plist = load_plist(self.preference_path)
        if plist is not None:
            recommended = plist.get("RecommendedUpdates", [])
            if isinstance(recommended, list):
                if len(recommended) == 0:
                    return CheckResult(
                        check_name=self.name,
                        status=Status.PASS,
                        severity=self.severity,
                        message="No pending software updates",
                        remediation=self.remediation,
                        details={},
                    )
                else:
                    update_names = [u.get("Display Name", "Unknown") for u in recommended if isinstance(u, dict)]
                    return CheckResult(
                        check_name=self.name,
                        status=Status.FAIL,
                        severity=self.severity,
                        message=f"{len(recommended)} software update(s) available",
                        remediation=self.remediation,
                        details={"updates": update_names},
                    )

        # Fallback to softwareupdate command (slower, requires network)
        if not is_online:
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Cannot check for updates - no network connectivity",
                remediation="Connect to the internet to check for software updates",
                details={"offline": True},
            )
        
        try:
            result = run_command(["/usr/sbin/softwareupdate", "-l"], timeout=30)
        except FileNotFoundError:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="softwareupdate command not available",
                remediation=self.remediation,
                details={},
            )
        except TimeoutExpired:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Timed out checking for software updates",
                remediation=self.remediation,
                details={},
            )
        except CommandExecutionError as exc:
            stdout = exc.stdout.lower()
            stderr = exc.stderr.lower()
            # Check for network-related errors
            if "network" in stderr or "connection" in stderr or "internet" in stderr:
                return CheckResult(
                    check_name=self.name,
                    status=Status.SKIP,
                    severity=self.severity,
                    message="Cannot check for updates - network error",
                    remediation="Ensure internet connectivity and retry",
                    details={"error": exc.stderr},
                )
            if "software update found" in stdout or "available updates" in stdout:
                return CheckResult(
                    check_name=self.name,
                    status=Status.FAIL,
                    severity=self.severity,
                    message="Software updates are available",
                    remediation=self.remediation,
                    details={"stdout": exc.stdout},
                )
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="Error querying software updates",
                remediation=self.remediation,
                details={"stderr": exc.stderr, "stdout": exc.stdout},
            )

        stdout = result.stdout.lower()
        if "no new software available" in stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="No pending software updates",
                remediation=self.remediation,
                details={},
            )
        if "software update found" in stdout or "available updates" in stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message="Software updates are available",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )
        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="Unable to determine update status",
            remediation=self.remediation,
            details={"raw_output": result.stdout},
        )


class AutomaticUpdatesCheck(SecurityCheck):
    """Ensure automatic update settings are enabled."""

    name = "Automatic Updates"
    description = "Validates key automatic update preferences are enabled."
    category = "system_integrity"
    severity = Severity.MEDIUM
    remediation = "Enable automatic updates in System Settings > General > Software Update."

    preference_path = Path("/Library/Preferences/com.apple.SoftwareUpdate.plist")

    def run(self) -> CheckResult:
        plist = load_plist(self.preference_path)
        if plist is None:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Unable to read Software Update preferences",
                remediation=self.remediation,
                details={"path": str(self.preference_path)},
            )

        # Modern macOS uses these keys (AutomaticCheckEnabled is deprecated)
        checks = {
            "AutomaticDownload": plist.get("AutomaticDownload"),
            "CriticalUpdateInstall": plist.get("CriticalUpdateInstall"),
            "ConfigDataInstall": plist.get("ConfigDataInstall"),
        }

        # Only flag as disabled if explicitly set to False/0
        # Missing keys default to enabled on modern macOS
        disabled = [key for key, value in checks.items() if value is not None and not bool(value)]
        if disabled:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="One or more automatic update preferences are disabled",
                remediation=self.remediation,
                details={"disabled": disabled},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="Automatic update preferences are enabled",
            remediation=self.remediation,
            details={},
        )


class SecurityUpdateAutoInstallCheck(SecurityCheck):
    """Ensure automatic installation of security updates is enabled.
    
    This is a HIGH severity check that specifically validates the
    CriticalUpdateInstall setting which controls automatic installation
    of security patches and XProtect/Gatekeeper data updates.
    """

    name = "Security Update Auto-Install"
    description = "Validates that security updates are automatically installed."
    category = "system_integrity"
    severity = Severity.HIGH
    remediation = (
        "Enable automatic security updates: System Settings > General > Software Update > "
        "Automatic Updates > Install Security Responses and system files."
    )

    preference_path = Path("/Library/Preferences/com.apple.SoftwareUpdate.plist")

    def run(self) -> CheckResult:
        plist = load_plist(self.preference_path)
        if plist is None:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Unable to read Software Update preferences",
                remediation=self.remediation,
                details={"path": str(self.preference_path)},
            )

        # Check the critical security update settings
        critical_update_install = plist.get("CriticalUpdateInstall")
        config_data_install = plist.get("ConfigDataInstall")
        
        # Build status report
        settings = {
            "CriticalUpdateInstall": critical_update_install,
            "ConfigDataInstall": config_data_install,
        }
        
        # CriticalUpdateInstall is the main security update toggle
        # ConfigDataInstall controls XProtect, Gatekeeper, and MRT updates
        
        disabled_settings: list[str] = []
        
        # Check CriticalUpdateInstall (security patches)
        if critical_update_install is not None and not bool(critical_update_install):
            disabled_settings.append("Security updates (CriticalUpdateInstall)")
        
        # Check ConfigDataInstall (XProtect, Gatekeeper data)
        if config_data_install is not None and not bool(config_data_install):
            disabled_settings.append("System data files (ConfigDataInstall)")
        
        if disabled_settings:
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message=f"Security auto-updates disabled: {', '.join(disabled_settings)}",
                remediation=self.remediation,
                details={
                    "disabled": disabled_settings,
                    "settings": settings,
                },
            )
        
        # If keys are not present, they default to enabled on modern macOS
        if critical_update_install is None and config_data_install is None:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="Security update auto-install enabled (using macOS defaults)",
                remediation=self.remediation,
                details={"settings": settings, "note": "Using default values"},
            )
        
        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="Security update auto-install is enabled",
            remediation=self.remediation,
            details={"settings": settings},
        )
