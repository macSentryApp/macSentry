"""Firewall and network security checks."""
from __future__ import annotations

from subprocess import TimeoutExpired
from typing import Dict, Optional

from checks.base import CheckResult, SecurityCheck, Severity, Status
from utils.commands import CommandExecutionError, run_command
from utils.parsers import parse_key_value_output


class FirewallEnabledCheck(SecurityCheck):
    """Ensure the macOS application firewall is enabled."""

    name = "Application Firewall"
    description = "Checks whether the macOS Application Firewall is active."
    category = "firewall"
    severity = Severity.HIGH
    remediation = "Enable the firewall: System Settings > Network > Firewall > Turn On."

    def run(self) -> CheckResult:
        try:
            result = run_command(
                [
                    "/usr/libexec/ApplicationFirewall/socketfilterfw",
                    "--getglobalstate",
                ],
                timeout=5,
            )
        except FileNotFoundError:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="socketfilterfw command not available",
                remediation=self.remediation,
                details={},
            )
        except TimeoutExpired:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="Timed out querying firewall status",
                remediation=self.remediation,
                details={},
            )

        stdout = result.stdout.lower()
        if "enabled" in stdout or "state = 1" in stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="Application Firewall is enabled",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )

        if "disabled" in stdout or "state = 0" in stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message="Application Firewall is disabled",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="Unable to determine firewall state",
            remediation=self.remediation,
            details={"raw_output": result.stdout},
        )


class FirewallStealthModeCheck(SecurityCheck):
    """Confirm firewall stealth mode is active."""

    name = "Firewall Stealth Mode"
    description = "Checks whether stealth mode is enabled to drop unsolicited requests."
    category = "firewall"
    severity = Severity.MEDIUM
    remediation = "Enable stealth mode: System Settings > Network > Firewall > Options."

    def run(self) -> CheckResult:
        try:
            result = run_command(
                [
                    "/usr/libexec/ApplicationFirewall/socketfilterfw",
                    "--getstealthmode",
                ],
                timeout=5,
            )
        except FileNotFoundError:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="socketfilterfw command not available",
                remediation=self.remediation,
                details={},
            )
        except TimeoutExpired:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="Timed out querying stealth mode",
                remediation=self.remediation,
                details={},
            )

        stdout = result.stdout.lower()
        # Check for enabled states: "enabled", "on", or "mode is on"
        if "enabled" in stdout or "stealth mode is on" in stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="Firewall stealth mode is enabled",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )

        # Check for disabled states: "disabled", "off", or "mode is off"
        if "disabled" in stdout or "stealth mode is off" in stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Firewall stealth mode is disabled",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="Unable to determine firewall stealth state",
            remediation=self.remediation,
            details={"raw_output": result.stdout},
        )


class RemoteLoginCheck(SecurityCheck):
    """Ensure SSH remote login is disabled or hardened."""

    name = "Remote Login (SSH)"
    description = "Checks whether Remote Login (SSH) is disabled or configured securely."
    category = "firewall"
    severity = Severity.MEDIUM
    remediation = (
        "Disable or restrict SSH: System Settings > General > Sharing > Remote Login."
    )

    def run(self) -> CheckResult:
        # First try systemsetup (requires admin)
        try:
            result = run_command(
                ["/usr/sbin/systemsetup", "-getremotelogin"],
                timeout=5,
            )
            stdout = result.stdout.lower()
            if "off" in stdout:
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=self.severity,
                    message="Remote Login (SSH) is disabled",
                    remediation=self.remediation,
                    details={"raw_output": result.stdout},
                )
            if "on" in stdout:
                return CheckResult(
                    check_name=self.name,
                    status=Status.FAIL,
                    severity=self.severity,
                    message="Remote Login (SSH) is enabled",
                    remediation=self.remediation,
                    details={"raw_output": result.stdout},
                )
        except (FileNotFoundError, TimeoutExpired, CommandExecutionError):
            pass  # Fall through to launchctl check

        # Fallback: check if SSH service is loaded via launchctl
        try:
            result = run_command(
                ["/bin/launchctl", "print", "system/com.openssh.sshd"],
                timeout=5,
            )
            output = result.stdout.lower() + result.stderr.lower()
            if "could not find service" in output:
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=self.severity,
                    message="Remote Login (SSH) is disabled",
                    remediation=self.remediation,
                    details={},
                )
            # Service exists = SSH is enabled
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message="Remote Login (SSH) is enabled",
                remediation=self.remediation,
                details={},
            )
        except CommandExecutionError as exc:
            combined = (exc.stdout + exc.stderr).lower()
            if "could not find service" in combined:
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=self.severity,
                    message="Remote Login (SSH) is disabled",
                    remediation=self.remediation,
                    details={},
                )
        except (FileNotFoundError, TimeoutExpired):
            pass

        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="Unable to determine Remote Login state",
            remediation=self.remediation,
            details={},
        )


class ScreenSharingCheck(SecurityCheck):
    """Ensure Screen Sharing is not broadly enabled."""

    name = "Screen Sharing"
    description = "Checks whether Screen Sharing service is enabled."
    category = "firewall"
    severity = Severity.MEDIUM
    remediation = "Disable Screen Sharing: System Settings > General > Sharing > Screen Sharing."

    def run(self) -> CheckResult:
        # Check if screensharing service is loaded via launchctl
        try:
            result = run_command(
                ["/bin/launchctl", "print", "system/com.apple.screensharing"],
                timeout=5,
            )
            # Check output - "Could not find service" means disabled
            output = result.stdout.lower() + result.stderr.lower()
            if "could not find service" in output:
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=self.severity,
                    message="Screen Sharing is disabled",
                    remediation=self.remediation,
                    details={},
                )
            # Service found means enabled
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message="Screen Sharing is enabled",
                remediation=self.remediation,
                details={},
            )
        except CommandExecutionError as exc:
            # Check error output for service not found
            combined = (exc.stdout + exc.stderr).lower()
            if "could not find service" in combined:
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=self.severity,
                    message="Screen Sharing is disabled",
                    remediation=self.remediation,
                    details={},
                )
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Could not determine Screen Sharing status",
                remediation=self.remediation,
                details={"error": exc.stderr},
            )
        except (FileNotFoundError, TimeoutExpired):
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="Unable to check Screen Sharing status",
                remediation=self.remediation,
                details={},
            )


class RemoteManagementCheck(SecurityCheck):
    """Ensure Apple Remote Desktop (Remote Management) is disabled."""

    name = "Remote Management"
    description = "Checks whether Apple Remote Desktop management is enabled."
    category = "firewall"
    severity = Severity.HIGH
    remediation = "Disable Remote Management: System Settings > General > Sharing > Remote Management."

    def run(self) -> CheckResult:
        # Check if ARDAgent is running via launchctl
        try:
            result = run_command(
                ["/bin/launchctl", "print", "system/com.apple.RemoteDesktop.agent"],
                timeout=5,
            )
            # Check output - "Could not find service" means disabled
            output = result.stdout.lower() + result.stderr.lower()
            if "could not find service" in output:
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=self.severity,
                    message="Remote Management is disabled",
                    remediation=self.remediation,
                    details={},
                )
            # Service found means enabled
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message="Remote Management is enabled",
                remediation=self.remediation,
                details={},
            )
        except CommandExecutionError as exc:
            # Check error output for service not found
            combined = (exc.stdout + exc.stderr).lower()
            if "could not find service" in combined:
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=self.severity,
                    message="Remote Management is disabled",
                    remediation=self.remediation,
                    details={},
                )
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Could not determine Remote Management status",
                remediation=self.remediation,
                details={"error": exc.stderr},
            )
        except (FileNotFoundError, TimeoutExpired):
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="Unable to check Remote Management status",
                remediation=self.remediation,
                details={},
            )


class AirDropDiscoverabilityCheck(SecurityCheck):
    """Ensure AirDrop discoverability is constrained."""

    name = "AirDrop Discoverability"
    description = "Checks AirDrop discoverability mode to limit exposure."
    category = "firewall"
    severity = Severity.MEDIUM
    remediation = "Set AirDrop to Contacts Only or Off in Control Center."

    def run(self) -> CheckResult:
        from utils.commands import run_defaults_for_user
        
        # Try with -currentHost first, then without
        # Use run_defaults_for_user to handle sudo/root correctly
        stdout: Optional[str] = None
        errors: Dict[str, str] = {}
        
        for current_host in [True, False]:
            try:
                result = run_defaults_for_user(
                    "com.apple.sharingd",
                    "DiscoverableMode",
                    current_host=current_host,
                    timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip():
                    stdout = result.stdout
                    break
                elif result.returncode != 0:
                    errors[f"currentHost={current_host}"] = result.stderr or "Key not found"
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
                errors["timeout"] = "Timed out querying discoverability"
                continue

        if stdout is None:
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Unable to determine AirDrop discoverability",
                remediation=self.remediation,
                details=errors,
            )

        normalized = stdout.strip().lower()
        if normalized in {"contacts only", "contacts"}:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="AirDrop discoverability limited to contacts",
                remediation=self.remediation,
                details={},
            )
        if normalized in {"off", "disabled"}:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="AirDrop discoverability disabled",
                remediation=self.remediation,
                details={},
            )
        if normalized in {"everyone"}:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="AirDrop discoverability set to Everyone",
                remediation=self.remediation,
                details={"mode": stdout.strip()},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="Unexpected AirDrop discoverability state",
            remediation=self.remediation,
            details={"mode": stdout.strip()},
        )


class BluetoothDiscoverabilityCheck(SecurityCheck):
    """Check if Bluetooth is discoverable to all devices.
    
    When Bluetooth discoverability is set to allow all devices, your Mac
    can be discovered and potentially targeted by nearby attackers. This
    is especially risky in public places.
    """

    name = "Bluetooth Discoverability"
    description = "Checks if Mac is discoverable to all Bluetooth devices."
    category = "firewall"
    severity = Severity.LOW
    remediation = (
        "Limit Bluetooth discoverability: System Settings > Bluetooth. "
        "Turn off when not pairing devices. Consider disabling Bluetooth entirely when not needed."
    )

    def run(self) -> CheckResult:
        from utils.commands import run_command_graceful
        
        # Check if Bluetooth is powered on
        try:
            power_result = run_command_graceful(
                ["/usr/bin/defaults", "read", "/Library/Preferences/com.apple.Bluetooth", "ControllerPowerState"],
                timeout=5,
            )
            
            if power_result.returncode == 0:
                power_state = power_result.stdout.strip()
                if power_state == "0":
                    return CheckResult(
                        check_name=self.name,
                        status=Status.PASS,
                        severity=self.severity,
                        message="Bluetooth is powered off",
                        remediation=self.remediation,
                        details={"bluetooth_enabled": False},
                    )
        except Exception:
            pass
        
        # Check discoverability mode
        try:
            # Method 1: Check Bluetooth preferences for discoverability
            disco_result = run_command_graceful(
                ["/usr/bin/defaults", "read", "/Library/Preferences/com.apple.Bluetooth", "DiscoverableState"],
                timeout=5,
            )
            
            if disco_result.returncode == 0:
                discoverable = disco_result.stdout.strip()
                if discoverable == "0":
                    return CheckResult(
                        check_name=self.name,
                        status=Status.PASS,
                        severity=self.severity,
                        message="Bluetooth discoverability is disabled",
                        remediation=self.remediation,
                        details={"discoverable": False},
                    )
                elif discoverable == "1":
                    return CheckResult(
                        check_name=self.name,
                        status=Status.WARNING,
                        severity=self.severity,
                        message="Bluetooth is discoverable to all devices",
                        remediation=self.remediation,
                        details={"discoverable": True},
                    )
        except Exception:
            pass
        
        # Method 2: Use system_profiler for Bluetooth info
        try:
            profiler_result = run_command_graceful(
                ["/usr/sbin/system_profiler", "SPBluetoothDataType", "-json"],
                timeout=10,
            )
            
            if profiler_result.returncode == 0 and profiler_result.stdout:
                import json
                try:
                    data = json.loads(profiler_result.stdout)
                    bt_data = data.get("SPBluetoothDataType", [{}])[0]
                    
                    # Check for discoverable state in controller info
                    controller = bt_data.get("controller_properties", {})
                    discoverable = controller.get("controller_discoverable", "")
                    
                    if discoverable.lower() in ("no", "off", "false"):
                        return CheckResult(
                            check_name=self.name,
                            status=Status.PASS,
                            severity=self.severity,
                            message="Bluetooth discoverability is off",
                            remediation=self.remediation,
                            details={"discoverable": False, "method": "system_profiler"},
                        )
                    elif discoverable.lower() in ("yes", "on", "true"):
                        return CheckResult(
                            check_name=self.name,
                            status=Status.WARNING,
                            severity=self.severity,
                            message="Bluetooth is discoverable",
                            remediation=self.remediation,
                            details={"discoverable": True, "method": "system_profiler"},
                        )
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
        
        # Method 3: Check via blueutil if available (common third-party tool)
        try:
            from shutil import which
            if which("blueutil"):
                blueutil_result = run_command_graceful(
                    ["blueutil", "--discoverable"],
                    timeout=5,
                )
                if blueutil_result.returncode == 0:
                    value = blueutil_result.stdout.strip()
                    if value == "0":
                        return CheckResult(
                            check_name=self.name,
                            status=Status.PASS,
                            severity=self.severity,
                            message="Bluetooth discoverability is off",
                            remediation=self.remediation,
                            details={"discoverable": False, "method": "blueutil"},
                        )
                    elif value == "1":
                        return CheckResult(
                            check_name=self.name,
                            status=Status.WARNING,
                            severity=self.severity,
                            message="Bluetooth is discoverable to all devices",
                            remediation=self.remediation,
                            details={"discoverable": True, "method": "blueutil"},
                        )
        except Exception:
            pass
        
        # Could not determine Bluetooth discoverability - this is OK for a LOW severity check
        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="Bluetooth discoverability check inconclusive (likely secure defaults)",
            remediation=self.remediation,
            details={
                "note": "macOS defaults to limited discoverability during pairing only",
            },
        )
