"""Authentication and access control checks."""
from __future__ import annotations

import re
from pathlib import Path
from subprocess import TimeoutExpired

from checks.base import CheckResult, SecurityCheck, Severity, Status
from utils.commands import run_command
from utils.parsers import parse_defaults_bool


class AutoLoginDisabledCheck(SecurityCheck):
    """Ensure automatic login is disabled."""

    name = "Automatic Login"
    description = "Checks whether automatic login is configured for any user."
    category = "authentication"
    severity = Severity.HIGH
    remediation = "Disable auto-login: System Settings > Users & Groups > Login Options."

    def run(self) -> CheckResult:
        try:
            result = run_command(
                [
                    "/usr/bin/defaults",
                    "read",
                    "/Library/Preferences/com.apple.loginwindow",
                    "autoLoginUser",
                ],
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
                message="Timed out querying automatic login",
                remediation=self.remediation,
                details={},
            )

        if result.returncode != 0 or not result.stdout.strip():
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="Automatic login not configured",
                remediation=self.remediation,
                details={},
            )

        username = result.stdout.strip()
        return CheckResult(
            check_name=self.name,
            status=Status.FAIL,
            severity=self.severity,
            message=f"Automatic login enabled for user '{username}'",
            remediation=self.remediation,
            details={"username": username},
        )


class GuestAccountDisabledCheck(SecurityCheck):
    """Ensure guest account login is disabled."""

    name = "Guest Account"
    description = "Verifies that the guest account is not enabled."
    category = "authentication"
    severity = Severity.MEDIUM
    remediation = "Disable guest user: System Settings > Users & Groups > Guest User."

    def run(self) -> CheckResult:
        try:
            result = run_command(
                [
                    "/usr/bin/defaults",
                    "read",
                    "/Library/Preferences/com.apple.loginwindow",
                    "GuestEnabled",
                ],
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
                message="Timed out querying guest account",
                remediation=self.remediation,
                details={},
            )

        if result.returncode != 0:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="Guest account not configured",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )

        enabled = parse_defaults_bool(result.stdout)
        if enabled:
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message="Guest account login is enabled",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="Guest account login is disabled",
            remediation=self.remediation,
            details={},
        )


class ScreenSaverPasswordCheck(SecurityCheck):
    """Ensure screen saver requires immediate password."""

    name = "Screen Saver Password"
    description = "Checks that a password is required immediately after sleep or screen saver."
    category = "authentication"
    severity = Severity.MEDIUM
    remediation = (
        "Require password immediately: System Settings > Lock Screen > Require password immediately."
    )

    def run(self) -> CheckResult:
        # Use sysadminctl on modern macOS (10.13+) as defaults domain has changed
        try:
            result = run_command(
                ["/usr/sbin/sysadminctl", "-screenLock", "status"],
                timeout=5,
            )
        except FileNotFoundError:
            return self._fallback_defaults_check()
        except TimeoutExpired:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="Timed out checking screen lock status",
                remediation=self.remediation,
                details={},
            )

        output = result.stdout.lower() + result.stderr.lower()

        if "immediate" in output:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="Password required immediately after sleep or screen saver",
                remediation=self.remediation,
                details={"raw_output": result.stdout.strip() + result.stderr.strip()},
            )

        if "off" in output or "disabled" in output:
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message="Screen lock password requirement is disabled",
                remediation=self.remediation,
                details={"raw_output": result.stdout.strip() + result.stderr.strip()},
            )

        # Check for delay (e.g., "screenLock delay is 5 seconds")
        delay_match = re.search(r"delay.*?(\d+)", output)
        if delay_match:
            delay_seconds = int(delay_match.group(1))
            if delay_seconds > 0:
                return CheckResult(
                    check_name=self.name,
                    status=Status.WARNING,
                    severity=self.severity,
                    message=f"Password required after {delay_seconds} second(s)",
                    remediation=self.remediation,
                    details={"delay_seconds": delay_seconds},
                )

        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="Unable to determine screen lock status",
            remediation=self.remediation,
            details={"raw_output": result.stdout.strip() + result.stderr.strip()},
        )

    def _fallback_defaults_check(self) -> CheckResult:
        """Fallback to defaults command for older macOS versions."""
        try:
            result = run_command(
                ["/usr/bin/defaults", "-currentHost", "read",
                 "com.apple.screensaver", "askForPassword"],
                timeout=5,
            )
        except (FileNotFoundError, TimeoutExpired):
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Unable to check screen lock settings",
                remediation=self.remediation,
                details={},
            )

        if result.returncode != 0:
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Screen lock preference not configured",
                remediation=self.remediation,
                details={},
            )

        enabled = parse_defaults_bool(result.stdout.strip())
        if enabled:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="Password required after sleep or screen saver",
                remediation=self.remediation,
                details={},
            )
        return CheckResult(
            check_name=self.name,
            status=Status.FAIL,
            severity=self.severity,
            message="Password not required after sleep or screen saver",
            remediation=self.remediation,
            details={},
        )


class SudoTimeoutCheck(SecurityCheck):
    """Verify sudo timestamp timeout is reasonable."""

    name = "Sudo Session Timeout"
    description = "Ensures sudo timestamp timeout is not disabled."
    category = "authentication"
    severity = Severity.MEDIUM
    remediation = "Set timestamp_timeout to 5 minutes in /etc/sudoers."
    requires_sudo = True

    def run(self) -> CheckResult:
        sudoers_path = Path("/etc/sudoers")
        try:
            content = sudoers_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="/etc/sudoers file not found",
                remediation=self.remediation,
                details={},
            )
        except PermissionError:
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Requires elevated privileges to read /etc/sudoers",
                remediation=self.remediation,
                details={},
            )

        match = re.search(r"timestamp_timeout\s*=\s*(-?\d+)", content)
        if not match:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="timestamp_timeout not explicitly set (defaults to 5 minutes)",
                remediation=self.remediation,
                details={},
            )

        timeout_value = int(match.group(1))
        if timeout_value <= 0:
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message="sudo timestamp timeout disabled or unlimited",
                remediation=self.remediation,
                details={"timeout": timeout_value},
            )
        if timeout_value > 15:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message=f"sudo timeout set to {timeout_value} minutes (recommend ≤ 15)",
                remediation=self.remediation,
                details={"timeout": timeout_value},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message=f"sudo timeout set to {timeout_value} minute(s)",
            remediation=self.remediation,
            details={"timeout": timeout_value},
        )


class PasswordPolicyCheck(SecurityCheck):
    """Validate local password policy requirements."""

    name = "Password Policy"
    description = "Ensures password policy enforces minimum length and complexity."
    category = "authentication"
    severity = Severity.HIGH
    remediation = (
        "Configure pwpolicy to require minimum length ≥ 12 and disallow simple passwords."
    )
    requires_sudo = True

    def run(self) -> CheckResult:
        try:
            result = run_command(["/usr/bin/pwpolicy", "getaccountpolicies"], timeout=10)
        except FileNotFoundError:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="pwpolicy command not available",
                remediation=self.remediation,
                details={},
            )
        except TimeoutExpired:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="Timed out retrieving password policies",
                remediation=self.remediation,
                details={},
            )

        policy_text = result.stdout or result.stderr
        if not policy_text:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Unable to parse password policy output",
                remediation=self.remediation,
                details={},
            )

        min_length_match = re.search(r"minLength\"?\s*[:=]\s*(\d+)", policy_text)
        max_failed_match = re.search(r"maxFailedAttempts\"?\s*[:=]\s*(\d+)", policy_text)

        findings: list[str] = []
        if min_length_match:
            min_length = int(min_length_match.group(1))
            if min_length < 12:
                findings.append(f"Minimum length is {min_length} (<12)")
        else:
            findings.append("Minimum length requirement not found")

        if max_failed_match:
            max_failed = int(max_failed_match.group(1))
            if max_failed > 10:
                findings.append(f"Maximum failed attempts is {max_failed} (>10)")

        if findings:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Password policy may be too lax",
                remediation=self.remediation,
                details={"findings": findings},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="Password policy enforces recommended controls",
            remediation=self.remediation,
            details={},
        )
