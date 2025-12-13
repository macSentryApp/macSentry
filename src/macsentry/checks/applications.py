"""Application security related checks."""
from __future__ import annotations

import shlex
from pathlib import Path
from typing import Iterable, List

from .base import CheckResult, SecurityCheck, Severity, Status
from ..utils.commands import run_command, CommandTimeoutError

_APPLICATIONS_DIRS: tuple[Path, ...] = (Path("/Applications"), Path.home() / "Applications")
_MAX_APPS_TO_SCAN = 25
_MAX_APP_SIZE_GB = 2  # Skip apps larger than this (e.g., Xcode ~10GB takes forever to verify)


def _get_app_size_bytes(app_path: Path) -> int:
    """Get approximate size of app bundle (sum of file sizes)."""
    try:
        total = 0
        for f in app_path.rglob("*"):
            if f.is_file():
                total += f.stat().st_size
                # Early exit if already over threshold
                if total > _MAX_APP_SIZE_GB * 1024 * 1024 * 1024:
                    return total
        return total
    except (OSError, PermissionError):
        return 0


def _iter_app_bundles() -> Iterable[Path]:
    counted = 0
    seen: set[Path] = set()
    max_size = _MAX_APP_SIZE_GB * 1024 * 1024 * 1024
    for base_dir in _APPLICATIONS_DIRS:
        if not base_dir.exists():
            continue
        for entry in sorted(base_dir.iterdir()):
            if counted >= _MAX_APPS_TO_SCAN:
                return
            if not entry.name.endswith(".app"):
                continue
            real_path = entry.resolve()
            if real_path in seen:
                continue
            # Skip very large apps (e.g., Xcode) - codesign --deep takes too long
            if _get_app_size_bytes(real_path) > max_size:
                continue
            seen.add(real_path)
            counted += 1
            yield real_path


class UnsignedApplicationsCheck(SecurityCheck):
    """Detect unsigned application bundles in common locations."""

    name = "Unsigned Applications"
    description = "Scans application bundles to identify unsigned apps."
    category = "applications"
    severity = Severity.MEDIUM
    remediation = "Remove or re-install unsigned applications from trusted sources."

    def run(self) -> CheckResult:
        unsigned: List[str] = []
        errors: dict[str, str] = {}

        # Check if codesign exists
        from shutil import which
        if not which("codesign"):
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="codesign tool not present",
                remediation=self.remediation,
                details={},
            )

        for app_path in _iter_app_bundles():
            cmd = ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app_path)]
            try:
                result = run_command(cmd, timeout=15)
            except CommandTimeoutError:
                errors[str(app_path)] = "codesign verification timed out"
                continue
            except FileNotFoundError:
                return CheckResult(
                    check_name=self.name,
                    status=Status.SKIP,
                    severity=self.severity,
                    message="codesign tool not present",
                    remediation=self.remediation,
                    details={},
                )

            # Only flag as unsigned if truly not signed at all.
            # codesign can fail for other reasons (strict validation, nested code issues)
            # which don't mean the app is unsigned.
            if result.returncode != 0:
                stderr_lower = result.stderr.lower()
                if "not signed" in stderr_lower or "code signature not found" in stderr_lower:
                    unsigned.append(str(app_path))

        if errors and not unsigned:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Unable to assess some applications",
                remediation=self.remediation,
                details=errors,
            )

        if unsigned:
            # Build actionable message with app names
            app_names = [Path(p).name for p in unsigned]
            
            # Show first 3 apps in message, rest in details
            preview_count = min(3, len(app_names))
            preview = ", ".join(app_names[:preview_count])
            
            if len(app_names) > preview_count:
                message = f"{len(unsigned)} unsigned apps detected: {preview}, +{len(app_names) - preview_count} more"
            else:
                message = f"{len(unsigned)} unsigned app(s) detected: {preview}"
            
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message=message,
                remediation=self.remediation,
                details={
                    "applications": unsigned,
                    "app_names": app_names,
                    "count": len(unsigned),
                },
            )

        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="Scanned applications are signed",
            remediation=self.remediation,
            details={},
        )


class DangerousEntitlementsCheck(SecurityCheck):
    """Detect applications with high-risk entitlements.
    
    Checks for:
    - com.apple.security.cs.disable-library-validation: Allows loading unsigned/untrusted dylibs.
      This weakens code signing and allows attackers to inject malicious code.
    - com.apple.security.get-task-allow: Allows debugging by other processes.
      CRITICAL if found in production apps - should only exist in development builds.
    
    Supports local whitelist override via ~/.config/macsentry/whitelist.json
    """

    name = "Dangerous Application Entitlements"
    description = "Scans application entitlements for disable-library-validation or get-task-allow."
    category = "applications"
    severity = Severity.HIGH
    remediation = (
        "Review applications with dangerous entitlements. For get-task-allow, ensure you're "
        "not running development builds in production. For disable-library-validation, "
        "consider if the app truly needs this or if it's a security risk."
    )

    # Dangerous entitlements with detailed explanations
    risky_entitlements = {
        "com.apple.security.cs.disable-library-validation": {
            "short_name": "disable-library-validation",
            "risk_level": "high",
            "explanation": (
                "Allows the app to load arbitrary dynamic libraries (dylibs) without code signing validation. "
                "This weakens macOS code signing protections and could allow attackers to inject malicious "
                "code into the app's process via dylib hijacking or injection attacks."
            ),
        },
        "com.apple.security.get-task-allow": {
            "short_name": "get-task-allow",
            "risk_level": "critical",
            "explanation": (
                "Allows other processes to attach a debugger and inspect/modify the app's memory. "
                "This is a HUGE security risk if found in production apps - it should ONLY exist in "
                "development builds. Attackers can use this to extract secrets, bypass protections, "
                "or inject malicious code. Production apps from the App Store never have this entitlement."
            ),
        },
    }

    # Apps that legitimately may need certain entitlements (with reasons)
    # Note: Even these should be reviewed - the entitlement may still be risky
    # Users can extend this via ~/.config/macsentry/whitelist.json
    expected_entitlements: dict[str, dict[str, str]] = {
        # VPN apps often need disable-library-validation for network extensions
        "Mullvad VPN.app": {
            "disable-library-validation": "VPN apps may need this for network extension plugins",
        },
        "Tailscale.app": {
            "disable-library-validation": "VPN apps may need this for network extension plugins",
        },
        "WireGuard.app": {
            "disable-library-validation": "VPN apps may need this for network extension plugins",
        },
        # Development tools legitimately have get-task-allow
        "Xcode.app": {
            "get-task-allow": "Development tool - debugging support expected",
        },
        # Some legitimate apps with plugins
        "Visual Studio Code.app": {
            "disable-library-validation": "Electron app with plugin support",
        },
        "Slack.app": {
            "disable-library-validation": "Electron app with plugin support",
        },
        "Discord.app": {
            "disable-library-validation": "Electron app with plugin support",
        },
        # Audio/Video production software
        "REAPER.app": {
            "get-task-allow": "DAW - may use debugging for plugin development features",
            "disable-library-validation": "DAW - loads third-party VST/AU plugins",
        },
        "Ableton Live 11 Suite.app": {
            "disable-library-validation": "DAW - loads third-party plugins",
        },
        "Logic Pro.app": {
            "disable-library-validation": "DAW - loads third-party plugins",
        },
        # Virtualization
        "Parallels Desktop.app": {
            "disable-library-validation": "Virtualization software with kernel extensions",
        },
        "VMware Fusion.app": {
            "disable-library-validation": "Virtualization software with kernel extensions",
        },
        # Development tools
        "Cursor.app": {
            "disable-library-validation": "Electron-based IDE with plugin support",
        },
        "Zed.app": {
            "disable-library-validation": "IDE with plugin support",
        },
    }
    
    @classmethod
    def _load_local_whitelist(cls) -> dict[str, dict[str, str]]:
        """Load local whitelist from ~/.config/macsentry/whitelist.json."""
        import json
        whitelist_path = Path.home() / ".config" / "macsentry" / "whitelist.json"
        
        if not whitelist_path.exists():
            return {}
        
        try:
            with whitelist_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("entitlement_whitelist", {})
        except (json.JSONDecodeError, OSError, KeyError):
            return {}
    
    def _get_merged_whitelist(self) -> dict[str, dict[str, str]]:
        """Get merged whitelist (built-in + local overrides)."""
        merged = dict(self.expected_entitlements)
        local = self._load_local_whitelist()
        
        # Merge local whitelist (local entries override built-in)
        for app_name, entitlements in local.items():
            if app_name in merged:
                merged[app_name].update(entitlements)
            else:
                merged[app_name] = entitlements
        
        return merged

    def run(self) -> CheckResult:
        # Maps app path -> dict with entitlements and whether expected
        risky_apps: dict[str, dict] = {}
        errors: dict[str, str] = {}
        
        # Load merged whitelist (built-in + local)
        whitelist = self._get_merged_whitelist()

        for app_path in _iter_app_bundles():
            cmd = [
                "/usr/bin/codesign",
                "-d",
                "--entitlements",
                "-",
                str(app_path),
            ]
            try:
                result = run_command(cmd, timeout=15)
            except CommandTimeoutError:
                errors[str(app_path)] = "Entitlement extraction timed out"
                continue
            except FileNotFoundError:
                return CheckResult(
                    check_name=self.name,
                    status=Status.SKIP,
                    severity=self.severity,
                    message="codesign tool not present",
                    remediation=self.remediation,
                    details={},
                )

            output = (result.stdout + "\n" + result.stderr).lower()
            app_name = Path(app_path).name
            found_info: dict[str, dict] = {}
            
            for ent_key, ent_info in self.risky_entitlements.items():
                if ent_key.lower() in output:
                    short_name = ent_info["short_name"]
                    # Check if this is an expected entitlement for this app (using merged whitelist)
                    expected_apps = whitelist.get(app_name, {})
                    expected_reason = expected_apps.get(short_name)
                    
                    found_info[short_name] = {
                        "risk_level": ent_info["risk_level"],
                        "explanation": ent_info["explanation"],
                        "expected": expected_reason is not None,
                        "expected_reason": expected_reason,
                    }
            
            if found_info:
                risky_apps[str(app_path)] = {
                    "app_name": app_name,
                    "entitlements": found_info,
                }

        if errors and not risky_apps:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Unable to inspect entitlements for some applications",
                remediation=self.remediation,
                details={"errors": errors},
            )

        if risky_apps:
            # Separate critical (get-task-allow in unexpected apps) from high risk
            critical_apps: List[str] = []
            high_risk_apps: List[str] = []
            unexpected_count = 0
            
            for app_path, info in risky_apps.items():
                app_name = info["app_name"]
                ents = info["entitlements"]
                
                # Check for get-task-allow (critical) in non-dev apps
                if "get-task-allow" in ents:
                    ent_data = ents["get-task-allow"]
                    if not ent_data["expected"]:
                        critical_apps.append(app_name)
                        unexpected_count += 1
                
                # Track disable-library-validation
                if "disable-library-validation" in ents:
                    ent_data = ents["disable-library-validation"]
                    if not ent_data["expected"]:
                        high_risk_apps.append(app_name)
                        unexpected_count += 1
            
            # Build message based on severity
            if critical_apps:
                preview = ", ".join(critical_apps[:2])
                extra = f", +{len(critical_apps) - 2} more" if len(critical_apps) > 2 else ""
                message = f"CRITICAL: {len(critical_apps)} app(s) with get-task-allow (debuggable): {preview}{extra}"
            else:
                # Build summary for high-risk apps
                app_summaries: List[str] = []
                for app_path, info in risky_apps.items():
                    app_name = info["app_name"]
                    ents = list(info["entitlements"].keys())
                    expected_marker = "" if any(
                        not info["entitlements"][e]["expected"] for e in ents
                    ) else " (expected)"
                    app_summaries.append(f"{app_name} ({', '.join(ents)}){expected_marker}")
                
                preview_count = min(3, len(app_summaries))
                preview = ", ".join(app_summaries[:preview_count])
                extra = f", +{len(app_summaries) - preview_count} more" if len(app_summaries) > preview_count else ""
                message = f"{len(risky_apps)} app(s) with dangerous entitlements: {preview}{extra}"
            
            # Build detailed output with explanations
            detailed_findings: dict[str, dict] = {}
            for app_path, info in risky_apps.items():
                app_name = info["app_name"]
                app_findings: dict[str, str] = {}
                for ent_name, ent_data in info["entitlements"].items():
                    status = "expected" if ent_data["expected"] else "UNEXPECTED"
                    reason = ent_data.get("expected_reason", "")
                    app_findings[ent_name] = f"{status}" + (f" - {reason}" if reason else "")
                detailed_findings[app_name] = app_findings
            
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message=message,
                remediation=self.remediation,
                details={
                    "applications": list(risky_apps.keys()),
                    "app_entitlements": detailed_findings,
                    "total_count": len(risky_apps),
                    "unexpected_count": unexpected_count,
                    "critical_apps": critical_apps,
                    "entitlement_explanations": {
                        ent_info["short_name"]: ent_info["explanation"]
                        for ent_info in self.risky_entitlements.values()
                    },
                },
            )

        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="No dangerous entitlements detected in scanned apps",
            remediation=self.remediation,
            details={"apps_scanned": _MAX_APPS_TO_SCAN},
        )


class QuarantineEnforcementCheck(SecurityCheck):
    """Ensure Gatekeeper quarantine enforcement remains enabled."""

    name = "Quarantine Enforcement"
    description = "Verifies Launch Services quarantine is enabled for downloaded files."
    category = "applications"
    severity = Severity.MEDIUM
    remediation = "Enable quarantine by setting LSQuarantine to true via defaults."

    def run(self) -> CheckResult:
        from macsentry.utils.commands import run_defaults_for_user
        
        try:
            # Use run_defaults_for_user to properly read user preferences when running as root
            result = run_defaults_for_user(
                "com.apple.LaunchServices",
                "LSQuarantine",
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
        except CommandTimeoutError:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="Timed out reading LSQuarantine setting",
                remediation=self.remediation,
                details={},
            )

        # If the key doesn't exist (returncode != 0), quarantine is enabled by default
        if result.returncode != 0:
            # Check if it's a "key does not exist" error - this means default (enabled)
            if "does not exist" in result.stderr.lower():
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=self.severity,
                    message="Quarantine enforcement is enabled (default)",
                    remediation=self.remediation,
                    details={"note": "LSQuarantine key not set, using macOS default (enabled)"},
                )
            # Other error
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message="Unable to determine quarantine enforcement state",
                remediation=self.remediation,
                details={"error": result.stderr},
            )

        value = result.stdout.strip().lower()
        if value in {"1", "true", "yes"}:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="Quarantine enforcement is enabled",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )
        if value in {"0", "false", "no"}:
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message="Quarantine enforcement is disabled",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.WARNING,
            severity=self.severity,
            message="Unable to determine quarantine enforcement state",
            remediation=self.remediation,
            details={"raw_output": result.stdout},
        )


class SafariSecuritySettingsCheck(SecurityCheck):
    """Check Safari browser security settings (if Safari is installed/used).
    
    Validates important Safari security preferences including:
    - Fraudulent website warnings
    - JavaScript enabled status
    - Pop-up blocking
    - Cross-site tracking prevention
    - AutoFill settings for passwords and credit cards
    """

    name = "Safari Security Settings"
    description = "Checks Safari browser security configuration for recommended settings."
    category = "applications"
    severity = Severity.MEDIUM
    remediation = (
        "Configure Safari security in Safari > Settings > Security and Privacy tabs. "
        "Enable fraudulent website warnings, block pop-ups, and prevent cross-site tracking."
    )

    def run(self) -> CheckResult:
        from macsentry.utils.commands import run_defaults_for_user
        
        # Check if Safari exists
        safari_app = Path("/Applications/Safari.app")
        if not safari_app.exists():
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Safari is not installed",
                remediation=self.remediation,
                details={},
            )
        
        findings: List[str] = []
        settings_checked: dict[str, str] = {}
        
        # Define security settings to check
        # Format: (domain, key, expected_for_secure, description)
        security_settings = [
            ("com.apple.Safari", "WarnAboutFraudulentWebsites", True, "Fraudulent website warnings"),
            ("com.apple.Safari", "BlockStoragePolicy", 2, "Block all cookies"),  # 2 = block all 3rd party
            ("com.apple.Safari", "SendDoNotTrackHTTPHeader", True, "Send Do Not Track header"),
            ("com.apple.Safari", "AutoFillPasswords", False, "AutoFill passwords disabled"),
            ("com.apple.Safari", "AutoFillCreditCardData", False, "AutoFill credit cards disabled"),
            ("com.apple.Safari", "WebKitJavaScriptEnabled", True, "JavaScript enabled"),  # usually needed
        ]
        
        for domain, key, secure_value, description in security_settings:
            try:
                result = run_defaults_for_user(domain, key, timeout=5)
                
                if result.returncode != 0:
                    # Key doesn't exist - skip this setting
                    settings_checked[key] = "not configured"
                    continue
                
                raw_value = result.stdout.strip()
                
                # Parse the value
                if isinstance(secure_value, bool):
                    # Boolean comparison
                    current_value = raw_value.lower() in {"1", "true", "yes"}
                    is_secure = (current_value == secure_value)
                elif isinstance(secure_value, int):
                    # Integer comparison (for BlockStoragePolicy)
                    try:
                        current_value = int(raw_value)
                        is_secure = (current_value >= secure_value)
                    except ValueError:
                        is_secure = False
                        current_value = raw_value
                else:
                    current_value = raw_value
                    is_secure = (current_value == secure_value)
                
                settings_checked[key] = str(current_value)
                
                if not is_secure:
                    if key == "WarnAboutFraudulentWebsites" and not current_value:
                        findings.append("Fraudulent website warnings disabled")
                    elif key == "AutoFillPasswords" and current_value:
                        findings.append("Password AutoFill is enabled (security risk)")
                    elif key == "AutoFillCreditCardData" and current_value:
                        findings.append("Credit card AutoFill is enabled")
                    elif key == "SendDoNotTrackHTTPHeader" and not current_value:
                        findings.append("Do Not Track header not sent")
                        
            except (FileNotFoundError, TimeoutExpired):
                continue
        
        if not settings_checked:
            return CheckResult(
                check_name=self.name,
                status=Status.SKIP,
                severity=self.severity,
                message="Unable to read Safari preferences (Safari may not have been used)",
                remediation=self.remediation,
                details={},
            )
        
        # Focus on critical findings
        critical_findings = [f for f in findings if "Fraudulent" in f or "Password AutoFill" in f]
        
        if critical_findings:
            return CheckResult(
                check_name=self.name,
                status=Status.FAIL,
                severity=self.severity,
                message=f"Safari security issues: {'; '.join(critical_findings[:2])}",
                remediation=self.remediation,
                details={"findings": findings, "settings": settings_checked},
            )
        
        if findings:
            return CheckResult(
                check_name=self.name,
                status=Status.WARNING,
                severity=self.severity,
                message=f"Safari security recommendations: {'; '.join(findings[:2])}",
                remediation=self.remediation,
                details={"findings": findings, "settings": settings_checked},
            )
        
        return CheckResult(
            check_name=self.name,
            status=Status.PASS,
            severity=self.severity,
            message="Safari security settings are properly configured",
            remediation=self.remediation,
            details={"settings": settings_checked},
        )
