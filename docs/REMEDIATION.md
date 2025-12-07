# Remediation Guide

This document provides step-by-step remediation instructions for all security findings detected by macOS Security Audit. Each section corresponds to a check category and lists all possible findings with their fixes.

---

## Quick Actions

### Most Critical Fixes

| Priority | Finding | Action |
|----------|---------|--------|
| 🔴 | FileVault disabled | Enable in System Settings > Privacy & Security > FileVault |
| 🔴 | SIP disabled | Boot to Recovery, run `csrutil enable` |
| 🟠 | Firewall disabled | System Settings > Network > Firewall > Turn On |
| 🟠 | Gatekeeper disabled | Run `sudo spctl --master-enable` |
| 🟠 | Automatic login enabled | System Settings > Users & Groups > Login Options |

---

## Encryption

### FileVault Encryption

**If FAIL:** Full-disk encryption is not enabled.

**GUI Remediation:**
```
System Settings > Privacy & Security > FileVault > Turn On
```

**Notes:**
- Encryption happens in the background; no downtime required
- Store your recovery key securely (iCloud or external)
- Required for compliance with most security standards

---

### External Disk Encryption

**If FAIL:** External drives are mounted without encryption.

**GUI Remediation (new disk):**
```
Disk Utility > Select external drive > Erase > Choose "APFS (Encrypted)"
```

**GUI Remediation (existing disk):**
```
Right-click volume in Finder > Encrypt "[Volume Name]"
```

**Notes:**
- Existing data preserved when encrypting in-place
- APFS encryption is hardware-accelerated on modern Macs

---

## Firewall

### Application Firewall

**If FAIL:** Incoming connections are not filtered.

**GUI Remediation:**
```
System Settings > Network > Firewall > Turn On
```

**Terminal Remediation:**
```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
```

---

### Firewall Stealth Mode

**If FAIL:** Mac responds to network probes.

**GUI Remediation:**
```
System Settings > Network > Firewall > Options > Enable Stealth Mode
```

**Terminal Remediation:**
```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
```

---

### Remote Login (SSH)

**If FAIL:** SSH is enabled and accepting connections.

**GUI Remediation:**
```
System Settings > General > Sharing > Remote Login > Off
```

**If SSH is Required:**
- Limit to specific users in Sharing preferences
- Use key-based authentication: `PasswordAuthentication no` in `/etc/ssh/sshd_config`
- Consider fail2ban or similar rate limiting

---

### Screen Sharing

**If FAIL:** VNC screen sharing is enabled.

**GUI Remediation:**
```
System Settings > General > Sharing > Screen Sharing > Off
```

---

### Remote Management

**If FAIL:** Apple Remote Desktop is enabled.

**GUI Remediation:**
```
System Settings > General > Sharing > Remote Management > Off
```

---

### AirDrop Discoverability

**If WARNING:** AirDrop is set to "Everyone".

**GUI Remediation:**
```
Control Center > AirDrop > Contacts Only
```

**Terminal Remediation:**
```bash
defaults write com.apple.sharingd DiscoverableMode -string "Contacts Only"
```

---

## System Integrity

### System Integrity Protection (SIP)

**If FAIL:** SIP is disabled, leaving system files unprotected.

**Remediation (requires Recovery Mode):**

**Intel Mac:**
```
1. Restart and hold Command+R
2. Open Terminal from Utilities menu
3. Run: csrutil enable
4. Restart
```

**Apple Silicon:**
```
1. Shut down Mac
2. Press and hold power button until "Loading startup options"
3. Click Options > Continue
4. Open Terminal from Utilities menu
5. Run: csrutil enable
6. Restart
```

---

### Gatekeeper

**If FAIL:** Gatekeeper is disabled.

**Terminal Remediation:**
```bash
sudo spctl --master-enable
```

**GUI Verification:**
```
System Settings > Privacy & Security > Allow apps from: App Store and identified developers
```

---

### XProtect Definitions

**If WARNING:** XProtect signatures are more than 30 days old.

**Remediation:**
```bash
softwareupdate --background
```

**GUI Remediation:**
```
System Settings > General > Software Update > Check for updates
```

---

### Malware Removal Tool

**If WARNING:** XProtect Remediator hasn't been updated recently.

**Remediation:**
```
System Settings > General > Software Update > Install available updates
```

---

### Software Updates Pending

**If WARNING:** Security updates are available but not installed.

**Terminal Remediation:**
```bash
softwareupdate -ia
```

**GUI Remediation:**
```
System Settings > General > Software Update > Update Now
```

---

### Automatic Updates

**If WARNING:** Automatic updates are partially or fully disabled.

**GUI Remediation:**
```
System Settings > General > Software Update > Automatic Updates
  ✓ Check for updates
  ✓ Download new updates when available
  ✓ Install macOS updates
  ✓ Install app updates from App Store
  ✓ Install Security Responses and system files
```

---

## Authentication

### Automatic Login

**If FAIL:** A user is configured for automatic login.

**GUI Remediation:**
```
System Settings > Users & Groups > Login Options > Automatic login: Off
```

---

### Guest Account

**If FAIL:** Guest account is enabled.

**GUI Remediation:**
```
System Settings > Users & Groups > Guest User > Allow guests to log in: Off
```

---

### Screen Saver Password

**If FAIL:** Password is not required immediately after sleep/screensaver.

**GUI Remediation:**
```
System Settings > Lock Screen > Require password immediately after sleep or screen saver
```

---

### Sudo Session Timeout

**If FAIL/WARNING:** Sudo timeout is disabled or too long.

**Remediation:**
```bash
sudo visudo
```

Add or modify:
```
Defaults timestamp_timeout=5
```

**Notes:**
- Value is in minutes
- `0` means prompt every time
- `-1` (disabled) or values >15 are flagged

---

### Password Policy

**If WARNING:** Password policy doesn't enforce sufficient complexity.

**Check current policy:**
```bash
pwpolicy getaccountpolicies
```

**Set recommended policy:**
```bash
pwpolicy -setglobalpolicy "minChars=12 maxFailedLoginAttempts=10"
```

---

## Privacy

All privacy checks audit the TCC (Transparency, Consent, and Control) database for granted permissions.

### Camera / Microphone / Screen Recording / Accessibility / Full Disk Access / Location

**If WARNING:** Third-party applications have been granted sensitive permissions.

**GUI Remediation:**
```
System Settings > Privacy & Security > [Permission Type]
```

Review each listed application and:
- **Remove** apps you no longer use
- **Revoke** permissions for apps that don't need them
- **Verify** legitimate apps (e.g., Zoom for camera/mic is expected)

**Common Legitimate Uses:**
| Permission | Expected Apps |
|------------|---------------|
| Camera | Video conferencing (Zoom, Teams, FaceTime) |
| Microphone | Video/voice apps, voice assistants |
| Screen Recording | Screen recorders, remote support tools |
| Accessibility | Password managers, automation tools, accessibility software |
| Full Disk Access | Backup software, security tools, terminal emulators |
| Location | Maps, weather, Find My |

---

## Applications

### Unsigned Applications

**If WARNING:** Unsigned application bundles were found.

**Investigation:**
1. Identify the flagged applications in the output
2. Verify if they're from a trusted source
3. Check if a signed version is available

**Remediation:**
- Replace with signed versions from developer or App Store
- Remove if no longer needed
- Contact developer to request code signing

---

### Dangerous Application Entitlements

**If WARNING:** Apps have risky entitlements like `disable-library-validation` or `get-task-allow`.

**Investigation:**
```bash
codesign -d --entitlements - /Applications/AppName.app
```

**Common Legitimate Uses:**
- **Development tools** (Xcode, debuggers) - `get-task-allow`
- **Plugin hosts** (VSCode, Electron apps) - `disable-library-validation`

**Remediation:**
- Ensure apps are from trusted developers
- Consider alternatives without these entitlements
- For development tools, verify they're official releases

---

### Quarantine Enforcement

**If FAIL:** Gatekeeper quarantine is disabled for downloads.

**Terminal Remediation:**
```bash
defaults write com.apple.LaunchServices LSQuarantine -bool true
```

---

## Configuration

### Firmware Password

**If FAIL:** No firmware password is set (Intel Macs) or Startup Security is reduced (Apple Silicon).

**Intel Mac Remediation:**
```
1. Boot to Recovery Mode (Command+R)
2. Utilities > Startup Security Utility or Firmware Password Utility
3. Turn On Firmware Password
4. Set a strong password and store it securely
```

**Apple Silicon Remediation:**
```
1. Shut down Mac
2. Press and hold power button until "Loading startup options"
3. Click Options > Continue
4. Utilities > Startup Security Utility
5. Set to "Full Security"
```

---

### Secure Boot

**If FAIL:** Secure Boot is set to reduced security.

**Remediation:**
```
1. Boot to Recovery Mode
2. Utilities > Startup Security Utility
3. Select "Full Security"
```

---

### Time Machine Encryption

**If FAIL:** Time Machine backup destination is not encrypted.

**GUI Remediation (new backup):**
```
System Settings > General > Time Machine > Add Backup Disk > ✓ Encrypt Backup
```

**GUI Remediation (existing backup):**
```
System Settings > General > Time Machine > Select disk > Turn On Encryption
```

**Notes:**
- Encrypting an existing backup may take considerable time
- Store the encryption password securely

---

### Crash Reporting / Analytics Sharing

**If WARNING/INFO:** Diagnostic data is being shared.

**GUI Remediation:**
```
System Settings > Privacy & Security > Analytics & Improvements
  ☐ Share Mac Analytics
  ☐ Share with App Developers
  ☐ Share iCloud Analytics
  ☐ Improve Siri & Dictation
```

---

## Bulk Remediation Script

For environments requiring automated hardening, here's a starter script for non-interactive fixes:

```bash
#!/bin/bash
# macOS Security Hardening - Non-Interactive Fixes
# Run with: sudo ./harden.sh
# WARNING: Review each command before running in production

set -e

echo "Enabling Application Firewall..."
/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

echo "Enabling Stealth Mode..."
/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

echo "Enabling Gatekeeper..."
spctl --master-enable

echo "Enabling Quarantine..."
defaults write com.apple.LaunchServices LSQuarantine -bool true

echo "Done. Some changes require logout or restart."
```

---

## Verification

After applying remediations, re-run the audit to verify fixes:

```bash
macos-security-audit --format json > after-remediation.json
```

Compare with your baseline to confirm improvements.

---

## References

- [Apple Platform Security Guide](https://support.apple.com/guide/security/)
- [CIS Benchmarks for macOS](https://www.cisecurity.org/benchmark/apple_os)
- [macOS Security Compliance Project](https://github.com/usnistgov/macos_security)
