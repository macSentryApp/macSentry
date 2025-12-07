# Security Checks Reference

This document provides detailed documentation for all security checks implemented in macOS Security Audit, including rationale, detection methodology, and remediation guidance.

---

## Quick Reference Table

| # | Check Name | Category | Severity | Sudo |
|---|------------|----------|----------|------|
| 1 | FileVault Encryption | encryption | CRITICAL | No |
| 2 | External Disk Encryption | encryption | HIGH | No |
| 3 | Application Firewall | firewall | HIGH | No |
| 4 | Firewall Stealth Mode | firewall | MEDIUM | No |
| 5 | Remote Login (SSH) | firewall | MEDIUM | No |
| 6 | Screen Sharing | firewall | MEDIUM | No |
| 7 | Remote Management | firewall | HIGH | No |
| 8 | AirDrop Discoverability | firewall | MEDIUM | No |
| 9 | Bluetooth Discoverability | firewall | LOW | No |
| 10 | System Integrity Protection | system_integrity | CRITICAL | No |
| 11 | Gatekeeper | system_integrity | HIGH | No |
| 12 | XProtect Definitions | system_integrity | MEDIUM | No |
| 13 | Malware Removal Tool | system_integrity | MEDIUM | No |
| 14 | Software Updates Pending | system_integrity | MEDIUM | No |
| 15 | Automatic Updates | system_integrity | MEDIUM | No |
| 16 | Security Update Auto-Install | system_integrity | HIGH | No |
| 17 | Automatic Login | authentication | HIGH | No |
| 18 | Guest Account | authentication | MEDIUM | No |
| 19 | Screen Saver Password | authentication | MEDIUM | No |
| 20 | Sudo Session Timeout | authentication | MEDIUM | Yes |
| 21 | Password Policy | authentication | HIGH | Yes |
| 22 | TCC Database Access | privacy | INFO | No |
| 23 | Camera Permissions | privacy | MEDIUM | No |
| 24 | Microphone Permissions | privacy | MEDIUM | No |
| 25 | Screen Recording Permissions | privacy | HIGH | No |
| 26 | Accessibility Permissions | privacy | HIGH | No |
| 27 | Full Disk Access Permissions | privacy | HIGH | No |
| 28 | Location Permissions | privacy | MEDIUM | No |
| 29 | Unsigned Applications | applications | MEDIUM | No |
| 30 | Dangerous Application Entitlements | applications | HIGH | No |
| 31 | Quarantine Enforcement | applications | MEDIUM | No |
| 32 | Safari Security Settings | applications | MEDIUM | No |
| 33 | Firmware Password | configuration | CRITICAL | Yes |
| 34 | Secure Boot | configuration | HIGH | Yes |
| 35 | Time Machine Encryption | configuration | MEDIUM | No |
| 36 | Crash Reporting | configuration | LOW | No |
| 37 | Analytics Sharing | configuration | LOW | No |
| 38 | Apple ID 2FA | configuration | HIGH | No |
| 39 | Find My Mac | configuration | MEDIUM | No |

**Summary:** 39 checks total — 3 CRITICAL, 15 HIGH, 17 MEDIUM, 3 LOW, 1 INFO | 4 require sudo

---

## Table of Contents

- [Encryption Checks](#encryption-checks)
- [Firewall Checks](#firewall-checks)
- [System Integrity Checks](#system-integrity-checks)
- [Authentication Checks](#authentication-checks)
- [Privacy Checks](#privacy-checks)
- [Application Checks](#application-checks)
- [Configuration Checks](#configuration-checks)

---

## Encryption Checks

### FileVault Encryption

| Property | Value |
|----------|-------|
| **Check Name** | `FileVault Encryption` |
| **Category** | encryption |
| **Severity** | CRITICAL |
| **Requires Sudo** | No |

**Rationale:**
FileVault provides full-disk encryption using XTS-AES-128 with a 256-bit key. Without FileVault, anyone with physical access to your Mac can boot from external media and access all data on the internal drive. This is especially critical for laptops that may be lost or stolen.

**What It Checks:**
Queries `fdesetup status` to determine if FileVault encryption is enabled on the boot volume.

**Remediation:**
```
System Settings > Privacy & Security > FileVault > Turn On
```

**Technical Details:**
- Uses `/usr/bin/fdesetup status` to query encryption state
- FileVault uses the Secure Enclave on Apple Silicon for key protection
- Encryption is performed in the background and doesn't require downtime

---

### External Disk Encryption

| Property | Value |
|----------|-------|
| **Check Name** | `External Disk Encryption` |
| **Category** | encryption |
| **Severity** | HIGH |
| **Requires Sudo** | No |

**Rationale:**
External drives often contain sensitive data and are easily lost or stolen. Unencrypted external volumes pose a significant data breach risk, especially for portable storage devices.

**What It Checks:**
Enumerates APFS containers via `diskutil apfs list -plist` and checks the `FileVault` or `Encryption` flag for volumes on external/removable media.

**Remediation:**
```
Open Disk Utility > Select external drive > Erase > Choose APFS (Encrypted)
```
Or for existing volumes:
```
Right-click volume in Finder > Encrypt "[Volume Name]"
```

**Technical Details:**
- Checks both user-level and system-level APFS containers
- Identifies external disks by querying `Removable`, `RemovableMedia`, or `External` attributes
- APFS encryption uses hardware-accelerated AES on modern Macs

---

## Firewall Checks

### Application Firewall

| Property | Value |
|----------|-------|
| **Check Name** | `Application Firewall` |
| **Category** | firewall |
| **Severity** | HIGH |
| **Requires Sudo** | No |

**Rationale:**
The macOS Application Firewall controls incoming connections on a per-application basis. Without it, any application can accept incoming network connections, potentially exposing services to attackers on the local network or internet.

**What It Checks:**
Queries `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` to determine if the firewall is enabled.

**Remediation:**
```
System Settings > Network > Firewall > Turn On
```
Or via Terminal:
```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
```

**Technical Details:**
- The Application Firewall works at Layer 7 (application layer)
- Does not affect outgoing connections
- Can be configured to allow signed apps automatically

---

### Firewall Stealth Mode

| Property | Value |
|----------|-------|
| **Check Name** | `Firewall Stealth Mode` |
| **Category** | firewall |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
Stealth mode prevents your Mac from responding to ICMP ping requests and connection attempts from closed TCP/UDP ports. This makes your Mac less discoverable to network scanners and reduces exposure to reconnaissance attacks.

**What It Checks:**
Queries `/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode` to check stealth mode status.

**Remediation:**
```
System Settings > Network > Firewall > Options > Enable Stealth Mode
```
Or via Terminal:
```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
```

---

### Remote Login (SSH)

| Property | Value |
|----------|-------|
| **Check Name** | `Remote Login (SSH)` |
| **Category** | firewall |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
SSH provides remote command-line access to your Mac. While useful for administrators, an enabled SSH server exposes your Mac to brute-force attacks and potential unauthorized access if not properly secured.

**What It Checks:**
1. Queries `systemsetup -getremotelogin` (requires admin)
2. Falls back to checking if `com.openssh.sshd` service is loaded via `launchctl`

**Remediation:**
```
System Settings > General > Sharing > Remote Login > Off
```

**Security Hardening (if SSH is required):**
- Limit access to specific users via the Sharing preference
- Use key-based authentication instead of passwords
- Consider using a non-standard port

---

### Screen Sharing

| Property | Value |
|----------|-------|
| **Check Name** | `Screen Sharing` |
| **Category** | firewall |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
Screen Sharing allows VNC connections to your Mac, providing full graphical remote access. If enabled without restrictions, attackers on your network could potentially view or control your screen.

**What It Checks:**
Checks if `com.apple.screensharing` service is loaded via `launchctl print`.

**Remediation:**
```
System Settings > General > Sharing > Screen Sharing > Off
```

---

### Remote Management

| Property | Value |
|----------|-------|
| **Check Name** | `Remote Management` |
| **Category** | firewall |
| **Severity** | HIGH |
| **Requires Sudo** | No |

**Rationale:**
Apple Remote Desktop (ARD) provides extensive remote administration capabilities including file transfer, remote execution, and system configuration. Enabled without proper controls, it represents a significant attack surface.

**What It Checks:**
Checks if `com.apple.RemoteDesktop.agent` service is loaded via `launchctl print`.

**Remediation:**
```
System Settings > General > Sharing > Remote Management > Off
```

---

### AirDrop Discoverability

| Property | Value |
|----------|-------|
| **Check Name** | `AirDrop Discoverability` |
| **Category** | firewall |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
AirDrop set to "Everyone" allows any nearby Apple device to see your Mac and attempt to send files. This can be exploited for social engineering attacks or to send malicious content.

**What It Checks:**
Reads `DiscoverableMode` from `com.apple.sharingd` preferences.

**Remediation:**
```
Control Center > AirDrop > Contacts Only (or Off)
```

**Acceptable Values:**
- **Contacts Only** - PASS (recommended)
- **Off** - PASS
- **Everyone** - WARNING

---

### Bluetooth Discoverability

| Property | Value |
|----------|-------|
| **Check Name** | `Bluetooth Discoverability` |
| **Category** | firewall |
| **Severity** | LOW |
| **Requires Sudo** | No |

**Rationale:**
When Bluetooth discoverability is set to allow all devices, your Mac can be discovered and potentially targeted by nearby attackers. This is especially risky in public places like cafes, airports, or conferences.

**What It Checks:**
1. Reads Bluetooth power state from `/Library/Preferences/com.apple.Bluetooth`
2. Checks `DiscoverableState` preference
3. Falls back to `system_profiler SPBluetoothDataType` for controller info
4. Optionally uses `blueutil` if available

**Remediation:**
```
System Settings > Bluetooth > Turn off when not pairing devices
```
Consider disabling Bluetooth entirely when not needed for better security.

**Note:** macOS defaults to limited discoverability only during active pairing, which is reasonably secure.

---

## System Integrity Checks

### System Integrity Protection (SIP)

| Property | Value |
|----------|-------|
| **Check Name** | `System Integrity Protection` |
| **Category** | system_integrity |
| **Severity** | CRITICAL |
| **Requires Sudo** | No |

**Rationale:**
SIP protects critical system files and processes from modification, even by root. Disabling SIP removes fundamental security protections and allows malware to gain persistent, privileged access to your system.

**What It Checks:**
Queries `csrutil status` to determine SIP state.

**Remediation:**
```
1. Restart Mac and hold Command+R (Intel) or Power button (Apple Silicon)
2. Open Terminal from Recovery Mode
3. Run: csrutil enable
4. Restart
```

**Technical Details:**
SIP protects:
- `/System`, `/usr`, `/bin`, `/sbin`
- System processes and kernel extensions
- NVRAM variables

---

### Gatekeeper

| Property | Value |
|----------|-------|
| **Check Name** | `Gatekeeper` |
| **Category** | system_integrity |
| **Severity** | HIGH |
| **Requires Sudo** | No |

**Rationale:**
Gatekeeper ensures only trusted software runs on your Mac by verifying code signatures and notarization. Without Gatekeeper, malicious software can execute without any warnings.

**What It Checks:**
Queries `spctl --status` to check if assessments are enabled.

**Remediation:**
```bash
sudo spctl --master-enable
```
Or via System Settings:
```
System Settings > Privacy & Security > Allow apps from: App Store and identified developers
```

---

### XProtect Definitions

| Property | Value |
|----------|-------|
| **Check Name** | `XProtect Definitions` |
| **Category** | system_integrity |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
XProtect is Apple's built-in malware detection system. Outdated definitions mean your Mac won't detect recently discovered malware variants.

**What It Checks:**
Reads the modification time of `/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist` and alerts if older than 30 days.

**Remediation:**
```bash
softwareupdate --background
```
Or ensure automatic updates are enabled in System Settings.

---

### Malware Removal Tool

| Property | Value |
|----------|-------|
| **Check Name** | `Malware Removal Tool` |
| **Category** | system_integrity |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
XProtect Remediator (formerly MRT) actively removes known malware from infected systems. Outdated versions may not remediate recently discovered threats.

**What It Checks:**
Checks the modification time of XProtect.app (modern) or MRT.app (legacy) and alerts if older than 45 days.

**Remediation:**
```
System Settings > General > Software Update > Install any available updates
```

---

### Software Updates Pending

| Property | Value |
|----------|-------|
| **Check Name** | `Software Updates Pending` |
| **Category** | system_integrity |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
Pending security updates leave known vulnerabilities unpatched. Attackers actively exploit publicly disclosed vulnerabilities.

**What It Checks:**
1. Reads `RecommendedUpdates` from `/Library/Preferences/com.apple.SoftwareUpdate.plist`
2. Falls back to `softwareupdate -l` command

**Remediation:**
```
System Settings > General > Software Update > Update Now
```

---

### Automatic Updates

| Property | Value |
|----------|-------|
| **Check Name** | `Automatic Updates` |
| **Category** | system_integrity |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
Automatic updates ensure security patches are applied promptly without requiring manual intervention. Disabled automatic updates can leave systems vulnerable for extended periods.

**What It Checks:**
Reads `AutomaticDownload`, `CriticalUpdateInstall`, and `ConfigDataInstall` from Software Update preferences.

**Remediation:**
```
System Settings > General > Software Update > Automatic Updates > On
```

---

### Security Update Auto-Install

| Property | Value |
|----------|-------|
| **Check Name** | `Security Update Auto-Install` |
| **Category** | system_integrity |
| **Severity** | HIGH |
| **Requires Sudo** | No |

**Rationale:**
Security updates patch critical vulnerabilities that are actively exploited in the wild. Apple's Rapid Security Response mechanism delivers time-sensitive security fixes between regular updates. Disabling automatic security updates leaves your Mac vulnerable to known exploits.

**What It Checks:**
Reads `CriticalUpdateInstall` and `ConfigDataInstall` from `/Library/Preferences/com.apple.SoftwareUpdate.plist`. These control automatic installation of security patches and system data files (XProtect, Gatekeeper definitions).

**Remediation:**
```
System Settings > General > Software Update > Automatic Updates > 
  Install Security Responses and system files: On
```

**Technical Details:**
- `CriticalUpdateInstall` controls security patches and Rapid Security Responses
- `ConfigDataInstall` controls XProtect, Gatekeeper, and MRT definition updates
- Both should be enabled for maximum protection

---

## Authentication Checks

### Automatic Login

| Property | Value |
|----------|-------|
| **Check Name** | `Automatic Login` |
| **Category** | authentication |
| **Severity** | HIGH |
| **Requires Sudo** | No |

**Rationale:**
Automatic login bypasses password authentication at boot, allowing anyone with physical access to immediately use the computer with full user privileges.

**What It Checks:**
Reads `autoLoginUser` from `/Library/Preferences/com.apple.loginwindow`.

**Remediation:**
```
System Settings > Users & Groups > Login Options > Automatic login: Off
```

---

### Guest Account

| Property | Value |
|----------|-------|
| **Check Name** | `Guest Account` |
| **Category** | authentication |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
The guest account provides unauthenticated access to your Mac. While data is deleted on logout, it provides a potential attack vector for local privilege escalation or network-based attacks.

**What It Checks:**
Reads `GuestEnabled` from `/Library/Preferences/com.apple.loginwindow`.

**Remediation:**
```
System Settings > Users & Groups > Guest User > Allow guests to log in: Off
```

---

### Screen Saver Password

| Property | Value |
|----------|-------|
| **Check Name** | `Screen Saver Password` |
| **Category** | authentication |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
A delay before requiring password after screen lock allows an attacker to access an unattended computer during that window.

**What It Checks:**
1. Queries `sysadminctl -screenLock status` for immediate lock requirement
2. Falls back to reading `askForPassword` from screensaver preferences

**Remediation:**
```
System Settings > Lock Screen > Require password immediately after sleep or screen saver
```

---

### Sudo Session Timeout

| Property | Value |
|----------|-------|
| **Check Name** | `Sudo Session Timeout` |
| **Category** | authentication |
| **Severity** | MEDIUM |
| **Requires Sudo** | Yes |

**Rationale:**
A long or disabled sudo timeout allows cached credentials to be reused for extended periods, increasing the risk of privilege escalation if a session is compromised.

**What It Checks:**
Reads `/etc/sudoers` for `timestamp_timeout` setting. Flags values ≤0 (disabled) or >15 minutes.

**Remediation:**
Add to `/etc/sudoers` via `visudo`:
```
Defaults timestamp_timeout=5
```

---

### Password Policy

| Property | Value |
|----------|-------|
| **Check Name** | `Password Policy` |
| **Category** | authentication |
| **Severity** | HIGH |
| **Requires Sudo** | Yes |

**Rationale:**
Weak password policies allow easily guessable passwords that can be brute-forced or obtained through social engineering.

**What It Checks:**
Queries `pwpolicy getaccountpolicies` for minimum length (recommends ≥12) and maximum failed attempts (recommends ≤10).

**Remediation:**
Configure password policy via:
```bash
pwpolicy -setglobalpolicy "minChars=12 maxFailedLoginAttempts=10"
```

---

## Privacy Checks

All privacy checks query the TCC (Transparency, Consent, and Control) database to audit which applications have been granted sensitive permissions.

### Camera Permissions

| Property | Value |
|----------|-------|
| **Check Name** | `Camera Permissions` |
| **Category** | privacy |
| **Severity** | MEDIUM |
| **Requires Sudo** | No (but requires Full Disk Access for complete results) |

**Rationale:**
Camera access allows applications to capture video without visible indication. Malicious apps with camera access can conduct surveillance.

**What It Checks:**
Queries TCC database for `kTCCServiceCamera` permissions granted to third-party apps.

**Remediation:**
```
System Settings > Privacy & Security > Camera > Review and remove unnecessary apps
```

---

### Microphone Permissions

| Property | Value |
|----------|-------|
| **Check Name** | `Microphone Permissions` |
| **Category** | privacy |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
Microphone access enables audio surveillance. Unlike camera, there's no hardware indicator light for microphone usage on all Mac models.

**What It Checks:**
Queries TCC database for `kTCCServiceMicrophone` permissions.

**Remediation:**
```
System Settings > Privacy & Security > Microphone > Review and remove unnecessary apps
```

---

### Screen Recording Permissions

| Property | Value |
|----------|-------|
| **Check Name** | `Screen Recording Permissions` |
| **Category** | privacy |
| **Severity** | HIGH |
| **Requires Sudo** | No |

**Rationale:**
Screen recording captures everything visible on screen, including passwords, private messages, and sensitive documents. This is one of the most powerful permissions an app can have.

**What It Checks:**
Queries TCC database for `kTCCServiceScreenCapture` permissions.

**Remediation:**
```
System Settings > Privacy & Security > Screen Recording > Review and remove unnecessary apps
```

---

### Accessibility Permissions

| Property | Value |
|----------|-------|
| **Check Name** | `Accessibility Permissions` |
| **Category** | privacy |
| **Severity** | HIGH |
| **Requires Sudo** | No |

**Rationale:**
Accessibility access allows apps to control your Mac, simulate keystrokes, read screen content, and interact with other applications. This permission is frequently abused by malware.

**What It Checks:**
Queries TCC database for `kTCCServiceAccessibility` permissions.

**Remediation:**
```
System Settings > Privacy & Security > Accessibility > Review and remove unnecessary apps
```

---

### Full Disk Access Permissions

| Property | Value |
|----------|-------|
| **Check Name** | `Full Disk Access Permissions` |
| **Category** | privacy |
| **Severity** | HIGH |
| **Requires Sudo** | No |

**Rationale:**
Full Disk Access grants read access to protected locations including Mail, Messages, Safari data, and other apps' containers. This bypasses sandboxing protections.

**What It Checks:**
Queries TCC database for `kTCCServiceSystemPolicyAllFiles` permissions.

**Remediation:**
```
System Settings > Privacy & Security > Full Disk Access > Review and remove unnecessary apps
```

---

### Location Permissions

| Property | Value |
|----------|-------|
| **Check Name** | `Location Permissions` |
| **Category** | privacy |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
Location data reveals your physical whereabouts and movement patterns. This data can be used for stalking, profiling, or targeted attacks.

**What It Checks:**
Queries TCC database for `kTCCServiceLocation` permissions.

**Remediation:**
```
System Settings > Privacy & Security > Location Services > Review and remove unnecessary apps
```

---

## Application Checks

### Unsigned Applications

| Property | Value |
|----------|-------|
| **Check Name** | `Unsigned Applications` |
| **Category** | applications |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
Code signing verifies the identity of the developer and ensures the code hasn't been tampered with. Unsigned applications bypass these protections and may be malicious or compromised.

**What It Checks:**
Runs `codesign --verify --deep --strict` on applications in `/Applications` and `~/Applications` (up to 25 apps scanned).

**Remediation:**
- Remove unsigned applications
- Replace with signed versions from trusted sources
- If the app is legitimate but unsigned, contact the developer

---

### Dangerous Application Entitlements

| Property | Value |
|----------|-------|
| **Check Name** | `Dangerous Application Entitlements` |
| **Category** | applications |
| **Severity** | HIGH |
| **Requires Sudo** | No |

**Rationale:**
Certain entitlements weaken macOS security protections:
- `com.apple.security.cs.disable-library-validation` - Allows loading unsigned libraries
- `com.apple.security.get-task-allow` - Allows debugging/injection by other processes

**What It Checks:**
Extracts entitlements via `codesign -d --entitlements` and checks for dangerous entries.

**Remediation:**
- Review why the application requires these entitlements
- Consider alternatives that don't require weakened security
- For development tools, ensure they're from trusted sources

---

### Quarantine Enforcement

| Property | Value |
|----------|-------|
| **Check Name** | `Quarantine Enforcement` |
| **Category** | applications |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
The quarantine flag triggers Gatekeeper checks on downloaded files. Disabling it allows malicious downloads to execute without verification.

**What It Checks:**
Reads `LSQuarantine` from `com.apple.LaunchServices` preferences.

**Remediation:**
```bash
defaults write com.apple.LaunchServices LSQuarantine -bool true
```

---

### Safari Security Settings

| Property | Value |
|----------|-------|
| **Check Name** | `Safari Security Settings` |
| **Category** | applications |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
Safari is the default browser on macOS and handles sensitive operations like banking and authentication. Misconfigured security settings can expose users to phishing, tracking, and credential theft.

**What It Checks:**
Reads Safari preferences from `com.apple.Safari` domain:
- `WarnAboutFraudulentWebsites` - Phishing and malware warnings
- `SendDoNotTrackHTTPHeader` - Privacy tracking header
- `AutoFillPasswords` - Password autofill (security risk if enabled)
- `AutoFillCreditCardData` - Credit card autofill
- `BlockStoragePolicy` - Third-party cookie blocking

**Remediation:**
```
Safari > Settings > Security:
  - Fraudulent sites: Warn when visiting a fraudulent website ✓
  
Safari > Settings > Privacy:
  - Prevent cross-site tracking ✓
  - Block all cookies (optional, may break some sites)

Safari > Settings > AutoFill:
  - User names and passwords: Off (use a dedicated password manager)
  - Credit cards: Off
```

**Note:** This check is skipped if Safari is not installed or has never been used.

---

## Configuration Checks

### Firmware Password

| Property | Value |
|----------|-------|
| **Check Name** | `Firmware Password` |
| **Category** | configuration |
| **Severity** | CRITICAL |
| **Requires Sudo** | Yes |

**Rationale:**
A firmware password prevents booting from external media or entering Recovery Mode without authentication. This protects against physical attacks that attempt to bypass the operating system.

**What It Checks:**
Queries `firmwarepasswd -check` (Intel Macs) or checks Startup Security Utility settings (Apple Silicon).

**Remediation:**
**Intel Macs:**
```
1. Boot to Recovery Mode
2. Utilities > Startup Security Utility or Firmware Password Utility
3. Turn On Firmware Password
```

**Apple Silicon:**
```
1. Shut down Mac
2. Press and hold power button until "Loading startup options" appears
3. Click Options > Continue
4. Utilities > Startup Security Utility
```

---

### Secure Boot

| Property | Value |
|----------|-------|
| **Check Name** | `Secure Boot` |
| **Category** | configuration |
| **Severity** | HIGH |
| **Requires Sudo** | Yes |

**Rationale:**
Secure Boot ensures only trusted, signed operating systems and kernel extensions can run. Reduced security allows potentially compromised or unsigned code to run at boot.

**What It Checks:**
Queries `csrutil authenticated-root status` to check if authenticated root is enabled (Apple Silicon).

**Remediation:**
```
1. Boot to Recovery Mode
2. Utilities > Startup Security Utility
3. Select "Full Security"
```

---

### Time Machine Encryption

| Property | Value |
|----------|-------|
| **Check Name** | `Time Machine Encryption` |
| **Category** | configuration |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
Time Machine backups contain complete copies of your data. Unencrypted backup drives expose all your data if lost or stolen.

**What It Checks:**
Queries `tmutil destinationinfo` for backup destinations and checks APFS encryption status for each mounted volume.

**Remediation:**
```
System Settings > General > Time Machine > Select disk > Encrypt Backup
```
Or when adding a new backup disk, check "Encrypt backups".

---

### Crash Reporting

| Property | Value |
|----------|-------|
| **Check Name** | `Crash Reporting` |
| **Category** | configuration |
| **Severity** | LOW |
| **Requires Sudo** | No |

**Rationale:**
Automatic crash reports may contain sensitive data from memory at the time of crash. While useful for debugging, some organizations prefer to disable automatic submission for privacy.

**What It Checks:**
Reads `AutoSubmit` from `/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist`.

**Remediation:**
```
System Settings > Privacy & Security > Analytics & Improvements > Share Mac Analytics: Off
```

---

### Analytics Sharing

| Property | Value |
|----------|-------|
| **Check Name** | `Analytics Sharing` |
| **Category** | configuration |
| **Severity** | LOW |
| **Requires Sudo** | No |

**Rationale:**
Analytics data sharing sends usage information to Apple and third parties. While generally anonymized, some organizations require disabling for compliance or privacy policies.

**What It Checks:**
Reads `ThirdPartyDataSubmit` and `AutoSubmitWithiCloud` from crash reporter preferences.

**Remediation:**
```
System Settings > Privacy & Security > Analytics & Improvements > 
  - Share Mac Analytics: Off
  - Share with App Developers: Off
  - Share iCloud Analytics: Off
```

---

### Apple ID 2FA

| Property | Value |
|----------|-------|
| **Check Name** | `Apple ID 2FA` |
| **Category** | configuration |
| **Severity** | HIGH |
| **Requires Sudo** | No |

**Rationale:**
Two-factor authentication (2FA) is a critical security feature that protects your Apple ID from unauthorized access. Without 2FA, an attacker who obtains your password can access:
- iCloud data (photos, documents, backups)
- App Store and iTunes purchases
- iMessage and FaceTime
- Find My devices
- Keychain passwords synced to iCloud

This is a **huge security win** if not already enabled.

**What It Checks:**
1. Verifies an Apple ID is signed in via `MobileMeAccounts`
2. Checks authentication type indicators for 2FA/HSA2
3. Looks for Apple ID authentication tokens in keychain

**Remediation:**
```
System Settings > [Your Name] > Sign-In & Security > Two-Factor Authentication
```

**Important:** Once enabled, 2FA cannot be disabled on accounts that have used it for more than two weeks.

---

### Find My Mac

| Property | Value |
|----------|-------|
| **Check Name** | `Find My Mac` |
| **Category** | configuration |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
Find My Mac allows you to:
- **Locate** your Mac on a map if it's lost or stolen
- **Lock** your Mac remotely with a passcode
- **Erase** all data remotely to prevent unauthorized access
- **Display a message** on the lock screen with contact information
- **Activation Lock** prevents anyone from erasing and reactivating your Mac

This is critical for device recovery and preventing unauthorized data access.

**What It Checks:**
1. Reads `FMMEnabled` from Find My Mac preferences
2. Checks for `fmm-mobileme-token-FMM` in NVRAM (activation lock)
3. Queries iCloud preferences for Find My Mac status

**Remediation:**
```
System Settings > [Your Name] > iCloud > Find My Mac > Turn On
```

**Requirements:**
- Must be signed into iCloud
- Location Services must be enabled
- Find My network access recommended for offline finding

---

## Understanding Check Results

### Status Values

| Status | Meaning |
|--------|---------|
| **PASS** | Check passed - the security control is properly configured |
| **FAIL** | Check failed - the security control is not configured correctly |
| **WARNING** | Potential issue detected - review recommended |
| **SKIP** | Check was skipped (unsupported OS version, missing permissions, etc.) |
| **ERROR** | Check encountered an error during execution |

### Severity Levels

| Severity | Description |
|----------|-------------|
| **CRITICAL** | Fundamental security control - must be addressed immediately |
| **HIGH** | Significant security risk - address as soon as possible |
| **MEDIUM** | Moderate security risk - plan to address |
| **LOW** | Minor security consideration - address when convenient |
| **INFO** | Informational only - no action required |

---

## Version Compatibility Matrix

This matrix shows which checks are available on different macOS versions and hardware configurations.

### macOS Version Support

| Check Name | macOS 13 (Ventura) | macOS 14 (Sonoma) | macOS 15 (Sequoia) | macOS 16 (Tahoe) | Notes |
|------------|:------------------:|:-----------------:|:------------------:|:----------------:|-------|
| FileVault Encryption | ✓ | ✓ | ✓ | ✓ | |
| External Disk Encryption | ✓ | ✓ | ✓ | ✓ | APFS volumes only |
| Application Firewall | ✓ | ✓ | ✓ | ✓ | |
| Firewall Stealth Mode | ✓ | ✓ | ✓ | ✓ | |
| Remote Login (SSH) | ✓ | ✓ | ✓ | ✓ | |
| Screen Sharing | ✓ | ✓ | ✓ | ✓ | |
| Remote Management | ✓ | ✓ | ✓ | ✓ | |
| AirDrop Discoverability | ✓ | ✓ | ✓ | ✓ | |
| Bluetooth Discoverability | ✓ | ✓ | ✓ | ✓ | |
| System Integrity Protection | ✓ | ✓ | ✓ | ✓ | |
| Gatekeeper | ✓ | ✓ | ✓ | ✓ | |
| XProtect Definitions | ✓ | ✓ | ✓ | ✓ | |
| Malware Removal Tool | ✓ | ✓ | ✓ | ✓ | XProtect Remediator on 13+ |
| Software Updates Pending | ✓ | ✓ | ✓ | ✓ | |
| Automatic Updates | ✓ | ✓ | ✓ | ✓ | |
| Security Update Auto-Install | ✓ | ✓ | ✓ | ✓ | RSR on 13.3+ |
| Automatic Login | ✓ | ✓ | ✓ | ✓ | |
| Guest Account | ✓ | ✓ | ✓ | ✓ | |
| Screen Saver Password | ✓ | ✓ | ✓ | ✓ | |
| Sudo Session Timeout | ✓ | ✓ | ✓ | ✓ | Requires sudo |
| Password Policy | ✓ | ✓ | ✓ | ✓ | Requires sudo |
| Apple ID 2FA | ✓ | ✓ | ✓ | ✓ | |
| Find My Mac | ✓ | ✓ | ✓ | ✓ | |
| TCC Privacy Checks | ✓ | ✓ | ✓ | ✓ | |
| Unsigned Applications | ✓ | ✓ | ✓ | ✓ | |
| Dangerous Entitlements | ✓ | ✓ | ✓ | ✓ | |
| Quarantine Enforcement | ✓ | ✓ | ✓ | ✓ | |
| Safari Security Settings | ✓ | ✓ | ✓ | ✓ | |
| Firmware Password | ✓ | ✓ | ✓ | ✓ | Intel only |
| Secure Boot | ✓ | ✓ | ✓ | ✓ | T2/Apple Silicon only |
| Time Machine Encryption | ✓ | ✓ | ✓ | ✓ | |
| Crash Reporting | ✓ | ✓ | ✓ | ✓ | |
| Analytics Sharing | ✓ | ✓ | ✓ | ✓ | |

### Hardware-Specific Checks

| Check Name | Intel (pre-T2) | Intel (T2) | Apple Silicon | Notes |
|------------|:--------------:|:----------:|:-------------:|-------|
| Firmware Password | ✓ | ✓ | ✗ | Not applicable to Apple Silicon |
| Secure Boot | ✗ | ✓ | ✓ | Requires T2 or Secure Enclave |
| Secure Enclave | ✗ | ✓ | ✓ | |
| Rosetta Translation | ✗ | ✗ | ✓ | Only on Apple Silicon |
| FileVault (HW Accelerated) | Partial | ✓ | ✓ | Full acceleration on T2+ |

### Feature Availability by Configuration

| Feature | Standard User | Admin User | Root/Sudo | Notes |
|---------|:-------------:|:----------:|:---------:|-------|
| Most security checks | ✓ | ✓ | ✓ | ~90% of checks |
| TCC Privacy checks (full) | Partial | Partial | ✓ | Full Disk Access helps |
| Firmware Password check | ✗ | ✗ | ✓ | Requires sudo |
| Sudo Timeout check | ✗ | ✗ | ✓ | Requires sudo |
| Password Policy check | ✗ | ✗ | ✓ | Requires sudo |
| Secure Boot check | ✗ | ✗ | ✓ | Requires sudo |

---

## Exit Codes for CI/CD Integration

macSentry uses structured exit codes for automation and CI/CD pipelines:

| Exit Code | Meaning | CI/CD Action |
|:---------:|---------|--------------|
| **0** | All checks passed | ✅ Pipeline success |
| **1** | Warnings found (non-critical) | ⚠️ Review recommended |
| **2** | Critical/High issues found | ❌ Pipeline should fail |
| **3** | Errors during execution | ❌ Investigate failures |

### Usage Examples

```bash
# Run audit and capture exit code
python3 macos_security_audit.py --format json -o results.json
EXIT_CODE=$?

case $EXIT_CODE in
  0) echo "All checks passed" ;;
  1) echo "Warnings found - review recommended" ;;
  2) echo "Critical issues - security review required" ;;
  3) echo "Execution errors - check logs" ;;
esac

# CI/CD pipeline example (GitHub Actions)
- name: Security Audit
  run: |
    python3 macos_security_audit.py --min-severity HIGH --format json -o audit.json
  continue-on-error: false  # Fail on exit code 2 or 3

# Strict mode - fail on any warning
- name: Strict Security Audit
  run: |
    python3 macos_security_audit.py --format json -o audit.json
    if [ $? -ne 0 ]; then exit 1; fi
```

---

## False Positive Handling

### App Entitlements Whitelist

Some applications legitimately require entitlements that would otherwise be flagged as dangerous. macSentry maintains a whitelist of known-safe applications and their expected entitlements.

#### Currently Whitelisted Applications

| Application | Entitlement | Reason |
|-------------|-------------|--------|
| **Xcode.app** | `get-task-allow` | Development tool - debugging support expected |
| **Visual Studio Code.app** | `disable-library-validation` | Electron app with plugin architecture |
| **Slack.app** | `disable-library-validation` | Electron app with plugin support |
| **Discord.app** | `disable-library-validation` | Electron app with plugin support |
| **Mullvad VPN.app** | `disable-library-validation` | VPN - network extension plugins |
| **Tailscale.app** | `disable-library-validation` | VPN - network extension plugins |
| **WireGuard.app** | `disable-library-validation` | VPN - network extension plugins |

#### Contributing to the Whitelist

If you've identified a false positive, you can submit a PR to add it to the whitelist:

1. **File location**: `checks/applications.py` - `DangerousEntitlementsCheck.expected_entitlements`

2. **Required information**:
   - Application name (exact `.app` bundle name)
   - Entitlement(s) being whitelisted
   - Justification explaining why this is expected/safe
   - Link to vendor documentation if available

3. **PR format**:
   ```python
   # In DangerousEntitlementsCheck.expected_entitlements
   "YourApp.app": {
       "disable-library-validation": "Brief justification for why this is expected",
   },
   ```

4. **Acceptance criteria**:
   - App must be from a reputable vendor
   - Entitlement must be genuinely required for app functionality
   - App must be code-signed and notarized
   - Preference for apps distributed via App Store or official channels

#### Local Whitelist Override

For local/enterprise apps, create a `~/.config/macsentry/whitelist.json`:

```json
{
  "entitlement_whitelist": {
    "MyInternalApp.app": {
      "disable-library-validation": "Internal enterprise app with plugins",
      "get-task-allow": "Development build for internal testing"
    }
  }
}
```

---

## References

- [Apple Platform Security Guide](https://support.apple.com/guide/security/)
- [CIS Benchmarks for macOS](https://www.cisecurity.org/benchmark/apple_os)
- [NIST macOS Security Guidance](https://www.nist.gov/itl/tig/projects/macos-security)
- [macOS Security Compliance Project](https://github.com/usnistgov/macos_security)
