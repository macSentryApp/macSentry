# 🛡️ macSentry

**macSentry** is a lightweight, automated security auditing tool for macOS that detects common misconfigurations and vulnerabilities, producing actionable reports with severity levels and remediation guidance. Designed for macOS 13+ (Ventura, Sonoma, Sequoia, Tahoe) on both Apple Silicon and Intel, it runs 90%+ of checks without elevated privileges and integrates seamlessly with launchd for scheduled scans.

---

## Features

- **39 security checks** across encryption, firewall, system integrity, authentication, privacy, applications, and configuration categories
- **No external dependencies** — uses only Python standard library and built-in macOS commands
- **Multiple output formats** — human-readable text, JSON, and HTML reports
- **Scheduled scanning** via launchd with included plist and installer
- **Minimal privilege requirements** — most checks run without sudo
- **CI/CD integration** — structured exit codes for automation pipelines
- **Performance metrics** — timing breakdown for optimization
- **Recommended actions** — prioritized remediation guidance with time estimates

---

## Requirements

- macOS 13.0+ (Ventura, Sonoma, Sequoia, Tahoe)
- Python 3.9+

---

## Installation

### Option 1: pipx (Recommended)

```bash
# Install pipx if you don't have it
brew install pipx
pipx ensurepath

# Install macSentry
pipx install macSentry

# Run
macsentry --help
```

### Option 2: pip

```bash
# Install in a virtual environment
python3 -m venv ~/.venv/macsentry
source ~/.venv/macsentry/bin/activate
pip install macSentry

# Run
macsentry --help
```

### Option 3: Git Clone (Development)

```bash
# Clone the repository
git clone https://github.com/macSentry/macos-security-audit.git
cd macos-security-audit

# Create virtual environment and install in editable mode
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Run
macsentry --dry-run
```

### Option 4: Homebrew

```bash
# Install from local formula
brew install --build-from-source ./Formula/macos-security-audit.rb

# Or add tap (once published)
brew tap macSentry/macos-security-audit
brew install macos-security-audit

# Run
macsentry --help
```

---

## Usage

### Run All Checks

```bash
macsentry
```

### Filter by Category

```bash
macsentry --categories encryption,firewall
```

### Output Formats

```bash
# JSON output
macsentry --format json

# HTML report
macsentry --format html --output report.html
```

### Severity Filtering

```bash
# Show only CRITICAL and HIGH findings
macsentry --min-severity HIGH
```

### Include Passed Checks

```bash
macsentry --verbose
```

### Dry Run (List Checks Without Executing)

```bash
macsentry --dry-run
```

### Run Elevated Checks (Requires sudo)

```bash
sudo macsentry --elevated
```

---

## Scheduling with launchd

The included `install.sh` script installs a LaunchAgent that runs the audit daily at 09:00.

```bash
# Install the scheduled job
chmod +x install.sh
./install.sh

# Verify installation
launchctl list | grep macos-security-audit

# Unload if needed
launchctl unload ~/Library/LaunchAgents/com.macos-security-audit.plist
```

Logs are written to:
- **stdout**: `~/Library/Logs/macos-security-audit/macos-security-audit.log`
- **stderr**: `~/Library/Logs/macos-security-audit/macos-security-audit.error`
- **Application logs**: `~/Library/Logs/macos-security-audit/audit.log`

---

## Check Reference

| Check Name | Category | Severity | Requires Sudo |
|------------|----------|----------|---------------|
| FileVault Encryption | encryption | CRITICAL | No |
| External Disk Encryption | encryption | HIGH | No |
| Application Firewall | firewall | HIGH | No |
| Firewall Stealth Mode | firewall | MEDIUM | No |
| Remote Login (SSH) | firewall | MEDIUM | No |
| Screen Sharing | firewall | MEDIUM | No |
| Remote Management | firewall | HIGH | No |
| AirDrop Discoverability | firewall | MEDIUM | No |
| Bluetooth Discoverability | firewall | LOW | No |
| System Integrity Protection | system_integrity | CRITICAL | No |
| Gatekeeper | system_integrity | HIGH | No |
| XProtect Definitions | system_integrity | MEDIUM | No |
| Malware Removal Tool | system_integrity | MEDIUM | No |
| Software Updates Pending | system_integrity | MEDIUM | No |
| Automatic Updates | system_integrity | MEDIUM | No |
| Automatic Login | authentication | HIGH | No |
| Guest Account | authentication | MEDIUM | No |
| Screen Saver Password | authentication | MEDIUM | No |
| Sudo Session Timeout | authentication | MEDIUM | Yes |
| Password Policy | authentication | HIGH | Yes |
| Camera Permissions | privacy | MEDIUM | No |
| Microphone Permissions | privacy | MEDIUM | No |
| Screen Recording Permissions | privacy | HIGH | No |
| Accessibility Permissions | privacy | HIGH | No |
| Full Disk Access Permissions | privacy | HIGH | No |
| Location Permissions | privacy | MEDIUM | No |
| Unsigned Applications | applications | MEDIUM | No |
| Dangerous Application Entitlements | applications | HIGH | No |
| Quarantine Enforcement | applications | MEDIUM | No |
| Firmware Password | configuration | CRITICAL | Yes |
| Secure Boot | configuration | HIGH | Yes |
| Time Machine Encryption | configuration | MEDIUM | No |
| Crash Reporting | configuration | LOW | No |
| Analytics Sharing | configuration | LOW | No |
| Apple ID 2FA | configuration | HIGH | No |
| Find My Mac | configuration | MEDIUM | No |

---

## Remediation Guide

### CRITICAL Severity

| Issue | Fix |
|-------|-----|
| **FileVault Disabled** | System Settings → Privacy & Security → FileVault → Turn On |
| **SIP Disabled** | Boot to Recovery Mode → Terminal → `csrutil enable` → Reboot |

### HIGH Severity

| Issue | Fix |
|-------|-----|
| **Firewall Disabled** | System Settings → Network → Firewall → Turn On |
| **Gatekeeper Disabled** | Terminal: `sudo spctl --master-enable` |
| **Automatic Login Enabled** | System Settings → Users & Groups → Login Options → Disable |
| **Remote Management Enabled** | System Settings → General → Sharing → Remote Management → Off |
| **Screen Recording Permissions** | System Settings → Privacy & Security → Screen Recording → Review apps |
| **Accessibility Permissions** | System Settings → Privacy & Security → Accessibility → Review apps |
| **Full Disk Access Permissions** | System Settings → Privacy & Security → Full Disk Access → Review apps |
| **Dangerous Entitlements** | Remove or replace apps with risky entitlements |
| **Firmware Password Not Set** | Boot to Recovery → Utilities → Startup Security Utility |
| **Secure Boot Disabled** | Boot to Recovery → Startup Security Utility → Full Security |

### MEDIUM Severity

| Issue | Fix |
|-------|-----|
| **Stealth Mode Disabled** | System Settings → Network → Firewall → Options → Enable Stealth Mode |
| **Remote Login Enabled** | System Settings → General → Sharing → Remote Login → Off |
| **Screen Sharing Enabled** | System Settings → General → Sharing → Screen Sharing → Off |
| **Guest Account Enabled** | System Settings → Users & Groups → Guest User → Off |
| **Screen Saver Password Delayed** | System Settings → Lock Screen → Require password immediately |
| **Pending Software Updates** | System Settings → General → Software Update → Install |
| **Automatic Updates Disabled** | System Settings → General → Software Update → Automatic Updates → On |
| **XProtect Outdated** | Run `softwareupdate --background` |
| **Time Machine Unencrypted** | System Settings → General → Time Machine → Encrypt Backups |
| **Quarantine Disabled** | Terminal: `defaults write com.apple.LaunchServices LSQuarantine -bool true` |

### LOW Severity

| Issue | Fix |
|-------|-----|
| **Crash Reporting Enabled** | System Settings → Privacy & Security → Analytics & Improvements → Off |
| **Analytics Sharing Enabled** | System Settings → Privacy & Security → Analytics & Improvements → Off |

---

## Troubleshooting

### Common Issues

#### "TCC database access denied"

**Symptom:** Privacy checks skip with "Grant Full Disk Access" message.

**Solution:**
```
System Settings > Privacy & Security > Full Disk Access > Add Terminal (or your Python app)
```
Then restart Terminal and re-run the audit.

#### "Requires elevated privileges"

**Symptom:** Checks like Firmware Password or Password Policy show as skipped.

**Solution:**
```bash
sudo macsentry --elevated
```

#### launchd fails on external volume

**Symptom:** Scheduled job shows error "Operation not permitted" in logs.

**Cause:** macOS security restrictions prevent launchd agents from accessing external/removable volumes.

**Solution:** Move the project to an internal volume:
```bash
cp -R /Volumes/ExternalDisk/macos-security-audit ~/Applications/
cd ~/Applications/macos-security-audit
./install.sh
```

#### "Command timed out"

**Symptom:** Individual checks fail with timeout errors.

**Causes:**
- Slow disk access (especially for external drives)
- Network-dependent checks during connectivity issues
- System under heavy load

**Solution:** The tool uses circuit breakers to handle repeated failures. Re-run the audit when the system is less busy.

#### "Unable to determine [X] status"

**Symptom:** Checks return WARNING with indeterminate status.

**Causes:**
- macOS version differences in command output
- Unexpected system configuration
- Third-party tools modifying default behavior

**Solution:** Check the `details` field in JSON output for raw command output, then file an issue if the detection logic needs updating.

#### HTML Report Won't Open

**Symptom:** Generated HTML file shows raw HTML code.

**Solution:** Ensure the file has `.html` extension:
```bash
macsentry --format html --output report.html
open report.html
```

#### No Checks Run

**Symptom:** Audit completes instantly with no output.

**Possible Causes:**
- Invalid category filter: `--categories xyz` where `xyz` doesn't match any category
- Using `--elevated` without sudo but all non-sudo checks filtered out

**Solution:** Run `--dry-run` to verify which checks would execute:
```bash
macsentry --dry-run
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
macsentry --debug
```

Logs are written to `~/Library/Logs/macos-security-audit/audit.log`.

---

## CI/CD Integration

macSentry provides structured exit codes for automation pipelines:

| Exit Code | Meaning | CI/CD Action |
|:---------:|---------|--------------|
| **0** | All checks passed | ✅ Pipeline success |
| **1** | Warnings found (non-critical) | ⚠️ Review recommended |
| **2** | Critical/High issues found | ❌ Pipeline should fail |
| **3** | Errors during execution | ❌ Investigate failures |

### GitHub Actions Example

```yaml
jobs:
  security-audit:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Security Audit
        run: |
          macsentry --format json -o audit-results.json
        continue-on-error: false
      
      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: security-audit
          path: audit-results.json
```

### Shell Script Example

```bash
#!/bin/bash
macsentry --format json -o results.json
EXIT_CODE=$?

case $EXIT_CODE in
  0) echo "✅ All security checks passed" ;;
  1) echo "⚠️ Warnings found - review recommended" ;;
  2) echo "❌ Critical issues found - immediate action required" ;;
  3) echo "🔴 Errors during execution - check logs" ;;
esac

exit $EXIT_CODE
```

See [CHECKS.md](docs/CHECKS.md#exit-codes-for-cicd-integration) for more CI/CD examples.

---

### Verifying Installation

```bash
# Check Python version (requires 3.10+)
python3 --version

# Verify the script runs
macsentry --dry-run

# Check if scheduled job is installed
launchctl list | grep macos-security-audit
```

---

## FAQ

### Why do some checks require sudo?

Certain system configurations (firmware password, sudoers file, password policies) are protected and require root access to query. Run with `sudo macsentry --elevated` to include these checks.

### How do I disable specific checks?

Currently, checks cannot be individually disabled. Use `--categories` to limit which categories run, or filter output with `--min-severity`.

### Why do privacy checks show "Requires Full Disk Access"?

The TCC database that stores privacy permissions is protected. Grant Full Disk Access to Terminal (or your Python interpreter) in System Settings → Privacy & Security → Full Disk Access to enable these checks.

### How do I customize severity levels?

Severity levels are hardcoded per check. To adjust, modify the `severity` class attribute in the corresponding check file under `checks/`. See [CHECKS.md](docs/CHECKS.md) for details on each check.

### Can I run this on older macOS versions?

The tool targets macOS 13+. Some checks may work on older versions, but compatibility is not guaranteed. Checks with `min_version` set will be skipped automatically on unsupported versions.

### Where are logs stored?

- **Application logs**: `~/Library/Logs/macos-security-audit/audit.log`
  - Automatically rotated at 5MB (3 backups retained: `audit.log.1`, `audit.log.2`, `audit.log.3`)
- **Scheduled job output**: `~/Library/Logs/macos-security-audit/macos-security-audit.log` and `macos-security-audit.error`

### Is there telemetry?

No. This tool does not collect, transmit, or phone home any data. All logs and reports remain local on your machine. If you want to share findings, you can manually export reports using `--format json` or `--format html`.

### How do I uninstall the scheduled job?

```bash
launchctl unload ~/Library/LaunchAgents/com.macos-security-audit.plist
rm ~/Library/LaunchAgents/com.macos-security-audit.plist
```

### Why are some applications flagged as unsigned?

Applications that fail `codesign --verify` may be unsigned, have broken signatures, or lack notarization. Consider replacing them with signed alternatives from trusted sources.

### What's the difference between FAIL and WARNING?

- **FAIL**: The security control is definitively misconfigured (e.g., FileVault disabled)
- **WARNING**: A potential issue that may require review (e.g., third-party apps with camera access)

---

## Project Structure

```
macSentry/
├── macos_security_audit.py      # CLI entry point
├── checks/
│   ├── __init__.py
│   ├── base.py                  # Base SecurityCheck class
│   ├── encryption.py            # FileVault, disk encryption
│   ├── firewall.py              # Firewall, network security
│   ├── system_integrity.py      # SIP, Gatekeeper, updates
│   ├── authentication.py        # Login, password, sudo
│   ├── privacy.py               # TCC permissions
│   ├── applications.py          # Code signing, entitlements
│   └── configuration.py         # Firmware, boot, backups
├── utils/
│   ├── __init__.py
│   ├── commands.py              # Safe command execution
│   ├── compat.py                # Python version compatibility
│   ├── parsers.py               # Plist and output parsing
│   └── reporting.py             # Text, JSON, HTML formatters
├── launchd/
│   └── com.macos-security-audit.plist
├── Formula/
│   └── macos-security-audit.rb  # Homebrew formula
├── scripts/
│   ├── setup-dev.sh             # Development environment setup
│   ├── lint.sh                  # Run all linters
│   ├── test-deployment.sh       # Deployment test suite
│   └── self-update.sh           # Auto-update script
├── tests/
│   ├── test_command_execution.py
│   └── test_encryption_checks.py
├── install.sh                   # LaunchAgent installer
├── uninstall.sh                 # LaunchAgent uninstaller
└── README.md
```

---

## Running Tests

```bash
python3 -m unittest discover -s tests
```

---

## Development

### Setup Development Environment

```bash
# Run the setup script (creates venv, installs tools, sets up pre-commit)
./scripts/setup-dev.sh

# Or manually:
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

### Static Analysis & Linting

This project enforces strict code quality standards:

| Tool | Purpose | Configuration |
|------|---------|---------------|
| **Pylint** | Comprehensive linting | `pyproject.toml` (score ≥ 8.0) |
| **Flake8** | Style & complexity | `.flake8` |
| **MyPy** | Type checking (strict mode) | `pyproject.toml` |
| **Bandit** | Security vulnerabilities | `pyproject.toml`, `.bandit` |
| **Semgrep** | Vulnerability patterns | `p/python`, `p/security-audit` |
| **Radon** | Cyclomatic complexity | Target: all functions ≤ 10 |

#### Run All Linters

```bash
./scripts/lint.sh
```

#### Run Individual Tools

```bash
# Style & complexity
flake8 checks/ utils/

# Comprehensive linting
pylint checks/ utils/

# Type checking (90%+ coverage enforced)
mypy checks/ utils/ --strict

# Security analysis
bandit -r checks/ utils/ -ll

# Vulnerability patterns
semgrep --config p/python --config p/security-audit checks/ utils/

# Cyclomatic complexity report
radon cc checks/ utils/ -a -s
```

### Pre-commit Hooks

Pre-commit hooks automatically run on every commit to block non-compliant code:

```bash
# Install hooks (done by setup-dev.sh)
pre-commit install

# Run manually on all files
pre-commit run --all-files

# Skip hooks (emergency only)
git commit --no-verify -m "message"
```

### Code Quality Standards

- **Type hints**: 90%+ coverage required (enforced by mypy strict mode)
- **Cyclomatic complexity**: Maximum 10 per function (enforced by radon/flake8)
- **Pylint score**: Minimum 8.0/10
- **Security**: No medium+ severity issues (bandit)
- **No hardcoded secrets**: Detected by pre-commit and semgrep

---

## Contributing

1. Fork the repository
2. Run `./scripts/setup-dev.sh` to set up your development environment
3. Create a feature branch (`git checkout -b feature/new-check`)
4. Add tests for new functionality
5. Ensure all checks pass:
   - `./scripts/lint.sh` (all linters)
   - `python3 -m unittest discover -s tests` (unit tests)
6. Pre-commit hooks will automatically validate your code
7. Submit a pull request

### Adding a New Check

1. Create or edit the appropriate file in `checks/`
2. Inherit from `SecurityCheck` and define required attributes:
   - `name`: Unique check identifier
   - `description`: Brief explanation
   - `category`: One of `encryption`, `firewall`, `system_integrity`, `authentication`, `privacy`, `applications`, `configuration`
   - `severity`: `Severity.CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`
   - `remediation`: User-facing fix instructions
   - `requires_sudo`: Set to `True` if elevated privileges needed
3. Implement the `run()` method returning a `CheckResult`
4. Add tests in `tests/`

---

## Documentation

- **[CHECKS.md](docs/CHECKS.md)** — Detailed documentation for all security checks with rationale and remediation
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** — Contributor guide covering internal architecture and design patterns
- **[CHANGELOG.md](CHANGELOG.md)** — Version history and release notes
- **[MANUAL_TESTING_CHECKLIST.md](docs/MANUAL_TESTING_CHECKLIST.md)** — QA testing procedures

---

## Support

- **Issues & Bug Reports**: [GitHub Issues](https://github.com/your-org/macos-security-audit/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/macos-security-audit/discussions)
- **Documentation**: [docs/](docs/) — Architecture, check details, and testing guides
- **Changelog**: [CHANGELOG.md](CHANGELOG.md) — Version history and release notes

When reporting issues, please include:
1. macOS version (`sw_vers`)
2. Python version (`python3 --version`)
3. Relevant log output from `~/Library/Logs/macos-security-audit/audit.log`
4. Steps to reproduce

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

Built using macOS system commands including `fdesetup`, `csrutil`, `spctl`, `codesign`, `defaults`, `systemsetup`, and `diskutil`. Inspired by CIS Benchmarks for macOS and Apple Platform Security documentation.
