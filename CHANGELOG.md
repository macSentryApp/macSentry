# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Remediation layer with user-consent-based fixes
- Configuration file for check customization
- Check exclusion by name
- Baseline comparison for drift detection
- Integration with MDM solutions
- Slack/webhook notifications for findings

---

## [0.1.0] - 2024-12-01

Initial release of macOS Security Audit.

### Added

#### Security Checks (34 total)

**Encryption (2 checks)**
- FileVault full-disk encryption status
- External disk encryption audit for APFS volumes

**Firewall (6 checks)**
- Application Firewall status
- Firewall Stealth Mode configuration
- Remote Login (SSH) service detection
- Screen Sharing service detection
- Remote Management (ARD) service detection
- AirDrop discoverability settings

**System Integrity (6 checks)**
- System Integrity Protection (SIP) status
- Gatekeeper enforcement status
- XProtect signature freshness (30-day threshold)
- Malware Removal Tool (XProtect Remediator) freshness
- Pending software update detection
- Automatic updates configuration

**Authentication (5 checks)**
- Automatic login detection
- Guest account status
- Screen saver password requirements
- Sudo session timeout configuration (requires sudo)
- Password policy validation (requires sudo)

**Privacy (7 checks)**
- TCC Database Access verification
- Camera permissions audit
- Microphone permissions audit
- Screen Recording permissions audit
- Accessibility permissions audit
- Full Disk Access permissions audit
- Location Services permissions audit

**Applications (3 checks)**
- Unsigned application detection
- Dangerous entitlement scanning (`disable-library-validation`, `get-task-allow`)
- Quarantine enforcement (LSQuarantine) status

**Configuration (5 checks)**
- Firmware password status (requires sudo)
- Secure Boot / Authenticated Root status (requires sudo)
- Time Machine backup encryption
- Crash reporting preferences
- Analytics sharing preferences

#### Core Features
- Multiple output formats: text, JSON, HTML
- Category-based check filtering (`--categories`)
- Severity-based filtering (`--min-severity`)
- Dry-run mode to list checks without execution
- Parallel check execution for improved performance
- launchd integration for scheduled daily scans
- Application logging to `~/Library/Logs/macos-security-audit/`
- Self-update mechanism (`--self-update`)

#### Architecture
- Strict layer separation (Detection, Reporting, Remediation)
- Dependency injection for OS interactions
- Circuit breaker pattern for failure protection
- Graceful degradation on individual check failures
- Full type hints with mypy strict mode

#### Quality Assurance
- Comprehensive test suite with pytest
- Code coverage enforcement (80%+ threshold)
- Static analysis: Ruff, Bandit, Semgrep
- Pre-commit hooks for automated quality gates
- GitHub Actions CI/CD workflows

#### Documentation
- Complete README with usage examples
- Security check reference (`docs/CHECKS.md`)
- Remediation guide (`docs/REMEDIATION.md`)
- Contributor guide (`CONTRIBUTING.md`)
- Architecture guide (`docs/ARCHITECTURE.md`)
- Manual testing checklist

#### Installation
- Homebrew formula for easy installation
- Direct install script (`install.sh`)
- Uninstall script (`uninstall.sh`)

### Technical Details
- Python 3.10+ required
- No external runtime dependencies
- macOS 13+ (Ventura, Sonoma, Sequoia) supported
- Apple Silicon and Intel compatible

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 0.1.0 | 2024-12-01 | Initial release with 34 security checks |

---

## Security

For security vulnerabilities, please see [SECURITY.md](SECURITY.md) or contact the maintainers directly rather than filing a public issue.
