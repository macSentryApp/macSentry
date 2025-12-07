# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email your findings to the project maintainers (create a private security advisory on GitHub)
3. Alternatively, use GitHub's private vulnerability reporting feature:
   - Go to the repository's **Security** tab
   - Click **Report a vulnerability**
   - Fill out the form with details

### What to Include

When reporting a vulnerability, please include:

- **Description**: A clear description of the vulnerability
- **Impact**: What an attacker could achieve by exploiting this
- **Reproduction steps**: Detailed steps to reproduce the issue
- **Affected versions**: Which versions are impacted
- **Suggested fix**: If you have ideas for remediation (optional)

### Response Timeline

- **Acknowledgment**: Within 48 hours of receiving your report
- **Initial assessment**: Within 7 days
- **Resolution target**: Within 30 days for critical issues, 90 days for others
- **Disclosure**: Coordinated disclosure after a fix is available

### What to Expect

- We will acknowledge receipt of your vulnerability report
- We will investigate and validate the issue
- We will work on a fix and coordinate disclosure with you
- We will credit you in the security advisory (unless you prefer anonymity)

### Scope

This security policy applies to:

- The `macos-security-audit` Python tool and all its modules
- Installation scripts (`install.sh`, `uninstall.sh`)
- Self-update mechanisms
- Any official distribution channels (Homebrew formula, etc.)

### Out of Scope

- Security issues in third-party dependencies (report to their maintainers)
- Issues that require physical access to the machine
- Social engineering attacks

## Security Best Practices

When using this tool:

1. **Run with least privilege**: Only use `sudo` when specifically required
2. **Review before running**: Inspect scripts before execution
3. **Keep updated**: Use `--self-update` to get security fixes
4. **Verify integrity**: Check signatures/checksums when downloading releases

## Privacy Note

This tool does **not** collect, transmit, or phone home any data. All logs and reports remain local on your machine. See the README for more details.
