# Contributing to macOS Security Audit

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to the project.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Adding a New Security Check](#adding-a-new-security-check)
- [Code Standards](#code-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

---

## Code of Conduct

Please be respectful, inclusive, and professional in all interactions. We're building security tools to help the community—collaboration should reflect that mission.

---

## Ways to Contribute

### For Everyone

- **Report bugs** — Open an issue with reproduction steps
- **Suggest new checks** — Propose security checks via issue discussion
- **Improve documentation** — Fix typos, clarify explanations, add examples
- **Test on different macOS versions** — Report compatibility issues

### For Developers

- **Implement new security checks** — See [Adding a New Security Check](#adding-a-new-security-check)
- **Fix bugs** — Pick up issues labeled `good first issue` or `bug`
- **Improve test coverage** — Add tests for edge cases
- **Optimize performance** — Profile and improve check execution

### For Security Researchers

- **Review detection logic** — Validate checks against real-world scenarios
- **Report false positives/negatives** — Help improve accuracy
- **Contribute threat intelligence** — Share knowledge of macOS attack patterns

---

## Development Setup

### Prerequisites

- macOS 13+ (Ventura, Sonoma, Sequoia, or Tahoe)
- Python 3.10+
- Git

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/macos-security-audit.git
cd macos-security-audit

# Run the setup script
./scripts/setup-dev.sh

# Or manually:
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

### Running the Tool Locally

```bash
# Activate virtual environment
source .venv/bin/activate

# Run the audit
python macos_security_audit.py

# Run specific categories
python macos_security_audit.py --categories encryption,firewall

# Run with sudo for privileged checks
sudo python macos_security_audit.py
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_encryption_checks.py -v

# Run tests matching a pattern
pytest -k "filevault" -v
```

### Running Linters

```bash
# Run all linters via script
./scripts/lint.sh

# Or individually:
ruff check .
ruff format --check .
mypy .
bandit -r . -c pyproject.toml
```

---

## Project Structure

```
macos-security-audit/
├── macos_security_audit.py  # CLI entry point
├── checks/                   # Security check implementations
│   ├── base.py              # Base class and registry
│   ├── types.py             # Core types (Severity, Status, CheckResult)
│   ├── encryption.py        # Encryption checks
│   ├── firewall.py          # Firewall/network checks
│   ├── system_integrity.py  # SIP, Gatekeeper, XProtect
│   ├── authentication.py    # Login and password checks
│   ├── privacy.py           # TCC permission audits
│   ├── applications.py      # App signing and entitlements
│   └── configuration.py     # System configuration checks
├── core/                     # Core infrastructure
│   ├── circuit_breaker.py   # Failure protection
│   └── injection.py         # Dependency injection
├── utils/                    # Shared utilities
│   ├── commands.py          # Subprocess helpers
│   ├── parsers.py           # Output parsing
│   └── reporting.py         # Output formatters
├── tests/                    # Test suite
├── docs/                     # Documentation
└── scripts/                  # Development scripts
```

---

## Adding a New Security Check

### 1. Choose the Right Module

Place your check in the appropriate category module under `checks/`:

| Category | Module | Examples |
|----------|--------|----------|
| Encryption | `encryption.py` | FileVault, disk encryption |
| Firewall | `firewall.py` | Firewall, sharing services |
| System Integrity | `system_integrity.py` | SIP, Gatekeeper, updates |
| Authentication | `authentication.py` | Login, passwords, sudo |
| Privacy | `privacy.py` | TCC permissions |
| Applications | `applications.py` | Signing, entitlements |
| Configuration | `configuration.py` | System settings |

### 2. Implement the Check

```python
from checks.base import SecurityCheck
from checks.types import CheckResult, Severity, Status
from utils.commands import run_command


class MyNewCheck(SecurityCheck):
    """One-line description of what this check does."""

    name = "Human-Readable Check Name"
    description = "Longer description for documentation."
    category = "category_name"  # Must match module category
    severity = Severity.MEDIUM  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    remediation = "How to fix this if it fails."
    requires_sudo = False  # Set True if elevated privileges needed
    min_version = (13, 0, 0)  # Optional: minimum macOS version

    def run(self) -> CheckResult:
        # Implement detection logic
        try:
            result = run_command(["/usr/bin/some_command"], timeout=5)
        except FileNotFoundError:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message="Required command not found",
                remediation=self.remediation,
                details={},
            )

        # Analyze output and return appropriate status
        if "secure" in result.stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="Security control is properly configured",
                remediation=self.remediation,
                details={"raw_output": result.stdout},
            )

        return CheckResult(
            check_name=self.name,
            status=Status.FAIL,
            severity=self.severity,
            message="Security control is not configured",
            remediation=self.remediation,
            details={"raw_output": result.stdout},
        )
```

### 3. Add Tests

Create tests in `tests/test_{category}_checks.py`:

```python
import pytest
from unittest.mock import patch, MagicMock
from checks.{category} import MyNewCheck
from checks.types import Status


class TestMyNewCheck:
    def test_pass_when_secure(self):
        with patch("checks.{category}.run_command") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="secure setting enabled",
                stderr=""
            )
            check = MyNewCheck()
            result = check.run()
            assert result.status == Status.PASS

    def test_fail_when_insecure(self):
        with patch("checks.{category}.run_command") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="insecure",
                stderr=""
            )
            check = MyNewCheck()
            result = check.run()
            assert result.status == Status.FAIL

    def test_error_on_missing_command(self):
        with patch("checks.{category}.run_command") as mock_run:
            mock_run.side_effect = FileNotFoundError()
            check = MyNewCheck()
            result = check.run()
            assert result.status == Status.ERROR
```

### 4. Update Documentation

Add your check to `docs/CHECKS.md`:

1. Add to the Quick Reference Table
2. Add a detailed section with rationale, detection method, and remediation

### 5. Test Manually

```bash
# Run your specific check
python macos_security_audit.py --dry-run | grep "Your Check Name"
python macos_security_audit.py 2>&1 | grep -A5 "Your Check Name"
```

---

## Code Standards

### Style

- **Formatter:** Ruff (compatible with Black)
- **Line length:** 100 characters
- **Imports:** Sorted with isort rules

### Type Hints

All code must have complete type annotations:

```python
def my_function(param: str, count: int = 0) -> Optional[List[str]]:
    ...
```

### Docstrings

Use Google-style docstrings for public functions:

```python
def complex_function(path: Path, recursive: bool = False) -> List[str]:
    """Short description of the function.

    Longer description if needed, explaining behavior,
    edge cases, or important notes.

    Args:
        path: The filesystem path to process.
        recursive: Whether to process subdirectories.

    Returns:
        List of discovered file paths.

    Raises:
        FileNotFoundError: If path doesn't exist.
    """
```

### Security Considerations

- **Never execute user input** without validation
- **Use absolute paths** for system commands (`/usr/bin/defaults`, not `defaults`)
- **Handle timeouts** for all subprocess calls
- **Sanitize outputs** before including in results
- **Avoid information disclosure** in error messages

---

## Testing Requirements

### Coverage

- Minimum 80% line coverage required
- All new checks must have corresponding tests
- Test both pass and fail conditions

### Test Types

1. **Unit tests** — Mock system commands, test logic
2. **Integration tests** — Test with real system (marked with `@pytest.mark.integration`)

### Mocking Guidelines

```python
# Good: Mock at the boundary
with patch("checks.firewall.run_command") as mock:
    mock.return_value = ...

# Bad: Mock deep internals
with patch("subprocess.Popen") as mock:  # Too low-level
    ...
```

---

## Pull Request Process

### Before Submitting

1. ✅ All tests pass: `pytest`
2. ✅ Linters pass: `./scripts/lint.sh`
3. ✅ Type checks pass: `mypy .`
4. ✅ Documentation updated if needed
5. ✅ Commit messages are clear and descriptive

### PR Template

```markdown
## Summary
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature (new security check)
- [ ] Documentation update
- [ ] Refactoring

## Testing
Describe how you tested the changes.

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Linters pass
- [ ] Manual testing performed on macOS [version]
```

### Review Process

1. Submit PR against `main` branch
2. CI checks must pass
3. At least one maintainer review required
4. Address feedback, push updates
5. Maintainer merges when approved

---

## Release Process

Releases are managed by maintainers:

1. Update `CHANGELOG.md` with release notes
2. Tag release: `git tag v1.x.x`
3. Push tag: `git push origin v1.x.x`
4. GitHub Actions builds and publishes

---

## Questions?

- **General questions:** Open a Discussion on GitHub
- **Bug reports:** Open an Issue with reproduction steps
- **Security issues:** See [SECURITY.md](SECURITY.md)

Thank you for contributing to macOS security! 🔐
