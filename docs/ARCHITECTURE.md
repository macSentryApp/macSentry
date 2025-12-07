# Architecture Guide

This document describes the internal architecture of macOS Security Audit for contributors and developers.

---

## Table of Contents

- [Design Principles](#design-principles)
- [Layer Architecture](#layer-architecture)
- [Module Structure](#module-structure)
- [Core Components](#core-components)
- [Check Implementation](#check-implementation)
- [Dependency Injection](#dependency-injection)
- [Resilience Patterns](#resilience-patterns)
- [Testing Strategy](#testing-strategy)
- [Adding New Checks](#adding-new-checks)

---

## Design Principles

### 1. No External Dependencies
The tool uses only Python standard library and built-in macOS commands. This ensures:
- Easy deployment without package management
- No supply chain vulnerabilities
- Compatibility across Python versions 3.10+

### 2. Graceful Degradation
Individual check failures never crash the entire audit:
- All exceptions are caught and reported
- Timeouts are enforced on all operations
- Circuit breakers protect against repeated failures

### 3. Minimal Privileges
Most checks run without sudo:
- Only 5 checks require elevated privileges
- Checks gracefully skip when privileges are insufficient
- Clear indication of which checks need elevation

### 4. Strict Layer Separation
Three distinct layers with clear responsibilities:
```
┌─────────────────────────────────────────────────────────────────┐
│                     DETECTION LAYER                              │
│  - Discovers system state (read-only)                            │
│  - Returns structured findings                                   │
│  - NO side effects                                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     REPORTING LAYER                              │
│  - Formats detection results                                     │
│  - Multiple output formats (text, JSON, HTML)                    │
│  - Severity aggregation and filtering                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   REMEDIATION LAYER (Future)                     │
│  - Applies fixes based on detection findings                     │
│  - Requires explicit user consent                                │
│  - Maintains audit trail                                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Layer Architecture

### Detection Layer (`checks/`)

The detection layer is strictly **read-only**. Each check:
- Queries system state via macOS commands or file reads
- Returns a `CheckResult` with status, severity, and details
- Never modifies system configuration

```python
class SecurityCheck(metaclass=SecurityCheckMeta):
    """Base class for all security checks."""
    
    name: str = ""
    description: str = ""
    category: str = "general"
    severity: Severity = Severity.INFO
    remediation: str = "Review system configuration."
    requires_sudo: bool = False
    min_version: Optional[Tuple[int, int, int]] = None
    timeout: int = 5
    
    @abstractmethod
    def run(self) -> CheckResult:
        """Execute the security check."""
```

### Reporting Layer (`utils/reporting.py`)

The reporting layer transforms findings into human-readable or machine-parseable output:

- **Text**: Console-friendly with color coding
- **JSON**: Structured for automation and integration
- **HTML**: Visual reports for sharing

### Remediation Layer (Future: `core/interfaces.py`)

Planned for future implementation:
- Proposes fixes based on findings
- Requires explicit user consent before changes
- Provides rollback capability

---

## Module Structure

```
macos-security-audit/
├── macos_security_audit.py      # Entry point and CLI
│
├── checks/                       # Detection layer
│   ├── __init__.py              # Check loader
│   ├── base.py                  # SecurityCheck base class, registry
│   ├── types.py                 # Shared types (CheckResult, Severity, Status)
│   ├── encryption.py            # FileVault, disk encryption
│   ├── firewall.py              # Network security checks
│   ├── system_integrity.py      # SIP, Gatekeeper, updates
│   ├── authentication.py        # Login, password, sudo
│   ├── privacy.py               # TCC permissions
│   ├── applications.py          # Code signing, entitlements
│   └── configuration.py         # Hardware security, backups
│
├── core/                         # Architectural components
│   ├── __init__.py
│   ├── interfaces.py            # Abstract layer definitions
│   ├── injection.py             # Dependency injection container
│   ├── circuit_breaker.py       # Failure protection pattern
│   └── resilience.py            # Graceful degradation utilities
│
├── utils/                        # Shared utilities
│   ├── __init__.py
│   ├── commands.py              # Safe command execution
│   ├── parsers.py               # Output parsing (plist, defaults)
│   ├── compat.py                # Python version compatibility
│   └── reporting.py             # Output formatters
│
└── tests/                        # Test suite
    ├── conftest.py              # Shared fixtures
    └── test_*.py                # Unit tests
```

---

## Core Components

### Check Registry (`checks/base.py`)

Automatic registration of security checks via metaclass:

```python
class CheckRegistry:
    """Registry for all security checks."""
    
    _registry: ClassVar[Dict[str, Type[SecurityCheck]]] = {}
    
    @classmethod
    def register(cls, check_cls: Type[SecurityCheck]) -> None:
        """Register a check class by name."""
        
    @classmethod
    def get_all(cls) -> Iterable[Type[SecurityCheck]]:
        """Get all registered checks."""
        
    @classmethod
    def by_category(cls, categories: Iterable[str]) -> Iterable[Type[SecurityCheck]]:
        """Filter checks by category."""
```

Checks are auto-registered when their module is imported:

```python
class SecurityCheckMeta(abc.ABCMeta):
    """Metaclass that auto-registers concrete security checks."""
    
    def __new__(mcls, name, bases, namespace):
        cls = super().__new__(mcls, name, bases, namespace)
        if not inspect_is_abstract(cls):
            CheckRegistry.register(cls)
        return cls
```

### Check Result Types (`checks/types.py`)

```python
class Status(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    SKIP = "skip"
    ERROR = "error"

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class CheckResult:
    check_name: str
    status: Status
    severity: Severity
    message: str
    remediation: str
    details: Dict[str, Any] = field(default_factory=dict)
```

---

## Dependency Injection

The `core/injection.py` module provides complete OS abstraction:

### OSInterface Protocol

```python
class OSInterface(Protocol):
    """Protocol defining all OS-level interactions."""
    
    def run_command(self, args: Sequence[str], timeout: float) -> CommandResult: ...
    def read_file(self, path: Path) -> Optional[str]: ...
    def read_file_bytes(self, path: Path) -> Optional[bytes]: ...
    def file_exists(self, path: Path) -> bool: ...
    def get_file_mtime(self, path: Path) -> Optional[float]: ...
    def list_directory(self, path: Path) -> List[Path]: ...
    def get_home_directory(self) -> Path: ...
```

### Production Implementation

```python
class RealOSInterface:
    """Production implementation wrapping real OS calls."""
    
    def run_command(self, args, timeout=30.0, check=False):
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return CommandResult(stdout=result.stdout, stderr=result.stderr, ...)
```

### Mock Implementation for Testing

```python
class MockOSInterface:
    """Mock for testing without real OS calls."""
    
    def mock_command_response(self, args: Sequence[str], response: CommandResult):
        """Set up expected command output."""
        
    def mock_file_content(self, path: Path, content: str):
        """Set up mock file content."""
```

### Container Usage

```python
# Production
container = get_container()  # Returns RealOSInterface

# Testing
mock_os = MockOSInterface()
mock_os.mock_command_response(["fdesetup", "status"], 
    CommandResult(stdout="FileVault is On.", returncode=0))
container = DependencyContainer(os_interface=mock_os)
set_container(container)
```

---

## Resilience Patterns

### Circuit Breaker (`core/circuit_breaker.py`)

Protects against repeated failures:

```python
breaker = CircuitBreaker(
    failure_threshold=3,    # Open after 3 consecutive failures
    reset_timeout=60.0,     # Wait 60s before testing recovery
    success_threshold=1,    # Close after 1 success in half-open
)

if breaker.can_execute("filevault_check"):
    try:
        result = run_check()
        breaker.record_success("filevault_check")
    except Exception:
        breaker.record_failure("filevault_check")
else:
    # Circuit is open, skip this check
    pass
```

**States:**
- **CLOSED**: Normal operation
- **OPEN**: Rejecting requests (too many failures)
- **HALF_OPEN**: Testing if issue resolved

### Graceful Degradation (`core/resilience.py`)

Decorators for error handling:

```python
@with_graceful_degradation(default_return=None, log_errors=True)
def risky_operation():
    # Exceptions caught, logged, and default returned
    pass

@with_timeout(timeout_seconds=5.0, default_return=None)
def slow_operation():
    # Returns None if not completed in 5 seconds
    pass
```

### Check Executor

Combines all resilience patterns:

```python
executor = CheckExecutor(
    config=ExecutorConfig(
        check_timeout=30.0,
        parallel=True,
        max_workers=4,
        use_circuit_breaker=True,
    )
)

results = executor.execute_all(checks)
# All checks attempted, failures captured in results
```

---

## Testing Strategy

### Test Organization

```
tests/
├── conftest.py                    # Shared fixtures
├── test_encryption_checks.py      # Encryption check tests
├── test_firewall_checks.py        # Firewall check tests
├── test_command_execution.py      # Command utility tests
└── ...
```

### Fixtures (`conftest.py`)

```python
@pytest.fixture
def mock_os():
    """Provide a fresh MockOSInterface."""
    return MockOSInterface()

@pytest.fixture
def container(mock_os):
    """Provide container with mock OS."""
    return DependencyContainer(os_interface=mock_os)
```

### Testing Checks

```python
def test_filevault_enabled(mock_os, container):
    """Test FileVault check when enabled."""
    mock_os.mock_command_response(
        ["fdesetup", "status"],
        CommandResult(stdout="FileVault is On.", stderr="", returncode=0)
    )
    
    check = FileVaultStatusCheck()
    result = check.run()
    
    assert result.status == Status.PASS
    assert "enabled" in result.message.lower()
```

### Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=checks --cov=utils --cov-report=html

# Specific test file
pytest tests/test_encryption_checks.py -v
```

---

## Adding New Checks

### Step 1: Create Check Class

```python
# In checks/your_category.py

class YourNewCheck(SecurityCheck):
    """Brief description of what this checks."""
    
    name = "Your Check Name"
    description = "Detailed description of the check."
    category = "your_category"  # encryption, firewall, system_integrity, etc.
    severity = Severity.MEDIUM
    remediation = "Instructions for fixing the issue."
    requires_sudo = False  # Set True if needs elevation
    min_version = (13, 0, 0)  # Optional: minimum macOS version
    
    def run(self) -> CheckResult:
        # 1. Query system state
        try:
            result = commands.run_command([...], timeout=5)
        except Exception as exc:
            return CheckResult(
                check_name=self.name,
                status=Status.ERROR,
                severity=self.severity,
                message=str(exc),
                remediation=self.remediation,
            )
        
        # 2. Analyze result
        if "expected_good_value" in result.stdout:
            return CheckResult(
                check_name=self.name,
                status=Status.PASS,
                severity=self.severity,
                message="Check passed",
                remediation=self.remediation,
            )
        
        return CheckResult(
            check_name=self.name,
            status=Status.FAIL,
            severity=self.severity,
            message="Check failed",
            remediation=self.remediation,
            details={"raw_output": result.stdout},
        )
```

### Step 2: Add Tests

```python
# In tests/test_your_category_checks.py

class TestYourNewCheck:
    def test_check_passes(self, mock_os):
        mock_os.mock_command_response(
            [...],
            CommandResult(stdout="expected_good_value", returncode=0)
        )
        
        check = YourNewCheck()
        result = check.run()
        
        assert result.status == Status.PASS
    
    def test_check_fails(self, mock_os):
        mock_os.mock_command_response(
            [...],
            CommandResult(stdout="bad_value", returncode=0)
        )
        
        check = YourNewCheck()
        result = check.run()
        
        assert result.status == Status.FAIL
```

### Step 3: Document Check

Add entry to `docs/CHECKS.md`:

```markdown
### Your Check Name

| Property | Value |
|----------|-------|
| **Check Name** | `Your Check Name` |
| **Category** | your_category |
| **Severity** | MEDIUM |
| **Requires Sudo** | No |

**Rationale:**
Why this check matters for security.

**What It Checks:**
Technical details of detection methodology.

**Remediation:**
Step-by-step fix instructions.
```

### Step 4: Update README

Add to the Check Reference table in `README.md`:

```markdown
| Your Check Name | your_category | MEDIUM | No |
```

---

## Code Quality Standards

### Type Hints

All code must be fully typed (mypy strict mode):

```python
def run_command(args: Sequence[str], timeout: float = 5.0) -> CommandResult:
    ...
```

### Docstrings

All public functions need docstrings:

```python
def run_command(args: Sequence[str], timeout: float = 5.0) -> CommandResult:
    """Execute a shell command safely.
    
    Args:
        args: Command and arguments
        timeout: Maximum seconds to wait
        
    Returns:
        CommandResult with stdout, stderr, and return code
        
    Raises:
        CommandExecutionError: If command fails and check=True
    """
```

### Complexity Limits

- Maximum cyclomatic complexity: 10 per function
- Maximum function length: 50 statements
- Maximum arguments: 7

### Pre-commit Hooks

Always run before committing:

```bash
pre-commit run --all-files
```

---

## Common Patterns

### Safe Command Execution

```python
from utils.commands import run_command, CommandExecutionError

try:
    result = run_command(["/usr/bin/tool", "arg"], timeout=5)
    if result.returncode == 0:
        # Process stdout
        pass
except FileNotFoundError:
    # Tool not installed
    pass
except TimeoutExpired:
    # Command took too long
    pass
except CommandExecutionError as exc:
    # Command failed with non-zero exit
    pass
```

### Plist Parsing

```python
from utils.parsers import load_plist

plist = load_plist(Path("/path/to/file.plist"))
if plist is None:
    # File not found or parse error
    pass
else:
    value = plist.get("key", default)
```

### Defaults Reading

```python
result = run_command([
    "/usr/bin/defaults", "read", 
    "/Library/Preferences/com.apple.something",
    "SomeKey"
])

from utils.parsers import parse_defaults_bool
enabled = parse_defaults_bool(result.stdout)  # Returns bool or None
```

---

## Performance Considerations

### Parallel Execution

Checks run in parallel by default (8 workers max):

```python
with ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 4)) as executor:
    futures = {executor.submit(check.execute): check for check in checks}
```

### Timeouts

All external operations have timeouts:
- Default check timeout: 5 seconds
- Software update check: 30 seconds
- Maximum per-check: configurable

### Application Scanning Limits

Application checks scan max 25 apps to prevent long runtimes:

```python
_MAX_APPS_TO_SCAN = 25
```

---

## Security Considerations

### Input Validation

All command arguments are passed as lists (no shell injection):

```python
# Safe - arguments are separate
run_command(["/usr/bin/tool", user_input])

# NEVER do this
run_command(f"/usr/bin/tool {user_input}", shell=True)  # Dangerous!
```

### No Secrets in Code

- API keys and secrets must use environment variables
- Bandit scans for hardcoded secrets

### Read-Only Operations

Detection checks must never:
- Write files
- Modify system configuration
- Execute system modification commands
- Store persistent state

---

## Getting Help

- **Issues**: GitHub issue tracker
- **Discussions**: GitHub discussions
- **Security Issues**: security@yourproject.com (do not file public issues)
