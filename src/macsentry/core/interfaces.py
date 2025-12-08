"""Abstract interfaces defining strict layer separation.

Architecture:
┌─────────────────────────────────────────────────────────────────┐
│                     DETECTION LAYER                              │
│  - Discovers system state                                        │
│  - Returns structured findings                                   │
│  - NO side effects (read-only)                                   │
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
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, TypeVar

# Type variable for generic results
T = TypeVar("T")


# =============================================================================
# OS INTERFACE - Abstraction for all OS interactions (Dependency Injection)
# =============================================================================


@dataclass
class CommandResult:
    """Result from running a shell command."""

    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False


class OSInterface(Protocol):
    """Protocol defining all OS-level interactions.

    This abstraction allows complete mocking of OS interactions for testing.
    All file I/O, subprocess calls, and system queries go through this interface.
    """

    def run_command(
        self,
        args: Sequence[str],
        timeout: float = 30.0,
        check: bool = False,
    ) -> CommandResult:
        """Execute a shell command and return results.

        Args:
            args: Command and arguments to execute
            timeout: Maximum seconds to wait
            check: If True, raise on non-zero exit

        Returns:
            CommandResult with stdout, stderr, and return code
        """
        ...

    def read_file(self, path: Path) -> Optional[str]:
        """Read file contents as string.

        Args:
            path: Path to file

        Returns:
            File contents or None if unreadable
        """
        ...

    def read_file_bytes(self, path: Path) -> Optional[bytes]:
        """Read file contents as bytes.

        Args:
            path: Path to file

        Returns:
            File contents or None if unreadable
        """
        ...

    def file_exists(self, path: Path) -> bool:
        """Check if file exists.

        Args:
            path: Path to check

        Returns:
            True if file exists
        """
        ...

    def get_file_mtime(self, path: Path) -> Optional[float]:
        """Get file modification time.

        Args:
            path: Path to file

        Returns:
            Modification time as timestamp, or None if unavailable
        """
        ...

    def list_directory(self, path: Path) -> List[Path]:
        """List directory contents.

        Args:
            path: Directory path

        Returns:
            List of paths in directory
        """
        ...

    def get_home_directory(self) -> Path:
        """Get current user's home directory."""
        ...


# =============================================================================
# DETECTION LAYER - Read-only system state discovery
# =============================================================================


@dataclass
class Finding:
    """A single security finding from detection.

    Findings are immutable results from detection - they describe
    what was found, not what to do about it.
    """

    check_id: str
    check_name: str
    passed: bool
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    skipped: bool = False
    skip_reason: Optional[str] = None


class DetectionLayer(ABC):
    """Abstract base for detection operations.

    Detection is strictly read-only - it discovers and reports
    system state without making any changes.
    """

    @property
    @abstractmethod
    def check_id(self) -> str:
        """Unique identifier for this check."""
        ...

    @property
    @abstractmethod
    def check_name(self) -> str:
        """Human-readable name for this check."""
        ...

    @property
    @abstractmethod
    def severity(self) -> str:
        """Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO."""
        ...

    @property
    @abstractmethod
    def category(self) -> str:
        """Category this check belongs to."""
        ...

    @abstractmethod
    def detect(self, os_interface: OSInterface) -> Finding:
        """Run detection and return finding.

        This method MUST be read-only - no side effects allowed.

        Args:
            os_interface: Injected OS interface for all system access

        Returns:
            Finding describing the detected state
        """
        ...


# =============================================================================
# REPORTING LAYER - Formats and presents findings
# =============================================================================


@dataclass
class Report:
    """A formatted security report."""

    findings: List[Finding]
    summary: Dict[str, Any]
    generated_at: str
    system_info: Dict[str, str]
    format_type: str  # text, json, html


class ReportingLayer(ABC):
    """Abstract base for reporting operations.

    Reporting takes findings and formats them for output.
    It does not modify findings or system state.
    """

    @abstractmethod
    def generate(
        self,
        findings: Iterable[Finding],
        system_info: Dict[str, str],
    ) -> Report:
        """Generate a report from findings.

        Args:
            findings: Detection results to report
            system_info: System metadata to include

        Returns:
            Formatted report
        """
        ...

    @abstractmethod
    def render(self, report: Report) -> str:
        """Render report to output format.

        Args:
            report: Report to render

        Returns:
            Rendered string (text, JSON, or HTML)
        """
        ...


# =============================================================================
# REMEDIATION LAYER - Future: applies fixes (requires consent)
# =============================================================================


@dataclass
class RemediationAction:
    """A proposed remediation action."""

    finding: Finding
    action_id: str
    description: str
    command: Optional[str] = None
    manual_steps: Optional[str] = None
    requires_sudo: bool = False
    requires_reboot: bool = False
    reversible: bool = True


@dataclass
class RemediationResult:
    """Result of applying a remediation."""

    action: RemediationAction
    success: bool
    message: str
    changes_made: List[str] = field(default_factory=list)
    rollback_available: bool = False


class RemediationLayer(ABC):
    """Abstract base for remediation operations (Future).

    Remediation applies fixes based on detection findings.
    It ALWAYS requires explicit user consent before making changes.
    """

    @abstractmethod
    def plan(self, finding: Finding) -> Optional[RemediationAction]:
        """Plan remediation for a finding.

        Args:
            finding: The finding to remediate

        Returns:
            Proposed action, or None if no remediation available
        """
        ...

    @abstractmethod
    def apply(
        self,
        action: RemediationAction,
        os_interface: OSInterface,
        dry_run: bool = True,
    ) -> RemediationResult:
        """Apply a remediation action.

        Args:
            action: The action to apply
            os_interface: Injected OS interface
            dry_run: If True, simulate without making changes

        Returns:
            Result of the remediation attempt
        """
        ...

    @abstractmethod
    def rollback(
        self,
        result: RemediationResult,
        os_interface: OSInterface,
    ) -> bool:
        """Roll back a remediation if possible.

        Args:
            result: The remediation result to roll back
            os_interface: Injected OS interface

        Returns:
            True if rollback succeeded
        """
        ...
