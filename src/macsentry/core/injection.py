"""Dependency injection container for OS interactions.

This module provides a clean way to inject dependencies, making all
OS-level operations mockable for testing. The real implementation
wraps actual system calls, while tests can inject mock implementations.

Usage:
    # Production code
    container = get_container()
    result = container.os.run_command(["ls", "-la"])

    # Test code
    mock_os = MockOSInterface()
    container = DependencyContainer(os_interface=mock_os)
    # Now all checks use the mock
"""
from __future__ import annotations

import logging
import plistlib
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .interfaces import CommandResult, OSInterface

logger = logging.getLogger(__name__)

# Global container instance (singleton pattern)
_container: Optional["DependencyContainer"] = None


class RealOSInterface:
    """Production implementation of OSInterface.

    This class wraps real OS operations - subprocess calls,
    file I/O, etc. It's the default implementation used in production.
    """

    def run_command(
        self,
        args: Sequence[str],
        timeout: float = 30.0,
        check: bool = False,
    ) -> CommandResult:
        """Execute a shell command."""
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,  # We handle errors ourselves
            )
            if check and result.returncode != 0:
                logger.warning(
                    "Command %s failed with code %d: %s",
                    args[0],
                    result.returncode,
                    result.stderr,
                )
            return CommandResult(
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            logger.error("Command timed out: %s", args[0])
            return CommandResult(
                stdout=exc.stdout or "" if hasattr(exc, "stdout") else "",
                stderr=exc.stderr or "" if hasattr(exc, "stderr") else "",
                returncode=-1,
                timed_out=True,
            )
        except FileNotFoundError:
            logger.error("Command not found: %s", args[0])
            return CommandResult(
                stdout="",
                stderr=f"Command not found: {args[0]}",
                returncode=-1,
                timed_out=False,
            )
        except OSError as exc:
            logger.error("OS error running %s: %s", args[0], exc)
            return CommandResult(
                stdout="",
                stderr=str(exc),
                returncode=-1,
                timed_out=False,
            )

    def read_file(self, path: Path) -> Optional[str]:
        """Read file contents as string."""
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            logger.debug("Cannot read file %s: %s", path, exc)
            return None

    def read_file_bytes(self, path: Path) -> Optional[bytes]:
        """Read file contents as bytes."""
        try:
            return path.read_bytes()
        except OSError as exc:
            logger.debug("Cannot read file %s: %s", path, exc)
            return None

    def file_exists(self, path: Path) -> bool:
        """Check if file exists."""
        return path.exists()

    def get_file_mtime(self, path: Path) -> Optional[float]:
        """Get file modification time."""
        try:
            return path.stat().st_mtime
        except OSError:
            return None

    def list_directory(self, path: Path) -> List[Path]:
        """List directory contents."""
        try:
            return list(path.iterdir())
        except OSError:
            return []

    def get_home_directory(self) -> Path:
        """Get current user's home directory."""
        return Path.home()


class MockOSInterface:
    """Mock implementation of OSInterface for testing.

    Configure responses using the mock_* methods, then inject
    this into the DependencyContainer for testing.

    Example:
        mock = MockOSInterface()
        mock.mock_command_response(
            ["fdesetup", "status"],
            CommandResult(stdout="FileVault is On.", stderr="", returncode=0)
        )
        container = DependencyContainer(os_interface=mock)
    """

    def __init__(self) -> None:
        self._command_responses: Dict[tuple, CommandResult] = {}
        self._file_contents: Dict[Path, str] = {}
        self._file_bytes: Dict[Path, bytes] = {}
        self._file_mtimes: Dict[Path, float] = {}
        self._directories: Dict[Path, List[Path]] = {}
        self._home_dir: Path = Path("/Users/testuser")
        self._default_command_response = CommandResult(
            stdout="", stderr="Command not mocked", returncode=1
        )

    def mock_command_response(
        self, args: Sequence[str], response: CommandResult
    ) -> None:
        """Set up a mock response for a command."""
        self._command_responses[tuple(args)] = response

    def mock_file_content(self, path: Path, content: str) -> None:
        """Set up mock file content."""
        self._file_contents[path] = content

    def mock_file_bytes(self, path: Path, content: bytes) -> None:
        """Set up mock file bytes."""
        self._file_bytes[path] = content

    def mock_file_mtime(self, path: Path, mtime: float) -> None:
        """Set up mock file modification time."""
        self._file_mtimes[path] = mtime

    def mock_directory(self, path: Path, contents: List[Path]) -> None:
        """Set up mock directory contents."""
        self._directories[path] = contents

    def mock_home_directory(self, path: Path) -> None:
        """Set up mock home directory."""
        self._home_dir = path

    def run_command(
        self,
        args: Sequence[str],
        timeout: float = 30.0,
        check: bool = False,
    ) -> CommandResult:
        """Return mock command response."""
        key = tuple(args)
        if key in self._command_responses:
            return self._command_responses[key]
        # Try prefix matching (for commands with variable arguments)
        for cmd_key, response in self._command_responses.items():
            if tuple(args[: len(cmd_key)]) == cmd_key:
                return response
        return self._default_command_response

    def read_file(self, path: Path) -> Optional[str]:
        """Return mock file content."""
        return self._file_contents.get(path)

    def read_file_bytes(self, path: Path) -> Optional[bytes]:
        """Return mock file bytes."""
        return self._file_bytes.get(path)

    def file_exists(self, path: Path) -> bool:
        """Check if file is mocked."""
        return path in self._file_contents or path in self._file_bytes

    def get_file_mtime(self, path: Path) -> Optional[float]:
        """Return mock file mtime."""
        return self._file_mtimes.get(path)

    def list_directory(self, path: Path) -> List[Path]:
        """Return mock directory contents."""
        return self._directories.get(path, [])

    def get_home_directory(self) -> Path:
        """Return mock home directory."""
        return self._home_dir


@dataclass
class DependencyContainer:
    """Container for all injectable dependencies.

    This is the central point for dependency injection. All code
    that needs OS access should get it through this container.

    Attributes:
        os_interface: Implementation of OSInterface to use
    """

    os_interface: OSInterface

    @property
    def os(self) -> OSInterface:
        """Shorthand accessor for OS interface."""
        return self.os_interface

    def load_plist(self, path: Path) -> Optional[Dict[str, Any]]:
        """Convenience method to load a plist file.

        Args:
            path: Path to plist file

        Returns:
            Parsed plist data, or None if unreadable
        """
        data = self.os_interface.read_file_bytes(path)
        if data is None:
            return None
        try:
            return plistlib.loads(data)
        except (plistlib.InvalidFileException, ValueError):
            return None


def get_container() -> DependencyContainer:
    """Get the global dependency container.

    Returns the singleton container instance, creating it with
    the real OS interface if it doesn't exist.

    Returns:
        The global DependencyContainer instance
    """
    global _container
    if _container is None:
        _container = DependencyContainer(os_interface=RealOSInterface())
    return _container


def set_container(container: DependencyContainer) -> None:
    """Set the global dependency container.

    Used primarily for testing to inject mock dependencies.

    Args:
        container: Container to use globally
    """
    global _container
    _container = container


def reset_container() -> None:
    """Reset the global container to None.

    Forces recreation with real OS interface on next get_container().
    Used for test cleanup.
    """
    global _container
    _container = None
