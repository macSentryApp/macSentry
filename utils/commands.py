"""Secure command execution utilities for macOS security audit."""
from __future__ import annotations

import logging
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence, Tuple, TypeVar

# Python 3.9 compatible dataclass
if sys.version_info >= (3, 10):
    from dataclasses import dataclass, field
else:
    from dataclasses import dataclass as _dataclass, field

    def dataclass(*args: Any, **kwargs: Any):
        kwargs.pop("slots", None)
        return _dataclass(*args, **kwargs)

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 5
_DISK_OPERATION_TIMEOUT = 30  # Increased for slower Macs/SSDs

# Commands known to be slow on certain hardware
SLOW_COMMANDS = {
    "/usr/sbin/diskutil": _DISK_OPERATION_TIMEOUT,
    "/usr/bin/tmutil": 20,
    "/usr/sbin/system_profiler": 15,
}

class CommandExecutionError(RuntimeError):
    """Raised when a command cannot be executed or exits with error."""

    def __init__(
        self,
        command: Sequence[str],
        stdout: str,
        stderr: str,
        returncode: int,
    ) -> None:
        super().__init__(
            f"Command '{' '.join(command)}' failed with code {returncode}: {stderr.strip()}"
        )
        self.command = list(command)
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class CommandTimeoutError(RuntimeError):
    """Raised when a command times out with additional context."""

    def __init__(
        self,
        command: Sequence[str],
        timeout: int,
        suggestion: str = "",
    ) -> None:
        cmd_str = " ".join(shlex.quote(arg) for arg in command)
        message = f"Command timed out after {timeout}s: {cmd_str}"
        if suggestion:
            message += f"\nSuggestion: {suggestion}"
        super().__init__(message)
        self.command = list(command)
        self.timeout = timeout
        self.suggestion = suggestion
        self.cmd_str = cmd_str

    def __str__(self) -> str:
        return f"Command '{self.command[0]}' timed out after {self.timeout}s"

    def detailed_message(self) -> str:
        """Get detailed error message with suggestions."""
        lines = [
            f"Command timed out: {self.cmd_str}",
            f"Timeout: {self.timeout} seconds",
        ]
        if self.suggestion:
            lines.append(f"Suggestion: {self.suggestion}")
        return "\n".join(lines)


@dataclass(slots=True)
class CommandResult:
    """Container for command outputs."""

    stdout: str
    stderr: str
    returncode: int
    elapsed_time: float = 0.0  # Execution time in seconds
    command: Sequence[str] = field(default_factory=list)

    def to_tuple(self) -> Tuple[str, str, int]:
        return self.stdout, self.stderr, self.returncode

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for reporting."""
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "returncode": self.returncode,
            "elapsed_time": self.elapsed_time,
            "command": list(self.command),
        }


def get_suggested_timeout(command: Sequence[str]) -> int:
    """Get suggested timeout for a command based on known slow commands."""
    if not command:
        return _DEFAULT_TIMEOUT
    cmd_path = command[0]
    return SLOW_COMMANDS.get(cmd_path, _DEFAULT_TIMEOUT)


def get_timeout_suggestion(command: Sequence[str]) -> str:
    """Get a helpful suggestion for timeout errors based on the command."""
    if not command:
        return ""
    
    cmd = command[0]
    suggestions = {
        "/usr/sbin/diskutil": (
            "Disk operations can be slow on external/network drives. "
            "Check if any external or network volumes are mounted. "
            "Try disconnecting external drives and retry."
        ),
        "/usr/bin/tmutil": (
            "Time Machine queries can be slow if backup volumes are not mounted. "
            "Ensure Time Machine drive is connected or skip this check."
        ),
        "/usr/sbin/system_profiler": (
            "System profiler can be slow on older hardware. "
            "This is usually a one-time delay."
        ),
    }
    return suggestions.get(cmd, "")


def run_command(
    command: Sequence[str],
    *,
    timeout: int | None = None,
    check: bool = False,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    raise_on_timeout: bool = True,
) -> CommandResult:
    """Execute a system command safely.

    Args:
        command: Command with arguments.
        timeout: Timeout in seconds. If None, auto-selects based on command.
        check: Raise CommandExecutionError on non-zero exit.
        cwd: Working directory.
        env: Additional environment variables.
        raise_on_timeout: If False, return empty result instead of raising.

    Returns:
        CommandResult with stdout, stderr, return code, and timing.

    Raises:
        CommandTimeoutError: If the command exceeds timeout (and raise_on_timeout=True).
        FileNotFoundError: If the command cannot be located.
        CommandExecutionError: When check=True and command fails.
    """
    if not command:
        raise ValueError("Command cannot be empty")

    # Auto-select timeout if not specified
    if timeout is None:
        timeout = get_suggested_timeout(command)

    start_time = time.perf_counter()
    cmd_str = " ".join(shlex.quote(arg) for arg in command)
    
    try:
        logger.debug("Running command (timeout=%ds): %s", timeout, cmd_str)
        completed = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=str(cwd) if cwd else None,
            env=env,
        )
        elapsed = time.perf_counter() - start_time
        
    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - start_time
        suggestion = get_timeout_suggestion(command)
        logger.error(
            "Command timed out after %.1fs (limit: %ds): %s",
            elapsed, timeout, cmd_str
        )
        if raise_on_timeout:
            raise CommandTimeoutError(command, timeout, suggestion)
        # Return empty result for graceful degradation
        return CommandResult(
            stdout="",
            stderr=f"Command timed out after {timeout}s",
            returncode=-1,
            elapsed_time=elapsed,
            command=list(command),
        )
        
    except FileNotFoundError:
        logger.error("Command not found: %s", command[0])
        raise

    result = CommandResult(
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
        returncode=completed.returncode,
        elapsed_time=time.perf_counter() - start_time,
        command=list(command),
    )
    
    # Log slow commands for debugging
    if result.elapsed_time > 5:
        logger.info(
            "Slow command (%.1fs): %s", result.elapsed_time, command[0]
        )

    if check and completed.returncode != 0:
        logger.warning(
            "Command exited with non-zero code %s: %s", completed.returncode, command
        )
        raise CommandExecutionError(command, result.stdout, result.stderr, completed.returncode)

    return result


def run_command_graceful(
    command: Sequence[str],
    *,
    timeout: int | None = None,
    default_stdout: str = "",
    default_returncode: int = -1,
) -> CommandResult:
    """Execute a command with graceful fallback on any error.
    
    This is useful for non-critical operations where failure should not
    stop the entire check.
    
    Args:
        command: Command with arguments.
        timeout: Timeout in seconds.
        default_stdout: Default stdout if command fails.
        default_returncode: Default return code if command fails.
    
    Returns:
        CommandResult, never raises exceptions.
    """
    try:
        return run_command(command, timeout=timeout, raise_on_timeout=False)
    except (FileNotFoundError, OSError) as exc:
        logger.debug("Command failed gracefully: %s - %s", command[0], exc)
        return CommandResult(
            stdout=default_stdout,
            stderr=str(exc),
            returncode=default_returncode,
            elapsed_time=0.0,
            command=list(command),
        )


def which(executable: str) -> str | None:
    """Return full path for executable if available."""

    if not executable:
        raise ValueError("Executable name cannot be empty")
    path = shutil.which(executable)
    if path:
        logger.debug("Found executable %s at %s", executable, path)
    else:
        logger.debug("Executable %s not found", executable)
    return path


def run_first_available(
    commands: Iterable[Sequence[str]],
    *,
    timeout: int = _DEFAULT_TIMEOUT,
    check: bool = False,
) -> CommandResult:
    """Run the first command that exists in the system."""

    for cmd in commands:
        if which(cmd[0]):
            return run_command(cmd, timeout=timeout, check=check)
    raise FileNotFoundError("No runnable command found in provided list")


def get_console_user() -> Tuple[str, int]:
    """Get the currently logged-in console user.
    
    Returns:
        Tuple of (username, uid). Returns ("", 0) if unable to determine.
    """
    try:
        # Use scutil to get the console user - most reliable method
        result = subprocess.run(
            ["/usr/sbin/scutil"],
            input="show State:/Users/ConsoleUser\n",
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "Name :" in line:
                    username = line.split(":")[-1].strip()
                    if username and username != "loginwindow":
                        # Get UID for this user
                        uid_result = subprocess.run(
                            ["/usr/bin/id", "-u", username],
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        if uid_result.returncode == 0:
                            return (username, int(uid_result.stdout.strip()))
    except (subprocess.TimeoutExpired, ValueError, OSError) as exc:
        logger.debug("Could not get console user: %s", exc)
    
    # Fallback: check SUDO_USER environment variable
    import os
    sudo_user = os.environ.get("SUDO_USER", "")
    if sudo_user:
        try:
            uid_result = subprocess.run(
                ["/usr/bin/id", "-u", sudo_user],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if uid_result.returncode == 0:
                return (sudo_user, int(uid_result.stdout.strip()))
        except (subprocess.TimeoutExpired, ValueError, OSError):
            pass
    
    return ("", 0)


def run_defaults_for_user(
    domain: str,
    key: str,
    *,
    current_host: bool = False,
    timeout: int = _DEFAULT_TIMEOUT,
) -> CommandResult:
    """Run defaults read command for the console user, even when running as root.
    
    When running as root/sudo, defaults normally reads root's preferences.
    This function ensures we read the actual logged-in user's preferences.
    
    Args:
        domain: The defaults domain (e.g., "com.apple.sharingd")
        key: The preference key to read
        current_host: If True, use -currentHost flag
        timeout: Command timeout in seconds
    
    Returns:
        CommandResult from the defaults command
    """
    import os
    
    # Check if we're running as root
    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    
    if is_root:
        username, uid = get_console_user()
        if username and uid > 0:
            # Run defaults as the console user using su or launchctl
            # Method 1: Use su to run as the user
            cmd_args = ["/usr/bin/defaults"]
            if current_host:
                cmd_args.extend(["-currentHost"])
            cmd_args.extend(["read", domain, key])
            
            full_cmd = ["/usr/bin/su", username, "-c", " ".join(shlex.quote(arg) for arg in cmd_args)]
            logger.debug("Running defaults as user %s: %s", username, full_cmd)
            return run_command(full_cmd, timeout=timeout, raise_on_timeout=False)
    
    # Not root, or couldn't determine console user - run normally
    cmd = ["/usr/bin/defaults"]
    if current_host:
        cmd.extend(["-currentHost"])
    cmd.extend(["read", domain, key])
    return run_command(cmd, timeout=timeout, raise_on_timeout=False)
