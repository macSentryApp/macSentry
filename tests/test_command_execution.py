"""Unit tests for command execution utilities."""
from __future__ import annotations

import subprocess
import sys
import pytest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from macsentry.utils.commands import (
    CommandExecutionError,
    CommandResult,
    run_command,
    which,
    run_first_available,
)


class TestRunCommand:
    """Tests for run_command function."""

    @patch("utils.commands.subprocess.run")
    def test_run_command_success(self, mock_run: MagicMock) -> None:
        """Test successful command execution."""
        mock_run.return_value = SimpleNamespace(
            stdout="output\n",
            stderr="",
            returncode=0,
        )

        result = run_command(["/usr/bin/true"], timeout=2)
        
        assert result.stdout == "output"
        assert result.stderr == ""
        assert result.returncode == 0
        mock_run.assert_called_once()

    @patch("utils.commands.subprocess.run")
    def test_run_command_strips_whitespace(self, mock_run: MagicMock) -> None:
        """Test that stdout/stderr are stripped."""
        mock_run.return_value = SimpleNamespace(
            stdout="  output  \n\n",
            stderr="  error  \n",
            returncode=0,
        )

        result = run_command(["/usr/bin/echo"], timeout=2)
        
        assert result.stdout == "output"
        assert result.stderr == "error"

    @patch("utils.commands.subprocess.run")
    def test_run_command_non_zero_without_check(self, mock_run: MagicMock) -> None:
        """Test non-zero exit without check=True returns result."""
        mock_run.return_value = SimpleNamespace(
            stdout="",
            stderr="failure",
            returncode=1,
        )

        result = run_command(["/usr/bin/false"], timeout=2, check=False)
        
        assert result.returncode == 1
        assert result.stderr == "failure"

    @patch("utils.commands.subprocess.run")
    def test_run_command_non_zero_with_check_raises(self, mock_run: MagicMock) -> None:
        """Test non-zero exit with check=True raises CommandExecutionError."""
        mock_run.return_value = SimpleNamespace(
            stdout="",
            stderr="failure",
            returncode=23,
        )

        with pytest.raises(CommandExecutionError) as exc_info:
            run_command(["/usr/bin/false"], timeout=2, check=True)

        assert "failed with code 23" in str(exc_info.value)
        assert exc_info.value.returncode == 23
        assert exc_info.value.stderr == "failure"

    @patch("utils.commands.subprocess.run")
    def test_run_command_timeout_propagates(self, mock_run: MagicMock) -> None:
        """Test TimeoutExpired is propagated."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["sleep", "10"], timeout=1)

        with pytest.raises(subprocess.TimeoutExpired):
            run_command(["sleep", "10"], timeout=1)

    @patch("utils.commands.subprocess.run")
    def test_run_command_missing_binary(self, mock_run: MagicMock) -> None:
        """Test FileNotFoundError is propagated."""
        mock_run.side_effect = FileNotFoundError()

        with pytest.raises(FileNotFoundError):
            run_command(["/path/to/missing"], timeout=1)

    def test_run_command_empty_command_raises(self) -> None:
        """Test empty command raises ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            run_command([], timeout=1)

    @patch("utils.commands.subprocess.run")
    def test_run_command_with_cwd(self, mock_run: MagicMock) -> None:
        """Test command execution with working directory."""
        mock_run.return_value = SimpleNamespace(
            stdout="output",
            stderr="",
            returncode=0,
        )
        cwd = Path("/tmp")

        run_command(["ls"], timeout=2, cwd=cwd)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["cwd"] == "/tmp"

    @patch("utils.commands.subprocess.run")
    def test_run_command_with_env(self, mock_run: MagicMock) -> None:
        """Test command execution with custom environment."""
        mock_run.return_value = SimpleNamespace(
            stdout="output",
            stderr="",
            returncode=0,
        )
        env = {"MY_VAR": "value"}

        run_command(["echo"], timeout=2, env=env)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["env"] == env


class TestCommandResult:
    """Tests for CommandResult dataclass."""

    def test_create_command_result(self) -> None:
        """Test creating CommandResult."""
        result = CommandResult(stdout="out", stderr="err", returncode=0)
        
        assert result.stdout == "out"
        assert result.stderr == "err"
        assert result.returncode == 0

    def test_to_tuple(self) -> None:
        """Test to_tuple method."""
        result = CommandResult(stdout="out", stderr="err", returncode=42)
        
        tup = result.to_tuple()
        
        assert tup == ("out", "err", 42)


class TestCommandExecutionError:
    """Tests for CommandExecutionError exception."""

    def test_error_attributes(self) -> None:
        """Test exception attributes are set correctly."""
        error = CommandExecutionError(
            command=["cmd", "arg1", "arg2"],
            stdout="output",
            stderr="error message",
            returncode=127,
        )
        
        assert error.command == ["cmd", "arg1", "arg2"]
        assert error.stdout == "output"
        assert error.stderr == "error message"
        assert error.returncode == 127

    def test_error_message(self) -> None:
        """Test exception message format."""
        error = CommandExecutionError(
            command=["failed_cmd"],
            stdout="",
            stderr="permission denied",
            returncode=1,
        )
        
        message = str(error)
        assert "failed_cmd" in message
        assert "failed with code 1" in message
        assert "permission denied" in message


class TestWhich:
    """Tests for which function."""

    def test_which_finds_existing(self) -> None:
        """Test which finds existing executables."""
        # /bin/ls should exist on all systems
        result = which("ls")
        assert result is not None
        assert "ls" in result

    def test_which_returns_none_for_missing(self) -> None:
        """Test which returns None for missing executables."""
        result = which("definitely_not_a_real_command_12345")
        assert result is None

    def test_which_empty_raises(self) -> None:
        """Test which raises for empty executable name."""
        with pytest.raises(ValueError, match="cannot be empty"):
            which("")


class TestRunFirstAvailable:
    """Tests for run_first_available function."""

    @patch("utils.commands.which")
    @patch("utils.commands.run_command")
    def test_runs_first_available(self, mock_run, mock_which) -> None:
        """Test runs first available command."""
        mock_which.side_effect = [None, "/usr/bin/second"]
        mock_run.return_value = CommandResult("output", "", 0)

        commands = [
            ["/missing/first"],
            ["/usr/bin/second", "arg"],
        ]
        result = run_first_available(commands)

        assert result.stdout == "output"
        mock_run.assert_called_once_with(
            ["/usr/bin/second", "arg"],
            timeout=5,
            check=False,
        )

    @patch("utils.commands.which")
    def test_raises_when_none_available(self, mock_which) -> None:
        """Test raises FileNotFoundError when no command available."""
        mock_which.return_value = None

        commands = [
            ["/missing/first"],
            ["/missing/second"],
        ]
        
        with pytest.raises(FileNotFoundError, match="No runnable command"):
            run_first_available(commands)

    @patch("utils.commands.which")
    @patch("utils.commands.run_command")
    def test_respects_timeout_and_check(self, mock_run, mock_which) -> None:
        """Test timeout and check parameters are passed through."""
        mock_which.return_value = "/usr/bin/cmd"
        mock_run.return_value = CommandResult("", "", 0)

        run_first_available([["/usr/bin/cmd"]], timeout=10, check=True)

        mock_run.assert_called_once_with(
            ["/usr/bin/cmd"],
            timeout=10,
            check=True,
        )


class TestCommandExecutionEdgeCases:
    """Edge case tests for command execution."""

    @patch("utils.commands.subprocess.run")
    def test_handles_unicode_output(self, mock_run) -> None:
        """Test handling of unicode in output."""
        mock_run.return_value = SimpleNamespace(
            stdout="Héllo Wörld 你好",
            stderr="",
            returncode=0,
        )

        result = run_command(["echo"], timeout=2)
        
        assert "Héllo" in result.stdout
        assert "你好" in result.stdout

    @patch("utils.commands.subprocess.run")
    def test_handles_multiline_output(self, mock_run) -> None:
        """Test handling of multiline output."""
        mock_run.return_value = SimpleNamespace(
            stdout="line1\nline2\nline3\n",
            stderr="",
            returncode=0,
        )

        result = run_command(["cat"], timeout=2)
        
        # Whitespace is stripped
        assert result.stdout == "line1\nline2\nline3"

    @patch("utils.commands.subprocess.run")
    def test_handles_large_output(self, mock_run) -> None:
        """Test handling of large output."""
        large_output = "x" * 100000
        mock_run.return_value = SimpleNamespace(
            stdout=large_output,
            stderr="",
            returncode=0,
        )

        result = run_command(["generate_lots"], timeout=2)
        
        assert len(result.stdout) == 100000
