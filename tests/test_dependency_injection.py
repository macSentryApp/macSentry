"""Unit tests for dependency injection container."""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from core.injection import (
    CommandResult,
    DependencyContainer,
    MockOSInterface,
    RealOSInterface,
    get_container,
    reset_container,
    set_container,
)


class TestMockOSInterface(unittest.TestCase):
    """Test MockOSInterface for testing scenarios."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.mock_os = MockOSInterface()

    def test_mock_command_response(self) -> None:
        """Should return mocked command responses."""
        expected = CommandResult(
            stdout="FileVault is On.",
            stderr="",
            returncode=0,
        )
        self.mock_os.mock_command_response(
            ["fdesetup", "status"],
            expected,
        )

        result = self.mock_os.run_command(["fdesetup", "status"])

        self.assertEqual(result.stdout, "FileVault is On.")
        self.assertEqual(result.returncode, 0)

    def test_unmocked_command_returns_error(self) -> None:
        """Unmocked commands should return error response."""
        result = self.mock_os.run_command(["unmocked", "command"])

        self.assertEqual(result.returncode, 1)
        self.assertIn("not mocked", result.stderr)

    def test_mock_file_content(self) -> None:
        """Should return mocked file content."""
        test_path = Path("/test/file.txt")
        self.mock_os.mock_file_content(test_path, "test content")

        content = self.mock_os.read_file(test_path)

        self.assertEqual(content, "test content")

    def test_unmocked_file_returns_none(self) -> None:
        """Unmocked files should return None."""
        result = self.mock_os.read_file(Path("/unmocked/file.txt"))
        self.assertIsNone(result)

    def test_mock_file_exists(self) -> None:
        """File exists should check mocked files."""
        test_path = Path("/test/exists.txt")
        self.mock_os.mock_file_content(test_path, "content")

        self.assertTrue(self.mock_os.file_exists(test_path))
        self.assertFalse(self.mock_os.file_exists(Path("/not/mocked")))

    def test_mock_file_mtime(self) -> None:
        """Should return mocked modification time."""
        test_path = Path("/test/file.txt")
        self.mock_os.mock_file_mtime(test_path, 1234567890.0)

        mtime = self.mock_os.get_file_mtime(test_path)

        self.assertEqual(mtime, 1234567890.0)

    def test_mock_directory_listing(self) -> None:
        """Should return mocked directory contents."""
        dir_path = Path("/test/dir")
        expected = [Path("/test/dir/file1.txt"), Path("/test/dir/file2.txt")]
        self.mock_os.mock_directory(dir_path, expected)

        contents = self.mock_os.list_directory(dir_path)

        self.assertEqual(contents, expected)

    def test_mock_home_directory(self) -> None:
        """Should return mocked home directory."""
        self.mock_os.mock_home_directory(Path("/Users/testuser"))

        home = self.mock_os.get_home_directory()

        self.assertEqual(home, Path("/Users/testuser"))

    def test_prefix_matching_for_commands(self) -> None:
        """Should match commands by prefix for variable arguments."""
        self.mock_os.mock_command_response(
            ["diskutil", "info"],
            CommandResult(stdout="disk info", stderr="", returncode=0),
        )

        # Should match even with additional arguments
        result = self.mock_os.run_command(["diskutil", "info", "-plist", "/dev/disk0"])

        self.assertEqual(result.stdout, "disk info")


class TestRealOSInterface(unittest.TestCase):
    """Test RealOSInterface with controlled commands."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.real_os = RealOSInterface()

    def test_run_simple_command(self) -> None:
        """Should run a simple command successfully."""
        result = self.real_os.run_command(["echo", "hello"])

        self.assertEqual(result.stdout.strip(), "hello")
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.timed_out)

    def test_command_not_found(self) -> None:
        """Should handle command not found gracefully."""
        result = self.real_os.run_command(["nonexistent_command_xyz"])

        self.assertEqual(result.returncode, -1)
        self.assertIn("not found", result.stderr.lower())

    def test_read_nonexistent_file(self) -> None:
        """Should return None for nonexistent files."""
        result = self.real_os.read_file(Path("/nonexistent/path/file.txt"))
        self.assertIsNone(result)

    def test_file_exists_check(self) -> None:
        """Should correctly check file existence."""
        self.assertTrue(self.real_os.file_exists(Path("/etc/hosts")))
        self.assertFalse(self.real_os.file_exists(Path("/nonexistent/file")))

    def test_get_home_directory(self) -> None:
        """Should return a valid home directory."""
        home = self.real_os.get_home_directory()
        self.assertTrue(home.exists())
        self.assertTrue(home.is_dir())


class TestDependencyContainer(unittest.TestCase):
    """Test DependencyContainer functionality."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.mock_os = MockOSInterface()
        self.container = DependencyContainer(os_interface=self.mock_os)

    def test_os_shorthand(self) -> None:
        """os property should return the os_interface."""
        self.assertIs(self.container.os, self.mock_os)

    def test_load_plist_success(self) -> None:
        """Should load plist from mocked file."""
        import plistlib

        test_path = Path("/test/test.plist")
        plist_data = {"key": "value", "number": 42}
        self.mock_os.mock_file_bytes(test_path, plistlib.dumps(plist_data))

        result = self.container.load_plist(test_path)

        self.assertEqual(result, plist_data)

    def test_load_plist_file_not_found(self) -> None:
        """Should return None for missing plist."""
        result = self.container.load_plist(Path("/nonexistent.plist"))
        self.assertIsNone(result)

    def test_load_plist_invalid_content(self) -> None:
        """Should return None for invalid plist content."""
        test_path = Path("/test/invalid.plist")
        self.mock_os.mock_file_bytes(test_path, b"not valid plist content")

        result = self.container.load_plist(test_path)

        self.assertIsNone(result)


class TestGlobalContainer(unittest.TestCase):
    """Test global container management."""

    def tearDown(self) -> None:
        """Clean up global state."""
        reset_container()

    def test_get_container_creates_default(self) -> None:
        """get_container should create container with real OS interface."""
        container = get_container()

        self.assertIsInstance(container, DependencyContainer)
        self.assertIsInstance(container.os_interface, RealOSInterface)

    def test_get_container_returns_same_instance(self) -> None:
        """get_container should return singleton."""
        container1 = get_container()
        container2 = get_container()

        self.assertIs(container1, container2)

    def test_set_container_overrides_global(self) -> None:
        """set_container should override the global instance."""
        mock_os = MockOSInterface()
        custom_container = DependencyContainer(os_interface=mock_os)

        set_container(custom_container)

        self.assertIs(get_container(), custom_container)

    def test_reset_container_clears_global(self) -> None:
        """reset_container should clear the global instance."""
        get_container()  # Create instance
        reset_container()

        # Next call should create new instance
        container = get_container()
        self.assertIsInstance(container.os_interface, RealOSInterface)


if __name__ == "__main__":
    unittest.main()
