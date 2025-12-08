"""Unit tests for encryption-related security checks."""
from __future__ import annotations

import plistlib
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from macsentry.checks.encryption import ExternalDiskEncryptionCheck, FileVaultStatusCheck


class FileVaultStatusCheckTests(unittest.TestCase):
    """Test FileVault status parsing."""

    @patch("checks.encryption.commands.run_command")
    def test_filevault_enabled(self, mock_run: MagicMock) -> None:
        mock_run.return_value = SimpleNamespace(stdout="FileVault is On.\n", stderr="", returncode=0)
        check = FileVaultStatusCheck()
        result = check.execute()
        self.assertEqual(result.status.value, "PASS")
        self.assertIn("enabled", result.message.lower())

    @patch("checks.encryption.commands.run_command")
    def test_filevault_disabled(self, mock_run: MagicMock) -> None:
        mock_run.return_value = SimpleNamespace(stdout="FileVault is Off.\n", stderr="", returncode=0)
        check = FileVaultStatusCheck()
        result = check.execute()
        self.assertEqual(result.status.value, "FAIL")
        self.assertIn("disabled", result.message.lower())

    @patch("checks.encryption.commands.run_command")
    def test_filevault_unknown(self, mock_run: MagicMock) -> None:
        mock_run.return_value = SimpleNamespace(stdout="Unexpected response", stderr="", returncode=0)
        check = FileVaultStatusCheck()
        result = check.execute()
        self.assertEqual(result.status.value, "WARNING")


class ExternalDiskEncryptionCheckTests(unittest.TestCase):
    """Test external disk encryption parsing."""

    @patch("checks.encryption.commands.run_command")
    def test_no_disks(self, mock_run: MagicMock) -> None:
        mock_run.return_value = SimpleNamespace(stdout="", stderr="", returncode=0)
        check = ExternalDiskEncryptionCheck()
        result = check.execute()
        self.assertEqual(result.status.value, "PASS")

    @patch.object(ExternalDiskEncryptionCheck, "_is_external_disk")
    @patch("checks.encryption.commands.run_command")
    def test_unencrypted_disk_detected(self, mock_run: MagicMock, mock_is_external: MagicMock) -> None:
        # Create APFS list plist with unencrypted external volume
        plist = plistlib.dumps(
            {
                "Containers": [
                    {
                        "ContainerReference": "disk2",
                        "PhysicalStores": [{"DeviceIdentifier": "disk2s1"}],
                        "Volumes": [
                            {
                                "Name": "External Drive",
                                "FileVault": False,
                                "Encryption": False,
                            }
                        ],
                    }
                ]
            }
        ).decode("utf-8")
        mock_run.return_value = SimpleNamespace(stdout=plist, stderr="", returncode=0)
        mock_is_external.return_value = True

        check = ExternalDiskEncryptionCheck()
        result = check.execute()
        self.assertEqual(result.status.value, "FAIL")
        self.assertIn("External Drive", result.details.get("unencrypted", []))


if __name__ == "__main__":
    unittest.main()
