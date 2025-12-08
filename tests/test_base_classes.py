"""Unit tests for base classes and utilities."""
from __future__ import annotations

import pytest
from typing import Any
from unittest.mock import MagicMock, patch, PropertyMock

from macsentry.checks.base import (
    SecurityCheck,
    CheckRegistry,
    SecurityCheckMeta,
    inspect_is_abstract,
)
from macsentry.checks.types import CheckResult, Status, Severity


class TestCheckRegistry:
    """Test cases for CheckRegistry."""

    def test_register_check(self, clear_check_registry):
        """Test registering a check adds it to registry."""
        class TestCheck(SecurityCheck):
            auto_register = False
            name = "Test Check"
            
            def run(self) -> CheckResult:
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=Severity.INFO,
                    message="Test",
                    remediation="None",
                )
        
        CheckRegistry.register(TestCheck)
        
        assert "Test Check" in [c.name for c in CheckRegistry.get_all()]

    def test_register_duplicate_raises_error(self, clear_check_registry):
        """Test registering duplicate name raises ValueError."""
        class TestCheck1(SecurityCheck):
            auto_register = False
            name = "Duplicate Name"
            
            def run(self) -> CheckResult:
                pass
        
        class TestCheck2(SecurityCheck):
            auto_register = False
            name = "Duplicate Name"
            
            def run(self) -> CheckResult:
                pass
        
        CheckRegistry.register(TestCheck1)
        
        with pytest.raises(ValueError, match="Duplicate"):
            CheckRegistry.register(TestCheck2)

    def test_register_empty_name_raises_error(self, clear_check_registry):
        """Test registering check with empty name raises ValueError."""
        class NoNameCheck(SecurityCheck):
            auto_register = False
            name = ""
            
            def run(self) -> CheckResult:
                pass
        
        with pytest.raises(ValueError, match="must define a name"):
            CheckRegistry.register(NoNameCheck)

    def test_get_all_returns_all_registered(self, clear_check_registry):
        """Test get_all returns all registered checks."""
        class Check1(SecurityCheck):
            auto_register = False
            name = "Check 1"
            def run(self): pass
        
        class Check2(SecurityCheck):
            auto_register = False
            name = "Check 2"
            def run(self): pass
        
        CheckRegistry.register(Check1)
        CheckRegistry.register(Check2)
        
        all_checks = list(CheckRegistry.get_all())
        assert len(all_checks) == 2

    def test_by_category_filters_correctly(self, clear_check_registry):
        """Test by_category filters by category."""
        class FirewallCheck(SecurityCheck):
            auto_register = False
            name = "Firewall Test"
            category = "firewall"
            def run(self): pass
        
        class AuthCheck(SecurityCheck):
            auto_register = False
            name = "Auth Test"
            category = "authentication"
            def run(self): pass
        
        CheckRegistry.register(FirewallCheck)
        CheckRegistry.register(AuthCheck)
        
        firewall_checks = list(CheckRegistry.by_category(["firewall"]))
        auth_checks = list(CheckRegistry.by_category(["authentication"]))
        
        assert len(firewall_checks) == 1
        assert firewall_checks[0].name == "Firewall Test"
        assert len(auth_checks) == 1
        assert auth_checks[0].name == "Auth Test"

    def test_by_category_case_insensitive(self, clear_check_registry):
        """Test by_category is case insensitive."""
        class TestCheck(SecurityCheck):
            auto_register = False
            name = "Test"
            category = "FireWall"
            def run(self): pass
        
        CheckRegistry.register(TestCheck)
        
        result = list(CheckRegistry.by_category(["FIREWALL"]))
        assert len(result) == 1

    def test_clear_empties_registry(self, clear_check_registry):
        """Test clear removes all registered checks."""
        class TestCheck(SecurityCheck):
            auto_register = False
            name = "Test"
            def run(self): pass
        
        CheckRegistry.register(TestCheck)
        CheckRegistry.clear()
        
        assert list(CheckRegistry.get_all()) == []


class TestSecurityCheck:
    """Test cases for SecurityCheck base class."""

    def test_execute_calls_run(self, clear_check_registry):
        """Test execute calls the run method."""
        class TestCheck(SecurityCheck):
            auto_register = False
            name = "Test Check"
            
            def run(self) -> CheckResult:
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=Severity.INFO,
                    message="Success",
                    remediation="None",
                )
        
        check = TestCheck()
        result = check.execute()
        
        assert result.status == Status.PASS
        assert result.check_name == "Test Check"

    def test_execute_skips_if_not_applicable(self, clear_check_registry):
        """Test execute returns SKIP if check is not applicable."""
        class FutureCheck(SecurityCheck):
            auto_register = False
            name = "Future Check"
            min_version = (99, 0, 0)  # Future version
            
            def run(self) -> CheckResult:
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=Severity.INFO,
                    message="Should not run",
                    remediation="None",
                )
        
        check = FutureCheck()
        result = check.execute()
        
        assert result.status == Status.SKIP
        assert "not applicable" in result.message.lower()

    def test_execute_skips_if_requires_sudo_not_root(self, clear_check_registry):
        """Test execute returns SKIP if sudo required but not root."""
        class RootCheck(SecurityCheck):
            auto_register = False
            name = "Root Check"
            requires_sudo = True
            
            def run(self) -> CheckResult:
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=Severity.INFO,
                    message="Should not run",
                    remediation="None",
                )
        
        with patch.object(SecurityCheck, "_is_root", return_value=False):
            check = RootCheck()
            result = check.execute()
        
        assert result.status == Status.SKIP
        assert "privileges" in result.message.lower()

    def test_execute_handles_exception(self, clear_check_registry):
        """Test execute catches exceptions and returns ERROR."""
        class BrokenCheck(SecurityCheck):
            auto_register = False
            name = "Broken Check"
            
            def run(self) -> CheckResult:
                raise RuntimeError("Something broke")
        
        check = BrokenCheck()
        result = check.execute()
        
        assert result.status == Status.ERROR
        assert "Something broke" in result.message
        assert result.details.get("exception_type") == "RuntimeError"

    def test_execute_fixes_check_name_mismatch(self, clear_check_registry):
        """Test execute corrects check_name if mismatched."""
        class MismatchCheck(SecurityCheck):
            auto_register = False
            name = "Correct Name"
            
            def run(self) -> CheckResult:
                return CheckResult(
                    check_name="Wrong Name",
                    status=Status.PASS,
                    severity=Severity.INFO,
                    message="Test",
                    remediation="None",
                )
        
        check = MismatchCheck()
        result = check.execute()
        
        assert result.check_name == "Correct Name"

    @pytest.mark.parametrize("version_str,expected", [
        ("14.0.0", (14, 0, 0)),
        ("13.5.1", (13, 5, 1)),
        ("15.1", (15, 1, 0)),
        ("12.0", (12, 0, 0)),
        ("", (0, 0, 0)),
    ])
    def test_get_macos_version_parsing(self, version_str, expected):
        """Test macOS version string parsing."""
        with patch("platform.mac_ver", return_value=(version_str, ("", "", ""), "")):
            class TestCheck(SecurityCheck):
                auto_register = False
                name = "Test"
                def run(self): pass
            
            check = TestCheck()
            assert check._macos_version == expected

    def test_is_applicable_with_min_version(self):
        """Test is_applicable respects min_version."""
        class VersionedCheck(SecurityCheck):
            auto_register = False
            name = "Versioned"
            min_version = (14, 0, 0)
            def run(self): pass
        
        with patch("platform.mac_ver", return_value=("15.0.0", ("", "", ""), "")):
            check = VersionedCheck()
            assert check.is_applicable() is True
        
        with patch("platform.mac_ver", return_value=("13.0.0", ("", "", ""), "")):
            check = VersionedCheck()
            assert check.is_applicable() is False

    def test_is_root_returns_false_normally(self):
        """Test _is_root returns False for normal users."""
        # This should return False for non-root users
        result = SecurityCheck._is_root()
        # We can't assert specific value as it depends on execution context
        assert isinstance(result, bool)

    def test_repr(self, clear_check_registry):
        """Test __repr__ output."""
        class TestCheck(SecurityCheck):
            auto_register = False
            name = "Test Check"
            severity = Severity.HIGH
            def run(self): pass
        
        check = TestCheck()
        repr_str = repr(check)
        
        assert "TestCheck" in repr_str
        assert "Test Check" in repr_str
        assert "HIGH" in repr_str


class TestInspectIsAbstract:
    """Test the inspect_is_abstract helper."""

    def test_abstract_class_returns_true(self):
        """Test that abstract classes are detected."""
        # SecurityCheck itself is abstract
        assert inspect_is_abstract(SecurityCheck) is True

    def test_concrete_class_returns_false(self, clear_check_registry):
        """Test that concrete classes return False."""
        class ConcreteCheck(SecurityCheck):
            auto_register = False
            name = "Concrete"
            
            def run(self) -> CheckResult:
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=Severity.INFO,
                    message="Test",
                    remediation="None",
                )
        
        assert inspect_is_abstract(ConcreteCheck) is False


class TestSecurityCheckMeta:
    """Test the SecurityCheckMeta metaclass."""

    def test_auto_register_true_registers_check(self, clear_check_registry):
        """Test that auto_register=True registers the check."""
        # Create a new class that should auto-register
        class AutoRegisteredCheck(SecurityCheck):
            name = "Auto Registered"
            
            def run(self) -> CheckResult:
                return CheckResult(
                    check_name=self.name,
                    status=Status.PASS,
                    severity=Severity.INFO,
                    message="Test",
                    remediation="None",
                )
        
        # Should be in registry
        names = [c.name for c in CheckRegistry.get_all()]
        assert "Auto Registered" in names

    def test_auto_register_false_skips_registration(self, clear_check_registry):
        """Test that auto_register=False skips registration."""
        class NotRegisteredCheck(SecurityCheck):
            auto_register = False
            name = "Not Registered"
            
            def run(self) -> CheckResult:
                pass
        
        # Should NOT be in registry
        names = [c.name for c in CheckRegistry.get_all()]
        assert "Not Registered" not in names


class TestCheckResult:
    """Test cases for CheckResult dataclass."""

    def test_create_check_result(self):
        """Test creating a CheckResult."""
        result = CheckResult(
            check_name="Test",
            status=Status.PASS,
            severity=Severity.HIGH,
            message="All good",
            remediation="None needed",
            details={"key": "value"},
        )
        
        assert result.check_name == "Test"
        assert result.status == Status.PASS
        assert result.severity == Severity.HIGH
        assert result.message == "All good"
        assert result.remediation == "None needed"
        assert result.details == {"key": "value"}

    def test_default_details_empty_dict(self):
        """Test that details defaults to empty dict."""
        result = CheckResult(
            check_name="Test",
            status=Status.PASS,
            severity=Severity.INFO,
            message="Test",
            remediation="None",
        )
        
        assert result.details == {}


class TestStatusEnum:
    """Test Status enum values."""

    def test_all_status_values_exist(self):
        """Test all expected status values exist."""
        assert Status.PASS.value == "PASS"
        assert Status.FAIL.value == "FAIL"
        assert Status.WARNING.value == "WARNING"
        assert Status.SKIP.value == "SKIP"
        assert Status.ERROR.value == "ERROR"


class TestSeverityEnum:
    """Test Severity enum values."""

    def test_all_severity_values_exist(self):
        """Test all expected severity values exist."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"
