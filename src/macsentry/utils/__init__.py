"""Utility helpers for macOS security audit."""
from __future__ import annotations

from .commands import (
    CommandExecutionError,
    CommandTimeoutError,
    CommandResult,
    run_command,
    run_command_graceful,
    which,
    get_suggested_timeout,
    get_console_user,
    run_defaults_for_user,
)
from .reporting import format_html_report, format_json_report, format_text_report
from .system_info import (
    DeviceType,
    SecurityChipType,
    HardwareInfo,
    SystemRequirements,
    EnvironmentInfo,
    get_hardware_info,
    get_macos_version,
    get_macos_version_name,
    validate_system_requirements,
    get_extended_system_info,
    format_hardware_summary,
    get_disk_timeout,
    detect_mdm_enrollment,
    is_running_under_rosetta,
    check_network_connectivity,
    check_sudo_available,
    get_environment_info,
    clear_cached_info,
)

__all__ = [
    # Commands
    "CommandExecutionError",
    "CommandTimeoutError",
    "CommandResult",
    "run_command",
    "run_command_graceful",
    "which",
    "get_suggested_timeout",
    "get_console_user",
    "run_defaults_for_user",
    # Reporting
    "format_text_report",
    "format_json_report",
    "format_html_report",
    # System info
    "DeviceType",
    "SecurityChipType",
    "HardwareInfo",
    "SystemRequirements",
    "EnvironmentInfo",
    "get_hardware_info",
    "get_macos_version",
    "get_macos_version_name",
    "validate_system_requirements",
    "get_extended_system_info",
    "format_hardware_summary",
    "get_disk_timeout",
    # Environment detection
    "detect_mdm_enrollment",
    "is_running_under_rosetta",
    "check_network_connectivity",
    "check_sudo_available",
    "get_environment_info",
    "clear_cached_info",
]
