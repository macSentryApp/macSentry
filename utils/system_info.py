"""System information and hardware detection utilities."""
from __future__ import annotations

import logging
import os
import platform
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Minimum supported macOS version
MIN_MACOS_VERSION = (10, 15)  # Catalina
RECOMMENDED_MACOS_VERSION = (12, 0)  # Monterey

# Required system commands
REQUIRED_COMMANDS = [
    "/usr/bin/fdesetup",
    "/usr/sbin/diskutil",
    "/usr/bin/defaults",
    "/usr/bin/csrutil",
]

OPTIONAL_COMMANDS = [
    "/usr/bin/tmutil",
    "/usr/sbin/firmwarepasswd",
    "/usr/bin/profiles",
]

# Disk operation timeouts by hardware type
DISK_TIMEOUTS = {
    "apple_silicon": 30,  # Apple Silicon tends to be faster
    "intel": 45,          # Intel Macs may have older/slower storage
    "default": 30,
}


class DeviceType(Enum):
    """Mac device type classification."""
    MACBOOK = "macbook"           # MacBook, MacBook Air, MacBook Pro
    IMAC = "imac"                 # iMac, iMac Pro
    MAC_MINI = "mac_mini"         # Mac mini
    MAC_PRO = "mac_pro"           # Mac Pro
    MAC_STUDIO = "mac_studio"     # Mac Studio
    UNKNOWN = "unknown"


class SecurityChipType(Enum):
    """Security chip classification."""
    T2 = "t2"                     # Intel Mac with T2 chip
    APPLE_SILICON = "apple_silicon"  # M1/M2/M3 series (Secure Enclave)
    NONE = "none"                 # Older Intel Mac without T2


@dataclass
class HardwareInfo:
    """Hardware information for the current Mac."""
    
    chip_type: str  # "apple_silicon" or "intel"
    model_name: str
    model_identifier: str
    cpu_brand: str
    cpu_cores: int
    memory_gb: float
    is_vm: bool = False
    boot_rom_version: str = ""
    serial_number: str = ""
    device_type: DeviceType = DeviceType.UNKNOWN
    security_chip: SecurityChipType = SecurityChipType.NONE
    has_builtin_camera: bool = True
    has_builtin_mic: bool = True
    
    def to_dict(self) -> Dict[str, str | int | float | bool]:
        """Convert to dictionary for reporting."""
        return {
            "chip_type": self.chip_type,
            "model_name": self.model_name,
            "model_identifier": self.model_identifier,
            "cpu_brand": self.cpu_brand,
            "cpu_cores": self.cpu_cores,
            "memory_gb": self.memory_gb,
            "is_vm": self.is_vm,
            "device_type": self.device_type.value,
            "security_chip": self.security_chip.value,
            "has_builtin_camera": self.has_builtin_camera,
            "has_builtin_mic": self.has_builtin_mic,
        }
    
    @property
    def is_portable(self) -> bool:
        """Check if device is a laptop (has built-in battery)."""
        return self.device_type == DeviceType.MACBOOK
    
    @property
    def is_desktop(self) -> bool:
        """Check if device is a desktop Mac."""
        return self.device_type in (
            DeviceType.IMAC,
            DeviceType.MAC_MINI,
            DeviceType.MAC_PRO,
            DeviceType.MAC_STUDIO,
        )
    
    @property
    def has_secure_enclave(self) -> bool:
        """Check if device has Secure Enclave (T2 or Apple Silicon)."""
        return self.security_chip in (SecurityChipType.T2, SecurityChipType.APPLE_SILICON)


@dataclass
class SystemRequirements:
    """System requirements validation result."""
    
    passed: bool
    macos_version: Tuple[int, ...]
    macos_version_str: str
    python_version: Tuple[int, ...]
    is_macos: bool
    missing_commands: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, object]:
        """Convert to dictionary for reporting."""
        return {
            "passed": self.passed,
            "macos_version": self.macos_version_str,
            "python_version": ".".join(map(str, self.python_version)),
            "is_macos": self.is_macos,
            "missing_commands": self.missing_commands,
            "warnings": self.warnings,
            "errors": self.errors,
        }


@lru_cache(maxsize=1)
def get_hardware_info() -> HardwareInfo:
    """Detect hardware type and specifications.
    
    Returns:
        HardwareInfo with chip type, model, and specifications.
    """
    # Detect chip type
    machine = platform.machine().lower()
    is_apple_silicon = machine in ("arm64", "arm64e")
    chip_type = "apple_silicon" if is_apple_silicon else "intel"
    
    # Get model info from system_profiler
    model_name = "Unknown Mac"
    model_identifier = "Unknown"
    cpu_brand = platform.processor() or "Unknown"
    cpu_cores = os.cpu_count() or 1
    memory_gb = _get_memory_gb()
    is_vm = _detect_virtual_machine()
    boot_rom = ""
    
    try:
        result = subprocess.run(
            ["/usr/sbin/system_profiler", "SPHardwareDataType", "-detailLevel", "mini"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if "Model Name:" in line:
                    model_name = line.split(":", 1)[1].strip()
                elif "Model Identifier:" in line:
                    model_identifier = line.split(":", 1)[1].strip()
                elif "Chip:" in line:
                    cpu_brand = line.split(":", 1)[1].strip()
                elif "Processor Name:" in line and not is_apple_silicon:
                    cpu_brand = line.split(":", 1)[1].strip()
                elif "Boot ROM Version:" in line:
                    boot_rom = line.split(":", 1)[1].strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("Could not get hardware info: %s", exc)
    
    # Detect device type and security chip
    device_type = _detect_device_type(model_identifier, model_name)
    security_chip = _detect_security_chip(is_apple_silicon, model_identifier)
    has_camera, has_mic = _detect_builtin_peripherals(device_type)
    
    return HardwareInfo(
        chip_type=chip_type,
        model_name=model_name,
        model_identifier=model_identifier,
        cpu_brand=cpu_brand,
        cpu_cores=cpu_cores,
        memory_gb=memory_gb,
        is_vm=is_vm,
        boot_rom_version=boot_rom,
        device_type=device_type,
        security_chip=security_chip,
        has_builtin_camera=has_camera,
        has_builtin_mic=has_mic,
    )


def _detect_device_type(model_identifier: str, model_name: str) -> DeviceType:
    """Detect the type of Mac device."""
    model_id_lower = model_identifier.lower()
    model_name_lower = model_name.lower()
    
    # Check model identifier patterns
    if model_id_lower.startswith("macbook"):
        return DeviceType.MACBOOK
    if model_id_lower.startswith("imac"):
        return DeviceType.IMAC
    if model_id_lower.startswith("macmini") or "mac mini" in model_id_lower:
        return DeviceType.MAC_MINI
    if model_id_lower.startswith("macpro") or "mac pro" in model_id_lower:
        return DeviceType.MAC_PRO
    if model_id_lower.startswith("mac14,") and "studio" in model_name_lower:
        return DeviceType.MAC_STUDIO
    if "mac studio" in model_name_lower:
        return DeviceType.MAC_STUDIO
    
    # Fallback to model name check
    if "macbook" in model_name_lower:
        return DeviceType.MACBOOK
    if "imac" in model_name_lower:
        return DeviceType.IMAC
    if "mac mini" in model_name_lower:
        return DeviceType.MAC_MINI
    if "mac pro" in model_name_lower:
        return DeviceType.MAC_PRO
    if "mac studio" in model_name_lower:
        return DeviceType.MAC_STUDIO
    
    return DeviceType.UNKNOWN


def _detect_security_chip(is_apple_silicon: bool, model_identifier: str) -> SecurityChipType:
    """Detect security chip type (T2 or Apple Silicon Secure Enclave)."""
    if is_apple_silicon:
        return SecurityChipType.APPLE_SILICON
    
    # T2 chip Intel Macs (2018-2020 models)
    # Reference: https://support.apple.com/en-us/103265
    t2_models = {
        # MacBook Air
        "macbookair8,", "macbookair9,",
        # MacBook Pro
        "macbookpro15,", "macbookpro16,",
        # Mac mini
        "macmini8,",
        # Mac Pro
        "macpro7,",
        # iMac
        "imac20,", "imacpro1,",
    }
    
    model_id_lower = model_identifier.lower()
    for t2_prefix in t2_models:
        if model_id_lower.startswith(t2_prefix):
            return SecurityChipType.T2
    
    return SecurityChipType.NONE


def _detect_builtin_peripherals(device_type: DeviceType) -> Tuple[bool, bool]:
    """Detect if device has built-in camera and microphone.
    
    Returns:
        Tuple of (has_camera, has_mic)
    """
    # All MacBooks and iMacs have built-in camera and mic
    if device_type in (DeviceType.MACBOOK, DeviceType.IMAC):
        return (True, True)
    
    # Mac mini, Mac Pro, Mac Studio have no built-in camera but have built-in mic (speaker/mic)
    # Actually Mac mini has no built-in speaker/mic, Mac Pro and Mac Studio have built-in speaker
    if device_type == DeviceType.MAC_MINI:
        return (False, False)
    if device_type in (DeviceType.MAC_PRO, DeviceType.MAC_STUDIO):
        return (False, True)  # Has internal speaker which may include mic
    
    # Unknown - assume has both for safety (will check permissions)
    return (True, True)


def _get_memory_gb() -> float:
    """Get system memory in GB."""
    try:
        result = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "hw.memsize"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            bytes_mem = int(result.stdout.strip())
            return round(bytes_mem / (1024 ** 3), 1)
    except (subprocess.TimeoutExpired, ValueError, OSError):
        pass
    return 0.0


def _detect_virtual_machine() -> bool:
    """Detect if running in a virtual machine."""
    try:
        result = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "machdep.cpu.features"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        features = result.stdout.lower()
        if "vmm" in features:
            return True
    except (subprocess.TimeoutExpired, OSError):
        pass
    
    # Check for common VM indicators
    try:
        result = subprocess.run(
            ["/usr/sbin/system_profiler", "SPHardwareDataType"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout.lower()
        vm_indicators = ["vmware", "virtualbox", "parallels", "qemu", "virtual machine"]
        for indicator in vm_indicators:
            if indicator in output:
                return True
    except (subprocess.TimeoutExpired, OSError):
        pass
    
    return False


@lru_cache(maxsize=1)
def get_macos_version() -> Tuple[int, ...]:
    """Get macOS version as tuple of integers.
    
    Returns:
        Tuple like (14, 1, 0) for macOS 14.1.0
    """
    version_str = platform.mac_ver()[0]
    if not version_str:
        return (0, 0, 0)
    
    try:
        parts = [int(p) for p in version_str.split(".")]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])
    except ValueError:
        return (0, 0, 0)


def get_macos_version_name() -> str:
    """Get macOS version name (e.g., 'Sonoma', 'Ventura')."""
    version = get_macos_version()
    major = version[0]
    
    names = {
        26: "Tahoe",
        15: "Sequoia",
        14: "Sonoma",
        13: "Ventura",
        12: "Monterey",
        11: "Big Sur",
        10: {
            15: "Catalina",
            14: "Mojave",
            13: "High Sierra",
            12: "Sierra",
        },
    }
    
    if major == 10:
        minor = version[1] if len(version) > 1 else 0
        return names.get(10, {}).get(minor, "Unknown")
    return names.get(major, "Unknown")


def check_command_available(cmd_path: str) -> bool:
    """Check if a command is available at the given path."""
    return os.path.isfile(cmd_path) and os.access(cmd_path, os.X_OK)


def validate_system_requirements() -> SystemRequirements:
    """Validate that the system meets requirements for the audit tool.
    
    Returns:
        SystemRequirements with validation results.
    """
    errors: List[str] = []
    warnings: List[str] = []
    missing_commands: List[str] = []
    
    # Check OS
    is_macos = platform.system() == "Darwin"
    if not is_macos:
        errors.append(f"This tool requires macOS (detected: {platform.system()})")
    
    # Check macOS version
    macos_version = get_macos_version()
    macos_version_str = platform.mac_ver()[0] or "Unknown"
    
    if macos_version < MIN_MACOS_VERSION:
        errors.append(
            f"macOS {'.'.join(map(str, MIN_MACOS_VERSION))} or later required "
            f"(detected: {macos_version_str})"
        )
    elif macos_version < RECOMMENDED_MACOS_VERSION:
        warnings.append(
            f"macOS {'.'.join(map(str, RECOMMENDED_MACOS_VERSION))} or later recommended "
            f"for full feature support (detected: {macos_version_str})"
        )
    
    # Check Python version
    python_version = sys.version_info[:3]
    if python_version < (3, 9):
        errors.append(f"Python 3.9+ required (detected: {'.'.join(map(str, python_version))})")
    
    # Check required commands
    for cmd in REQUIRED_COMMANDS:
        if not check_command_available(cmd):
            missing_commands.append(cmd)
            errors.append(f"Required command not found: {cmd}")
    
    # Check optional commands
    for cmd in OPTIONAL_COMMANDS:
        if not check_command_available(cmd):
            warnings.append(f"Optional command not available: {cmd}")
    
    # Check for VM
    hw = get_hardware_info()
    if hw.is_vm:
        warnings.append("Running in virtual machine - some checks may not apply")
    
    passed = len(errors) == 0
    
    return SystemRequirements(
        passed=passed,
        macos_version=macos_version,
        macos_version_str=macos_version_str,
        python_version=python_version,
        is_macos=is_macos,
        missing_commands=missing_commands,
        warnings=warnings,
        errors=errors,
    )


def get_disk_timeout() -> int:
    """Get appropriate disk operation timeout based on hardware.
    
    Returns:
        Timeout in seconds for disk operations.
    """
    hw = get_hardware_info()
    return DISK_TIMEOUTS.get(hw.chip_type, DISK_TIMEOUTS["default"])


def get_extended_system_info() -> Dict[str, object]:
    """Get extended system information for reports and debugging.
    
    Returns:
        Dictionary with comprehensive system information.
    """
    mac_ver = platform.mac_ver()
    hw = get_hardware_info()
    macos_name = get_macos_version_name()
    
    return {
        "os": f"macOS {mac_ver[0] or 'Unknown'}",
        "os_version": mac_ver[0] or "Unknown",
        "os_name": macos_name,
        "release": mac_ver[2] or "Unknown",
        "kernel": platform.release(),
        "arch": platform.machine(),
        "python": sys.version.split()[0],
        "python_path": sys.executable,
        "hardware": hw.to_dict(),
        "hostname": platform.node(),
        "user": os.getenv("USER", "unknown"),
    }


def format_hardware_summary() -> str:
    """Format a one-line hardware summary for logging."""
    hw = get_hardware_info()
    macos_ver = platform.mac_ver()[0]
    macos_name = get_macos_version_name()
    
    return (
        f"{hw.model_name} ({hw.chip_type.replace('_', ' ').title()}) | "
        f"macOS {macos_ver} {macos_name} | "
        f"{hw.cpu_brand} | {hw.memory_gb}GB RAM"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Environment Detection (MDM, Rosetta, Network)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class EnvironmentInfo:
    """Runtime environment information."""
    
    is_mdm_enrolled: bool = False
    mdm_server: str = ""
    is_rosetta_process: bool = False
    is_network_available: bool = True
    has_sudo_access: bool = False
    
    def to_dict(self) -> Dict[str, str | bool]:
        return {
            "is_mdm_enrolled": self.is_mdm_enrolled,
            "mdm_server": self.mdm_server,
            "is_rosetta_process": self.is_rosetta_process,
            "is_network_available": self.is_network_available,
            "has_sudo_access": self.has_sudo_access,
        }


@lru_cache(maxsize=1)
def detect_mdm_enrollment() -> Tuple[bool, str]:
    """Detect if the Mac is enrolled in Mobile Device Management (MDM).
    
    Returns:
        Tuple of (is_enrolled, mdm_server_or_type)
    """
    # Check profiles command for MDM enrollment
    try:
        result = subprocess.run(
            ["/usr/bin/profiles", "status", "-type", "enrollment"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
        output_lower = output.lower()
        
        if "mdm enrollment: yes" in output_lower or "enrolled via dep: yes" in output_lower:
            # Try to get MDM server info
            server = _extract_mdm_server(output)
            return (True, server or "MDM Enrolled")
        
        if "mdm enrollment: no" in output_lower:
            return (False, "")
            
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("Could not check MDM enrollment: %s", exc)
    
    # Fallback: check for common MDM configuration profiles
    mdm_indicators = [
        Path("/Library/Managed Preferences"),
        Path("/var/db/ConfigurationProfiles/Settings"),
    ]
    
    for path in mdm_indicators:
        if path.exists():
            try:
                # Check if there are actual managed preferences
                if path.is_dir() and any(path.iterdir()):
                    return (True, "Configuration Profiles Detected")
            except (PermissionError, OSError):
                pass
    
    return (False, "")


def _extract_mdm_server(profiles_output: str) -> str:
    """Extract MDM server name from profiles output."""
    # Common MDM solutions
    mdm_names = {
        "jamf": "Jamf Pro",
        "kandji": "Kandji",
        "mosyle": "Mosyle",
        "workspace one": "VMware Workspace ONE",
        "airwatch": "VMware AirWatch",
        "intune": "Microsoft Intune",
        "meraki": "Cisco Meraki",
        "addigy": "Addigy",
        "hexnode": "Hexnode",
        "fleetsmith": "Fleetsmith",
        "simplemdm": "SimpleMDM",
    }
    
    output_lower = profiles_output.lower()
    for key, name in mdm_names.items():
        if key in output_lower:
            return name
    
    return ""


@lru_cache(maxsize=1)
def is_running_under_rosetta() -> bool:
    """Detect if the current process is running under Rosetta 2 translation.
    
    Returns:
        True if running as Intel binary on Apple Silicon via Rosetta.
    """
    # Check if we're on Apple Silicon
    machine = platform.machine().lower()
    if machine not in ("arm64", "arm64e"):
        # Not on Apple Silicon, so Rosetta doesn't apply
        return False
    
    # Check if Python itself is running as x86_64 under Rosetta
    try:
        result = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "sysctl.proc_translated"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            translated = result.stdout.strip()
            return translated == "1"
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    
    return False


@lru_cache(maxsize=1)
def check_network_connectivity(timeout: float = 3.0) -> bool:
    """Check if network connectivity is available.
    
    Uses multiple methods to determine connectivity without making
    external HTTP requests.
    
    Args:
        timeout: Socket timeout in seconds.
    
    Returns:
        True if network appears available.
    """
    # Method 1: Try to resolve a common domain
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname("apple.com")
        return True
    except (socket.gaierror, socket.timeout, OSError):
        pass
    
    # Method 2: Check for active network interfaces
    try:
        result = subprocess.run(
            ["/sbin/ifconfig", "-a"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            output = result.stdout
            # Look for active interfaces with IP addresses (excluding loopback)
            if "inet " in output and "127.0.0.1" not in output.replace("inet 127.0.0.1", ""):
                # Has non-loopback IP, might have connectivity
                return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    
    # Method 3: Check networksetup for active service
    try:
        result = subprocess.run(
            ["/usr/sbin/networksetup", "-listallhardwareports"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and ("Wi-Fi" in result.stdout or "Ethernet" in result.stdout):
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    
    return False


def check_sudo_available() -> bool:
    """Check if sudo access is available without prompting for password.
    
    Returns:
        True if sudo commands can be run without password prompt.
    """
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "-n", "true"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


@lru_cache(maxsize=1)
def get_environment_info() -> EnvironmentInfo:
    """Get comprehensive environment information.
    
    Returns:
        EnvironmentInfo with MDM, Rosetta, network status.
    """
    is_mdm, mdm_server = detect_mdm_enrollment()
    
    return EnvironmentInfo(
        is_mdm_enrolled=is_mdm,
        mdm_server=mdm_server,
        is_rosetta_process=is_running_under_rosetta(),
        is_network_available=check_network_connectivity(),
        has_sudo_access=check_sudo_available(),
    )


def clear_cached_info() -> None:
    """Clear all cached system information. Useful for testing."""
    get_hardware_info.cache_clear()
    get_macos_version.cache_clear()
    detect_mdm_enrollment.cache_clear()
    is_running_under_rosetta.cache_clear()
    check_network_connectivity.cache_clear()
    get_environment_info.cache_clear()
