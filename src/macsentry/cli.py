"""macSentry - Beautiful CLI Interface."""
from __future__ import annotations

import itertools
import os
import shutil
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional

from .checks.types import CheckResult, Severity, Status

# ═══════════════════════════════════════════════════════════════════════════════
# ANSI Color & Style Codes
# ═══════════════════════════════════════════════════════════════════════════════

class Colors:
    """ANSI color codes for terminal output."""
    
    # Reset
    RESET = "\033[0m"
    
    # Styles
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"
    
    # Foreground Colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Bright Foreground
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    
    # Background Colors
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"
    
    # 256 Color mode
    @staticmethod
    def fg(code: int) -> str:
        """256-color foreground."""
        return f"\033[38;5;{code}m"
    
    @staticmethod
    def bg(code: int) -> str:
        """256-color background."""
        return f"\033[48;5;{code}m"
    
    # True color (24-bit)
    @staticmethod
    def rgb(r: int, g: int, b: int) -> str:
        """24-bit RGB foreground color."""
        return f"\033[38;2;{r};{g};{b}m"
    
    @staticmethod
    def bg_rgb(r: int, g: int, b: int) -> str:
        """24-bit RGB background color."""
        return f"\033[48;2;{r};{g};{b}m"


# ═══════════════════════════════════════════════════════════════════════════════
# Theme Colors (Purple-based palette)
# ═══════════════════════════════════════════════════════════════════════════════

class Theme:
    """Custom theme colors for macSentry."""
    
    # Primary accent - Purple
    ACCENT = Colors.rgb(97, 86, 140)  # #61568C
    ACCENT_LIGHT = Colors.rgb(122, 111, 168)  # Lighter purple
    ACCENT_DIM = Colors.rgb(45, 41, 64)  # Dim purple
    
    # Status colors
    SUCCESS = Colors.rgb(107, 158, 120)  # Muted green
    WARNING = Colors.rgb(201, 168, 87)   # Muted gold
    ERROR = Colors.rgb(184, 90, 90)      # Muted red
    INFO = Colors.rgb(90, 122, 158)      # Muted blue
    
    # Severity colors
    CRITICAL = Colors.rgb(199, 90, 90)   # Red
    HIGH = Colors.rgb(201, 138, 87)      # Orange
    MEDIUM = Colors.rgb(201, 168, 87)    # Gold
    LOW = Colors.rgb(90, 138, 199)       # Blue
    INFO_SEV = Colors.rgb(97, 86, 140)   # Purple
    
    # Text colors
    TEXT = Colors.rgb(242, 242, 242)     # Off-white
    TEXT_DIM = Colors.rgb(129, 139, 140) # Gray
    TEXT_MUTED = Colors.rgb(90, 99, 102) # Muted
    
    # UI elements
    BORDER = Colors.rgb(71, 84, 89)      # Slate
    
    @staticmethod
    def severity_color(severity: Severity) -> str:
        """Get color for severity level."""
        return {
            Severity.CRITICAL: Theme.CRITICAL,
            Severity.HIGH: Theme.HIGH,
            Severity.MEDIUM: Theme.MEDIUM,
            Severity.LOW: Theme.LOW,
            Severity.INFO: Theme.INFO_SEV,
        }.get(severity, Theme.TEXT)
    
    @staticmethod
    def status_color(status: Status) -> str:
        """Get color for status."""
        return {
            Status.PASS: Theme.SUCCESS,
            Status.FAIL: Theme.ERROR,
            Status.WARNING: Theme.WARNING,
            Status.SKIP: Theme.TEXT_MUTED,
            Status.ERROR: Theme.CRITICAL,
        }.get(status, Theme.TEXT)


# ═══════════════════════════════════════════════════════════════════════════════
# Terminal Utilities
# ═══════════════════════════════════════════════════════════════════════════════

def supports_color() -> bool:
    """Check if terminal supports color output."""
    if os.getenv("NO_COLOR"):
        return False
    if os.getenv("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def get_terminal_width() -> int:
    """Get terminal width, default 80."""
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 80


def clear_line() -> None:
    """Clear current line."""
    sys.stdout.write("\033[2K\r")
    sys.stdout.flush()


def move_up(lines: int = 1) -> None:
    """Move cursor up N lines."""
    sys.stdout.write(f"\033[{lines}A")
    sys.stdout.flush()


def hide_cursor() -> None:
    """Hide cursor."""
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()


def show_cursor() -> None:
    """Show cursor."""
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()


# ═══════════════════════════════════════════════════════════════════════════════
# Icons & Symbols
# ═══════════════════════════════════════════════════════════════════════════════

class Icons:
    """Unicode icons for CLI output."""
    
    # Status icons
    PASS = "✓"
    FAIL = "✗"
    WARNING = "⚠"
    SKIP = "○"
    ERROR = "⊘"
    
    # Severity icons
    CRITICAL = "🔴"
    HIGH = "🟠"
    MEDIUM = "🟡"
    LOW = "🔵"
    INFO = "🟣"
    
    # Progress
    SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    SPINNER_DOTS = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
    PROGRESS_FULL = "█"
    PROGRESS_EMPTY = "░"
    PROGRESS_PARTIAL = ["▏", "▎", "▍", "▌", "▋", "▊", "▉"]
    
    # Decorative
    ARROW = "→"
    BULLET = "•"
    DIAMOND = "◆"
    STAR = "★"
    SHIELD = "🛡️"
    LOCK = "🔒"
    CHECK = "☑"
    BOX = "☐"
    
    # Box drawing
    BOX_TL = "╭"
    BOX_TR = "╮"
    BOX_BL = "╰"
    BOX_BR = "╯"
    BOX_H = "─"
    BOX_V = "│"
    BOX_DOUBLE_H = "═"
    
    @staticmethod
    def status_icon(status: Status) -> str:
        """Get icon for status."""
        return {
            Status.PASS: Icons.PASS,
            Status.FAIL: Icons.FAIL,
            Status.WARNING: Icons.WARNING,
            Status.SKIP: Icons.SKIP,
            Status.ERROR: Icons.ERROR,
        }.get(status, "?")
    
    @staticmethod
    def severity_icon(severity: Severity) -> str:
        """Get icon for severity."""
        return {
            Severity.CRITICAL: Icons.CRITICAL,
            Severity.HIGH: Icons.HIGH,
            Severity.MEDIUM: Icons.MEDIUM,
            Severity.LOW: Icons.LOW,
            Severity.INFO: Icons.INFO,
        }.get(severity, Icons.BULLET)


# ═══════════════════════════════════════════════════════════════════════════════
# ASCII Art Banner
# ═══════════════════════════════════════════════════════════════════════════════

BANNER = r"""
                         ╭─────────────────────────────────────────╮
                         │                                         │
  ███╗   ███╗ █████╗  ██████╗███████╗███████╗███╗   ██╗████████╗██╗   ██╗  │
  ████╗ ████║██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝╚██╗ ██╔╝  │
  ██╔████╔██║███████║██║     ███████╗█████╗  ██╔██╗ ██║   ██║    ╚████╔╝   │
  ██║╚██╔╝██║██╔══██║██║     ╚════██║██╔══╝  ██║╚██╗██║   ██║     ╚██╔╝    │
  ██║ ╚═╝ ██║██║  ██║╚██████╗███████║███████╗██║ ╚████║   ██║      ██║     │
  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝      ╚═╝     │
                         │                                         │
                         │      macOS Security Audit Tool          │
                         ╰─────────────────────────────────────────╯
"""

BANNER_SIMPLE = r"""
  ╔══════════════════════════════════════════════════════════════════════╗
  ║                                                                      ║
  ║   ███╗   ███╗ █████╗  ██████╗███████╗███████╗███╗   ██╗████████╗   ║
  ║   ████╗ ████║██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝   ║
  ║   ██╔████╔██║███████║██║     ███████╗█████╗  ██╔██╗ ██║   ██║      ║
  ║   ██║╚██╔╝██║██╔══██║██║     ╚════██║██╔══╝  ██║╚██╗██║   ██║      ║
  ║   ██║ ╚═╝ ██║██║  ██║╚██████╗███████║███████╗██║ ╚████║   ██║      ║
  ║   ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝      ║
  ║                                                                      ║
  ║               🛡️  macOS Security Audit Tool  🔒                     ║
  ║                                                                      ║
  ╚══════════════════════════════════════════════════════════════════════╝
"""

BANNER_COMPACT = r"""
   ╭──────────────────────────────────────────────────────────────────────╮
   │  ╔╦╗╔═╗╔═╗╔═╗╔═╗╔╗╔╔╦╗╦═╗╦ ╦                                         │
   │  ║║║╠═╣║  ╚═╗║╣ ║║║ ║ ╠╦╝╚╦╝  🛡️  macOS Security Audit Tool         │
   │  ╩ ╩╩ ╩╚═╝╚═╝╚═╝╝╚╝ ╩ ╩╚═ ╩                                          │
   ╰──────────────────────────────────────────────────────────────────────╯
"""

BANNER_MINIMAL = r"""
╭─────────────────────────────────────────────────────────────────╮
│  🛡️  macSentry - macOS Security Audit                          │
╰─────────────────────────────────────────────────────────────────╯
"""


# ═══════════════════════════════════════════════════════════════════════════════
# Spinner Animation
# ═══════════════════════════════════════════════════════════════════════════════

class Spinner:
    """Animated spinner for long-running operations."""
    
    def __init__(
        self,
        message: str = "Loading",
        frames: List[str] | None = None,
        color: str = Theme.ACCENT,
    ):
        self.message = message
        self.frames = frames or Icons.SPINNER_DOTS
        self.color = color
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._use_color = supports_color()
    
    def _animate(self) -> None:
        frame_iter = itertools.cycle(self.frames)
        while self._running:
            frame = next(frame_iter)
            if self._use_color:
                line = f"\r  {self.color}{frame}{Colors.RESET} {self.message}"
            else:
                line = f"\r  {frame} {self.message}"
            sys.stdout.write(line)
            sys.stdout.flush()
            time.sleep(0.08)
    
    def start(self) -> "Spinner":
        """Start the spinner animation."""
        if supports_color():
            hide_cursor()
        self._running = True
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()
        return self
    
    def stop(self, final_message: str = "", icon: str = Icons.PASS, color: str = Theme.SUCCESS) -> None:
        """Stop the spinner with a final message."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=0.2)
        clear_line()
        if final_message:
            if self._use_color:
                print(f"  {color}{icon}{Colors.RESET} {final_message}")
            else:
                print(f"  {icon} {final_message}")
        if supports_color():
            show_cursor()
    
    def __enter__(self) -> "Spinner":
        return self.start()
    
    def __exit__(self, *args) -> None:
        self.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# Progress Bar
# ═══════════════════════════════════════════════════════════════════════════════

class ProgressBar:
    """Beautiful progress bar with percentage and ETA."""
    
    def __init__(
        self,
        total: int,
        width: int = 40,
        title: str = "Progress",
        show_percentage: bool = True,
        show_count: bool = True,
        show_eta: bool = True,
    ):
        self.total = total
        self.width = width
        self.title = title
        self.show_percentage = show_percentage
        self.show_count = show_count
        self.show_eta = show_eta
        self.current = 0
        self.start_time = time.time()
        self._use_color = supports_color()
        self._last_update_time = self.start_time
        self._smoothed_rate: float = 0.0  # Exponential moving average of items/sec
    
    def _format_eta(self, seconds: float) -> str:
        """Format ETA in human-readable form."""
        if seconds < 0 or seconds > 3600:  # Cap at 1 hour
            return "--:--"
        minutes, secs = divmod(int(seconds), 60)
        return f"{minutes:02d}:{secs:02d}"
    
    def _calculate_eta(self) -> str:
        """Calculate estimated time remaining."""
        if self.current == 0:
            return "--:--"
        
        elapsed = time.time() - self.start_time
        if elapsed < 0.5:  # Need at least 0.5s of data
            return "--:--"
        
        # Calculate rate with smoothing
        current_rate = self.current / elapsed
        if self._smoothed_rate == 0:
            self._smoothed_rate = current_rate
        else:
            # Exponential moving average (more weight to recent)
            self._smoothed_rate = 0.7 * current_rate + 0.3 * self._smoothed_rate
        
        remaining = self.total - self.current
        if self._smoothed_rate > 0:
            eta_seconds = remaining / self._smoothed_rate
            return self._format_eta(eta_seconds)
        return "--:--"
    
    def update(self, current: int | None = None, message: str = "") -> None:
        """Update progress bar."""
        if current is not None:
            self.current = current
        else:
            self.current += 1
        
        self._last_update_time = time.time()
        
        # Calculate progress
        progress = min(self.current / max(self.total, 1), 1.0)
        filled = int(self.width * progress)
        
        # Build bar
        bar_filled = Icons.PROGRESS_FULL * filled
        bar_empty = Icons.PROGRESS_EMPTY * (self.width - filled)
        
        # Build status text
        parts = []
        if self.show_percentage:
            parts.append(f"{progress * 100:5.1f}%")
        if self.show_count:
            parts.append(f"{self.current}/{self.total}")
        if self.show_eta and self.current < self.total:
            eta = self._calculate_eta()
            parts.append(f"ETA {eta}")
        status = " ".join(parts)
        
        # Colorize
        if self._use_color:
            bar = f"{Theme.ACCENT}{bar_filled}{Colors.RESET}{Theme.TEXT_MUTED}{bar_empty}{Colors.RESET}"
            title = f"{Theme.TEXT}{self.title}{Colors.RESET}"
            status_colored = f"{Theme.TEXT_DIM}{status}{Colors.RESET}"
        else:
            bar = f"{bar_filled}{bar_empty}"
            title = self.title
            status_colored = status
        
        # Print
        line = f"\r  {title} │{bar}│ {status_colored}"
        if message:
            # Truncate message if too long
            max_msg_len = get_terminal_width() - len(line) - 5
            if len(message) > max_msg_len:
                message = message[:max_msg_len - 3] + "..."
            if self._use_color:
                line += f"  {Theme.TEXT_DIM}{message}{Colors.RESET}"
            else:
                line += f"  {message}"
        
        sys.stdout.write(line)
        sys.stdout.flush()
    
    def finish(self, message: str = "Complete") -> None:
        """Complete the progress bar."""
        elapsed = time.time() - self.start_time
        clear_line()
        if self._use_color:
            print(f"  {Theme.SUCCESS}{Icons.PASS}{Colors.RESET} {self.title}: {message} ({elapsed:.1f}s)")
        else:
            print(f"  {Icons.PASS} {self.title}: {message} ({elapsed:.1f}s)")


# ═══════════════════════════════════════════════════════════════════════════════
# Console Output
# ═══════════════════════════════════════════════════════════════════════════════

class Console:
    """Pretty console output."""
    
    def __init__(self, color: bool | None = None):
        self.use_color = color if color is not None else supports_color()
        self.width = get_terminal_width()
    
    def _c(self, text: str, color: str) -> str:
        """Colorize text if colors enabled."""
        if self.use_color:
            return f"{color}{text}{Colors.RESET}"
        return text
    
    def banner(self, compact: bool = False) -> None:
        """Print the application banner."""
        banner_text = BANNER_MINIMAL if compact else BANNER_COMPACT
        if self.use_color:
            # Colorize the banner
            for line in banner_text.split("\n"):
                # Color box drawing characters
                colored = line
                for char in "╭╮╰╯│─═╔╗╚╝║":
                    colored = colored.replace(char, f"{Theme.BORDER}{char}{Colors.RESET}")
                # Color the title text
                colored = colored.replace("macSentry", f"{Theme.ACCENT}macSentry{Colors.RESET}")
                colored = colored.replace("macOS Security Audit", f"{Theme.TEXT_DIM}macOS Security Audit{Colors.RESET}")
                print(colored)
        else:
            print(banner_text)
    
    def header(self, text: str) -> None:
        """Print a section header."""
        width = min(70, self.width - 4)
        line = Icons.BOX_H * width
        print()
        if self.use_color:
            print(f"  {Theme.BORDER}{Icons.BOX_TL}{line}{Icons.BOX_TR}{Colors.RESET}")
            print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET} {Theme.ACCENT}{Colors.BOLD}{text.center(width - 2)}{Colors.RESET} {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
            print(f"  {Theme.BORDER}{Icons.BOX_BL}{line}{Icons.BOX_BR}{Colors.RESET}")
        else:
            print(f"  {Icons.BOX_TL}{line}{Icons.BOX_TR}")
            print(f"  {Icons.BOX_V} {text.center(width - 2)} {Icons.BOX_V}")
            print(f"  {Icons.BOX_BL}{line}{Icons.BOX_BR}")
    
    def subheader(self, text: str) -> None:
        """Print a subsection header."""
        print()
        if self.use_color:
            print(f"  {Theme.ACCENT}{Icons.DIAMOND}{Colors.RESET} {Theme.TEXT}{Colors.BOLD}{text}{Colors.RESET}")
            print(f"  {Theme.TEXT_MUTED}{'─' * (len(text) + 2)}{Colors.RESET}")
        else:
            print(f"  {Icons.DIAMOND} {text}")
            print(f"  {'─' * (len(text) + 2)}")
    
    def info(self, key: str, value: str) -> None:
        """Print key-value info."""
        if self.use_color:
            print(f"    {Theme.TEXT_DIM}{key}:{Colors.RESET} {Theme.TEXT}{value}{Colors.RESET}")
        else:
            print(f"    {key}: {value}")
    
    def success(self, message: str) -> None:
        """Print success message."""
        if self.use_color:
            print(f"  {Theme.SUCCESS}{Icons.PASS}{Colors.RESET} {message}")
        else:
            print(f"  {Icons.PASS} {message}")
    
    def error(self, message: str) -> None:
        """Print error message."""
        if self.use_color:
            print(f"  {Theme.ERROR}{Icons.FAIL}{Colors.RESET} {message}")
        else:
            print(f"  {Icons.FAIL} {message}")
    
    def warning(self, message: str) -> None:
        """Print warning message."""
        if self.use_color:
            print(f"  {Theme.WARNING}{Icons.WARNING}{Colors.RESET} {message}")
        else:
            print(f"  {Icons.WARNING} {message}")
    
    def dim(self, message: str) -> None:
        """Print dimmed message."""
        if self.use_color:
            print(f"  {Theme.TEXT_MUTED}{message}{Colors.RESET}")
        else:
            print(f"  {message}")
    
    def blank(self) -> None:
        """Print blank line."""
        print()
    
    def separator(self) -> None:
        """Print separator line."""
        width = min(70, self.width - 4)
        if self.use_color:
            print(f"  {Theme.TEXT_MUTED}{'─' * width}{Colors.RESET}")
        else:
            print(f"  {'─' * width}")
    
    def category_label(self, category: str, count: int) -> None:
        """Print a category label for grouping checks.
        
        Args:
            category: Human-readable category name.
            count: Number of checks in this category.
        """
        if self.use_color:
            print(f"\n    {Theme.ACCENT}{Icons.DIAMOND}{Colors.RESET} {Theme.TEXT_DIM}{category}{Colors.RESET} {Theme.TEXT_MUTED}({count}){Colors.RESET}")
        else:
            print(f"\n    {Icons.DIAMOND} {category} ({count})")
    
    def check_result(self, result: CheckResult, show_details: bool = False, show_verbose_hint: bool = True) -> None:
        """Print a single check result.
        
        Args:
            result: The check result to display.
            show_details: If True, show full details dict.
            show_verbose_hint: If True and details exist but not shown, hint about --verbose.
        """
        status_icon = Icons.status_icon(result.status)
        status_color = Theme.status_color(result.status)
        severity_icon = Icons.severity_icon(result.severity)
        severity_color = Theme.severity_color(result.severity)
        
        if self.use_color:
            status_badge = f"{status_color}{status_icon}{Colors.RESET}"
            severity_badge = f"{severity_color}[{result.severity.value}]{Colors.RESET}"
            name = f"{Theme.TEXT}{result.check_name}{Colors.RESET}"
        else:
            status_badge = status_icon
            severity_badge = f"[{result.severity.value}]"
            name = result.check_name
        
        print(f"  {status_badge} {severity_badge} {name}")
        
        # Message
        if self.use_color:
            print(f"     {Theme.TEXT_DIM}{Icons.ARROW} {result.message}{Colors.RESET}")
        else:
            print(f"     {Icons.ARROW} {result.message}")
        
        # Remediation for failures
        if result.status in (Status.FAIL, Status.WARNING) and result.remediation:
            if self.use_color:
                print(f"     {Theme.WARNING}{Icons.BULLET} Fix: {result.remediation}{Colors.RESET}")
            else:
                print(f"     {Icons.BULLET} Fix: {result.remediation}")
        
        # Details if requested
        if show_details and result.details:
            # Format details nicely
            self._print_details(result.details)
        elif show_verbose_hint and result.details and result.status in (Status.FAIL, Status.WARNING):
            # Check if details contain actionable info (lists, counts)
            has_actionable = any(
                isinstance(v, (list, dict)) and len(v) > 0
                for v in result.details.values()
            )
            if has_actionable:
                if self.use_color:
                    print(f"     {Theme.TEXT_MUTED}{Icons.INFO} Run with --verbose for full details{Colors.RESET}")
                else:
                    print(f"     {Icons.INFO} Run with --verbose for full details")
    
    def _print_details(self, details: dict) -> None:
        """Print details dict in a readable format."""
        for key, value in details.items():
            if isinstance(value, list) and value:
                if self.use_color:
                    print(f"     {Theme.TEXT_MUTED}{key}:{Colors.RESET}")
                else:
                    print(f"     {key}:")
                for item in value[:10]:  # Limit to 10 items
                    if self.use_color:
                        print(f"       {Theme.TEXT_DIM}- {item}{Colors.RESET}")
                    else:
                        print(f"       - {item}")
                if len(value) > 10:
                    remaining = len(value) - 10
                    if self.use_color:
                        print(f"       {Theme.TEXT_MUTED}... and {remaining} more{Colors.RESET}")
                    else:
                        print(f"       ... and {remaining} more")
            elif isinstance(value, dict) and value:
                if self.use_color:
                    print(f"     {Theme.TEXT_MUTED}{key}:{Colors.RESET}")
                else:
                    print(f"     {key}:")
                for k, v in list(value.items())[:10]:
                    if self.use_color:
                        print(f"       {Theme.TEXT_DIM}{k}: {v}{Colors.RESET}")
                    else:
                        print(f"       {k}: {v}")
            elif value:
                if self.use_color:
                    print(f"     {Theme.TEXT_MUTED}{key}: {value}{Colors.RESET}")
                else:
                    print(f"     {key}: {value}")
    
    def summary_box(self, stats: dict[str, int]) -> None:
        """Print a summary statistics box."""
        total = stats.get("total", 0)
        passed = stats.get("pass", 0)
        failed = stats.get("fail", 0)
        warnings = stats.get("warning", 0)
        skipped = stats.get("skip", 0)
        errors = stats.get("error", 0)
        
        # Calculate pass rate
        executed = total - skipped
        pass_rate = (passed / executed * 100) if executed > 0 else 0
        
        width = 50
        line = Icons.BOX_H * width
        
        print()
        if self.use_color:
            print(f"  {Theme.BORDER}{Icons.BOX_TL}{line}{Icons.BOX_TR}{Colors.RESET}")
            print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET} {Theme.ACCENT}{Colors.BOLD}{'SCAN SUMMARY'.center(width - 2)}{Colors.RESET} {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
            print(f"  {Theme.BORDER}├{'─' * width}┤{Colors.RESET}")
            
            # Stats rows
            print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}  Total Checks:  {Theme.TEXT}{total:>5}{Colors.RESET}{'':>{width - 22}}{Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
            print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}  {Theme.SUCCESS}{Icons.PASS} Passed{Colors.RESET}:      {Theme.SUCCESS}{passed:>5}{Colors.RESET}{'':>{width - 22}}{Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
            print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}  {Theme.ERROR}{Icons.FAIL} Failed{Colors.RESET}:      {Theme.ERROR}{failed:>5}{Colors.RESET}{'':>{width - 22}}{Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
            print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}  {Theme.WARNING}{Icons.WARNING} Warnings{Colors.RESET}:    {Theme.WARNING}{warnings:>5}{Colors.RESET}{'':>{width - 22}}{Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
            print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}  {Theme.TEXT_MUTED}{Icons.SKIP} Skipped{Colors.RESET}:     {Theme.TEXT_MUTED}{skipped:>5}{Colors.RESET}{'':>{width - 22}}{Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
            
            if errors > 0:
                print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}  {Theme.CRITICAL}{Icons.ERROR} Errors{Colors.RESET}:      {Theme.CRITICAL}{errors:>5}{Colors.RESET}{'':>{width - 22}}{Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
            
            print(f"  {Theme.BORDER}├{'─' * width}┤{Colors.RESET}")
            
            # Pass rate bar
            bar_width = 30
            filled = int(bar_width * pass_rate / 100)
            bar = f"{Theme.SUCCESS}{Icons.PROGRESS_FULL * filled}{Colors.RESET}{Theme.TEXT_MUTED}{Icons.PROGRESS_EMPTY * (bar_width - filled)}{Colors.RESET}"
            
            rate_color = Theme.SUCCESS if pass_rate >= 80 else (Theme.WARNING if pass_rate >= 60 else Theme.ERROR)
            print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}  Pass Rate: {bar} {rate_color}{pass_rate:>5.1f}%{Colors.RESET} {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
            
            print(f"  {Theme.BORDER}{Icons.BOX_BL}{line}{Icons.BOX_BR}{Colors.RESET}")
        else:
            print(f"  +{'-' * width}+")
            print(f"  | {'SCAN SUMMARY'.center(width - 2)} |")
            print(f"  +{'-' * width}+")
            print(f"  |  Total: {total:>5}  |  Passed: {passed:>4}  |  Failed: {failed:>4}  |")
            print(f"  |  Warnings: {warnings:>4}  |  Skipped: {skipped:>4}  |  Errors: {errors:>4}  |")
            print(f"  +{'-' * width}+")
            print(f"  |  Pass Rate: {pass_rate:>5.1f}%{'':>{width - 20}}|")
            print(f"  +{'-' * width}+")
    
    def severity_breakdown(self, stats: dict[str, int]) -> None:
        """Print severity breakdown."""
        critical = stats.get("critical", 0)
        high = stats.get("high", 0)
        medium = stats.get("medium", 0)
        low = stats.get("low", 0)
        info = stats.get("info", 0)
        
        if self.use_color:
            print(f"  {Theme.TEXT_DIM}Severity Breakdown:{Colors.RESET}")
            if critical > 0:
                print(f"    {Theme.CRITICAL}{Icons.CRITICAL} Critical: {critical}{Colors.RESET}")
            if high > 0:
                print(f"    {Theme.HIGH}{Icons.HIGH} High: {high}{Colors.RESET}")
            if medium > 0:
                print(f"    {Theme.MEDIUM}{Icons.MEDIUM} Medium: {medium}{Colors.RESET}")
            if low > 0:
                print(f"    {Theme.LOW}{Icons.LOW} Low: {low}{Colors.RESET}")
            if info > 0:
                print(f"    {Theme.INFO_SEV}{Icons.INFO} Info: {info}{Colors.RESET}")
        else:
            print(f"  Severity Breakdown:")
            print(f"    Critical: {critical} | High: {high} | Medium: {medium} | Low: {low} | Info: {info}")
    
    def recommended_actions(self, actions: List[dict]) -> None:
        """Print a recommended actions box.
        
        Args:
            actions: List of dicts with keys: severity, title, risk, time_minutes
                Example: [
                    {"severity": "HIGH", "title": "Review REAPER.app entitlements",
                     "risk": "Debuggable in production (get-task-allow)", "time_minutes": 5},
                ]
        """
        if not actions:
            return
        
        width = 52
        line = Icons.BOX_H * width
        
        print()
        if self.use_color:
            # Top border
            print(f"  {Theme.BORDER}{Icons.BOX_TL}{line}{Icons.BOX_TR}{Colors.RESET}")
            # Title
            title = "RECOMMENDED ACTIONS"
            padding = (width - len(title)) // 2
            print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}{' ' * padding}{Theme.ACCENT}{Colors.BOLD}{title}{Colors.RESET}{' ' * (width - padding - len(title))}{Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
            # Separator
            print(f"  {Theme.BORDER}├{'─' * width}┤{Colors.RESET}")
            
            # Actions
            for i, action in enumerate(actions[:5], 1):  # Limit to 5 actions
                severity = action.get("severity", "MEDIUM")
                title = action.get("title", "Review issue")
                risk = action.get("risk", "")
                time_est = action.get("time_minutes", 5)
                
                # Severity color
                sev_color = {
                    "CRITICAL": Theme.CRITICAL,
                    "HIGH": Theme.ERROR,
                    "MEDIUM": Theme.WARNING,
                    "LOW": Theme.LOW,
                }.get(severity, Theme.TEXT_DIM)
                
                # Main line with severity badge
                sev_badge = f"[{severity}]"
                main_line = f"  {i}. {sev_badge} {title}"
                if len(main_line) > width - 2:
                    main_line = main_line[:width - 5] + "..."
                print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}  {sev_color}{i}. [{severity}]{Colors.RESET} {title[:width - 14]:<{width - 14}}{Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
                
                # Risk line
                if risk:
                    risk_display = risk if len(risk) <= width - 10 else risk[:width - 13] + "..."
                    print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}     {Theme.TEXT_DIM}Risk: {risk_display}{Colors.RESET}{' ' * max(0, width - 11 - len(risk_display))}{Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
                
                # Time estimate
                print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}     {Theme.TEXT_MUTED}Time: {time_est} minute{'s' if time_est != 1 else ''}{Colors.RESET}{' ' * (width - 18 - len(str(time_est)))}{Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
                
                # Blank line between actions (except last)
                if i < len(actions[:5]):
                    print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}{' ' * width}{Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
            
            # Footer separator
            print(f"  {Theme.BORDER}├{'─' * width}┤{Colors.RESET}")
            
            # Footer with links
            print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}  📚 {Theme.TEXT_DIM}Detailed remediation: macsentry.app/docs{Colors.RESET}{' ' * 6}{Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
            print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}  💾 {Theme.TEXT_DIM}Export results: macsentry --format json{Colors.RESET}{' ' * 7}{Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
            print(f"  {Theme.BORDER}{Icons.BOX_V}{Colors.RESET}  🔄 {Theme.TEXT_DIM}Schedule daily: macsentry --install-schedule{Colors.RESET}{' ' * 2}{Theme.BORDER}{Icons.BOX_V}{Colors.RESET}")
            
            # Bottom border
            print(f"  {Theme.BORDER}{Icons.BOX_BL}{line}{Icons.BOX_BR}{Colors.RESET}")
        else:
            # Non-color version
            print(f"  +{'-' * width}+")
            print(f"  | {'RECOMMENDED ACTIONS'.center(width - 2)} |")
            print(f"  +{'-' * width}+")
            for i, action in enumerate(actions[:5], 1):
                severity = action.get("severity", "MEDIUM")
                title = action.get("title", "Review issue")[:35]
                risk = action.get("risk", "")[:35]
                time_est = action.get("time_minutes", 5)
                print(f"  | {i}. [{severity}] {title:<35} |")
                if risk:
                    print(f"  |    Risk: {risk:<40} |")
                print(f"  |    Time: {time_est} minutes{' ' * (width - 20)} |")
            print(f"  +{'-' * width}+")
    
    def performance_metrics(self, total_time: float, slowest_checks: List[tuple]) -> None:
        """Print performance metrics.
        
        Args:
            total_time: Total execution time in seconds.
            slowest_checks: List of (check_name, elapsed_time, reason) tuples.
        """
        print()
        if self.use_color:
            print(f"  {Theme.ACCENT}◆{Colors.RESET} {Theme.TEXT}{Colors.BOLD}Performance{Colors.RESET}")
            print(f"  {Theme.TEXT_MUTED}──────────────{Colors.RESET}")
            print(f"    {Theme.TEXT_DIM}Total time:{Colors.RESET} {Theme.TEXT}{total_time:.1f}s{Colors.RESET}")
            
            if slowest_checks:
                print(f"    {Theme.TEXT_DIM}Slowest checks:{Colors.RESET}")
                for check_name, elapsed, reason in slowest_checks[:5]:
                    # Color code by time
                    if elapsed > 5:
                        time_color = Theme.ERROR
                    elif elapsed > 2:
                        time_color = Theme.WARNING
                    else:
                        time_color = Theme.TEXT_DIM
                    
                    reason_text = f" ({reason})" if reason else ""
                    print(f"      {Theme.TEXT_DIM}•{Colors.RESET} {check_name}: {time_color}{elapsed:.1f}s{Colors.RESET}{Theme.TEXT_MUTED}{reason_text}{Colors.RESET}")
        else:
            print(f"  ◆ Performance")
            print(f"  ──────────────")
            print(f"    Total time: {total_time:.1f}s")
            if slowest_checks:
                print(f"    Slowest checks:")
                for check_name, elapsed, reason in slowest_checks[:5]:
                    reason_text = f" ({reason})" if reason else ""
                    print(f"      • {check_name}: {elapsed:.1f}s{reason_text}")


# ═══════════════════════════════════════════════════════════════════════════════
# Live Check Runner Display
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class LiveCheckState:
    """State for live check execution display."""
    check_name: str
    status: str  # "running", "done"
    result: Optional[CheckResult] = None


class LiveProgress:
    """Display live progress of security checks."""
    
    def __init__(self, total: int, console: Console | None = None):
        self.total = total
        self.console = console or Console()
        self.completed = 0
        self.results: List[CheckResult] = []
        self.current_check: str = ""
        self._lock = threading.Lock()
        self._start_time = time.time()
    
    def start_check(self, check_name: str) -> None:
        """Mark a check as starting."""
        with self._lock:
            self.current_check = check_name
            self._update_display()
    
    def complete_check(self, result: CheckResult) -> None:
        """Mark a check as complete."""
        with self._lock:
            self.completed += 1
            self.results.append(result)
            self._print_result(result)
            self._update_display()
    
    def _update_display(self) -> None:
        """Update the progress display."""
        progress = self.completed / max(self.total, 1)
        bar_width = 30
        filled = int(bar_width * progress)
        
        if self.console.use_color:
            bar = f"{Theme.ACCENT}{Icons.PROGRESS_FULL * filled}{Colors.RESET}{Theme.TEXT_MUTED}{Icons.PROGRESS_EMPTY * (bar_width - filled)}{Colors.RESET}"
            status = f"{Theme.TEXT_DIM}[{self.completed}/{self.total}]{Colors.RESET}"
        else:
            bar = f"{Icons.PROGRESS_FULL * filled}{Icons.PROGRESS_EMPTY * (bar_width - filled)}"
            status = f"[{self.completed}/{self.total}]"
        
        # Show current check being run
        current = self.current_check if self.current_check else "..."
        if len(current) > 40:
            current = current[:37] + "..."
        
        sys.stdout.write(f"\r  {bar} {status} Running: {current}{'':20}")
        sys.stdout.flush()
    
    def _print_result(self, result: CheckResult) -> None:
        """Print a single result on its own line."""
        clear_line()
        
        icon = Icons.status_icon(result.status)
        if self.console.use_color:
            color = Theme.status_color(result.status)
            print(f"  {color}{icon}{Colors.RESET} {result.check_name}")
        else:
            print(f"  {icon} {result.check_name}")
    
    def finish(self) -> None:
        """Complete the progress display."""
        clear_line()
        elapsed = time.time() - self._start_time
        
        if self.console.use_color:
            print(f"  {Theme.SUCCESS}{Icons.PASS}{Colors.RESET} Completed {self.total} checks in {elapsed:.1f}s")
        else:
            print(f"  {Icons.PASS} Completed {self.total} checks in {elapsed:.1f}s")


# ═══════════════════════════════════════════════════════════════════════════════
# Module Exports
# ═══════════════════════════════════════════════════════════════════════════════

__all__ = [
    "Colors",
    "Theme",
    "Icons",
    "Console",
    "Spinner",
    "ProgressBar",
    "LiveProgress",
    "supports_color",
    "get_terminal_width",
    "BANNER",
    "BANNER_SIMPLE",
    "BANNER_COMPACT",
    "BANNER_MINIMAL",
]
