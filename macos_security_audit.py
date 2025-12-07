"""macSentry - macOS Security Audit main entry point."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import logging.handlers
import os
import platform
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from checks import load_checks
from checks.base import CheckRegistry, CheckResult, SecurityCheck, Severity, Status
from cli import (
    Console,
    Icons,
    LiveProgress,
    ProgressBar,
    Spinner,
    Theme,
    Colors,
    show_cursor,
    hide_cursor,
)
from utils import (
    CommandExecutionError,
    format_html_report,
    format_json_report,
    format_text_report,
    validate_system_requirements,
    get_extended_system_info,
    format_hardware_summary,
    get_hardware_info,
)

__version__ = "1.2.0"

_LOG_DIR = Path.home() / "Library" / "Logs" / "macos-security-audit"
_STATE_DIR = Path.home() / "Library" / "Application Support" / "macos-security-audit"
_FIRST_RUN_MARKER = _STATE_DIR / ".first_run_complete"
_DEFAULT_MIN_SEVERITY = Severity.INFO
_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

# Verbosity levels
VERBOSITY_QUIET = 0      # Only errors and summary
VERBOSITY_NORMAL = 1     # Issues and warnings
VERBOSITY_VERBOSE = 2    # Include passed checks
VERBOSITY_DEBUG = 3      # Include timing and internal details


class _InstantiationFailureStub(SecurityCheck):
    """Placeholder check used when instantiation fails."""

    auto_register = False
    name = "check-instantiation-error"
    description = "Placeholder for failed check instantiation"
    category = "internal"

    def __init__(self, original_cls: type[SecurityCheck]):
        self.original_cls = original_cls
        self._original_name = getattr(original_cls, "name", original_cls.__name__)
        self._original_category = getattr(original_cls, "category", "general")
        self._original_severity = getattr(original_cls, "severity", Severity.INFO)
        self._original_remediation = getattr(
            original_cls, "remediation", "Review system configuration."
        )
        super().__init__()
        self.name = f"{self._original_name} (unavailable)"
        self.category = str(self._original_category)
        if isinstance(self._original_severity, Severity):
            severity = self._original_severity
        else:
            try:
                severity = Severity(str(self._original_severity))
            except ValueError:
                severity = Severity.INFO
        self.severity = severity
        self.remediation = str(self._original_remediation)

    def run(self) -> CheckResult:
        return CheckResult(
            check_name=self.name,
            status=Status.ERROR,
            severity=self.severity,
            message=(
                "Original check could not be instantiated. See logs for stack trace."
            ),
            remediation=self.remediation,
            details={"original_class": self.original_cls.__name__},
        )


def configure_logging(level: int = logging.INFO) -> None:
    """Configure logging for the application.

    Logs are written to ~/Library/Logs/macos-security-audit/audit.log
    with automatic rotation at 5MB and 3 backup files retained.
    """
    _LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = _LOG_DIR / "audit.log"

    formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Rotating file handler: 5MB max, keep 3 backups
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.WARNING)

    logging.basicConfig(level=level, handlers=[file_handler, console_handler])


@dataclass
class CheckTiming:
    """Timing information for a single check."""
    check_name: str
    elapsed_time: float
    status: Status
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_name": self.check_name,
            "elapsed_time": round(self.elapsed_time, 3),
            "status": self.status.value,
        }


@dataclass
class ExecutionOptions:
    categories: Sequence[str]
    include_sudo_checks: bool
    dry_run: bool
    verbosity: int  # 0=quiet, 1=normal, 2=verbose, 3=debug
    min_severity: Severity
    show_timing: bool = False
    
    @property
    def verbose(self) -> bool:
        return self.verbosity >= VERBOSITY_VERBOSE


@dataclass
class OutputOptions:
    format: str
    output_path: Path | None
    export_detailed: bool = False  # Export with device/timing metadata
    timestamp: bool = False  # Add timestamp to filename


def _is_first_run() -> bool:
    """Check if this is the first time running the tool."""
    return not _FIRST_RUN_MARKER.exists()


def _mark_first_run_complete() -> None:
    """Mark that the first run has completed."""
    try:
        _STATE_DIR.mkdir(parents=True, exist_ok=True)
        _FIRST_RUN_MARKER.write_text(
            datetime.now().isoformat(),
            encoding="utf-8"
        )
    except OSError:
        pass  # Silently fail if we can't write the marker


def _display_first_run_tips(console: Console, output_path: Path | None = None) -> None:
    """Display helpful tips for first-time users."""
    console.blank()
    if console.use_color:
        print(f"  {Theme.SUCCESS}{Icons.STAR}{Colors.RESET} {Theme.TEXT}{Colors.BOLD}First audit complete!{Colors.RESET}")
    else:
        print(f"  {Icons.STAR} First audit complete!")
    
    console.blank()
    console.dim("Consider these next steps:")
    
    tips = [
        ("Set up daily checks", "macsentry --install-schedule"),
        ("Fix critical issues first", "FileVault, Firewall, Gatekeeper"),
        ("Export detailed report", "macsentry --format html -o report.html"),
    ]
    
    if output_path:
        tips.append(("View your report", f"open {output_path}"))
    
    for tip_title, tip_detail in tips:
        if console.use_color:
            print(f"    {Theme.ACCENT}{Icons.BULLET}{Colors.RESET} {Theme.TEXT}{tip_title}:{Colors.RESET} {Theme.TEXT_DIM}{tip_detail}{Colors.RESET}")
        else:
            print(f"    {Icons.BULLET} {tip_title}: {tip_detail}")
    
    console.blank()


def _generate_timestamped_path(base_path: Path) -> Path:
    """Generate a timestamped version of the output path.
    
    Example: report.html -> report_2024-01-15_143022.html
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    stem = base_path.stem
    suffix = base_path.suffix
    return base_path.parent / f"{stem}_{timestamp}{suffix}"


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="macSentry - macOS Security Audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          Run all checks with normal output
  %(prog)s --verbose                Show all checks including passed
  %(prog)s --debug                  Show timing and debug information
  %(prog)s --format json -o out.json  Export detailed JSON report
  %(prog)s --categories encryption  Run only encryption checks
""",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--categories",
        type=str,
        help="Comma-separated list of categories to run (default: all)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "html"],
        default="text",
        help="Report output format",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Write report to file instead of stdout",
    )
    parser.add_argument(
        "--min-severity",
        type=str,
        choices=[sev.value for sev in Severity],
        default=Severity.INFO.value,
        help="Minimum severity to display in reports",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="count",
        default=0,
        help="Increase output verbosity (-v for passed checks, -vv for debug)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Minimal output (only errors and summary)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List checks without executing",
    )
    parser.add_argument(
        "--elevated",
        action="store_true",
        help="Run checks that require elevated privileges",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging and show check timing breakdown",
    )
    parser.add_argument(
        "--show-timing",
        action="store_true",
        help="Show timing breakdown for each check",
    )
    parser.add_argument(
        "--export-detailed",
        action="store_true",
        help="Export with device/hardware metadata for multi-device comparison",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip system requirements validation",
    )
    parser.add_argument(
        "--timestamp",
        action="store_true",
        help="Add timestamp to output filename for historical tracking",
    )
    return parser.parse_args(argv)


def _parse_categories(raw: str | None) -> List[str]:
    if not raw:
        return []
    return [part.strip().lower() for part in raw.split(",") if part.strip()]


def _instantiate_checks(categories: Sequence[str], include_sudo: bool) -> List[SecurityCheck]:
    checks: List[SecurityCheck] = []
    if categories:
        selected_classes = list(CheckRegistry.by_category(categories))
    else:
        selected_classes = list(CheckRegistry.get_all())

    for check_cls in selected_classes:
        if not include_sudo and getattr(check_cls, "requires_sudo", False):
            continue
        try:
            checks.append(check_cls())
        except Exception:  # noqa: BLE001
            logging.getLogger(__name__).exception(
                "Failed to instantiate check %s", check_cls.__name__
            )
            placeholder = _InstantiationFailureStub(original_cls=check_cls)
            checks.append(placeholder)
    return checks


@dataclass
class RunResult:
    """Result of running all checks including timing data."""
    results: List[CheckResult]
    timings: List[CheckTiming]
    total_elapsed: float
    
    def get_slowest_checks(self, n: int = 5) -> List[CheckTiming]:
        """Get the N slowest checks."""
        return sorted(self.timings, key=lambda t: t.elapsed_time, reverse=True)[:n]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for export."""
        return {
            "total_elapsed": round(self.total_elapsed, 3),
            "timings": [t.to_dict() for t in self.timings],
        }


def _run_checks(
    checks: Iterable[SecurityCheck],
    console: Console | None = None,
    live: bool = True,
    collect_timing: bool = False,
) -> RunResult:
    """Run all checks with optional live progress display.
    
    Args:
        checks: Security checks to run.
        console: Console for output.
        live: Show live progress.
        collect_timing: Collect per-check timing data.
    
    Returns:
        RunResult with results and optional timing data.
    """
    checks_list = list(checks)
    results: List[CheckResult] = []
    timings: List[CheckTiming] = []
    console = console or Console()
    total_start = time.perf_counter()
    
    if live and console.use_color:
        hide_cursor()
    
    try:
        if live:
            progress = ProgressBar(
                total=len(checks_list),
                width=35,
                title="Scanning",
            )
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 4)) as executor:
            # Track start times for each check
            check_start_times: Dict[concurrent.futures.Future, float] = {}
            future_map = {}
            
            for check in checks_list:
                future = executor.submit(check.execute)
                future_map[future] = check
                check_start_times[future] = time.perf_counter()
            
            for future in concurrent.futures.as_completed(future_map):
                check = future_map[future]
                check_elapsed = time.perf_counter() - check_start_times[future]
                
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    logging.getLogger(__name__).exception(
                        "Unhandled exception while executing check %s", check.name
                    )
                    result = CheckResult(
                        check_name=check.name,
                        status=Status.ERROR,
                        severity=check.severity,
                        message=str(exc),
                        remediation=check.remediation,
                        details={"exception_type": type(exc).__name__},
                    )
                
                results.append(result)
                
                if collect_timing:
                    timings.append(CheckTiming(
                        check_name=check.name,
                        elapsed_time=check_elapsed,
                        status=result.status,
                    ))
                
                if live:
                    progress.update(message=check.name)
        
        if live:
            progress.finish(f"{len(results)} checks completed")
    
    finally:
        if live and console.use_color:
            show_cursor()
    
    total_elapsed = time.perf_counter() - total_start
    return RunResult(results=results, timings=timings, total_elapsed=total_elapsed)


def _filter_results_for_output(
    results: Iterable[CheckResult], options: ExecutionOptions
) -> List[CheckResult]:
    min_rank = _SEVERITY_RANK.get(options.min_severity, 0)
    filtered: List[CheckResult] = []
    for res in results:
        if _SEVERITY_RANK.get(res.severity, 0) < min_rank:
            continue
        if not options.verbose and res.status == Status.PASS:
            continue
        filtered.append(res)
    return filtered


def _get_system_info() -> dict[str, str]:
    mac_ver = platform.mac_ver()
    return {
        "os": f"macOS {mac_ver[0] or 'Unknown'}",
        "release": mac_ver[0] or "Unknown",
        "name": platform.system(),
        "arch": platform.machine(),
        "python": sys.version.split()[0],
    }


def _render_report(
    *,
    results: Iterable[CheckResult],
    system_info: dict[str, str],
    options: ExecutionOptions,
    output_options: OutputOptions,
) -> str:
    results_list = list(results)
    filtered_results = _filter_results_for_output(results_list, options)
    min_severity = options.min_severity
    if output_options.format == "json":
        return format_json_report(
            results=filtered_results,
            system_info=system_info,
            summary_source=results_list,
        )
    if output_options.format == "html":
        return format_html_report(
            results=filtered_results,
            system_info=system_info,
            summary_source=results_list,
        )
    return format_text_report(
        results=results_list,
        system_info=system_info,
        verbose=options.verbose,
        min_severity=min_severity,
    )


def _print_dry_run(checks: Sequence[SecurityCheck], console: Console) -> None:
    """Display checks that would be executed in dry-run mode."""
    console.subheader("Checks that would be executed (dry-run)")
    
    # Group by category
    by_category: dict[str, List[SecurityCheck]] = {}
    for check in checks:
        cat = check.category
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(check)
    
    for category, cat_checks in sorted(by_category.items()):
        if console.use_color:
            print(f"\n  {Theme.ACCENT}{Icons.DIAMOND}{Colors.RESET} {Theme.TEXT}{Colors.BOLD}{category.title()}{Colors.RESET}")
        else:
            print(f"\n  {Icons.DIAMOND} {category.title()}")
        
        for check in sorted(cat_checks, key=lambda c: c.name):
            severity_color = Theme.severity_color(check.severity)
            sudo_label = f" {Theme.WARNING}(sudo){Colors.RESET}" if check.requires_sudo else ""
            if console.use_color:
                print(f"    {Theme.TEXT_DIM}{Icons.BULLET}{Colors.RESET} {check.name} {severity_color}[{check.severity.value}]{Colors.RESET}{sudo_label}")
            else:
                sudo_txt = " (sudo)" if check.requires_sudo else ""
                print(f"    {Icons.BULLET} {check.name} [{check.severity.value}]{sudo_txt}")
    
    console.blank()
    console.dim(f"Total: {len(checks)} checks")


def _collect_stats(results: Iterable[CheckResult]) -> dict[str, int]:
    """Collect statistics from results."""
    results_list = list(results)
    status_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    
    for r in results_list:
        status_counts[r.status.value.lower()] += 1
        severity_counts[r.severity.value.lower()] += 1
    
    return {
        "total": len(results_list),
        "pass": status_counts.get("pass", 0),
        "fail": status_counts.get("fail", 0),
        "warning": status_counts.get("warning", 0),
        "skip": status_counts.get("skip", 0),
        "error": status_counts.get("error", 0),
        "critical": severity_counts.get("critical", 0),
        "high": severity_counts.get("high", 0),
        "medium": severity_counts.get("medium", 0),
        "low": severity_counts.get("low", 0),
        "info": severity_counts.get("info", 0),
    }


def _validate_and_display_requirements(console: Console, skip_validation: bool = False) -> bool:
    """Validate system requirements and display results.
    
    Returns:
        True if validation passed (or was skipped), False if critical errors.
    """
    if skip_validation:
        console.dim("Skipping system requirements validation")
        return True
    
    reqs = validate_system_requirements()
    
    if not reqs.is_macos:
        console.error("This tool requires macOS")
        return False
    
    # Display errors
    for error in reqs.errors:
        console.error(error)
    
    # Display warnings
    for warning in reqs.warnings:
        console.warning(warning)
    
    if not reqs.passed:
        console.blank()
        console.error("System requirements not met. Use --skip-validation to bypass.")
        return False
    
    return True


def _display_timing_breakdown(run_result: RunResult, console: Console) -> None:
    """Display check timing breakdown."""
    if not run_result.timings:
        return
    
    console.subheader("Timing Breakdown")
    
    # Show slowest checks
    slowest = run_result.get_slowest_checks(10)
    
    if console.use_color:
        print(f"  {Theme.TEXT_DIM}Top 10 Slowest Checks:{Colors.RESET}")
    else:
        print("  Top 10 Slowest Checks:")
    
    for timing in slowest:
        status_icon = Icons.status_icon(timing.status)
        status_color = Theme.status_color(timing.status)
        time_str = f"{timing.elapsed_time:.3f}s"
        
        # Color code by time
        if timing.elapsed_time > 5:
            time_color = Theme.ERROR
        elif timing.elapsed_time > 2:
            time_color = Theme.WARNING
        else:
            time_color = Theme.TEXT_DIM
        
        if console.use_color:
            print(f"    {time_color}{time_str:>8}{Colors.RESET}  {status_color}{status_icon}{Colors.RESET} {timing.check_name}")
        else:
            print(f"    {time_str:>8}  {status_icon} {timing.check_name}")
    
    # Summary stats
    total_time = sum(t.elapsed_time for t in run_result.timings)
    avg_time = total_time / len(run_result.timings) if run_result.timings else 0
    
    console.blank()
    console.info("Total check time", f"{total_time:.2f}s")
    console.info("Average per check", f"{avg_time:.3f}s")
    console.info("Wall clock time", f"{run_result.total_elapsed:.2f}s")


def _export_detailed_report(
    run_result: RunResult,
    system_info: Dict[str, Any],
    stats: Dict[str, int],
    output_path: Path,
) -> None:
    """Export detailed JSON report with device/timing metadata for multi-device comparison."""
    hw = get_hardware_info()
    
    report = {
        "version": __version__,
        "generated_at": datetime.now().isoformat(),
        "device": {
            "hostname": platform.node(),
            "hardware": hw.to_dict(),
            "macos_version": system_info.get("os_version", "Unknown"),
            "macos_name": system_info.get("os_name", "Unknown"),
        },
        "summary": stats,
        "timing": run_result.to_dict(),
        "results": [
            {
                "check_name": r.check_name,
                "status": r.status.value,
                "severity": r.severity.value,
                "message": r.message,
                "remediation": r.remediation,
                "details": r.details,
            }
            for r in run_result.results
        ],
    }
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def _group_by_category(results: List[CheckResult]) -> Dict[str, List[CheckResult]]:
    """Group results by category."""
    grouped: Dict[str, List[CheckResult]] = {}
    for result in results:
        cat = result.category
        if cat not in grouped:
            grouped[cat] = []
        grouped[cat].append(result)
    return grouped


def _display_results_with_categories(
    results: List[CheckResult],
    console: Console,
    section_title: str,
    show_details: bool,
    show_verbose_hint: bool,
) -> None:
    """Display results grouped by category."""
    grouped = _group_by_category(results)
    
    # Sort categories for consistent display
    category_order = [
        "system_integrity", "authentication", "encryption", 
        "firewall", "privacy", "applications", "configuration", "general"
    ]
    
    sorted_categories = sorted(
        grouped.keys(),
        key=lambda c: category_order.index(c) if c in category_order else len(category_order)
    )
    
    for category in sorted_categories:
        cat_results = grouped[category]
        if not cat_results:
            continue
        
        # Get display name for category
        cat_display = cat_results[0].category_display_name if cat_results else category.replace("_", " ").title()
        
        # Show category label
        console.category_label(cat_display, len(cat_results))
        
        for result in cat_results:
            console.check_result(result, show_details=show_details, show_verbose_hint=show_verbose_hint)


def _display_results(
    results: List[CheckResult],
    console: Console,
    options: ExecutionOptions,
) -> None:
    """Display results in the terminal with beautiful formatting."""
    # Sort by severity (critical first), then by status (fail first), then by category
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    status_order = {Status.FAIL: 0, Status.ERROR: 1, Status.WARNING: 2, Status.PASS: 3, Status.SKIP: 4}
    category_order = [
        "system_integrity", "authentication", "encryption", 
        "firewall", "privacy", "applications", "configuration", "general"
    ]
    
    def sort_key(r: CheckResult) -> tuple:
        cat_idx = category_order.index(r.category) if r.category in category_order else len(category_order)
        return (severity_order.get(r.severity, 5), status_order.get(r.status, 5), cat_idx, r.check_name)
    
    sorted_results = sorted(results, key=sort_key)
    
    # Filter by severity
    min_rank = _SEVERITY_RANK.get(options.min_severity, 0)
    
    # Group results by status
    failures = [r for r in sorted_results if r.status in (Status.FAIL, Status.ERROR) and _SEVERITY_RANK.get(r.severity, 0) >= min_rank]
    warnings = [r for r in sorted_results if r.status == Status.WARNING and _SEVERITY_RANK.get(r.severity, 0) >= min_rank]
    passed = [r for r in sorted_results if r.status == Status.PASS and _SEVERITY_RANK.get(r.severity, 0) >= min_rank]
    skipped = [r for r in sorted_results if r.status == Status.SKIP and _SEVERITY_RANK.get(r.severity, 0) >= min_rank]
    
    # Show details in verbose mode
    show_details = options.verbose
    
    # Display failures with category grouping
    if failures:
        console.subheader(f"Issues Found ({len(failures)})")
        _display_results_with_categories(failures, console, "Issues", show_details, not show_details)
    
    # Display warnings with category grouping
    if warnings:
        console.subheader(f"Warnings ({len(warnings)})")
        _display_results_with_categories(warnings, console, "Warnings", show_details, not show_details)
    
    # Display passed (if verbose) with category grouping
    if options.verbose and passed:
        console.subheader(f"Passed Checks ({len(passed)})")
        _display_results_with_categories(passed, console, "Passed", show_details, False)
    
    # Display skipped (if verbose) with category grouping
    if options.verbose and skipped:
        console.subheader(f"Skipped Checks ({len(skipped)})")
        _display_results_with_categories(skipped, console, "Skipped", show_details, False)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    configure_logging(level=logging.DEBUG if args.debug else logging.INFO)
    logger = logging.getLogger(__name__)
    
    # Determine verbosity level
    if args.quiet:
        verbosity = VERBOSITY_QUIET
    elif args.debug:
        verbosity = VERBOSITY_DEBUG
    elif args.verbose >= 2:
        verbosity = VERBOSITY_DEBUG
    elif args.verbose == 1:
        verbosity = VERBOSITY_VERBOSE
    else:
        verbosity = VERBOSITY_NORMAL
    
    # Force quiet mode for machine-readable formats to stdout
    # (JSON/HTML without output file should only print the report)
    if args.format in ("json", "html") and not args.output:
        verbosity = VERBOSITY_QUIET
    
    # Initialize console
    console = Console()
    
    # Print banner (skip in quiet mode)
    if verbosity > VERBOSITY_QUIET:
        console.banner(compact=True)
        console.blank()
    
    # Validate system requirements (skip display for machine-readable output)
    if verbosity > VERBOSITY_QUIET:
        if not _validate_and_display_requirements(console, args.skip_validation):
            return 1
    elif not args.skip_validation:
        # Still validate but silently
        from utils.system_info import validate_system_requirements
        is_valid, _ = validate_system_requirements()
        if not is_valid:
            return 1

    # Load checks
    if verbosity > VERBOSITY_QUIET:
        with Spinner("Loading security checks...") as spinner:
            try:
                load_checks()
                time.sleep(0.2)  # Brief pause for visual effect
            except ImportError as exc:
                spinner.stop(f"Failed to load checks: {exc}", Icons.FAIL, Theme.ERROR)
                return 1
            spinner.stop("Security checks loaded", Icons.PASS, Theme.SUCCESS)
    else:
        try:
            load_checks()
        except ImportError:
            return 1
    
    # System info - use extended info for better hardware detection
    system_info = get_extended_system_info()
    hw = get_hardware_info()
    
    # Log hardware info for debugging/testing matrix
    logger.info("Hardware: %s", format_hardware_summary())
    
    if verbosity >= VERBOSITY_NORMAL:
        console.subheader("System Information")
        console.info("OS", f"{system_info.get('os', 'Unknown')} ({system_info.get('os_name', 'Unknown')})")
        console.info("Hardware", f"{hw.model_name} ({hw.chip_type.replace('_', ' ').title()})")
        console.info("Architecture", system_info.get("arch", "Unknown"))
        if verbosity >= VERBOSITY_DEBUG:
            console.info("CPU", hw.cpu_brand)
            console.info("Memory", f"{hw.memory_gb} GB")
            console.info("Python", system_info.get("python", "Unknown"))
        console.info("Scan Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    categories = _parse_categories(args.categories)
    
    # Determine if we should collect timing
    collect_timing = args.debug or args.show_timing or args.export_detailed
    
    options = ExecutionOptions(
        categories=categories,
        include_sudo_checks=args.elevated,
        dry_run=args.dry_run,
        verbosity=verbosity,
        min_severity=Severity(args.min_severity),
        show_timing=args.show_timing or args.debug,
    )

    checks = _instantiate_checks(options.categories, options.include_sudo_checks)
    if not checks:
        console.warning("No checks selected for execution")
        return 0
    
    if verbosity >= VERBOSITY_NORMAL:
        console.dim(f"Selected {len(checks)} checks to run")

    if options.dry_run:
        _print_dry_run(checks, console)
        return 0

    # Run checks with live progress
    if verbosity >= VERBOSITY_NORMAL:
        console.subheader("Running Security Audit")
    
    run_result = _run_checks(
        checks,
        console,
        live=(verbosity >= VERBOSITY_NORMAL),
        collect_timing=collect_timing,
    )
    
    # Display results
    if verbosity >= VERBOSITY_NORMAL:
        _display_results(run_result.results, console, options)
    
    # Timing breakdown (if requested)
    if options.show_timing and run_result.timings:
        _display_timing_breakdown(run_result, console)
    
    # Summary (skip for machine-readable output)
    stats = _collect_stats(run_result.results)
    if verbosity > VERBOSITY_QUIET:
        console.summary_box(stats)
        if verbosity >= VERBOSITY_NORMAL:
            console.severity_breakdown(stats)
        console.blank()

    # Check if this is the first run
    is_first_run = _is_first_run()
    
    # Handle file output
    base_output_path = Path(args.output).expanduser() if args.output else None
    
    # Apply timestamp to filename if requested
    if base_output_path and args.timestamp:
        final_output_path = _generate_timestamped_path(base_output_path)
    else:
        final_output_path = base_output_path
    
    output_options = OutputOptions(
        format=args.format,
        output_path=final_output_path,
        export_detailed=args.export_detailed,
        timestamp=args.timestamp,
    )

    if output_options.output_path:
        try:
            if output_options.export_detailed:
                # Export detailed report with device/timing metadata
                _export_detailed_report(
                    run_result=run_result,
                    system_info=system_info,
                    stats=stats,
                    output_path=output_options.output_path,
                )
                console.success(f"Detailed report saved to {output_options.output_path}")
            else:
                report = _render_report(
                    results=run_result.results,
                    system_info=system_info,
                    options=options,
                    output_options=output_options,
                )
                output_options.output_path.parent.mkdir(parents=True, exist_ok=True)
                output_options.output_path.write_text(report, encoding="utf-8")
                console.success(f"Report saved to {output_options.output_path}")
        except (CommandExecutionError, OSError) as exc:
            console.error(f"Failed to save report: {exc}")
            return 1
    elif output_options.format in ("json", "html"):
        # Print JSON/HTML to stdout when no output file specified
        report = _render_report(
            results=run_result.results,
            system_info=system_info,
            options=options,
            output_options=output_options,
        )
        print(report)
    
    # Determine exit code based on results
    # 0 = All checks passed
    # 1 = Warnings found (non-critical)
    # 2 = Critical/High issues found
    # 3 = Errors during execution
    exit_code = _determine_exit_code(stats)
    
    # Skip CLI decorations for machine-readable formats (JSON/HTML to stdout)
    is_machine_readable = output_options.format in ("json", "html") and not output_options.output_path
    
    if not is_machine_readable:
        # Show first-run tips if applicable
        if is_first_run and verbosity >= VERBOSITY_NORMAL:
            _display_first_run_tips(console, output_options.output_path)
            _mark_first_run_complete()
        
        # Generate recommended actions from failures/warnings
        _display_recommended_actions(run_result.results, console, options)
        
        # Show performance metrics in verbose mode
        if options.show_timing and run_result.timings:
            slowest = [
                (t.check_name, t.elapsed_time, _get_check_timing_reason(t.check_name))
                for t in run_result.get_slowest_checks(5)
            ]
            console.performance_metrics(run_result.total_elapsed, slowest)
        
        # Final status
        if exit_code == 3:
            console.error(f"Scan completed with {stats['error']} errors")
        elif exit_code == 2:
            console.warning(f"Scan completed with {stats['fail']} critical/high issues")
        elif exit_code == 1:
            console.dim(f"Scan completed with warnings (review recommended)")
        else:
            console.success(f"Security scan completed successfully in {run_result.total_elapsed:.1f}s")
    
    return exit_code


def _determine_exit_code(stats: Dict[str, int]) -> int:
    """Determine appropriate exit code for CI/CD integration.
    
    Exit codes:
        0 = All checks passed
        1 = Warnings found (non-critical)
        2 = Critical/High issues found
        3 = Errors during execution
    """
    # Check for errors first (highest priority)
    if stats.get("error", 0) > 0:
        return 3
    
    # Check for critical/high failures
    critical_count = stats.get("critical", 0)
    high_count = stats.get("high", 0)
    fail_count = stats.get("fail", 0)
    
    # If any critical or high severity issues exist, return 2
    if critical_count > 0 or high_count > 0 or fail_count > 0:
        return 2
    
    # Check for warnings
    if stats.get("warning", 0) > 0:
        return 1
    
    # All passed
    return 0


def _get_check_timing_reason(check_name: str) -> str:
    """Get explanation for why a check might be slow."""
    reasons = {
        "Dangerous Application Entitlements": "scanning /Applications",
        "Unsigned Applications": "codesign verification",
        "External Disk Encryption": "diskutil calls",
        "TCC Database Access": "SQLite queries",
        "Camera Permissions": "TCC database query",
        "Microphone Permissions": "TCC database query",
        "Screen Recording Permissions": "TCC database query",
        "Full Disk Access Permissions": "TCC database query",
        "Time Machine Encryption": "tmutil queries",
        "Safari Security Settings": "preferences query",
        "Software Updates Pending": "softwareupdate query",
    }
    return reasons.get(check_name, "")


def _display_recommended_actions(
    results: List[CheckResult],
    console: Console,
    options: ExecutionOptions,
) -> None:
    """Generate and display recommended actions from results."""
    # Only show in non-quiet mode
    if options.verbosity <= VERBOSITY_QUIET:
        return
    
    # Collect actionable failures and warnings
    actions: List[Dict[str, Any]] = []
    
    # Time estimates by check type
    time_estimates = {
        "FileVault Encryption": 30,  # Long process
        "Dangerous Application Entitlements": 5,
        "Unsigned Applications": 10,
        "Application Firewall": 2,
        "Firewall Stealth Mode": 2,
        "Gatekeeper": 2,
        "System Integrity Protection": 15,  # Requires restart
        "Automatic Login": 2,
        "Guest Account": 2,
        "Screen Saver Password": 1,
        "XProtect Definitions": 5,
        "Camera Permissions": 1,
        "Microphone Permissions": 1,
        "Screen Recording Permissions": 2,
        "Accessibility Permissions": 2,
        "Full Disk Access Permissions": 2,
        "Apple ID 2FA": 10,
        "Find My Mac": 5,
    }
    
    for result in results:
        if result.status not in (Status.FAIL, Status.WARNING):
            continue
        
        # Build action entry
        action = {
            "severity": result.severity.value,
            "title": result.check_name,
            "risk": result.message[:60] if result.message else "",
            "time_minutes": time_estimates.get(result.check_name, 5),
        }
        actions.append(action)
    
    # Sort by severity (CRITICAL first)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    actions.sort(key=lambda a: severity_order.get(a["severity"], 5))
    
    # Display if there are actions
    if actions:
        console.recommended_actions(actions[:5])  # Top 5 actions


if __name__ == "__main__":
    sys.exit(main())
