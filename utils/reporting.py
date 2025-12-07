"""Reporting helpers for macSentry."""
from __future__ import annotations

import datetime as _dt
import html
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable, Mapping

from checks.types import CheckResult, Severity, Status

_HEADER_LINE = "═" * 70

# ANSI color codes for terminal output
_COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "gray": "\033[90m",
}

_SEVERITY_COLORS = {
    Severity.CRITICAL: _COLORS["bold"] + _COLORS["red"],
    Severity.HIGH: _COLORS["red"],
    Severity.MEDIUM: _COLORS["yellow"],
    Severity.LOW: _COLORS["blue"],
    Severity.INFO: _COLORS["cyan"],
}

_STATUS_COLORS = {
    Status.PASS: _COLORS["green"],
    Status.FAIL: _COLORS["red"],
    Status.WARNING: _COLORS["yellow"],
    Status.SKIP: _COLORS["gray"],
    Status.ERROR: _COLORS["bold"] + _COLORS["red"],
}


def _colorize(text: str, color: str) -> str:
    """Wrap text with ANSI color codes."""
    return f"{color}{text}{_COLORS['reset']}"


_SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}
_STATUS_LABELS = {
    Status.PASS: "PASS",
    Status.FAIL: "FAIL",
    Status.WARNING: "WARNING",
    Status.SKIP: "SKIP",
    Status.ERROR: "ERROR",
}


def _sort_results(results: Iterable[CheckResult]) -> list[CheckResult]:
    return sorted(
        results,
        key=lambda r: (
            -_SEVERITY_ORDER.get(r.severity, 0),
            r.status != Status.PASS,
            r.check_name,
        ),
    )


def _timestamp(dt: _dt.datetime | None = None) -> str:
    return (dt or _dt.datetime.now()).strftime("%Y-%m-%d %H:%M")


def _collect_summary(results: Iterable[CheckResult]) -> dict[str, int]:
    summary: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()

    for result in results:
        summary[result.status.value.lower()] += 1
        severity_counts[result.severity.value.lower()] += 1

    total = sum(summary.values())
    summary_dict = {"total": total}
    summary_dict.update({k: summary.get(k, 0) for k in ("pass", "fail", "warning", "skip", "error")})
    summary_dict.update({
        "critical": severity_counts.get("CRITICAL".lower(), 0),
        "high": severity_counts.get("HIGH".lower(), 0),
        "medium": severity_counts.get("MEDIUM".lower(), 0),
        "low": severity_counts.get("LOW".lower(), 0),
        "info": severity_counts.get("INFO".lower(), 0),
    })
    return summary_dict


def _format_system_info(system_info: Mapping[str, str]) -> str:
    return "System: " + ", ".join(f"{key}: {value}" for key, value in system_info.items())


def format_text_report(
    *,
    results: Iterable[CheckResult],
    system_info: Mapping[str, str],
    verbose: bool = False,
    min_severity: Severity | None = None,
    color: bool | None = None,
) -> str:
    """Generate a human-readable text report.

    Args:
        color: Enable ANSI colors. None = auto-detect TTY.
    """
    use_color = color if color is not None else sys.stdout.isatty()

    filtered = []
    min_value = _SEVERITY_ORDER.get(min_severity, 0) if min_severity else 0
    for res in results:
        if _SEVERITY_ORDER.get(res.severity, 0) < min_value:
            continue
        if not verbose and res.status == Status.PASS:
            continue
        filtered.append(res)

    display_results = _sort_results(filtered)
    summary = _collect_summary(results)

    lines = [
        f"╔{_HEADER_LINE}╗",
        f"║               macSentry Report - {_timestamp()}               ║",
        f"╚{_HEADER_LINE}╝",
        "",
        _format_system_info(system_info),
        "",
    ]

    if not display_results:
        lines.append("No findings for selected criteria.")
    else:
        for res in display_results:
            sev_text = res.severity.value
            status_text = _STATUS_LABELS[res.status]
            if use_color:
                sev_text = _colorize(sev_text, _SEVERITY_COLORS.get(res.severity, ""))
                status_text = _colorize(status_text, _STATUS_COLORS.get(res.status, ""))
            lines.append(f"[{sev_text}] {res.check_name} - {status_text}")
            lines.append(f"  → {res.message}")
            if res.remediation:
                lines.append(f"  → Remediation: {res.remediation}")
            if res.details:
                details_json = json.dumps(res.details, indent=2, sort_keys=True)
                # Indent subsequent lines to align with "Details:"
                indented = details_json.replace("\n", "\n      ")
                lines.append(f"    Details: {indented}")
            lines.append("")

    lines.extend(
        [
            "Summary:",
            f"  Total checks: {summary['total']}",
            f"  Passed: {summary['pass']}  Failed: {summary['fail']}  Warnings: {summary['warning']}  Skipped: {summary['skip']}  Errors: {summary['error']}",
            f"  Severity counts - Critical: {summary['critical']}, High: {summary['high']}, Medium: {summary['medium']}, Low: {summary['low']}, Info: {summary['info']}",
        ]
    )

    return "\n".join(lines).strip() + "\n"


def format_json_report(
    *,
    results: Iterable[CheckResult],
    system_info: Mapping[str, str],
    scan_time: _dt.datetime | None = None,
    summary_source: Iterable[CheckResult] | None = None,
) -> str:
    """Generate a JSON report using filtered results for output."""

    scan_time = scan_time or _dt.datetime.utcnow()
    summary_basis = list(summary_source) if summary_source is not None else list(results)
    payload = {
        "scan_date": scan_time.replace(microsecond=0).isoformat() + "Z",
        "system": dict(system_info),
        "checks": [
            {
                "name": res.check_name,
                "status": res.status.value,
                "severity": res.severity.value,
                "message": res.message,
                "remediation": res.remediation,
                "details": res.details,
            }
            for res in _sort_results(results)
        ],
        "summary": _collect_summary(summary_basis),
    }

    return json.dumps(payload, indent=2, sort_keys=True)


def format_html_report(
    *,
    results: Iterable[CheckResult],
    system_info: Mapping[str, str],
    scan_time: _dt.datetime | None = None,
    summary_source: Iterable[CheckResult] | None = None,
) -> str:
    """Generate a minimal HTML report."""

    scan_time = scan_time or _dt.datetime.utcnow()
    summary_basis = list(summary_source) if summary_source is not None else list(results)
    summary = _collect_summary(summary_basis)
    rows = []
    for res in _sort_results(results):
        severity_class = f"severity-{html.escape(res.severity.value)}"
        rows.append(
            "<tr>"
            f"<td class=\"{severity_class}\">{html.escape(res.severity.value)}</td>"
            f"<td>{html.escape(res.status.value)}</td>"
            f"<td>{html.escape(res.check_name)}</td>"
            f"<td>{html.escape(res.message)}</td>"
            f"<td>{html.escape(res.remediation)}</td>"
            "</tr>"
        )

    system_table = "".join(
        f"<li><strong>{html.escape(key)}:</strong> {html.escape(value)}</li>"
        for key, value in system_info.items()
    )

    html_doc = f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <title>macSentry Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; color: #222; padding: 2rem; }}
    header {{ margin-bottom: 2rem; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; }}
    th, td {{ padding: 0.75rem; border-bottom: 1px solid #ddd; text-align: left; }}
    th {{ background: #1f2937; color: #f9fafb; }}
    tr:nth-child(even) {{ background: #f1f5f9; }}
    .severity-CRITICAL {{ color: #b91c1c; font-weight: 600; }}
    .severity-HIGH {{ color: #b45309; font-weight: 600; }}
    .severity-MEDIUM {{ color: #92400e; }}
    .severity-LOW {{ color: #0369a1; }}
    .severity-INFO {{ color: #047857; }}
    footer {{ margin-top: 2rem; font-size: 0.9rem; color: #555; }}
  </style>
</head>
<body>
  <header>
    <h1>macSentry Report</h1>
    <p><strong>Generated:</strong> {html.escape(scan_time.isoformat())}Z</p>
    <ul>{system_table}</ul>
  </header>
  <main>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Status</th>
          <th>Check</th>
          <th>Message</th>
          <th>Remediation</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows) if rows else '<tr><td colspan="5">No findings for selected filters.</td></tr>'}
      </tbody>
    </table>
  </main>
  <footer>
    <p>Total: {summary['total']} | Passed: {summary['pass']} | Failed: {summary['fail']} | Warnings: {summary['warning']} | Skipped: {summary['skip']} | Errors: {summary['error']}</p>
  </footer>
</body>
</html>
"""

    return html_doc


def write_report(output_path: Path, content: str) -> None:
    """Persist report content to the specified path."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
