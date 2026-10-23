"""Terminal summaries and JSON reports."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from sentry_sec.models import SEVERITY_ORDER, Finding, RunStatus, ScannerRun, ScanResult

REPORT_SCHEMA_VERSION = 1
MAX_FINDINGS_SHOWN = 25


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(finding.severity for finding in findings)
    return {severity.value: counts[severity] for severity in SEVERITY_ORDER}


def to_dict(result: ScanResult) -> dict:
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "target": result.target,
        "complete": result.is_complete,
        "scanners": [
            {**asdict(run), "complete": run.is_complete}  # StrEnum values serialize as strings
            for run in result.runs
        ],
        "summary": {
            "total_findings": len(result.findings),
            "by_severity": severity_counts(result.findings),
        },
        "findings": [asdict(finding) for finding in result.findings],
    }


def to_json(result: ScanResult) -> str:
    return json.dumps(to_dict(result), indent=2) + "\n"


def write_json(result: ScanResult, path: Path) -> None:
    path.write_text(to_json(result), encoding="utf-8")


def describe_run(run: ScannerRun) -> str:
    version = f" {run.version}" if run.version else ""
    if run.status is RunStatus.COMPLETED:
        state = "completed with warnings" if run.warnings else "completed"
        return f"{run.scanner}{version}: {state}, {run.finding_count} finding(s)"
    return f"{run.scanner}: {run.status.value.upper().replace('_', ' ')} - {run.message}"


def format_location(finding: Finding) -> str:
    if not finding.file_path:
        return ""
    if finding.start_line is None:
        return finding.file_path
    if finding.end_line and finding.end_line != finding.start_line:
        return f"{finding.file_path}:{finding.start_line}-{finding.end_line}"
    return f"{finding.file_path}:{finding.start_line}"


def render_text(result: ScanResult) -> str:
    lines = [f"Sentry scan of {result.target}", "", "Scanners:"]
    for run in result.runs:
        lines.append(f"  {describe_run(run)}")
        for warning in run.warnings:
            lines.append(f"    warning: {warning}")
        if run.status is not RunStatus.COMPLETED and run.diagnostics:
            lines.append(f"    diagnostics: {run.diagnostics[:300]}")

    lines += ["", f"Findings: {len(result.findings)}"]
    for severity, count in severity_counts(result.findings).items():
        if count:
            lines.append(f"  {severity}: {count}")

    for finding in result.findings[:MAX_FINDINGS_SHOWN]:
        location = format_location(finding)
        where = f" ({location})" if location else ""
        lines.append(
            f"  [{finding.severity.value.upper()}] {finding.scanner}: {finding.rule_id}{where}"
        )
        lines.append(f"      {finding.title}")
    hidden = len(result.findings) - MAX_FINDINGS_SHOWN
    if hidden > 0:
        lines.append(f"  ... and {hidden} more (use --format json for the full list)")

    lines.append("")
    if not result.is_complete:
        lines.append(
            "RESULT: INCOMPLETE - at least one scanner failed or returned partial results."
        )
        lines.append("        Do not treat this scan as clean.")
    elif result.findings:
        lines.append(
            "RESULT: findings reported. These are scanner results, not confirmed vulnerabilities."
        )
    else:
        lines.append("RESULT: no findings reported. This does not mean the code is secure;")
        lines.append("        scanners only detect what their rules and databases cover.")
    return "\n".join(lines) + "\n"
