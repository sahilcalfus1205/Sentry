"""Semgrep adapter.

Runs `semgrep scan --json` and converts its report into normalized findings.
Semgrep exit codes (without --error): 0 on a completed scan, with or without
findings; any other code means the scan itself failed.
"""

from __future__ import annotations

import re
from pathlib import Path

from sentry_sec.models import Finding, ScannerRun, Severity, make_fingerprint
from sentry_sec.scanners.base import (
    CommandOutput,
    Interpretation,
    ScannerError,
    execute,
    location_fingerprint_part,
    parse_json,
    relative_path,
    truncate,
)

NAME = "semgrep"
# The curated default ruleset from the Semgrep Registry. Needs network access.
DEFAULT_CONFIG = "p/default"
MAX_REPORTED_ERRORS = 5

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "ERROR": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "WARNING": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)
# Optional rule metadata worth keeping as-is.
METADATA_KEYS = ("category", "likelihood", "impact", "owasp", "subcategory")


def scan(target: Path, timeout: float) -> tuple[ScannerRun, list[Finding]]:
    arguments = [
        "scan",
        "--json",
        "--quiet",
        "--metrics=off",
        "--disable-version-check",
        f"--config={DEFAULT_CONFIG}",
        str(target),
    ]
    return execute(
        NAME,
        "semgrep",
        arguments,
        timeout,
        lambda output: interpret_output(output, target),
    )


def interpret_output(output: CommandOutput, target: Path) -> Interpretation:
    if output.exit_code != 0:
        detail = truncate(output.stderr, 300) or "no error output"
        raise ScannerError(f"semgrep exited with code {output.exit_code}: {detail}")
    return parse_report(parse_json(output.stdout, NAME), target)


def parse_report(report: dict, target: Path) -> Interpretation:
    if not isinstance(report.get("results"), list):
        raise ScannerError("semgrep JSON has no 'results' list")

    findings = [
        convert_result(result, target) for result in report["results"] if isinstance(result, dict)
    ]
    return Interpretation(
        findings=findings,
        warnings=collect_warnings(report),
        version=report.get("version") if isinstance(report.get("version"), str) else None,
    )


def collect_warnings(report: dict) -> list[str]:
    """Semgrep reports per-file/per-rule problems in 'errors'; those mean partial coverage."""
    warnings = []
    errors = report.get("errors")
    if isinstance(errors, list) and errors:
        warnings.append(
            f"semgrep reported {len(errors)} error(s); some files or rules may be skipped"
        )
        for error in errors[:MAX_REPORTED_ERRORS]:
            if isinstance(error, dict):
                message = str(error.get("message") or error.get("type") or "unknown error")
                warnings.append(truncate(message.splitlines()[0], 200))
    paths = report.get("paths")
    if isinstance(paths, dict) and paths.get("scanned") == []:
        warnings.append("semgrep scanned 0 files")
    return warnings


def convert_result(result: dict, target: Path) -> Finding:
    extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}

    rule_id = str(result.get("check_id") or "unknown")
    original_severity = extra.get("severity")
    severity = SEVERITY_MAP.get(str(original_severity).upper(), Severity.UNKNOWN)
    message = extra.get("message")
    file_path = relative_path(result["path"], target) if result.get("path") else None
    start_line = line_number(result.get("start"))
    end_line = line_number(result.get("end"))

    return Finding(
        scanner=NAME,
        rule_id=rule_id,
        # Semgrep rules have no separate title; use the message's first line.
        title=first_sentence(str(message)) if message else rule_id,
        description=str(message) if message else None,
        severity=severity,
        original_severity=str(original_severity) if original_severity else None,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        cwe=find_cwes(metadata.get("cwe")),
        references=as_string_list(metadata.get("references")),
        confidence=str(metadata["confidence"]) if metadata.get("confidence") else None,
        fingerprint=make_fingerprint(
            NAME,
            rule_id,
            file_path,
            location_fingerprint_part(target, file_path, start_line, end_line),
        ),
        metadata={
            key: ", ".join(as_string_list(metadata[key]))
            for key in METADATA_KEYS
            if metadata.get(key)
        },
    )


def first_sentence(message: str) -> str:
    first_line = message.splitlines()[0] if message.strip() else message
    sentence = first_line.split(". ")[0]
    return sentence if len(sentence) <= 120 else sentence[:117] + "..."


def line_number(position: object) -> int | None:
    if isinstance(position, dict) and isinstance(position.get("line"), int):
        return position["line"]
    return None


def as_string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def find_cwes(value: object) -> list[str]:
    """Semgrep CWE metadata is a string or a list like 'CWE-89: SQL Injection...'."""
    ids = []
    for text in as_string_list(value):
        for match in CWE_PATTERN.findall(text):
            cwe = match.upper()
            if cwe not in ids:
                ids.append(cwe)
    return ids
