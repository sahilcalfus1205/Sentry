"""Shared data structures: normalized findings and scan results.

Scan execution status (ScannerRun) is kept separate from findings so that a
failed scan can never be mistaken for a clean one.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum

# Version of the JSON report layout; bump when the layout changes incompatibly.
REPORT_SCHEMA_VERSION = 1


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


# Most severe first. Used for sorting and for report ordering.
SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
]


class RunStatus(StrEnum):
    COMPLETED = "completed"
    NOT_INSTALLED = "not_installed"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


@dataclass
class Finding:
    scanner: str
    rule_id: str
    title: str
    severity: Severity
    # Raw severity string exactly as the scanner reported it, if any.
    original_severity: str | None = None
    description: str | None = None
    # Path relative to the scanned directory, when the scanner gave one.
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    cwe: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    # Scanner-provided confidence as reported (e.g. "HIGH"). Never invented.
    confidence: str | None = None
    fingerprint: str = ""
    # Scanner-specific extras (package name, fixed version, ...).
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class ScannerRun:
    """What happened when one scanner was executed."""

    scanner: str
    status: RunStatus
    version: str | None = None
    exit_code: int | None = None
    # Human-readable explanation when status is not COMPLETED.
    message: str | None = None
    # Problems that make a COMPLETED run partial (e.g. files that failed to parse).
    warnings: list[str] = field(default_factory=list)
    # Truncated stderr, kept for troubleshooting.
    diagnostics: str | None = None
    finding_count: int = 0

    @property
    def is_complete(self) -> bool:
        return self.status is RunStatus.COMPLETED and not self.warnings


@dataclass
class ScanResult:
    target: str
    runs: list[ScannerRun]
    findings: list[Finding]

    @property
    def is_complete(self) -> bool:
        return bool(self.runs) and all(run.is_complete for run in self.runs)


def make_fingerprint(*parts: str | int | None) -> str:
    """Stable id from the parts that identify a finding (not from its message text)."""
    joined = "\x1f".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(joined.encode()).hexdigest()[:16]
