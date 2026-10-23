"""Scan orchestration: run the selected scanners and aggregate their results."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from sentry_sec.models import SEVERITY_ORDER, Finding, ScannerRun, ScanResult
from sentry_sec.scanners import SCANNERS

ScannerFunction = Callable[[Path, float], tuple[ScannerRun, list[Finding]]]

DEFAULT_TIMEOUT_SECONDS = 600.0


def run_scan(
    target: Path,
    scanner_names: list[str],
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    scanners: dict[str, ScannerFunction] = SCANNERS,
) -> ScanResult:
    """Run each named scanner against `target` and combine the results.

    Findings are kept as reported by each scanner; no deduplication happens here.
    """
    unknown = [name for name in scanner_names if name not in scanners]
    if unknown:
        raise ValueError(f"unknown scanner(s): {', '.join(unknown)}")

    runs: list[ScannerRun] = []
    findings: list[Finding] = []
    for name in scanner_names:
        run, scanner_findings = scanners[name](target, timeout)
        runs.append(run)
        findings.extend(scanner_findings)

    severity_rank = {severity: rank for rank, severity in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda finding: (severity_rank[finding.severity], finding.scanner))
    return ScanResult(target=str(target), runs=runs, findings=findings)
