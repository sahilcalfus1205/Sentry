"""Compare two JSON reports to see which findings are new, persisting, or resolved.

Findings are matched only by their fingerprint. Line numbers are part of the
fingerprint, so a finding that moves to another line shows up as one resolved
plus one new finding. That is a known limitation.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from sentry_sec.models import REPORT_SCHEMA_VERSION


class ReportError(Exception):
    """A report file cannot be read or is not a Sentry report."""


@dataclass
class Comparison:
    new: list[dict] = field(default_factory=list)
    persisting: list[dict] = field(default_factory=list)
    resolved: list[dict] = field(default_factory=list)
    # Missing from the new report, but their scanner did not complete there,
    # so we cannot say they were fixed.
    unverified: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_reliable(self) -> bool:
        return not self.warnings


def load_report(path: Path) -> dict:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ReportError(f"cannot read {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ReportError(f"{path} is not valid JSON: {error}") from error

    if not isinstance(report, dict) or "findings" not in report or "scanners" not in report:
        raise ReportError(f"{path} is not a Sentry report")
    if report.get("schema_version") != REPORT_SCHEMA_VERSION:
        raise ReportError(
            f"{path} has schema_version {report.get('schema_version')!r}; "
            f"expected {REPORT_SCHEMA_VERSION}"
        )
    if not isinstance(report["findings"], list) or not isinstance(report["scanners"], list):
        raise ReportError(f"{path} has malformed 'findings' or 'scanners'")
    return report


def incomplete_scanners(report: dict) -> list[str]:
    return [
        str(scanner.get("scanner"))
        for scanner in report["scanners"]
        if isinstance(scanner, dict) and not scanner.get("complete")
    ]


def group_by_fingerprint(findings: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for finding in findings:
        groups[str(finding.get("fingerprint", ""))].append(finding)
    return groups


def compare_reports(old: dict, new: dict) -> Comparison:
    comparison = Comparison()
    old_groups = group_by_fingerprint(old["findings"])
    new_groups = group_by_fingerprint(new["findings"])
    incomplete_in_new = incomplete_scanners(new)

    for fingerprint, new_findings in new_groups.items():
        old_findings = old_groups.get(fingerprint, [])
        matched = min(len(old_findings), len(new_findings))
        comparison.persisting.extend(new_findings[:matched])
        comparison.new.extend(new_findings[matched:])

    for fingerprint, old_findings in old_groups.items():
        matched = min(len(old_findings), len(new_groups.get(fingerprint, [])))
        for finding in old_findings[matched:]:
            if finding.get("scanner") in incomplete_in_new:
                comparison.unverified.append(finding)
            else:
                comparison.resolved.append(finding)

    if incomplete_in_new:
        comparison.warnings.append(
            "new report is incomplete for: "
            + ", ".join(incomplete_in_new)
            + "; findings from these scanners cannot be reported as resolved"
        )
    if incomplete_scanners(old):
        comparison.warnings.append(
            "old report is incomplete for: "
            + ", ".join(incomplete_scanners(old))
            + "; some 'new' findings may have existed before but were missed"
        )
    return comparison
