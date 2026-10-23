"""Trivy adapter.

Runs `trivy fs --format json` and converts vulnerabilities, secrets and
misconfigurations into normalized findings. Without --exit-code, Trivy exits 0
when a scan completes (with or without findings) and nonzero when it fails.

Matched secret text is deliberately never copied into findings.
"""

from __future__ import annotations

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

NAME = "trivy"

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def scan(target: Path, timeout: float) -> tuple[ScannerRun, list[Finding]]:
    arguments = [
        "fs",
        "--format=json",
        "--quiet",
        "--scanners=vuln,secret,misconfig",
        str(target),
    ]
    return execute(
        NAME,
        "trivy",
        arguments,
        timeout,
        lambda output: interpret_output(output, target),
    )


def interpret_output(output: CommandOutput, target: Path) -> Interpretation:
    if output.exit_code != 0:
        detail = truncate(output.stderr, 300) or "no error output"
        raise ScannerError(f"trivy exited with code {output.exit_code}: {detail}")
    return parse_report(parse_json(output.stdout, NAME), target)


def parse_report(report: dict, target: Path) -> Interpretation:
    # Trivy omits "Results" entirely when nothing was found.
    results = report.get("Results") or []
    if not isinstance(results, list):
        raise ScannerError("trivy JSON 'Results' is not a list")

    findings: list[Finding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        file_path = relative_path(result["Target"], target) if result.get("Target") else None
        for vulnerability in dict_items(result.get("Vulnerabilities")):
            findings.append(convert_vulnerability(vulnerability, file_path))
        for secret in dict_items(result.get("Secrets")):
            findings.append(convert_secret(secret, file_path, target))
        for misconfiguration in dict_items(result.get("Misconfigurations")):
            # Passed checks are only present when explicitly requested; skip them anyway.
            if str(misconfiguration.get("Status", "FAIL")).upper() != "PASS":
                findings.append(convert_misconfiguration(misconfiguration, file_path, target))
    return Interpretation(findings=findings, warnings=[])


def dict_items(value: object) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def normalize_severity(value: object) -> tuple[Severity, str | None]:
    original = str(value) if value else None
    return SEVERITY_MAP.get(str(value).upper(), Severity.UNKNOWN), original


def string_list(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def convert_vulnerability(vulnerability: dict, file_path: str | None) -> Finding:
    vulnerability_id = str(vulnerability.get("VulnerabilityID") or "unknown")
    package = str(vulnerability.get("PkgName") or "")
    installed = str(vulnerability.get("InstalledVersion") or "")
    severity, original = normalize_severity(vulnerability.get("Severity"))
    references = string_list(vulnerability.get("References"))
    primary_url = vulnerability.get("PrimaryURL")
    if primary_url and primary_url not in references:
        references.insert(0, str(primary_url))

    metadata = {"package": package, "installed_version": installed}
    if vulnerability.get("FixedVersion"):
        metadata["fixed_version"] = str(vulnerability["FixedVersion"])

    return Finding(
        scanner=NAME,
        rule_id=vulnerability_id,
        title=str(vulnerability.get("Title") or f"{vulnerability_id} in {package}"),
        description=vulnerability.get("Description"),
        severity=severity,
        original_severity=original,
        file_path=file_path,
        cwe=string_list(vulnerability.get("CweIDs")),
        cve=[vulnerability_id] if vulnerability_id.upper().startswith("CVE-") else [],
        references=references,
        fingerprint=make_fingerprint(NAME, vulnerability_id, file_path, package, installed),
        metadata={key: value for key, value in metadata.items() if value},
    )


def convert_secret(secret: dict, file_path: str | None, target: Path) -> Finding:
    rule_id = str(secret.get("RuleID") or "unknown")
    severity, original = normalize_severity(secret.get("Severity"))
    start_line = secret.get("StartLine") if isinstance(secret.get("StartLine"), int) else None
    end_line = secret.get("EndLine") if isinstance(secret.get("EndLine"), int) else None
    return Finding(
        scanner=NAME,
        rule_id=rule_id,
        title=str(secret.get("Title") or rule_id),
        severity=severity,
        original_severity=original,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        fingerprint=make_fingerprint(
            NAME,
            rule_id,
            file_path,
            location_fingerprint_part(target, file_path, start_line, end_line),
        ),
        metadata={"category": str(secret["Category"])} if secret.get("Category") else {},
    )


def convert_misconfiguration(
    misconfiguration: dict, file_path: str | None, target: Path
) -> Finding:
    rule_id = str(misconfiguration.get("ID") or misconfiguration.get("AVDID") or "unknown")
    severity, original = normalize_severity(misconfiguration.get("Severity"))
    cause = misconfiguration.get("CauseMetadata")
    cause = cause if isinstance(cause, dict) else {}
    start_line = cause.get("StartLine") if isinstance(cause.get("StartLine"), int) else None
    end_line = cause.get("EndLine") if isinstance(cause.get("EndLine"), int) else None

    references = string_list(misconfiguration.get("References"))
    primary_url = misconfiguration.get("PrimaryURL")
    if primary_url and primary_url not in references:
        references.insert(0, str(primary_url))

    metadata = {
        "message": misconfiguration.get("Message"),
        "resolution": misconfiguration.get("Resolution"),
        "avd_id": misconfiguration.get("AVDID"),
    }
    return Finding(
        scanner=NAME,
        rule_id=rule_id,
        title=str(misconfiguration.get("Title") or rule_id),
        description=misconfiguration.get("Description"),
        severity=severity,
        original_severity=original,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        references=references,
        fingerprint=make_fingerprint(
            NAME,
            rule_id,
            file_path,
            location_fingerprint_part(target, file_path, start_line, end_line),
        ),
        metadata={key: str(value) for key, value in metadata.items() if value},
    )
