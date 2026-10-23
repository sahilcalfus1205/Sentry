"""Trivy adapter tests. Mocked: the fixture JSON is hand-written to match Trivy's schema."""

import subprocess
from pathlib import Path

import pytest
from conftest import fixture_text, load_fixture

from sentry_sec.models import RunStatus, Severity
from sentry_sec.scanners import trivy
from sentry_sec.scanners.base import CommandOutput, ScannerError

TARGET = Path("/work/repo")


def parsed():
    return trivy.parse_report(load_fixture("trivy_report.json"), TARGET).findings


def test_vulnerability_is_normalized():
    vulnerability = parsed()[0]
    assert vulnerability.scanner == "trivy"
    assert vulnerability.rule_id == "CVE-2023-32681"
    assert vulnerability.cve == ["CVE-2023-32681"]
    assert vulnerability.cwe == ["CWE-200"]
    assert vulnerability.severity is Severity.MEDIUM
    assert vulnerability.file_path == "requirements.txt"
    assert vulnerability.start_line is None  # Trivy gives no line for package vulns
    assert vulnerability.metadata["package"] == "requests"
    assert vulnerability.metadata["fixed_version"] == "2.31.0"
    assert vulnerability.references[0] == "https://avd.aquasec.com/nvd/cve-2023-32681"


def test_unknown_severity_and_missing_fields():
    vulnerability = parsed()[1]
    assert vulnerability.severity is Severity.UNKNOWN
    assert vulnerability.original_severity == "VERY_BAD"
    assert vulnerability.cve == []  # GHSA id is not a CVE
    assert vulnerability.title == "GHSA-xxxx-yyyy-zzzz in example"
    assert "fixed_version" not in vulnerability.metadata
    assert vulnerability.description is None


def test_misconfiguration_is_normalized_and_passed_checks_skipped():
    findings = parsed()
    misconfigurations = [finding for finding in findings if finding.rule_id.startswith("DS")]
    assert [finding.rule_id for finding in misconfigurations] == ["DS002"]
    assert misconfigurations[0].severity is Severity.HIGH
    assert misconfigurations[0].file_path == "deploy/Dockerfile"
    assert (misconfigurations[0].start_line, misconfigurations[0].end_line) == (1, 4)
    assert "USER" in misconfigurations[0].metadata["resolution"]


def test_secret_is_normalized_without_secret_text():
    secret = parsed()[-1]
    assert secret.rule_id == "aws-access-key-id"
    assert secret.severity is Severity.CRITICAL
    assert secret.start_line == 7
    assert "AWS_KEY" not in repr(secret)  # matched text must not be copied


def test_report_without_results_is_clean():
    result = trivy.parse_report(load_fixture("trivy_empty.json"), TARGET)
    assert result.findings == []


def test_results_of_wrong_type_is_an_error():
    with pytest.raises(ScannerError):
        trivy.parse_report({"Results": "oops"}, TARGET)


def test_nonzero_exit_is_a_failure():
    output = CommandOutput(
        stdout="", stderr="FATAL failed to download vulnerability DB", exit_code=1
    )
    with pytest.raises(ScannerError, match="vulnerability DB"):
        trivy.interpret_output(output, TARGET)


def test_scan_with_mocked_subprocess(fake_subprocess):
    fake_subprocess(stdout=fixture_text("trivy_report.json"))
    run, findings = trivy.scan(TARGET, timeout=60)
    command, _ = fake_subprocess.calls[0]
    assert command[:2] == ["trivy", "fs"]
    assert "--format=json" in command
    assert run.status is RunStatus.COMPLETED
    assert len(findings) == 4


def test_scan_failure_modes(fake_subprocess):
    fake_subprocess(installed=False)
    assert trivy.scan(TARGET, 60)[0].status is RunStatus.NOT_INSTALLED

    fake_subprocess(raises=subprocess.TimeoutExpired(cmd="trivy", timeout=60))
    assert trivy.scan(TARGET, 60)[0].status is RunStatus.TIMED_OUT

    fake_subprocess(stdout="<html>", returncode=0)
    assert trivy.scan(TARGET, 60)[0].status is RunStatus.FAILED
