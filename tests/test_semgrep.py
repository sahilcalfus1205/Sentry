"""Semgrep adapter tests. Mocked: they use recorded-style JSON, not a real semgrep."""

import subprocess
from pathlib import Path

import pytest
from conftest import fixture_text, load_fixture

from sentry_sec.models import RunStatus, Severity
from sentry_sec.scanners import semgrep
from sentry_sec.scanners.base import CommandOutput, ScannerError

TARGET = Path("/work/repo")


def test_parse_normal_findings():
    result = semgrep.parse_report(load_fixture("semgrep_report.json"), TARGET)
    first = result.findings[0]
    assert result.version == "1.182.0"
    assert len(result.findings) == 3
    assert first.scanner == "semgrep"
    assert first.rule_id.endswith("subprocess-shell-true")
    assert first.severity is Severity.HIGH
    assert first.original_severity == "ERROR"
    assert first.file_path == "app/run.py"
    assert (first.start_line, first.end_line) == (12, 12)
    assert first.cwe == ["CWE-78"]
    assert first.confidence == "MEDIUM"
    assert first.title == "Found 'subprocess' function 'call' with 'shell=True'."
    assert first.metadata["likelihood"] == "HIGH"
    assert first.fingerprint
    assert result.warnings == []


def test_unknown_severity_is_kept_as_unknown_with_original():
    finding = semgrep.parse_report(load_fixture("semgrep_report.json"), TARGET).findings[1]
    assert finding.severity is Severity.UNKNOWN
    assert finding.original_severity == "SOMETHING_NEW"
    assert finding.cwe == ["CWE-798"]  # CWE given as a plain string
    assert (finding.start_line, finding.end_line) == (3, 5)


def test_missing_optional_fields_are_not_invented():
    finding = semgrep.parse_report(load_fixture("semgrep_report.json"), TARGET).findings[2]
    assert finding.rule_id == "minimal.rule"
    assert finding.file_path is None
    assert finding.start_line is None
    assert finding.confidence is None
    assert finding.original_severity is None
    assert finding.cwe == []
    assert finding.description is None


def test_empty_report_has_no_findings_and_no_warnings():
    result = semgrep.parse_report(load_fixture("semgrep_empty.json"), TARGET)
    assert result.findings == []
    assert result.warnings == []


def test_scan_errors_become_warnings():
    result = semgrep.parse_report(load_fixture("semgrep_partial.json"), TARGET)
    assert result.findings == []
    assert any("1 error" in warning for warning in result.warnings)
    assert any("Syntax error" in warning for warning in result.warnings)


def test_report_without_results_list_is_an_error():
    with pytest.raises(ScannerError):
        semgrep.parse_report({"version": "1"}, TARGET)


def test_nonzero_exit_is_a_failure_not_a_clean_scan():
    output = CommandOutput(stdout="", stderr="invalid configuration", exit_code=2)
    with pytest.raises(ScannerError, match="code 2.*invalid configuration"):
        semgrep.interpret_output(output, TARGET)


def test_scan_with_mocked_subprocess(fake_subprocess):
    fake_subprocess(stdout=fixture_text("semgrep_report.json"), stderr="some progress")
    run, findings = semgrep.scan(TARGET, timeout=30)
    command, kwargs = fake_subprocess.calls[0]
    assert command[:2] == ["semgrep", "scan"]
    assert "--json" in command
    assert command[-1] == str(TARGET)
    assert kwargs.get("shell") is None
    assert kwargs["timeout"] == 30
    assert run.status is RunStatus.COMPLETED
    assert run.finding_count == 3
    assert run.diagnostics == "some progress"  # diagnostics kept alongside findings
    assert len(findings) == 3


def test_scan_malformed_json(fake_subprocess):
    fake_subprocess(stdout="{not json")
    run, findings = semgrep.scan(TARGET, timeout=30)
    assert run.status is RunStatus.FAILED
    assert "malformed JSON" in run.message
    assert findings == []


def test_scan_empty_stdout(fake_subprocess):
    fake_subprocess(stdout="", stderr="boom")
    run, _ = semgrep.scan(TARGET, timeout=30)
    assert run.status is RunStatus.FAILED
    assert run.diagnostics == "boom"


def test_scan_missing_executable(fake_subprocess):
    fake_subprocess(installed=False)
    run, findings = semgrep.scan(TARGET, timeout=30)
    assert run.status is RunStatus.NOT_INSTALLED
    assert fake_subprocess.calls == []
    assert findings == []


def test_scan_timeout(fake_subprocess):
    fake_subprocess(raises=subprocess.TimeoutExpired(cmd="semgrep", timeout=30))
    run, _ = semgrep.scan(TARGET, timeout=30)
    assert run.status is RunStatus.TIMED_OUT
    assert "30 seconds" in run.message


def test_scan_os_error(fake_subprocess):
    fake_subprocess(raises=PermissionError("denied"))
    run, _ = semgrep.scan(TARGET, timeout=30)
    assert run.status is RunStatus.FAILED
    assert "denied" in run.message
