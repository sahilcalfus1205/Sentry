"""Engine and reporting tests, using fake scanner functions (no subprocesses)."""

import json
from pathlib import Path

import pytest

from sentry_sec import cli
from sentry_sec.engine import run_scan
from sentry_sec.models import Finding, RunStatus, ScannerRun, Severity
from sentry_sec.reporting import render_text, to_dict, to_json

TARGET = Path("/work/repo")


def finding(scanner, rule_id, severity=Severity.MEDIUM, path="app.py", line=10):
    return Finding(scanner, rule_id, rule_id, severity, file_path=path, start_line=line)


def fake_scanner(run, findings=()):
    return lambda target, timeout: (run, list(findings))


def clean(name):
    return fake_scanner(ScannerRun(name, RunStatus.COMPLETED))


def test_runs_selected_scanners_only():
    scanners = {"semgrep": clean("semgrep"), "trivy": clean("trivy")}
    result = run_scan(TARGET, ["trivy"], scanners=scanners)
    assert [run.scanner for run in result.runs] == ["trivy"]


def test_unknown_scanner_name_is_rejected():
    with pytest.raises(ValueError, match="nope"):
        run_scan(TARGET, ["nope"], scanners={"semgrep": clean("semgrep")})


def test_findings_from_multiple_scanners_are_aggregated_most_severe_first():
    scanners = {
        "semgrep": fake_scanner(
            ScannerRun("semgrep", RunStatus.COMPLETED, finding_count=1),
            [finding("semgrep", "r1", Severity.LOW)],
        ),
        "trivy": fake_scanner(
            ScannerRun("trivy", RunStatus.COMPLETED, finding_count=1),
            [finding("trivy", "CVE-1", Severity.CRITICAL)],
        ),
    }
    result = run_scan(TARGET, ["semgrep", "trivy"], scanners=scanners)
    assert [f.rule_id for f in result.findings] == ["CVE-1", "r1"]
    assert result.is_complete


def test_related_findings_at_same_location_are_not_merged():
    scanners = {
        "semgrep": fake_scanner(
            ScannerRun("semgrep", RunStatus.COMPLETED), [finding("semgrep", "a")]
        ),
        "trivy": fake_scanner(ScannerRun("trivy", RunStatus.COMPLETED), [finding("trivy", "b")]),
    }
    result = run_scan(TARGET, ["semgrep", "trivy"], scanners=scanners)
    assert len(result.findings) == 2


def test_one_failed_scanner_does_not_hide_other_findings_and_marks_scan_incomplete():
    scanners = {
        "semgrep": fake_scanner(
            ScannerRun("semgrep", RunStatus.COMPLETED), [finding("semgrep", "a")]
        ),
        "trivy": fake_scanner(ScannerRun("trivy", RunStatus.NOT_INSTALLED, message="missing")),
    }
    result = run_scan(TARGET, ["semgrep", "trivy"], scanners=scanners)
    assert len(result.findings) == 1
    assert not result.is_complete


def test_json_report_structure_and_keeps_status_separate_from_findings():
    scanners = {"trivy": fake_scanner(ScannerRun("trivy", RunStatus.FAILED, message="boom"))}
    report = json.loads(to_json(run_scan(TARGET, ["trivy"], scanners=scanners)))
    assert report["complete"] is False
    assert report["scanners"][0]["status"] == "failed"
    assert report["summary"]["total_findings"] == 0
    assert report["findings"] == []


def test_json_report_contains_finding_fields():
    scanners = {
        "semgrep": fake_scanner(
            ScannerRun("semgrep", RunStatus.COMPLETED), [finding("semgrep", "a")]
        )
    }
    report = to_dict(run_scan(TARGET, ["semgrep"], scanners=scanners))
    assert report["findings"][0]["severity"] == "medium"
    assert report["summary"]["by_severity"]["medium"] == 1


def test_text_report_never_calls_failed_scan_clean():
    scanners = {"trivy": fake_scanner(ScannerRun("trivy", RunStatus.TIMED_OUT, message="too slow"))}
    text = render_text(run_scan(TARGET, ["trivy"], scanners=scanners))
    assert "INCOMPLETE" in text
    assert "too slow" in text


def test_text_report_for_zero_findings_does_not_claim_security():
    text = render_text(run_scan(TARGET, ["semgrep"], scanners={"semgrep": clean("semgrep")}))
    assert "does not mean the code is secure" in text


@pytest.mark.parametrize(
    ("complete", "count", "expected"),
    [(True, 0, 0), (True, 2, 1), (False, 0, 3), (False, 2, 3)],
)
def test_exit_codes(complete, count, expected):
    assert cli.exit_code_for(complete, count) == expected


def test_cli_rejects_missing_directory(capsys):
    assert cli.main(["scan", "/definitely/not/here"]) == cli.EXIT_USAGE
    assert "not a directory" in capsys.readouterr().err


def test_cli_output_requires_json_format(tmp_path):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["scan", str(tmp_path), "--output", str(tmp_path / "r.json")])
    assert exit_info.value.code == cli.EXIT_USAGE


def test_cli_writes_json_report_and_returns_incomplete_when_scanner_missing(
    tmp_path, fake_subprocess, capsys
):
    fake_subprocess(installed=False)
    report_path = tmp_path / "report.json"
    code = cli.main(["scan", str(tmp_path), "--format", "json", "--output", str(report_path)])
    assert code == cli.EXIT_SCAN_INCOMPLETE
    report = json.loads(report_path.read_text())
    assert {run["status"] for run in report["scanners"]} == {"not_installed"}
    assert "INCOMPLETE" in capsys.readouterr().out
