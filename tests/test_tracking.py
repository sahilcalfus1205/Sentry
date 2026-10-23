import json

import pytest

from sentry_sec import cli
from sentry_sec.models import REPORT_SCHEMA_VERSION
from sentry_sec.tracking import ReportError, compare_reports, load_report


def make_finding(fingerprint, scanner="semgrep", rule_id="rule"):
    return {
        "scanner": scanner,
        "rule_id": rule_id,
        "severity": "high",
        "fingerprint": fingerprint,
        "file_path": "a.py",
        "start_line": 1,
    }


def make_report(findings, incomplete=()):
    names = {finding["scanner"] for finding in findings} | set(incomplete) | {"semgrep"}
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "scanners": [{"scanner": name, "complete": name not in incomplete} for name in names],
        "findings": findings,
    }


def test_new_persisting_and_resolved():
    old = make_report([make_finding("same"), make_finding("fixed")])
    new = make_report([make_finding("same"), make_finding("added")])
    result = compare_reports(old, new)
    assert [f["fingerprint"] for f in result.new] == ["added"]
    assert [f["fingerprint"] for f in result.persisting] == ["same"]
    assert [f["fingerprint"] for f in result.resolved] == ["fixed"]
    assert result.is_reliable


def test_identical_reports_have_nothing_new_or_resolved():
    report = make_report([make_finding("a"), make_finding("b")])
    result = compare_reports(report, report)
    assert result.new == [] and result.resolved == []
    assert len(result.persisting) == 2


def test_different_rules_are_not_matched_just_because_location_matches():
    old = make_report([make_finding("one", rule_id="r1")])
    new = make_report([make_finding("two", rule_id="r2")])
    result = compare_reports(old, new)
    assert len(result.new) == 1 and len(result.resolved) == 1


def test_duplicate_fingerprints_are_counted_not_collapsed():
    old = make_report([make_finding("dup")])
    new = make_report([make_finding("dup"), make_finding("dup")])
    result = compare_reports(old, new)
    assert len(result.persisting) == 1
    assert len(result.new) == 1


def test_finding_from_scanner_that_failed_in_new_report_is_unverified_not_resolved():
    old = make_report([make_finding("cve", scanner="trivy")])
    new = make_report([], incomplete=["trivy"])
    result = compare_reports(old, new)
    assert result.resolved == []
    assert len(result.unverified) == 1
    assert not result.is_reliable


def test_incomplete_old_report_gives_warning():
    old = make_report([], incomplete=["trivy"])
    result = compare_reports(old, make_report([make_finding("x")]))
    assert not result.is_reliable
    assert len(result.new) == 1


def test_load_report_rejects_bad_files(tmp_path):
    with pytest.raises(ReportError, match="cannot read"):
        load_report(tmp_path / "missing.json")

    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{nope")
    with pytest.raises(ReportError, match="not valid JSON"):
        load_report(bad_json)

    wrong_shape = tmp_path / "wrong.json"
    wrong_shape.write_text('{"hello": 1}')
    with pytest.raises(ReportError, match="not a Sentry report"):
        load_report(wrong_shape)

    wrong_version = tmp_path / "version.json"
    wrong_version.write_text(json.dumps({**make_report([]), "schema_version": 99}))
    with pytest.raises(ReportError, match="schema_version"):
        load_report(wrong_version)


def write_report(path, report):
    path.write_text(json.dumps(report))
    return str(path)


def test_cli_compare_exit_codes(tmp_path, capsys):
    old = write_report(tmp_path / "old.json", make_report([make_finding("a")]))
    same = write_report(tmp_path / "same.json", make_report([make_finding("a")]))
    worse = write_report(
        tmp_path / "worse.json", make_report([make_finding("a"), make_finding("b")])
    )
    broken = write_report(tmp_path / "broken.json", make_report([], incomplete=["semgrep"]))

    assert cli.main(["compare", old, same]) == cli.EXIT_CLEAN
    assert cli.main(["compare", old, worse]) == cli.EXIT_FINDINGS
    assert cli.main(["compare", old, broken]) == cli.EXIT_SCAN_INCOMPLETE
    assert cli.main(["compare", old, str(tmp_path / "nope.json")]) == cli.EXIT_USAGE
    assert "cannot read" in capsys.readouterr().err


def test_cli_compare_json_output(tmp_path, capsys):
    old = write_report(tmp_path / "old.json", make_report([make_finding("a")]))
    new = write_report(tmp_path / "new.json", make_report([make_finding("b")]))
    cli.main(["compare", old, new, "--format", "json"])
    output = json.loads(capsys.readouterr().out)
    assert output["summary"] == {"new": 1, "persisting": 0, "resolved": 1, "unverified": 0}
