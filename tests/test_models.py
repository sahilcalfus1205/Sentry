from sentry_sec.models import RunStatus, ScannerRun, ScanResult, make_fingerprint


def test_fingerprint_is_stable_and_sensitive_to_parts():
    assert make_fingerprint("a", "b", 1) == make_fingerprint("a", "b", 1)
    assert make_fingerprint("a", "b", 1) != make_fingerprint("a", "b", 2)


def test_fingerprint_parts_do_not_run_together():
    assert make_fingerprint("ab", "c") != make_fingerprint("a", "bc")


def test_run_with_warnings_is_not_complete():
    run = ScannerRun("semgrep", RunStatus.COMPLETED, warnings=["1 file failed to parse"])
    assert not run.is_complete


def test_failed_run_is_not_complete():
    assert not ScannerRun("trivy", RunStatus.FAILED).is_complete


def test_result_with_no_runs_is_not_complete():
    assert not ScanResult(target="x", runs=[], findings=[]).is_complete


def test_result_complete_only_if_every_run_is_complete():
    good = ScannerRun("semgrep", RunStatus.COMPLETED)
    bad = ScannerRun("trivy", RunStatus.NOT_INSTALLED)
    assert ScanResult("x", [good], []).is_complete
    assert not ScanResult("x", [good, bad], []).is_complete
