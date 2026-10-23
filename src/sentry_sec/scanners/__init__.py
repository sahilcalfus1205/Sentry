"""Scanner adapters. Each exposes `scan(target, timeout) -> (ScannerRun, findings)`."""

from sentry_sec.scanners import semgrep, trivy

SCANNERS = {
    semgrep.NAME: semgrep.scan,
    trivy.NAME: trivy.scan,
}
