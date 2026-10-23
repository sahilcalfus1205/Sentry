# Sentry (`sentry-sec`)

A small CLI that runs [Semgrep](https://semgrep.dev) and [Trivy](https://trivy.dev)
on a local directory, normalizes their findings into one format, and prints a
summary or writes a JSON report. Works without AI, cloud accounts, or Jira.

`sentry-sec` is a working name. Current scope: local scanning only.

## What the scanners detect

| Scanner | Detects |
|---------|---------|
| Semgrep | Insecure code patterns in source (injection, unsafe APIs, weak crypto, ...) using the `p/default` registry ruleset |
| Trivy   | Known vulnerabilities in dependencies (lockfiles/manifests), hardcoded secrets, and misconfigurations in Dockerfiles / IaC (Terraform, Kubernetes, ...) |

## Prerequisites

- [uv](https://docs.astral.sh/uv/) and Python 3.11+
- Scanners (Sentry never installs them for you):
  - Semgrep: `brew install semgrep` or `uv tool install semgrep` ([docs](https://semgrep.dev/docs/getting-started/))
  - Trivy: `brew install trivy` or see the [install docs](https://trivy.dev/latest/getting-started/installation/)

**Network:** Semgrep downloads the `p/default` rules from the Semgrep Registry on each run
(metrics are disabled). Trivy downloads its vulnerability DB and checks on first use and
periodically afterwards. Offline scans fail until these are available locally.

## Setup

```bash
uv sync
uv run sentry-sec --help
```

## Usage

```bash
uv run sentry-sec scan .                              # both scanners (default)
uv run sentry-sec scan . --scanner semgrep            # one scanner
uv run sentry-sec scan . --scanner trivy
uv run sentry-sec scan . --scanner all
uv run sentry-sec scan . --format json                # JSON report on stdout
uv run sentry-sec scan . --format json --output report.json   # summary on stdout, JSON in file
uv run sentry-sec scan . --timeout 120                # per-scanner timeout in seconds (default 600)
```

The text summary lists each scanner's status, severity counts, and the first 25 findings.
The JSON report has every finding plus per-scanner status (`completed`, `not_installed`,
`timed_out`, `failed`), warnings, and truncated stderr diagnostics. Severities are normalized
to `critical/high/medium/low/info/unknown`; the scanner's original value is kept.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | All scanners completed fully; no findings |
| 1 | All scanners completed fully; findings reported |
| 2 | Usage error (bad arguments, path is not a directory, report not writable) |
| 3 | A scanner is missing, failed, timed out, or returned partial results. Takes priority over 1; findings found are still reported |

## Troubleshooting

- **`NOT INSTALLED`**: the executable is not on `PATH`. Install it (see above) and retry.
- **`semgrep exited with code 2` / `trivy exited with code 1`**: usually no network (rule or DB
  download) or bad config. The scanner's stderr is shown under `diagnostics` and in the JSON report.
- **`completed with warnings`**: the scanner reported errors, e.g. files it could not parse. The scan
  is treated as incomplete (exit 3).
- **`TIMED OUT`**: raise `--timeout` or scan a smaller directory.

## Limitations

- Findings are scanner results, not confirmed vulnerabilities. Zero findings does not mean secure.
- No deduplication: findings are kept exactly as each scanner reports them.
- Semgrep honors suppression inside the scanned repo (`.semgrepignore`, `# nosem`), so a repo can hide its own findings.
- Trivy package vulnerabilities have no line numbers. Matched secret text is never copied into reports.
- Semgrep ruleset is fixed to `p/default`; no custom rules option yet.
- Tests use mocked scanner output and hand-written fixtures. Semgrep was also run manually against
  a sample file; Trivy has not been validated against a real install.

## Development

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

Project rules are in [CLAUDE.md](CLAUDE.md).

## Roadmap

1. Finding tracking: stable fingerprints, compare scans (new / persisting / resolved).
2. Optional AI triage of findings with source context (provider-independent, never required).
3. GitHub Actions workflow, CI failure policies, SARIF output.
4. Jira ticket grouping and dedup, with dry-run and explicit authorization.
