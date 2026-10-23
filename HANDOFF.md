# Handoff: where Sentry (`sentry-sec`) stands and what is left

Read this first, then `CLAUDE.md` (permanent engineering rules) and `README.md` (user docs).

## 1. What this project is

A CLI that runs Semgrep and Trivy on a local directory, normalizes their findings into one
format, prints a summary, writes a JSON report, and compares two reports. The long-term vision
is a security assistant with AI triage, GitHub Actions automation, and Jira integration, but
only the local CLI exists today. `sentry-sec` is a working name; the final product name is undecided.

## 2. Quick start

```bash
uv sync
uv run sentry-sec --help
uv run sentry-sec scan <dir> [--scanner semgrep|trivy|all] [--format text|json] [--output f.json]
uv run sentry-sec compare old.json new.json
uv run pytest && uv run ruff check . && uv run ruff format --check .
scripts/clean.sh            # remove caches; --all also removes .venv
```

Semgrep and Trivy must be installed separately (see README). Both need network access
(Semgrep downloads the `p/default` rules; Trivy downloads its vulnerability DB).

## 3. Code map

| File | Responsibility |
|------|----------------|
| `src/sentry_sec/cli.py` | argparse commands `scan` and `compare`, exit codes |
| `models.py` | `Finding`, `ScannerRun`, `ScanResult`, `Severity`, `RunStatus`, `make_fingerprint`, `REPORT_SCHEMA_VERSION` |
| `engine.py` | `run_scan()`: runs selected scanners, aggregates, sorts by severity. No dedup |
| `scanners/base.py` | `execute()` (subprocess, timeout, missing exe, errors), `parse_json`, `location_fingerprint_part` |
| `scanners/semgrep.py`, `trivy.py` | build the command, interpret output, convert to `Finding` |
| `scanners/__init__.py` | `SCANNERS` registry: name to `scan(target, timeout)` |
| `reporting.py` | text summary, JSON report, comparison rendering |
| `tracking.py` | `compare_reports()`: new / persisting / resolved / unverified |
| `tests/` | pytest with fixtures in `tests/fixtures/` and fake subprocess (`conftest.py`) |
| `.github/workflows/ci.yml` | lint, format check, tests on Python 3.11 and 3.13 (mocked tests only) |

Data flow: `cli` calls `engine.run_scan`, which calls each adapter. Each adapter returns
`(ScannerRun, [Finding])`. `reporting` renders a `ScanResult`. `compare` reads two JSON reports
(it never re-scans) and works on plain dicts.

## 4. Key behaviors and decisions (do not undo without a reason)

- **Run status is separate from findings.** A scanner that is missing, timed out, failed, or
  reported errors (partial coverage) makes the scan incomplete. Never report that as clean.
- **`scan` exit codes:** 0 complete, no findings; 1 complete with findings; 2 usage error;
  3 incomplete (takes priority over 1). **`compare`:** 0 reliable, no new; 1 reliable, new;
  2 unreadable report; 3 a report was incomplete.
- **Scanner exit codes:** we do not pass `--error` / `--exit-code`, so any nonzero scanner exit
  means the scan failed, not "findings found".
- **No shell.** Commands are argument lists. We never run scanned code. No `cwd` change, so
  scanner config files in the scanned repo (e.g. `trivy.yaml`) are not picked up from the target.
- **No dedup.** Findings are kept exactly as reported. `compare` matches only by fingerprint
  and counts duplicates (does not collapse them).
- **Fingerprint** = hash of scanner, rule id, relative file path, and a hash of the
  whitespace-trimmed flagged code (falls back to line numbers if the file is unreadable or the
  path escapes the target). Trivy package vulns use package and installed version instead. Only
  hashes are stored, never source text. Trivy secret text (`Match`) is never copied.
- **Unverified findings:** in `compare`, findings from a scanner that was incomplete in the new
  report are listed as unverified, not resolved.
- **Severity mapping:** Semgrep `ERROR` to high, `WARNING` to medium, `INFO` to low; unknown
  values map to `unknown` and the original is kept in `original_severity`.
- **Dependencies:** none at runtime (stdlib only). Dev: pytest, ruff. Keep it that way unless
  there is a real need.
- **JSON report schema** is versioned (`REPORT_SCHEMA_VERSION = 1`). Bump it on incompatible
  changes; `compare` rejects other versions.

## 5. What has and has not been verified

- Done: 57 mocked pytest tests, ruff, CI green on GitHub.
- Real Semgrep 1.182.0 and Trivy 0.76.1 were run manually on a small throwaway project: both
  produced findings, JSON reports, and a working `compare`. This is not automated.
- Gaps: the Trivy fixture in `tests/fixtures/trivy_report.json` is hand-written (the old `DS002`
  id style; real Trivy now emits `DS-0002`). No real captured output is stored. No automated
  tests use real scanners. Other Semgrep and Trivy versions are untested. Large-repo
  performance is untested. Windows is untested.

## 6. Known limitations and small to-dos

1. Editing or reformatting the flagged line changes the fingerprint (shows as resolved + new).
   Reports made before the code-hash change are not comparable with newer ones.
2. Semgrep ruleset is fixed to `p/default`. Add an option for custom or local rules so it can
   run offline (`--semgrep-config` or a config file).
3. Trivy runs `fs` mode only (`vuln,secret,misconfig`). No container image scanning
   (`trivy image`) and no choice of Trivy scanners.
4. Text output shows 25 findings max. Add a flag if needed.
5. Capture real Semgrep and Trivy JSON into `tests/fixtures/` (strip anything sensitive) and
   refresh the Trivy fixture to the current schema.
6. Add real-scanner integration tests marked with a pytest marker, skipped when the tools are
   missing and not run in the default CI job.
7. `pyproject.toml` `authors` and project name/description need a final decision. Add a LICENSE
   if it will be open source. `requires-python` is `>=3.11`.
8. Semgrep's `.semgrepignore` and `# nosem` in the scanned repo can hide findings. Decide
   whether that is acceptable; document or add an opt-out.
9. `compare` output has no severity grouping or file sorting yet.

## 7. Remaining scope, in suggested order

Each stage is separate. Follow `CLAUDE.md`: smallest solution, no speculative features.

### Stage A: Configuration and policy (do before CI gating)
- Optional `sentry.toml` (stdlib `tomllib`, no new dependency): severity threshold for exit
  code 1, scanner list, timeout, Semgrep config, paths to ignore.
- A `--fail-on <severity>` flag. `compare --fail-on` should consider new findings only.
- Treat the config as trusted only when it comes from the invoking user, not from the scanned
  repo.

### Stage B: GitHub Actions scan workflow
- Workflow that installs Semgrep and Trivy and scans pull requests and pushes.
- Upload the JSON report as an artifact. Fail only on new findings above the threshold by
  comparing against the base branch's report.
- SARIF output for GitHub code scanning (new reporting function, new `--format sarif`).
- Security: never give workflows that run untrusted pull request code any secrets. Use
  `permissions:` minimally, and separate privileged jobs (comments, tickets) into a workflow
  triggered by `workflow_run` that only reads artifacts. Avoid `pull_request_target` with
  checkout of PR code.

### Stage C: Finding tracking over time
- Fingerprints that tolerate small edits, e.g. also store the rule and an approximate context;
  keep matching conservative. Different rules on the same line are never merged.
- Status history (new / persisting / resolved / reintroduced) stored as report files or a
  simple JSON store. Do not add a database until files are insufficient.

### Stage D: AI security analyst (optional, never required)
- Input: normalized findings plus source context read from the repo (the code around the
  flagged lines).
- Output: structured assessment: classification (likely genuine / needs review / likely false
  positive), evidence, impact and exploitability, confidence and uncertainty, remediation,
  and what extra information is needed.
- Store it separately from scanner data (e.g. `assessment` next to the finding, clearly
  labeled as AI-generated). Never say a vulnerability is "confirmed" without evidence.
- Treat source files, comments, and scanner text as untrusted. Instructions inside them must
  not override system instructions (prompt injection).
- Use the simplest provider interface (one function that takes a prompt and returns text).
  Core scanning must not import any AI SDK. No API key means the feature is simply off.

### Stage E: Jira integration (separate from scanners and the engine)
- Group related findings into actionable tickets; do not create one ticket per raw finding.
- Avoid duplicate tickets across scans (use fingerprints and a stored ticket key mapping);
  update existing tickets when issues persist or change.
- Ticket contents: locations, evidence, severity, impact, remediation, verification steps.
- Respect confidence and policy before creating anything. Provide a `--dry-run` mode.
- Require explicit configuration and authorization. Credentials only in a trusted (non-PR)
  context.

### Stage F: More scanners (only if there is a concrete need)
- Dedicated secret scanner, IaC scanner, license scanning. Each as one new file in `scanners/`
  that returns `(ScannerRun, [Finding])` and a line in `SCANNERS`. Do not build a plugin framework.

## 8. Working rules for the next person

- Read `CLAUDE.md` before changing anything. Update it only for lasting convention changes.
- Run `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .` before committing.
  Never claim a check passed unless you ran it. Say clearly when a test used mocks.
- Update the README when behavior changes.
- Do not touch other repositories. Do not commit generated files (`scripts/clean.sh` removes them).
