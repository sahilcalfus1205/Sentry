# Handoff: where Sentry (`sentry-sec`) stands and what is left

Read this first, then `CLAUDE.md` (permanent engineering rules) and `README.md` (user docs).

## 1. What this project is

Target product: a **private, internal** code-scanning tool. It runs through GitHub Actions on pushes
to the organization's private repositories, runs deterministic scanners (Semgrep, Trivy), optionally
adds local-AI analysis, and creates or updates Jira tickets without duplicates. One central,
privately hosted Sentry repository serves many application repositories. It must not require
paid APIs or paid services by default (see section 8). Hosted AI models are allowed only as an
explicit opt-in by the user (section 6).

Today only the **local CLI core** exists: scan with Semgrep and Trivy, normalize findings, text and
JSON reports, and `compare` of two reports. No config file, policy, Jira, GitHub Actions scan
workflow, state store, or AI exists yet. `sentry-sec` is the CLI/package name (the name `sentry`
collides with other products); the project may still be called Sentry.

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

## 3. Code map (what exists now)

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
| `.github/workflows/ci.yml` | Sentry's own CI: lint, format check, tests on Python 3.11 and 3.13 (mocked only) |

Data flow: `cli` calls `engine.run_scan`, which calls each adapter. Each adapter returns
`(ScannerRun, [Finding])`. `reporting` renders a `ScanResult`. `compare` reads two JSON reports
(it never re-scans) and works on plain dicts.

## 4. Key behaviors and decisions already implemented (do not undo without a reason)

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
  path escapes the target). Trivy package vulns use package and installed version instead.
  Moving code between lines keeps the fingerprint. Only hashes are stored; Trivy secret text
  (`Match`) is never copied.
- **Unverified findings:** in `compare`, findings from a scanner that was incomplete in the new
  report are listed as unverified, not resolved. The same rule must apply to Jira (section 6).
- **Severity mapping:** Semgrep `ERROR` to high, `WARNING` to medium, `INFO` to low; unknown
  values map to `unknown` and the original is kept in `original_severity`.
- **Dependencies:** none at runtime (stdlib only). Dev: pytest, ruff.
- **JSON report schema** is versioned (`REPORT_SCHEMA_VERSION = 1`). Bump it on incompatible
  changes; `compare` rejects other versions.

## 5. Verification status

- Done: 57 mocked pytest tests, ruff, Sentry's CI green on GitHub.
- Real Semgrep 1.182.0 and Trivy 0.76.1 were run manually on a small throwaway project: both
  produced findings, JSON reports, and a working `compare`. This is not automated.
- Gaps: `tests/fixtures/trivy_report.json` is hand-written (old `DS002` id style; real Trivy now
  emits `DS-0002`). No real captured output is stored. No automated tests use real scanners.
  Other scanner versions, large-repo performance, and Windows are untested.

## 6. Target design from the project brief (not built yet)

### Settled decisions
- Private internal repo; Python; `uv`; CLI-first (no web or desktop app); no public PyPI.
- Central reusable GitHub Actions workflow, called by thin workflows in application repositories,
  pinned to a reviewed release tag or commit SHA (never a development branch).
- Two separate workflows: Sentry's own CI (exists) and a scanning workflow (`sentry-scan.yml`,
  to build).
- Deterministic scanning works fully without AI. AI is optional and off by default. The default
  zero-cost mode uses only local models. A user may explicitly opt in to an external (hosted)
  model with their own credentials; Sentry never switches to one silently or as a fallback.
- Jira via REST API (not Jira Automation rules). No duplicate ticket per repeated finding.
- Zero additional cost target (section 8).

### CLI framework: Typer vs argparse (open conflict, decide early)
The brief names Typer as the CLI framework. The current code uses stdlib `argparse`, which keeps
the project dependency-free and fits `CLAUDE.md` ("no dependency when stdlib is enough"). Decide in
Stage 1: either adopt Typer (small migration confined to `cli.py`; document why) or record
that argparse stays. Do not mix both.

### Config and policy
- `config.py`: load and validate a config file (stdlib `tomllib` preferred), plus
  `sentry-sec config validate`. Per-repository thresholds, exclusions, scanner list, timeouts,
  Semgrep rules, Jira settings.
- `policy.py`: **scanning and the CI gate are separate decisions.** Scan success, findings above
  the severity threshold, scanner failure (incomplete), Jira delivery failure, and AI unavailability
  must produce distinguishable outcomes. Start with: run all configured checks, report, and fail CI
  by configurable severity threshold. Whether Jira delivery failures fail CI is configurable;
  they must be visible and retryable, never silently dropped. Config comes from the invoking
  trusted context, not from the scanned repository's code.

### Finding model additions
Existing fields cover rule, file, severity, description, fingerprint, scanner. Add, as needed:
repository identity, branch/commit, scanner version (Semgrep version is already in the run
record; copy per finding or per report), first/last seen, and an optional AI assessment kept clearly
separate from scanner evidence.
- **Evidence conflict:** the brief wants a minimal code excerpt in findings and tickets; the
  current rule is that reports never contain source text. Resolve as: excerpts are opt-in, short
  (a few lines), never included for secret findings, and passed through the same redaction. Keep
  hashes-only as the default for JSON reports.

### Fingerprints and the finding-to-ticket mapping
- Brief wants repository identity in the fingerprint (add the repo name/identifier, so two repos
  with the same file and rule do not collide), plus scanner, rule, normalized path, and a code
  pattern or symbol. We already hash flagged code. Never merge distinct problems just because they
  share a rule; keep the "unverified, not resolved" rule.
- **Durable mapping** from fingerprint to Jira issue key is required because runners are
  temporary. Preferred first option: make Jira the store, e.g. one label or custom field per ticket
  holding the fingerprint, found with a JQL search before creating. No paid database. Hide behind
  a small `state/store.py` interface so it can be replaced. Must handle concurrent runs and retries
  (Jira create is not idempotent): search before create, record after create, bounded retries,
  rate-limit handling.
- Must also persist enough prior-scan state to know a finding is gone. Options: Jira search of
  open Sentry tickets for the repo (no artifact needed), or a stored previous report. Validate
  against the 500 MB artifact limit before choosing.

### Jira lifecycle
- New finding: create a ticket if it meets the ticketing policy (severity/confidence).
- Existing finding: update only when useful details change.
- Reintroduced: reopen when appropriate, or follow a configurable policy if permanently closed.
- No longer present: resolve **only after a complete successful scan** (never after an incomplete
  one). Reuse `compare`'s reliable/unverified logic.
- Grouping: critical and high get their own tickets; related lower-severity findings may be
  grouped by deterministic rules. Never merge unrelated problems into one ticket.
- Ticket content: actionable summary, severity and confidence, repo and branch, file and
  line/symbol, impact, minimal evidence, remediation, commit/source link, fingerprint, and any
  AI advice explicitly labeled as AI-generated. Never send whole repositories or extra files.
- `--dry-run` shows planned Jira actions without changing Jira. The default local CLI mode must
  be non-destructive (no ticket changes without explicit config and flag).
- `integrations/jira.py` stays independent of scanner adapters and the engine.

### Optional AI (local by default, external models by explicit opt-in)
- Separate module (`ai/analyzer.py`), off by default, enabled by config.
- Provider interface: one small function (prompt in, text out). Start with a local provider (e.g.
  Ollama with an open-weight model). Add an external provider (OpenAI, Anthropic, or any hosted API)
  only when asked for, as another implementation of the same function. Core scanning never imports
  an AI SDK; import provider code lazily only when that provider is selected.
- Local runtime notes: a GitHub-hosted runner is temporary and slow for model downloads; a
  self-hosted runner on existing hardware can keep the model. For the strict zero-cost target, ship
  with AI disabled first.
- **External models rules (all required):**
  - The user selects the provider and model explicitly in config; there is no default external
    provider and no silent fallback from local to hosted (or hosted to another hosted).
  - The API key comes only from an environment variable or CI secret named in config. Never from a
    config file value, never logged.
  - Costs and usage limits belong to the user's own account. Add a per-run cap on findings sent
    and on prompt size; no unbounded loops.
  - Data minimization: send only the selected finding's rule, message, and a short code excerpt, never
    whole files or repositories. Never send matched secret text or findings from secret scanners;
    run excerpts through the same redaction as reports. State in the README that selected
    code leaves the machine and the organization's policy must allow it.
  - Provide a dry run that prints what would be sent without sending it. Reports label
    which provider and model produced each assessment.
  - Prompts treat all source and scanner text as untrusted; the model gets no tools and cannot run
    commands.
- Output: classification (likely genuine / needs review / likely false positive), evidence, impact
  and exploitability, confidence and uncertainty, remediation, extra information needed. Validate its
  structure, label it unverified.
- AI never decides identity, deduplication, suppression, ticket closure, merging, or bypassing CI.
- Source files, comments, and scanner text are untrusted input (prompt injection). The model must
  not be able to disclose secrets or run commands.

## 7. Roadmap (brief's staged order)

Validate each stage before the next. Keep it simple per `CLAUDE.md`.

**Stage 1: Foundation. Mostly done.**
Done: private-ready Python package with `uv`, CLI shell, `CLAUDE.md`, Sentry CI.
Left: decide Typer vs argparse; `config.py` plus `config validate`; finalize CLI command name;
confirm the GitHub repository is private (it was created under a personal account and may be
public; check before adding any internal details).

**Stage 2: Deterministic scanning. Mostly done.**
Done: Semgrep and Trivy adapters, normalized findings, fingerprints, JSON, `compare`, tests.
Left: add repository identity, commit/branch, first/last seen, scanner version to findings or
report; `policy.py` with severity thresholds and `--fail-on`; pick first rule sets and adapters
(review licenses and resource needs); capture real fixtures; optional real-scanner tests under a
pytest marker; Semgrep custom/local rules option; `trivy image` only if a repo needs it.

**Stage 3: Jira integration.**
`integrations/jira.py` (auth, search, create, update, transition), `state/store.py`, dry-run,
duplicate detection, bounded retries and rate limits, safe resolve and reopen rules, ticket
templates, grouping. Decide Jira project, issue types, fields, and workflow transitions. Test only
against a non-production Jira project. Use a dedicated Jira account with minimal permissions.

**Stage 4: GitHub Actions scanning.**
Reusable workflow `sentry-scan.yml` in the private Sentry repo (check org settings allow private
reuse), thin caller workflows in application repos, pinned to a release or SHA. Triggers: pushes on
configured branches, optional pull requests, manual runs for backfills. Install Semgrep and Trivy
in the job, cache dependencies, upload the JSON report as a short-retention artifact, write a job
summary. Optional SARIF output. Verify permissions, repository access, usage limits, error
handling.

**Stage 5: Rollout.**
Enable in one non-critical repository, check ticket quality and Actions usage, then expand
gradually. Define versioning and rollout policy for Sentry releases.

**Stage 6: Optional AI.**
Local provider first: evaluate an open-weight model on existing hardware, measure resources and
accuracy, enable only if it adds value. Then an opt-in external provider behind the same interface,
following the external-model rules in section 6.

## 8. Cost constraints (zero additional cost target)

Figures below were quoted in planning; verify against current official GitHub and Atlassian
documentation and the real billing settings before rollout.

| Area | Allowance | Design response |
|------|-----------|-----------------|
| GitHub Actions | 2,000 standard runner minutes/month, shared with every workflow in the org | Keep scans short, cache, monitor usage. At ~3 min/scan, at most ~666 scans/month if nothing else ran |
| Actions artifacts | 500 MB | Keep only useful reports, short retention |
| Actions cache | 10 GB per repo | Bound caches, avoid duplicate model caches |
| Jira Free | 10 users, 2 GB storage | Minimize duplicate tickets and attachments |
| Jira Automation | 150 steps/month | Use the REST API directly, not automation rules |
| Hosted AI | none assumed | Off by default. If a user opts in, it uses their own API key and billing; enforce per-run caps |

Rules: disable or zero out Actions overage spending where possible; use standard Linux runners
only; no paid APIs, databases, or scanning services; do not run a full local model in every
short-lived hosted job; consider a self-hosted runner if quota is tight. A free hosted AI tier is
not a zero-cost guarantee, and an opted-in hosted model can cost money, so it is never part of the
zero-cost default. "Free" means no new subscriptions or avoidable overages,
not zero total economic cost.

## 9. Security rules for the privileged parts

- Credentials: GitHub Actions secrets (org-level with explicit repo access). Jira token never in
  code or config files. The Jira identity has only the needed project permissions. A hosted AI key
  exists only if the user opts in, and is passed only to the job that calls the model.
- The scan job needs no Jira write access. Only the job that delivers tickets receives Jira
  credentials, and that job must not execute untrusted code.
- Do not expose secrets to untrusted code or fork pull requests. Avoid `pull_request_target`
  with checkout of PR code. Split privileged work into a separate job or `workflow_run` workflow
  that only reads the report artifact.
- Minimal `permissions:` in every workflow. Pin actions and the Sentry workflow to SHAs or
  reviewed tags.
- Never resolve tickets after an incomplete scan. Log ticket keys and outcomes without printing
  credentials or source code.

## 10. Known limitations and small to-dos

1. Editing or reformatting the flagged line changes the fingerprint (resolved + new). Reports
   made before the code-hash change are not comparable with newer ones.
2. Semgrep ruleset is fixed to `p/default` (needs network). Add a custom/local rules option.
3. Trivy runs `fs` mode with `vuln,secret,misconfig` only.
4. Text output shows 25 findings max.
5. `pyproject.toml` `authors` and project description need a final decision. Add a LICENSE only if
   it will be shared (it is meant to be private/internal).
6. Semgrep's `.semgrepignore` and `# nosem` in the scanned repo can hide findings; decide whether
   that is acceptable for org-wide enforcement or needs an opt-out.
7. `compare` output has no severity grouping or file sorting.

## 11. Open decisions (from the brief)

GitHub org and repo setup; final CLI command name; Typer vs argparse; push/PR branch scope;
first rule sets and adapters; AI local model, runtime, hardware budget, and which external providers to support; Jira project, issue types,
fields, transitions; durable mapping implementation; grouping and reopening policies; actual
remaining Actions quota and hardware capacity; Sentry versioning and rollout policy.

## 12. Working rules for the next person

- Read `CLAUDE.md` before changing anything. Update it only for lasting convention changes.
- Run `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .` before committing.
  Never claim a check passed unless you ran it. Say clearly when a test used mocks.
- Update the README when behavior changes.
- Do not touch other repositories. Do not commit generated files or secrets.
