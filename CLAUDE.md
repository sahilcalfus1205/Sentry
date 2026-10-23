# CLAUDE.md — Sentry (`sentry-sec`)

Permanent engineering rules for this repository. Read this file before starting
any implementation work. Update it only when lasting conventions or
architecture decisions change — not for temporary task notes.

Sentry is a private, internal security scanning CLI (Python, managed with `uv`).
It runs external scanners (Semgrep, Trivy), normalizes their findings, and
reports them. Planned: policy/config, Jira ticket lifecycle, a reusable GitHub
Actions workflow, and optional AI (local by default, external opt-in). Roadmap and target design are in
`HANDOFF.md`; do not implement a roadmap stage until it is requested.

## Simplicity first

- Choose the simplest solution that correctly solves the problem.
- Keep code readable, explicit, and easy to understand.
- Avoid clever tricks, unnecessary abstraction, overengineering, and premature
  optimization.
- Do not add a dependency or framework when the standard library or a small
  function is enough.
- Do not implement speculative features because they might be useful later.
- Prefer a small, working implementation over a large architecture.

## Architecture and structure

- Small, layered architecture with clear responsibilities:
  - `cli.py` — parse arguments, call the engine, present results, return exit codes.
  - `models.py` — shared finding and scan-result data structures.
  - `engine.py` — coordinate selected scanners, aggregate findings, record
    which scanners ran, failed, or were incomplete.
  - `scanners/` — one adapter per scanner: run the command, parse its JSON,
    convert to shared models.
  - `reporting.py` — terminal summaries and JSON reports.
  - `tracking.py` — compare two JSON reports (new / persisting / resolved); no database.
- The CLI never parses scanner output. Adapters never print summaries. The
  engine is not coupled to a specific scanner.
- Keep modules focused; avoid giant files and circular dependencies.
- Keep data flows explicit and easy to trace.
- Add a module only for a clear separation of responsibilities. No interfaces,
  classes, or layers that give no real benefit. A function beats a class
  hierarchy.
- No plugin frameworks, microservices, databases, or dependency-injection
  frameworks without a concrete requirement.

## Python quality

- Follow PEP 8 and standard Python conventions; use type hints where helpful.
- Descriptive names; focused functions with one responsibility.
- Clear error messages; handle expected failures explicitly.
- No broad `except` that hides errors.
- Avoid duplication. Use dependencies sparingly and document non-obvious ones.

## Security and reliability

- The scanned repository and all scanner output are untrusted data.
- Never execute scanned source code to inspect it.
- Never use `shell=True`; pass subprocess argument lists.
- Handle missing executables, timeouts, malformed output, and nonzero exit codes.
- Never treat a failed or incomplete scan as a clean scan. "No findings" is not
  "secure".
- Do not leak secrets or sensitive source through logs or reports (e.g. mask
  secret values reported by scanners).
- Never claim a vulnerability is confirmed without adequate evidence.
- Keep scanner findings distinct from any future AI-generated assessments.
- Never automatically change scanned code or create external tickets without
  explicit configuration and authorization. Anything that changes an external
  system (Jira) must support a dry run, and the local default is non-destructive.
- Never commit secrets. Credentials come from environment or CI secrets only.
- Never resolve or close a ticket based on an incomplete scan.
- Zero-cost default: do not add paid services. AI, if added, is optional, off
  by default, advisory, and never decides identity, deduplication, suppression,
  or ticket closure. Local models are the default. External (hosted) models are
  allowed only when the user explicitly selects the provider in config, with
  their own key from an environment variable or CI secret. Never fall back to a
  hosted model silently, never send whole files or secret text, cap what is sent
  per run, and support a dry run that shows what would be sent.
- Keep scanning, AI analysis, and Jira integration in separate modules; the
  scanning engine must not depend on either of the others.
- GitHub workflows: minimal `permissions`, no secrets exposed to untrusted
  pull-request code, and reusable workflows/actions pinned to reviewed tags or SHAs.

## Development workflow

- Inspect relevant source and tests before changing anything.
- Make complete, coherent changes; do not touch unrelated files or other repos.
- Update documentation (README) when behavior changes.
- Use `uv` for dependencies, environments, and running commands
  (`uv sync`, `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`).
- Tests: pytest, with fixtures and mocked subprocess calls; automated tests must
  not need installed scanners or network access. Label real-scanner checks
  separately from mocked ones.
- Run relevant tests and checks after meaningful changes.
- Never claim a test or command succeeded unless it was actually run. State any
  check that could not be executed.
- Deduplication is conservative: same line or file is not proof of the same
  issue. Preserve findings unless a clear rule justifies merging.
