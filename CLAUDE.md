# CLAUDE.md — Sentry (`sentry-sec`)

Permanent engineering rules for this repository. Read this file before starting
any implementation work. Update it only when lasting conventions or
architecture decisions change — not for temporary task notes.

Sentry is a standalone security scanning CLI (Python, managed with `uv`). It
runs external scanners (Semgrep, Trivy), normalizes their findings, and
reports them. Long-term plans (AI triage, finding tracking, GitHub Actions,
Jira) are roadmap items: do not implement them until explicitly requested.

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
  explicit configuration and authorization.

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
