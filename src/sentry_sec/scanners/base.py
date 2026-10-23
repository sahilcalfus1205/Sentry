"""Shared subprocess execution and error handling for scanner adapters."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sentry_sec.models import Finding, RunStatus, ScannerRun

MAX_DIAGNOSTIC_CHARS = 2000


class ScannerError(Exception):
    """A scanner ran but its result cannot be trusted (bad exit code, bad JSON)."""


@dataclass
class CommandOutput:
    stdout: str
    stderr: str
    exit_code: int


@dataclass
class Interpretation:
    """What an adapter learned from a scanner's output."""

    findings: list[Finding]
    warnings: list[str]
    version: str | None = None


Interpreter = Callable[[CommandOutput], Interpretation]


def truncate(text: str, limit: int = MAX_DIAGNOSTIC_CHARS) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit] + f"... [truncated {len(text) - limit} chars]"


def parse_json(stdout: str, scanner: str) -> dict:
    """Parse scanner stdout as a JSON object, or raise ScannerError."""
    if not stdout.strip():
        raise ScannerError(f"{scanner} produced no output on stdout")
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise ScannerError(f"{scanner} produced malformed JSON: {error}") from error
    if not isinstance(data, dict):
        raise ScannerError(f"{scanner} JSON output is not an object")
    return data


def relative_path(path: str, target: Path) -> str:
    """Make a scanner-reported path relative to the scanned directory when possible."""
    try:
        return Path(path).relative_to(target).as_posix()
    except ValueError:
        return Path(path).as_posix()


def execute(
    scanner: str,
    executable: str,
    arguments: list[str],
    timeout: float,
    interpret: Interpreter,
) -> tuple[ScannerRun, list[Finding]]:
    """Run a scanner as a subprocess and turn the outcome into a ScannerRun.

    Never raises for expected failures; they are recorded in the ScannerRun.
    """
    if shutil.which(executable) is None:
        message = f"'{executable}' was not found on PATH; install it to use this scanner"
        return ScannerRun(scanner, RunStatus.NOT_INSTALLED, message=message), []

    try:
        completed = subprocess.run(  # noqa: S603 - argument list, no shell
            [executable, *arguments],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        message = f"{scanner} did not finish within {timeout:g} seconds"
        return ScannerRun(scanner, RunStatus.TIMED_OUT, message=message), []
    except OSError as error:
        message = f"could not start {scanner}: {error}"
        return ScannerRun(scanner, RunStatus.FAILED, message=message), []

    output = CommandOutput(completed.stdout, completed.stderr, completed.returncode)
    diagnostics = truncate(output.stderr) or None
    try:
        interpretation = interpret(output)
    except ScannerError as error:
        run = ScannerRun(
            scanner,
            RunStatus.FAILED,
            exit_code=output.exit_code,
            message=str(error),
            diagnostics=diagnostics,
        )
        return run, []

    run = ScannerRun(
        scanner,
        RunStatus.COMPLETED,
        version=interpretation.version,
        exit_code=output.exit_code,
        warnings=interpretation.warnings,
        diagnostics=diagnostics,
        finding_count=len(interpretation.findings),
    )
    return run, interpretation.findings
