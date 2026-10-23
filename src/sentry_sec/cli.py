"""Command-line interface for sentry-sec."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sentry_sec.engine import DEFAULT_TIMEOUT_SECONDS, run_scan
from sentry_sec.reporting import render_text, to_json, write_json
from sentry_sec.scanners import SCANNERS

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_SCAN_INCOMPLETE = 3

EXIT_CODE_HELP = """\
exit codes:
  0  scan completed on every scanner, no findings
  1  scan completed on every scanner, findings reported
  2  usage error (bad arguments or path)
  3  a scanner is missing, failed, timed out, or returned partial results
     (takes priority over 1; the report still lists any findings that were found)
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentry-sec",
        description="Scan a local repository with Semgrep and/or Trivy.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser(
        "scan",
        help="scan a local directory",
        description="Scan a local directory with Semgrep and/or Trivy.",
        epilog=EXIT_CODE_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan.add_argument("path", type=Path, help="directory to scan")
    scan.add_argument(
        "--scanner",
        choices=[*SCANNERS, "all"],
        default="all",
        help="scanner to run (default: all)",
    )
    scan.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="text prints a summary; json prints the report to stdout unless --output is given",
    )
    scan.add_argument(
        "--output", type=Path, help="write the JSON report to this file (requires --format json)"
    )
    scan.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="seconds each scanner may run (default: %(default)g)",
    )
    return parser


def exit_code_for(result_complete: bool, finding_count: int) -> int:
    if not result_complete:
        return EXIT_SCAN_INCOMPLETE
    return EXIT_FINDINGS if finding_count else EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.output and args.format != "json":
        parser.error("--output requires --format json")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    target = args.path.expanduser().resolve()
    if not target.is_dir():
        print(f"error: '{args.path}' is not a directory", file=sys.stderr)
        return EXIT_USAGE

    scanner_names = list(SCANNERS) if args.scanner == "all" else [args.scanner]
    result = run_scan(target, scanner_names, timeout=args.timeout)

    if args.format == "json" and not args.output:
        sys.stdout.write(to_json(result))
    else:
        sys.stdout.write(render_text(result))
    if args.output:
        try:
            write_json(result, args.output)
        except OSError as error:
            print(f"error: could not write report: {error}", file=sys.stderr)
            return EXIT_USAGE
        print(f"JSON report written to {args.output}")

    return exit_code_for(result.is_complete, len(result.findings))


if __name__ == "__main__":
    sys.exit(main())
