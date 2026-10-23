#!/usr/bin/env bash
# Remove generated files (caches, build output, local reports) from the project.
# Usage: scripts/clean.sh          caches and build output only
#        scripts/clean.sh --all    also remove the .venv virtual environment
set -euo pipefail

cd "$(dirname "$0")/.."

case "${1:-}" in
  "" | --all) ;;
  *) echo "usage: scripts/clean.sh [--all]" >&2; exit 2 ;;
esac

# Skip .venv and .git so we never touch installed packages or history.
find . \( -name .venv -o -name .git \) -prune -o \
  \( -name __pycache__ -o -name .pytest_cache -o -name .ruff_cache -o -name '*.egg-info' \) \
  -type d -prune -exec rm -rf {} +

rm -rf dist build
rm -f report.json

if [ "${1:-}" = "--all" ]; then
  rm -rf .venv
  echo "Removed caches, build output, reports, and .venv (run 'uv sync' to recreate it)."
else
  echo "Removed caches, build output, and local reports."
fi
