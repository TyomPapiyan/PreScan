#!/usr/bin/env bash
# PreScan pre-push gate: runs the full local checklist and fails on the first
# mismatch. This is the single source of truth for "green locally" — the CLAUDE.md
# checklist and the pre-push hook both defer to it (no duplicated step lists).
#
# Usage: scripts/check.sh   (or via the git pre-push hook, see README)
set -euo pipefail

cd "$(dirname "$0")/.."

# Prefer the project venv if present, so the hook works without manual activation.
if [[ -x ".venv/bin/python" ]]; then
    export PATH="$PWD/.venv/bin:$PATH"
fi

step() {
    printf '\n\033[1m==> %s\033[0m\n' "$1"
}

step "1/5  ruff check ."
ruff check .

step "2/5  ruff format --check ."
ruff format --check .

step "3/5  mypy src/"
mypy src/

step "4/5  mypy --platform win32 src/"
mypy --platform win32 src/

step "5/5  pytest"
pytest

printf '\n\033[32mAll checks passed.\033[0m\n'
