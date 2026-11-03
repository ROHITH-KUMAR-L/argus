#!/usr/bin/env bash
# Every gate that must pass before a commit. Fails on the first error.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all --check
cargo clippy --quiet --all-targets -- -D warnings
cargo test --quiet 2>&1 | grep -E 'test result' | awk '{p+=$4; f+=$6} END {print "rust: " p " passed, " f " failed"; exit f>0}'
uv run ruff format --check --quiet .
uv run ruff check --quiet .
uv run mypy
uv run pytest -q "$@" | tail -1
echo "ALL CHECKS PASSED"
