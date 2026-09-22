#!/usr/bin/env bash
# Lint, type-check and test the project in a throwaway virtualenv.
set -euo pipefail

cd "$(dirname "$0")"
VENV=${VENV:-.venv}

if [ ! -x "$VENV/bin/python" ]; then
    python3 -m venv "$VENV"
fi

"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e ".[dev]"

echo "== ruff =="
"$VENV/bin/ruff" check src tests scripts
"$VENV/bin/ruff" format --check src tests scripts

echo "== mypy =="
"$VENV/bin/mypy" src

echo "== pytest =="
"$VENV/bin/pytest" --cov=otaudit --cov-report=term-missing --cov-fail-under=90

echo "== sample =="
"$VENV/bin/python" scripts/make_sample.py
"$VENV/bin/otaudit" analyse samples/demo.pcap --scope samples/scope.yaml --report /dev/null
