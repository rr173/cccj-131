#!/usr/bin/env bash
# Run the whole verification suite.  Every command is independent and safe to
# re-run.  Generated databases go to ./run/ (git-ignorable, deletable).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p run

export PYTHONIOENCODING=utf-8
PY=${PYTHON:-python3}

echo "== compile check =="
$PY -m compileall -q receipt_ledger tests

echo
echo "== input / identity rules =="
$PY -I tests/test_inputs.py

echo
echo "== status, corrections, decisions, queries =="
$PY -I tests/test_status.py

echo
echo "== reference independence guard =="
$PY -I tests/test_reference_independence.py

echo
echo "== incremental engine vs brute-force reference (step by step) =="
$PY -I tests/test_reference_crosscheck.py

echo
echo "== main tracked drill =="
$PY -I tests/drill.py > run/drill.txt
tail -n 25 run/drill.txt

echo
echo "== replay the drill through the CLI on a real SQLite file =="
bash scripts/drill_cli.sh

echo
echo "== bulk scenario (10k rows here; python3 -I tests/bulk.py runs 100k) =="
$PY -I tests/bulk.py --quick --out run/bulk | tail -n 25

echo
echo "ALL CHECKS PASSED"
