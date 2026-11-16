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
echo "== offline .eml archive import (acceptance) =="
$PY -I tests/test_archive.py

echo
echo "== archive-import reconciliation (audit-archive-import) =="
$PY -I tests/test_audit.py

echo
echo "== offline MTA event reconstruction (acceptance) =="
$PY -I tests/test_mta_events.py

echo
echo "== replay the MTA event reconstruction drill (hand-written expectations) =="
bash scripts/drill_mta_events.sh > run/drill_mta_events.txt
tail -n 22 run/drill_mta_events.txt

echo
echo "== replay the archive audit drill (hand-written expectations) =="
bash scripts/drill_audit_archive.sh > run/drill_audit_archive.txt
tail -n 20 run/drill_audit_archive.txt

echo
echo "== investigation sub-ledger export (export-case) =="
$PY -I tests/test_export_case.py

echo
echo "== main tracked drill =="
$PY -I tests/drill.py > run/drill.txt
tail -n 25 run/drill.txt

echo
echo "== replay the drill through the CLI on a real SQLite file =="
bash scripts/drill_cli.sh

echo
echo "== replay the export-case drill (source moved away) =="
bash scripts/drill_export_case.sh > run/drill_export_case.txt
tail -n 12 run/drill_export_case.txt

echo
echo "== bulk scenario (10k rows here; python3 -I tests/bulk.py runs 100k) =="
$PY -I tests/bulk.py --quick --out run/bulk | tail -n 25

echo
echo "ALL CHECKS PASSED"
