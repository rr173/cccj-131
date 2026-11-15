#!/usr/bin/env bash
# The main drill replayed through the CLI on a real SQLite file, one JSONL
# material file per step.  Each step prints the state so the transition is
# auditable from the shell alone.
#
#   bash scripts/drill_cli.sh [workdir]
set -euo pipefail
cd "$(dirname "$0")/.."

WORK=${1:-run/drill_cli}
PY=${PYTHON:-python3}
rm -rf "$WORK"
mkdir -p "$WORK"
DB="$WORK/ledger.sqlite"

# -I keeps the interpreter isolated from cwd/site; the project path is added
# explicitly inside the snippet so nothing is picked up implicitly
cli() {
  $PY -I -c 'import sys
sys.path.insert(0, sys.argv[1])
from receipt_ledger.cli import main
sys.exit(main(sys.argv[2:]))' "$PWD" "$@"
}

write() { # write <file> <json-line...>
  local file=$1; shift
  printf '%s\n' "$@" > "$WORK/$file"
}

show() { # show <title> <cli args...>
  echo
  echo "--- $1"
  shift
  "$@" || true
}

echo "### init"
cli init "$DB"

echo
echo "### step 1: only attempt att-1 is registered"
write outbound_1.jsonl \
  '{"gateway_id":"gw","delivery_id":"D-100","attempt_id":"att-1","recipient":"Alice@Example.COM","queue_id":"QUEUE-9","envelope_id":"ENV-A","sent_at":"2026-02-01T00:00:00Z"}' \
  '{"gateway_id":"gw","delivery_id":"D-200","attempt_id":"att-1","recipient":"bob@example.com","queue_id":"QUEUE-B","envelope_id":"ENV-B","sent_at":"2026-02-01T00:00:00Z"}'
write dsn_1.jsonl \
  '{"gateway_id":"gw","report_id":"RPT-1","item_id":"ITEM-1","recipient":"Alice@example.com","occurred_at":"2026-02-01T01:00:00Z","action":"delivered","queue_id":"QUEUE-9"}' \
  '{"gateway_id":"gw","report_id":"RPT-B","item_id":"ITEM-B","recipient":"bob@example.com","occurred_at":"2026-02-01T01:30:00Z","action":"failed","queue_id":"QUEUE-B"}'
cli import-outbound "$DB" "$WORK/outbound_1.jsonl"
cli import-dsn "$DB" "$WORK/dsn_1.jsonl"
show "alice (expect delivered)" cli status "$DB" --gateway gw --delivery D-100 --recipient Alice@example.com
show "bob (expect failed, unaffected)" cli status "$DB" --gateway gw --delivery D-200 --recipient bob@example.com

echo
echo "### step 2: the retry att-2 arrives late and also satisfies the conditions"
write outbound_2.jsonl \
  '{"gateway_id":"gw","delivery_id":"D-100","attempt_id":"att-2","recipient":"Alice@example.com","queue_id":"QUEUE-9","envelope_id":"ENV-B","sent_at":"2026-02-01T00:10:00Z"}'
cli import-outbound "$DB" "$WORK/outbound_2.jsonl"
show "receipt is now ambiguous" cli explain-item "$DB" --gateway gw --report RPT-1 --item ITEM-1
show "alice delivery (expect awaiting)" cli status "$DB" --gateway gw --delivery D-100 --recipient Alice@example.com
show "att-1 (expect awaiting, its proof was revoked)" cli attempt-status "$DB" --gateway gw --delivery D-100 --attempt att-1 --recipient Alice@example.com
show "bob still failed" cli status "$DB" --gateway gw --delivery D-200 --recipient bob@example.com

echo
echo "### step 3: human decision using the *current* candidate fingerprint"
FP=$(cli fingerprint "$DB" --gateway gw --report RPT-1 --item ITEM-1 \
     | $PY -I -c 'import json,sys; print(json.load(sys.stdin)["candidate_fingerprint"])')
echo "current fingerprint: $FP"
write resolve_1.jsonl \
  "{\"gateway_id\":\"gw\",\"report_id\":\"RPT-1\",\"item_id\":\"ITEM-1\",\"delivery_id\":\"D-100\",\"attempt_id\":\"att-2\",\"recipient\":\"Alice@example.com\",\"candidate_fingerprint\":\"$FP\",\"decided_at\":\"2026-02-01T02:00:00Z\"}"
cli import-resolutions "$DB" "$WORK/resolve_1.jsonl"
show "att-2 (expect delivered)" cli attempt-status "$DB" --gateway gw --delivery D-100 --attempt att-2 --recipient Alice@example.com
show "att-1 (expect awaiting)" cli attempt-status "$DB" --gateway gw --delivery D-100 --attempt att-1 --recipient Alice@example.com
show "alice delivery (expect delivered via att-2)" cli status "$DB" --gateway gw --delivery D-100 --recipient Alice@example.com

echo
echo "### step 4: the gateway withdraws the receipt"
write cor_1.jsonl \
  '{"gateway_id":"gw","report_id":"RPT-1-COR1","item_id":"ITEM-1-COR1","target_report_id":"RPT-1","target_item_id":"ITEM-1","occurred_at":"2026-02-01T03:00:00Z","action":"withdraw"}'
cli import-corrections "$DB" "$WORK/cor_1.jsonl"
show "receipt chain (expect withdrawn, history intact)" cli explain-item "$DB" --gateway gw --report RPT-1 --item ITEM-1
show "att-2 (expect awaiting again)" cli attempt-status "$DB" --gateway gw --delivery D-100 --attempt att-2 --recipient Alice@example.com
show "att-1 (expect awaiting, never proven)" cli attempt-status "$DB" --gateway gw --delivery D-100 --attempt att-1 --recipient Alice@example.com
show "bob still failed" cli status "$DB" --gateway gw --delivery D-200 --recipient bob@example.com

echo
echo "### step 5: late arrivals -- pending chain, conflict, stale decision"
write outbound_3.jsonl \
  '{"gateway_id":"gw","delivery_id":"D-300","attempt_id":"att-1","recipient":"carol@example.com","queue_id":"QUEUE-C","sent_at":"2026-03-01T00:00:00Z"}'
cli import-outbound "$DB" "$WORK/outbound_3.jsonl"
write cor_early.jsonl \
  '{"gateway_id":"gw","report_id":"RPT-2-COR1","item_id":"ITEM-2-COR1","target_report_id":"RPT-2","target_item_id":"ITEM-2","occurred_at":"2026-03-01T04:00:00Z","action":"failed"}'
cli import-corrections "$DB" "$WORK/cor_early.jsonl"
show "pending queue (correction before original)" cli pending "$DB"

write dsn_2.jsonl \
  '{"gateway_id":"gw","report_id":"RPT-2","item_id":"ITEM-2","recipient":"carol@example.com","occurred_at":"2026-03-01T01:00:00Z","action":"delivered","queue_id":"QUEUE-C"}'
cli import-dsn "$DB" "$WORK/dsn_2.jsonl"
show "chain completed by the late original" cli explain-item "$DB" --gateway gw --report RPT-2 --item ITEM-2
show "carol (expect failed)" cli status "$DB" --gateway gw --delivery D-300 --recipient carol@example.com
show "nothing pending now" cli pending "$DB"

write cor_rival.jsonl \
  '{"gateway_id":"gw","report_id":"RPT-2-COR2","item_id":"ITEM-2-COR2","target_report_id":"RPT-2","target_item_id":"ITEM-2","occurred_at":"2026-03-01T05:00:00Z","action":"delivered"}'
cli import-corrections "$DB" "$WORK/cor_rival.jsonl"
show "conflict (two corrections on one parent)" cli conflicts "$DB"
show "carol (expect awaiting: conflicted chain contributes nothing)" cli status "$DB" --gateway gw --delivery D-300 --recipient carol@example.com

echo
echo "### step 6: a stale human decision is rejected"
write outbound_4.jsonl \
  '{"gateway_id":"gw","delivery_id":"D-400","attempt_id":"att-1","recipient":"dave@example.com","queue_id":"QUEUE-D","sent_at":"2026-04-01T00:00:00Z"}' \
  '{"gateway_id":"gw","delivery_id":"D-400","attempt_id":"att-2","recipient":"dave@example.com","queue_id":"QUEUE-D","sent_at":"2026-04-01T00:10:00Z"}'
write dsn_3.jsonl \
  '{"gateway_id":"gw","report_id":"RPT-4","item_id":"ITEM-4","recipient":"dave@example.com","occurred_at":"2026-04-01T01:00:00Z","action":"delivered","queue_id":"QUEUE-D"}'
cli import-outbound "$DB" "$WORK/outbound_4.jsonl"
cli import-dsn "$DB" "$WORK/dsn_3.jsonl"
OLD_FP=$(cli fingerprint "$DB" --gateway gw --report RPT-4 --item ITEM-4 \
     | $PY -I -c 'import json,sys; print(json.load(sys.stdin)["candidate_fingerprint"])')
write outbound_5.jsonl \
  '{"gateway_id":"gw","delivery_id":"D-400","attempt_id":"att-3","recipient":"dave@example.com","queue_id":"QUEUE-D","sent_at":"2026-04-01T00:20:00Z"}'
cli import-outbound "$DB" "$WORK/outbound_5.jsonl"
write resolve_stale.jsonl \
  "{\"gateway_id\":\"gw\",\"report_id\":\"RPT-4\",\"item_id\":\"ITEM-4\",\"delivery_id\":\"D-400\",\"attempt_id\":\"att-1\",\"recipient\":\"dave@example.com\",\"candidate_fingerprint\":\"$OLD_FP\",\"decided_at\":\"2026-04-01T02:00:00Z\"}"
echo "--- stale decision (expect a decision_error and exit code 2)"
set +e
cli import-resolutions "$DB" "$WORK/resolve_stale.jsonl"
STATUS=$?
set -e
echo "exit code: $STATUS"
test "$STATUS" -eq 2

echo
echo "### final summary"
cli summary "$DB"
echo
echo "drill replay complete: $DB"
