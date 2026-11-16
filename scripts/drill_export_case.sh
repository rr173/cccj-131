#!/usr/bin/env bash
# Replayable export-case drill on a real SQLite file, entirely through the CLI.
#
#   bash scripts/drill_export_case.sh [workdir]
#
# Builds a source ledger with:
#   * delivery A (retries a1, a2) whose receipt R is ambiguous across A and B;
#   * B has another retry that, with C's attempt, makes receipt S ambiguous;
#   * a receipt T with two competing corrections (a real conflict);
#   * a human decision that later went stale;
#   * a correction group whose original is absent;
#   * an unrelated delivery D, and another recipient sharing A's import file.
# Then exports the case and checks that the sub-ledger alone answers the
# ordinary query commands and rebuild, with the source moved away.
set -euo pipefail
cd "$(dirname "$0")/.."

WORK=${1:-run/drill_export_case}
PY=${PYTHON:-python3}
rm -rf "$WORK"
mkdir -p "$WORK"
DB="$WORK/source.sqlite"

cli() {
  $PY -I -c 'import sys
sys.path.insert(0, sys.argv[1])
from receipt_ledger.cli import main
sys.exit(main(sys.argv[2:]))' "$PWD" "$@"
}

write() { local file=$1; shift; printf '%s\n' "$@" > "$WORK/$file"; }

echo "### init source ledger"
cli init "$DB"

echo
echo "### outbound: A retries, B retries, C retries, unrelated D, shared-file recipient"
write outbound_1.jsonl \
  '{"gateway_id":"gw-main","delivery_id":"D-A","attempt_id":"a1","recipient":"alice@example.com","queue_id":"Q1","envelope_id":"E-U","sent_at":"2026-01-01T00:00:00Z"}' \
  '{"gateway_id":"gw-main","delivery_id":"D-A","attempt_id":"a2","recipient":"alice@example.com","queue_id":"Q1","envelope_id":"E-A2","sent_at":"2026-01-01T00:10:00Z"}' \
  '{"gateway_id":"gw-main","delivery_id":"D-EVE","attempt_id":"e1","recipient":"eve@example.com","queue_id":"Q9","sent_at":"2026-01-01T00:00:00Z"}'
write outbound_2.jsonl \
  '{"gateway_id":"gw-main","delivery_id":"D-B","attempt_id":"b1","recipient":"alice@example.com","queue_id":"Q1","sent_at":"2026-01-01T00:20:00Z"}' \
  '{"gateway_id":"gw-main","delivery_id":"D-B","attempt_id":"b2","recipient":"alice@example.com","queue_id":"Q2","sent_at":"2026-01-01T00:50:00Z"}'
write outbound_3.jsonl \
  '{"gateway_id":"gw-main","delivery_id":"D-C","attempt_id":"c1","recipient":"alice@example.com","queue_id":"Q2","sent_at":"2026-01-01T00:40:00Z"}' \
  '{"gateway_id":"gw-main","delivery_id":"D-C","attempt_id":"c2","recipient":"alice@example.com","queue_id":"Q2","sent_at":"2026-01-01T00:45:00Z"}'
write outbound_4.jsonl \
  '{"gateway_id":"gw-main","delivery_id":"D-X","attempt_id":"x1","recipient":"alice@example.com","queue_id":"Q3","envelope_id":"E-U","sent_at":"2026-01-01T00:15:00Z"}' \
  '{"gateway_id":"gw-main","delivery_id":"D-X","attempt_id":"x2","recipient":"alice@example.com","queue_id":"Q3","envelope_id":"E-X2","sent_at":"2026-01-01T00:25:00Z"}'
write outbound_5.jsonl \
  '{"gateway_id":"gw-main","delivery_id":"D-D","attempt_id":"d1","recipient":"dave@example.com","queue_id":"Q9","sent_at":"2026-01-01T00:00:00Z"}'
cli import-outbound "$DB" "$WORK/outbound_1.jsonl"
cli import-outbound "$DB" "$WORK/outbound_2.jsonl"
cli import-outbound "$DB" "$WORK/outbound_3.jsonl"
cli import-outbound "$DB" "$WORK/outbound_4.jsonl"
cli import-outbound "$DB" "$WORK/outbound_5.jsonl"

echo
echo "### receipts: R (A/B), S (B/C), T (conflict), U (stale decision), D"
write dsn_1.jsonl \
  '{"gateway_id":"gw-main","report_id":"RPT-R","item_id":"ITEM-R","recipient":"alice@example.com","occurred_at":"2026-01-01T01:00:00Z","action":"delivered","queue_id":"Q1"}' \
  '{"gateway_id":"gw-main","report_id":"RPT-S","item_id":"ITEM-S","recipient":"alice@example.com","occurred_at":"2026-01-01T01:10:00Z","action":"delivered","queue_id":"Q2"}' \
  '{"gateway_id":"gw-main","report_id":"RPT-T","item_id":"ITEM-T","recipient":"alice@example.com","occurred_at":"2026-01-01T01:05:00Z","action":"delivered","queue_id":"Q1"}' \
  '{"gateway_id":"gw-main","report_id":"RPT-U","item_id":"ITEM-U","recipient":"alice@example.com","occurred_at":"2026-01-01T00:20:00Z","action":"delivered","envelope_id":"E-U"}'
write dsn_2.jsonl \
  '{"gateway_id":"gw-main","report_id":"RPT-D","item_id":"ITEM-D","recipient":"dave@example.com","occurred_at":"2026-01-01T01:00:00Z","action":"failed","queue_id":"Q9"}'
cli import-dsn "$DB" "$WORK/dsn_1.jsonl"
cli import-dsn "$DB" "$WORK/dsn_2.jsonl"

echo
echo "### the human decision quotes RPT-U's fingerprint, then goes stale"
FP=$(cli fingerprint "$DB" --gateway gw-main --report RPT-U --item ITEM-U \
     | $PY -I -c 'import json,sys; print(json.load(sys.stdin)["candidate_fingerprint"])')
write resolve.jsonl \
  "{\"gateway_id\":\"gw-main\",\"report_id\":\"RPT-U\",\"item_id\":\"ITEM-U\",\"delivery_id\":\"D-X\",\"attempt_id\":\"x1\",\"recipient\":\"alice@example.com\",\"candidate_fingerprint\":\"$FP\",\"decided_at\":\"2026-01-01T00:30:00Z\"}"
cli import-resolutions "$DB" "$WORK/resolve.jsonl"

echo
echo "### competing corrections on T (conflict) and a correction on U"
write corrections.jsonl \
  '{"gateway_id":"gw-main","report_id":"RPT-T-C1","item_id":"ITEM-T-C1","target_report_id":"RPT-T","target_item_id":"ITEM-T","occurred_at":"2026-01-01T02:00:00Z","action":"withdraw"}' \
  '{"gateway_id":"gw-main","report_id":"RPT-T-C2","item_id":"ITEM-T-C2","target_report_id":"RPT-T","target_item_id":"ITEM-T","occurred_at":"2026-01-01T03:00:00Z","action":"failed"}' \
  '{"gateway_id":"gw-main","report_id":"RPT-U-C1","item_id":"ITEM-U-C1","target_report_id":"RPT-U","target_item_id":"ITEM-U","occurred_at":"2026-01-01T00:05:00Z","action":"delivered"}'
cli import-corrections "$DB" "$WORK/corrections.jsonl"

echo
echo "### a correction group whose original never arrived"
write corrections_missing.jsonl \
  '{"gateway_id":"gw-main","report_id":"RPT-M-C1","item_id":"ITEM-M-C1","target_report_id":"RPT-M","target_item_id":"ITEM-M","occurred_at":"2026-01-01T02:00:00Z","action":"failed"}' \
  '{"gateway_id":"gw-main","report_id":"RPT-M-C2","item_id":"ITEM-M-C2","target_report_id":"RPT-M","target_item_id":"ITEM-M","occurred_at":"2026-01-01T03:00:00Z","action":"delivered"}' \
  '{"gateway_id":"gw-main","report_id":"RPT-M-C3","item_id":"ITEM-M-C3","target_report_id":"RPT-M-C1","target_item_id":"ITEM-M-C1","occurred_at":"2026-01-01T04:00:00Z","action":"withdraw"}'
cli import-corrections "$DB" "$WORK/corrections_missing.jsonl"

echo
echo "### source state before export"
cli summary "$DB"
echo "--- conflicts"
cli conflicts "$DB"

echo
echo "### export the case"
write selectors.json \
  '{"deliveries":[{"gateway_id":"gw-main","delivery_id":"D-A","recipient":"alice@EXAMPLE.com"}],"items":[{"gateway_id":"gw-main","report_id":"RPT-M-C1","item_id":"ITEM-M-C1"}]}'
cli export-case "$DB" "$WORK/selectors.json" "$WORK/case"
echo
echo "--- selection.json (carried identities and reasons)"
$PY -I -c 'import json,sys
doc=json.load(open(sys.argv[1]))
print("fact_counts:", json.dumps(doc["fact_counts"]))
print("attempts:")
for a in doc["carried"]["attempts"]:
    print("  %s/%s/%s %s  <- %s" % (a["gateway_id"], a["delivery_id"],
          a["attempt_id"], a["recipient"], "; ".join(a["reasons"])))
print("items:")
for i in doc["carried"]["items"]:
    print("  %s/%s/%s  <- %s" % (i["gateway_id"], i["kind"],
          i["report_id"], "; ".join(i["reasons"])))
print("absent targets:", json.dumps(doc["carried"]["absent_targets"]))
print("receipt groups:")
for g in doc["carried"]["receipt_groups"]:
    print("  %s mark=%s state=%s candidates=%d" % (
        g["root"]["report_id"], g["mark"], g["chain_state"],
        g["candidate_count"]))' "$WORK/case/selection.json"

echo
echo "### move the source away, then query the sub-ledger alone"
mv "$DB" "$DB.hidden"
SUB="$WORK/case/ledger.sqlite"
cli status "$SUB" --gateway gw-main --delivery D-A --recipient alice@example.com
echo "--- R stays ambiguous"
cli explain-item "$SUB" --gateway gw-main --report RPT-R --item ITEM-R
echo "--- T stays conflicted"
cli conflicts "$SUB"
echo "--- the missing-original group stays pending"
cli pending "$SUB"
echo "--- rebuild reproduces the same state"
cli rebuild "$SUB"
cli summary "$SUB"
mv "$DB.hidden" "$DB"

echo
echo "drill complete. sub-ledger: $SUB"
