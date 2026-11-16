#!/usr/bin/env bash
# Re-runnable transcript of the archive-import audit.
#
# The expectations printed and checked here are hand-written business facts
# about fixtures/archive/mixed/eml/mixed.eml -- they are not produced by the
# audit.  Every step uses a fresh directory under ./run/audit-drill/.
#
#   block 0  dave@example.com   delivered  2026-02-04T10:00:00Z  Q-1  -> record
#   block 1  erin@example.com   failed     2026-02-04T10:01:00Z  Q-2  -> quarantined
#   block 2  frank@example.com  failed     2026-02-04T10:02:00Z  Q-3  -> record
#
# Scenario:
#   1. convert the batch, import it, audit -> verified (2 imported, 1 quarantine)
#   2. audit a ledger that never saw the file -> incomplete (2 missing)
#   3. import one receipt first from another file, then the batch, audit ->
#      that receipt is deduplicated_existing (not missing)
#   4. a ledger with the batch file registered but one expected fact removed
#      and one unrelated fact added -> both are named, non-zero exit
#   5. tamper with the manifest digest -> invalid_package
#   6. a later correction -> the facts are still imported (audit is fact-only)
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p run
WORK=run/audit-drill
rm -rf "$WORK"
mkdir -p "$WORK"

PY=${PYTHON:-python3}
CLI="$PY -m receipt_ledger.cli"
GATEWAY=gw-main
BATCH="$WORK/batch"
DB="$WORK/ledger.sqlite"
EARLY_DB="$WORK/early.sqlite"
DOC_DB="$WORK/doctored.sqlite"
TAMPER="$WORK/tampered"

fail() { echo "DRILL FAILED: $*" >&2; exit 1; }

say() { echo; echo "== $* =="; }

# run the audit and echo "exit_code outcome"
audit() {
  local db=$1 dir=$2 out rc
  set +e
  out=$($CLI audit-archive-import "$db" "$dir")
  rc=$?
  set -e
  echo "$out" > "$WORK/last.json"
  echo "exit=$rc outcome=$(printf '%s' "$out" | $PY -c \
    'import json,sys; print(json.load(sys.stdin)["outcome"])')"
}

expect() {  # expect <described> <actual> <wanted>
  [ "$2" = "$3" ] || fail "$1: expected $3, got $2"
  echo "ok   $1 = $3"
}

# ------------------------------------------------------------------------- #
say "1. convert + import + audit: every valid receipt found"
$CLI convert-archive fixtures/archive/mixed/eml "$BATCH" --gateway "$GATEWAY" \
  > "$WORK/convert.json"
$CLI init "$DB" > /dev/null
$CLI import-dsn "$DB" "$BATCH/dsn.jsonl" > "$WORK/import.json"

result=$(audit "$DB" "$BATCH")
expect "step 1 exit/outcome" "$result" "exit=0 outcome=verified"
$PY - "$WORK/last.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
rows = [(r["source"]["block_index"], r["record"]["item_id"],
         r["record"]["recipient"], r["record"]["action"], r["result"])
        for r in report["records"]]
assert rows == [
    (0, "item-0", "dave@example.com", "delivered", "imported_by_this_batch"),
    (2, "item-2", "frank@example.com", "failed", "imported_by_this_batch"),
], rows
q = report["quarantine"]
assert [(e["source"]["block_index"], e["expected_in_ledger"]) for e in q] == \
    [(1, False)], q
assert report["summary"]["missing"] == 0, report["summary"]
assert report["summary"]["quarantined_blocks"] == 1, report["summary"]
print("ok   receipts = blocks 0,2 imported; block 1 quarantined, not missing")
PY

# ------------------------------------------------------------------------- #
say "2. a ledger that never imported the batch"
$CLI init "$WORK/empty.sqlite" > /dev/null
result=$(audit "$WORK/empty.sqlite" "$BATCH")
expect "step 2 exit/outcome" "$result" "exit=1 outcome=incomplete"
$PY - "$WORK/last.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
results = [r["result"] for r in report["records"]]
assert results == ["missing", "missing"], results
kinds = [i["kind"] for i in report["issues"]]
assert "batch_file_not_imported" in kinds, kinds
assert report["summary"]["quarantined_blocks"] == 1, report["summary"]
print("ok   both receipts missing; quarantine still not a missing receipt")
PY

# ------------------------------------------------------------------------- #
say "3. one receipt arrived earlier from another file -> dedup, not missing"
$CLI init "$EARLY_DB" > /dev/null
$PY - "$BATCH/dsn.jsonl" "$WORK/early.jsonl" <<'PY'
import json, sys
first = json.loads(open(sys.argv[1], encoding="utf-8").readline())
# a different serialization on purpose: same facts, different file digest
with open(sys.argv[2], "w", encoding="utf-8") as fh:
    fh.write(json.dumps(first, ensure_ascii=False) + "\n")
PY
$CLI import-dsn "$EARLY_DB" "$WORK/early.jsonl" > /dev/null
$CLI import-dsn "$EARLY_DB" "$BATCH/dsn.jsonl" > "$WORK/early-batch.json"
result=$(audit "$EARLY_DB" "$BATCH")
expect "step 3 exit/outcome" "$result" "exit=0 outcome=verified"
$PY - "$WORK/last.json" "$WORK/early.jsonl" <<'PY'
import hashlib, json, sys
report = json.load(open(sys.argv[1]))
by_item = {r["business_identity"]["item_id"]: r for r in report["records"]}
early_sha = hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()
dedup = by_item["item-0"]
assert dedup["result"] == "deduplicated_existing", dedup["result"]
assert dedup["ledger_fact"]["import_file"]["sha256"] == early_sha, dedup
assert by_item["item-2"]["result"] == "imported_by_this_batch", by_item
assert report["summary"]["missing"] == 0, report["summary"]
assert report["summary"]["deduplicated_existing"] == 1, report["summary"]
print("ok   item-0 deduplicated_existing (old provenance kept), item-2 this batch")
PY

# ------------------------------------------------------------------------- #
say "4. same valid line count: one expected fact absent, one unrelated present"
cp "$DB" "$DOC_DB"
$PY - "$DOC_DB" "$BATCH/dsn.jsonl" <<'PY'
import hashlib, sys
sys.path.insert(0, ".")
from receipt_ledger import Ledger, ingest
from receipt_ledger.ingest import gateway_signature, parse_dsn

db, batch = sys.argv[1], sys.argv[2]
batch_sha = hashlib.sha256(open(batch, "rb").read()).hexdigest()
ledger = Ledger.open(db)
try:
    conn = ledger.conn
    # simulate a ledger that registered this exact file but holds a doctored
    # fact set: remove item-2, add an unrelated identity.
    file_id = conn.execute(
        "SELECT id FROM import_file WHERE sha256=?", (batch_sha,)).fetchone()[0]
    conn.execute("DELETE FROM dsn_line WHERE item_id='item-2'"
                 " AND import_file=?", (file_id,))
    gateway = ledger._gateway_row(gateway_signature("gw-main"))
    row = {"gateway_id": "gw-main", "report_id": "rpt-" + "0" * 64,
           "item_id": "item-9", "recipient": "mallory@example.com",
           "occurred_at": "2026-02-04T11:00:00Z", "action": "failed",
           "queue_id": "Q-9"}
    parsed = parse_dsn(row, "drill-doctored")
    conn.execute(
        "INSERT INTO dsn_line (gateway_row, report_id, report_sig, item_id,"
        " item_sig, occurred_at_us, occurred_text, action, recipient_sig,"
        " recipient_text, queue_sig, queue_id, envelope_sig, envelope_id,"
        " canonical_hash, import_file) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (gateway, parsed["report_id"], parsed["report_sig"],
         parsed["item_id"], parsed["item_sig"], parsed["occurred_at_us"],
         parsed["occurred_text"], parsed["action"], parsed["recipient_sig"],
         parsed["recipient"], parsed["queue_sig"], parsed["queue_id"],
         parsed["envelope_sig"], parsed["envelope_id"],
         ledger._dsn_hash("gw-main", parsed), file_id))
    conn.commit()
finally:
    ledger.close()
print("ok   doctored ledger prepared (line count unchanged)")
PY
result=$(audit "$DOC_DB" "$BATCH")
case "$result" in
  exit=0*) fail "step 4: a doctored ledger must not verify ($result)" ;;
  *) echo "ok   step 4 non-zero exit ($result)" ;;
esac
$PY - "$WORK/last.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
by_item = {r["business_identity"]["item_id"]: r for r in report["records"]}
assert by_item["item-2"]["result"] == "missing", by_item["item-2"]
assert by_item["item-0"]["result"] == "imported_by_this_batch", by_item
extra = [(e["identity"]["item_id"], e["kind"])
         for e in report["unexpected_facts"]]
assert extra == [("item-9", "unexpected_identity")], extra
kinds = [i["kind"] for i in report["issues"]]
assert "missing_fact" in kinds, kinds
print("ok   item-2 missing AND item-9 unexpected are named separately")
PY

# ------------------------------------------------------------------------- #
say "5. tampered manifest: declared dsn digest no longer matches the bytes"
cp -r "$BATCH" "$TAMPER"
printf '\n' >> "$TAMPER/dsn.jsonl"
result=$(audit "$DB" "$TAMPER")
expect "step 5 exit/outcome" "$result" "exit=2 outcome=invalid_package"
$PY - "$WORK/last.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
codes = [p["code"] for p in report["package"]["problems"]]
assert "output_digest_mismatch" in codes, codes
assert report["verified"] is False, report
print("ok   output_digest_mismatch named; never verified")
PY

# ------------------------------------------------------------------------- #
say "6. a later correction: the import facts stay, state is not re-judged"
$CLI import-corrections "$DB" <($PY - <<'PY'
import json
print(json.dumps({
    "gateway_id": "gw-main", "report_id": "rpt-corr-1",
    "item_id": "item-corr-1", "target_report_id": "rpt-ignored",
    "target_item_id": "item-0",
    "occurred_at": "2026-02-05T00:00:00Z", "action": "withdraw"}))
PY
) > /dev/null
result=$(audit "$DB" "$BATCH")
expect "step 6 exit/outcome" "$result" "exit=0 outcome=verified"
$PY - "$WORK/last.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
assert all(r["result"] == "imported_by_this_batch" for r in report["records"])
assert "effective_action" not in report["records"][0]
print("ok   facts still imported; no delivery state is restated")
PY

echo
echo "audit drill: all hand-written expectations met"
