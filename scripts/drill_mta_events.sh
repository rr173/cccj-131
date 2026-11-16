#!/usr/bin/env bash
# Re-runnable transcript of the offline MTA event reconstruction.
#
# The expectations checked here are hand-written business facts about the
# committed fixtures under fixtures/mta_events/ -- they are not produced by
# the reconstructor.  Every step uses a fresh directory under
# ./run/mta-drill/ and the original logs are never modified.
#
# Scenario coverage (see tests/mta_samples.py):
#   main             two recipients, one deferred->sent retry, a duplicate
#                    rotation-boundary line, reverse-time file order
#   reused           same host/queue id, two lifetimes, same Message-ID
#   missing_queued   delivery/removed with no lifecycle -> orphans
#   requeued         second queued before the first removed -> quarantine
#   content_conflict same time/recipient, contradictory results -> quarantine
#   ambiguous        same recipient, two deliveries at one timestamp
#   bad_lines        unknown event, malformed event, bad recipient, bad JSON
#   undecodable      non-UTF-8 file -> batch failure, no output
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p run
WORK=run/mta-drill
rm -rf "$WORK"
mkdir -p "$WORK"

PY=${PYTHON:-python3}
CLI="$PY -m receipt_ledger.cli"
GATEWAY=gw-main

fail() { echo "DRILL FAILED: $*" >&2; exit 1; }
say() { echo; echo "== $* =="; }
expect() {  # expect <described> <actual> <wanted>
  [ "$2" = "$3" ] || fail "$1: expected $3, got $2"
  echo "ok   $1 = $3"
}

# ------------------------------------------------------------------------- #
say "1. main sample: three per-recipient attempts, stable retry numbering"
OUT="$WORK/main-out"
$CLI import-mta-events fixtures/mta_events/main "$OUT" --gateway "$GATEWAY" \
  > "$WORK/main-summary.json"
$PY - "$WORK/main-summary.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["records"] == 3, s
assert s["source_lines"] == 6 and s["logical_events"] == 5, s
assert s["emitted_lifecycles"] == 1 and s["quarantined_lifecycles"] == 0, s
PY
echo "ok   summary tallies"

# hand-numbered per-recipient retry facts
$PY - "$OUT/outbound.jsonl" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
assert len(rows) == 3, rows
by = {(r["recipient"], r["attempt_id"]): r for r in rows}
alice = sorted((r for r in rows if r["recipient"] == "alice@example.com"),
               key=lambda r: r["attempt_id"])
assert [r["sent_at"] for r in alice] == [
    "2026-03-10T10:05:00Z", "2026-03-10T10:10:00Z"], alice
assert all(r["queue_id"] == "Q-100" and r["envelope_id"] == "<msg-main-1>"
           and r["gateway_id"] == "gw-main" for r in rows), rows
bob = [r for r in rows if r["recipient"] == "bob@example.com"]
assert len(bob) == 1 and bob[0]["attempt_id"] == "att-1", bob
# deferred then sent map to distinct attempts of one delivery
assert len({r["delivery_id"] for r in rows}) == 1, rows
PY
echo "ok   three attempts with hand-numbered retries"

# the duplicate boundary line keeps both source coordinates
$PY - "$OUT/manifest.jsonl" <<'PY'
import json, sys
man = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
lines = [m for m in man if m["type"] == "event_line"]
dups = [m for m in lines if m["duplicate_of"]]
assert len(dups) == 1, dups
d = dups[0]
coords = sorted((m["file"], m["line"]) for m in lines
                if m["event_digest"] == d["event_digest"])
assert coords == [("mta-49-early.jsonl", 1), ("mta-50-late.jsonl", 2)], coords
assert d["outbound"]["recipient"] == "alice@example.com" \
    and d["outbound"]["attempt_id"] == "att-2", d
PY
echo "ok   duplicate line retains both source coordinates"

# ------------------------------------------------------------------------- #
say "2. products import straight into a ledger and query as hand facts"
DB="$WORK/ledger.sqlite"
$CLI init "$DB" > /dev/null
$CLI import-outbound "$DB" "$OUT/outbound.jsonl" > "$WORK/import.json"
expect "imported rows" "$($PY -c \
  'import json;print(json.load(open("'"$WORK/import.json"'"))["inserted"])')" 3
DLV=$($PY -c 'import json;print(json.loads(open("'"$OUT/outbound.jsonl"'").readline())["delivery_id"])')
$CLI attempt-status "$DB" --gateway "$GATEWAY" --delivery "$DLV" \
  --attempt att-2 --recipient alice@example.com > "$WORK/status.json"
$PY - "$WORK/status.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["status"] == "awaiting" and s["attempt_id"] == "att-2", s
PY
echo "ok   gateway/delivery/attempt/recipient lookup works"

# ------------------------------------------------------------------------- #
say "3. queue id reused after removed with the same Message-ID never merges"
$CLI import-mta-events fixtures/mta_events/reused "$WORK/reused-out" \
  --gateway "$GATEWAY" > /dev/null
$PY - "$WORK/reused-out/outbound.jsonl" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
ids = {r["delivery_id"] for r in rows}
assert len(ids) == 2, ids                       # two mails, two deliveries
assert {r["envelope_id"] for r in rows} == {"<msg-reused>"}
carol = [r for r in rows if r["recipient"] == "carol@example.org"]
dave = sorted((r for r in rows if r["recipient"] == "dave@example.org"),
              key=lambda r: r["attempt_id"])
assert len(carol) == 1 and [r["attempt_id"] for r in dave] == [
    "att-1", "att-2"], rows
PY
echo "ok   two lifecycles, two delivery ids, independent retry sequences"

# ------------------------------------------------------------------------- #
say "4. isolation scenarios"
$CLI import-mta-events fixtures/mta_events/missing_queued \
  "$WORK/orphan-out" --gateway "$GATEWAY" > /dev/null
$PY - "$WORK/orphan-out" <<'PY'
import json, os, sys
out = sys.argv[1]
rows = [json.loads(l) for l in open(os.path.join(out, "outbound.jsonl"))]
q = [json.loads(l) for l in open(os.path.join(out, "quarantine.jsonl"))]
assert rows == [] and sorted(x["category"] for x in q) == [
    "orphan_event", "orphan_event"], q
PY
echo "ok   missing queued -> orphan reports, no guessed rows"

$CLI import-mta-events fixtures/mta_events/requeued "$WORK/rq-out" \
  --gateway "$GATEWAY" > /dev/null
$PY - "$WORK/rq-out" <<'PY'
import json, os, sys
out = sys.argv[1]
rows = [json.loads(l) for l in open(os.path.join(out, "outbound.jsonl"))]
q = [json.loads(l) for l in open(os.path.join(out, "quarantine.jsonl"))]
assert [x["category"] for x in q] == ["queued_before_removed"], q
assert [r["recipient"] for r in rows] == ["grace@example.net"], rows
PY
echo "ok   requeued lifecycle quarantined; neighbor lifecycle still emits"

$CLI import-mta-events fixtures/mta_events/content_conflict "$WORK/cf-out" \
  --gateway "$GATEWAY" > /dev/null
$PY - "$WORK/cf-out" <<'PY'
import json, os, sys
out = sys.argv[1]
rows = [json.loads(l) for l in open(os.path.join(out, "outbound.jsonl"))]
q = [json.loads(l) for l in open(os.path.join(out, "quarantine.jsonl"))]
assert [x["category"] for x in q] == ["content_conflict"], q
assert [r["recipient"] for r in rows] == ["ivan@example.net"], rows
PY
echo "ok   content conflict isolated; valid neighbor unaffected"

$CLI import-mta-events fixtures/mta_events/ambiguous "$WORK/am-out" \
  --gateway "$GATEWAY" > /dev/null
$PY - "$WORK/am-out" <<'PY'
import json, os, sys
out = sys.argv[1]
rows = [json.loads(l) for l in open(os.path.join(out, "outbound.jsonl"))]
q = [json.loads(l) for l in open(os.path.join(out, "quarantine.jsonl"))]
assert rows == [] and [x["category"] for x in q] == [
    "ambiguous_delivery_order"], q
PY
echo "ok   same-timestamp retries quarantined, never line-number ordered"

$CLI import-mta-events fixtures/mta_events/bad_lines "$WORK/bad-out" \
  --gateway "$GATEWAY" > /dev/null
$PY - "$WORK/bad-out" <<'PY'
import json, os, sys
out = sys.argv[1]
rows = [json.loads(l) for l in open(os.path.join(out, "outbound.jsonl"))]
q = [json.loads(l) for l in open(os.path.join(out, "quarantine.jsonl"))]
assert sorted(x["category"] for x in q) == sorted([
    "invalid_json", "unknown_event", "malformed_event",
    "invalid_recipient"]), q
assert [r["recipient"] for r in rows] == ["leo@example.io"], rows
coords = sorted((x["source"]["line"] for x in q if x["kind"] == "event_line"))
assert coords == [2, 3, 4, 5], coords
PY
echo "ok   line-level isolation scoped to the bad lines"

# ------------------------------------------------------------------------- #
say "5. undecodable file and existing target: failed publish leaves nothing"
set +e
out=$($CLI import-mta-events fixtures/mta_events/undecodable \
  "$WORK/should-not-exist" --gateway "$GATEWAY" 2>&1)
rc=$?
set -e
expect "undecodable exit" "$rc" 2
echo "$out" | $PY -c 'import json,sys; assert json.load(sys.stdin)["code"] == "input_error"'
[ ! -e "$WORK/should-not-exist" ] || fail "undecodable: output directory appeared"
echo "ok   no partial output after decode failure"

set +e
out=$($CLI import-mta-events fixtures/mta_events/main "$OUT" \
  --gateway "$GATEWAY" 2>&1)
rc=$?
set -e
expect "existing target exit" "$rc" 2
echo "$out" | $PY -c 'import json,sys; assert json.load(sys.stdin)["code"] == "output_exists"'
echo "ok   existing target refused and left intact"

# ------------------------------------------------------------------------- #
say "6. determinism: rearranged files and lines produce identical business output"
mkdir -p "$WORK/rearranged"
$PY - "$WORK/rearranged" <<'PY'
import json, os, sys
from tests.mta_samples import MAIN
target = sys.argv[1]
events = [e for f in MAIN.values() for e in f]
order = [4, 1, 5, 0, 2, 3]           # shuffled physical line order
with open(os.path.join(target, "z-one.jsonl"), "w") as h:
    for i in order:
        h.write(json.dumps(events[i]) + "\n")
    h.write(json.dumps(events[3]) + "\n")   # third copy of the boundary line
PY
$CLI import-mta-events "$WORK/rearranged" "$WORK/rearranged-out" \
  --gateway "$GATEWAY" > /dev/null
cmp "$OUT/outbound.jsonl" "$WORK/rearranged-out/outbound.jsonl"
cmp "$OUT/quarantine.jsonl" "$WORK/rearranged-out/quarantine.jsonl"
echo "ok   canonical business output identical regardless of arrangement"

echo
echo "MTA event reconstruction drill completed"
