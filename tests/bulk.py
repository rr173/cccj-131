"""Bulk scenario: 100,000 outbound recipient rows, then sparse late evidence.

What this demonstrates
---------------------
* importing 100k attempts is a handful of statements, not one commit per row;
* a late outbound row or a single receipt touches only the *affected* roots,
  proven by counting the roots re-evaluated and by showing the SQLite query
  plan of the affected-root join;
* the total row work per late arrival does not grow with the size of the repo.

Run with::

    python3 -m tests.bulk              # summary + plans
    python3 -m tests.bulk --quick      # 10k rows instead of 100k
"""

from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helpers import new_ledger  # noqa: E402


def recipient(i):
    return "user%06d@example.com" % i


def build_outbound(rows):
    lines = []
    for i in range(rows):
        lines.append(json.dumps({
            "gateway_id": "bulk-gw",
            "delivery_id": "D%06d" % i,
            "attempt_id": "att-1",
            "recipient": recipient(i),
            "queue_id": "Q%03d" % (i % 200),
            "envelope_id": "E%06d" % i,
            "sent_at": "2026-05-01T00:00:00Z",
        }))
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_dsn(rows, every=100):
    lines = []
    for i in range(0, rows, every):
        lines.append(json.dumps({
            "gateway_id": "bulk-gw",
            "report_id": "R%06d" % i,
            "item_id": "I%06d" % i,
            "recipient": recipient(i),
            "occurred_at": "2026-05-01T01:00:00Z",
            "action": "delivered",
            "queue_id": "Q%03d" % (i % 200),
        }))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _uses_index(plan):
    return any("USING INDEX" in row[3] or "USING COVERING INDEX" in row[3]
               for row in plan)


def query_plan(ledger, sql, params=()):
    return [tuple(row) for row in ledger.conn.execute(
        "EXPLAIN QUERY PLAN " + sql, params)]


def write_artifacts(result, outdir):
    """Write the transcript and query plans so they survive the run."""
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "bulk_result.json"), "w",
              encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, default=str)
    with open(os.path.join(outdir, "bulk_plan.txt"), "w",
              encoding="utf-8") as handle:
        for name, plan in result["plans"].items():
            handle.write(f"## {name}\n")
            for row in plan:
                handle.write("  " + " | ".join(str(col) for col in row) + "\n")
    return outdir


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    rows = 10_000 if "--quick" in argv else 100_000
    evidence_every = 100
    ledger = new_ledger()
    result = {}

    t0 = time.monotonic()
    out = ledger.import_outbound(build_outbound(rows), source="bulk-outbound")
    t_out = time.monotonic() - t0
    t0 = time.monotonic()
    dsn = ledger.import_dsn(build_dsn(rows, evidence_every), source="bulk-dsn")
    t_dsn = time.monotonic() - t0
    result["bulk"] = {"outbound_rows": rows,
                      "receipts": rows // evidence_every,
                      "outbound_seconds": round(t_out, 2),
                      "receipt_seconds": round(t_dsn, 2),
                      "outbound": dict(out), "dsn": dict(dsn)}

    summary = ledger.explain_summary()
    result["after_bulk"] = {
        "deliveries_total": summary["deliveries_total"],
        "delivery_counts": summary["delivery_counts"],
        "proven_delivered": summary["proven_delivered"]}

    # ---- one late outbound row for one recipient ------------------------ #
    # recipient 0 already has a receipt, so the late attempt must flip that
    # receipt from unique to ambiguous -- and nothing else
    late = json.dumps({
        "gateway_id": "bulk-gw", "delivery_id": "D000000",
        "attempt_id": "att-2", "recipient": recipient(0),
        "queue_id": "Q000", "envelope_id": "E-LATE",
        "sent_at": "2026-05-01T00:30:00Z"}) + "\n"
    t0 = time.monotonic()
    late_out = ledger.import_outbound(late.encode(), source="bulk-late-attempt")
    t_late = time.monotonic() - t0
    result["late_attempt"] = {
        "outcome": dict(late_out), "seconds": round(t_late, 4),
        "proven_delivered_after": ledger.explain_summary()[
            "proven_delivered"]}

    # ---- one late receipt ---------------------------------------------- #
    t0 = time.monotonic()
    late_dsn = ledger.import_dsn((json.dumps({
        "gateway_id": "bulk-gw", "report_id": "R-LATE", "item_id": "I-LATE",
        "recipient": recipient(43), "occurred_at": "2026-05-01T02:00:00Z",
        "action": "failed", "envelope_id": "E000043"}) + "\n").encode(),
        source="bulk-late-receipt")
    t_late_dsn = time.monotonic() - t0
    result["late_receipt"] = {"outcome": dict(late_dsn),
                              "seconds": round(t_late_dsn, 4)}

    # ---- query plans ---------------------------------------------------- #
    # temp table exists only inside the import transaction; recreate an empty
    # one so EXPLAIN can resolve the name
    ledger.conn.execute("CREATE TEMP TABLE IF NOT EXISTS new_attempt_ids"
                        " (id INTEGER PRIMARY KEY)")
    result["plans"] = {
        "affected_roots_join": query_plan(
            ledger,
            "SELECT DISTINCT l.line_key FROM item_link l"
            " JOIN outbound_attempt a"
            "   ON a.gateway_row = l.gateway_row"
            "  AND a.recipient_sig = l.recipient_sig"
            " WHERE l.kind='dsn' AND a.id IN (SELECT id FROM new_attempt_ids)"
            "   AND a.sent_at_us <= l.lookup_at_us"
            "   AND (l.cond_queue_sig IS NULL OR l.cond_queue_sig = a.queue_sig)"
            "   AND (l.cond_envelope_sig IS NULL"
            "        OR l.cond_envelope_sig = a.envelope_sig)"),
        "candidate_lookup": query_plan(
            ledger,
            "SELECT id, delivery_id, attempt_id, recipient_sig"
            " FROM outbound_attempt WHERE gateway_row=? AND recipient_sig=?"
            " AND sent_at_us<=? AND queue_sig=? ORDER BY delivery_id,"
            " attempt_id, recipient_sig", (1, b"x", 0, b"q:Q")),
        "last_attempt_per_delivery": query_plan(
            ledger,
            "SELECT * FROM outbound_attempt WHERE gateway_row=? AND"
            " delivery_id=? AND recipient_sig=? ORDER BY sent_at_us DESC,"
            " attempt_id DESC", (1, "D", b"x")),
        "receipts_for_recipient": query_plan(
            ledger,
            "SELECT * FROM item_link WHERE kind='dsn' AND recipient_sig=?"
            " ORDER BY lookup_at_us", (b"x",)),
    }

    scoped = ledger.import_outbound(json.dumps({
        "gateway_id": "bulk-gw", "delivery_id": "D000100",
        "attempt_id": "att-2", "recipient": recipient(100),
        "queue_id": "Q100", "envelope_id": "E-LATE-2",
        "sent_at": "2026-05-01T00:40:00Z"}).encode() + b"\n",
        source="bulk-late-attempt-2")
    result["late_attempt_2"] = dict(scoped)
    result["isolation"] = {
        "roots_re_evaluated_by_one_late_attempt":
            scoped["affected_roots"],
        "note": ("one late attempt for one recipient re-evaluates at most that"
                 " recipient's receipts; no full-repository status rewrite"
                 " happens")}

    final = ledger.explain_summary()
    result["after_late"] = {
        "delivery_counts": final["delivery_counts"],
        "proven_delivered": final["proven_delivered"],
        "receipt_buckets": final["receipt_buckets"]}
    result["after_late"]["ambiguous_roots"] = final["receipt_buckets"].get(
        "ambiguous", 0)
    result["checks"] = {
        "single_late_attempt_re_evaluated_one_root":
            scoped["affected_roots"] == 1,
        "single_late_receipt_re_evaluated_one_root":
            late_dsn["affected_roots"] == 1,
        "bulk_delivered_matches_unique_receipts":
            result["after_bulk"]["proven_delivered"] == rows // evidence_every,
        "late_attempt_revoked_exactly_one_proof":
            result["late_attempt"]["proven_delivered_after"] + 1
            == result["after_bulk"]["proven_delivered"],
        "candidate_lookup_uses_index": _uses_index(
            result["plans"]["candidate_lookup"]),
        "retry_lookup_uses_index": _uses_index(
            result["plans"]["last_attempt_per_delivery"]),
        "receipt_lookup_uses_index": _uses_index(
            result["plans"]["receipts_for_recipient"]),
        "no_full_scan_of_outbound_attempts": not any(
            "SCAN outbound_attempt" in row[3]
            for plan in result["plans"].values() for row in plan),
    }
    failed = [name for name, ok in result["checks"].items() if not ok]
    result["all_checks_passed"] = not failed
    outdir = None
    if "--out" in argv:
        index = argv.index("--out")
        outdir = argv[index + 1] if len(argv) > index + 1 else "run/bulk"
        write_artifacts(result, outdir)
        result["artifacts"] = outdir
    print(json.dumps(result, indent=2, default=str))
    if failed:
        print("FAILED CHECKS: " + ", ".join(failed), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
