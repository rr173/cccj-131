"""The main tracked drill.

Reproduces, step by step and with every state printed, the required scenario:

1. one recipient, two attempts of the same delivery sharing a queue_id;
2. initially only attempt 1 is registered, a ``delivered`` receipt is
   temporarily unique and proves attempt 1 delivered;
3. attempt 2 is registered late (also satisfying the time condition) and the
   same receipt becomes *ambiguous* -- attempt 1 must stop looking delivered;
4. a human decides, with the *new* candidate fingerprint, that the receipt
   belongs to attempt 2; attempt 2 becomes delivered;
5. the gateway corrects (withdraws) that receipt; attempt 2 returns to
   awaiting, and attempt 1 is still *not* proven successful;
6. another recipient's ``failed`` receipt is unaffected throughout;
7. late arrivals: a correction arriving before its original, two competing
   branches on one parent, and an over-due human decision -- each listed with
   its status and exclusion reason.

Run with::

    python3 -m tests.drill            # human-readable transcript
    python3 -m tests.drill --json     # machine-readable transcript
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from receipt_ledger import DecisionError  # noqa: E402
from receipt_ledger.reference import ReferenceSnapshot  # noqa: E402
from tests.helpers import (correction, dsn, jsonl, new_ledger,  # noqa: E402
                           outbound, resolution)

STEPS = []


def record(step, ledger, extra=None):
    """Capture the state after a step for both transcript forms."""
    snap = ReferenceSnapshot(ledger.conn)
    ref_attempts = {(gw, d, a, r.hex()): s
                    for (gw, d, a, r), s in snap.attempt_statuses().items()}
    ref_deliveries = {(gw, d, r.hex()): info["status"]
                      for (gw, d, r), info in
                      snap.delivery_statuses().items()}
    summary = ledger.explain_summary()
    links = []
    for row in ledger.conn.execute(
            "SELECT line_key, chain_state, mark, effective_action,"
            " effective_at_us, candidate_fp, candidate_net,"
            " delivery_id, attempt_id, assigned_kind, contributes, note"
            " FROM item_link WHERE kind='dsn' ORDER BY line_key"):
        links.append({
            "line_key": row["line_key"],
            "chain_state": row["chain_state"],
            "mark": row["mark"],
            "effective_action": row["effective_action"],
            "effective_at_us": row["effective_at_us"],
            "candidate_fingerprint": row["candidate_fp"],
            "candidate_count": len(json.loads(row["candidate_net"])),
            "assigned": (None if row["delivery_id"] is None else
                         {"delivery_id": row["delivery_id"],
                          "attempt_id": row["attempt_id"],
                          "assigned_by": row["assigned_kind"]}),
            "contributes": bool(row["contributes"]),
            "note": row["note"],
        })
    entry = {
        "step": step,
        "delivery_counts": summary["delivery_counts"],
        "proven_delivered": summary["proven_delivered"],
        "receipt_buckets": summary["receipt_buckets"],
        "receipts": links,
        "engine_attempts": {
            "%s/%s/%s/%s" % (gw, d, a, bytes(r).hex()): s
            for (gw, d, a, r), s in _engine_attempt_statuses(ledger).items()},
        "reference_attempts": {
            "%s/%s/%s/%s" % k: v for k, v in ref_attempts.items()},
        "reference_delivery": {
            "%s/%s/%s" % k: v for k, v in ref_deliveries.items()},
        "pending": ledger.pending_associations(),
        "conflicts": ledger.correction_conflicts(),
    }
    entry.update(extra or {})
    if entry["engine_attempts"] != entry["reference_attempts"]:
        raise AssertionError(
            f"step {step}: engine and reference disagree\n"
            f"engine={entry['engine_attempts']}\n"
            f"reference={entry['reference_attempts']}")
    STEPS.append(entry)
    return entry


def _engine_attempt_statuses(ledger):
    rows = ledger.conn.execute(
        "SELECT g.ident, s.delivery_id, s.attempt_id, s.recipient_sig,"
        " s.status FROM derived_attempt_status s JOIN gateway g"
        " ON g.id = s.gateway_row").fetchall()
    return {(row[0].decode().removeprefix("i:"), row[1], row[2],
             bytes(row[3])): row[4] for row in rows}


def run():
    del STEPS[:]
    led = new_ledger()

    # ---- step 1: only the first attempt is registered ------------------- #
    led.import_outbound(jsonl(
        outbound("gw-main", "D-100", "att-1", "Alice@Example.COM",
                 "2026-02-01T00:00:00Z", queue="QUEUE-9", envelope="ENV-A"),
        # an unrelated recipient's attempt, failed the whole time
        outbound("gw-main", "D-200", "att-1", "bob@example.com",
                 "2026-02-01T00:00:00Z", queue="QUEUE-B", envelope="ENV-B"),
    ))
    led.import_dsn(jsonl(
        # domain case differs from the outbound row, local part is identical:
        # only the ASCII domain is case-folded by project convention
        dsn("gw-main", "RPT-1", "ITEM-1", "Alice@example.com",
            "2026-02-01T01:00:00Z", "delivered", queue="QUEUE-9"),
        dsn("gw-main", "RPT-B", "ITEM-B", "bob@example.com",
            "2026-02-01T01:30:00Z", "failed", queue="QUEUE-B"),
    ))
    step1 = record("1. only attempt att-1 registered; receipt RPT-1/ITEM-1 "
                   "unique -> att-1 delivered", led)
    assert step1["engine_attempts"][
        "gw-main/D-100/att-1/723a416c696365406578616d706c652e636f6d"
    ] == "delivered"
    assert step1["engine_attempts"][
        "gw-main/D-200/att-1/723a626f62406578616d706c652e636f6d"] == "failed"

    # ---- step 2: the retry arrives late and also matches ---------------- #
    led.import_outbound(jsonl(
        outbound("gw-main", "D-100", "att-2", "Alice@example.com",
                 "2026-02-01T00:10:00Z", queue="QUEUE-9", envelope="ENV-B"),
    ))
    step2 = record("2. retry att-2 registered late (same queue, sent before "
                   "occurred_at) -> receipt ambiguous", led)
    assert step2["receipts"][0]["mark"] == "ambiguous"
    assert step2["engine_attempts"][
        "gw-main/D-100/att-1/723a416c696365406578616d706c652e636f6d"
    ] == "awaiting"
    assert step2["engine_attempts"][
        "gw-main/D-200/att-1/723a626f62406578616d706c652e636f6d"] == "failed"

    # ---- step 3: a human resolves it onto the second attempt ------------ #
    item = led.explain_item("gw-main", "RPT-1", "ITEM-1")
    new_fp = item["candidate_fingerprint"]
    led.import_resolutions(jsonl(resolution(
        "gw-main", "RPT-1", "ITEM-1", "D-100", "att-2", "Alice@example.com",
        new_fp, "2026-02-01T02:00:00Z")))
    step3 = record("3. human decision with the *new* fingerprint picks att-2 "
                   "-> att-2 delivered, att-1 still awaiting", led)
    assert step3["engine_attempts"][
        "gw-main/D-100/att-2/723a416c696365406578616d706c652e636f6d"
    ] == "delivered"
    assert step3["engine_attempts"][
        "gw-main/D-100/att-1/723a416c696365406578616d706c652e636f6d"
    ] == "awaiting"

    # ---- step 4: the gateway withdraws that receipt --------------------- #
    led.import_corrections(jsonl(correction(
        "gw-main", "RPT-1-COR1", "ITEM-1-COR1", "RPT-1", "ITEM-1",
        "2026-02-01T03:00:00Z", "withdraw")))
    step4 = record("4. correction withdraws RPT-1/ITEM-1 -> att-2 awaiting; "
                   "att-1 still not proven", led)
    assert step4["engine_attempts"][
        "gw-main/D-100/att-2/723a416c696365406578616d706c652e636f6d"
    ] == "awaiting"
    assert step4["engine_attempts"][
        "gw-main/D-100/att-1/723a416c696365406578616d706c652e636f6d"
    ] == "awaiting"
    assert step4["engine_attempts"][
        "gw-main/D-200/att-1/723a626f62406578616d706c652e636f6d"] == "failed"
    assert step4["receipts"][0]["mark"] == "withdrawn"
    # the withdrawn chain still lets you see the original evidence
    detail = led.explain_item("gw-main", "RPT-1", "ITEM-1")
    assert [node["line_key"] for node in detail["chain"]] == ["dsn:1", "cor:1"]
    assert detail["effective_action"] is None
    assert step4["proven_delivered"] == 0

    # ---- step 5: correction before original, two branches, stale decision #
    led2 = new_ledger()
    led2.import_outbound(jsonl(
        outbound("gw-late", "D-300", "att-1", "carol@example.com",
                 "2026-03-01T00:00:00Z", queue="QUEUE-C")))
    # correction arrives first, referring to a not-yet-imported receipt
    early = led2.import_corrections(jsonl(correction(
        "gw-late", "RPT-2-COR1", "ITEM-2-COR1", "RPT-2", "ITEM-2",
        "2026-03-01T04:00:00Z", "failed")))
    late_pending = record(
        "5a. correction for RPT-2 arrives before the original -> pending, "
        "contributes nothing", led2, {"import": early})
    assert late_pending["pending"][0]["category"] == "correction_pending"
    assert late_pending["proven_delivered"] == 0

    led2.import_dsn(jsonl(dsn(
        "gw-late", "RPT-2", "ITEM-2", "carol@example.com",
        "2026-03-01T01:00:00Z", "delivered", queue="QUEUE-C")))
    completed = record(
        "5b. the original arrives -> pending correction completes the chain; "
        "end action failed wins", led2)
    assert completed["receipts"][0]["chain_state"] == "clean"
    assert completed["receipts"][0]["effective_action"] == "failed"
    assert completed["engine_attempts"][
        "gw-late/D-300/att-1/723a6361726f6c406578616d706c652e636f6d"
    ] == "failed"

    # a second, competing correction on the same parent -> conflict
    led2.import_corrections(jsonl(correction(
        "gw-late", "RPT-2-COR2", "ITEM-2-COR2", "RPT-2", "ITEM-2",
        "2026-03-01T05:00:00Z", "delivered")))
    conflicted = record(
        "5c. a second, different correction targets the same parent -> "
        "correction_conflict; the whole chain stops contributing", led2)
    assert conflicted["receipts"][0]["chain_state"] == "conflict"
    assert conflicted["engine_attempts"][
        "gw-late/D-300/att-1/723a6361726f6c406578616d706c652e636f6d"
    ] == "awaiting"
    assert conflicted["conflicts"][0]["branches"]

    # over-due decision: a fingerprint captured before the conflict
    fresh = new_ledger()
    fresh.import_outbound(jsonl(
        outbound("gw-stale", "D-400", "att-1", "dave@example.com",
                 "2026-04-01T00:00:00Z", queue="QUEUE-D"),
        outbound("gw-stale", "D-400", "att-2", "dave@example.com",
                 "2026-04-01T00:10:00Z", queue="QUEUE-D")))
    fresh.import_dsn(jsonl(dsn(
        "gw-stale", "RPT-4", "ITEM-4", "dave@example.com",
        "2026-04-01T01:00:00Z", "delivered", queue="QUEUE-D")))
    stale_fp = fresh.explain_item("gw-stale", "RPT-4", "ITEM-4")[
        "candidate_fingerprint"]
    # candidates change: an attempt arrives that also satisfies the conditions
    fresh.import_outbound(jsonl(
        outbound("gw-stale", "D-400", "att-3", "dave@example.com",
                 "2026-04-01T00:20:00Z", queue="QUEUE-D")))
    try:
        fresh.import_resolutions(jsonl(resolution(
            "gw-stale", "RPT-4", "ITEM-4", "D-400", "att-1",
            "dave@example.com", stale_fp, "2026-04-01T02:00:00Z")))
        raise AssertionError("stale decision must be rejected")
    except DecisionError as exc:
        stale_rejected = record(
            "5d. over-due human decision (fingerprint from before att-3) is "
            "rejected, not silently re-pointed", fresh,
            {"rejection": exc.to_dict()})
    assert stale_rejected["rejection"]["code"] == "decision_error"
    assert stale_rejected["rejection"]["details"]["supplied_fingerprint"] \
        != stale_rejected["rejection"]["details"]["current_fingerprint"]
    # and no decision row was written
    assert fresh.conn.execute(
        "SELECT COUNT(*) FROM manual_decision").fetchone()[0] == 0
    # the new fingerprint is accepted and resolves cleanly
    new_fp4 = fresh.explain_item("gw-stale", "RPT-4", "ITEM-4")[
        "candidate_fingerprint"]
    fresh.import_resolutions(jsonl(resolution(
        "gw-stale", "RPT-4", "ITEM-4", "D-400", "att-1", "dave@example.com",
        new_fp4, "2026-04-01T03:00:00Z")))
    final = record("5e. re-issued decision with the current fingerprint is "
                   "applied", fresh)
    # att-1 carries the evidence and is delivered, but it is no longer the
    # latest registered attempt: att-3 is, so the *delivery* stays unproven.
    # This is the retry rule -- an older attempt's success never makes a newer
    # in-flight retry look successful.
    assert final["engine_attempts"][
        "gw-stale/D-400/att-1/723a64617665406578616d706c652e636f6d"
    ] == "delivered"
    assert final["engine_attempts"][
        "gw-stale/D-400/att-3/723a64617665406578616d706c652e636f6d"
    ] == "awaiting"
    deliv = fresh.delivery_status("gw-stale", "D-400", "dave@example.com")
    assert deliv["status"] == "awaiting"
    assert deliv["latest_attempt_id"] == "att-3"
    by_id = {a["attempt_id"]: a["status"] for a in deliv["attempts"]}
    assert by_id == {"att-1": "delivered", "att-2": "awaiting",
                     "att-3": "awaiting"}
    assert final["proven_delivered"] == 0
    return STEPS


TRANSCRIPT_SKIP = {"engine_attempts", "reference_attempts",
                   "reference_delivery"}


def to_transcript(steps):
    lines = []
    for step in steps:
        lines.append("=" * 72)
        lines.append(step["step"])
        if "import" in step:
            lines.append("  import outcome: " + json.dumps(step["import"]))
        if "rejection" in step:
            lines.append("  rejection: " + json.dumps(step["rejection"]))
        lines.append("  delivery counts: "
                     + json.dumps(step["delivery_counts"]))
        lines.append("  proven delivered: %s" % step["proven_delivered"])
        lines.append("  receipt buckets: " + json.dumps(step["receipt_buckets"]))
        for receipt in step["receipts"]:
            lines.append(
                "  receipt %-8s state=%-8s mark=%-9s action=%-9s "
                "candidates=%d assigned=%s fp=%s.."
                % (receipt["line_key"], receipt["chain_state"],
                   receipt["mark"], receipt["effective_action"],
                   receipt["candidate_count"],
                   json.dumps(receipt["assigned"]),
                   (receipt["candidate_fingerprint"] or "")[:8]))
            lines.append("      note: %s" % receipt["note"])
        lines.append("  attempts (engine == reference):")
        for key in sorted(step["engine_attempts"]):
            lines.append("    %-55s %s" % (key, step["engine_attempts"][key]))
        if step["pending"]:
            lines.append("  pending evidence:")
            for item in step["pending"]:
                lines.append("    %-20s %s %s"
                             % (item.get("category"), item.get("line_key"),
                                item.get("note", "")))
        if step["conflicts"]:
            lines.append("  correction conflicts:")
            for item in step["conflicts"]:
                lines.append("    root=%s state=%s branches=%s"
                             % (item["root"], item["state"],
                                [b["line_key"] for b in item["branches"]]))
    return "\n".join(lines)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    steps = run()
    if "--json" in argv:
        print(json.dumps(steps, indent=2, ensure_ascii=False))
    else:
        print(to_transcript(steps))
    return 0


if __name__ == "__main__":
    sys.exit(main())
