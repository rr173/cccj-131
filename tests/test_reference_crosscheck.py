"""Cross-check the incremental engine against the brute-force reference.

For every step of every scenario below, the ledger is advanced and then
compared with ``receipt_ledger.reference`` on:

* per-attempt status,
* per-(delivery, recipient) status and its chosen last attempt,
* receipt evidence buckets.

The reference never imports the engine's matching, chain analysis or merge
code; it reads facts with plain SELECTs and re-derives everything itself.
"""

from __future__ import annotations

import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from receipt_ledger import reference  # noqa: E402
from receipt_ledger.addr import recipient_sig  # noqa: E402
from tests.helpers import (correction, dsn, jsonl, new_ledger,  # noqa: E402
                           outbound, resolution, snapshot_statuses)


class Mismatch(AssertionError):
    pass


def compare(ledger, label):
    """Compare engine state with the reference implementation."""
    ref = reference.ReferenceSnapshot(ledger.conn)
    ref_attempts = ref.attempt_statuses()
    ref_deliveries = ref.delivery_statuses()

    # -- attempts -------------------------------------------------------- #
    engine_attempts = snapshot_statuses(ledger)
    expected_attempts = {
        (gw, delivery, attempt, rec_sig): status
        for (gw, delivery, attempt, rec_sig), status in ref_attempts.items()}
    if engine_attempts != expected_attempts:
        only_engine = set(engine_attempts) - set(expected_attempts)
        only_ref = set(expected_attempts) - set(engine_attempts)
        differing = {k: (engine_attempts[k], expected_attempts[k])
                     for k in set(engine_attempts) & set(expected_attempts)
                     if engine_attempts[k] != expected_attempts[k]}
        raise Mismatch(
            f"{label}: attempt status mismatch\n"
            f"  only engine: {sorted(only_engine)}\n"
            f"  only ref:    {sorted(only_ref)}\n"
            f"  differing:   {differing}")

    # -- deliveries ------------------------------------------------------ #
    engine_deliveries = {}
    for gw, delivery, attempt, rec_sig in sorted(expected_attempts):
        text = None
        row = ledger.conn.execute(
            "SELECT recipient_text FROM outbound_attempt WHERE delivery_id=?"
            " AND recipient_sig=?", (delivery, rec_sig)
        ).fetchone()
        if row:
            text = row[0]
        if text is not None:
            engine_deliveries[(gw, delivery, rec_sig)] = (
                ledger.delivery_status(gw, delivery, text))
    for key, ref_info in ref_deliveries.items():
        gw, delivery, rec_sig = key
        engine_info = engine_deliveries.get(key)
        if engine_info is None:
            raise Mismatch(f"{label}: delivery {key} missing in engine")
        if engine_info["status"] != ref_info["status"]:
            raise Mismatch(
                f"{label}: delivery {key} status "
                f"{engine_info['status']} != reference {ref_info['status']}")
        if engine_info["latest_attempt_id"] != ref_info["latest_attempt_id"]:
            raise Mismatch(
                f"{label}: delivery {key} last attempt "
                f"{engine_info['latest_attempt_id']} != "
                f"reference {ref_info['latest_attempt_id']}")

    # -- receipt buckets ------------------------------------------------- #
    ref_summary = reference.reference_summary(ledger.conn)
    engine_summary = ledger.explain_summary()
    for mark, count in ref_summary["receipt_buckets"].items():
        engine_count = engine_summary["receipt_buckets"].get(mark, 0)
        if engine_count != count:
            raise Mismatch(
                f"{label}: bucket {mark} engine={engine_count} != ref={count}")
    for mark, count in engine_summary["receipt_buckets"].items():
        if ref_summary["receipt_buckets"].get(mark, 0) != count:
            raise Mismatch(
                f"{label}: bucket {mark} engine={count} != "
                f"ref={ref_summary['receipt_buckets'].get(mark, 0)}")
    for status, count in ref_summary["delivery_counts"].items():
        engine_count = engine_summary["delivery_counts"].get(status, 0)
        if engine_count != count:
            raise Mismatch(
                f"{label}: delivery count {status} engine={engine_count} != "
                f"ref={count}")
    return True


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #
def drill_scenario():
    """The main tracked drill, compared step by step."""
    led = new_ledger()
    led.import_outbound(jsonl(outbound(
        "gw1", "D1", "a1", "User@Example.COM",
        "2026-01-01T00:00:00Z", queue="Q1", envelope="E1")))
    compare(led, "drill/outbound-1")

    led.import_dsn(jsonl(dsn(
        "gw1", "R1", "I1", "User@example.com", "2026-01-01T01:00:00Z",
        "delivered", queue="Q1")))
    compare(led, "drill/dsn-1")
    assert led.delivery_status(
        "gw1", "D1", "User@example.com")["status"] == "delivered"

    led.import_outbound(jsonl(outbound(
        "gw1", "D1", "a2", "User@example.com",
        "2026-01-01T00:30:00Z", queue="Q1", envelope="E2")))
    compare(led, "drill/outbound-2")
    assert led.attempt_status("gw1", "D1", "a1", "User@example.com")[
        "status"] == "awaiting"
    assert led.attempt_status("gw1", "D1", "a2", "User@example.com")[
        "status"] == "awaiting"

    item = led.explain_item("gw1", "R1", "I1")
    assert item["mark"] == "ambiguous" and len(item["candidates"]) == 2
    fp = item["candidate_fingerprint"]

    led.import_resolutions(jsonl(resolution(
        "gw1", "R1", "I1", "D1", "a2", "User@example.com", fp,
        "2026-01-01T02:00:00Z")))
    compare(led, "drill/resolution")
    assert led.attempt_status("gw1", "D1", "a2", "User@example.com")[
        "status"] == "delivered"

    led.import_corrections(jsonl(correction(
        "gw1", "CR1", "CI1", "R1", "I1", "2026-01-01T03:00:00Z", "withdraw")))
    compare(led, "drill/withdraw")
    assert led.attempt_status("gw1", "D1", "a2", "User@example.com")[
        "status"] == "awaiting"
    assert led.attempt_status("gw1", "D1", "a1", "User@example.com")[
        "status"] == "awaiting"
    return led


def scenario_matrix_fields():
    """Empty intersection and the "two gateways, same numbers" case."""
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("gwA", "D1", "a1", "x@e.com", "2026-01-01T00:00:00Z",
                 queue="Q1", envelope="E1")))
    # conditions that cannot both hold -> empty intersection
    led.import_dsn(jsonl(dsn(
        "gwA", "R1", "I1", "x@e.com", "2026-01-01T01:00:00Z", "delivered",
        queue="Q1", envelope="OTHER")))
    compare(led, "matrix/empty-intersection")
    assert led.explain_item("gwA", "R1", "I1")["mark"] == "unmatched"

    # same report/item numbers on a different gateway must not collide
    led.import_outbound(jsonl(
        outbound("gwB", "D1", "a1", "x@e.com", "2026-01-01T00:00:00Z",
                 queue="Q1", envelope="E1")))
    led.import_dsn(jsonl(dsn(
        "gwB", "R1", "I1", "x@e.com", "2026-01-01T01:00:00Z", "delivered",
        queue="Q1", envelope="E1")))
    compare(led, "matrix/two-gateways")
    assert led.explain_item("gwA", "R1", "I1")["mark"] == "unmatched"
    assert led.explain_item("gwB", "R1", "I1")["mark"] == "unique"
    assert led.attempt_status("gwB", "D1", "a1", "x@e.com")[
        "status"] == "delivered"
    assert led.attempt_status("gwA", "D1", "a1", "x@e.com")[
        "status"] == "awaiting"
    return led


def scenario_terminals():
    """Opposite terminals, delayed-only, and retry selection."""
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "u@e.com", "2026-01-01T00:00:00Z",
                 queue="Q1"),
        outbound("g", "D2", "b1", "u@e.com", "2026-01-01T00:00:00Z",
                 queue="Q2"),
        outbound("g", "D3", "c1", "u@e.com", "2026-01-01T00:00:00Z",
                 queue="Q3")))
    led.import_dsn(jsonl(
        # two terminal receipts, same attempt -> inconsistent
        dsn("g", "R1", "I1", "u@e.com", "2026-01-01T01:00:00Z", "delivered",
            queue="Q1"),
        dsn("g", "R2", "I2", "u@e.com", "2026-01-01T01:10:00Z", "failed",
            queue="Q1"),
        # delayed only -> delayed (non-terminal)
        dsn("g", "R3", "I3", "u@e.com", "2026-01-01T01:20:00Z", "delayed",
            queue="Q3")))
    compare(led, "terminals/initial")
    assert led.attempt_status("g", "D1", "a1", "u@e.com")[
        "status"] == "inconsistent"
    assert led.attempt_status("g", "D2", "b1", "u@e.com")[
        "status"] == "awaiting"
    assert led.attempt_status("g", "D3", "c1", "u@e.com")[
        "status"] == "delayed"

    # retries: D4 has a1 delivered, then a2 (later) failed -> last attempt's
    # status wins, the old success does not leak
    led.import_outbound(jsonl(
        outbound("g", "D4", "a1", "u@e.com", "2026-01-01T00:00:00Z",
                 queue="Q4"),
        outbound("g", "D4", "a2", "u@e.com", "2026-01-01T02:00:00Z",
                 queue="Q4")))
    led.import_dsn(jsonl(
        dsn("g", "R4", "I4", "u@e.com", "2026-01-01T01:00:00Z", "delivered",
            queue="Q4")))
    compare(led, "terminals/retry")
    assert led.delivery_status("g", "D4", "u@e.com")["status"] == "awaiting"
    return led


def randomized_scenario(seed, steps=12):
    """Random small inputs; compared after every import."""
    rng = random.Random(seed)
    led = new_ledger()
    gateways = ["gA", "gB"]
    recipients = ["User@Example.com", "user@example.com", "other@e.com"]
    queues = [None, "Q1", "Q2"]
    envelopes = [None, "E1", "E2"]
    deliveries = {"gA": ["D1", "D2"], "gB": ["D1"]}
    attempts = {"gA": ["a1", "a2"], "gB": ["b1"]}
    report_counter = {"gA": 0, "gB": 0}
    dsn_items = []
    corrections_made = []

    for step in range(steps):
        action = rng.choices(
            ["outbound", "dsn", "correction", "resolution"],
            weights=[4, 4, 2, 1])[0]
        if action == "outbound":
            gw = rng.choice(gateways)
            row = outbound(
                gw, rng.choice(deliveries[gw]), rng.choice(attempts[gw]),
                rng.choice(recipients),
                "2026-01-01T%02d:00:00Z" % rng.randrange(0, 6),
                queue=rng.choice(queues), envelope=rng.choice(envelopes))
            try:
                led.import_outbound(jsonl(row))
            except Exception:
                compare(led, f"random seed={seed} step={step} rejected")
                continue
        elif action == "dsn" or not dsn_items:
            gw = rng.choice(gateways)
            report_counter[gw] += 1
            rid = "R%d" % report_counter[gw]
            iid = "I%d" % report_counter[gw]
            queue = rng.choice(queues)
            envelope = rng.choice(envelopes)
            if queue is None and envelope is None:
                queue = "Q1"
            row = dsn(
                gw, rid, iid, rng.choice(recipients),
                "2026-01-01T%02d:30:00Z" % rng.randrange(0, 8),
                rng.choice(["delivered", "failed", "delayed"]),
                queue=queue, envelope=envelope)
            try:
                led.import_dsn(jsonl(row))
            except Exception:
                compare(led, f"random seed={seed} step={step} rejected-dsn")
                report_counter[gw] -= 1
                continue
            dsn_items.append((gw, rid, iid))
        elif action == "correction" and dsn_items:
            gw, rid, iid = rng.choice(dsn_items)
            report_counter[gw] += 1
            target = (gw, rid, iid)
            if rng.random() < 0.3 and corrections_made:
                target = rng.choice(corrections_made)
            row = correction(
                gw, "CR%d" % report_counter[gw], "CI%d" % report_counter[gw],
                target[1], target[2],
                "2026-01-01T%02d:45:00Z" % rng.randrange(0, 9),
                rng.choice(["delivered", "failed", "delayed", "withdraw"]))
            try:
                led.import_corrections(jsonl(row))
                corrections_made.append(
                    (gw, row["report_id"], row["item_id"]))
            except Exception:
                pass
        elif action == "resolution" and dsn_items:
            gw, rid, iid = rng.choice(dsn_items)
            try:
                item = led.explain_item(gw, rid, iid)
            except KeyError:
                continue
            if not item["candidates"]:
                continue
            chosen = rng.choice(item["candidates"])
            text = None
            for rec in recipients:
                if recipient_sig(rec).hex() == chosen["recipient_sig"]:
                    text = rec
            if text is None:
                continue
            try:
                led.import_resolutions(jsonl(resolution(
                    gw, rid, iid, chosen["delivery_id"], chosen["attempt_id"],
                    text, item["candidate_fingerprint"],
                    "2026-01-01T09:00:00Z")))
            except Exception as exc:  # a conflicted chain refuses decisions
                compare(led, f"random seed={seed} step={step} rejected")
                del exc
                continue
        compare(led, f"random seed={seed} step={step} action={action}")
    return led


def main():
    drill_scenario()
    scenario_matrix_fields()
    scenario_terminals()
    for seed in range(40):
        randomized_scenario(seed, steps=16)
    print("reference cross-check: OK")


if __name__ == "__main__":
    main()
