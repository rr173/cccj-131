"""Investigation sub-ledger export (``export-case``).

Acceptance tests.  Every expectation about *what must be carried* is a
hand-written business identity below -- never a set produced by the exporter.
The exporter is only asked to perform the copy, and its own derived state is
compared with an independently recomputed state of the source.

Run: python3 -I tests/test_export_case.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from receipt_ledger import Ledger  # noqa: E402
from receipt_ledger.case_export import (  # noqa: E402
    LEDGER_NAME, SELECTION_NAME, export_case, parse_selection)
from receipt_ledger.errors import ExportError  # noqa: E402
from tests.helpers import (check, correction, dsn, jsonl,  # noqa: E402
                           outbound, resolution)

def _cli(args):
    """Run the CLI isolated from cwd/site (project path added explicitly)."""
    snippet = ("import sys\n"
               "sys.path.insert(0, sys.argv[1])\n"
               "from receipt_ledger.cli import main\n"
               "sys.exit(main(sys.argv[2:]))")
    return subprocess.run([sys.executable, "-I", "-c", snippet, ROOT] + args,
                          cwd=ROOT, capture_output=True, text=True)


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A = "alice@example.com"


# --------------------------------------------------------------------------- #
# independent helpers (no exporter code)
# --------------------------------------------------------------------------- #
class Workdir:
    def __init__(self):
        self.path = tempfile.mkdtemp(prefix="export-case-test-")
        self.source = os.path.join(self.path, "source.sqlite")

    def ledger(self):
        """Open or create the source ledger (a test may add two batches)."""
        if os.path.exists(self.source):
            return Ledger.open(self.source)
        return Ledger.create(self.source)

    def sub(self, name="case"):
        return os.path.join(self.path, name)

    def cleanup(self):
        shutil.rmtree(self.path, ignore_errors=True)


def read_doc(out_dir):
    with open(os.path.join(out_dir, SELECTION_NAME), encoding="utf-8") as fh:
        return json.load(fh)


def open_sub(out_dir):
    return Ledger.open(os.path.join(out_dir, LEDGER_NAME))


def _gw(value):
    return bytes(value).decode().removeprefix("i:")


def attempt_identities(ledger):
    """Business identities of every attempt: (gw, delivery, attempt, recipient)."""
    return {
        (_gw(row["g"]), row["delivery_id"], row["attempt_id"],
         row["recipient_text"])
        for row in ledger.conn.execute(
            "SELECT g.ident AS g, a.delivery_id, a.attempt_id,"
            " a.recipient_text FROM outbound_attempt a JOIN gateway g"
            " ON g.id=a.gateway_row")}


def item_identities(ledger):
    """Business identities of every receipt/correction item."""
    out = set()
    for table, kind in (("dsn_line", "dsn"), ("correction_line", "cor")):
        for row in ledger.conn.execute(
                f"SELECT g.ident AS g, t.report_id, t.item_id FROM {table} t"
                " JOIN gateway g ON g.id=t.gateway_row"):
            out.add((_gw(row["g"]), kind, row["report_id"], row["item_id"]))
    return out


def decision_identities(ledger):
    """Human decisions, keyed by root identity + chosen attempt + fingerprint."""
    out = set()
    for row in ledger.conn.execute(
            "SELECT g.ident AS g, d.root_report_id, d.root_item_id,"
            " d.delivery_id, d.attempt_id, d.candidate_fp, d.candidate_net"
            " FROM manual_decision d JOIN gateway g ON g.id=d.gateway_row"):
        out.add((_gw(row["g"]), row["root_report_id"], row["root_item_id"],
                 row["delivery_id"], row["attempt_id"], row["candidate_fp"],
                 row["candidate_net"]))
    return out


def import_file_identities(ledger):
    return {(row["sha256"], row["kind"], row["source_name"],
             row["line_count"]) for row in ledger.conn.execute(
                 "SELECT * FROM import_file")}


def strip_ids(rows):
    """Rows without physical ids, for order-independent assertions."""
    return sorted(tuple(value for key, value in row.items()
                        if key != "id") for row in rows)


def expect_export_error(code, fn):
    try:
        fn()
    except ExportError as exc:
        check(exc.code == code,
              f"expected export error {code!r}, got {exc.code!r}: {exc}")
        return exc
    raise AssertionError(f"expected ExportError {code!r}, nothing raised")


def count(ledger, table):
    return ledger.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


# --------------------------------------------------------------------------- #
# reference state, recomputed from the source's own fact tables
# --------------------------------------------------------------------------- #
def snapshot_views(ledger):
    ctx, info = ledger._load_graph()
    views = {}
    for root, (kind, _row) in ctx["nodes"].items():
        if kind != "dsn":
            continue
        views[root] = ledger._evaluate_root(ctx, info, root)
    return views


def view_business(ledger, view):
    row = ledger.conn.execute(
        "SELECT g.ident AS g, d.report_id, d.item_id FROM dsn_line d"
        " JOIN gateway g ON g.id=d.gateway_row WHERE d.id=?",
        (int(view["root"].split(":", 1)[1]),)).fetchone()
    return (bytes(row["g"]).decode().removeprefix("i:"),
            row["report_id"], row["item_id"])


def comparable(ledger, view):
    def member(m):
        return (m[1], m[2], bytes(m[3]).hex())

    decisions = []
    for row in ledger.conn.execute(
            "SELECT delivery_id, attempt_id, recipient_sig, candidate_fp,"
            " candidate_net FROM manual_decision WHERE line_key=?"
            " ORDER BY id", (view["root"],)):
        decisions.append((row["delivery_id"], row["attempt_id"],
                          bytes(row["recipient_sig"]).hex(),
                          row["candidate_fp"], row["candidate_net"]))
    return {
        "chain_state": view["chain_state"],
        "effective_action": view["effective_action"],
        "effective_at_us": view["effective_at_us"],
        "fingerprint": view["candidate_fp"],
        "candidates": sorted(member(m) for m in view["candidates"]),
        "mark": view["mark"],
        "assignment": (member(view["assignment"])
                       if view["assignment"] is not None else None),
        "assigned_kind": view["assigned_kind"],
        "contributes": bool(view["contributes"]),
        "decisions": decisions,
    }


# =========================================================================== #
# 1. the main drill
# =========================================================================== #
MAIN = Workdir()
try:
    led = MAIN.ledger()

    # -- outbound --------------------------------------------------------- #
    # D-A retries and an unrelated recipient share one outbound file.
    led.import_outbound(jsonl(
        outbound("gw-main", "D-A", "a1", A, "2026-01-01T00:00:00Z",
                 queue="Q1", envelope="E-U"),
        outbound("gw-main", "D-A", "a2", A, "2026-01-01T00:10:00Z",
                 queue="Q1", envelope="E-A2"),
        outbound("gw-main", "D-EVE", "e1", "eve@example.com",
                 "2026-01-01T00:00:00Z", queue="Q9"),
    ), source="outbound_A_shared.jsonl")
    # B does not match R, but b2 matches S; C matches S too.
    led.import_outbound(jsonl(
        outbound("gw-main", "D-B", "b1", A, "2026-01-01T00:20:00Z",
                 queue="Q1"),
        outbound("gw-main", "D-B", "b2", A, "2026-01-01T00:50:00Z",
                 queue="Q2"),
    ), source="outbound_B.jsonl")
    led.import_outbound(jsonl(
        outbound("gw-main", "D-C", "c1", A, "2026-01-01T00:40:00Z",
                 queue="Q2"),
        outbound("gw-main", "D-C", "c2", A, "2026-01-01T00:45:00Z",
                 queue="Q2"),
    ), source="outbound_C.jsonl")
    # D-X exists only so a stale decision can point at x1.
    led.import_outbound(jsonl(
        outbound("gw-main", "D-X", "x1", A, "2026-01-01T00:15:00Z",
                 queue="Q3", envelope="E-U"),
        outbound("gw-main", "D-X", "x2", A, "2026-01-01T00:25:00Z",
                 queue="Q3", envelope="E-X2"),
    ), source="outbound_X.jsonl")
    # completely unrelated delivery
    led.import_outbound(jsonl(
        outbound("gw-main", "D-D", "d1", "dave@example.com",
                 "2026-01-01T00:00:00Z", queue="Q9"),
    ), source="outbound_D.jsonl")

    # -- receipts --------------------------------------------------------- #
    led.import_dsn(jsonl(
        dsn("gw-main", "RPT-R", "ITEM-R", A, "2026-01-01T01:00:00Z",
            "delivered", queue="Q1"),
        dsn("gw-main", "RPT-S", "ITEM-S", A, "2026-01-01T01:10:00Z",
            "delivered", queue="Q2"),
        dsn("gw-main", "RPT-T", "ITEM-T", A, "2026-01-01T01:05:00Z",
            "delivered", queue="Q1"),
        dsn("gw-main", "RPT-U", "ITEM-U", A, "2026-01-01T00:20:00Z",
            "delivered", envelope="E-U"),
    ), source="dsn_main.jsonl")
    led.import_dsn(jsonl(
        dsn("gw-main", "RPT-D", "ITEM-D", "dave@example.com",
            "2026-01-01T01:00:00Z", "failed", queue="Q9"),
    ), source="dsn_dave.jsonl")

    # A human decision on RPT-U whose candidate set later changed (stale).
    stale_fp = led.explain_item("gw-main", "RPT-U", "ITEM-U")[
        "candidate_fingerprint"]
    led.import_resolutions(jsonl(
        resolution("gw-main", "RPT-U", "ITEM-U", "D-X", "x1", A,
                   stale_fp, "2026-01-01T00:30:00Z"),
    ), source="resolution_alice.jsonl")
    # Competing corrections: RPT-T becomes conflicted; RPT-U is corrected.
    led.import_corrections(jsonl(
        correction("gw-main", "RPT-T-C1", "ITEM-T-C1", "RPT-T", "ITEM-T",
                   "2026-01-01T02:00:00Z", "withdraw"),
        correction("gw-main", "RPT-T-C2", "ITEM-T-C2", "RPT-T", "ITEM-T",
                   "2026-01-01T03:00:00Z", "failed"),
        correction("gw-main", "RPT-U-C1", "ITEM-U-C1", "RPT-U", "ITEM-U",
                   "2026-01-01T00:05:00Z", "delivered"),
    ), source="corrections.jsonl")
    # Explicitly named group whose original is absent: two competing
    # corrections on the missing parent plus a child of one of them.
    led.import_corrections(jsonl(
        correction("gw-main", "RPT-M-C1", "ITEM-M-C1", "RPT-M", "ITEM-M",
                   "2026-01-01T02:00:00Z", "failed"),
        correction("gw-main", "RPT-M-C2", "ITEM-M-C2", "RPT-M", "ITEM-M",
                   "2026-01-01T03:00:00Z", "delivered"),
        correction("gw-main", "RPT-M-C3", "ITEM-M-C3",
                   "RPT-M-C1", "ITEM-M-C1", "2026-01-01T04:00:00Z",
                   "withdraw"),
    ), source="corrections_missing.jsonl")

    # -- hand-written expectation before the export ----------------------- #
    # Starting from delivery D-A and receipt RPT-M-C1 must carry exactly:
    #   attempts  D-A/{a1,a2} (selected + retries)
    #             D-B/{b1,b2} (b1 is a candidate of RPT-R, b2 of RPT-S)
    #             D-C/{c1,c2} (candidates of RPT-S)
    #             D-X/{x1,x2} (x1 is the stale decision's saved candidate)
    #   items     RPT-R, RPT-S, RPT-T (+ corrections C1/C2)
    #             RPT-U (+ correction U-C1)
    #             RPT-M-C1/C2/C3 with absent RPT-M/ITEM-M
    #   excluded  D-EVE/e1, D-D/d1 and the dave receipts
    expected_attempts = {
        ("gw-main", "D-A", "a1", A), ("gw-main", "D-A", "a2", A),
        ("gw-main", "D-B", "b1", A), ("gw-main", "D-B", "b2", A),
        ("gw-main", "D-C", "c1", A), ("gw-main", "D-C", "c2", A),
        ("gw-main", "D-X", "x1", A), ("gw-main", "D-X", "x2", A)}
    expected_items = {
        ("gw-main", "dsn", "RPT-R", "ITEM-R"),
        ("gw-main", "dsn", "RPT-S", "ITEM-S"),
        ("gw-main", "dsn", "RPT-T", "ITEM-T"),
        ("gw-main", "dsn", "RPT-U", "ITEM-U"),
        ("gw-main", "cor", "RPT-T-C1", "ITEM-T-C1"),
        ("gw-main", "cor", "RPT-T-C2", "ITEM-T-C2"),
        ("gw-main", "cor", "RPT-U-C1", "ITEM-U-C1"),
        ("gw-main", "cor", "RPT-M-C1", "ITEM-M-C1"),
        ("gw-main", "cor", "RPT-M-C2", "ITEM-M-C2"),
        ("gw-main", "cor", "RPT-M-C3", "ITEM-M-C3")}
    expected_decisions = {
        ("gw-main", "RPT-U", "ITEM-U", "D-X", "x1", stale_fp,
         json.dumps([
             {"delivery_id": "D-A", "attempt_id": "a1",
              "recipient": "723a616c696365406578616d706c652e636f6d"},
             {"delivery_id": "D-X", "attempt_id": "x1",
              "recipient": "723a616c696365406578616d706c652e636f6d"}],
             sort_keys=True, separators=(",", ":")))}

    source_views = snapshot_views(led)
    source_business = {view_business(led, view): view
                       for view in source_views.values()}
    carried_roots = ["RPT-R", "RPT-S", "RPT-T", "RPT-U"]
    before = {
        root: comparable(led, source_business[("gw-main", root, "ITEM-"
                                               + root.split("-")[-1])])
        for root in carried_roots}
    source_imports = import_file_identities(led)
    del source_views, source_business

    # -- export ----------------------------------------------------------- #
    out = MAIN.sub()
    result = export_case(MAIN.source, {
        "deliveries": [{"gateway_id": "gw-main", "delivery_id": "D-A",
                        "recipient": "alice@EXAMPLE.COM"}],
        "items": [{"gateway_id": "gw-main", "report_id": "RPT-M-C1",
                   "item_id": "ITEM-M-C1"}]}, out)

    # -- 1a. exactly the hand-written scope is carried -------------------- #
    sub = open_sub(out)
    try:
        check(attempt_identities(sub) == expected_attempts,
              "attempt scope differs from the hand-written expectation:\n"
              f"  extra:   {attempt_identities(sub) - expected_attempts}\n"
              f"  missing: {expected_attempts - attempt_identities(sub)}")
        check(item_identities(sub) == expected_items,
              "item scope differs from the hand-written expectation:\n"
              f"  extra:   {item_identities(sub) - expected_items}\n"
              f"  missing: {expected_items - item_identities(sub)}")
        check(decision_identities(sub) == expected_decisions,
              "decision scope differs from the hand-written expectation")

        # out-of-scope facts really are gone, including the shared import file
        check(not {"eve@example.com", "dave@example.com"} &
              {row[3] for row in attempt_identities(sub)},
              "unrelated recipients leaked into the sub-ledger")
        check(import_file_identities(sub) <= source_imports,
              "import_file provenance must be copied, not invented")

        # -- 1b. no ambiguity or conflict was pruned away ----------------- #
        r = sub.explain_item("gw-main", "RPT-R", "ITEM-R")
        check(r["mark"] == "ambiguous" and len(r["candidates"]) == 3,
              "RPT-R must stay ambiguous across A/B (was 3 candidates)")
        s = sub.explain_item("gw-main", "RPT-S", "ITEM-S")
        check(s["mark"] == "ambiguous" and len(s["candidates"]) == 3,
              "RPT-S must stay ambiguous across B/C")
        t = sub.explain_item("gw-main", "RPT-T", "ITEM-T")
        check(t["chain_state"] == "conflict",
              "the competing corrections on RPT-T must stay a conflict")
        conflicts = sub.correction_conflicts()
        check(len(conflicts) == 1 and
              [b["item_id"] for b in conflicts[0]["branches"]]
              == ["ITEM-T-C1", "ITEM-T-C2"],
              "both competing correction branches must survive")
        u = sub.explain_item("gw-main", "RPT-U", "ITEM-U")
        check(len(u["decisions"]) == 1 and not
              u["decisions"][0]["matches_current_set"],
              "the stale decision must travel, still stale")

        # -- 1c. pending group with absent original ------------------------ #
        pending = sub.pending_associations()
        categories = {(p["category"], p["line_key"]) for p in pending}
        check(("correction_pending", "cor:4") in categories and
              ("correction_pending", "cor:5") in categories and
              ("correction_pending", "cor:6") in categories,
              "the absent-original group must stay pending, not disappear")
        doc = read_doc(out)
        absent = {(a["gateway_id"], a["report_id"], a["item_id"])
                  for a in doc["carried"]["absent_targets"]}
        check(absent == {("gw-main", "RPT-M", "ITEM-M")},
              "the missing target is a logical identity, not a fabricated row")
        check(sub.conn.execute(
            "SELECT COUNT(*) FROM dsn_line WHERE report_id='RPT-M'"
        ).fetchone()[0] == 0, "the missing original must not be fabricated")

        # -- 1d. states match the source, by business identity ------------- #
        for root, expected in before.items():
            detail = sub.explain_item("gw-main", root,
                                      "ITEM-" + root.split("-")[-1])
            row = sub.conn.execute(
                "SELECT l.* FROM item_link l JOIN dsn_line d"
                " ON l.line_key = 'dsn:' || d.id WHERE d.report_id=?",
                (root,)).fetchone()
            got = comparable(sub, {
                "root": row["line_key"], "chain_state": row["chain_state"],
                "effective_action": row["effective_action"],
                "effective_at_us": row["effective_at_us"],
                "candidate_fp": row["candidate_fp"],
                "candidates": [(c["attempt_row"], c["delivery_id"],
                                c["attempt_id"], c["recipient_sig"])
                               for c in sub.conn.execute(
                                   "SELECT * FROM item_candidate WHERE"
                                   " line_key=? ORDER BY idx",
                                   (row["line_key"],))],
                "mark": row["mark"],
                "assignment": (None if row["attempt_row"] is None else
                               (row["attempt_row"], row["delivery_id"],
                                row["attempt_id"], row["recipient_sig"])),
                "assigned_kind": row["assigned_kind"],
                "contributes": row["contributes"]})
            check(got == expected,
                  f"{root}: sub-ledger state differs from the source")

        # -- 1e. derivations are regenerated, not copied ------------------- #
        statuses_before = {
            (row["delivery_id"], row["attempt_id"], row["status"])
            for row in sub.conn.execute(
                "SELECT * FROM derived_attempt_status")}
        sub.rebuild()
        statuses_after = {
            (row["delivery_id"], row["attempt_id"], row["status"])
            for row in sub.conn.execute(
                "SELECT * FROM derived_attempt_status")}
        check(statuses_before == statuses_after,
              "rebuild in the sub-ledger must reproduce its own state")
        check(count(sub, "dsn_line") + count(sub, "correction_line") ==
              len(expected_items), "no extra receipt rows after rebuild")
    finally:
        sub.close()

    # -- 1f. selection.json explains the extra scope ---------------------- #
    doc = read_doc(out)
    check(doc["fact_counts"]["outbound_attempts"] == 8,
          "selection.json must report the carried attempt count")
    check(doc["fact_counts"]["dsn_originals"] == 4 and
          doc["fact_counts"]["corrections"] == 6,
          "selection.json must report the carried receipt counts")
    check(doc["fact_counts"]["human_decisions"] == 1,
          "selection.json must report the carried decision count")
    reasons = {(a["delivery_id"], a["attempt_id"]): a["reasons"]
               for a in doc["carried"]["attempts"]}
    check(any("retry" in why for why in reasons[("D-A", "a2")]),
          "retries must carry an explicit reason")
    check(any("candidate" in why for why in reasons[("D-B", "b1")]),
          "candidate attempts must carry an explicit reason")
    shared = [f for f in doc["carried"]["import_files"]
              if f["source_name"] == "outbound_A_shared.jsonl"]
    check(len(shared) == 1, "the shared outbound file must be referenced")
    check(shared[0]["source_line_count"] == 3 and
          shared[0]["carried_total"] == 2 and shared[0]["partial"] is True,
          "a partial import file must not pretend to be carried whole")
    check(doc["selection"]["deliveries"][0]["recipient_canonical"]
          == "alice@example.com",
          "the normalized selector must be recorded")
    check(len(doc["selections"] if "selections" in doc else
              doc["selection"]["items"]) == 1,
          "the normalized item selector must be recorded")

    # -- 1g. source is untouched, and still works after moving it away ---- #
    first = Ledger.open(MAIN.source)
    try:
        repeated = attempt_identities(first)
    finally:
        first.close()
    second = Ledger.open(MAIN.source)
    try:
        check(attempt_identities(second) == repeated,
              "reading the source is repeatable")
    finally:
        second.close()
    moved = MAIN.source + ".moved"
    os.rename(MAIN.source, moved)
    try:
        # the sub-ledger still answers every required query
        reopened = open_sub(out)
        try:
            check(reopened.delivery_status(
                "gw-main", "D-B", A)["status"] == "awaiting",
                "status must work with the source moved away")
            a1 = reopened.attempt_status(
                "gw-main", "D-A", "a1", A)
            b2 = reopened.attempt_status(
                "gw-main", "D-B", "b2", A)
            check(a1["status"] in {"awaiting", "delivered", "delayed",
                                   "failed", "inconsistent"} and
                  b2["status"] in {"awaiting", "delivered", "delayed",
                                   "failed", "inconsistent"},
                  "attempt-status must work with the source moved away")
            check(reopened.pending_associations(),
                  "pending must work with the source moved away")
            check(reopened.correction_conflicts(),
                  "conflicts must work with the source moved away")
            check(reopened.explain_summary()["deliveries_total"] == 4,
                  "summary counts only the carried deliveries")
            reopened.rebuild()
            check(reopened.explain_item("gw-main", "RPT-T", "ITEM-T")
                  ["chain_state"] == "conflict",
                  "rebuild must work with the source moved away")
        finally:
            reopened.close()
        # ... and through the ordinary CLI commands, too
        sub_path = os.path.join(out, LEDGER_NAME)
        for command in (
                ["status", sub_path, "--gateway", "gw-main",
                 "--delivery", "D-B", "--recipient", A],
                ["attempt-status", sub_path, "--gateway", "gw-main",
                 "--delivery", "D-A", "--attempt", "a1", "--recipient", A],
                ["explain-item", sub_path, "--gateway", "gw-main",
                 "--report", "RPT-S", "--item", "ITEM-S"],
                ["pending", sub_path], ["conflicts", sub_path],
                ["summary", sub_path], ["rebuild", sub_path]):
            done = _cli(command)
            check(done.returncode == 0,
                  f"CLI {command[0]} failed with the source moved away: "
                  f"{done.stderr}")
    finally:
        os.rename(moved, MAIN.source)
finally:
    MAIN.cleanup()


# =========================================================================== #
# 2. withdrawn group keeps candidates; stale decision pulls historical ones
# =========================================================================== #
tmp = Workdir()
try:
    led = tmp.ledger()
    led.import_outbound(jsonl(
        outbound("g", "DW", "w1", "u@e.com", "2026-01-01T00:00:00Z",
                 queue="QW"),
        outbound("g", "DW", "w2", "u@e.com", "2026-01-01T00:30:00Z",
                 queue="QW")))
    led.import_dsn(jsonl(
        dsn("g", "RPT-W", "ITEM-W", "u@e.com", "2026-01-01T01:00:00Z",
            "delivered", queue="QW")))
    led.import_corrections(jsonl(
        correction("g", "RPT-W-C", "ITEM-W-C", "RPT-W", "ITEM-W",
                   "2026-01-01T02:00:00Z", "withdraw")))
    check(led.explain_item("g", "RPT-W", "ITEM-W")["mark"] == "withdrawn",
          "setup: the group is withdrawn")

    out = tmp.sub("withdrawn")
    export_case(tmp.source, {"items": [
        {"gateway_id": "g", "report_id": "RPT-W", "item_id": "ITEM-W"}]}, out)
    sub = open_sub(out)
    try:
        check(attempt_identities(sub) == {
            ("g", "DW", "w1", "u@e.com"), ("g", "DW", "w2", "u@e.com")},
            "a withdrawn group must still carry its current candidates")
        check(sub.explain_item("g", "RPT-W", "ITEM-W")["mark"]
              == "withdrawn", "withdrawn mark must survive the export")
        check(len(sub.explain_item("g", "RPT-W", "ITEM-W")["candidates"])
              == 2, "withdrawn candidates must not be pruned")
    finally:
        sub.close()

    # a stale decision's saved attempt is carried even though it is no longer
    # a current candidate
    led2 = tmp.ledger()
    led2.import_outbound(jsonl(
        outbound("g", "DS", "s1", "v@e.com", "2026-01-01T00:00:00Z",
                 queue="QS"),
        outbound("g", "DS", "s2", "v@e.com", "2026-01-01T00:10:00Z",
                 queue="QS"),
        outbound("g", "DT", "t1", "v@e.com", "2026-01-01T00:20:00Z",
                 queue="QS")))
    led2.import_dsn(jsonl(
        dsn("g", "RPT-V", "ITEM-V", "v@e.com", "2026-01-01T01:00:00Z",
            "delivered", queue="QS")))
    old_fp = led2.explain_item("g", "RPT-V", "ITEM-V")[
        "candidate_fingerprint"]
    led2.import_resolutions(jsonl(
        resolution("g", "RPT-V", "ITEM-V", "DT", "t1", "v@e.com",
                   old_fp, "2026-01-01T02:00:00Z")))
    # a correction moves occurred_at, so the candidate set changes: the
    # decision is now stale and DT/t1 is no longer a candidate.
    led2.import_corrections(jsonl(
        correction("g", "RPT-V-C", "ITEM-V-C", "RPT-V", "ITEM-V",
                   "2026-01-01T00:05:00Z", "delivered")))
    check(led2.explain_item("g", "RPT-V", "ITEM-V")["mark"] == "unique",
          "setup: the corrected time leaves one candidate")
    current = {(c["delivery_id"], c["attempt_id"])
               for c in led2.explain_item("g", "RPT-V", "ITEM-V")["candidates"]}
    check(("DT", "t1") not in current, "setup: t1 is no longer a candidate")

    out2 = tmp.sub("stale")
    export_case(tmp.source, {"items": [
        {"gateway_id": "g", "report_id": "RPT-V", "item_id": "ITEM-V"}]}, out2)
    sub2 = open_sub(out2)
    try:
        check(("g", "DT", "t1", "v@e.com") in attempt_identities(sub2),
              "an attempt saved by a stale decision must still travel")
        check(decision_identities(sub2) == {
            ("g", "RPT-V", "ITEM-V", "DT", "t1", old_fp,
             json.dumps([
                 {"delivery_id": "DS", "attempt_id": "s1",
                  "recipient": "723a7640652e636f6d"},
                 {"delivery_id": "DS", "attempt_id": "s2",
                  "recipient": "723a7640652e636f6d"},
                 {"delivery_id": "DT", "attempt_id": "t1",
                  "recipient": "723a7640652e636f6d"}],
                 sort_keys=True, separators=(",", ":")))},
            "the historical candidate set must be carried verbatim")
        check(sub2.explain_item("g", "RPT-V", "ITEM-V")["mark"] == "unique",
              "the current assignment must remain the unique candidate")
    finally:
        sub2.close()

    # -- a group with no original DSN never invents candidates ------------ #
    led3 = tmp.ledger()
    led3.import_outbound(jsonl(
        outbound("g", "DONLY", "o1", "u@e.com", "2026-01-01T00:00:00Z",
                 queue="QO")))
    led3.import_corrections(jsonl(
        correction("g", "RPT-P-C", "ITEM-P-C", "RPT-P", "ITEM-P",
                   "2026-01-01T02:00:00Z", "failed")))
    out3 = tmp.sub("outbound-only")
    export_case(tmp.source, {"deliveries": [
        {"gateway_id": "g", "delivery_id": "DONLY",
         "recipient": "u@e.com"}]}, out3)
    sub3 = open_sub(out3)
    try:
        check(attempt_identities(sub3) == {("g", "DONLY", "o1", "u@e.com")},
              "an outbound-only selection carries just that delivery")
        check(count(sub3, "dsn_line") == 0 and
              count(sub3, "correction_line") == 0,
              "with no receipt group in scope, no receipts travel")
    finally:
        sub3.close()

    # -- an unmatched receipt carries no candidate attempt ---------------- #
    led4 = tmp.ledger()
    led4.import_outbound(jsonl(
        outbound("g", "DX", "a1", "w@e.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led4.import_dsn(jsonl(
        dsn("g", "RPT-X", "ITEM-X", "w@e.com", "2026-01-01T01:00:00Z",
            "delivered", queue="OTHER")))
    check(led4.explain_item("g", "RPT-X", "ITEM-X")["mark"] == "unmatched",
          "setup: contradictory conditions are unmatched")
    out4 = tmp.sub("unmatched")
    export_case(tmp.source, {"items": [
        {"gateway_id": "g", "report_id": "RPT-X", "item_id": "ITEM-X"}]}, out4)
    sub4 = open_sub(out4)
    try:
        check(count(sub4, "outbound_attempt") == 0,
              "an unmatched group must not drag in any attempt")
        check(sub4.explain_item("g", "RPT-X", "ITEM-X")["mark"]
              == "unmatched", "the empty candidate set must survive")
    finally:
        sub4.close()

    # -- two corrections sharing a missing target, imported separately ---- #
    led5 = tmp.ledger()
    led5.import_corrections(jsonl(correction(
        "g", "RPT-M1", "ITEM-M1", "MISSING", "MISSING-ITEM",
        "2026-01-01T01:00:00Z", "failed")))
    led5.close()
    led5 = Ledger.open(tmp.source)
    try:
        led5.import_corrections(jsonl(correction(
            "g", "RPT-M2", "ITEM-M2", "MISSING", "MISSING-ITEM",
            "2026-01-01T02:00:00Z", "delivered")))
    finally:
        led5.close()
    out5 = tmp.sub("missing-group")
    export_case(tmp.source, {"items": [
        {"gateway_id": "g", "report_id": "RPT-M2",
         "item_id": "ITEM-M2"}]}, out5)
    sub5 = open_sub(out5)
    try:
        check(item_identities(sub5) == {
            ("g", "cor", "RPT-M1", "ITEM-M1"),
            ("g", "cor", "RPT-M2", "ITEM-M2")},
            "corrections sharing one absent target are one group across "
            "imports")
        check(count(sub5, "dsn_line") == 0,
              "the missing original must never be fabricated")
        doc = read_doc(out5)
        check(doc["carried"]["absent_targets"][0]["report_id"] == "MISSING",
              "the logical missing identity is recorded")
    finally:
        sub5.close()
finally:
    tmp.cleanup()


# =========================================================================== #
# 3. same delivery/report numbers on two gateways must not cross
# =========================================================================== #
tmp = Workdir()
try:
    led = tmp.ledger()
    led.import_outbound(jsonl(
        outbound("gwA", "D1", "a1", "x@e.com", "2026-01-01T00:00:00Z",
                 queue="Q"),
        outbound("gwB", "D1", "a1", "x@e.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("gwA", "R1", "I1", "x@e.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q"),
        dsn("gwB", "R1", "I1", "x@e.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    out = tmp.sub()
    export_case(tmp.source, {"items": [
        {"gateway_id": "gwA", "report_id": "R1", "item_id": "I1"}]}, out)
    sub = open_sub(out)
    try:
        check(attempt_identities(sub) == {("gwA", "D1", "a1", "x@e.com")},
              "only the selected gateway's attempt may travel")
        check(item_identities(sub) == {("gwA", "dsn", "R1", "I1")},
              "only the selected gateway's receipt may travel")
        check(sub.explain_item("gwA", "R1", "I1")["mark"] == "unique",
              "gwA's receipt stays unique without gwB's attempt")
        try:
            sub.explain_item("gwB", "R1", "I1")
            raise AssertionError("gwB's item must not exist in the sub-ledger")
        except KeyError:
            pass
    finally:
        sub.close()

    # the same identity on two gateways: a correction in gwA must never be
    # attached to gwB's identically numbered receipt
    led.import_corrections(jsonl(
        correction("gwA", "R1C", "I1C", "R1", "I1",
                   "2026-01-01T02:00:00Z", "withdraw"),
        correction("gwB", "R1C", "I1C", "R1", "I1",
                   "2026-01-01T02:00:00Z", "failed")))
    check(led.explain_item("gwA", "R1", "I1")["mark"] == "withdrawn",
          "setup: gwA's receipt is withdrawn")
    check(led.explain_item("gwB", "R1", "I1")["mark"] == "unique",
          "setup: gwB's receipt is still unique")
    out2 = tmp.sub("gw-isolation")
    export_case(tmp.source, {"items": [
        {"gateway_id": "gwA", "report_id": "R1", "item_id": "I1"}]}, out2)
    sub2 = open_sub(out2)
    try:
        check(item_identities(sub2) == {
            ("gwA", "dsn", "R1", "I1"), ("gwA", "cor", "R1C", "I1C")},
            "only gwA's receipt and correction may travel")
        check(sub2.explain_item("gwA", "R1", "I1")["mark"] == "withdrawn",
              "gwA keeps its own withdrawal")
        try:
            sub2.explain_item("gwB", "R1", "I1")
            raise AssertionError("gwB's receipt must not travel")
        except KeyError:
            pass
    finally:
        sub2.close()
finally:
    tmp.cleanup()


# =========================================================================== #
# 4. selector validation, unknown selections, existing target
# =========================================================================== #
tmp = Workdir()
try:
    led = tmp.ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@e.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@e.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    good = {"items": [{"gateway_id": "g", "report_id": "R1",
                       "item_id": "I1"}]}

    # normalization: duplicates collapse, the address is canonicalized.  The
    # local part is byte-exact, so only the *domain* case may differ here.
    normalized = parse_selection({
        "deliveries": [
            {"gateway_id": "g", "delivery_id": "D1", "recipient": "a@E.COM"},
            {"gateway_id": "g", "delivery_id": "D1", "recipient": "a@e.com"}],
        "items": [
            {"gateway_id": "g", "report_id": "R1", "item_id": "I1"},
            {"gateway_id": "g", "report_id": "R1", "item_id": "I1"}]})
    check(len(normalized["deliveries"]) == 1 and
          len(normalized["items"]) == 1,
          "duplicate selectors must normalize to one entry")
    check(normalized["deliveries"][0]["recipient_canonical"] == "a@e.com",
          "the selector address uses the ledger's canonical form")
    # a different local-part case is a different recipient, not a duplicate
    distinct = parse_selection({
        "deliveries": [
            {"gateway_id": "g", "delivery_id": "D1", "recipient": "a@e.com"},
            {"gateway_id": "g", "delivery_id": "D1", "recipient": "A@e.com"}]})
    check(len(distinct["deliveries"]) == 2,
          "the local part stays case-sensitive, even for selectors")

    for bad, label in [
        ({}, "empty document"),
        ({"deliveries": [], "items": []}, "no selectors at all"),
        ({"deliveries": []}, "empty array only"),
        ({"items": [{"gateway_id": "g", "report_id": "R1"}]},
         "missing field"),
        ({"items": [{"gateway_id": "g", "report_id": "R1", "item_id": "I1",
                    "extra": 1}]}, "unknown field"),
        ({"items": {"gateway_id": "g", "report_id": "R1", "item_id": "I1"}},
         "items not an array"),
        ({"items": [{"gateway_id": "", "report_id": "R1", "item_id": "I1"}]},
         "empty value"),
        ({"items": [{"gateway_id": "g", "report_id": "R1",
                     "item_id": 7}]}, "non-string value"),
        ({"deliveries": [{"gateway_id": "g", "delivery_id": "D1",
                          "recipient": '"bad"@e.com'}]},
         "unsupported address"),
        ({"delivery": []}, "unknown top-level key"),
        ("not json", "invalid JSON text"),
        (b"\xff\xfe", "invalid UTF-8"),
        ([], "not an object"),
    ]:
        expect_export_error("invalid_selection",
                            lambda b=bad: parse_selection(b))
        # ... and the whole export fails atomically, leaving nothing
        target = tmp.sub("bad-%d" % abs(hash(label)))
        expect_export_error("invalid_selection",
                            lambda b=bad, t=target: export_case(
                                tmp.source, b, t))
        check(not os.path.lexists(target),
              f"a failed export ({label}) must leave no target directory")

    expect_export_error(
        "unknown_selection",
        lambda: export_case(tmp.source, {
            "items": [{"gateway_id": "g", "report_id": "NOPE",
                       "item_id": "I1"}]}, tmp.sub("unknown-item")))
    expect_export_error(
        "unknown_selection",
        lambda: export_case(tmp.source, {
            "deliveries": [{"gateway_id": "g", "delivery_id": "NOPE",
                            "recipient": "a@e.com"}]}, tmp.sub("unknown-dlv")))
    expect_export_error(
        "unknown_selection",
        lambda: export_case(tmp.source, {
            "items": [{"gateway_id": "nope", "report_id": "R1",
                       "item_id": "I1"}]}, tmp.sub("unknown-gw")))
    # one bad selector among good ones fails the whole export
    expect_export_error(
        "unknown_selection",
        lambda: export_case(tmp.source, {
            "deliveries": [{"gateway_id": "g", "delivery_id": "D1",
                            "recipient": "a@e.com"}],
            "items": [{"gateway_id": "g", "report_id": "NOPE",
                       "item_id": "I1"}]}, tmp.sub("mixed")))
    for name in ("unknown-item", "unknown-dlv", "unknown-gw", "mixed"):
        check(not os.path.lexists(tmp.sub(name)),
              f"failed export {name!r} must leave no target directory")

    # an existing target is refused, and its content is not touched
    existing = tmp.sub("existing")
    os.makedirs(existing)
    marker = os.path.join(existing, "keep.txt")
    with open(marker, "w", encoding="utf-8") as fh:
        fh.write("keep")
    expect_export_error("output_exists",
                        lambda: export_case(tmp.source, good, existing))
    check(os.listdir(existing) == ["keep.txt"],
          "an existing target must not be modified")
    expect_export_error("output_error",
                        lambda: export_case(tmp.source, good,
                                            os.path.join(tmp.path, "no",
                                                         "such", "dir")))
finally:
    tmp.cleanup()


# =========================================================================== #
# 5. controlled write failure leaves nothing; a retry succeeds
# =========================================================================== #
tmp = Workdir()
try:
    led = tmp.ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@e.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@e.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    good = {"items": [{"gateway_id": "g", "report_id": "R1",
                       "item_id": "I1"}]}

    import receipt_ledger.case_export as case_export

    target = tmp.sub("write-failure")

    def boom():
        raise OSError(28, "No space left on device")

    case_export._publish_hook = boom
    try:
        expect_export_error("output_error",
                            lambda: export_case(tmp.source, good, target))
    finally:
        case_export._publish_hook = None
    check(not os.path.lexists(target),
          "a write failure must not leave a target directory")
    leftovers = [name for name in os.listdir(tmp.path)
                 if name.startswith("write-failure.tmp-")]
    check(leftovers == [], f"temporary directories must be removed: {leftovers}")

    summary = export_case(tmp.source, good, target)
    check(os.path.isdir(target), "the retry after a write failure succeeds")
    for name in (LEDGER_NAME, SELECTION_NAME):
        check(os.path.isfile(os.path.join(target, name)),
              f"the completed export must contain {name}")
    check(summary["fact_counts"]["outbound_attempts"] == 1,
          "the retry exports the expected attempt")
finally:
    tmp.cleanup()


# =========================================================================== #
# 6. concurrency: one instant, never a mix of before/after
# =========================================================================== #
def _build_concurrency_source(path):
    led = Ledger.create(path)
    led.import_outbound(jsonl(
        outbound("g", "DCON", "a1", "c@e.com", "2026-01-01T00:00:00Z",
                 queue="QC"),
        outbound("g", "DOTHER", "o1", "other@e.com",
                 "2026-01-01T00:00:00Z", queue="QO")))
    led.import_dsn(jsonl(
        dsn("g", "RPT-C", "ITEM-C", "c@e.com", "2026-01-01T01:00:00Z",
            "delivered", queue="QC"),
        dsn("g", "RPT-O", "ITEM-O", "other@e.com",
            "2026-01-01T01:00:00Z", "delivered", queue="QO")))
    led.close()
    return {
        "items": [{"gateway_id": "g", "report_id": "RPT-C",
                   "item_id": "ITEM-C"}]}


WORKER_SOURCE = r'''
"""Two-process export worker: hold the snapshot open while a peer commits."""

import json
import os
import sys
import time

sys.path.insert(0, sys.argv[1])

from receipt_ledger import Ledger
from receipt_ledger.case_export import export_case


def main():
    mode, source, selectors_path, output, signal_dir = sys.argv[2:7]
    with open(selectors_path, encoding="utf-8") as handle:
        selectors = json.load(handle)

    def signal(name):
        with open(os.path.join(signal_dir, name), "x", encoding="utf-8") as h:
            h.write(str(os.getpid()))

    def wait(name, timeout=30):
        path = os.path.join(signal_dir, name)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(path):
                return
            time.sleep(0.01)
        raise SystemExit(f"timed out waiting for {name}")

    if mode == "hold-snapshot":
        import receipt_ledger.case_export as case_export
        done = {"paused": False}

        def pause():
            if done["paused"]:
                return
            done["paused"] = True
            signal("snapshot-taken")
            wait("writer-done")

        case_export._after_snapshot_hook = pause
        try:
            export_case(source, selectors, output)
        finally:
            case_export._after_snapshot_hook = None
    elif mode == "writer":
        wait("snapshot-taken")
        writer = Ledger.open(source)
        try:
            writer.import_outbound((
                b'{"gateway_id":"g","delivery_id":"DCON","attempt_id":"a2",'
                b'"recipient":"c@e.com","queue_id":"QC",'
                b'"sent_at":"2026-01-01T00:30:00Z"}\n'))
        finally:
            writer.close()
        signal("writer-done")
    else:
        raise SystemExit(f"unknown mode {mode!r}")


if __name__ == "__main__":
    main()
'''


def _write_worker_files(tmp):
    worker = os.path.join(tmp.path, "_worker.py")
    with open(worker, "w", encoding="utf-8") as handle:
        handle.write(WORKER_SOURCE)
    selectors = os.path.join(tmp.path, "selectors.json")
    with open(selectors, "w", encoding="utf-8") as handle:
        json.dump({"items": [{"gateway_id": "g", "report_id": "RPT-C",
                              "item_id": "ITEM-C"}]}, handle)
    signals = os.path.join(tmp.path, "signals")
    os.makedirs(signals)
    return worker, selectors, signals


def test_concurrent_import_is_one_instant():
    """A batch that widens the candidate set commits during the export.

    The export must describe exactly one instant.  Two independent runs:

    * commit lands *after* the snapshot was taken -> the export describes the
      state before it (1 candidate, ``unique``), and a later export sees the
      committed state (2 candidates, ``ambiguous``);
    * commit lands *while the export is running in another process* (a real
      two-process pause after the snapshot) -> the export still describes the
      pre-commit instant, and the source shows the commit afterwards.  The
      result must match one of the two snapshots, never a mixture such as
      "2 attempts carried but a fingerprint of 1".
    """
    import receipt_ledger.case_export as case_export

    # -- (a) commit just after the snapshot was taken --------------------- #
    for round_index in range(2):
        tmp = Workdir()
        try:
            good = _build_concurrency_source(tmp.source)

            def pause():
                writer = Ledger.open(tmp.source)
                try:
                    writer.import_outbound(jsonl(
                        outbound("g", "DCON", "a2", "c@e.com",
                                 "2026-01-01T00:30:00Z", queue="QC")))
                finally:
                    writer.close()

            case_export._after_snapshot_hook = pause
            try:
                summary = export_case(tmp.source, good, tmp.sub())
            finally:
                case_export._after_snapshot_hook = None
            sub = open_sub(tmp.sub())
            try:
                item = sub.explain_item("g", "RPT-C", "ITEM-C")
                check(attempt_identities(sub) ==
                      {("g", "DCON", "a1", "c@e.com")},
                      "the snapshot must predate the concurrent commit")
                check(item["mark"] == "unique" and len(item["candidates"]) == 1,
                      "candidates and attempts must come from the same instant")
                check(summary["fact_counts"]["outbound_attempts"] == 1,
                      "selection.json counts the same instant")
                check(count(sub, "outbound_attempt") == 1,
                      "no attempt from the later commit may appear")
            finally:
                sub.close()

            second = tmp.sub("after")
            export_case(tmp.source, good, second)
            sub = open_sub(second)
            try:
                check(attempt_identities(sub) == {
                    ("g", "DCON", "a1", "c@e.com"),
                    ("g", "DCON", "a2", "c@e.com")},
                    "a later export must see the committed attempt")
                check(sub.explain_item("g", "RPT-C", "ITEM-C")["mark"]
                      == "ambiguous", "the later export must see ambiguity")
            finally:
                sub.close()
        finally:
            tmp.cleanup()

    # -- (b) a real two-process pause while the export is running --------- #
    for round_index in range(2):
        tmp = Workdir()
        try:
            _build_concurrency_source(tmp.source)
            worker, selectors, signals = _write_worker_files(tmp)
            exporter = subprocess.Popen(
                [sys.executable, "-I", worker, ROOT, "hold-snapshot",
                 tmp.source, selectors, tmp.sub(), signals],
                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True)
            try:
                writer = subprocess.Popen(
                    [sys.executable, "-I", worker, ROOT, "writer",
                     tmp.source, selectors, tmp.sub("unused"), signals],
                    cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True)
                out, err = exporter.communicate(timeout=60)
                writer_out, writer_err = writer.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                exporter.kill()
                writer.kill()
                raise
            check(exporter.returncode == 0,
                  f"exporter failed: {err}\n{out}")
            check(writer.returncode == 0,
                  f"writer failed: {writer_err}\n{writer_out}")

            sub = open_sub(tmp.sub())
            try:
                check(attempt_identities(sub) ==
                      {("g", "DCON", "a1", "c@e.com")},
                      "a commit during a paused export must not appear")
                item = sub.explain_item("g", "RPT-C", "ITEM-C")
                check(item["mark"] == "unique" and
                      len(item["candidates"]) == 1,
                      "candidates and attempts must come from one instant")
            finally:
                sub.close()

            source_ledger = Ledger.open(tmp.source)
            try:
                source_attempts = attempt_identities(source_ledger)
                check({("g", "DCON", "a1", "c@e.com"),
                       ("g", "DCON", "a2", "c@e.com")} <= source_attempts,
                      "the writer's commit must be in the source")
            finally:
                source_ledger.close()
            after = tmp.sub("after")
            export_case(tmp.source, {
                "items": [{"gateway_id": "g", "report_id": "RPT-C",
                           "item_id": "ITEM-C"}]}, after)
            sub = open_sub(after)
            try:
                check(sub.explain_item("g", "RPT-C", "ITEM-C")["mark"]
                      == "ambiguous",
                      "a fresh export must see the committed ambiguity")
            finally:
                sub.close()
        finally:
            tmp.cleanup()


test_concurrent_import_is_one_instant()


# =========================================================================== #
# 7. CLI entry point
# =========================================================================== #
def test_cli_roundtrip():
    tmp = Workdir()
    try:
        led = tmp.ledger()
        led.import_outbound(jsonl(
            outbound("g", "D1", "a1", "a@e.com", "2026-01-01T00:00:00Z",
                     queue="Q")))
        led.import_dsn(jsonl(
            dsn("g", "R1", "I1", "a@e.com", "2026-01-01T01:00:00Z",
                "delivered", queue="Q")))
        led.close()
        selectors = os.path.join(tmp.path, "selectors.json")
        with open(selectors, "w", encoding="utf-8") as fh:
            json.dump({"items": [{"gateway_id": "g", "report_id": "R1",
                                  "item_id": "I1"}]}, fh)
        out = tmp.sub()
        completed = _cli(["export-case", tmp.source, selectors, out])
        check(completed.returncode == 0,
              f"CLI export failed: {completed.stderr}\n{completed.stdout}")
        payload = json.loads(completed.stdout)
        check(payload["output_dir"] == out and
              payload["fact_counts"]["dsn_originals"] == 1,
              "the CLI prints the export summary")
        check(os.path.isfile(os.path.join(out, LEDGER_NAME)),
              "the CLI writes ledger.sqlite")
        # querying the sub-ledger through the ordinary commands
        for command in (["status", os.path.join(out, LEDGER_NAME),
                         "--gateway", "g", "--delivery", "D1",
                         "--recipient", "a@e.com"],
                        ["summary", os.path.join(out, LEDGER_NAME)],
                        ["pending", os.path.join(out, LEDGER_NAME)]):
            done = _cli(command)
            check(done.returncode == 0,
                  f"CLI {command[0]} failed on the sub-ledger: "
                  f"{done.stderr}")
        # a bad selector exits non-zero and leaves nothing
        bad = os.path.join(tmp.path, "bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write('{"items": []}')
        bad_out = tmp.sub("bad")
        done = _cli(["export-case", tmp.source, bad, bad_out])
        check(done.returncode == 2, "an invalid selector must exit non-zero")
        check(not os.path.lexists(bad_out),
              "the failed CLI export must leave nothing")
    finally:
        tmp.cleanup()


test_cli_roundtrip()


# =========================================================================== #
# 8. randomized: the export never changes an interpretation
# =========================================================================== #
def _oracle_views(ledger, reference, gateway):
    """Oracle views of one gateway keyed by the item's report/item identity."""
    out = {}
    for key, view in reference.ReferenceSnapshot(ledger.conn).evaluate().items():
        if view["gw"] != gateway:
            continue
        # the oracle's key is dsn:<gateway_row>:<report>:<item>; re-key by the
        # business identity so source and sub-ledger row numbers can differ
        parts = key.split(":", 3)
        out["%s:%s" % (parts[2], parts[3])] = view
    return out


def test_random_exports_match_independent_reference():
    """For random small sources, export a random named item / delivery.

    The sub-ledger is compared with ``receipt_ledger.reference`` -- a separate
    brute-force implementation that imports no engine code -- so this does not
    merely re-use the engine's own view of the source.  Expectations here are
    *relational*: whatever the source says must still be said, and no receipt
    group carried may change its mark, fingerprint or candidate set.
    """
    import random
    from receipt_ledger import reference

    def business(value):
        # reference snapshots already decode the gateway identity
        if isinstance(value, str):
            return value.removeprefix("i:")
        return bytes(value).decode().removeprefix("i:")

    for seed in range(12):
        rng = random.Random(1000 + seed)
        tmp = Workdir()
        try:
            led = tmp.ledger()
            gateways = ["gA", "gB"]
            recipients = ["u@e.com", "v@e.com"]
            deliveries = {gw: ["D1", "D2"] for gw in gateways}
            attempts = {gw: ["a1", "a2"] for gw in gateways}
            queues = [None, "Q1", "Q2"]
            envelopes = [None, "E1"]
            reports = []
            counter = {gw: 0 for gw in gateways}
            correction_targets = []
            for step in range(14):
                action = rng.choices(
                    ["outbound", "dsn", "correction", "resolution"],
                    weights=[4, 4, 2, 1])[0]
                if action == "outbound":
                    gw = rng.choice(gateways)
                    try:
                        led.import_outbound(jsonl(outbound(
                            gw, rng.choice(deliveries[gw]),
                            rng.choice(attempts[gw]), rng.choice(recipients),
                            "2026-01-01T%02d:00:00Z" % rng.randrange(0, 6),
                            queue=rng.choice(queues),
                            envelope=rng.choice(envelopes))))
                    except Exception:
                        pass
                elif action == "dsn" or not reports:
                    gw = rng.choice(gateways)
                    counter[gw] += 1
                    report = "R%d-%s" % (counter[gw], gw)
                    queue = rng.choice(queues)
                    envelope = rng.choice(envelopes)
                    if queue is None and envelope is None:
                        queue = "Q1"
                    try:
                        led.import_dsn(jsonl(dsn(
                            gw, report, "I%d" % counter[gw],
                            rng.choice(recipients),
                            "2026-01-01T%02d:30:00Z" % rng.randrange(0, 8),
                            rng.choice(["delivered", "failed", "delayed"]),
                            queue=queue, envelope=envelope)))
                        reports.append((gw, report, "I%d" % counter[gw]))
                    except Exception:
                        counter[gw] -= 1
                elif action == "correction":
                    choices = correction_targets or reports
                    if not choices:
                        continue
                    gw, report, item = rng.choice(choices)
                    counter[gw] += 1
                    try:
                        led.import_corrections(jsonl(correction(
                            gw, "C%d" % counter[gw], "CI%d" % counter[gw],
                            report, item,
                            "2026-01-01T%02d:45:00Z" % rng.randrange(0, 9),
                            rng.choice(["delivered", "failed", "delayed",
                                        "withdraw"]))))
                        correction_targets.append(
                            (gw, "C%d" % counter[gw], "CI%d" % counter[gw]))
                    except Exception:
                        counter[gw] -= 1
                elif action == "resolution" and reports:
                    gw, report, item = rng.choice(reports)
                    try:
                        detail = led.explain_item(gw, report, item)
                    except KeyError:
                        continue
                    if not detail["candidates"]:
                        continue
                    chosen = rng.choice(detail["candidates"])
                    text = None
                    for candidate in recipients:
                        from receipt_ledger.addr import recipient_sig
                        if recipient_sig(candidate).hex() == \
                                chosen["recipient_sig"]:
                            text = candidate
                    if text is None:
                        continue
                    try:
                        led.import_resolutions(jsonl(resolution(
                            gw, report, item, chosen["delivery_id"],
                            chosen["attempt_id"], text,
                            detail["candidate_fingerprint"],
                            "2026-01-01T09:00:00Z")))
                    except Exception:
                        pass

            # choose a random named item among those that exist
            if not reports:
                continue
            gw, report, item = rng.choice(reports)
            delivery = None
            rows = led.conn.execute(
                "SELECT g.ident AS g, a.delivery_id, a.recipient_text"
                " FROM outbound_attempt a JOIN gateway g ON g.id=a.gateway_row"
                " ORDER BY a.id").fetchall()
            if rows:
                picked = rng.choice(rows)
                delivery = {"gateway_id": business(picked["g"]),
                            "delivery_id": picked["delivery_id"],
                            "recipient": picked["recipient_text"]}
            selectors = {"items": [{"gateway_id": gw, "report_id": report,
                                    "item_id": item}]}
            if delivery is not None:
                selectors["deliveries"] = [delivery]
            out = tmp.sub("case")
            export_case(tmp.source, selectors, out)

            # -- the oracle's source view ------------------------------- #
            oracle = reference.ReferenceSnapshot(led.conn)
            oracle_attempts = {
                (business(gw), delivery, attempt, bytes(sig).hex()): status
                for (gw, delivery, attempt, sig), status in
                oracle.attempt_statuses().items()}
            oracle_deliveries = {
                (business(gw), delivery, bytes(sig).hex()): info["status"]
                for (gw, delivery, sig), info in
                oracle.delivery_statuses().items()}
            source_facts = {
                "attempts": attempt_identities(led),
                "items": item_identities(led),
                "decisions": decision_identities(led)}

            sub = open_sub(out)
            try:
                sub_attempts = {
                    (business(gw), delivery, attempt, bytes(sig).hex()): status
                    for (gw, delivery, attempt, sig), status in
                    reference.ReferenceSnapshot(
                        sub.conn).attempt_statuses().items()}
                sub_deliveries = {
                    (business(gw), delivery, bytes(sig).hex()): info["status"]
                    for (gw, delivery, sig), info in
                    reference.ReferenceSnapshot(
                        sub.conn).delivery_statuses().items()}
                sub_attempt_keys = set(sub_attempts)
                sub_delivery_keys = set(sub_deliveries)
                check(sub_attempts == {
                    key: value for key, value in oracle_attempts.items()
                    if key in sub_attempt_keys},
                    f"seed {seed}: carried attempt statuses must match the "
                    "independent oracle for the source")
                check(sub_deliveries == {
                    key: value for key, value in oracle_deliveries.items()
                    if key in sub_delivery_keys},
                    f"seed {seed}: carried delivery statuses must match the "
                    "independent oracle for the source")

                # every carried receipt group must keep its interpretation,
                # compared through the independent oracle (mark, fingerprint,
                # candidate set, chain state, decision count, contribution)
                for line_key in item_identities(sub):
                    gateway, kind, group_report, group_item = line_key
                    if kind != "dsn":
                        continue
                    source_views = _oracle_views(led, reference, gateway)
                    sub_views = _oracle_views(sub, reference, gateway)
                    source_view = source_views.get(
                        "%s:%s" % (group_report, group_item))
                    sub_view = sub_views.get(
                        "%s:%s" % (group_report, group_item))
                    check(source_view is not None and sub_view is not None,
                          f"seed {seed}: missing oracle view for "
                          f"{group_report}")
                    check(sub_view["mark"] == source_view["mark"],
                          f"seed {seed}: {group_report} changed mark "
                          f"{source_view['mark']} -> {sub_view['mark']}")
                    check(sub_view["fp"] == source_view["fp"],
                          f"seed {seed}: {group_report} changed its "
                          "candidate fingerprint")
                    check(sub_view["candidates"] == source_view["candidates"],
                          f"seed {seed}: {group_report} changed its "
                          "candidate set")
                    check(sub_view["state"] == source_view["state"],
                          f"seed {seed}: {group_report} changed chain state")
                    check(sub_view["action"] == source_view["action"],
                          f"seed {seed}: {group_report} changed effective "
                          "action")
                    check(sub_view["contributes"] == source_view["contributes"],
                          f"seed {seed}: {group_report} changed contribution")
            finally:
                sub.close()

            # scope check: every carried fact exists in the source
            sub_again = open_sub(out)
            try:
                check(attempt_identities(sub_again) <= source_facts["attempts"],
                      f"seed {seed}: invented an attempt")
                check(item_identities(sub_again) <= source_facts["items"],
                      f"seed {seed}: invented an item")
                check(decision_identities(sub_again)
                      <= source_facts["decisions"],
                      f"seed {seed}: invented a decision")
            finally:
                sub_again.close()
        finally:
            tmp.cleanup()


test_random_exports_match_independent_reference()


def main():
    print("export-case tests: all passed")


if __name__ == "__main__":
    main()
