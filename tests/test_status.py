"""Delivery-status semantics, correction chains, decisions and queries."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from receipt_ledger import DecisionError, Ledger  # noqa: E402
from tests.helpers import (TempLedger, check, correction, dsn,  # noqa: E402
                           jsonl, new_ledger, outbound, resolution)


def attempts(ledger, delivery, recipient):
    return ledger.delivery_status("g", delivery, recipient)


def status(ledger, delivery, recipient):
    return attempts(ledger, delivery, recipient)["status"]


# --------------------------------------------------------------------------- #
# matching
# --------------------------------------------------------------------------- #
def test_empty_intersection_is_unmatched_not_guessed():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q1", envelope="E1")))
    # queue matches, envelope does not -> intersection empty
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q1", envelope="E2")))
    item = led.explain_item("g", "R1", "I1")
    check(item["mark"] == "unmatched", "contradicting conditions -> unmatched")
    check(item["candidates"] == [], "no candidate survives")
    check(status(led, "D1", "a@example.com") == "awaiting",
          "unmatched evidence proves nothing")


def test_missing_condition_does_not_widen_beyond_supplied_ones():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q1", envelope="E1")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", envelope="E1")))
    check(led.explain_item("g", "R1", "I1")["mark"] == "unique",
          "supplied envelope alone is enough to be unique")
    # the receipt never constrained queue_id, so an attempt with a *different*
    # queue but the same envelope is a valid candidate: the supplied conditions
    # are an intersection, and unsupplied fields do not narrow it
    led.import_outbound(jsonl(
        outbound("g", "D2", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q9", envelope="E1")))
    check(led.explain_item("g", "R1", "I1")["mark"] == "ambiguous",
          "an attempt matching only the supplied envelope also matches")
    check(led.attempt_status("g", "D2", "a1", "a@example.com")["status"]
          == "awaiting", "ambiguous evidence credits nobody")
    led.import_outbound(jsonl(
        outbound("g", "D3", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q9", envelope="E9")))
    check(led.explain_item("g", "R1", "I1")["mark"] == "ambiguous",
          "an attempt with a different envelope is still excluded")


def test_sent_at_must_not_be_after_occurred_at():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T02:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    check(led.explain_item("g", "R1", "I1")["mark"] == "unmatched",
          "future attempt cannot be the sender of an earlier receipt")


def test_late_attempt_turns_unique_into_ambiguous_and_back_is_never_assumed():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    check(status(led, "D1", "a@example.com") == "delivered", "unique first")
    led.import_outbound(jsonl(
        outbound("g", "D1", "a2", "a@example.com", "2026-01-01T00:30:00Z",
                 queue="Q")))
    check(status(led, "D1", "a@example.com") == "awaiting",
          "late attempt revokes the earlier proof")
    check(led.attempt_status("g", "D1", "a1", "a@example.com")["status"]
          == "awaiting", "the old attempt loses its evidence too")


def test_domain_case_and_local_case():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "Case@Example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "Case@EXAMPLE.COM", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    check(led.explain_item("g", "R1", "I1")["mark"] == "unique",
          "domain case is irrelevant")
    led.import_dsn(jsonl(
        dsn("g", "R2", "I2", "case@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    check(led.explain_item("g", "R2", "I2")["mark"] == "unmatched",
          "local-part case matters")


# --------------------------------------------------------------------------- #
# terminals
# --------------------------------------------------------------------------- #
def test_opposite_terminals_are_inconsistent_not_last_wins():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q"),
        dsn("g", "R2", "I2", "a@example.com", "2026-01-01T05:00:00Z",
            "failed", queue="Q")))
    check(led.attempt_status("g", "D1", "a1", "a@example.com")["status"]
          == "inconsistent", "delivered + failed -> inconsistent")
    summary = led.explain_summary()
    check(summary["proven_delivered"] == 0, "inconsistent is not a success")
    check(summary["inconsistent_deliveries"], "listed separately")


def test_delayed_alone_is_non_terminal():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delayed", queue="Q")))
    check(status(led, "D1", "a@example.com") == "delayed", "delayed-only")
    check(led.explain_summary()["proven_delivered"] == 0,
          "delayed is not a success")
    # a later delivered receipt upgrades the same attempt
    led.import_dsn(jsonl(
        dsn("g", "R2", "I2", "a@example.com", "2026-01-01T02:00:00Z",
            "delivered", queue="Q")))
    check(status(led, "D1", "a@example.com") == "delivered",
          "delayed + delivered -> delivered")


def test_delayed_plus_failed_is_failed():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delayed", queue="Q"),
        dsn("g", "R2", "I2", "a@example.com", "2026-01-01T02:00:00Z",
            "failed", queue="Q")))
    check(status(led, "D1", "a@example.com") == "failed",
          "delayed is superseded by a terminal verdict")


def test_retry_selection_uses_last_attempt_and_lexicographic_tiebreak():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q"),
        outbound("g", "D1", "a2", "a@example.com", "2026-01-01T02:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    info = attempts(led, "D1", "a@example.com")
    check(info["latest_attempt_id"] == "a2", "the later attempt is chosen")
    check(info["status"] == "awaiting",
          "the older attempt's success does not make the retry delivered")
    check({a["attempt_id"]: a["status"] for a in info["attempts"]}
          == {"a1": "delivered", "a2": "awaiting"},
          "both attempts keep their own status")

    # identical sent_at: raw lexicographic attempt_id decides (documented)
    led.import_outbound(jsonl(
        outbound("g", "D2", "att-10", "b@example.com", "2026-01-01T00:00:00Z",
                 queue="Q"),
        outbound("g", "D2", "att-9", "b@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R2", "I2", "b@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R3", "I3", "b@example.com", "2026-01-01T00:30:00Z",
            "failed", queue="Q")))
    # R2 (delivered) matches both attempts; R3 (failed) matches both too.
    # Both attempts end inconsistent, so this scenario shows the tiebreak
    # only through latest_attempt_id.
    check(attempts(led, "D2", "b@example.com")["latest_attempt_id"]
          == "att-9",
          "string 'att-9' > 'att-10' lexicographically, documented tie-break")


# --------------------------------------------------------------------------- #
# corrections
# --------------------------------------------------------------------------- #
def test_correction_replaces_action_and_time():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    check(status(led, "D1", "a@example.com") == "delivered", "before")
    led.import_corrections(jsonl(
        correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T02:00:00Z",
                   "failed")))
    check(status(led, "D1", "a@example.com") == "failed", "correction wins")
    item = led.explain_item("g", "R1", "I1")
    check([n["line_key"] for n in item["chain"]] == ["dsn:1", "cor:1"],
          "original and correction both visible")
    check(item["effective_action"] == "failed", "end of chain supplies action")
    check(item["chain_end"] == "cor:1", "chain end is the correction")


def test_correction_time_change_reevaluates_candidates():
    led = new_ledger()
    # attempt at 00:30 matches a receipt at 01:00 but not one corrected to 00:10
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:30:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    check(status(led, "D1", "a@example.com") == "delivered", "matches first")
    led.import_corrections(jsonl(
        correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T00:10:00Z",
                   "delivered")))
    check(status(led, "D1", "a@example.com") == "awaiting",
          "time correction removes the candidate")
    check(led.explain_item("g", "R1", "I1")["mark"] == "unmatched",
          "and the receipt is unmatched now")


def test_correction_arrives_before_original_stays_pending():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_corrections(jsonl(
        correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T02:00:00Z",
                   "failed")))
    pending = led.pending_associations()
    check(len(pending) == 1 and pending[0]["category"] == "correction_pending",
          "pending correction is listed, not dropped")
    check(status(led, "D1", "a@example.com") == "awaiting",
          "pending chain contributes nothing")
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    check(status(led, "D1", "a@example.com") == "failed",
          "when the original arrives the pending chain completes")
    check(led.pending_associations() == [], "nothing pending anymore")


def test_reversed_chain_arrives_in_reverse():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    # C2 corrects C1, which corrects R1 -- all before R1 exists
    led.import_corrections(jsonl(
        correction("g", "C2", "CI2", "C1", "CI1", "2026-01-01T04:00:00Z",
                   "failed"),
        correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T03:00:00Z",
                   "delivered")))
    check(len(led.pending_associations()) == 2, "both corrections pending")
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    item = led.explain_item("g", "R1", "I1")
    check(item["chain_state"] == "clean", "chain becomes clean")
    # the corrections were imported C2 first, so C1 is row 2 and C2 is row 1;
    # the *chain* order is R1 -> C1 -> C2 regardless of import order
    by_report = {node["report_id"]: node["line_key"]
                 for node in item["chain"]}
    check(by_report["R1"] == item["root"], "root is the original")
    check(item["chain_end"] == by_report["C2"],
          "end is C2, the correction of C1")
    check(item["effective_action"] == "failed", "end action is used")
    check(status(led, "D1", "a@example.com") == "failed", "status follows end")


def test_two_corrections_on_one_parent_conflict():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    led.import_corrections(jsonl(
        correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T02:00:00Z",
                   "failed"),
        correction("g", "C2", "CI2", "R1", "I1", "2026-01-01T03:00:00Z",
                   "delayed")))
    item = led.explain_item("g", "R1", "I1")
    check(item["chain_state"] == "conflict", "conflict detected")
    check(item["contributes"] is False, "conflict chain contributes nothing")
    check(status(led, "D1", "a@example.com") == "awaiting",
          "no branch chosen by import order")
    conflicts = led.correction_conflicts()
    check(len(conflicts) == 1, "one conflicted root")
    check({b["line_key"] for b in conflicts[0]["branches"]}
          == {"cor:1", "cor:2"}, "both branches reported")
    # import order must not matter: build the mirror image
    led2 = new_ledger()
    led2.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led2.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    led2.import_corrections(jsonl(
        correction("g", "C2", "CI2", "R1", "I1", "2026-01-01T03:00:00Z",
                   "delayed"),
        correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T02:00:00Z",
                   "failed")))
    check(led2.explain_item("g", "R1", "I1")["chain_state"] == "conflict",
          "same conflict regardless of order")
    check(status(led2, "D1", "a@example.com") == "awaiting",
          "same status regardless of order")


def test_correction_cycle_is_error_evidence():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    # C1 corrects R1; C2 corrects C1; C1 also targets C2 -> cycle C1 <-> C2
    led.import_corrections(jsonl(
        correction("g", "C1", "CI1", "C2", "CI2", "2026-01-01T02:00:00Z",
                   "failed"),
        correction("g", "C2", "CI2", "C1", "CI1", "2026-01-01T03:00:00Z",
                   "delayed")))
    item = led.explain_item("g", "R1", "I1")
    check(item["chain_state"] == "clean",
          "the original is not itself on the cycle")
    cycle_rows = [r for r in led.pending_associations()
                  if r["category"] == "correction_excluded"]
    check(len(cycle_rows) == 2, "both cycle members excluded")
    check(all(r["chain_state"] == "cycle" for r in cycle_rows),
          "cycle state recorded")
    # a correction that closes a cycle through the original also excludes it
    led2 = new_ledger()
    led2.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led2.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    led2.import_corrections(jsonl(
        correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T02:00:00Z",
                   "delivered"),
        correction("g", "C2", "CI2", "C1", "CI1", "2026-01-01T03:00:00Z",
                   "failed")))
    # no cycle here -- just a clean 3-node chain; sanity check
    check(led2.explain_item("g", "R1", "I1")["chain_state"] == "clean",
          "linear chain is clean")


def test_withdrawing_end_leaves_no_effective_action_but_keeps_history():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    led.import_corrections(jsonl(
        correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T02:00:00Z",
                   "withdraw")))
    item = led.explain_item("g", "R1", "I1")
    check(item["effective_action"] is None, "no effective action")
    check(item["mark"] == "withdrawn", "marked withdrawn")
    check(status(led, "D1", "a@example.com") == "awaiting", "status reverts")
    # the original action is still recoverable
    original = led.conn.execute(
        "SELECT action FROM dsn_line WHERE report_id='R1'").fetchone()
    check(original[0] == "delivered", "original action still stored")
    check(led.explain_item("g", "C1", "CI1")["root"] == "dsn:1",
          "the correction itself is queryable")


def test_correction_cannot_change_matching_fields():
    for field, kw in [("envelope", {"envelope": "OTHER"}),
                      ("queue", {"queue": "OTHER"}), ]:
        led = new_ledger()
        led.import_outbound(jsonl(
            outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                     queue="Q", envelope="E")))
        led.import_dsn(jsonl(
            dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
                "delivered", queue="Q", envelope="E")))
        led.import_corrections(jsonl(
            correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T02:00:00Z",
                       "failed", **kw)))
        item = led.explain_item("g", "R1", "I1")
        check(item["chain_state"] == "invalid",
              f"changing {field} makes the chain invalid")
        check(item["contributes"] is False,
              f"changing {field} contributes nothing")
        check(status(led, "D1", "a@example.com") == "awaiting",
              f"changing {field} removes the evidence")


# --------------------------------------------------------------------------- #
# human decisions
# --------------------------------------------------------------------------- #
def _ambiguous_setup():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q"),
        outbound("g", "D1", "a2", "a@example.com", "2026-01-01T00:10:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    return led


def test_decision_is_bound_to_the_fingerprint():
    led = _ambiguous_setup()
    item = led.explain_item("g", "R1", "I1")
    check(item["mark"] == "ambiguous", "ambiguous before the decision")
    check(led.explain_summary()["proven_delivered"] == 0, "not counted")
    led.import_resolutions(jsonl(resolution(
        "g", "R1", "I1", "D1", "a1", "a@example.com",
        item["candidate_fingerprint"], "2026-01-01T02:00:00Z")))
    check(led.attempt_status("g", "D1", "a1", "a@example.com")["status"]
          == "delivered", "the chosen attempt is delivered")
    check(led.attempt_status("g", "D1", "a2", "a@example.com")["status"]
          == "awaiting", "the other attempt is untouched")
    # the *delivery* still shows awaiting because the latest attempt is a2;
    # the delivery-level total follows the last registered attempt only
    deliv = led.delivery_status("g", "D1", "a@example.com")
    check(deliv["status"] == "awaiting", "delivery follows its last attempt")
    check({a["attempt_id"]: a["status"] for a in deliv["attempts"]}
          == {"a1": "delivered", "a2": "awaiting"},
          "per-attempt detail preserves the proof for a1")
    check(led.explain_summary()["proven_delivered"] == 0,
          "an older attempt's proof is not a delivery success")


def test_stale_decision_is_rejected_and_writes_nothing():
    led = _ambiguous_setup()
    item = led.explain_item("g", "R1", "I1")
    stale_fp = item["candidate_fingerprint"]
    led.import_outbound(jsonl(
        outbound("g", "D1", "a3", "a@example.com", "2026-01-01T00:20:00Z",
                 queue="Q")))
    current = led.explain_item("g", "R1", "I1")
    check(current["mark"] == "ambiguous", "still ambiguous with 3 candidates")
    try:
        led.import_resolutions(jsonl(resolution(
            "g", "R1", "I1", "D1", "a1", "a@example.com", stale_fp,
            "2026-01-01T02:00:00Z")))
    except DecisionError as exc:
        check(exc.details["current_fingerprint"]
              == current["candidate_fingerprint"],
              "rejection names the current fingerprint")
        check(len(exc.details["current_candidates"]) == 3,
              "rejection lists the current candidates")
    else:
        raise AssertionError("stale decision must be rejected")
    check(led.conn.execute(
        "SELECT COUNT(*) FROM manual_decision").fetchone()[0] == 0,
        "rejected decision leaves no row")
    check(led.explain_summary()["proven_delivered"] == 0,
          "rejected decision changes no status")


def test_decision_choosing_a_non_candidate_is_rejected():
    led = _ambiguous_setup()
    item = led.explain_item("g", "R1", "I1")
    led.import_outbound(jsonl(
        outbound("g", "D2", "z1", "a@example.com", "2026-01-01T03:00:00Z",
                 queue="Q")))
    try:
        led.import_resolutions(jsonl(resolution(
            "g", "R1", "I1", "D2", "z1", "a@example.com",
            item["candidate_fingerprint"], "2026-01-01T04:00:00Z")))
    except DecisionError:
        pass
    else:
        raise AssertionError("non-candidate choice must be rejected")


def test_decision_on_conflicted_chain_is_rejected():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q"),
        outbound("g", "D1", "a2", "a@example.com", "2026-01-01T00:10:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    fp = led.explain_item("g", "R1", "I1")["candidate_fingerprint"]
    led.import_corrections(jsonl(
        correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T02:00:00Z",
                   "failed"),
        correction("g", "C2", "CI2", "R1", "I1", "2026-01-01T03:00:00Z",
                   "delayed")))
    try:
        led.import_resolutions(jsonl(resolution(
            "g", "R1", "I1", "D1", "a1", "a@example.com", fp,
            "2026-01-01T04:00:00Z")))
    except DecisionError:
        pass
    else:
        raise AssertionError("decision on a conflicted chain must be rejected")


def test_decision_lapses_when_candidates_change():
    led = _ambiguous_setup()
    item = led.explain_item("g", "R1", "I1")
    led.import_resolutions(jsonl(resolution(
        "g", "R1", "I1", "D1", "a1", "a@example.com",
        item["candidate_fingerprint"], "2026-01-01T02:00:00Z")))
    check(led.attempt_status("g", "D1", "a1", "a@example.com")["status"]
          == "delivered", "decision applied")
    # a new attempt appears: the fingerprint differs, so the decision lapses
    led.import_outbound(jsonl(
        outbound("g", "D1", "a3", "a@example.com", "2026-01-01T00:20:00Z",
                 queue="Q")))
    check(led.attempt_status("g", "D1", "a1", "a@example.com")["status"]
          == "awaiting", "old decision no longer applies")
    check(led.explain_summary()["proven_delivered"] == 0,
          "and it does not count as success")
    pending = led.pending_associations()
    check(pending and pending[0]["stale_decisions"],
          "the stale decision is surfaced with its fingerprint")


# --------------------------------------------------------------------------- #
# queries
# --------------------------------------------------------------------------- #
def test_timeline_shows_all_material():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    fp = led.explain_item("g", "R1", "I1")["candidate_fingerprint"]
    led.import_resolutions(jsonl(resolution(
        "g", "R1", "I1", "D1", "a1", "a@example.com", fp,
        "2026-01-01T02:00:00Z")))
    led.import_corrections(jsonl(
        correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T03:00:00Z",
                   "failed", recipient="a@example.com")))
    events = led.recipient_timeline("a@example.com")
    kinds = [event["kind"] for event in events]
    check(kinds.count("outbound_attempt") == 1, "attempt in timeline")
    check(kinds.count("receipt_chain") == 1, "receipt chain in timeline")
    check(kinds.count("correction") == 1, "correction in timeline")
    check(kinds.count("manual_decision") == 1, "decision in timeline")
    check([e["at_us"] for e in events] == sorted(e["at_us"] for e in events),
          "timeline is time ordered")


def test_explain_item_carries_chain_candidates_decisions():
    led = _ambiguous_setup()
    item = led.explain_item("g", "R1", "I1")
    led.import_resolutions(jsonl(resolution(
        "g", "R1", "I1", "D1", "a2", "a@example.com",
        item["candidate_fingerprint"], "2026-01-01T02:00:00Z")))
    led.import_corrections(jsonl(
        correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T03:00:00Z",
                   "failed")))
    detail = led.explain_item("g", "R1", "I1")
    check(detail["root"] == "dsn:1", "root identified")
    check(len(detail["chain"]) == 2, "whole chain listed")
    check(len(detail["candidates"]) == 2, "candidate set listed")
    check(len(detail["decisions"]) == 1, "human decision listed")
    check(detail["decisions"][0]["matches_current_set"] is True,
          "decision still current")
    check(detail["assignment"]["attempt_id"] == "a2",
          "assignment visible with its provenance")
    check(detail["assignment"]["assigned_by"] == "decision",
          "provenance says human decision")


def test_summary_separates_unproven_evidence():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q"),
        outbound("g", "D2", "b1", "b@example.com", "2026-01-01T00:00:00Z",
                 queue="Q2"),
        outbound("g", "D3", "c1", "c@example.com", "2026-01-01T00:00:00Z",
                 queue="Q3"),
        outbound("g", "D4", "d1", "d@example.com", "2026-01-01T00:00:00Z",
                 queue="Q4"),
        outbound("g", "D5", "e1", "e@example.com", "2026-01-01T00:00:00Z",
                 queue="Q5")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q"),
        # ambiguous: two attempts share Q2
        dsn("g", "R2", "I2", "b@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q2"),
        # unmatched
        dsn("g", "R3", "I3", "c@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="NOPE"),
        # delayed only
        dsn("g", "R4", "I4", "d@example.com", "2026-01-01T01:00:00Z",
            "delayed", queue="Q4")))
    # add a second attempt to make R2 ambiguous
    led.import_outbound(jsonl(
        outbound("g", "D2", "b2", "b@example.com", "2026-01-01T00:10:00Z",
                 queue="Q2")))
    # D5 gets contradictory terminal receipts
    led.import_dsn(jsonl(
        dsn("g", "R5", "I5", "e@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q5"),
        dsn("g", "R6", "I6", "e@example.com", "2026-01-01T02:00:00Z",
            "failed", queue="Q5")))
    summary = led.explain_summary()
    check(summary["proven_delivered"] == 1,
          "only the genuinely proven delivery counts")
    counts = summary["delivery_counts"]
    check(summary["receipt_buckets"].get("ambiguous") == 1, "ambiguous listed")
    check(summary["receipt_buckets"].get("unmatched") == 1, "unmatched listed")
    check(summary["delivery_counts"]["delayed"] == 1, "delayed listed")
    check(summary["delivery_counts"]["inconsistent"] == 1, "inconsistent")
    check(summary["not_proven"]["ambiguous_evidence"] == 1,
          "ambiguous evidence not in success")
    check(summary["evidence_not_counted_as_success"]["ambiguous"],
          "evidence rows exposed")
    check(summary["handling"], "summary states the exclusion rule")


def test_rebuild_matches_incremental_state():
    led = _ambiguous_setup()
    item = led.explain_item("g", "R1", "I1")
    led.import_resolutions(jsonl(resolution(
        "g", "R1", "I1", "D1", "a1", "a@example.com",
        item["candidate_fingerprint"], "2026-01-01T02:00:00Z")))
    led.import_corrections(jsonl(
        correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T03:00:00Z",
                   "failed")))

    def state():
        rows = led.conn.execute(
            "SELECT attempt_row, status, effective_records, contributors FROM"
            " derived_attempt_status ORDER BY attempt_row").fetchall()
        return ([tuple(row) for row in rows],
                led.explain_summary()["receipt_buckets"],
                led.explain_summary()["delivery_counts"])

    before = state()
    led.rebuild()
    after = state()
    check(before == after, f"rebuild is idempotent: {before} != {after}")



def test_late_attempt_turns_unmatched_into_unique():
    led = new_ledger()
    # the receipt is imported first and matches nothing yet
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    # the only attempt so far was sent AFTER the receipt, so it cannot be the
    # sender of this receipt
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T02:00:00Z",
                 queue="Q")))
    check(led.explain_item("g", "R1", "I1")["mark"] == "unmatched",
          "a future attempt is not a candidate")
    check(led.attempt_status("g", "D1", "a1", "a@example.com")["status"]
          == "awaiting", "and no status is invented for it")
    # a late attempt sent before the receipt arrives: 0 -> 1 candidate
    led.import_outbound(jsonl(
        outbound("g", "D2", "b1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    item = led.explain_item("g", "R1", "I1")
    check(item["mark"] == "unique", "the late attempt makes it unique")
    check(item["candidates"][0]["delivery_id"] == "D2",
          "the qualifying attempt is identified")
    check(led.attempt_status("g", "D2", "b1", "a@example.com")["status"]
          == "delivered", "and it now proves that attempt")
    check(led.attempt_status("g", "D1", "a1", "a@example.com")["status"]
          == "awaiting", "the future attempt is still unproven")


def test_unrelated_pending_correction_survives_other_imports():
    led = new_ledger()
    # a pending correction for a receipt that will never arrive
    led.import_corrections(jsonl(
        correction("g", "CX", "CIX", "RX", "IX", "2026-01-01T05:00:00Z",
                   "failed")))
    check(len(led.pending_associations()) == 1, "pending recorded")
    # unrelated activity: a receipt that matches nothing
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    # a receipt with no matching attempt at all
    led.import_outbound(jsonl(
        outbound("g", "D2", "b1", "b@example.com", "2026-01-01T02:00:00Z",
                 queue="QB")))
    led.import_dsn(jsonl(
        dsn("g", "R2", "I2", "b@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="QB")))
    still = [row for row in led.pending_associations()
             if row.get("line_key") == "cor:1"]
    check(len(still) == 1, "the pending correction is still listed")
    check(still[0]["category"] == "correction_pending",
          "and still pending")


def test_stale_decision_on_unique_receipt_is_surfaced():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q"),
        outbound("g", "D1", "a2", "a@example.com", "2026-01-01T00:10:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    fp_two = led.explain_item("g", "R1", "I1")["candidate_fingerprint"]
    led.import_resolutions(jsonl(resolution(
        "g", "R1", "I1", "D1", "a1", "a@example.com", fp_two,
        "2026-01-01T02:00:00Z")))
    check(led.attempt_status("g", "D1", "a1", "a@example.com")["status"]
          == "delivered", "decision applied")
    # a conflicting chain exclusion removes a2 from the candidate set via a
    # time correction on an unrelated... instead: delete a2's candidacy by
    # correcting the receipt time to before a2 was sent
    led.import_corrections(jsonl(
        correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T00:05:00Z",
                   "delivered")))
    item = led.explain_item("g", "R1", "I1")
    check(len(item["candidates"]) == 1, "only a1 remains a candidate")
    check(item["mark"] == "unique", "and no human decision is needed")
    check(item["decisions"][0]["matches_current_set"] is False,
          "the old decision is marked stale")
    summary = led.explain_summary()
    check(summary["stale_decisions"],
          "summary surfaces the stale decision instead of dropping it")



def test_import_order_does_not_change_final_state():
    """Shuffle the import order; the final state must be identical."""
    import itertools

    outbound_rows = [
        outbound("g", "D1", "a1", "u@e.com", "2026-01-01T00:00:00Z",
                 queue="Q1", envelope="E1"),
        outbound("g", "D1", "a2", "u@e.com", "2026-01-01T00:20:00Z",
                 queue="Q1", envelope="E2"),
        outbound("g", "D2", "b1", "u@e.com", "2026-01-01T00:00:00Z",
                 queue="Q2"),
    ]
    dsn_rows = [
        dsn("g", "R1", "I1", "u@e.com", "2026-01-01T02:00:00Z", "delivered",
            queue="Q1"),
        dsn("g", "R2", "I2", "u@e.com", "2026-01-01T02:00:00Z", "failed",
            queue="Q2", envelope="E9"),
    ]
    correction_rows = [
        correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T03:00:00Z",
                   "delayed"),
    ]

    def final_state(payloads):
        led = new_ledger()
        for kind, rows in payloads:
            getattr(led, "import_" + kind)(jsonl(*rows), source=f"<{kind}>")
        return (tuple(led.conn.execute(
            "SELECT attempt_row, status FROM derived_attempt_status"
            " ORDER BY attempt_row").fetchall()),
            led.explain_summary()["delivery_counts"],
            tuple(sorted((row["line_key"], row["category"],
                          row["chain_state"])
                         for row in led.pending_associations())),
            tuple(sorted((r[0], r[1]) for r in led.conn.execute(
                "SELECT line_key, candidate_fp FROM item_link WHERE kind='dsn'"))))

    materials = [("outbound", outbound_rows), ("dsn", dsn_rows),
                 ("corrections", correction_rows)]
    baseline = final_state(materials)
    for order in itertools.permutations(range(3)):
        permuted = [materials[i] for i in order]
        check(final_state(permuted) == baseline,
              f"order {order} differs from the baseline state")



def test_state_persists_across_reopen():
    """A file-backed ledger must serve the same answers after close/reopen."""
    temp = TempLedger()
    led = temp.ledger
    try:
        led.import_outbound(jsonl(
            outbound("g", "D1", "a1", "a@example.com",
                     "2026-01-01T00:00:00Z", queue="Q")))
        led.import_dsn(jsonl(
            dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
                "delivered", queue="Q")))
        before = led.delivery_status("g", "D1", "a@example.com")
        reopened = Ledger.open(temp.path)
        try:
            after = reopened.delivery_status("g", "D1", "a@example.com")
            check(before["status"] == after["status"] == "delivered",
                  "status survives a reopen")
            # a rebuild on the reopened handle is still idempotent
            reopened.rebuild()
            check(reopened.delivery_status(
                "g", "D1", "a@example.com")["status"] == "delivered",
                "rebuild on a reopened ledger keeps the status")
            # and re-importing the same file is a no-op
            again = reopened.import_dsn(jsonl(
                dsn("g", "R1", "I1", "a@example.com",
                    "2026-01-01T01:00:00Z", "delivered", queue="Q")))
            check(again["inserted"] == 0, "identical re-import inserts nothing")
        finally:
            reopened.close()
    finally:
        temp.__exit__(None, None, None)



def test_time_correction_can_make_ambiguous_unique():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "u@e.com", "2026-01-01T00:00:00Z",
                 queue="Q"),
        outbound("g", "D1", "a2", "u@e.com", "2026-01-01T05:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "u@e.com", "2026-01-01T06:00:00Z",
            "delivered", queue="Q")))
    check(led.explain_item("g", "R1", "I1")["mark"] == "ambiguous",
          "both attempts qualify initially")
    # correcting the receipt time to before a2 was sent removes a2
    led.import_corrections(jsonl(
        correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T02:00:00Z",
                   "delivered")))
    item = led.explain_item("g", "R1", "I1")
    check(item["mark"] == "unique", "the corrected time leaves one candidate")
    check([c["attempt_id"] for c in item["candidates"]] == ["a1"],
          "and it is the attempt that existed then")
    check(led.attempt_status("g", "D1", "a1", "u@e.com")["status"]
          == "delivered", "a1 is proven")
    check(led.attempt_status("g", "D1", "a2", "u@e.com")["status"]
          == "awaiting", "a2 is not")


def main():
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
        print(f"  ok  {test.__name__}")
    print(f"status tests: {len(tests)} passed")


if __name__ == "__main__":
    main()
