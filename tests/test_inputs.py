"""Input rules: identity, duplication, atomicity, address handling.

These are *format / identity* failures.  Business ambiguity (unmatched,
ambiguous, conflict, pending) is tested elsewhere and must never raise.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from receipt_ledger import InputFormatError, InputIdentityError  # noqa: E402
from receipt_ledger.addr import AddressError, canonical_recipient  # noqa: E402
from tests.helpers import (check, correction, dsn, jsonl,  # noqa: E402
                           new_ledger, outbound)


def expect_error(exc_type, fn, *, label, code=None):
    try:
        fn()
    except exc_type as exc:
        if code is not None and getattr(exc, "code", None) != code:
            raise AssertionError(
                f"{label}: expected code {code}, got {getattr(exc, 'code', None)}")
        return exc
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"{label}: expected {exc_type.__name__}, got "
            f"{type(exc).__name__}: {exc}") from exc
    raise AssertionError(f"{label}: expected {exc_type.__name__}, nothing raised")


def count(ledger, table):
    return ledger.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_address_convention():
    # ASCII domain folded, local part kept byte-exact
    check(canonical_recipient("Alice@Example.COM") == b"Alice@example.com",
          "domain case folded, local kept")
    check(canonical_recipient("alice@example.com")
          != canonical_recipient("Alice@example.com"),
          "local part is case-sensitive")
    check(canonical_recipient("a.b+tag@x.example")
          == b"a.b+tag@x.example", "dot-atom local accepted")

    for bad, why in [
        ('"quoted local"@x.example', "quoted local part"),
        ("a@[192.0.2.1]", "address literal"),
        ("a@exämple.com", "non-ASCII domain"),
        ("a@example..com", "empty domain label"),
        ("a@example.com.", "trailing dot"),
        ("a b@example.com", "space in local"),
        ("a@localhost", "single-label domain"),
        ("a@b@c.example", "two @"),
        ("@example.com", "empty local"),
        ("a@", "empty domain"),
    ]:
        expect_error(AddressError, lambda b=bad: canonical_recipient(b),
                     label=why)


def test_address_rejection_is_format_error_and_atomic():
    led = new_ledger()
    payload = jsonl(
        dsn("g", "R1", "I1", "ok@example.com", "2026-01-01T00:00:00Z",
            "delivered", queue="Q"),
        dsn("g", "R2", "I2", '"bad"@example.com', "2026-01-01T00:00:00Z",
            "delivered", queue="Q"))
    expect_error(InputFormatError, lambda: led.import_dsn(payload),
                 label="unsupported address", code="input_format_error")
    check(count(led, "dsn_line") == 0, "failed file leaves no partial data")
    check(count(led, "import_file") == 0, "failed file not recorded")


def test_unknown_and_missing_fields():
    led = new_ledger()
    expect_error(
        InputFormatError,
        lambda: led.import_dsn(jsonl({
            "gateway_id": "g", "report_id": "R", "item_id": "I",
            "recipient": "a@example.com", "occurred_at": "2026-01-01T00:00:00Z",
            "action": "delivered", "queueid": "Q"})),
        label="mistyped field name")
    expect_error(
        InputFormatError,
        lambda: led.import_dsn(jsonl({
            "gateway_id": "g", "report_id": "R", "item_id": "I",
            "recipient": "a@example.com", "occurred_at": "2026-01-01T00:00:00Z",
            "action": "delivered"})),
        label="no queue/envelope condition")
    expect_error(
        InputFormatError,
        lambda: led.import_dsn(jsonl({
            "gateway_id": "g", "report_id": "R", "item_id": "I",
            "recipient": "a@example.com", "occurred_at": "2026-01-01T00:00:00Z",
            "action": "maybe", "queue_id": "Q"})),
        label="invalid action")
    expect_error(
        InputFormatError,
        lambda: led.import_dsn(jsonl({
            "gateway_id": "g", "report_id": "R", "item_id": "I",
            "recipient": "a@example.com", "occurred_at": "2026-01-01 00:00:00",
            "action": "delivered", "queue_id": "Q"})),
        label="naive timestamp")
    check(count(led, "dsn_line") == 0, "nothing written by rejected files")


def test_duplicate_identical_is_idempotent():
    led = new_ledger()
    payload = jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T00:00:00Z",
            "delivered", queue="Q"))
    first = led.import_dsn(payload)
    second = led.import_dsn(payload)          # byte-identical file
    third = led.import_dsn(payload + payload)  # same row twice in one file
    check(first["inserted"] == 1, "first import inserts")
    check(second["skipped"] and second["inserted"] == 0,
          "identical file is skipped")
    check(third["skipped"] or third["inserted"] == 0,
          "byte-identical duplicate file does not duplicate rows")
    check(count(led, "dsn_line") == 1, "one receipt row only")


def test_duplicate_conflicting_content_fails_file():
    led = new_ledger()
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T00:00:00Z",
            "delivered", queue="Q")))
    bad = jsonl(
        dsn("g", "R2", "I2", "b@example.com", "2026-01-01T00:00:00Z",
            "delivered", queue="Q"),
        # same identity, different action
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T00:00:00Z",
            "failed", queue="Q"))
    expect_error(InputIdentityError, lambda: led.import_dsn(bad),
                 label="same identity, different content",
                 code="input_identity_error")
    check(count(led, "dsn_line") == 1,
          "the rejected file's other rows were not committed")
    check(count(led, "import_file") == 1, "rejected file not recorded")


def test_conflicting_duplicate_within_one_file():
    led = new_ledger()
    payload = jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T00:00:00Z",
            "delivered", queue="Q"),
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T00:00:00Z",
            "failed", queue="Q"))
    expect_error(InputIdentityError, lambda: led.import_dsn(payload),
                 label="conflict inside one file")
    check(count(led, "dsn_line") == 0, "nothing from the conflicted file")


def test_identity_shared_between_dsn_and_correction():
    led = new_ledger()
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T00:00:00Z",
            "delivered", queue="Q")))
    conflict = jsonl(correction(
        "g", "R1", "I1", "R1", "I1", "2026-01-01T01:00:00Z", "withdraw"))
    expect_error(InputIdentityError, lambda: led.import_corrections(conflict),
                 label="correction reuses a receipt identity")
    check(count(led, "correction_line") == 0, "no correction row committed")


def test_same_identity_on_two_gateways_is_distinct():
    led = new_ledger()
    led.import_dsn(jsonl(
        dsn("gA", "R1", "I1", "a@example.com", "2026-01-01T00:00:00Z",
            "delivered", queue="Q"),
        dsn("gB", "R1", "I1", "a@example.com", "2026-01-01T00:00:00Z",
            "failed", queue="Q")))
    check(count(led, "dsn_line") == 2, "gateway is part of the identity")
    check(led.explain_item("gA", "R1", "I1")["effective_action"] == "delivered",
          "gateway A keeps its own action")
    check(led.explain_item("gB", "R1", "I1")["effective_action"] == "failed",
          "gateway B keeps its own action")


def test_naive_and_offset_timestamps_order_correctly():
    led = new_ledger()
    # +02:00 at 02:00 is 00:00Z: exactly equal to the attempt's sent_at
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T02:00:00+02:00",
            "delivered", queue="Q")))
    check(led.delivery_status("g", "D1", "a@example.com")["status"]
          == "delivered", "sent_at == occurred_at is a match")
    # one microsecond earlier must not match
    led.import_outbound(jsonl(
        outbound("g", "D2", "a1", "a@example.com",
                 "2026-01-01T00:00:00.000001Z", queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R2", "I2", "a@example.com",
            "2026-01-01T00:00:00.000000Z", "delivered", queue="Q")))
    check(led.attempt_status("g", "D2", "a1", "a@example.com")["status"]
          == "awaiting", "microsecond comparison is exact")


def test_correction_cannot_silently_change_recipient():
    led = new_ledger()
    led.import_outbound(jsonl(
        outbound("g", "D1", "a1", "a@example.com", "2026-01-01T00:00:00Z",
                 queue="Q"),
        outbound("g", "D2", "b1", "b@example.com", "2026-01-01T00:00:00Z",
                 queue="Q")))
    led.import_dsn(jsonl(
        dsn("g", "R1", "I1", "a@example.com", "2026-01-01T01:00:00Z",
            "delivered", queue="Q")))
    # recipient is not in the matching fields the correction may change: the
    # chain is excluded rather than quietly re-pointed at another recipient
    led.import_corrections(jsonl(
        correction("g", "C1", "CI1", "R1", "I1", "2026-01-01T02:00:00Z",
                   "delivered", recipient="b@example.com")))
    item = led.explain_item("g", "R1", "I1")
    check(item["chain_state"] == "invalid",
          "rewriting recipient makes the chain error evidence")
    check(item["contributes"] is False, "invalid chain contributes nothing")
    check(led.attempt_status("g", "D2", "b1", "b@example.com")["status"]
          == "awaiting", "the other recipient is not credited")
    check(led.attempt_status("g", "D1", "a1", "a@example.com")["status"]
          == "awaiting", "the original recipient is not credited either")


def test_decision_on_unknown_item_is_rejected():
    led = new_ledger()
    from tests.helpers import resolution
    payload = jsonl(resolution(
        "g", "NOPE", "NOPE", "D1", "a1", "a@example.com", "0" * 64,
        "2026-01-01T00:00:00Z"))
    expect_error(Exception, lambda: led.import_resolutions(payload),
                 label="decision on unknown item")
    check(count(led, "manual_decision") == 0,
          "no decision row for an unknown item")


def main():
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
        print(f"  ok  {test.__name__}")
    print(f"input tests: {len(tests)} passed")


if __name__ == "__main__":
    main()
