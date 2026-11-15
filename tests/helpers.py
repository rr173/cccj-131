"""Test helpers: build JSONL payloads and inspect ledger state."""

from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from receipt_ledger import Ledger  # noqa: E402


def jsonl(*rows):
    return ("\n".join(json.dumps(r, ensure_ascii=False) for r in rows)
            + "\n").encode("utf-8")


def outbound(gw, delivery, attempt, recipient, sent, queue=None, envelope=None):
    row = {"gateway_id": gw, "delivery_id": delivery, "attempt_id": attempt,
           "recipient": recipient, "sent_at": sent}
    if queue is not None:
        row["queue_id"] = queue
    if envelope is not None:
        row["envelope_id"] = envelope
    return row


def dsn(gw, report, item, recipient, occurred, action, queue=None,
        envelope=None):
    row = {"gateway_id": gw, "report_id": report, "item_id": item,
           "recipient": recipient, "occurred_at": occurred, "action": action}
    if queue is not None:
        row["queue_id"] = queue
    if envelope is not None:
        row["envelope_id"] = envelope
    return row


def correction(gw, report, item, target_report, target_item, occurred, action,
               queue=None, envelope=None, recipient=None):
    row = {"gateway_id": gw, "report_id": report, "item_id": item,
           "target_report_id": target_report, "target_item_id": target_item,
           "occurred_at": occurred, "action": action}
    if queue is not None:
        row["queue_id"] = queue
    if envelope is not None:
        row["envelope_id"] = envelope
    if recipient is not None:
        row["recipient"] = recipient
    return row


def resolution(gw, report, item, delivery, attempt, recipient, fingerprint_hex,
               decided):
    return {"gateway_id": gw, "report_id": report, "item_id": item,
            "delivery_id": delivery, "attempt_id": attempt,
            "recipient": recipient,
            "candidate_fingerprint": fingerprint_hex,
            "decided_at": decided}


def new_ledger():
    return Ledger.create()


class TempLedger:
    """Context manager over a temporary on-disk ledger."""

    def __init__(self):
        self.path = temp_db()
        self.ledger = Ledger.create(self.path)

    def __enter__(self):
        return self.ledger

    def __exit__(self, *exc):
        self.ledger.close()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(self.path + suffix)
            except FileNotFoundError:
                pass


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    return True


def temp_db():
    handle, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(handle)
    os.unlink(path)
    return path


def snapshot_statuses(ledger):
    """All attempt statuses keyed by (gateway_id, delivery, attempt, rec bytes)."""
    rows = ledger.conn.execute(
        "SELECT g.ident, s.delivery_id, s.attempt_id, s.recipient_sig,"
        " s.status FROM derived_attempt_status s JOIN gateway g"
        " ON g.id = s.gateway_row ORDER BY s.attempt_row").fetchall()
    out = {}
    for ident, delivery, attempt, rec_sig, status in rows:
        out[(ident.decode().removeprefix("i:"), delivery, attempt,
             bytes(rec_sig))] = status
    return out


def snapshot_delivery_statuses(ledger):
    rows = ledger.conn.execute(
        "SELECT g.ident, a.delivery_id, a.recipient_sig,"
        "       a.recipient_text FROM outbound_attempt a JOIN gateway g"
        " ON g.id = a.gateway_row").fetchall()
    pairs = {}
    for ident, delivery, rec_sig, text in rows:
        pairs[(ident.decode().removeprefix("i:"), delivery, text)] = rec_sig
    out = {}
    for (gw, delivery, text), rec_sig in pairs.items():
        try:
            out[(gw, delivery, rec_sig.hex())] = ledger.delivery_status(
                gw, delivery, text)["status"]
        except KeyError:
            out[(gw, delivery, rec_sig.hex())] = "missing"
    return out
