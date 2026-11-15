"""JSONL ingress: parse and validate a whole file before touching the DB.

Every parser is pure: it takes one JSON object and returns a normalized dict
with parsed instants and signature bytes, or raises ``InputFormatError``.  The
ledger collects the whole file first, so a malformed line anywhere leaves no
partial data behind.
"""

from __future__ import annotations

from .addr import AddressError, id_sig, identity_sig, recipient_sig
from .errors import InputFormatError
from .jsonio import parse_ts, require_keys

ACTIONS = ("delayed", "delivered", "failed")
CORRECTION_ACTIONS = ACTIONS + ("withdraw",)

OUTBOUND_REQUIRED = ("delivery_id", "attempt_id", "recipient", "sent_at")
OUTBOUND_OPTIONAL = ("queue_id", "envelope_id", "gateway_id")
DSN_REQUIRED = ("gateway_id", "report_id", "item_id", "recipient",
                "occurred_at", "action")
DSN_OPTIONAL = ("queue_id", "envelope_id")
CORRECTION_REQUIRED = ("gateway_id", "report_id", "item_id",
                       "target_report_id", "target_item_id",
                       "occurred_at", "action")
CORRECTION_OPTIONAL = ("queue_id", "envelope_id", "recipient")
RESOLVE_REQUIRED = ("gateway_id", "report_id", "item_id", "delivery_id",
                    "attempt_id", "recipient", "candidate_fingerprint",
                    "decided_at")
RESOLVE_OPTIONAL = ()


def gateway_signature(gateway_id, where="gateway"):
    return identity_sig(gateway_id, what=f"{where}: gateway_id")


def identity_signature(value, field):
    return identity_sig(value, what=field)


def _text(record, field, where):
    value = record[field]
    if not isinstance(value, str):
        raise InputFormatError(f"{where}: field {field!r} must be a string")
    if value == "":
        raise InputFormatError(f"{where}: field {field!r} must not be empty")
    return value


def _opt_text(record, field, where):
    value = record.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or value == "":
        raise InputFormatError(
            f"{where}: field {field!r} must be a non-empty string when present")
    return value


def _recipient(record, field, where):
    raw = record[field]
    try:
        return raw, recipient_sig(raw)
    except AddressError as exc:
        raise InputFormatError(f"{where}: {field}: {exc}") from exc


def _identity(record, field, where):
    try:
        return identity_sig(record[field], what=field)
    except AddressError as exc:
        raise InputFormatError(f"{where}: {field}: {exc}") from exc


def _id(record, field, where):
    try:
        return id_sig(record[field], what=field)
    except AddressError as exc:
        raise InputFormatError(f"{where}: {field}: {exc}") from exc


def _instant(record, field, where):
    return parse_ts(record[field], what=f"{where}: {field}")


def parse_outbound(record, where):
    require_keys(record, where=where, required=OUTBOUND_REQUIRED,
                 optional=OUTBOUND_OPTIONAL)
    raw_recipient, rec_sig = _recipient(record, "recipient", where)
    queue_id = _opt_text(record, "queue_id", where)
    envelope_id = _opt_text(record, "envelope_id", where)
    return {
        "delivery_id": _text(record, "delivery_id", where),
        "attempt_id": _text(record, "attempt_id", where),
        "recipient": raw_recipient,
        "recipient_sig": rec_sig,
        "queue_id": queue_id,
        "queue_sig": _id(record, "queue_id", where) if queue_id else None,
        "envelope_id": envelope_id,
        "envelope_sig": (_id(record, "envelope_id", where)
                         if envelope_id else None),
        "sent_at_us": _instant(record, "sent_at", where),
        "sent_at_text": record["sent_at"],
        "gateway_id": _opt_text(record, "gateway_id", where),
    }


def parse_dsn(record, where):
    require_keys(record, where=where, required=DSN_REQUIRED,
                 optional=DSN_OPTIONAL)
    action = record["action"]
    if not isinstance(action, str) or action not in ACTIONS:
        raise InputFormatError(
            f"{where}: action must be one of {list(ACTIONS)}, got {action!r}")
    queue_id = _opt_text(record, "queue_id", where)
    envelope_id = _opt_text(record, "envelope_id", where)
    if queue_id is None and envelope_id is None:
        raise InputFormatError(
            f"{where}: a receipt item needs at least one of queue_id/envelope_id")
    raw_recipient, rec_sig = _recipient(record, "recipient", where)
    return {
        "gateway_id": _text(record, "gateway_id", where),
        "gateway_sig": _identity(record, "gateway_id", where),
        "report_id": _text(record, "report_id", where),
        "report_sig": _identity(record, "report_id", where),
        "item_id": _text(record, "item_id", where),
        "item_sig": _identity(record, "item_id", where),
        "occurred_at_us": _instant(record, "occurred_at", where),
        "occurred_text": record["occurred_at"],
        "action": action,
        "recipient": raw_recipient,
        "recipient_sig": rec_sig,
        "queue_id": queue_id,
        "queue_sig": _id(record, "queue_id", where) if queue_id else None,
        "envelope_id": envelope_id,
        "envelope_sig": (_id(record, "envelope_id", where)
                         if envelope_id else None),
    }


def parse_correction(record, where):
    require_keys(record, where=where, required=CORRECTION_REQUIRED,
                 optional=CORRECTION_OPTIONAL)
    action = record["action"]
    if not isinstance(action, str) or action not in CORRECTION_ACTIONS:
        raise InputFormatError(
            f"{where}: action must be one of {list(CORRECTION_ACTIONS)}, "
            f"got {action!r}")
    queue_id = _opt_text(record, "queue_id", where)
    envelope_id = _opt_text(record, "envelope_id", where)
    recipient = rec_sig = None
    if "recipient" in record:
        recipient, rec_sig = _recipient(record, "recipient", where)
    return {
        "gateway_id": _text(record, "gateway_id", where),
        "gateway_sig": _identity(record, "gateway_id", where),
        "report_id": _text(record, "report_id", where),
        "report_sig": _identity(record, "report_id", where),
        "item_id": _text(record, "item_id", where),
        "item_sig": _identity(record, "item_id", where),
        "target_report_id": _text(record, "target_report_id", where),
        "target_report_sig": _identity(record, "target_report_id", where),
        "target_item_id": _text(record, "target_item_id", where),
        "target_item_sig": _identity(record, "target_item_id", where),
        "occurred_at_us": _instant(record, "occurred_at", where),
        "occurred_text": record["occurred_at"],
        "action": action,
        "recipient": recipient,
        "recipient_sig": rec_sig,
        "queue_id": queue_id,
        "queue_sig": _id(record, "queue_id", where) if queue_id else None,
        "envelope_id": envelope_id,
        "envelope_sig": (_id(record, "envelope_id", where)
                         if envelope_id else None),
    }


def parse_resolve(record, where):
    require_keys(record, where=where, required=RESOLVE_REQUIRED,
                 optional=RESOLVE_OPTIONAL)
    _, rec_sig = _recipient(record, "recipient", where)
    fp = record["candidate_fingerprint"]
    if not isinstance(fp, str) or len(fp) != 64 or any(
            c not in "0123456789abcdef" for c in fp):
        raise InputFormatError(
            f"{where}: candidate_fingerprint must be 64 lowercase hex chars")
    return {
        "gateway_id": _text(record, "gateway_id", where),
        "gateway_sig": _identity(record, "gateway_id", where),
        "report_sig": _identity(record, "report_id", where),
        "item_sig": _identity(record, "item_id", where),
        "delivery_id": _text(record, "delivery_id", where),
        "attempt_id": _text(record, "attempt_id", where),
        "recipient": record["recipient"],
        "recipient_sig": rec_sig,
        "candidate_fingerprint": fp,
        "decided_at_us": _instant(record, "decided_at", where),
        "decided_text": record["decided_at"],
    }
