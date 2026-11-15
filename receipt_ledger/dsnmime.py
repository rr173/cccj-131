"""Offline parser for gateway-exported bounce messages (.eml -> DSN items).

This module turns the raw bytes of one exported bounce message into canonical
receipt records the ledger can import, or into explicit quarantine outcomes.
It is pure: bytes in, structured results out, no I/O, no clock, no network.

What is accepted
----------------
Only a message whose top-level ``Content-Type`` is ``multipart/report`` with
``report-type=delivery-status`` is a DSN carrier.  Among its *direct* body
parts there must be exactly one ``message/delivery-status`` part.  Plain-text
parts, attachments and embedded ``message/rfc822`` messages are never treated
as receipt data, and nothing is ever guessed from the Subject, the body text
or attachment names.

Report-level failures (the whole message yields no records)
-----------------------------------------------------------
``report_type_mismatch``   not multipart/report, or report-type is not
                           ``delivery-status`` (compared case-insensitively)
``malformed_headers``      message or part header block is not parseable as
                           ``Name: value`` fields, or a structural header
                           (content-type / content-transfer-encoding) repeats
``mime_boundary``          no boundary parameter, no delimiter line, or the
                           closing delimiter is missing (unclosed boundary)
``transfer_encoding``      unsupported or undecodable content-transfer-
                           encoding on the multipart container or on the
                           delivery-status part (strict base64 / strict
                           quoted-printable)
``unsupported_charset``    the delivery-status part declares a charset other
                           than us-ascii / utf-8
``charset_decode``         the part bytes are not valid in the declared charset
``dsn_part_missing``       no message/delivery-status part
``dsn_part_duplicate``     more than one message/delivery-status part
``dsn_structure``          empty delivery-status body, malformed per-message
                           block, or per-recipient fields inside the
                           per-message block

Block-level quarantine (only that recipient block is dropped)
-------------------------------------------------------------
``malformed_field``        a block line is not a field / orphan continuation
``conflicting_fields``     a recognized field repeats with different values
``missing_field``          recipient / action / status / last-attempt-date
                           absent
``invalid_field_value``    a recognized field is empty or not in its defined
                           shape (e.g. a recipient without ``type; address``)
``unsupported_address_type``  recipient address type is not ``rfc822``
``unsupported_address``    the address itself violates the ledger convention
``unsupported_action``     action is not failed / delayed / delivered
``invalid_status``         status is not a ``class.subject.detail`` code with
                           class 2, 4 or 5
``action_status_mismatch`` action contradicts the status class
``invalid_date``           last-attempt-date is not a parseable RFC 2822 date
``missing_condition``      neither x-queue-id nor x-envelope-id is present

Field parsing rules
-------------------
* Field names are case-insensitive; values are handled per their definition.
* Unfolding removes the line break plus the leading whitespace of the
  continuation line and joins directly; nothing else is touched.  A line that
  does not start with whitespace always starts a new field, so adjacent
  fields are never glued together.  All value grammars below tolerate
  optional whitespace between tokens, so a fold point never changes the
  parsed result.
* A recipient address comes from ``Final-Recipient`` if present, otherwise
  from ``Original-Recipient`` (the documented precedence; the two never
  conflict).  The address type must be ``rfc822`` and the address must pass
  the ledger's own address convention; the emitted recipient is the
  ledger-canonical form (local part byte-exact, domain lowercased).
* ``Action`` (case-insensitive) must be consistent with the ``Status``
  class: delivered/2.x.x, failed/5.x.x, delayed/4.x.x.  Anything else -
  including ``relayed``/``expanded`` - is not a final per-recipient result.
* ``occurred_at`` is the block's own ``Last-Attempt-Date`` converted to
  RFC 3339 UTC.  Message-level fields (Reporting-MTA, Original-Envelope-ID,
  Arrival-Date, ...) are report-wide context only: they are recorded in the
  manifest, never copied into per-recipient records.
* ``queue_id`` / ``envelope_id`` come only from the per-recipient extension
  fields ``X-Queue-ID`` / ``X-Envelope-ID``; the ledger requires at least one
  matching condition, so a block with neither is quarantined rather than
  widened by a guess.

Identity
--------
``report_id`` is ``"rpt-" + sha256(raw message bytes)``: content-derived, so
the same report content always has the same identity and changed content can
never impersonate an earlier report.  ``item_id`` is ``"item-<n>"`` where
``<n>`` is the 0-based ordinal of the recipient block inside the
delivery-status part (empty blocks are skipped; the per-message block is not
numbered).  ``gateway_id`` is supplied by the operator, never parsed from the
message.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from datetime import date

from .addr import AddressError, canonical_recipient
from .jsonio import canonical_json

__all__ = [
    "ReportFailure",
    "RecipientRecord",
    "BlockQuarantine",
    "ParsedReport",
    "parse_message",
]

_EPOCH_ORDINAL = 719163  # date(1970, 1, 1).toordinal()


# --------------------------------------------------------------------------- #
# result types
# --------------------------------------------------------------------------- #
class ReportFailure(Exception):
    """Report-level problem: the whole message yields no canonical records."""

    def __init__(self, category, detail):
        super().__init__(f"{category}: {detail}")
        self.category = category
        self.detail = detail


@dataclass
class RecipientRecord:
    """One recipient block converted to a ledger-ready canonical record."""

    block_index: int
    record: dict


@dataclass
class BlockQuarantine:
    """One recipient block that could not be safely converted."""

    block_index: int
    category: str
    detail: str


@dataclass
class ParsedReport:
    """Successful parse of one message."""

    report_id: str
    context: dict        # per-message fields, raw values (report-wide context)
    parse_material: dict  # canonical structure hashed into parse_digest
    parse_digest: str
    outcomes: list       # RecipientRecord | BlockQuarantine, in block order


class _FieldError(Exception):
    """A header/field block is not shaped like 'Name: value' lines."""


class _BlockError(Exception):
    """One recipient block failed validation (becomes a BlockQuarantine)."""

    def __init__(self, category, detail):
        super().__init__(f"{category}: {detail}")
        self.category = category
        self.detail = detail


def _clip(value, limit=80):
    """Short, safe representation of an untrusted token for diagnostics."""
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


# --------------------------------------------------------------------------- #
# generic field-block parsing (message/part headers and DSN body blocks)
# --------------------------------------------------------------------------- #
_B_FIELD_RE = re.compile(rb"^([!-9;-~]+):(.*)$")
_S_FIELD_RE = re.compile(r"^([!-9;-~]+):(.*)$")


def _parse_field_lines(lines, pattern):
    """Parse ``Name: value`` fields with continuation-line unfolding.

    A line starting with SP/HTAB continues the previous field: the line
    break and the continuation's leading whitespace are removed and the
    remainder is appended directly.  Any other line starts a new field, so
    two adjacent fields are never merged.  Returns ``[(name_lower, value)]``
    with values unstripped; callers strip per field grammar.
    """
    fields = []
    for pos, line in enumerate(lines):
        whitespace = b" \t" if isinstance(line, bytes) else " \t"
        if line[:1] in (b" ", b"\t", " ", "\t"):
            if not fields:
                raise _FieldError(
                    f"line {pos + 1} continues a field that does not exist")
            name, value = fields[-1]
            fields[-1] = (name, value + line.lstrip(whitespace))
            continue
        match = pattern.match(line)
        if not match:
            raise _FieldError(
                f"line {pos + 1} is not a 'Name: value' field")
        fields.append((match.group(1).lower(), match.group(2)))
    return fields


def _split_head_body(data, newline):
    """Split at the first truly empty line into (head_lines, body)."""
    lines = data.split(newline)
    for pos, line in enumerate(lines):
        if line == newline[:0]:  # empty bytes/str
            return lines[:pos], newline.join(lines[pos + 1:])
    return lines, newline[:0]


# --------------------------------------------------------------------------- #
# Content-Type / CTE
# --------------------------------------------------------------------------- #
def _split_quoted(text, sep):
    """Split on ``sep`` occurrences that are outside quoted strings."""
    parts, buf, in_quote, escaped = [], [], False, False
    for char in text:
        if escaped:
            buf.append(char)
            escaped = False
        elif char == "\\" and in_quote:
            buf.append(char)
            escaped = True
        elif char == '"':
            buf.append(char)
            in_quote = not in_quote
        elif char == sep and not in_quote:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(char)
    parts.append("".join(buf))
    return parts


def _unquote(value):
    if len(value) < 2 or not value.endswith('"'):
        raise _FieldError("malformed quoted-string parameter")
    out, escaped = [], False
    for char in value[1:-1]:
        if escaped:
            out.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        else:
            out.append(char)
    if escaped:
        raise _FieldError("malformed quoted-string parameter")
    return "".join(out)


def _parse_content_type(raw):
    """Parse a Content-Type value into (maintype, subtype, params)."""
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise _FieldError("content-type is not ASCII") from exc
    chunks = _split_quoted(text, ";")
    main = chunks[0].strip()
    if main.count("/") != 1:
        raise _FieldError("content-type is not 'type/subtype'")
    maintype, subtype = (part.strip().lower() for part in main.split("/"))
    if not maintype or not subtype:
        raise _FieldError("content-type is not 'type/subtype'")
    params = {}
    for chunk in chunks[1:]:
        if not chunk.strip():
            continue  # tolerate a trailing ';'
        if "=" not in chunk:
            raise _FieldError("malformed content-type parameter")
        name, _, value = chunk.partition("=")
        name = name.strip().lower()
        value = value.strip()
        if not name:
            raise _FieldError("malformed content-type parameter")
        if name in params:
            raise _FieldError(f"duplicate content-type parameter {name!r}")
        if value.startswith('"'):
            value = _unquote(value)
        params[name] = value
    return maintype, subtype, params


def _cte_value(raw):
    try:
        return raw.decode("ascii").strip().lower()
    except UnicodeDecodeError as exc:
        raise ReportFailure(
            "transfer_encoding",
            "content-transfer-encoding is not ASCII") from exc


# --------------------------------------------------------------------------- #
# strict transfer decoding
# --------------------------------------------------------------------------- #
_B64_WS_RE = re.compile(rb"[ \t\n\r]+")
_QP_HEX = b"0123456789abcdefABCDEF"


def _decode_base64(body):
    compact = _B64_WS_RE.sub(b"", body)
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ReportFailure(
            "transfer_encoding",
            f"invalid base64 in delivery-status part: {exc}") from exc


def _decode_quoted_printable(body):
    """Strict quoted-printable: '=' must start =XX or a soft line break."""
    out = bytearray()
    pos = 0
    while pos < len(body):
        byte = body[pos]
        if byte != 0x3D:  # '='
            out.append(byte)
            pos += 1
            continue
        if body[pos + 1:pos + 2] == b"\n":  # soft break (input is normalized)
            pos += 2
            continue
        pair = body[pos + 1:pos + 3]
        if len(pair) == 2 and pair[0] in _QP_HEX and pair[1] in _QP_HEX:
            out.append(int(pair, 16))
            pos += 3
            continue
        raise ReportFailure(
            "transfer_encoding",
            f"invalid quoted-printable escape at offset {pos} in "
            "delivery-status part")
    return bytes(out)


def _decode_transfer(cte, body):
    if cte in ("7bit", "8bit", "binary"):
        return body
    if cte == "base64":
        return _decode_base64(body)
    if cte == "quoted-printable":
        return _decode_quoted_printable(body)
    raise ReportFailure(
        "transfer_encoding",
        f"unsupported content-transfer-encoding {_clip(cte)}")


# --------------------------------------------------------------------------- #
# MIME structure
# --------------------------------------------------------------------------- #
def _split_mime_parts(body, boundary):
    """Split a multipart body; require the closing delimiter to exist."""
    delimiter = b"--" + boundary.encode("ascii")
    closing = delimiter + b"--"
    parts, current = [], None
    saw_open = saw_close = False
    for line in body.split(b"\n"):
        marker = line.rstrip(b" \t")  # transport padding is allowed
        if marker == closing:
            if current is not None:
                parts.append(b"\n".join(current))
                current = None
            saw_close = True
            break  # everything after the closing delimiter is the epilogue
        if marker == delimiter:
            if current is not None:
                parts.append(b"\n".join(current))
            current = []
            saw_open = True
            continue
        if current is not None:
            current.append(line)
    if not saw_open:
        raise ReportFailure(
            "mime_boundary",
            f"no boundary delimiter {_clip('--' + boundary)} found")
    if not saw_close:
        raise ReportFailure(
            "mime_boundary",
            f"closing boundary {_clip('--' + boundary + '--')} not found")
    return parts


def _structural_headers(headers, where):
    """Extract Content-Type/CTE, rejecting duplicates of structural fields."""
    ctypes = [value for name, value in headers if name == b"content-type"]
    if len(ctypes) > 1:
        raise ReportFailure(
            "malformed_headers", f"{where}: duplicate content-type header")
    ctes = [value for name, value in headers
            if name == b"content-transfer-encoding"]
    if len(ctes) > 1:
        raise ReportFailure(
            "malformed_headers",
            f"{where}: duplicate content-transfer-encoding header")
    return ctypes, ctes


# --------------------------------------------------------------------------- #
# DSN body
# --------------------------------------------------------------------------- #
_MESSAGE_FIELDS = ("reporting-mta", "dsn-gateway", "received-from-mta",
                   "arrival-date", "original-envelope-id")
_RECIPIENT_CORE = ("final-recipient", "original-recipient", "action",
                   "status")
_RECOGNIZED_RECIPIENT_FIELDS = _RECIPIENT_CORE + (
    "last-attempt-date", "x-queue-id", "x-envelope-id")

_STATUS_RE = re.compile(r"^([245])\.\d{1,3}\.\d{1,3}$")
_DATE_RE = re.compile(
    r"^\s*(?:[A-Za-z]+\s*,\s*)?(\d{1,2})\s*([A-Za-z]+)\s*(\d{4})\s*"
    r"(\d{1,2}):(\d{2})(?:\s*:\s*(\d{2}))?\s*([+-]\d{4}|UT|GMT|Z)\s*$",
    re.IGNORECASE)
_MONTHS = {name: index for index, name in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun",
     "jul", "aug", "sep", "oct", "nov", "dec"), 1)}
_EXPECTED_CLASS = {"delivered": 2, "failed": 5, "delayed": 4}


def _message_context(fields):
    """Per-message fields are report-wide context, never per-recipient facts."""
    context = {name: [] for name in _MESSAGE_FIELDS}
    other = set()
    for name, value in fields:
        if name in context:
            context[name].append(value.strip())
        else:
            other.add(name)
    context["other_fields"] = sorted(other)
    return context


def _dedup_key(name, value):
    """Comparison key for repeated recognized fields (no silent picking)."""
    if name in ("final-recipient", "original-recipient"):
        atype, sep, addr = value.partition(";")
        if not sep:
            return (None, value)
        return (atype.strip().lower(), addr.strip())
    if name == "action":
        return value.lower()
    return value


def _recipient_address(value):
    if ";" not in value:
        raise _BlockError(
            "invalid_field_value",
            "recipient field is not '<address-type>; <address>'")
    atype, _, addr = value.partition(";")
    atype = atype.strip().lower()
    addr = addr.strip()
    if atype != "rfc822":
        raise _BlockError(
            "unsupported_address_type",
            f"address type {_clip(atype)} is not supported")
    if not addr:
        raise _BlockError("invalid_field_value", "recipient address is empty")
    try:
        canonical = canonical_recipient(addr)
    except AddressError as exc:
        raise _BlockError(
            "unsupported_address",
            f"recipient address is not supported: {exc}") from exc
    return canonical.decode("ascii")


def _parse_rfc2822(value):
    """Parse an RFC 2822 date-time into canonical RFC 3339 UTC text."""
    match = _DATE_RE.match(value)
    if not match:
        raise _BlockError(
            "invalid_date",
            f"last-attempt-date {_clip(value)} is not a supported RFC 2822 "
            "date-time")
    day, month_name, year, hour, minute, second, zone = match.groups()
    month = _MONTHS.get(month_name[:3].lower())
    if month is None:
        raise _BlockError(
            "invalid_date",
            f"last-attempt-date {_clip(value)} has an unknown month name")
    year, day = int(year), int(day)
    hour, minute = int(hour), int(minute)
    second = int(second) if second else 0
    if hour > 23 or minute > 59 or second > 59:
        raise _BlockError(
            "invalid_date",
            f"last-attempt-date {_clip(value)} has an out-of-range time")
    if zone.upper() in ("UT", "GMT", "Z"):
        offset_minutes = 0
    else:
        zh, zm = int(zone[1:3]), int(zone[3:5])
        if zh > 23 or zm > 59:
            raise _BlockError(
                "invalid_date",
                f"last-attempt-date {_clip(value)} has an invalid zone")
        offset_minutes = (zh * 60 + zm) * (1 if zone[0] == "+" else -1)
    try:
        ordinal = date(year, month, day).toordinal()
    except ValueError as exc:
        raise _BlockError(
            "invalid_date",
            f"last-attempt-date {_clip(value)} is not a valid calendar "
            "date") from exc
    total = ((ordinal - _EPOCH_ORDINAL) * 86400 + hour * 3600 + minute * 60
             + second - offset_minutes * 60)
    days, rem = divmod(total, 86400)
    try:
        moment = date.fromordinal(_EPOCH_ORDINAL + days)
    except ValueError as exc:
        raise _BlockError(
            "invalid_date",
            f"last-attempt-date {_clip(value)} is out of range") from exc
    hour, rem = divmod(rem, 3600)
    minute, second = divmod(rem, 60)
    return (f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}T"
            f"{hour:02d}:{minute:02d}:{second:02d}Z")


def _recipient_record(index, fields, gateway_id, report_id):
    grouped = {}
    for name, value in fields:
        if name in _RECOGNIZED_RECIPIENT_FIELDS:
            grouped.setdefault(name, []).append(value.strip())
    # Conflicting duplicates: never guess, never silently take the last one.
    for name, values in grouped.items():
        if len(values) > 1:
            keys = [_dedup_key(name, value) for value in values]
            if any(key != keys[0] for key in keys[1:]):
                raise _BlockError(
                    "conflicting_fields",
                    f"field {name!r} appears {len(values)} times with "
                    "different values")
    single = {name: values[0] for name, values in grouped.items()}
    for name, value in single.items():
        if value == "":
            raise _BlockError(
                "invalid_field_value", f"field {name!r} is empty")

    if "final-recipient" in single:
        chosen = single["final-recipient"]
    elif "original-recipient" in single:
        chosen = single["original-recipient"]
    else:
        raise _BlockError(
            "missing_field",
            "neither final-recipient nor original-recipient is present")
    recipient = _recipient_address(chosen)

    action = single.get("action")
    if action is None:
        raise _BlockError("missing_field", "action is missing")
    action = action.lower()
    if action not in _EXPECTED_CLASS:
        raise _BlockError(
            "unsupported_action",
            f"action {_clip(action)} is not a final delivery action")

    status = single.get("status")
    if status is None:
        raise _BlockError("missing_field", "status is missing")
    match = _STATUS_RE.match(status)
    if not match:
        raise _BlockError(
            "invalid_status",
            f"status {_clip(status)} is not a 'class.subject.detail' code "
            "with class 2, 4 or 5")
    if int(match.group(1)) != _EXPECTED_CLASS[action]:
        raise _BlockError(
            "action_status_mismatch",
            f"action {action!r} contradicts status {_clip(status)}")

    last_attempt = single.get("last-attempt-date")
    if last_attempt is None:
        raise _BlockError("missing_field", "last-attempt-date is missing")
    occurred_at = _parse_rfc2822(last_attempt)

    queue_id = single.get("x-queue-id")
    envelope_id = single.get("x-envelope-id")
    if queue_id is None and envelope_id is None:
        raise _BlockError(
            "missing_condition",
            "neither x-queue-id nor x-envelope-id is present")

    record = {"gateway_id": gateway_id, "report_id": report_id,
                  "item_id": f"item-{index}", "recipient": recipient,
                  "occurred_at": occurred_at, "action": action}
    if queue_id is not None:
        record["queue_id"] = queue_id
    if envelope_id is not None:
        record["envelope_id"] = envelope_id
    return record


def _recipient_outcome(index, block_lines, gateway_id, report_id):
    try:
        fields = _parse_field_lines(block_lines, _S_FIELD_RE)
    except _FieldError as exc:
        return BlockQuarantine(index, "malformed_field", str(exc))
    try:
        record = _recipient_record(index, fields, gateway_id, report_id)
    except _BlockError as exc:
        return BlockQuarantine(index, exc.category, exc.detail)
    return RecipientRecord(index, record)


def _parse_dsn_body(text, gateway_id, report_id):
    """Parse the delivery-status body into (context, outcomes)."""
    lines = text.split("\n")
    blocks, current = [], []
    for line in lines:
        if line == "":
            blocks.append(current)
            current = []
        else:
            current.append(line)
    blocks.append(current)
    blocks = [block for block in blocks if block]
    if not blocks:
        raise ReportFailure(
            "dsn_structure", "delivery-status part has no field blocks")
    try:
        message_fields = _parse_field_lines(blocks[0], _S_FIELD_RE)
    except _FieldError as exc:
        raise ReportFailure(
            "dsn_structure", f"per-message block: {exc}") from exc
    if any(name in _RECIPIENT_CORE for name, _ in message_fields):
        raise ReportFailure(
            "dsn_structure",
            "per-message block contains per-recipient fields")
    context = _message_context(message_fields)
    outcomes = [_recipient_outcome(index, block, gateway_id, report_id)
                for index, block in enumerate(blocks[1:])]
    return context, outcomes


# --------------------------------------------------------------------------- #
# top level
# --------------------------------------------------------------------------- #
_SUPPORTED_CHARSETS = {"us-ascii": "ascii", "ascii": "ascii",
                       "utf-8": "utf-8", "utf8": "utf-8"}


def parse_message(raw, *, gateway_id):
    """Parse one raw exported message into a :class:`ParsedReport`.

    Raises :class:`ReportFailure` when the message as a whole cannot yield
    canonical records; otherwise every recipient block becomes either a
    :class:`RecipientRecord` or a :class:`BlockQuarantine`, in original
    block order.
    """
    report_id = "rpt-" + hashlib.sha256(raw).hexdigest()
    data = raw.replace(b"\r\n", b"\n")  # parse copy; hashing uses raw bytes
    head_lines, body = _split_head_body(data, b"\n")
    try:
        headers = _parse_field_lines(head_lines, _B_FIELD_RE)
    except _FieldError as exc:
        raise ReportFailure("malformed_headers", f"message header: {exc}")
    ctypes, ctes = _structural_headers(headers, "message header")
    if not ctypes:
        raise ReportFailure(
            "report_type_mismatch", "message has no content-type header")
    try:
        maintype, subtype, params = _parse_content_type(ctypes[0])
    except _FieldError as exc:
        raise ReportFailure("malformed_headers",
                            f"message header: {exc}") from exc
    if (maintype, subtype) != ("multipart", "report"):
        raise ReportFailure(
            "report_type_mismatch",
            f"content-type is {maintype}/{subtype}, not multipart/report")
    if params.get("report-type", "").lower() != "delivery-status":
        raise ReportFailure(
            "report_type_mismatch",
            "report-type parameter is not 'delivery-status'")
    boundary = params.get("boundary")
    if not boundary:
        raise ReportFailure(
            "mime_boundary", "multipart/report has no boundary parameter")
    if ctes:
        cte = _cte_value(ctes[0])
        if cte not in ("7bit", "8bit", "binary"):
            raise ReportFailure(
                "transfer_encoding",
                f"multipart container uses content-transfer-encoding "
                f"{_clip(cte)}")

    dsn_parts = []
    for part in _split_mime_parts(body, boundary):
        part_head, part_body = _split_head_body(part, b"\n")
        try:
            part_headers = _parse_field_lines(part_head, _B_FIELD_RE)
        except _FieldError as exc:
            raise ReportFailure("malformed_headers", f"body part: {exc}")
        part_ctypes, part_ctes = _structural_headers(part_headers, "body part")
        part_type, part_params = ("text", "plain"), {}
        if part_ctypes:
            try:
                maintype, subtype, part_params = _parse_content_type(
                    part_ctypes[0])
            except _FieldError as exc:
                raise ReportFailure("malformed_headers",
                                    f"body part: {exc}") from exc
            part_type = (maintype, subtype)
        if part_type == ("message", "delivery-status"):
            dsn_parts.append((part_ctes, part_params, part_body))

    if not dsn_parts:
        raise ReportFailure(
            "dsn_part_missing", "no message/delivery-status body part")
    if len(dsn_parts) > 1:
        raise ReportFailure(
            "dsn_part_duplicate",
            f"{len(dsn_parts)} message/delivery-status body parts")
    part_ctes, part_params, part_body = dsn_parts[0]

    cte = _cte_value(part_ctes[0]) if part_ctes else "7bit"
    decoded = _decode_transfer(cte, part_body)
    charset = part_params.get("charset", "us-ascii").lower()
    codec = _SUPPORTED_CHARSETS.get(charset)
    if codec is None:
        raise ReportFailure(
            "unsupported_charset",
            f"delivery-status part charset {_clip(charset)} is not supported")
    try:
        text = decoded.decode(codec)
    except UnicodeDecodeError as exc:
        raise ReportFailure(
            "charset_decode",
            f"delivery-status part is not valid {charset}: {exc}") from exc
    # decoded content is a fresh byte stream (e.g. from base64) and may carry
    # its own CRLF line endings; normalize before block parsing
    text = text.replace("\r\n", "\n")

    context, outcomes = _parse_dsn_body(text, gateway_id, report_id)
    material = {"gateway_id": gateway_id, "context": context, "blocks": []}
    for outcome in outcomes:
        if isinstance(outcome, RecipientRecord):
            material["blocks"].append({
                "block_index": outcome.block_index, "outcome": "record",
                "record": outcome.record})
        else:
            material["blocks"].append({
                "block_index": outcome.block_index, "outcome": "quarantine",
                "category": outcome.category, "detail": outcome.detail})
    digest = hashlib.sha256(
        canonical_json(material).encode("utf-8")).hexdigest()
    return ParsedReport(report_id=report_id, context=context,
                        parse_material=material, parse_digest=digest,
                        outcomes=outcomes)
