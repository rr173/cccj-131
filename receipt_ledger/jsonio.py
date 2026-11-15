"""Strict JSONL reading, RFC 3339 time parsing and canonical hashing."""

from __future__ import annotations

import hashlib
import json
import re

from .errors import InputFormatError

_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?"
    r"(Z|[+-]\d{2}:\d{2})$",
    re.ASCII,
)
_EPOCH_ORDINAL = 719163  # date(1970, 1, 1).toordinal()


def parse_ts(value, what="timestamp"):
    """Parse an RFC 3339 timestamp into integer microseconds since the epoch.

    Deliberately strict: an offset is required (a naive local time would make
    matching depend on where the process runs), and the arithmetic is exact
    integer arithmetic -- no float epoch conversion, so microsecond ordering
    can never be off by a rounding error.
    """
    if not isinstance(value, str):
        raise InputFormatError(f"{what} must be an RFC 3339 string")
    m = _TS_RE.match(value)
    if not m:
        raise InputFormatError(
            f"{what} must be RFC 3339 with an explicit offset: {value!r}")
    year, month, day, hour, minute, second, frac, off = m.groups()
    year, month, day = int(year), int(month), int(day)
    hour, minute, second = int(hour), int(minute), int(second)
    micro = int((frac or "0").ljust(6, "0"))
    if hour > 23 or minute > 59 or second > 59:
        raise InputFormatError(f"{what} has an out-of-range time: {value!r}")
    from datetime import date
    try:
        ordinal = date(year, month, day).toordinal()
    except ValueError as exc:
        raise InputFormatError(f"{what} is not a valid date: {value!r}") from exc
    seconds = ((ordinal - _EPOCH_ORDINAL) * 86400
               + hour * 3600 + minute * 60 + second)
    if off != "Z":
        sign = 1 if off[0] == "+" else -1
        offset_min = sign * (int(off[1:3]) * 60 + int(off[4:6]))
        if abs(offset_min) >= 24 * 60:
            raise InputFormatError(f"{what} has an invalid offset: {value!r}")
        seconds -= offset_min * 60
    return seconds * 1_000_000 + micro


def read_jsonl_bytes(data, *, source="<memory>"):
    """Decode a whole file; return ``(records, sha256_hex)``.

    ``records`` is a list of ``(line_number, object)`` for every non-blank line.
    Blank lines are ignored; anything else that is not a JSON object fails the
    entire file.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("read_jsonl_bytes expects bytes")
    digest = hashlib.sha256(bytes(data)).hexdigest()
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputFormatError(f"{source}: file is not valid UTF-8: {exc}") from exc
    records = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise InputFormatError(
                f"{source}:{lineno}: invalid JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise InputFormatError(
                f"{source}:{lineno}: each line must be a JSON object")
        records.append((lineno, obj))
    if not records:
        raise InputFormatError(f"{source}: file contains no JSON objects")
    return records, digest


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def sha256_hex(text):
    if isinstance(text, str):
        text = text.encode("utf-8")
    return hashlib.sha256(text).hexdigest()


def require_keys(record, *, where, required, optional=()):
    """Reject missing required fields and unknown fields.

    Unknown fields are rejected rather than ignored: silently dropping a
    mistyped ``queueid`` would silently widen a candidate set.
    """
    required = set(required)
    allowed = required | set(optional)
    missing = sorted(required - set(record))
    if missing:
        raise InputFormatError(f"{where}: missing required field(s) {missing}")
    unknown = sorted(set(record) - allowed)
    if unknown:
        raise InputFormatError(f"{where}: unknown field(s) {unknown}")
