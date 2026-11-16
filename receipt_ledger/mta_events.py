"""Offline reconstruction of per-recipient send attempts from Postfix MTA logs.

The mail-operations team collects rotated, UTF-8 JSONL event logs from several
Postfix gateways and books them into the ledger afterwards.  The ledger's
``import-outbound`` already expects one row per recipient send attempt, but in
the raw log the facts are spread over three event kinds sharing one queue id:

* ``queued``    -- the mail entered the gateway queue (carries Message-ID and
  sender);
* ``delivery``  -- one SMTP delivery attempt to one recipient (``relay`` and
  ``result``, ``sent`` or ``deferred``);
* ``removed``   -- the queue entry left the queue.

A queue lifecycle runs from one ``queued`` to the matching ``removed`` on one
host.  ``import_mta_events`` reconstructs those lifecycles without touching any
ledger and writes three files into a **new** output directory:

``outbound.jsonl``
    Canonical per-recipient send attempts, one JSON object per line, directly
    importable with ``import-outbound``.  Every successful *or deferred*
    ``delivery`` event of a decidable lifecycle becomes one attempt:
    ``gateway_id`` (the operator-supplied gateway, never parsed from the log),
    ``delivery_id``, ``attempt_id``, ``recipient``, ``queue_id``,
    ``envelope_id`` (the lifecycle's Message-ID) and ``sent_at`` (the SMTP
    delivery timestamp).
``quarantine.jsonl``
    Everything that must not be guessed at: line-level failures (bad JSON,
    unknown event, malformed fields, unsupported recipient), orphan
    delivery/removed events with no lifecycle, and whole lifecycles excluded
    because they are ambiguous or contradictory.
``manifest.jsonl``
    Provenance only, one entry per physical source line plus one per
    reconstructed lifecycle and a leading ``run`` entry.  Source coordinates
    are relative path + line number + file SHA-256, so the originals need not
    stay online.

Identity rules
--------------
Neither ``queue_id`` nor Message-ID identifies a mail on its own: a queue id is
only unique within one host's one queue lifecycle and may be reused *after* a
``removed``, while the same Message-ID may legitimately span different mails.
The lifecycle identity is therefore ``(host, queue_id, lifecycle start)`` and
the ``delivery_id`` is derived from the full canonical event set of that one
lifecycle, so two reused-queue lifetimes with an identical Message-ID produce
two different deliveries and never merge.

Ordering and determinism
------------------------
Directory enumeration, file order and line order carry no meaning.  Events are
deduplicated on their canonical content (an identical line repeated across an
overlapping rotation boundary is one business event, but every copy keeps its
own manifest source coordinates), grouped by ``(host, queue_id)`` and ordered
by ``(timestamp, event kind, canonical content)``.  Retry numbers within one
recipient come from timestamp order only; distinct delivery events for the same
recipient at the same timestamp cannot be ordered without input line numbers,
so that whole lifecycle is quarantined as ambiguous.  The same input event set
always produces byte-identical business output and identical ids.

Atomicity
---------
All reading, parsing and reconstruction happens first.  The three files are
then written inside a controlled temporary directory next to the target,
fsynced and published with a single atomic ``os.rename``.  If the target
already exists, an input file cannot be decoded, or any write fails, the
command fails and leaves nothing behind.  Input files are only read.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from dataclasses import dataclass, field

from .addr import AddressError, canonical_recipient
from .errors import InputFormatError
from .jsonio import canonical_json, parse_ts

__all__ = ["MtaEventError", "import_mta_events"]

OUTBOUND_JSONL = "outbound.jsonl"
QUARANTINE_JSONL = "quarantine.jsonl"
MANIFEST_JSONL = "manifest.jsonl"
OUTPUT_NAMES = (OUTBOUND_JSONL, QUARANTINE_JSONL, MANIFEST_JSONL)

QUEUED = "queued"
DELIVERY = "delivery"
REMOVED = "removed"
EVENT_KINDS = (QUEUED, DELIVERY, REMOVED)
RESULTS = ("sent", "deferred")

# quarantine categories
CAT_INVALID_JSON = "invalid_json"
CAT_UNKNOWN_EVENT = "unknown_event"
CAT_MALFORMED = "malformed_event"
CAT_INVALID_RECIPIENT = "invalid_recipient"
CAT_ORPHAN = "orphan_event"
CAT_REQUEUED = "queued_before_removed"
CAT_CONTENT_CONFLICT = "content_conflict"
CAT_AMBIGUOUS_ORDER = "ambiguous_delivery_order"

_KIND_RANK = {QUEUED: 0, DELIVERY: 1, REMOVED: 2}
_FORMAT_VERSION = 1
_TOOL = "receipt_ledger import-mta-events"


class MtaEventError(Exception):
    """Batch-level failure; nothing is published when this is raised."""

    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def to_dict(self):
        return {"code": self.code, "message": self.message,
                "details": self.details}


class _LineError(Exception):
    """A single source line that cannot be turned into an event."""

    def __init__(self, category, detail):
        super().__init__(detail)
        self.category = category
        self.detail = detail


# --------------------------------------------------------------------------- #
# parsing: one JSON object -> one normalized, validated event
# --------------------------------------------------------------------------- #
def _require_nonempty_str(obj, key, where):
    value = obj.get(key)
    if not isinstance(value, str) or value == "":
        raise _LineError(CAT_MALFORMED,
                         f"{where}: field {key!r} must be a non-empty string")
    return value


def _reject_extra(obj, allowed, where):
    unknown = sorted(set(obj) - set(allowed))
    if unknown:
        raise _LineError(
            CAT_MALFORMED, f"{where}: unknown field(s) {unknown}")


def _parse_event(obj, where):
    """Validate one decoded JSON object; return the normalized event dict.

    The returned dict keeps the original string values (timestamp included)
    and adds nothing that could change its canonical form, so hashing
    ``canonical_json`` of it is a content identity independent of key order.
    """
    if not isinstance(obj, dict):
        raise _LineError(CAT_MALFORMED, f"{where}: each line must be a JSON "
                                        "object")
    event = _require_nonempty_str(obj, "event", where)
    if event not in EVENT_KINDS:
        raise _LineError(
            CAT_UNKNOWN_EVENT,
            f"{where}: unknown event {event!r}; expected one of "
            f"{list(EVENT_KINDS)}")
    base = ("timestamp", "host", "queue_id", "event")
    if event == QUEUED:
        allowed = base + ("message_id", "sender")
    elif event == DELIVERY:
        allowed = base + ("recipient", "relay", "result")
    else:
        allowed = base
    missing = sorted(k for k in allowed if k not in obj)
    if missing:
        raise _LineError(
            CAT_MALFORMED, f"{where}: missing required field(s) {missing}")
    _reject_extra(obj, allowed, where)
    normalized = {key: _require_nonempty_str(obj, key, where) for key in base}
    try:
        ts_us = parse_ts(normalized["timestamp"], what=f"{where}: timestamp")
    except InputFormatError as exc:
        raise _LineError(CAT_MALFORMED, str(exc)) from exc
    if event == QUEUED:
        normalized["message_id"] = _require_nonempty_str(
            obj, "message_id", where)
        normalized["sender"] = _require_nonempty_str(obj, "sender", where)
    elif event == DELIVERY:
        recipient = _require_nonempty_str(obj, "recipient", where)
        try:
            canonical_recipient(recipient)
        except AddressError as exc:
            raise _LineError(CAT_INVALID_RECIPIENT,
                             f"{where}: recipient: {exc}") from exc
        normalized["recipient"] = recipient
        normalized["relay"] = _require_nonempty_str(obj, "relay", where)
        result = _require_nonempty_str(obj, "result", where)
        if result not in RESULTS:
            raise _LineError(
                CAT_MALFORMED,
                f"{where}: result must be one of {list(RESULTS)}, "
                f"got {result!r}")
        normalized["result"] = result
    return normalized, ts_us


# --------------------------------------------------------------------------- #
# internal data shapes
# --------------------------------------------------------------------------- #
@dataclass
class SourceLine:
    file: str
    line: int
    file_sha256: str
    digest: str | None = None          # canonical event digest, if parsed
    error_category: str | None = None
    error_detail: str | None = None

    def coord(self):
        return {"file": self.file, "line": self.line,
                "file_sha256": self.file_sha256}


@dataclass
class LogicalEvent:
    digest: str
    event: dict
    ts_us: int
    sources: list[SourceLine] = field(default_factory=list)

    def kind(self):
        return self.event["event"]

    def source_coords(self):
        return [s.coord() for s in
                sorted(self.sources, key=lambda s: (s.file, s.line))]


@dataclass
class Segment:
    """One candidate queue lifecycle (queued ... removed) for one host/queue."""

    host: str
    queue_id: str
    events: list[LogicalEvent] = field(default_factory=list)
    category: str | None = None
    detail: str | None = None
    closed: bool = False

    def queued(self):
        return next((e for e in self.events if e.kind() == QUEUED), None)

    def removed(self):
        return next((e for e in self.events if e.kind() == REMOVED), None)

    def deliveries(self):
        return [e for e in self.events if e.kind() == DELIVERY]


def _sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _line(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _write_file(directory, name, text):
    path = os.path.join(directory, name)
    with open(path, "xb") as handle:  # must not exist in a fresh temp dir
        handle.write(text.encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())


def _collect_jsonl_files(input_dir):
    """Return (.jsonl relative paths sorted, other file relative paths sorted)."""
    jsonl_files, skipped = [], []
    for root, dirs, names in os.walk(input_dir):
        dirs.sort()
        for name in sorted(names):
            rel = os.path.relpath(os.path.join(root, name), input_dir)
            rel = rel.replace(os.sep, "/")
            if name.lower().endswith(".jsonl"):
                jsonl_files.append(rel)
            else:
                skipped.append(rel)
    return sorted(jsonl_files), sorted(skipped)


# --------------------------------------------------------------------------- #
# main entry point
# --------------------------------------------------------------------------- #
def import_mta_events(input_dir, output_dir, *, gateway_id):
    """Reconstruct MTA queue lifecycles into importable outbound attempts.

    Returns a JSON-serializable run summary.  Raises :class:`MtaEventError`
    (publishing nothing) when the input is unreadable/undecodable, no input
    events exist, the output path already exists, or a write fails.
    """
    if not isinstance(gateway_id, str) or not gateway_id:
        raise MtaEventError("input_error",
                            "gateway_id must be a non-empty string")
    if not os.path.isdir(input_dir):
        raise MtaEventError(
            "input_not_found",
            f"input directory {input_dir!r} does not exist or is not a "
            "directory")
    if os.path.lexists(output_dir):
        raise MtaEventError(
            "output_exists",
            f"output path {output_dir!r} already exists; refusing to "
            "overwrite it")
    parent = os.path.dirname(os.path.abspath(output_dir))
    if not os.path.isdir(parent):
        raise MtaEventError(
            "output_error",
            f"parent directory of {output_dir!r} does not exist")

    jsonl_files, skipped_files = _collect_jsonl_files(input_dir)
    if not jsonl_files:
        raise MtaEventError(
            "input_error",
            f"no .jsonl event files found below {input_dir!r}")

    source_lines: list[SourceLine] = []
    file_entries = []
    # digest -> LogicalEvent, merging identical events across rotation files
    logical: dict[str, LogicalEvent] = {}

    for rel in jsonl_files:
        path = os.path.join(input_dir, rel.replace("/", os.sep))
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except OSError as exc:
            raise MtaEventError(
                "input_error", f"cannot read input file {rel!r}: {exc}",
                {"file": rel}) from exc
        file_sha = hashlib.sha256(raw).hexdigest()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MtaEventError(
                "input_error", f"{rel}: file is not valid UTF-8: {exc}",
                {"file": rel, "file_sha256": file_sha}) from exc
        objects_in_file = 0
        for lineno, line_text in enumerate(text.splitlines(), 1):
            if not line_text.strip():
                continue
            objects_in_file += 1
            src = SourceLine(file=rel, line=lineno, file_sha256=file_sha)
            source_lines.append(src)
            try:
                obj = json.loads(line_text)
                normalized, ts_us = _parse_event(obj, f"{rel}:{lineno}")
            except json.JSONDecodeError as exc:
                src.error_category = CAT_INVALID_JSON
                src.error_detail = f"invalid JSON: {exc}"
                continue
            except _LineError as exc:
                src.error_category = exc.category
                src.error_detail = exc.detail
                continue
            digest = _sha256_text(canonical_json(normalized))
            src.digest = digest
            existing = logical.get(digest)
            if existing is None:
                logical[digest] = LogicalEvent(
                    digest=digest, event=normalized, ts_us=ts_us,
                    sources=[src])
            else:
                existing.sources.append(src)
        if objects_in_file == 0:
            raise MtaEventError(
                "input_error", f"{rel}: file contains no JSON objects",
                {"file": rel, "file_sha256": file_sha})
        file_entries.append({
            "type": "input_file", "file": rel, "file_sha256": file_sha,
            "lines": objects_in_file})

    outbound, quarantine, lifecycle_entries = _reconstruct(
        logical=logical, source_lines=source_lines, gateway_id=gateway_id)

    # stable, fully determined output orders
    outbound.sort(key=lambda r: (
        r["_host"], r["_queued_us"], r["queue_id"], r["delivery_id"],
        canonical_recipient(r["recipient"]), r["_sent_us"], r["_digest"]))
    quarantine.sort(key=lambda q: (
        q["kind"], q.get("category", ""), q.get("host", ""),
        q.get("queue_id", ""), q.get("timestamp", ""),
        json.dumps(q.get("sources", q.get("source", {})),
                   sort_keys=True, ensure_ascii=False)))

    outbound_rows = []
    for row in outbound:
        outbound_rows.append({
            "gateway_id": gateway_id,
            "delivery_id": row["delivery_id"],
            "attempt_id": row["attempt_id"],
            "recipient": row["recipient"],
            "queue_id": row["queue_id"],
            "envelope_id": row["envelope_id"],
            "sent_at": row["sent_at"],
        })
    outbound_text = "".join(_line(r) + "\n" for r in outbound_rows)
    quarantine_text = "".join(_line(q) + "\n" for q in quarantine)

    q_line_count = sum(1 for q in quarantine if q["kind"] == "event_line")
    orphan_count = sum(1 for q in quarantine if q["kind"] == "orphan_event")
    lifecycle_q_count = sum(1 for q in quarantine
                            if q["kind"] == "lifecycle")
    run_entry = {
        "type": "run",
        "format_version": _FORMAT_VERSION,
        "tool": _TOOL,
        "gateway_id": gateway_id,
        "input_dir": input_dir,
        "input_files": jsonl_files,
        "skipped_files": skipped_files,
        "source_lines": len(source_lines),
        "logical_events": len(logical),
        "lifecycles": len(lifecycle_entries),
        "emitted_lifecycles": sum(1 for e in lifecycle_entries
                                  if e["outcome"] == "emitted"),
        "quarantined_lifecycles": lifecycle_q_count,
        "records": len(outbound_rows),
        "quarantined_lines": q_line_count,
        "orphan_events": orphan_count,
        "outputs": {
            OUTBOUND_JSONL: {"sha256": _sha256_text(outbound_text),
                             "lines": len(outbound_rows)},
            QUARANTINE_JSONL: {"sha256": _sha256_text(quarantine_text),
                               "lines": len(quarantine)},
        },
    }
    manifest_text = _line(run_entry) + "\n"
    manifest_text += "".join(_line(e) + "\n" for e in file_entries)
    # line entries follow physical coordinates: (file, line)
    for src in sorted(source_lines, key=lambda s: (s.file, s.line)):
        manifest_text += _line(_line_manifest_entry(
            src, logical, lifecycle_entries)) + "\n"
    lifecycle_entries.sort(key=lambda e: (
        e["host"], e["queue_id"], e["queued_at"] or "",
        e.get("delivery_id") or "", "".join(e["event_digests"])))
    manifest_text += "".join(_line(e) + "\n" for e in lifecycle_entries)

    # Publish atomically: build in a controlled temp directory next to the
    # target, then rename it into place.
    temp_dir = "%s.tmp-%s" % (output_dir, uuid.uuid4().hex)
    try:
        os.mkdir(temp_dir)
        _write_file(temp_dir, OUTBOUND_JSONL, outbound_text)
        _write_file(temp_dir, QUARANTINE_JSONL, quarantine_text)
        _write_file(temp_dir, MANIFEST_JSONL, manifest_text)
        dir_fd = os.open(temp_dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        if os.path.lexists(output_dir):
            raise MtaEventError(
                "output_exists",
                f"output path {output_dir!r} already exists; refusing to "
                "overwrite it")
        os.rename(temp_dir, output_dir)
    except MtaEventError:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    except OSError as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise MtaEventError(
            "output_error",
            f"failed to write output directory {output_dir!r}: {exc}") from exc

    return {
        "input_dir": input_dir,
        "output_dir": output_dir,
        "gateway_id": gateway_id,
        "input_files": jsonl_files,
        "skipped_files": skipped_files,
        "source_lines": len(source_lines),
        "logical_events": len(logical),
        "lifecycles": len(lifecycle_entries),
        "emitted_lifecycles": run_entry["emitted_lifecycles"],
        "quarantined_lifecycles": lifecycle_q_count,
        "records": len(outbound_rows),
        "quarantined_lines": q_line_count,
        "orphan_events": orphan_count,
        "outputs": {name: os.path.join(output_dir, name)
                    for name in OUTPUT_NAMES},
    }


# --------------------------------------------------------------------------- #
# reconstruction: deduped logical events -> lifecycle segments
# --------------------------------------------------------------------------- #
def _event_order(ev: LogicalEvent):
    return (ev.ts_us, _KIND_RANK[ev.kind()], canonical_json(ev.event))


def _reconstruct(*, logical, source_lines, gateway_id):
    """Group events into lifecycle segments and emit/quarantine each one."""
    groups: dict[tuple[str, str], list[LogicalEvent]] = {}
    for ev in logical.values():
        groups.setdefault((ev.event["host"], ev.event["queue_id"]),
                          []).append(ev)

    outbound = []
    quarantine = []
    lifecycle_entries = []

    # line-level quarantine entries first; they participate in no lifecycle
    for src in source_lines:
        if src.error_category is not None:
            quarantine.append({
                "kind": "event_line",
                "category": src.error_category,
                "detail": src.error_detail,
                "source": src.coord(),
            })

    for (host, queue_id) in sorted(groups):
        events = sorted(groups[(host, queue_id)], key=_event_order)
        segments: list[Segment] = []
        current: Segment | None = None
        for ev in events:
            kind = ev.kind()
            if kind == QUEUED:
                if current is not None:
                    # The queue id was re-enqueued before the previous
                    # lifetime was removed: the boundary is unobservable, so
                    # the open lifetime is quarantined and a new one starts.
                    current.category = CAT_REQUEUED
                    current.detail = (
                        "a queued event reused this queue id before the "
                        "previous lifecycle was removed; lifecycle ownership "
                        "of its events cannot be decided")
                    current.closed = True
                    segments.append(current)
                current = Segment(host=host, queue_id=queue_id,
                                  events=[ev])
            elif current is None:
                quarantine.append(_orphan_entry(ev))
            else:
                current.events.append(ev)
                if kind == REMOVED:
                    current.closed = True
                    segments.append(current)
                    current = None
        if current is not None:
            # No removed event within the covered time window (a rotation
            # file may end mid-lifecycle); the segment stays open but its
            # boundaries are still complete enough to book its deliveries.
            segments.append(current)

        for segment in segments:
            entry = _finalize_segment(
                segment, gateway_id=gateway_id, outbound=outbound,
                quarantine=quarantine)
            lifecycle_entries.append(entry)

    return outbound, quarantine, lifecycle_entries


def _orphan_entry(ev: LogicalEvent):
    return {
        "kind": "orphan_event",
        "category": CAT_ORPHAN,
        "event": ev.kind(),
        "host": ev.event["host"],
        "queue_id": ev.event["queue_id"],
        "timestamp": ev.event["timestamp"],
        "event_digest": ev.digest,
        "sources": ev.source_coords(),
    }


def _delivery_id(segment: Segment):
    """Content-derived stable id for one lifecycle.

    The material is the lifecycle coordinates plus the complete sorted set of
    canonical event digests, so it is independent of file/line order and of
    rotation boundaries, and two reused-queue lifetimes (even with the same
    Message-ID) get different ids.
    """
    queued = segment.queued()
    material = [
        "receipt-ledger-mta-lifecycle-v1",
        segment.host,
        segment.queue_id,
        queued.event["timestamp"] if queued else None,
        sorted(ev.digest for ev in segment.events),
    ]
    return "dlv-" + _sha256_text(canonical_json(material))[:16]


def _finalize_segment(segment: Segment, *, gateway_id, outbound, quarantine):
    """Validate one segment; either emit its attempts or quarantine it whole."""
    queued = segment.queued()
    removed = segment.removed()
    deliveries = segment.deliveries()
    base_entry = {
        "type": "lifecycle",
        "host": segment.host,
        "queue_id": segment.queue_id,
        "queued_at": queued.event["timestamp"] if queued else None,
        "removed_at": removed.event["timestamp"] if removed else None,
        "closed": segment.closed,
        "event_digests": sorted(ev.digest for ev in segment.events),
        "sources": sorted(
            (coord for ev in segment.events for coord in ev.source_coords()),
            key=lambda c: (c["file"], c["line"])),
    }

    def quarantine_segment(category, detail):
        quarantine.append({
            "kind": "lifecycle",
            "category": category,
            "detail": detail,
            "host": segment.host,
            "queue_id": segment.queue_id,
            "timestamp": base_entry["queued_at"],
            "event_count": len(segment.events),
            "event_digests": base_entry["event_digests"],
            "sources": base_entry["sources"],
        })
        return {**base_entry, "outcome": "quarantined",
                "category": category, "detail": detail,
                "delivery_id": None, "attempts": []}

    if segment.category is not None:
        return quarantine_segment(segment.category, segment.detail)
    if queued is None:
        # Defensive: events without a queued are normally reported as
        # orphans during segmentation.
        return quarantine_segment(
            CAT_ORPHAN, "lifecycle has no queued event")

    # Validate delivery events: same recipient + same timestamp is either a
    # content contradiction (different result) or an unorderable retry pair.
    # Different recipients at one timestamp are parallel SMTP deliveries and
    # stay independent.
    per_recipient: dict[str, list[LogicalEvent]] = {}
    for ev in deliveries:
        per_recipient.setdefault(ev.event["recipient"], []).append(ev)
    for recipient in sorted(per_recipient):
        events = per_recipient[recipient]
        by_ts: dict[int, list[LogicalEvent]] = {}
        for ev in events:
            by_ts.setdefault(ev.ts_us, []).append(ev)
        for ts_us in sorted(by_ts):
            tied = by_ts[ts_us]
            if len(tied) < 2:
                continue
            results = {e.event["result"] for e in tied}
            detail = (
                f"recipient {recipient!r} has {len(tied)} distinct delivery "
                f"events at {tied[0].event['timestamp']!r}; retry order "
                "cannot be decided without input line numbers")
            if len(results) > 1:
                return quarantine_segment(CAT_CONTENT_CONFLICT, detail +
                                          " and their results contradict")
            return quarantine_segment(CAT_AMBIGUOUS_ORDER, detail)

    delivery_id = _delivery_id(segment)
    attempts = []
    for recipient in sorted(per_recipient,
                            key=lambda r: canonical_recipient(r)):
        ordered = sorted(per_recipient[recipient],
                         key=lambda e: (e.ts_us, e.digest))
        for ordinal, ev in enumerate(ordered, 1):
            attempt_id = f"att-{ordinal}"
            outbound.append({
                "delivery_id": delivery_id,
                "attempt_id": attempt_id,
                "recipient": recipient,
                "queue_id": segment.queue_id,
                "envelope_id": queued.event["message_id"],
                "sent_at": ev.event["timestamp"],
                "_host": segment.host,
                "_queued_us": queued.ts_us,
                "_sent_us": ev.ts_us,
                "_digest": ev.digest,
            })
            attempts.append({
                "recipient": recipient,
                "attempt_id": attempt_id,
                "sent_at": ev.event["timestamp"],
                "result": ev.event["result"],
                "event_digest": ev.digest,
            })
    attempts.sort(key=lambda a: (canonical_recipient(a["recipient"]),
                                 a["attempt_id"]))
    return {**base_entry, "outcome": "emitted", "category": None,
            "detail": None, "delivery_id": delivery_id, "attempts": attempts}


def _line_manifest_entry(src: SourceLine, logical, lifecycle_entries):
    """One manifest row per physical source line, with its full disposition."""
    entry = {"type": "event_line", **src.coord()}
    if src.error_category is not None:
        entry.update({"status": "quarantined_line",
                      "category": src.error_category,
                      "detail": src.error_detail,
                      "event_digest": None, "outbound": None,
                      "duplicate_of": None})
        return entry
    ev = logical[src.digest]
    first = min(ev.sources, key=lambda s: (s.file, s.line))
    is_duplicate = not (first.file == src.file and first.line == src.line)
    entry["event_digest"] = src.digest
    entry["duplicate_of"] = first.coord() if is_duplicate else None

    owning = next((e for e in lifecycle_entries
                   if src.digest in e["event_digests"]), None)
    if owning is None:
        entry.update({"status": "orphan", "outbound": None})
        return entry
    if owning["outcome"] == "quarantined":
        entry.update({"status": "lifecycle_quarantined",
                      "category": owning["category"], "outbound": None})
        return entry
    emitted = next((a for a in owning["attempts"]
                    if a["event_digest"] == src.digest), None)
    if emitted is None:
        # queued/removed events of an emitted lifecycle carry no attempt row
        entry.update({"status": "lifecycle_event", "outbound": None})
    else:
        entry.update({"status": "duplicate" if is_duplicate else "emitted",
                      "outbound": {
                          "delivery_id": owning["delivery_id"],
                          "attempt_id": emitted["attempt_id"],
                          "recipient": emitted["recipient"]}})
    return entry
