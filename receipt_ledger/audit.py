"""Read-only reconciliation of one archive batch against the ledger.

``audit_archive_import(LEDGER, ARCHIVE_OUTPUT_DIR)`` answers a narrower and
more honest question than an import command's exit status:

    For every valid receipt the archive batch produced, is that exact business
    fact (gateway/report/item identity **and** full canonical content) present
    in the ledger, and where did the ledger fact come from?

It never re-parses mail, never recomputes delivery state and never writes.
The original ``.eml`` files may be archived offline; the manifest is used for
provenance coordinates and content digests, not as proof that the raw bytes
can be read again.

Package validation (all of it before the ledger is touched)
------------------------------------------------------------
* exactly one ``run`` entry, first in ``manifest.jsonl``, with a supported
  format version and tallies consistent with the rest of the manifest and the
  product files;
* the run entry's SHA-256 and line count for ``dsn.jsonl`` and
  ``quarantine.jsonl`` match the bytes on disk;
* every manifest ``record`` index is unique, contiguous and points at the same
  line of ``dsn.jsonl``; the line's gateway/report/item identity equals the
  message's content-derived ``report_id`` (= ``"rpt-" + file_sha256``), its
  block's ``item_id`` and the record entry's own coordinates;
* a record's message is a successfully parsed message, its ``file_sha256`` and
  ``parse_digest`` agree with that message, and its block outcome is a record;
* every quarantine entry maps back to exactly one block of one message (or to
  one report-level failed message); failed messages yield no successful
  records and successful messages never hide a quarantine;
* duplicate identical records (the same message bytes exported from two files)
  are allowed; duplicate identities with *different* content are not.

Anything misaligned, duplicated, missing or digest-mismatched makes the input
package invalid; no per-record ledger verdict is attempted and the report can
never claim ``verified``.

Ledger check (one read view)
----------------------------
The ledger is opened read-only and copied with SQLite's online backup inside
one read transaction into a private temporary snapshot.  Concurrent importers
may keep committing; the snapshot is a single complete instant, so facts and
import-file rows can never be mixed across two commits.  The live read-only
connection's ``PRAGMA data_version`` is sampled before and after the audit; a
commit that landed while auditing is reported explicitly, never mixed into the
per-record verdicts.

For each valid receipt the audit looks up the exact
``(gateway, report, item)`` identity in ``dsn_line`` and compares the complete
canonical content (recipient, action, occurrence time, queue/envelope), not
just the presence of a row.  Results distinguish:

``imported_by_this_batch``
    The fact exists with identical content and its ``import_file`` row is the
    one carrying this ``dsn.jsonl`` digest.
``deduplicated_existing``
    The fact exists with identical content but was provided earlier by a
    different import file (the ledger kept the original provenance).  This is
    correct and is *not* reported as missing.
``present_but_file_not_imported``
    The fact exists, but no ``import_file`` row for this batch's digest exists:
    the batch file itself has not been imported.
``missing``
    No fact exists for this identity.
``conflict``
    The identity exists with different content, or is used by a correction.
    This is exactly the case the ledger refuses to import.

Quarantine entries are not receipts that should have been imported: they are
listed with their provenance and marked as not expected in the ledger.  Even
if a row with the same identity happens to exist, the quarantined block is
never described as imported; the coincidence is reported separately.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile

from . import ingest
from .engine import Ledger
from .schema import check_schema

__all__ = ["AuditError", "audit_archive_import"]

DSN_JSONL = "dsn.jsonl"
QUARANTINE_JSONL = "quarantine.jsonl"
MANIFEST_JSONL = "manifest.jsonl"
OUTPUT_NAMES = (DSN_JSONL, QUARANTINE_JSONL, MANIFEST_JSONL)

IMPORTED = "imported_by_this_batch"
DEDUPLICATED = "deduplicated_existing"
PRESENT_UNIMPORTED = "present_but_file_not_imported"
MISSING = "missing"
CONFLICT = "conflict"

_CLEAN_RECORD_STATUSES = (IMPORTED, DEDUPLICATED)

OUTCOME_EXIT = {
    "verified": 0,
    "incomplete": 1,
    "invalid_package": 2,
    "concurrent_change": 3,
    "conflict": 4,
}

# Test seam (default None, set only by the acceptance suite): called after the
# ledger snapshot has been taken and before it is inspected.
_after_snapshot_hook = None


class AuditError(Exception):
    """The archive directory or the ledger could not be read at all.

    A structurally invalid archive does **not** raise: it produces a report
    with ``outcome == "invalid_package"``.  This exception is for paths that
    are missing, unreadable or not a ledger, where there is nothing coherent
    to report.
    """

    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def to_dict(self):
        return {"code": self.code, "message": self.message,
                "details": self.details}


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


def _text(value):
    return isinstance(value, str) and value != ""


def _int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _problem(code, message, **details):
    entry = {"code": code, "message": message}
    entry.update(details)
    return entry


def _decode_jsonl(raw, name, problems):
    """Decode one product file into ``(entries, physical_line_count)``.

    ``entries`` is ``[(line_number, object)]``.  The batch writer terminates
    every line with ``\\n`` and writes exactly one object per line; a missing
    final newline, a blank interior line or invalid UTF-8/JSON is a defect.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        problems.append(_problem(
            "not_utf8", f"{name} is not valid UTF-8: {exc}", file=name))
        return [], 0
    if text == "":
        return [], 0
    if not text.endswith("\n"):
        problems.append(_problem(
            "unterminated_file", f"{name} does not end with a newline",
            file=name))
        return [], 0
    lines = text[:-1].split("\n")
    entries = []
    for lineno, line in enumerate(lines, 1):
        if not line.strip():
            problems.append(_problem(
                "blank_line", f"{name}:{lineno} is blank", file=name,
                line=lineno))
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            problems.append(_problem(
                "invalid_json", f"{name}:{lineno}: {exc}", file=name,
                line=lineno))
            continue
        if not isinstance(obj, dict):
            problems.append(_problem(
                "not_an_object", f"{name}:{lineno} is not a JSON object",
                file=name, line=lineno))
            continue
        entries.append((lineno, obj))
    return entries, len(lines)


def _file_row(row):
    if row is None:
        return None
    return {"id": row[0], "sha256": row[1], "kind": row[2],
            "source_name": row[3], "line_count": row[4]}


# --------------------------------------------------------------------------- #
# package model and validation
# --------------------------------------------------------------------------- #
class _Package:
    def __init__(self):
        self.problems = []
        self._seen_problems = set()
        self.run = {}
        self.gateway_id = None
        self.messages = {}            # message_index -> manifest message entry
        self.record_entries = []      # manifest record entries in order
        self.records = []             # bound records, by record_index
        self.copies = {}              # (report,item) -> [record_index, ...]
        self.quarantine = []          # canonical quarantine report entries
        self.dsn_lines = []           # parsed receipt objects, by line index
        self.dsn_sha256 = None
        self.quarantine_sha256 = None
        self.manifest_sha256 = None
        self.dsn_physical_lines = 0
        self.quarantine_physical_lines = 0
        self.declared = {}

    @property
    def valid(self):
        return not self.problems


def _add(pkg, code, message, **details):
    """Add a package problem once per (code, coordinates)."""
    key = (code, tuple(sorted((k, repr(v)) for k, v in details.items())))
    if key in pkg._seen_problems:
        return
    pkg._seen_problems.add(key)
    pkg.problems.append(_problem(code, message, **details))


# -- manifest messages ------------------------------------------------------ #
def _validate_messages(pkg, entries):
    seen_files = set()
    for lineno, obj in entries:
        if obj.get("type") != "message":
            continue
        where = f"manifest:{lineno}"
        index = obj.get("message_index")
        if not _int(index) or index < 0:
            _add(pkg, "bad_message_index",
                 f"{where}: message_index must be a non-negative integer",
                 manifest_line=lineno)
            continue
        if index in pkg.messages:
            _add(pkg, "duplicate_message_index",
                 f"message_index {index} appears more than once",
                 message_index=index)
            continue
        file = obj.get("file")
        sha = obj.get("file_sha256")
        status = obj.get("status")
        if not _text(file):
            _add(pkg, "bad_message_file",
                 f"{where}: file must be a non-empty string",
                 message_index=index)
        elif file in seen_files:
            _add(pkg, "duplicate_message_file",
                 f"file {file!r} appears in more than one message entry",
                 message_index=index, file=file)
        else:
            seen_files.add(file)
        if not _hex64(sha):
            _add(pkg, "bad_file_sha256",
                 f"{where}: file_sha256 must be 64 lowercase hex characters",
                 message_index=index, file=file)
        if status not in ("parsed", "failed"):
            _add(pkg, "bad_message_status",
                 f"{where}: status must be 'parsed' or 'failed'",
                 message_index=index, file=file)
        if status == "parsed":
            _validate_parsed_message(pkg, obj, index, where)
        elif status == "failed":
            if not _text(obj.get("category")) or not _text(obj.get("detail")):
                _add(pkg, "bad_failed_message",
                     f"{where}: a failed message needs category and detail",
                     message_index=index, file=file)
            for forbidden in ("report_id", "parse_digest", "blocks"):
                if forbidden in obj:
                    _add(pkg, "failed_message_has_parse_data",
                         f"{where}: a failed message must not carry "
                         f"{forbidden!r}", message_index=index, file=file)
        pkg.messages[index] = obj

    indexes = sorted(pkg.messages)
    if indexes != list(range(len(indexes))):
        _add(pkg, "non_contiguous_message_indexes",
             "manifest message indexes must be 0..N-1", found=indexes)
    files = [pkg.messages[i].get("file") for i in indexes]
    if all(isinstance(name, str) for name in files) \
            and files != sorted(files):
        _add(pkg, "message_order_mismatch",
             "manifest messages must be listed in sorted relative-path order",
             files=files)


def _validate_parsed_message(pkg, obj, index, where):
    report_id = obj.get("report_id")
    digest = obj.get("parse_digest")
    sha = obj.get("file_sha256")
    obj["_blocks_valid"] = False
    if not _text(report_id) or not report_id.startswith("rpt-"):
        _add(pkg, "bad_report_id",
             f"{where}: report_id must be a content-derived 'rpt-…' string",
             message_index=index)
    elif _hex64(sha) and report_id != "rpt-" + sha:
        _add(pkg, "report_id_not_file_digest",
             f"{where}: report_id is not derived from the declared file "
             "SHA-256", message_index=index, file_sha256=sha,
             report_id=report_id)
    if not _hex64(digest):
        _add(pkg, "bad_parse_digest",
             f"{where}: parse_digest must be 64 lowercase hex characters",
             message_index=index)
    if not isinstance(obj.get("context"), dict):
        _add(pkg, "bad_message_context",
             f"{where}: context must be a JSON object", message_index=index)
    blocks = obj.get("blocks")
    if not isinstance(blocks, list):
        _add(pkg, "bad_message_blocks",
             f"{where}: blocks must be an array", message_index=index)
        return
    obj["_blocks_valid"] = True
    indexes = []
    for pos, block in enumerate(blocks):
        bwhere = f"{where}: block {pos}"
        if not isinstance(block, dict):
            _add(pkg, "bad_block_entry",
                 f"{bwhere} is not a JSON object", message_index=index)
            obj["_blocks_valid"] = False
            continue
        block_index = block.get("block_index")
        if not _int(block_index) or block_index < 0:
            _add(pkg, "bad_block_index",
                 f"{bwhere}: block_index must be a non-negative integer",
                 message_index=index)
            obj["_blocks_valid"] = False
            continue
        indexes.append(block_index)
        outcome = block.get("outcome")
        if outcome == "record":
            record_index = block.get("record_index")
            if not _int(record_index) or record_index < 0:
                _add(pkg, "bad_block_record_index",
                     f"{bwhere}: record_index must be a non-negative integer",
                     message_index=index, block_index=block_index)
                obj["_blocks_valid"] = False
            item_id = block.get("item_id")
            if not _text(item_id):
                _add(pkg, "bad_block_item_id",
                     f"{bwhere}: item_id must be a non-empty string",
                     message_index=index, block_index=block_index)
                obj["_blocks_valid"] = False
            elif item_id != f"item-{block_index}":
                _add(pkg, "block_item_id_mismatch",
                     f"{bwhere}: item_id must identify its own block",
                     message_index=index, block_index=block_index,
                     item_id=item_id)
                obj["_blocks_valid"] = False
        elif outcome == "quarantine":
            if not _text(block.get("category")) \
                    or not _text(block.get("detail")):
                _add(pkg, "bad_block_quarantine",
                     f"{bwhere}: a quarantined block needs category and "
                     "detail", message_index=index,
                     block_index=block_index)
                obj["_blocks_valid"] = False
            if "record_index" in block:
                _add(pkg, "quarantined_block_has_record",
                     f"{bwhere}: a quarantined block must not point at a "
                     "record", message_index=index, block_index=block_index)
                obj["_blocks_valid"] = False
        else:
            _add(pkg, "bad_block_outcome",
                 f"{bwhere}: outcome must be 'record' or 'quarantine'",
                 message_index=index, block_index=block_index)
            obj["_blocks_valid"] = False
    if indexes != list(range(len(indexes))):
        _add(pkg, "non_contiguous_block_indexes",
             "block indexes of one message must be 0..N-1 in order",
             message_index=index, found=indexes)
        obj["_blocks_valid"] = False


# -- manifest records ------------------------------------------------------- #
def _validate_records(pkg, entries, dsn_entries):
    next_index = 0
    current_message = None
    for lineno, obj in entries:
        kind = obj.get("type")
        if kind == "message":
            current_message = obj.get("message_index")
            continue
        if kind != "record":
            continue
        where = f"manifest:{lineno}"
        record_index = obj.get("record_index")
        if not _int(record_index) or record_index < 0:
            _add(pkg, "bad_record_index",
                 f"{where}: record_index must be a non-negative integer",
                 manifest_line=lineno)
            continue
        if record_index != next_index:
            _add(pkg, "record_index_out_of_order",
                 "manifest record entries must be listed once each, in "
                 "record_index order 0..N-1", manifest_line=lineno,
                 expected=next_index, found=record_index)
        next_index = record_index + 1

        index = obj.get("message_index")
        message = pkg.messages.get(index) if _int(index) else None
        if message is None:
            _add(pkg, "record_unknown_message",
                 f"{where}: message_index does not name a message entry",
                 record_index=record_index, message_index=index)
        if current_message != index:
            _add(pkg, "record_outside_its_message",
                 f"{where}: record entry is not inside the section of the "
                 "message it names", record_index=record_index,
                 message_index=index)
        if message is not None and message.get("status") != "parsed":
            _add(pkg, "record_from_failed_message",
                 f"{where}: a failed message must not produce records",
                 record_index=record_index, message_index=index)
        elif message is not None:
            if obj.get("file") != message.get("file"):
                _add(pkg, "record_file_mismatch",
                     f"{where}: file does not match its message entry",
                     record_index=record_index, message_index=index)
            if obj.get("file_sha256") != message.get("file_sha256"):
                _add(pkg, "record_file_digest_mismatch",
                     f"{where}: file_sha256 does not match its message entry",
                     record_index=record_index, message_index=index)
            if obj.get("report_id") != message.get("report_id"):
                _add(pkg, "record_report_id_mismatch",
                     f"{where}: report_id does not match its message entry",
                     record_index=record_index, message_index=index)
            if obj.get("parse_digest") != message.get("parse_digest"):
                _add(pkg, "record_parse_digest_mismatch",
                     f"{where}: parse_digest does not match its message entry",
                     record_index=record_index, message_index=index)
            block = None
            block_index = obj.get("block_index")
            if message.get("_blocks_valid"):
                matches = [b for b in message["blocks"]
                           if b.get("block_index") == block_index]
                block = matches[0] if len(matches) == 1 else None
            if block is None:
                _add(pkg, "record_unknown_block",
                     f"{where}: block_index does not name a block of its "
                     "message", record_index=record_index,
                     message_index=index, block_index=block_index)
            else:
                if block.get("outcome") != "record":
                    _add(pkg, "record_points_at_quarantine",
                         f"{where}: block outcome is not 'record'",
                         record_index=record_index, message_index=index,
                         block_index=block_index)
                if block.get("record_index") != record_index:
                    _add(pkg, "record_block_index_mismatch",
                         f"{where}: its message block points at a different "
                         "record_index", record_index=record_index,
                         message_index=index, block_index=block_index)
                if block.get("item_id") != obj.get("item_id"):
                    _add(pkg, "record_item_id_mismatch",
                         f"{where}: item_id does not match its block entry",
                         record_index=record_index, message_index=index)
                if obj.get("item_id") != f"item-{block_index}":
                    _add(pkg, "record_item_does_not_name_block",
                         f"{where}: item_id does not identify block_index",
                         record_index=record_index, message_index=index,
                         block_index=block_index)
        pkg.record_entries.append(obj)

    if len(pkg.record_entries) != len(dsn_entries):
        _add(pkg, "record_count_mismatch",
             "the manifest must carry exactly one record entry per dsn.jsonl "
             "line", manifest_records=len(pkg.record_entries),
             dsn_lines=len(dsn_entries))

    by_index = {}
    for obj in pkg.record_entries:
        index = obj.get("record_index")
        if not _int(index):
            continue
        if index in by_index:
            _add(pkg, "duplicate_record_index",
                 f"record_index {index} appears more than once",
                 record_index=index)
            continue
        by_index[index] = obj
    if sorted(by_index) != list(range(len(dsn_entries))):
        _add(pkg, "record_indexes_do_not_cover_dsn",
             "record indexes must be exactly 0..N-1 of dsn.jsonl",
             manifest_indexes=sorted(by_index), dsn_lines=len(dsn_entries))

    # every message block that claims a record must be the record's block
    for index in sorted(pkg.messages):
        message = pkg.messages[index]
        if not message.get("_blocks_valid"):
            continue
        for block in message["blocks"]:
            if block.get("outcome") != "record":
                continue
            entry = by_index.get(block.get("record_index"))
            if entry is None:
                _add(pkg, "block_points_at_unknown_record",
                     "a message block points at a record entry that does not "
                     "exist", message_index=index,
                     block_index=block.get("block_index"),
                     record_index=block.get("record_index"))
                continue
            if entry.get("message_index") != index \
                    or entry.get("block_index") != block.get("block_index") \
                    or entry.get("item_id") != block.get("item_id"):
                _add(pkg, "block_record_binding_mismatch",
                     "a message block and its record entry name different "
                     "sources", message_index=index,
                     block_index=block.get("block_index"),
                     record_index=block.get("record_index"))
            # a block must be claimed by exactly one record entry
        claimed = [block.get("record_index") for block in message["blocks"]
                   if block.get("outcome") == "record"]
        if len(claimed) != len(set(claimed)):
            _add(pkg, "duplicate_block_record_binding",
                 "two blocks of one message claim the same record",
                 message_index=index)

    for position, (lineno, raw) in enumerate(dsn_entries):
        entry = by_index.get(position)
        try:
            parsed = ingest.parse_dsn(raw, f"{DSN_JSONL}:{lineno}")
        except Exception as exc:  # InputFormatError
            _add(pkg, "invalid_dsn_record",
                 f"{DSN_JSONL}:{lineno}: {exc}", line=lineno,
                 record_index=position)
            parsed = None
        if parsed is not None and pkg.gateway_id is not None \
                and parsed["gateway_id"] != pkg.gateway_id:
            _add(pkg, "dsn_gateway_mismatch",
                 f"{DSN_JSONL}:{lineno}: gateway_id does not match the run",
                 line=lineno, record_index=position,
                 expected=pkg.gateway_id, found=parsed["gateway_id"])
        pkg.dsn_lines.append(parsed)
        if entry is None or parsed is None:
            continue
        if parsed["report_id"] != entry.get("report_id"):
            _add(pkg, "dsn_report_id_mismatch",
                 f"{DSN_JSONL}:{lineno}: report_id does not match its record "
                 "entry", line=lineno, record_index=position)
        if parsed["item_id"] != entry.get("item_id"):
            _add(pkg, "dsn_item_id_mismatch",
                 f"{DSN_JSONL}:{lineno}: item_id does not match its record "
                 "entry", line=lineno, record_index=position)
        message = pkg.messages.get(entry.get("message_index"))
        if message is not None \
                and parsed["report_id"] != message.get("report_id"):
            _add(pkg, "dsn_report_id_not_message",
                 f"{DSN_JSONL}:{lineno}: report_id is not the message's "
                 "content-derived report_id", line=lineno,
                 record_index=position)
        pkg.records.append({
            "record_index": position,
            "identity": {
                "gateway_id": parsed["gateway_id"],
                "report_id": parsed["report_id"],
                "item_id": parsed["item_id"],
            },
            "parsed": parsed,
            "canonical_hash": Ledger._dsn_hash(parsed["gateway_id"], parsed),
            "entry": entry,
            "source": {
                "file": entry.get("file"),
                "file_sha256": entry.get("file_sha256"),
                "message_index": entry.get("message_index"),
                "block_index": entry.get("block_index"),
                "parse_digest": entry.get("parse_digest"),
            },
        })
    _check_duplicate_identities(pkg)
    _verify_parse_digests(pkg)


def _verify_parse_digests(pkg):
    """Recompute every message's ``parse_digest`` from dsn.jsonl + manifest.

    ``convert-archive`` hashes the canonical material
    ``{gateway_id, context, blocks}`` where each record block embeds the
    emitted record.  Rebuilding that material from the package and hashing it
    here ties the declared digest to the records actually present.
    """
    by_record = {record["record_index"]: record for record in pkg.records}
    if pkg.gateway_id is None:
        return
    for index in sorted(pkg.messages):
        message = pkg.messages[index]
        if message.get("status") != "parsed" or not message.get("_blocks_valid"):
            continue
        if not _hex64(message.get("parse_digest")):
            continue
        material = {"gateway_id": pkg.gateway_id,
                    "context": message.get("context"), "blocks": []}
        complete = True
        for block in message["blocks"]:
            if block.get("outcome") == "record":
                record = by_record.get(block.get("record_index"))
                if record is None or record.get("parsed") is None:
                    complete = False
                    break
                material["blocks"].append({
                    "block_index": block["block_index"],
                    "outcome": "record",
                    "record": _public_record(record["parsed"]),
                })
            else:
                material["blocks"].append({
                    "block_index": block.get("block_index"),
                    "outcome": "quarantine",
                    "category": block.get("category"),
                    "detail": block.get("detail"),
                })
        if not complete:
            continue
        digest = _sha256(json.dumps(
            material, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8"))
        if digest != message["parse_digest"]:
            _add(pkg, "parse_digest_mismatch",
                 "a message's declared parse_digest does not match the "
                 "canonical material rebuilt from its manifest entry and "
                 "dsn.jsonl records", message_index=index,
                 declared=message["parse_digest"], recomputed=digest)


def _check_duplicate_identities(pkg):
    seen = {}
    for record in pkg.records:
        key = (record["identity"]["gateway_id"],
               record["identity"]["report_id"],
               record["identity"]["item_id"])
        previous = seen.get(key)
        if previous is None:
            seen[key] = record
            continue
        if previous["canonical_hash"] != record["canonical_hash"]:
            _add(pkg, "conflicting_duplicate_identity",
                 "the same business identity appears twice with different "
                 "content", report_id=key[1], item_id=key[2],
                 record_indexes=[previous["record_index"],
                                 record["record_index"]])
    for record in pkg.records:
        key = (record["identity"]["report_id"],
               record["identity"]["item_id"])
        pkg.copies.setdefault(key, []).append(record["record_index"])


# -- quarantine ------------------------------------------------------------- #
def _validate_quarantine(pkg, entries):
    by_block = {}
    by_message = {}
    for lineno, obj in entries:
        where = f"{QUARANTINE_JSONL}:{lineno}"
        index = obj.get("message_index")
        message = pkg.messages.get(index) if _int(index) else None
        if message is None:
            _add(pkg, "quarantine_unknown_message",
                 f"{where}: message_index does not name a message entry",
                 line=lineno, message_index=index)
            continue
        if obj.get("file") != message.get("file") \
                or obj.get("file_sha256") != message.get("file_sha256"):
            _add(pkg, "quarantine_source_mismatch",
                 f"{where}: file/file_sha256 do not match the message entry",
                 line=lineno, message_index=index)
        if "block_index" not in obj:
            _add(pkg, "quarantine_missing_block_index",
                 f"{where}: block_index must be present (null for a failed "
                 "message)", line=lineno, message_index=index)
            continue
        block_index = obj.get("block_index")
        if block_index is None:
            key = ("message", index)
            if key in by_message:
                _add(pkg, "duplicate_quarantine_entry",
                     f"{where}: the failed message is quarantined twice",
                     message_index=index)
                continue
            by_message[key] = obj
            if message.get("status") != "failed":
                _add(pkg, "quarantine_message_not_failed",
                     f"{where}: a null block_index belongs to a report-level "
                     "failed message", line=lineno, message_index=index)
            elif obj.get("category") != message.get("category") \
                    or obj.get("detail") != message.get("detail"):
                _add(pkg, "quarantine_category_mismatch",
                     f"{where}: category/detail do not match the failed "
                     "message entry", line=lineno, message_index=index)
            pkg.quarantine.append({
                "kind": "message",
                "source": {"file": message.get("file"),
                           "file_sha256": message.get("file_sha256"),
                           "message_index": index, "block_index": None},
                "category": obj.get("category"), "detail": obj.get("detail"),
                "report_id": None, "item_id": None,
            })
            continue
        if not _int(block_index) or block_index < 0:
            _add(pkg, "bad_quarantine_block_index",
                 f"{where}: block_index must be a non-negative integer",
                 line=lineno, message_index=index)
            continue
        key = (index, block_index)
        if key in by_block:
            _add(pkg, "duplicate_quarantine_entry",
                 f"{where}: this block is quarantined twice",
                 message_index=index, block_index=block_index)
            continue
        by_block[key] = obj
        block = None
        if message.get("_blocks_valid"):
            matches = [b for b in message["blocks"]
                       if b.get("block_index") == block_index]
            block = matches[0] if len(matches) == 1 else None
        if block is None:
            _add(pkg, "quarantine_unknown_block",
                 f"{where}: block_index does not name a block of its message",
                 message_index=index, block_index=block_index)
        elif block.get("outcome") != "quarantine":
            _add(pkg, "quarantine_points_at_record",
                 f"{where}: block outcome is not 'quarantine'",
                 message_index=index, block_index=block_index)
        elif obj.get("category") != block.get("category") \
                or obj.get("detail") != block.get("detail"):
            _add(pkg, "quarantine_category_mismatch",
                 f"{where}: category/detail do not match the message block",
                 message_index=index, block_index=block_index)
        pkg.quarantine.append({
            "kind": "block",
            "source": {"file": message.get("file"),
                       "file_sha256": message.get("file_sha256"),
                       "message_index": index,
                       "block_index": block_index},
            "category": obj.get("category"), "detail": obj.get("detail"),
            "report_id": message.get("report_id"),
            "item_id": f"item-{block_index}",
        })

    # completeness: every quarantined block/message, and nothing invented
    for index in sorted(pkg.messages):
        message = pkg.messages[index]
        if message.get("status") == "failed":
            if ("message", index) not in by_message:
                _add(pkg, "missing_quarantine_entry",
                     "a failed message has no quarantine entry",
                     message_index=index)
            continue
        if not message.get("_blocks_valid"):
            continue
        for block in message["blocks"]:
            if block.get("outcome") == "quarantine" \
                    and (index, block.get("block_index")) not in by_block:
                _add(pkg, "missing_quarantine_entry",
                     "a quarantined block has no quarantine entry",
                     message_index=index,
                     block_index=block.get("block_index"))

    pkg.quarantine.sort(key=lambda entry: (
        entry["source"]["message_index"],
        -1 if entry["source"]["block_index"] is None
        else entry["source"]["block_index"]))


# -- run entry and product digests ----------------------------------------- #
def _validate_run(pkg):
    run = pkg.run
    if not run:
        return
    if run.get("format_version") != 1:
        _add(pkg, "unsupported_format_version",
             "only archive manifest format_version 1 is supported",
             format_version=run.get("format_version"))

    messages = len(pkg.messages)
    for key in ("messages", "eml_files"):
        if run.get(key) != messages:
            _add(pkg, "run_tally_mismatch",
                 f"run {key} tally does not match the manifest",
                 tally=key, declared=run.get(key), actual=messages)
    if run.get("records") != len(pkg.dsn_lines):
        _add(pkg, "run_tally_mismatch",
             "run records tally does not match dsn.jsonl",
             tally="records", declared=run.get("records"),
             actual=len(pkg.dsn_lines))
    manifest_quarantined = sum(
        1 for message in pkg.messages.values()
        for block in message.get("blocks") or []
        if isinstance(block, dict) and block.get("outcome") == "quarantine")
    if run.get("quarantined_blocks") != manifest_quarantined:
        _add(pkg, "run_tally_mismatch",
             "run quarantined_blocks tally does not match the manifest",
             tally="quarantined_blocks",
             declared=run.get("quarantined_blocks"),
             actual=manifest_quarantined)
    failed_messages = sum(1 for message in pkg.messages.values()
                          if message.get("status") == "failed")
    if run.get("failed_messages") != failed_messages:
        _add(pkg, "run_tally_mismatch",
             "run failed_messages tally does not match the manifest",
             tally="failed_messages", declared=run.get("failed_messages"),
             actual=failed_messages)

    outputs = run.get("outputs")
    if not isinstance(outputs, dict):
        _add(pkg, "missing_output_declarations",
             "the run entry must declare the dsn/quarantine output digests")
        return
    for name, actual_sha, actual_lines in (
            (DSN_JSONL, pkg.dsn_sha256, pkg.dsn_physical_lines),
            (QUARANTINE_JSONL, pkg.quarantine_sha256,
             pkg.quarantine_physical_lines)):
        declared = outputs.get(name)
        if not isinstance(declared, dict):
            _add(pkg, "missing_output_digest",
                 f"run.outputs has no entry for {name}", file=name)
            continue
        pkg.declared[name] = declared
        if declared.get("sha256") != actual_sha:
            _add(pkg, "output_digest_mismatch",
                 f"{name} does not match the digest declared by the run entry",
                 file=name, declared=declared.get("sha256"),
                 actual=actual_sha)
        if declared.get("lines") != actual_lines:
            _add(pkg, "output_line_count_mismatch",
                 f"{name} does not match the line count declared by the run "
                 "entry", file=name, declared=declared.get("lines"),
                 actual=actual_lines)


# -- top-level package validation ------------------------------------------ #
def _validate_package(output_dir):
    pkg = _Package()
    if not os.path.isdir(output_dir):
        raise AuditError(
            "archive_not_found",
            f"archive output directory {output_dir!r} does not exist")
    raws = {}
    for name in OUTPUT_NAMES:
        path = os.path.join(output_dir, name)
        if not os.path.isfile(path):
            _add(pkg, "missing_product",
                 f"{name} is missing from the archive directory", file=name)
            raws[name] = None
            continue
        try:
            with open(path, "rb") as handle:
                raws[name] = handle.read()
        except OSError as exc:
            raise AuditError(
                "archive_unreadable",
                f"cannot read {name!r}: {exc}", {"file": path}) from exc
    if any(raw is None for raw in raws.values()):
        return pkg

    pkg.dsn_sha256 = _sha256(raws[DSN_JSONL])
    pkg.quarantine_sha256 = _sha256(raws[QUARANTINE_JSONL])
    pkg.manifest_sha256 = _sha256(raws[MANIFEST_JSONL])

    dsn_entries, pkg.dsn_physical_lines = _decode_jsonl(
        raws[DSN_JSONL], DSN_JSONL, pkg.problems)
    quarantine_entries, pkg.quarantine_physical_lines = _decode_jsonl(
        raws[QUARANTINE_JSONL], QUARANTINE_JSONL, pkg.problems)
    manifest_entries, _ = _decode_jsonl(
        raws[MANIFEST_JSONL], MANIFEST_JSONL, pkg.problems)

    runs = [(lineno, obj) for lineno, obj in manifest_entries
            if obj.get("type") == "run"]
    if not manifest_entries:
        _add(pkg, "empty_manifest", "manifest.jsonl contains no entries")
    if len(runs) != 1:
        _add(pkg, "run_entry_count",
             "manifest.jsonl must contain exactly one run entry",
             found=len(runs))
        if runs:
            pkg.run = runs[0][1]
    else:
        pkg.run = runs[0][1]
        if manifest_entries[0][1] is not pkg.run:
            _add(pkg, "run_not_first",
                 "the single run entry must be the first manifest entry",
                 manifest_line=runs[0][0])
    gateway = pkg.run.get("gateway_id")
    if not _text(gateway):
        _add(pkg, "bad_run_gateway",
             "the run entry needs a non-empty gateway_id")
    else:
        pkg.gateway_id = gateway
    for lineno, obj in manifest_entries:
        if obj.get("type") not in ("run", "message", "record"):
            _add(pkg, "unknown_manifest_entry",
                 f"manifest:{lineno}: unknown entry type "
                 f"{obj.get('type')!r}", manifest_line=lineno)

    _validate_messages(pkg, manifest_entries)
    _validate_records(pkg, manifest_entries, dsn_entries)
    _validate_quarantine(pkg, quarantine_entries)
    _validate_run(pkg)
    return pkg


# --------------------------------------------------------------------------- #
# ledger snapshot
# --------------------------------------------------------------------------- #
def _unlink(path):
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(path + suffix)
        except FileNotFoundError:
            pass


def _open_snapshot(ledger_path):
    """Copy the ledger once inside a read transaction.

    Returns ``(snapshot_ledger, snapshot_path, source_connection,
    data_version_before)``.  The source is opened read-only and never written.
    The source connection stays open (outside any transaction) so the caller
    can sample ``PRAGMA data_version`` after reading the snapshot and detect a
    commit that landed while the audit was running.
    """
    if not os.path.isfile(ledger_path):
        raise AuditError(
            "ledger_not_found",
            f"ledger database {ledger_path!r} does not exist")
    try:
        source = sqlite3.connect(f"file:{ledger_path}?mode=ro", uri=True,
                                 isolation_level=None, timeout=30)
    except sqlite3.Error as exc:
        raise AuditError(
            "ledger_unreadable",
            f"cannot open ledger read-only: {exc}") from exc
    handle, snap_path = tempfile.mkstemp(prefix="receipt-ledger-audit-",
                                         suffix=".snapshot.sqlite")
    os.close(handle)
    os.unlink(snap_path)
    try:
        source.execute("BEGIN")
        source.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
        try:
            check_schema(source)
        except RuntimeError as exc:
            raise AuditError("not_a_ledger", str(exc)) from exc
        before = source.execute("PRAGMA data_version").fetchone()[0]
        destination = sqlite3.connect(snap_path)
        try:
            with destination:
                source.backup(destination)
        finally:
            destination.close()
        source.execute("ROLLBACK")
    except AuditError:
        try:
            source.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        source.close()
        _unlink(snap_path)
        raise
    except sqlite3.Error as exc:
        try:
            source.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        source.close()
        _unlink(snap_path)
        raise AuditError(
            "ledger_unreadable",
            f"cannot snapshot ledger: {exc}") from exc

    try:
        snapshot = Ledger.open(snap_path)
    except (RuntimeError, sqlite3.Error) as exc:
        source.close()
        _unlink(snap_path)
        raise AuditError("not_a_ledger",
                         f"cannot open ledger snapshot: {exc}") from exc
    return snapshot, snap_path, source, before


# --------------------------------------------------------------------------- #
# ledger lookup
# --------------------------------------------------------------------------- #
def _public_record(parsed):
    record = {"gateway_id": parsed["gateway_id"],
              "report_id": parsed["report_id"],
              "item_id": parsed["item_id"],
              "recipient": parsed["recipient"],
              "occurred_at": parsed["occurred_text"],
              "action": parsed["action"]}
    if parsed["queue_id"] is not None:
        record["queue_id"] = parsed["queue_id"]
    if parsed["envelope_id"] is not None:
        record["envelope_id"] = parsed["envelope_id"]
    return record


def _stored_content(row):
    return {"report_id": row["report_id"], "item_id": row["item_id"],
            "recipient": row["recipient_text"],
            "occurred_at": row["occurred_text"],
            "action": row["action"], "queue_id": row["queue_id"],
            "envelope_id": row["envelope_id"],
            "canonical_hash": row["canonical_hash"]}


def _content_diff(record, row):
    """Fields where a stored dsn_line row differs from the expected record."""
    parsed = record["parsed"]
    fields = []
    if row["report_id"] != parsed["report_id"]:
        fields.append("report_id")
    if row["item_id"] != parsed["item_id"]:
        fields.append("item_id")
    if row["recipient_text"] != parsed["recipient"]:
        fields.append("recipient")
    if row["occurred_at_us"] != parsed["occurred_at_us"]:
        fields.append("occurred_at")
    if row["action"] != parsed["action"]:
        fields.append("action")
    if row["queue_id"] != parsed["queue_id"]:
        fields.append("queue_id")
    if row["envelope_id"] != parsed["envelope_id"]:
        fields.append("envelope_id")
    if row["canonical_hash"] != record["canonical_hash"]:
        fields.append("canonical_hash")
    return fields


def _fact_detail(conn, row):
    source = conn.execute(
        "SELECT id, sha256, kind, source_name, line_count FROM import_file"
        " WHERE id=?", (row["import_file"],)).fetchone()
    return {"found": True, "line_id": row["id"],
            "content": _stored_content(row),
            "import_file": _file_row(source)}


def _batch_file(conn, digest):
    return conn.execute(
        "SELECT id, sha256, kind, source_name, line_count FROM import_file"
        " WHERE sha256=?", (digest,)).fetchone()


def _same_name_other_digest(conn, digest, name):
    rows = conn.execute(
        "SELECT id, sha256, kind, source_name, line_count FROM import_file"
        " WHERE kind='dsn'").fetchall()
    matches = [_file_row(row) for row in rows
               if row[1] != digest
               and os.path.basename(row[3].replace("\\", "/")) == name]
    return sorted(matches, key=lambda row: (row["sha256"],
                                            row["source_name"]))


def _audit_records(conn, pkg, batch_file_row, gateway_row):
    results = []
    for record in pkg.records:
        parsed = record["parsed"]
        fact = None
        correction = None
        if gateway_row is not None:
            fact = conn.execute(
                "SELECT * FROM dsn_line WHERE gateway_row=? AND report_sig=?"
                " AND item_sig=?", (gateway_row, parsed["report_sig"],
                                    parsed["item_sig"])).fetchone()
            correction = conn.execute(
                "SELECT id FROM correction_line WHERE gateway_row=?"
                " AND report_sig=? AND item_sig=?",
                (gateway_row, parsed["report_sig"],
                 parsed["item_sig"])).fetchone()
        item = {
            "record_index": record["record_index"],
            "business_identity": record["identity"],
            "source": record["source"],
            "record": _public_record(parsed),
            "identical_records_in_batch": list(pkg.copies.get(
                (parsed["report_id"], parsed["item_id"]), [])),
        }
        if fact is not None:
            diff = _content_diff(record, fact)
            item["ledger_fact"] = _fact_detail(conn, fact)
            item["ledger_fact"]["content_matches"] = not diff
            if diff:
                item["result"] = CONFLICT
                item["reason"] = (
                    "the ledger already holds this business identity with "
                    "different content; the ledger refuses such an import")
                item["conflicting_fields"] = diff
            elif batch_file_row is None:
                item["result"] = PRESENT_UNIMPORTED
                item["reason"] = (
                    "the identical fact is present, but this batch's "
                    "dsn.jsonl is not registered as an import file")
            elif fact["import_file"] == batch_file_row[0]:
                item["result"] = IMPORTED
                item["reason"] = (
                    "the fact exists with identical content and its "
                    "import_file row is this batch's dsn.jsonl")
            else:
                item["result"] = DEDUPLICATED
                item["reason"] = (
                    "the identical fact already existed and kept its original "
                    "import file; this batch's import deduplicated the row "
                    "and is registered separately")
        elif correction is not None:
            item["result"] = CONFLICT
            item["conflicting_identity_kind"] = "correction"
            item["reason"] = (
                "this business identity is already used by a correction line")
            item["ledger_fact"] = None
        else:
            item["result"] = MISSING
            if batch_file_row is None:
                item["reason"] = (
                    "no fact exists for this identity and this batch's "
                    "dsn.jsonl is not registered as an import file")
            else:
                item["reason"] = (
                    "the batch file is registered, but no fact exists for "
                    "this identity")
            item["ledger_fact"] = None
        results.append(item)

    extras = []
    batch_row_count = None
    if batch_file_row is not None:
        expected = {(record["identity"]["report_id"],
                     record["identity"]["item_id"]):
                    record["canonical_hash"] for record in pkg.records}
        rows = conn.execute(
            "SELECT id, report_id, item_id, canonical_hash, recipient_text,"
            " occurred_text, action, queue_id, envelope_id, import_file"
            " FROM dsn_line WHERE import_file=?"
            " ORDER BY report_id, item_id, canonical_hash, id",
            (batch_file_row[0],)).fetchall()
        # physical row ids only break ties between byte-identical copies;
        # sort by business content so the report never depends on row numbers
        rows = sorted(rows, key=lambda row: (
            row["report_id"], row["item_id"], row["canonical_hash"],
            row["recipient_text"], row["occurred_text"], row["action"],
            row["queue_id"] or "", row["envelope_id"] or ""))
        batch_row_count = len(rows)
        for row in rows:
            key = (row["report_id"], row["item_id"])
            if key not in expected:
                extras.append({
                    "kind": "unexpected_identity",
                    "identity": {"report_id": row["report_id"],
                                 "item_id": row["item_id"]},
                    "line_id": row["id"],
                    "content": _stored_content(row),
                    "reason": "this fact is attributed to the batch's import "
                              "file but is not one of the batch's records",
                })
            elif expected[key] != row["canonical_hash"]:
                extras.append({
                    "kind": "content_not_from_batch",
                    "identity": {"report_id": row["report_id"],
                                 "item_id": row["item_id"]},
                    "line_id": row["id"],
                    "content": _stored_content(row),
                    "reason": "the batch's import file carries this identity "
                              "with content that differs from the package",
                })
    return results, extras, batch_row_count


def _quarantine_report(conn, pkg, gateway_row):
    """Annotate every package quarantine entry for the report.

    ``conn`` may be ``None`` when the package is invalid and no ledger view was
    taken; the entries are then still marked as not expected, but the ledger
    coincidence check is simply unavailable.
    """
    report = []
    for entry in pkg.quarantine:
        item = dict(entry)
        item["expected_in_ledger"] = False
        item["note"] = ("a quarantined block is not a receipt that should "
                        "have been imported")
        coincidence = {"dsn": False, "correction": False}
        if conn is not None and gateway_row is not None \
                and entry.get("report_id") is not None:
            report_sig = ingest.identity_signature(entry["report_id"],
                                                   "report_id")
            item_sig = ingest.identity_signature(entry["item_id"], "item_id")
            coincidence["dsn"] = conn.execute(
                "SELECT 1 FROM dsn_line WHERE gateway_row=? AND report_sig=?"
                " AND item_sig=?", (gateway_row, report_sig,
                                    item_sig)).fetchone() is not None
            coincidence["correction"] = conn.execute(
                "SELECT 1 FROM correction_line WHERE gateway_row=?"
                " AND report_sig=? AND item_sig=?",
                (gateway_row, report_sig, item_sig)).fetchone() is not None
        item["ledger_identity_present"] = coincidence
        if coincidence["dsn"] or coincidence["correction"]:
            item["note"] = (
                "an unrelated ledger row happens to use the same identity; "
                "it does not make this quarantined block an imported receipt")
        report.append(item)
    return report


def _outcome_reasons(outcome, results, extras, issues, concurrent, pkg):
    """Human-readable justification for the single outcome code."""
    reasons = []
    for item in results:
        if item["result"] != IMPORTED:
            identity = item["business_identity"]
            reasons.append(
                "%s/%s: %s" % (identity["report_id"], identity["item_id"],
                               item["result"]))
    for extra in extras:
        identity = extra["identity"]
        reasons.append("%s/%s: %s" % (identity["report_id"],
                                      identity["item_id"], extra["kind"]))
    for issue in issues:
        if issue["kind"] in ("missing_fact", "identity_content_conflict",
                             "same_name_other_digest"):
            continue  # per-record verdicts, or informational context
        reasons.append(issue["kind"])
    if concurrent:
        reasons.append("concurrent_commit_during_audit")
    if not reasons:
        if not pkg.records:
            reasons.append("no receipts to reconcile")
        else:
            reasons.append("every valid receipt is present with identical "
                           "content (%d imported by this batch, %d already "
                           "deduplicated)" % (
                               sum(1 for item in results
                                   if item["result"] == IMPORTED),
                               sum(1 for item in results
                                   if item["result"] == DEDUPLICATED)))
    return reasons


def _summary(results, pkg, extras, issues, copies):
    counts = {IMPORTED: 0, DEDUPLICATED: 0, PRESENT_UNIMPORTED: 0,
              MISSING: 0, CONFLICT: 0}
    for item in results:
        counts[item["result"]] = counts.get(item["result"], 0) + 1
    distinct = {}
    for item in results:
        key = (item["business_identity"]["gateway_id"],
               item["business_identity"]["report_id"],
               item["business_identity"]["item_id"])
        distinct[key] = True
    return {
        "valid_receipts": len(results),
        "distinct_business_identities": len(distinct),
        "imported_by_this_batch": counts[IMPORTED],
        "deduplicated_existing": counts[DEDUPLICATED],
        "present_but_file_not_imported": counts[PRESENT_UNIMPORTED],
        "missing": counts[MISSING],
        "conflict": counts[CONFLICT],
        "identical_record_copies": sum(len(indexes) - 1
                                       for indexes in copies.values()),
        "quarantined_blocks": sum(
            1 for entry in pkg.quarantine
            if entry["source"]["block_index"] is not None),
        "failed_messages": sum(
            1 for entry in pkg.quarantine
            if entry["source"]["block_index"] is None),
        "unexpected_facts_for_batch": len(extras),
        "issue_count": len(issues),
    }


# --------------------------------------------------------------------------- #
# public entry point
# --------------------------------------------------------------------------- #
def audit_archive_import(ledger_path, output_dir):
    """Audit one archive batch against one ledger without modifying either.

    Returns a JSON-serializable report.  ``report["outcome"]`` is one of
    ``verified``, ``incomplete``, ``conflict``, ``invalid_package`` or
    ``concurrent_change``; ``report["exit_code"]`` is the matching process
    exit status.  Structural archive problems are reported, not raised;
    missing paths and unreadable or foreign databases raise
    :class:`AuditError`.
    """
    pkg = _validate_package(output_dir)
    report = {
        "command": "audit-archive-import",
        "archive": {
            "output_dir": output_dir,
            "gateway_id": pkg.gateway_id,
            "run": pkg.run,
            "products": {},
            "counts": {
                "messages": len(pkg.messages),
                "records": len(pkg.records),
                "quarantined_blocks": sum(
                    1 for entry in pkg.quarantine
                    if entry["source"]["block_index"] is not None),
                "failed_messages": sum(
                    1 for entry in pkg.quarantine
                    if entry["source"]["block_index"] is None),
            },
        },
        "package": {"valid": pkg.valid, "problems": pkg.problems},
        "ledger": {"path": ledger_path, "checked": False},
        "records": [],
        "quarantine": [],
        "unexpected_facts": [],
        "issues": [],
        "summary": {},
    }
    for name in OUTPUT_NAMES:
        declared = pkg.declared.get(name, {})
        actual_sha = {DSN_JSONL: pkg.dsn_sha256,
                      QUARANTINE_JSONL: pkg.quarantine_sha256,
                      MANIFEST_JSONL: pkg.manifest_sha256}[name]
        report["archive"]["products"][name] = {
            "sha256": actual_sha,
            "lines": pkg.dsn_physical_lines if name == DSN_JSONL else
            pkg.quarantine_physical_lines if name == QUARANTINE_JSONL else None,
            "declared_sha256": declared.get("sha256") if declared else None,
            "declared_lines": declared.get("lines") if declared else None,
        }
    # The package's quarantine list is reported even for an invalid package:
    # it is untrusted material, and the package problems say so.  No ledger
    # coincidence check is possible without a valid package view.
    report["quarantine"] = _quarantine_report(None, pkg, None)
    if not pkg.valid:
        report["outcome"] = "invalid_package"
        report["verified"] = False
        report["exit_code"] = OUTCOME_EXIT["invalid_package"]
        report["issues"] = [dict(problem) for problem in pkg.problems]
        report["summary"] = _summary([], pkg, [], report["issues"], {})
        report["ledger"]["reason"] = (
            "the archive package is structurally invalid; no per-record "
            "ledger verdict is attempted")
        return report

    snapshot, snap_path, source, before = _open_snapshot(ledger_path)
    try:
        if _after_snapshot_hook is not None:
            _after_snapshot_hook()
        conn = snapshot.conn
        gateway_row = conn.execute(
            "SELECT id FROM gateway WHERE ident=?",
            (ingest.identity_signature(pkg.gateway_id, "gateway_id"),)
        ).fetchone()
        gateway_row = gateway_row[0] if gateway_row else None
        batch_row = _batch_file(conn, pkg.dsn_sha256)
        batch_file = _file_row(batch_row)
        same_name = _same_name_other_digest(conn, pkg.dsn_sha256, DSN_JSONL)
        results, extras, batch_row_count = _audit_records(
            conn, pkg, batch_row, gateway_row)
        report["records"] = results
        report["unexpected_facts"] = extras
        report["quarantine"] = _quarantine_report(conn, pkg, gateway_row)

        ledger_issues = []
        # A batch that produced no receipts has nothing an import could
        # register; its quarantined material is reported separately and the
        # absence of an import_file row is not a missing import.
        if batch_row is None and pkg.records:
            ledger_issues.append({
                "kind": "batch_file_not_imported",
                "sha256": pkg.dsn_sha256,
                "reason": "no import_file row carries this exact dsn.jsonl "
                          "digest; matching by file name alone is never done",
            })
        elif batch_row is not None:
            if batch_file["kind"] != "dsn":
                ledger_issues.append({
                    "kind": "import_file_kind_mismatch",
                    "kind_found": batch_file["kind"],
                    "reason": "the import_file row for this digest is not a "
                              "receipt file",
                })
            if batch_file["line_count"] != len(pkg.dsn_lines):
                ledger_issues.append({
                    "kind": "import_file_line_count_mismatch",
                    "declared": batch_file["line_count"],
                    "package": len(pkg.dsn_lines),
                    "reason": "the ledger's import_file row records a "
                              "different line count than this dsn.jsonl",
                })
            if not results and batch_row_count:
                ledger_issues.append({
                    "kind": "unexpected_fact_for_batch",
                    "count": batch_row_count,
                    "reason": "the batch's import file is registered but the "
                              "package has no receipts",
                })
        if same_name:
            ledger_issues.append({
                "kind": "same_name_other_digest",
                "files": same_name,
                "reason": "other import files share this file name but not "
                          "its digest; they are not this batch and their "
                          "facts are not counted as this batch's provenance",
            })
        for item in results:
            if item["result"] == MISSING:
                ledger_issues.append({
                    "kind": "missing_fact",
                    "record_index": item["record_index"],
                    "identity": item["business_identity"],
                })
            elif item["result"] == PRESENT_UNIMPORTED:
                ledger_issues.append({
                    "kind": "file_not_imported",
                    "record_index": item["record_index"],
                    "identity": item["business_identity"],
                })
            elif item["result"] == CONFLICT:
                ledger_issues.append({
                    "kind": "identity_content_conflict",
                    "record_index": item["record_index"],
                    "identity": item["business_identity"],
                    "conflicting_fields": item.get("conflicting_fields", []),
                })
        for extra in extras:
            ledger_issues.append({
                "kind": "unexpected_fact_for_batch",
                "identity": extra["identity"],
                "detail": extra["reason"],
            })
        for entry in pkg.quarantine:
            if entry["kind"] == "message":
                ledger_issues.append({
                    "kind": "report_level_failure",
                    "source": entry["source"],
                    "category": entry["category"],
                    "detail": entry["detail"],
                    "reason": "a whole message could not be converted; the "
                              "batch is not fully accounted for even though "
                              "nothing was missing from the ledger",
                })
        after = source.execute("PRAGMA data_version").fetchone()[0]
        concurrent = before != after
        if concurrent:
            ledger_issues.append({
                "kind": "concurrent_commit_during_audit",
                "data_version_before": before,
                "data_version_after": after,
                "reason": "another process committed while this audit was "
                          "reading; every verdict describes the single "
                          "snapshot taken at data_version_before",
            })
        report["ledger"] = {
            "path": ledger_path,
            "checked": True,
            "snapshot": {
                "data_version_before": before,
                "data_version_after": after,
                "concurrent_commit_observed": concurrent,
            },
            "batch_import_file": batch_file,
            "batch_file_registered": batch_file is not None,
            "same_name_other_digests": same_name,
        }
        report["issues"] = ledger_issues
        report["summary"] = _summary(results, pkg, extras, ledger_issues,
                                     pkg.copies)
        hard_conflict = (
            any(item["result"] == CONFLICT for item in results)
            or any(extra["kind"] == "unexpected_identity"
                   for extra in extras)
            or any(issue["kind"] == "import_file_kind_mismatch"
                   for issue in ledger_issues))
        if hard_conflict:
            outcome = "conflict"
        elif any(item["result"] not in _CLEAN_RECORD_STATUSES
                 for item in results) or any(
                     issue["kind"] in ("batch_file_not_imported",
                                       "file_not_imported",
                                       "import_file_line_count_mismatch",
                                       "report_level_failure")
                     for issue in ledger_issues):
            outcome = "incomplete"
        elif concurrent:
            outcome = "concurrent_change"
        else:
            outcome = "verified"
        report["outcome"] = outcome
        report["verified"] = outcome == "verified"
        report["exit_code"] = OUTCOME_EXIT[outcome]
        report["outcome_reasons"] = _outcome_reasons(
            outcome, results, extras, ledger_issues, concurrent, pkg)
        if outcome == "verified" and not pkg.records:
            report["note"] = ("the batch produced no receipts at all "
                              "(no recipient blocks)" if not pkg.quarantine
                              else "the batch produced no canonical receipts; "
                                   "quarantined material is listed separately")
        return report
    finally:
        snapshot.close()
        source.close()
        _unlink(snap_path)
