"""Batch import of gateway-exported .eml archives into canonical DSN JSONL.

``convert_archive`` reads every ``.eml`` file below an input directory,
parses each one with :mod:`receipt_ledger.dsnmime`, and writes three files
into a **new** output directory:

``dsn.jsonl``
    Canonical receipt records, one JSON object per line, directly importable
    with ``receipt_ledger``'s ``import-dsn``.  Records keep the original
    per-file block order; files are processed in sorted relative-path order,
    so directory enumeration order never changes the output.
``quarantine.jsonl``
    One entry per recipient block that could not be safely converted, plus
    one entry per message that failed at report level (``block_index`` is
    null there).  Entries carry the diagnosable facts only - relative file
    path, file SHA-256, message index, block index, error category and a
    short detail.  They never copy the message body or other recipients'
    addresses.
``manifest.jsonl``
    Provenance, kept out of the ledger JSONL on purpose.  A ``run`` entry,
    then per message a ``message`` entry (parse status, report-level
    context, per-block outcomes, digest of the message's parse result) and
    one ``record`` entry per emitted record mapping it back to its source:
    relative path, file SHA-256, message index, recipient block index and
    the message parse digest.  Identical content in two different files
    yields two distinct provenance chains; the same file name with changed
    content yields a different SHA-256 and a different content-derived
    ``report_id``, so an old source identity can never impersonate new
    content.

Atomicity
---------
The whole batch is parsed and validated first.  All three files are written
inside a controlled temporary directory next to the target, fsynced, and
published with a single atomic ``os.rename``.  If the target path already
exists, or any read/write fails, the command fails and leaves nothing
behind - the target never appears with a partial batch.  Input files are
only read, never modified.

This command never opens, creates or modifies a ledger database; ledger
state is entirely determined by a subsequent, independent ``import-dsn``.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid

from .dsnmime import RecipientRecord, ReportFailure, parse_message

__all__ = ["ArchiveError", "convert_archive"]

DSN_JSONL = "dsn.jsonl"
QUARANTINE_JSONL = "quarantine.jsonl"
MANIFEST_JSONL = "manifest.jsonl"
OUTPUT_NAMES = (DSN_JSONL, QUARANTINE_JSONL, MANIFEST_JSONL)


class ArchiveError(Exception):
    """Batch-level failure; nothing is published when this is raised."""

    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def to_dict(self):
        return {"code": self.code, "message": self.message,
                "details": self.details}


def _line(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_file(directory, name, text):
    path = os.path.join(directory, name)
    with open(path, "xb") as handle:  # must not exist in a fresh temp dir
        handle.write(text.encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())


def _collect_eml_files(input_dir):
    """Return (eml relative paths sorted, skipped non-.eml paths sorted)."""
    eml, skipped = [], []
    for root, dirs, names in os.walk(input_dir):
        dirs.sort()
        for name in names:
            rel = os.path.relpath(os.path.join(root, name), input_dir)
            rel = rel.replace(os.sep, "/")
            if name.lower().endswith(".eml"):
                eml.append(rel)
            else:
                skipped.append(rel)
    return sorted(eml), sorted(skipped)


def convert_archive(input_dir, output_dir, *, gateway_id):
    """Convert a directory of raw .eml bounce exports into canonical JSONL.

    Returns a JSON-serializable run summary.  Raises :class:`ArchiveError`
    (publishing nothing) when the input is unreadable, the output path
    already exists, or any write fails.
    """
    if not isinstance(gateway_id, str) or not gateway_id:
        raise ArchiveError("input_error",
                           "gateway_id must be a non-empty string")
    if not os.path.isdir(input_dir):
        raise ArchiveError(
            "input_not_found",
            f"input directory {input_dir!r} does not exist or is not a "
            "directory")
    if os.path.lexists(output_dir):
        raise ArchiveError(
            "output_exists",
            f"output path {output_dir!r} already exists; refusing to "
            "overwrite it")
    parent = os.path.dirname(os.path.abspath(output_dir))
    if not os.path.isdir(parent):
        raise ArchiveError(
            "output_error",
            f"parent directory of {output_dir!r} does not exist")

    eml_files, skipped = _collect_eml_files(input_dir)

    records = []        # canonical ledger records, in output order
    quarantine = []     # quarantine entries, in (message, block) order
    manifest = []       # message/record manifest entries, in message order
    failed_messages = 0
    quarantined_blocks = 0

    for message_index, rel in enumerate(eml_files):
        path = os.path.join(input_dir, rel.replace("/", os.sep))
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except OSError as exc:
            raise ArchiveError(
                "input_error", f"cannot read input file {rel!r}: {exc}",
                {"file": rel}) from exc
        file_sha256 = hashlib.sha256(raw).hexdigest()
        source = {"file": rel, "file_sha256": file_sha256,
                  "message_index": message_index}
        try:
            parsed = parse_message(raw, gateway_id=gateway_id)
        except ReportFailure as exc:
            failed_messages += 1
            quarantine.append({**source, "block_index": None,
                               "category": exc.category,
                               "detail": exc.detail})
            manifest.append({"type": "message", **source, "status": "failed",
                             "category": exc.category, "detail": exc.detail})
            continue

        blocks = []
        record_entries = []
        for outcome in parsed.outcomes:
            if isinstance(outcome, RecipientRecord):
                record_index = len(records)
                records.append(outcome.record)
                blocks.append({"block_index": outcome.block_index,
                               "outcome": "record",
                               "record_index": record_index,
                               "item_id": outcome.record["item_id"]})
                record_entries.append({
                    "type": "record", "record_index": record_index, **source,
                    "block_index": outcome.block_index,
                    "parse_digest": parsed.parse_digest,
                    "report_id": parsed.report_id,
                    "item_id": outcome.record["item_id"]})
            else:
                quarantined_blocks += 1
                quarantine.append({**source,
                                   "block_index": outcome.block_index,
                                   "category": outcome.category,
                                   "detail": outcome.detail})
                blocks.append({"block_index": outcome.block_index,
                               "outcome": "quarantine",
                               "category": outcome.category,
                               "detail": outcome.detail})
        manifest.append({"type": "message", **source, "status": "parsed",
                         "report_id": parsed.report_id,
                         "parse_digest": parsed.parse_digest,
                         "context": parsed.context, "blocks": blocks})
        manifest.extend(record_entries)

    dsn_text = "".join(_line(record) + "\n" for record in records)
    quarantine_text = "".join(_line(entry) + "\n" for entry in quarantine)
    run_entry = {
        "type": "run",
        "format_version": 1,
        "tool": "receipt_ledger convert-archive",
        "gateway_id": gateway_id,
        "input_dir": input_dir,
        "eml_files": len(eml_files),
        "skipped_files": skipped,
        "messages": len(eml_files),
        "records": len(records),
        "quarantined_blocks": quarantined_blocks,
        "failed_messages": failed_messages,
        "outputs": {
            DSN_JSONL: {"sha256": _sha256_text(dsn_text),
                        "lines": len(records)},
            QUARANTINE_JSONL: {"sha256": _sha256_text(quarantine_text),
                               "lines": len(quarantine)},
        },
    }
    manifest_text = (_line(run_entry) + "\n"
                     + "".join(_line(entry) + "\n" for entry in manifest))

    # Publish atomically: complete the batch in a controlled temporary
    # directory next to the target, then rename it into place.
    temp_dir = "%s.tmp-%s" % (output_dir, uuid.uuid4().hex)
    try:
        os.mkdir(temp_dir)
        _write_file(temp_dir, DSN_JSONL, dsn_text)
        _write_file(temp_dir, QUARANTINE_JSONL, quarantine_text)
        _write_file(temp_dir, MANIFEST_JSONL, manifest_text)
        dir_fd = os.open(temp_dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        if os.path.lexists(output_dir):
            raise ArchiveError(
                "output_exists",
                f"output path {output_dir!r} already exists; refusing to "
                "overwrite it")
        os.rename(temp_dir, output_dir)
    except ArchiveError:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    except OSError as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise ArchiveError(
            "output_error",
            f"failed to write output directory {output_dir!r}: {exc}") from exc

    return {
        "input_dir": input_dir,
        "output_dir": output_dir,
        "gateway_id": gateway_id,
        "eml_files": len(eml_files),
        "skipped_files": len(skipped),
        "messages": len(eml_files),
        "records": len(records),
        "quarantined_blocks": quarantined_blocks,
        "failed_messages": failed_messages,
        "outputs": {name: os.path.join(output_dir, name)
                    for name in OUTPUT_NAMES},
    }
