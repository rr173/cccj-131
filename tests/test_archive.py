"""Acceptance suite for the offline .eml archive import (convert-archive).

Every expectation in this file is computed independently of the parser:
records are hand-written literals, digests are computed here with hashlib
over hand-built structures, and the ledger checks use the ledger's own
public API.  The parser's output is never used as its own expectation.

Run: python3 -I tests/test_archive.py
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from receipt_ledger import ArchiveError, Ledger, convert_archive  # noqa: E402
from receipt_ledger.archive import (DSN_JSONL, MANIFEST_JSONL,  # noqa: E402
                                    QUARANTINE_JSONL)
from tests.archive_samples import SAMPLES  # noqa: E402
from tests.helpers import check, jsonl, outbound  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "fixtures", "archive")
GATEWAY = "gw-main"


# --------------------------------------------------------------------------- #
# small independent helpers (no parser code)
# --------------------------------------------------------------------------- #
def sha(data):
    return hashlib.sha256(data).hexdigest()


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def jsonl_text(rows):
    return "".join(canon(row) + "\n" for row in rows)


def read_jsonl(path):
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def read_text(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def make_input(workdir, files):
    """Write {relative name: bytes} into a fresh input directory."""
    input_dir = os.path.join(workdir, "in")
    for rel, data in files.items():
        path = os.path.join(input_dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
    return input_dir


def convert(input_dir, workdir, gateway=GATEWAY, name="out"):
    output_dir = os.path.join(workdir, name)
    summary = convert_archive(input_dir, output_dir, gateway_id=gateway)
    return summary, output_dir


def expect_archive_error(fn, *, code, label):
    try:
        fn()
    except ArchiveError as exc:
        check(exc.code == code,
              f"{label}: expected code {code}, got {exc.code}: {exc}")
        return exc
    raise AssertionError(f"{label}: expected ArchiveError({code})")


# --------------------------------------------------------------------------- #
# hand-computed expectations for the main sample
# --------------------------------------------------------------------------- #
MAIN_BYTES = SAMPLES["main"]["bounce.eml"]
MAIN_SHA = sha(MAIN_BYTES)
MAIN_RID = "rpt-" + MAIN_SHA
MAIN_RECORDS = [
    {"gateway_id": GATEWAY, "report_id": MAIN_RID, "item_id": "item-0",
     "recipient": "Alice@example.com", "occurred_at": "2026-02-03T04:00:00Z",
     "action": "delivered", "queue_id": "QUEUE-9"},
    {"gateway_id": GATEWAY, "report_id": MAIN_RID, "item_id": "item-1",
     "recipient": "bob@example.net", "occurred_at": "2026-02-03T09:31:00Z",
     "action": "failed", "queue_id": "QUEUE-10", "envelope_id": "ENV-B"},
    {"gateway_id": GATEWAY, "report_id": MAIN_RID, "item_id": "item-2",
     "recipient": "carol@example.org", "occurred_at": "2026-02-03T09:32:00Z",
     "action": "delayed", "queue_id": "QUEUE-11"},
]
MAIN_CONTEXT = {
    "reporting-mta": ["dns;gw-main.example.com"],
    "dsn-gateway": [],
    "received-from-mta": [],
    "arrival-date": ["Tue,03 Feb 2026 08:15:00 +0000"],
    "original-envelope-id": ["ENV-A"],
    "other_fields": [],
}
MAIN_MATERIAL = {
    "gateway_id": GATEWAY,
    "context": MAIN_CONTEXT,
    "blocks": [
        {"block_index": 0, "outcome": "record", "record": MAIN_RECORDS[0]},
        {"block_index": 1, "outcome": "record", "record": MAIN_RECORDS[1]},
        {"block_index": 2, "outcome": "record", "record": MAIN_RECORDS[2]},
    ],
}
MAIN_DIGEST = sha(canon(MAIN_MATERIAL).encode("utf-8"))

MIXED_BYTES = SAMPLES["mixed"]["mixed.eml"]
MIXED_SHA = sha(MIXED_BYTES)
MIXED_RID = "rpt-" + MIXED_SHA
MIXED_RECORDS = [
    {"gateway_id": GATEWAY, "report_id": MIXED_RID, "item_id": "item-0",
     "recipient": "dave@example.com", "occurred_at": "2026-02-04T10:00:00Z",
     "action": "delivered", "queue_id": "Q-1"},
    {"gateway_id": GATEWAY, "report_id": MIXED_RID, "item_id": "item-2",
     "recipient": "frank@example.com", "occurred_at": "2026-02-04T10:02:00Z",
     "action": "failed", "queue_id": "Q-3"},
]
MIXED_QUARANTINE = {
    "file": "mixed.eml", "file_sha256": MIXED_SHA, "message_index": 0,
    "block_index": 1, "category": "action_status_mismatch",
    "detail": "action 'failed' contradicts status '2.1.5'"}


# --------------------------------------------------------------------------- #
# 1. the committed fixtures are exactly the hand-written sample bytes
# --------------------------------------------------------------------------- #
def test_fixtures_fresh():
    for case, files in sorted(SAMPLES.items()):
        for name, data in sorted(files.items()):
            path = os.path.join(FIXTURES, case, "eml", name)
            check(os.path.isfile(path), f"fixture missing: {path}")
            with open(path, "rb") as handle:
                check(handle.read() == data,
                      f"fixture {case}/{name} differs from "
                      "tests/archive_samples.py; regenerate with "
                      "scripts/make_archive_fixtures.py")


# --------------------------------------------------------------------------- #
# 2. main sample: folded fields, several recipients, message-level context,
#    attachments -- full canonical JSONL + provenance check
# --------------------------------------------------------------------------- #
def test_main_sample():
    workdir = tempfile.mkdtemp(prefix="arc-main-")
    try:
        input_dir = os.path.join(FIXTURES, "main", "eml")
        summary, out = convert(input_dir, workdir)
        check(summary["records"] == 3, "main: expected 3 records")
        check(summary["quarantined_blocks"] == 0, "main: no quarantines")
        check(summary["failed_messages"] == 0, "main: no failed messages")
        check(sorted(os.listdir(out)) == sorted(
            [DSN_JSONL, QUARANTINE_JSONL, MANIFEST_JSONL]),
            "main: output dir must hold exactly the three products")

        # canonical JSONL, byte-exact against the hand-written records
        expected_dsn = jsonl_text(MAIN_RECORDS)
        actual_dsn = read_text(os.path.join(out, DSN_JSONL))
        check(actual_dsn == expected_dsn,
              "main: dsn.jsonl bytes differ from hand-computed records")
        check(read_text(os.path.join(out, QUARANTINE_JSONL)) == "",
              "main: quarantine.jsonl must be empty")
        # the human-readable part and the embedded message/rfc822 attachment
        # carry DSN-looking lines that must never become receipt data
        check("not-a-receipt" not in actual_dsn
              and "nested@example.com" not in actual_dsn,
              "main: body/attachment text leaked into receipt records")

        manifest = read_jsonl(os.path.join(out, MANIFEST_JSONL))
        check(len(manifest) == 1 + 1 + 3,
              "main: manifest must have run + message + 3 record entries")
        run, message = manifest[0], manifest[1]
        record_entries = manifest[2:]

        check(run["type"] == "run" and run["format_version"] == 1,
              "main: bad run entry")
        check(run["gateway_id"] == GATEWAY, "main: run gateway")
        check(run["eml_files"] == 1 and run["messages"] == 1,
              "main: run counts")
        check(run["records"] == 3 and run["quarantined_blocks"] == 0
              and run["failed_messages"] == 0, "main: run tallies")
        check(run["skipped_files"] == [], "main: nothing skipped")
        check(run["outputs"][DSN_JSONL] ==
              {"sha256": sha(expected_dsn.encode("utf-8")), "lines": 3},
              "main: run entry dsn.jsonl digest")
        check(run["outputs"][QUARANTINE_JSONL] ==
              {"sha256": sha(b""), "lines": 0},
              "main: run entry quarantine digest")

        expected_message = {
            "type": "message", "message_index": 0, "file": "bounce.eml",
            "file_sha256": MAIN_SHA, "status": "parsed",
            "report_id": MAIN_RID, "parse_digest": MAIN_DIGEST,
            "context": MAIN_CONTEXT,
            "blocks": [
                {"block_index": 0, "outcome": "record", "record_index": 0,
                 "item_id": "item-0"},
                {"block_index": 1, "outcome": "record", "record_index": 1,
                 "item_id": "item-1"},
                {"block_index": 2, "outcome": "record", "record_index": 2,
                 "item_id": "item-2"},
            ],
        }
        check(message == expected_message,
              f"main: message entry mismatch:\n{message}")
        for k, entry in enumerate(record_entries):
            check(entry == {
                "type": "record", "record_index": k, "file": "bounce.eml",
                "file_sha256": MAIN_SHA, "message_index": 0,
                "block_index": k, "parse_digest": MAIN_DIGEST,
                "report_id": MAIN_RID, "item_id": f"item-{k}"},
                f"main: record entry {k} mismatch:\n{entry}")

        # message-level context must not leak into per-recipient records
        for record in read_jsonl(os.path.join(out, DSN_JSONL)):
            check(set(record) <= {"gateway_id", "report_id", "item_id",
                                  "recipient", "occurred_at", "action",
                                  "queue_id", "envelope_id"},
                  f"main: record carries non-ledger fields: {record}")
            check("ENV-A" not in canon(record)
                  and "gw-main.example.com" not in canon(record),
                  "main: message-level context leaked into a record")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 3. one bad recipient block between two good ones: only the bad block is
#    quarantined, order is preserved
# --------------------------------------------------------------------------- #
def test_mixed_blocks():
    workdir = tempfile.mkdtemp(prefix="arc-mixed-")
    try:
        input_dir = os.path.join(FIXTURES, "mixed", "eml")
        summary, out = convert(input_dir, workdir)
        check(summary["records"] == 2 and summary["quarantined_blocks"] == 1,
              "mixed: expected 2 records + 1 quarantined block")
        check(read_text(os.path.join(out, DSN_JSONL))
              == jsonl_text(MIXED_RECORDS),
              "mixed: dsn.jsonl differs from hand-computed records "
              "(block order must be preserved)")
        quarantine = read_jsonl(os.path.join(out, QUARANTINE_JSONL))
        check(quarantine == [MIXED_QUARANTINE],
              f"mixed: quarantine entry mismatch:\n{quarantine}")
        manifest = read_jsonl(os.path.join(out, MANIFEST_JSONL))
        message = manifest[1]
        check(message["status"] == "parsed", "mixed: message parsed")
        check([b["outcome"] for b in message["blocks"]]
              == ["record", "quarantine", "record"],
              "mixed: block outcomes out of order")
        check(message["blocks"][1]["category"] == "action_status_mismatch",
              "mixed: quarantined block category")
        record_entries = [e for e in manifest if e.get("type") == "record"]
        check([e["block_index"] for e in record_entries] == [0, 2],
              "mixed: record provenance must point at blocks 0 and 2")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 4. report-level failures: the whole message yields no canonical receipts
# --------------------------------------------------------------------------- #
def test_report_level_failures():
    cases = [
        ("missing_dsn_part", "dsn_part_missing",
         "no message/delivery-status body part"),
        ("duplicate_dsn_part", "dsn_part_duplicate",
         "2 message/delivery-status body parts"),
        ("unclosed_boundary", "mime_boundary",
         "closing boundary '--u1--' not found"),
        ("bad_transfer_encoding", "transfer_encoding",
         "invalid base64 in delivery-status part"),
        ("unknown_charset", "unsupported_charset",
         "delivery-status part charset 'x-weird-charset' is not supported"),
        ("not_a_report", "report_type_mismatch",
         "content-type is text/plain, not multipart/report"),
        ("empty_dsn_part", "dsn_structure",
         "delivery-status part has no field blocks"),
    ]
    workdir = tempfile.mkdtemp(prefix="arc-repfail-")
    try:
        for case, category, detail_prefix in cases:
            files = SAMPLES[case]
            input_dir = make_input(os.path.join(workdir, case), files)
            summary, out = convert(input_dir, os.path.join(workdir, case))
            check(summary["records"] == 0, f"{case}: no records expected")
            check(summary["failed_messages"] == 1,
                  f"{case}: one failed message expected")
            check(read_text(os.path.join(out, DSN_JSONL)) == "",
                  f"{case}: dsn.jsonl must be empty")
            name = next(iter(files))
            expected = [{
                "file": name, "file_sha256": sha(files[name]),
                "message_index": 0, "block_index": None,
                "category": category, "detail": read_jsonl(
                    os.path.join(out, QUARANTINE_JSONL))[0]["detail"]}]
            quarantine = read_jsonl(os.path.join(out, QUARANTINE_JSONL))
            check(quarantine == expected, f"{case}: quarantine shape")
            check(quarantine[0]["detail"].startswith(detail_prefix),
                  f"{case}: detail {quarantine[0]['detail']!r} does not "
                  f"start with {detail_prefix!r}")
            manifest = read_jsonl(os.path.join(out, MANIFEST_JSONL))
            check(len(manifest) == 2, f"{case}: run + message entries only")
            message = manifest[1]
            check(message["status"] == "failed"
                  and message["category"] == category,
                  f"{case}: manifest message entry")
            check("parse_digest" not in message,
                  f"{case}: failed messages carry no parse digest")
            check(not any(e.get("type") == "record" for e in manifest),
                  f"{case}: failed messages produce no record provenance")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 5. block-level cases: conflicting duplicates, unsupported address type,
#    base64 transfer, a report without recipients
# --------------------------------------------------------------------------- #
def test_block_level_cases():
    workdir = tempfile.mkdtemp(prefix="arc-block-")
    try:
        # conflicting duplicate Final-Recipient: block 0 converts, block 1
        # is quarantined; the parser must not pick a value
        files = SAMPLES["conflicting_fields"]
        raw = files["broken.eml"]
        rid = "rpt-" + sha(raw)
        input_dir = make_input(os.path.join(workdir, "cf"), files)
        summary, out = convert(input_dir, os.path.join(workdir, "cf"))
        check(summary["records"] == 1 and summary["quarantined_blocks"] == 1,
              "conflicting_fields: 1 record + 1 quarantine")
        expected_record = {
            "gateway_id": GATEWAY, "report_id": rid, "item_id": "item-0",
            "recipient": "gina@example.com",
            "occurred_at": "2026-02-05T11:00:00Z", "action": "delivered",
            "queue_id": "Q-10"}
        check(read_jsonl(os.path.join(out, DSN_JSONL)) == [expected_record],
              "conflicting_fields: record mismatch")
        quarantine = read_jsonl(os.path.join(out, QUARANTINE_JSONL))
        check(len(quarantine) == 1
              and quarantine[0]["block_index"] == 1
              and quarantine[0]["category"] == "conflicting_fields"
              and quarantine[0]["detail"] ==
              "field 'final-recipient' appears 2 times with different values",
              f"conflicting_fields: quarantine mismatch:\n{quarantine}")
        # quarantine entries must not copy any recipient address
        check("example.com" not in canon(quarantine),
              "conflicting_fields: quarantine leaks an address")

        # unsupported recipient address type
        files = SAMPLES["unsupported_addr_type"]
        raw = files["broken.eml"]
        rid = "rpt-" + sha(raw)
        input_dir = make_input(os.path.join(workdir, "uat"), files)
        summary, out = convert(input_dir, os.path.join(workdir, "uat"))
        check(summary["records"] == 1 and summary["quarantined_blocks"] == 1,
              "unsupported_addr_type: 1 record + 1 quarantine")
        expected_record = {
            "gateway_id": GATEWAY, "report_id": rid, "item_id": "item-0",
            "recipient": "iris@example.com",
            "occurred_at": "2026-02-05T12:00:00Z", "action": "delivered",
            "queue_id": "Q-20"}
        check(read_jsonl(os.path.join(out, DSN_JSONL)) == [expected_record],
              "unsupported_addr_type: record mismatch")
        quarantine = read_jsonl(os.path.join(out, QUARANTINE_JSONL))
        check(quarantine[0]["category"] == "unsupported_address_type"
              and quarantine[0]["detail"] ==
              "address type 'x400' is not supported",
              f"unsupported_addr_type: quarantine mismatch:\n{quarantine}")

        # valid base64-encoded delivery-status part
        files = SAMPLES["base64_dsn"]
        raw = files["encoded.eml"]
        rid = "rpt-" + sha(raw)
        input_dir = make_input(os.path.join(workdir, "b64"), files)
        summary, out = convert(input_dir, os.path.join(workdir, "b64"))
        check(summary["records"] == 1, "base64_dsn: 1 record")
        expected_record = {
            "gateway_id": GATEWAY, "report_id": rid, "item_id": "item-0",
            "recipient": "jack@example.com",
            "occurred_at": "2026-02-06T13:00:00Z", "action": "failed",
            "queue_id": "Q-30"}
        check(read_jsonl(os.path.join(out, DSN_JSONL)) == [expected_record],
              "base64_dsn: record mismatch")

        # a well-formed report with no recipient blocks: nothing to emit
        files = SAMPLES["no_recipients"]
        input_dir = make_input(os.path.join(workdir, "nr"), files)
        summary, out = convert(input_dir, os.path.join(workdir, "nr"))
        check(summary["records"] == 0 and summary["quarantined_blocks"] == 0
              and summary["failed_messages"] == 0,
              "no_recipients: parsed but empty")
        manifest = read_jsonl(os.path.join(out, MANIFEST_JSONL))
        check(manifest[1]["status"] == "parsed"
              and manifest[1]["blocks"] == [],
              "no_recipients: message entry")
        check(manifest[1]["context"]["reporting-mta"]
              == ["dns; gw1.example.com"],
              "no_recipients: context")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 6. field-level rules, each checked against hand-computed outcomes
# --------------------------------------------------------------------------- #
def _wrap(dsn_body, *, cte=None, charset=None):
    lines = [b"Content-Type: multipart/report; report-type=delivery-status;"
             b" boundary=b", b""]
    part_type = b"Content-Type: message/delivery-status"
    if charset:
        part_type += b'; charset="' + charset + b'"'
    lines += [b"--b", part_type]
    if cte:
        lines.append(b"Content-Transfer-Encoding: " + cte)
    lines += [b"", dsn_body, b"--b--", b""]
    return b"\r\n".join(lines)


def _one_block_outcome(dsn_body, *, cte=None, charset=None):
    """Parse a one-recipient-block report; return ('record', record) or
    ('quarantine', category, detail)."""
    from receipt_ledger.dsnmime import RecipientRecord, parse_message
    parsed = parse_message(_wrap(dsn_body, cte=cte, charset=charset),
                           gateway_id=GATEWAY)
    check(len(parsed.outcomes) == 1, "expected exactly one recipient block")
    outcome = parsed.outcomes[0]
    if isinstance(outcome, RecipientRecord):
        return ("record", outcome.record)
    return ("quarantine", outcome.category, outcome.detail)


def test_field_level_rules():
    head = b"Reporting-MTA: dns; g\n\n"
    base = (b"Final-Recipient: rfc822; a@b.cd\n"
            b"Action: failed\n"
            b"Status: 5.1.1\n"
            b"Last-Attempt-Date: Tue, 03 Feb 2026 10:00:00 +0000\n"
            b"X-Queue-ID: Q1\n")

    # identical repeated fields are unambiguous and accepted
    kind, record = _one_block_outcome(
        head + b"Final-Recipient: rfc822; a@b.cd\n" + base)
    check(kind == "record" and record["recipient"] == "a@b.cd",
          "identical duplicate fields must be accepted")

    # Final-Recipient wins over Original-Recipient (documented precedence)
    kind, record = _one_block_outcome(
        head + b"Original-Recipient: rfc822; orig@b.cd\n"
        + base.replace(b"Final-Recipient: rfc822; a@b.cd\n",
                       b"Final-Recipient: rfc822; final@b.cd\n"))
    check(kind == "record" and record["recipient"] == "final@b.cd",
          "Final-Recipient must win over Original-Recipient")

    # action token is case-insensitive
    kind, record = _one_block_outcome(
        head + base.replace(b"Action: failed", b"Action: FAILED"))
    check(kind == "record" and record["action"] == "failed",
          "action token must be case-insensitive")

    # occurred_at is never guessed from message-level Arrival-Date
    kind, category, detail = _one_block_outcome(
        b"Reporting-MTA: dns; g\nArrival-Date: Tue, 03 Feb 2026 08:00:00 +0000\n\n"
        + base.replace(b"Last-Attempt-Date: Tue, 03 Feb 2026 10:00:00 +0000\n",
                       b""))
    check((kind, category) == ("quarantine", "missing_field"),
          "missing Last-Attempt-Date must quarantine, not fall back to "
          "message-level context")

    # an envelope-only condition satisfies the ledger's matching rule
    kind, record = _one_block_outcome(
        head + base.replace(b"X-Queue-ID: Q1\n", b"X-Envelope-ID: E-1\n"))
    check(kind == "record" and record == {
        "gateway_id": GATEWAY, "report_id": record["report_id"],
        "item_id": "item-0", "recipient": "a@b.cd",
        "occurred_at": "2026-02-03T10:00:00Z", "action": "failed",
        "envelope_id": "E-1"}, "envelope-only condition must convert")

    # a non-ASCII address is quarantined, never coerced (the part declares
    # utf-8, so the bytes decode and the address rule is what rejects it)
    kind, category, detail = _one_block_outcome(
        head + base.replace(b"a@b.cd", "ü@b.cd".encode("utf-8")),
        cte=b"8bit", charset=b"utf-8")
    check((kind, category) == ("quarantine", "unsupported_address"),
          "non-ASCII address must be quarantined")
    # the same bytes without a charset declaration fail the whole report
    from receipt_ledger.dsnmime import ReportFailure, parse_message
    try:
        parse_message(_wrap(head + base.replace(
            b"a@b.cd", "ü@b.cd".encode("utf-8")), cte=b"8bit"),
            gateway_id=GATEWAY)
        raise AssertionError("undeclared 8bit content must fail the report")
    except ReportFailure as exc:
        check(exc.category == "charset_decode",
              f"undeclared 8bit category: {exc.category}")

    # conflicting repeated actions quarantine the block
    kind, category, detail = _one_block_outcome(
        head + base.replace(b"Action: failed\n",
                            b"Action: failed\nAction: delivered\n"))
    check((kind, category) == ("quarantine", "conflicting_fields"),
          "conflicting duplicate actions must quarantine")

    # quoted-printable: valid part decodes, corrupt escape fails the report
    qp = (b"Reporting-MTA: dns; g\n\nFinal-Recipient: rfc822; a@b.cd\n"
          b"Action: failed\nStatus: 5.1.1\n"
          b"Last-Attempt-Date: Tue, 03 Feb 2026 10:00:00 +0000\n"
          b"X-Queue-ID: Q=31\n")
    kind, record = _one_block_outcome(qp, cte=b"quoted-printable")
    check(kind == "record" and record["queue_id"] == "Q1",
          "quoted-printable escapes must be decoded")
    try:
        parse_message(_wrap(qp.replace(b"Q=31", b"Q=ZZ"),
                            cte=b"quoted-printable"), gateway_id=GATEWAY)
        raise AssertionError("corrupt quoted-printable must fail the report")
    except ReportFailure as exc:
        check(exc.category == "transfer_encoding",
              f"corrupt qp category: {exc.category}")


# --------------------------------------------------------------------------- #
# 7. target path already exists: fail before writing, leave no half batch
# --------------------------------------------------------------------------- #
def test_output_exists_no_partial():
    workdir = tempfile.mkdtemp(prefix="arc-exists-")
    try:
        input_dir = make_input(workdir, SAMPLES["main"])
        out = os.path.join(workdir, "out")
        os.mkdir(out)
        sentinel = os.path.join(out, "SENTINEL")
        with open(sentinel, "w", encoding="utf-8") as handle:
            handle.write("keep me")
        expect_archive_error(
            lambda: convert_archive(input_dir, out, gateway_id=GATEWAY),
            code="output_exists", label="existing target")
        check(read_text(sentinel) == "keep me", "sentinel must be untouched")
        check(os.listdir(out) == ["SENTINEL"],
              "existing target must not gain any product file")
        check([n for n in os.listdir(workdir) if ".tmp-" in n] == [],
              "no temporary directory may be left behind")

        # an existing *file* at the target path is also refused
        file_target = os.path.join(workdir, "a-file")
        with open(file_target, "w", encoding="utf-8") as handle:
            handle.write("occupied")
        expect_archive_error(
            lambda: convert_archive(input_dir, file_target,
                                    gateway_id=GATEWAY),
            code="output_exists", label="file at target")
        check(read_text(file_target) == "occupied", "file target untouched")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 7. input failures: nothing is published
# --------------------------------------------------------------------------- #
def test_input_failures():
    workdir = tempfile.mkdtemp(prefix="arc-input-")
    try:
        out = os.path.join(workdir, "out")
        expect_archive_error(
            lambda: convert_archive(os.path.join(workdir, "missing"), out,
                                    gateway_id=GATEWAY),
            code="input_not_found", label="missing input dir")
        check(not os.path.lexists(out), "no target may appear")

        expect_archive_error(
            lambda: convert_archive(os.path.join(FIXTURES, "main", "eml"),
                                    os.path.join(workdir, "no-parent", "x"),
                                    gateway_id=GATEWAY),
            code="output_error", label="missing output parent")

        if hasattr(os, "geteuid") and os.geteuid() != 0:
            input_dir = make_input(workdir, SAMPLES["main"])
            victim = os.path.join(input_dir, "bounce.eml")
            os.chmod(victim, 0)
            try:
                expect_archive_error(
                    lambda: convert_archive(input_dir, out,
                                            gateway_id=GATEWAY),
                    code="input_error", label="unreadable input file")
                check(not os.path.lexists(out),
                      "unreadable input: no target may appear")
            finally:
                os.chmod(victim, 0o644)

        # an empty input directory is a valid, empty batch
        empty_in = os.path.join(workdir, "empty")
        os.mkdir(empty_in)
        summary, out = convert(empty_in, workdir)
        check(summary["records"] == 0 and summary["messages"] == 0,
              "empty dir: zero counts")
        check(read_text(os.path.join(out, DSN_JSONL)) == "",
              "empty dir: empty dsn.jsonl")
        manifest = read_jsonl(os.path.join(out, MANIFEST_JSONL))
        check(len(manifest) == 1 and manifest[0]["type"] == "run",
              "empty dir: manifest holds only the run entry")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 8. determinism: re-runs and directory-order permutations change nothing
# --------------------------------------------------------------------------- #
def test_determinism():
    workdir = tempfile.mkdtemp(prefix="arc-det-")
    try:
        files = {"b.eml": SAMPLES["main"]["bounce.eml"],
                 "a.eml": SAMPLES["mixed"]["mixed.eml"],
                 "sub/c.eml": SAMPLES["base64_dsn"]["encoded.eml"]}
        input_dir = make_input(os.path.join(workdir, "one"), files)
        _, out1 = convert(input_dir, workdir, name="out1")

        # same input, second run to a fresh target: byte-identical products
        _, out2 = convert(input_dir, workdir, name="out2")
        for name in (DSN_JSONL, QUARANTINE_JSONL, MANIFEST_JSONL):
            check(read_text(os.path.join(out1, name))
                  == read_text(os.path.join(out2, name)),
                  f"determinism: {name} differs between identical runs")

        # re-running onto an existing target is refused
        expect_archive_error(
            lambda: convert_archive(input_dir, out1, gateway_id=GATEWAY),
            code="output_exists", label="re-run onto existing target")

        # rebuild the same file set in a second directory, writing files in
        # the opposite order: enumeration order must not change any product
        input_dir2 = os.path.join(workdir, "in2")
        for rel in ("sub/c.eml", "b.eml", "a.eml"):
            path = os.path.join(input_dir2, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(files[rel])
        summary3, out3 = convert(input_dir2, workdir, name="out3")
        check(summary3["records"] == 3 + 2 + 1,
              "determinism: record count across three files")
        check(read_text(os.path.join(out1, DSN_JSONL))
              == read_text(os.path.join(out3, DSN_JSONL)),
              "determinism: dsn.jsonl must not depend on creation order")
        check(read_text(os.path.join(out1, QUARANTINE_JSONL))
              == read_text(os.path.join(out3, QUARANTINE_JSONL)),
              "determinism: quarantine.jsonl must not depend on order")
        # manifest differs only in the recorded input_dir string
        man1 = read_jsonl(os.path.join(out1, MANIFEST_JSONL))
        man3 = read_jsonl(os.path.join(out3, MANIFEST_JSONL))
        check(man1[1:] == man3[1:],
              "determinism: message/record provenance must be identical")
        run1, run3 = dict(man1[0]), dict(man3[0])
        run1.pop("input_dir")
        run3.pop("input_dir")
        check(run1 == run3, "determinism: run entries apart from input_dir")

        # per-file block order and provenance survive the permutation:
        # records are grouped by sorted relative path a.eml, b.eml, sub/c.eml
        records = read_jsonl(os.path.join(out3, DSN_JSONL))
        check([r["report_id"] for r in records]
              == [MIXED_RID] * 2 + [MAIN_RID] * 3
              + ["rpt-" + sha(SAMPLES["base64_dsn"]["encoded.eml"])],
              "determinism: files must be processed in sorted path order")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 9. identical content in two files: provenance is never merged across files
# --------------------------------------------------------------------------- #
def test_identical_content_two_files():
    workdir = tempfile.mkdtemp(prefix="arc-dup-")
    try:
        files = {"a.eml": MAIN_BYTES, "b.eml": MAIN_BYTES}
        input_dir = make_input(workdir, files)
        summary, out = convert(input_dir, workdir)
        check(summary["records"] == 6, "dup: 3 recipients x 2 files")
        records = read_jsonl(os.path.join(out, DSN_JSONL))
        check(records == MAIN_RECORDS + MAIN_RECORDS,
              "dup: identical content yields identical record lines")
        manifest = read_jsonl(os.path.join(out, MANIFEST_JSONL))
        messages = [e for e in manifest if e.get("type") == "message"]
        check([m["file"] for m in messages] == ["a.eml", "b.eml"],
              "dup: one message entry per file")
        check(messages[0]["message_index"] == 0
              and messages[1]["message_index"] == 1,
              "dup: message indices follow sorted file order")
        check(messages[0]["file_sha256"] == messages[1]["file_sha256"]
              == MAIN_SHA, "dup: same content, same file hash")
        record_entries = [e for e in manifest if e.get("type") == "record"]
        check(len(record_entries) == 6, "dup: six record entries")
        for k, entry in enumerate(record_entries):
            expected_message = 0 if k < 3 else 1
            check(entry["message_index"] == expected_message
                  and entry["file"] == ("a.eml" if k < 3 else "b.eml")
                  and entry["block_index"] == k % 3
                  and entry["parse_digest"] == MAIN_DIGEST,
                  f"dup: record {k} points at the wrong source message")

        # the ledger dedups identical rows; provenance stays per-file
        ledger = Ledger.create()
        outcome = ledger.import_dsn(
            read_text(os.path.join(out, DSN_JSONL)).encode("utf-8"))
        check(outcome["inserted"] == 3 and outcome["duplicate_rows"] == 3,
              f"dup: ledger dedup of identical rows: {outcome}")
        ledger.close()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 10. same file name, changed content: the old identity cannot impersonate
# --------------------------------------------------------------------------- #
def test_same_name_changed_content():
    workdir = tempfile.mkdtemp(prefix="arc-changed-")
    try:
        changed = MAIN_BYTES.replace(b"QUEUE-9", b"QUEUE-99")
        check(changed != MAIN_BYTES, "changed sample must differ")
        in1 = make_input(os.path.join(workdir, "one"), {"x.eml": MAIN_BYTES})
        _, out1 = convert(in1, os.path.join(workdir, "one"))
        in2 = make_input(os.path.join(workdir, "two"), {"x.eml": changed})
        _, out2 = convert(in2, os.path.join(workdir, "two"))

        man1 = read_jsonl(os.path.join(out1, MANIFEST_JSONL))
        man2 = read_jsonl(os.path.join(out2, MANIFEST_JSONL))
        check(man1[1]["file"] == man2[1]["file"] == "x.eml",
              "changed: same file name")
        check(man1[1]["file_sha256"] != man2[1]["file_sha256"],
              "changed: file hash must change with content")
        check(man1[1]["report_id"] != man2[1]["report_id"],
              "changed: report identity is content-derived")
        check(man1[1]["parse_digest"] != man2[1]["parse_digest"],
              "changed: parse digest must change with content")

        # both batches import cleanly: distinct identities, no impersonation
        ledger = Ledger.create()
        first = ledger.import_dsn(
            read_text(os.path.join(out1, DSN_JSONL)).encode("utf-8"))
        second = ledger.import_dsn(
            read_text(os.path.join(out2, DSN_JSONL)).encode("utf-8"))
        check(first["inserted"] == 3 and second["inserted"] == 3,
              "changed: old and new content coexist as distinct receipts")
        rows = ledger.conn.execute(
            "SELECT DISTINCT queue_id FROM dsn_line ORDER BY queue_id"
        ).fetchall()
        queues = {r[0] for r in rows}
        check({"QUEUE-9", "QUEUE-99", "QUEUE-10", "QUEUE-11"} <= queues,
              "changed: both queue identities present")
        ledger.close()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 11. end to end: the ledger is driven only by the independent import step
# --------------------------------------------------------------------------- #
def test_ledger_end_to_end():
    workdir = tempfile.mkdtemp(prefix="arc-e2e-")
    try:
        in_main = os.path.join(FIXTURES, "main", "eml")
        in_mixed = os.path.join(FIXTURES, "mixed", "eml")
        _, out_main = convert(in_main, workdir, name="out-main")
        _, out_mixed = convert(in_mixed, workdir, name="out-mixed")
        # the conversion wrote no database of any kind
        for root, _, names in os.walk(workdir):
            for name in names:
                check(not name.endswith((".sqlite", ".sqlite-wal",
                                         ".sqlite-shm")),
                      f"convert-archive must not create ledger state: {name}")

        ledger = Ledger.create()
        try:
            summary0 = ledger.explain_summary()
            check(summary0["deliveries_total"] == 0,
                  "e2e: ledger starts empty; conversion touched nothing")

            ledger.import_outbound(jsonl(
                outbound(GATEWAY, "D-1", "att-1", "Alice@example.com",
                         "2026-02-01T00:00:00Z", queue="QUEUE-9"),
                outbound(GATEWAY, "D-2", "att-1", "bob@example.net",
                         "2026-02-01T00:00:00Z", queue="QUEUE-10",
                         envelope="ENV-B"),
                outbound(GATEWAY, "D-3", "att-1", "carol@example.org",
                         "2026-02-01T00:00:00Z", queue="QUEUE-11"),
                outbound(GATEWAY, "D-4", "att-1", "dave@example.com",
                         "2026-02-01T00:00:00Z", queue="Q-1"),
                outbound(GATEWAY, "D-5", "att-1", "frank@example.com",
                         "2026-02-01T00:00:00Z", queue="Q-3"),
                outbound(GATEWAY, "D-6", "att-1", "erin@example.com",
                         "2026-02-01T00:00:00Z", queue="Q-2"),
            ))
            dsn_main = read_text(os.path.join(out_main, DSN_JSONL))
            dsn_mixed = read_text(os.path.join(out_mixed, DSN_JSONL))
            first = ledger.import_dsn(dsn_main.encode("utf-8"))
            check(first["inserted"] == 3, f"e2e: main import: {first}")
            second = ledger.import_dsn(dsn_mixed.encode("utf-8"))
            check(second["inserted"] == 2, f"e2e: mixed import: {second}")

            expectations = {
                "D-1": ("Alice@example.com", "delivered"),
                "D-2": ("bob@example.net", "failed"),
                "D-3": ("carol@example.org", "delayed"),
                "D-4": ("dave@example.com", "delivered"),
                "D-5": ("frank@example.com", "failed"),
                "D-6": ("erin@example.com", "awaiting"),  # block quarantined
            }
            for delivery, (recipient, status) in expectations.items():
                got = ledger.delivery_status(GATEWAY, delivery,
                                             recipient)["status"]
                check(got == status,
                      f"e2e: {delivery}/{recipient}: expected {status}, "
                      f"got {got}")
            summary = ledger.explain_summary()
            check(summary["delivery_counts"] == {
                "awaiting": 1, "delayed": 1, "delivered": 2, "failed": 2,
                "inconsistent": 0}, f"e2e: summary: {summary['delivery_counts']}")
            check(summary["proven_delivered"] == 2, "e2e: proven count")

            # a byte-identical re-import is a no-op: replayability
            again = ledger.import_dsn(dsn_main.encode("utf-8"))
            check(again["skipped"] is True and again["inserted"] == 0,
                  "e2e: re-importing the same file is a no-op")
        finally:
            ledger.close()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 12. the re-runnable command line
# --------------------------------------------------------------------------- #
def test_cli_end_to_end():
    workdir = tempfile.mkdtemp(prefix="arc-cli-")
    try:
        out = os.path.join(workdir, "out")
        db = os.path.join(workdir, "ledger.sqlite")
        input_dir = os.path.join(FIXTURES, "main", "eml")

        def run_cli(*argv):
            return subprocess.run(
                [sys.executable, "-m", "receipt_ledger.cli", *argv],
                cwd=ROOT, capture_output=True, text=True)

        proc = run_cli("convert-archive", input_dir, out, "--gateway", GATEWAY)
        check(proc.returncode == 0, f"cli convert: {proc.stderr}{proc.stdout}")
        summary = json.loads(proc.stdout)
        check(summary["records"] == 3, "cli convert: 3 records")

        # re-running onto the existing target fails and changes nothing
        proc = run_cli("convert-archive", input_dir, out, "--gateway", GATEWAY)
        check(proc.returncode == 2, "cli re-run: must fail")
        check(json.loads(proc.stdout)["code"] == "output_exists",
              "cli re-run: output_exists")
        check(sorted(os.listdir(out)) == sorted(
            [DSN_JSONL, QUARANTINE_JSONL, MANIFEST_JSONL]),
            "cli re-run: products untouched")

        proc = run_cli("init", db)
        check(proc.returncode == 0, f"cli init: {proc.stderr}")
        proc = run_cli("import-dsn", db, os.path.join(out, DSN_JSONL))
        check(proc.returncode == 0, f"cli import-dsn: {proc.stderr}")
        outcome = json.loads(proc.stdout)
        check(outcome["inserted"] == 3, f"cli import: {outcome}")
        proc = run_cli("summary", db)
        counts = json.loads(proc.stdout)["delivery_counts"]
        check(counts["delivered"] == 0 and counts["failed"] == 0
              and counts["delayed"] == 0,
              "cli: receipts without outbound rows stay unmatched, "
              "never guessed")
        pending = json.loads(run_cli("pending", db).stdout)
        unmatched = [e for e in pending if e["category"] == "unmatched"]
        check(len(unmatched) == 3,
              f"cli: three unmatched receipts: {pending}")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


ALL_TESTS = [
    test_fixtures_fresh,
    test_main_sample,
    test_mixed_blocks,
    test_report_level_failures,
    test_block_level_cases,
    test_field_level_rules,
    test_output_exists_no_partial,
    test_input_failures,
    test_determinism,
    test_identical_content_two_files,
    test_same_name_changed_content,
    test_ledger_end_to_end,
    test_cli_end_to_end,
]


def main():
    for test in ALL_TESTS:
        test()
        print(f"ok {test.__name__}")
    print("all archive-import acceptance tests passed")


if __name__ == "__main__":
    main()
