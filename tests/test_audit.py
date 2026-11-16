"""Acceptance suite for ``audit-archive-import``.

Every expectation is hand-written from the archive package itself and from an
independently built ledger.  The audit's own per-record verdicts are never used
as their own expectation: expected identities, block numbers, quarantine
states and import provenance are literals in this file, and the ledger is
inspected with plain SQL to confirm the audit did not change it.

Run: python3 -I tests/test_audit.py
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

from receipt_ledger import Ledger, convert_archive  # noqa: E402
from receipt_ledger.audit import audit_archive_import  # noqa: E402
from tests.archive_samples import SAMPLES  # noqa: E402
from tests.helpers import check, jsonl, outbound  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "fixtures", "archive")
GATEWAY = "gw-main"

# --------------------------------------------------------------------------- #
# hand-computed expectations for the mixed sample
# --------------------------------------------------------------------------- #
# fixtures/archive/mixed/eml/mixed.eml has three recipient blocks:
#   block 0  dave@example.com   delivered   Q-1   -> valid record
#   block 1  erin@example.com   failed/2.1.5      -> quarantined
#   block 2  frank@example.com  failed      Q-3   -> valid record
MIXED_BYTES = SAMPLES["mixed"]["mixed.eml"]
MIXED_SHA = hashlib.sha256(MIXED_BYTES).hexdigest()
MIXED_REPORT = "rpt-" + MIXED_SHA

MIXED_EXPECTED = [
    {"block_index": 0, "item_id": "item-0", "recipient": "dave@example.com",
     "action": "delivered", "occurred_at": "2026-02-04T10:00:00Z",
     "queue_id": "Q-1"},
    {"block_index": 2, "item_id": "item-2", "recipient": "frank@example.com",
     "action": "failed", "occurred_at": "2026-02-04T10:02:00Z",
     "queue_id": "Q-3"},
]
MIXED_QUARANTINED_BLOCK = 1


def _sha(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def read_jsonl(path):
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def read_text(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def write_jsonl(path, rows, sort_keys=True):
    text = "".join(json.dumps(row, sort_keys=sort_keys,
                              separators=(",", ":"),
                              ensure_ascii=False) + "\n" for row in rows)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return text


def rewrite_run_digest(out, name):
    """Rewrite the run entry's declared digest for one product file.

    Used only to construct a *tampered* package; it never repairs anything
    else, so any remaining inconsistency is the package's own.
    """
    manifest = read_jsonl(os.path.join(out, "manifest.jsonl"))
    run = manifest[0]
    path = os.path.join(out, name)
    run["outputs"][name] = {"sha256": _sha(path),
                            "lines": len(read_text(path).splitlines())}
    write_jsonl(os.path.join(out, "manifest.jsonl"), manifest)


class Workdir:
    def __init__(self):
        self.path = tempfile.mkdtemp(prefix="audit-archive-test-")

    def child(self, *parts):
        return os.path.join(self.path, *parts)

    def archive(self, name="out", case="mixed", gateway=GATEWAY):
        output_dir = self.child(name)
        convert_archive(os.path.join(FIXTURES, case, "eml"), output_dir,
                        gateway_id=gateway)
        return output_dir

    def ledger(self, name="ledger.sqlite"):
        return self.child(name)

    def cleanup(self):
        shutil.rmtree(self.path, ignore_errors=True)


def import_dsn_file(db, path, source=None):
    """Import exactly as the operational command does; return the outcome."""
    ledger = Ledger.open(db) if os.path.exists(db) else Ledger.create(db)
    try:
        with open(path, "rb") as handle:
            data = handle.read()
        return ledger.import_dsn(data, source=source or path)
    finally:
        ledger.close()


def write_outbound(db, rows):
    ledger = Ledger.open(db)
    try:
        return ledger.import_outbound(jsonl(*rows))
    finally:
        ledger.close()


def snapshot_facts(db):
    """Every fact-layer row, ids included, as plain tuples."""
    conn = __import__("sqlite3").connect(db)
    try:
        out = {}
        for table, columns in (
                ("import_file", "*"),
                ("gateway", "*"),
                ("outbound_attempt", "*"),
                ("dsn_line", "*"),
                ("correction_line", "*"),
                ("manual_decision", "*")):
            out[table] = [tuple(row) for row in conn.execute(
                f"SELECT {columns} FROM {table} ORDER BY id")]
        return out
    finally:
        conn.close()


def by_identity(report):
    return {(item["business_identity"]["report_id"],
             item["business_identity"]["item_id"]): item
            for item in report["records"]}


def expect_audit_error(code, fn):
    from receipt_ledger.audit import AuditError
    try:
        fn()
    except AuditError as exc:
        check(exc.code == code,
              f"expected audit error {code!r}, got {exc.code!r}: {exc}")
        return exc
    raise AssertionError(f"expected AuditError {code!r}, nothing raised")


# --------------------------------------------------------------------------- #
# 1. the normal daily flow: convert, import, then reconcile every receipt
# --------------------------------------------------------------------------- #
def test_basic_batch_is_verified_with_sources():
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        outcome = import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        check(outcome["inserted"] == 2,
              f"hand expectation: 2 valid receipts, got {outcome}")

        report = audit_archive_import(db, out)
        check(report["package"]["valid"] is True,
              f"package problems: {report['package']['problems']}")
        check(report["outcome"] == "verified" and report["verified"] is True,
              f"expected verified, got {report['outcome']}: {report['issues']}")
        check(report["exit_code"] == 0, "verified must exit 0")

        # hand-written expectation of every valid receipt and its coordinates
        expected = [(entry["item_id"], entry["block_index"],
                     entry["recipient"], entry["action"],
                     entry["occurred_at"], entry["queue_id"])
                    for entry in MIXED_EXPECTED]
        got = [(item["business_identity"]["item_id"],
                item["source"]["block_index"], item["record"]["recipient"],
                item["record"]["action"], item["record"]["occurred_at"],
                item["record"].get("queue_id")) for item in report["records"]]
        check(got == expected, f"receipt rows mismatch:\n got={got}\n"
                               f"exp={expected}")
        for item in report["records"]:
            check(item["business_identity"]["gateway_id"] == GATEWAY,
                  "audit lost the gateway identity")
            check(item["business_identity"]["report_id"] == MIXED_REPORT,
                  "audit lost the content-derived report identity")
            check(item["source"]["file"] == "mixed.eml",
                  "audit lost the relative source path")
            check(item["source"]["file_sha256"] == MIXED_SHA,
                  "audit lost the file digest")
            check(item["result"] == "imported_by_this_batch",
                  f"expected this-batch provenance, got {item}")
            check(isinstance(item["ledger_fact"]["import_file"]["id"], int)
                  and item["ledger_fact"]["import_file"]["id"] > 0,
                  "the fact's import file must be a concrete row")
            check(item["ledger_fact"]["import_file"]["kind"] == "dsn",
                  "the fact's import file must be a receipt file")

        # the quarantined block is reported, is not expected, and is not a miss
        check(len(report["quarantine"]) == 1,
              f"expected one quarantined block: {report['quarantine']}")
        quarantine = report["quarantine"][0]
        check(quarantine["source"]["block_index"]
              == MIXED_QUARANTINED_BLOCK, "quarantine points at the wrong "
              "block")
        check(quarantine["source"]["file"] == "mixed.eml"
              and quarantine["source"]["file_sha256"] == MIXED_SHA,
              "quarantine lost its source coordinates")
        check(quarantine["expected_in_ledger"] is False,
              "a quarantined block must never be expected in the ledger")
        check(quarantine["kind"] == "block", "quarantine entry kind")
        check(report["summary"]["quarantined_blocks"] == 1,
              "quarantine tally")
        check(report["summary"]["missing"] == 0
              and not any(i["kind"] == "missing_fact"
                          for i in report["issues"]),
              "a quarantined block must not be reported as a missing import")
        check(report["summary"]["imported_by_this_batch"] == 2,
              "summary provenance count")
    finally:
        work.cleanup()


def test_original_eml_may_be_offline():
    """The audit must not need the .eml files; the manifest is provenance."""
    work = Workdir()
    try:
        source = work.child("eml_in")
        os.makedirs(source)
        for name in os.listdir(os.path.join(FIXTURES, "mixed", "eml")):
            shutil.copy(os.path.join(FIXTURES, "mixed", "eml", name),
                        os.path.join(source, name))
        out = work.child("out")
        convert_archive(source, out, gateway_id=GATEWAY)
        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        shutil.rmtree(source)  # the original bytes are gone
        report = audit_archive_import(db, out)
        check(report["outcome"] == "verified",
              f"offline originals must not matter: {report['issues']}")
    finally:
        work.cleanup()


# --------------------------------------------------------------------------- #
# 2. a fact that was already imported from another file is a dedup, not a miss
# --------------------------------------------------------------------------- #
def test_deduplicated_earlier_import_is_not_missing():
    work = Workdir()
    try:
        out = work.child("out")
        input_dir = work.child("in")
        os.makedirs(input_dir)
        shutil.copy(os.path.join(FIXTURES, "mixed", "eml", "mixed.eml"),
                    os.path.join(input_dir, "mixed.eml"))
        convert_archive(input_dir, out, gateway_id=GATEWAY)
        db = work.ledger()
        Ledger.create(db).close()

        # one of the two receipts arrives first through an unrelated file
        first_row = {
            "gateway_id": GATEWAY, "report_id": MIXED_REPORT,
            "item_id": "item-0", "recipient": "dave@example.com",
            "occurred_at": "2026-02-04T10:00:00Z", "action": "delivered",
            "queue_id": "Q-1"}
        early = work.child("early.jsonl")
        write_jsonl(early, [first_row])
        early_outcome = import_dsn_file(db, early)
        check(early_outcome["inserted"] == 1, "early import must add the fact")
        early_sha = _sha(early)

        batch_outcome = import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        check(batch_outcome["inserted"] == 1
              and batch_outcome["duplicate_rows"] == 1,
              f"the batch must insert one row and dedup the other: "
              f"{batch_outcome}")

        report = audit_archive_import(db, out)
        items = by_identity(report)
        dedup = items[(MIXED_REPORT, "item-0")]
        fresh = items[(MIXED_REPORT, "item-2")]
        check(dedup["result"] == "deduplicated_existing",
              f"item-0 must be deduplicated_existing: {dedup}")
        check(dedup["ledger_fact"]["import_file"]["sha256"] == early_sha,
              "a deduplicated fact must still point at its original source")
        check(fresh["result"] == "imported_by_this_batch",
              f"item-2 must be this batch's provenance: {fresh}")
        check(report["outcome"] == "verified",
              f"an earlier identical import must not fail the audit: "
              f"{report['outcome']} {report['issues']}")
        check(report["summary"]["deduplicated_existing"] == 1
              and report["summary"]["missing"] == 0,
              "dedup must never be counted as missing")
    finally:
        work.cleanup()


# --------------------------------------------------------------------------- #
# 3. same valid-line count, one expected fact missing, one unrelated present
# --------------------------------------------------------------------------- #
def test_missing_and_unrelated_identities_are_both_reported():
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        # A ledger that registers the batch file but holds one unrelated
        # receipt instead of the expected one.  Line count matches by design.
        unrelated = {
            "gateway_id": GATEWAY, "report_id": MIXED_REPORT,
            "item_id": "item-9", "recipient": "mallory@example.com",
            "occurred_at": "2026-02-04T11:00:00Z", "action": "failed",
            "queue_id": "Q-9"}
        doctored = work.child("doctored.jsonl")
        write_jsonl(doctored, [
            unrelated,
            # item-2 is the expected receipt that *is* present
            {"gateway_id": GATEWAY, "report_id": MIXED_REPORT,
             "item_id": "item-2", "recipient": "frank@example.com",
             "occurred_at": "2026-02-04T10:02:00Z", "action": "failed",
             "queue_id": "Q-3"}])
        # Make the ledger's import_file row carry the batch's digest while its
        # facts are the doctored set.  This is the "same line count, one
        # expected fact absent, an unrelated fact present" case.
        ledger = Ledger.create(db)
        try:
            ledger.conn.execute(
                "INSERT INTO import_file (sha256, kind, source_name,"
                " line_count) VALUES (?,?,?,?)",
                (_sha(os.path.join(out, "dsn.jsonl")), "dsn",
                 os.path.join(out, "dsn.jsonl"), 2))
            file_id = ledger.conn.execute(
                "SELECT id FROM import_file WHERE sha256=?",
                (_sha(os.path.join(out, "dsn.jsonl")),)).fetchone()[0]
            gateway = ledger._gateway_row(
                __import__("receipt_ledger.ingest",
                           fromlist=["ingest"]).gateway_signature(GATEWAY))
            from receipt_ledger import ingest as ingest_mod
            for row in read_jsonl(doctored):
                parsed = ingest_mod.parse_dsn(row, "doctored")
                ledger.conn.execute(
                    "INSERT INTO dsn_line (gateway_row, report_id, report_sig,"
                    " item_id, item_sig, occurred_at_us, occurred_text,"
                    " action, recipient_sig, recipient_text, queue_sig,"
                    " queue_id, envelope_sig, envelope_id, canonical_hash,"
                    " import_file) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (gateway, parsed["report_id"], parsed["report_sig"],
                     parsed["item_id"], parsed["item_sig"],
                     parsed["occurred_at_us"], parsed["occurred_text"],
                     parsed["action"], parsed["recipient_sig"],
                     parsed["recipient"], parsed["queue_sig"],
                     parsed["queue_id"], parsed["envelope_sig"],
                     parsed["envelope_id"], ledger._dsn_hash(GATEWAY, parsed),
                     file_id))
            ledger.conn.commit()
        finally:
            ledger.close()

        report = audit_archive_import(db, out)
        check(report["outcome"] in ("incomplete", "conflict"),
              f"a doctored ledger must not verify: {report['outcome']}")
        check(report["exit_code"] != 0, "must exit non-zero")
        items = by_identity(report)
        check(items[(MIXED_REPORT, "item-0")]["result"] == "missing",
              f"the absent expected fact must be named missing: "
              f"{items[(MIXED_REPORT, 'item-0')]}")
        check(items[(MIXED_REPORT, "item-2")]["result"] ==
              "imported_by_this_batch",
              "the present expected fact must remain imported")
        extra_identities = {(extra["identity"]["report_id"],
                             extra["identity"]["item_id"])
                            for extra in report["unexpected_facts"]}
        check((MIXED_REPORT, "item-9") in extra_identities,
              f"the unrelated identity must be named as unexpected: "
              f"{report['unexpected_facts']}")
        issue_kinds = {issue["kind"] for issue in report["issues"]}
        check("missing_fact" in issue_kinds,
              f"a missing fact must be an explicit issue: {issue_kinds}")
        check(report["summary"]["missing"] == 1
              and report["summary"]["unexpected_facts_for_batch"] == 1,
              f"summary must separate the two: {report['summary']}")
    finally:
        work.cleanup()


# --------------------------------------------------------------------------- #
# 4. tampered package: output digest and manifest index
# --------------------------------------------------------------------------- #
def test_package_digest_tamper_is_invalid():
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        path = os.path.join(out, "dsn.jsonl")
        text = read_text(path)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text.replace('"Q-1"', '"Q-1-X"'))
        report = audit_archive_import(db, out)
        check(report["outcome"] == "invalid_package"
              and report["verified"] is False,
              f"a changed dsn.jsonl must invalidate the package: "
              f"{report['outcome']}")
        check(report["exit_code"] == 2, "invalid package must exit 2")
        codes = {problem["code"] for problem in report["package"]["problems"]}
        check("output_digest_mismatch" in codes,
              f"the digest mismatch must be named: {codes}")
    finally:
        work.cleanup()


def test_manifest_index_tamper_is_invalid():
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        manifest_path = os.path.join(out, "manifest.jsonl")
        manifest = read_jsonl(manifest_path)
        # swap the two record entries' block indexes: still two unique
        # records, but the provenance no longer matches the message blocks
        records = [entry for entry in manifest if entry["type"] == "record"]
        check(len(records) == 2, "expected two record entries")
        records[0]["block_index"], records[1]["block_index"] = (
            records[1]["block_index"], records[0]["block_index"])
        write_jsonl(manifest_path, manifest)
        report = audit_archive_import(db, out)
        check(report["outcome"] == "invalid_package",
              f"a misindexed manifest must invalidate the package: "
              f"{report['outcome']}")
        codes = {problem["code"] for problem in report["package"]["problems"]}
        check(codes & {"record_block_index_mismatch",
                       "record_item_id_mismatch",
                       "record_item_does_not_name_block",
                       "dsn_item_id_mismatch"},
              f"the index misalignment must be named: {codes}")
    finally:
        work.cleanup()


def test_duplicate_record_index_is_invalid():
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        manifest_path = os.path.join(out, "manifest.jsonl")
        manifest = read_jsonl(manifest_path)
        records = [entry for entry in manifest if entry["type"] == "record"]
        records[1]["record_index"] = records[0]["record_index"]
        write_jsonl(manifest_path, manifest)
        report = audit_archive_import(db, out)
        check(report["outcome"] == "invalid_package",
              "a duplicate record index must invalidate the package")
        codes = {problem["code"] for problem in report["package"]["problems"]}
        check(codes & {"record_index_out_of_order", "duplicate_record_index",
                       "record_indexes_do_not_cover_dsn"},
              f"duplicate index must be named: {codes}")
    finally:
        work.cleanup()


def test_reordered_manifest_entries_are_invalid():
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        manifest_path = os.path.join(out, "manifest.jsonl")
        manifest = read_jsonl(manifest_path)
        run, message = manifest[0], manifest[1]
        records = manifest[2:]
        # put the run last: a single run entry, but not first
        write_jsonl(manifest_path, [message] + records + [run])
        report = audit_archive_import(db, out)
        check(report["outcome"] == "invalid_package",
              "a run entry that is not first must invalidate the package")
        codes = {problem["code"] for problem in report["package"]["problems"]}
        check("run_not_first" in codes, f"run position must be named: {codes}")
    finally:
        work.cleanup()


def test_parse_digest_tamper_is_invalid():
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        manifest_path = os.path.join(out, "manifest.jsonl")
        manifest = read_jsonl(manifest_path)
        records = [entry for entry in manifest if entry["type"] == "record"]
        fake = "0" * 64
        for entry in manifest:
            if entry.get("parse_digest"):
                entry["parse_digest"] = fake
        write_jsonl(manifest_path, manifest)
        report = audit_archive_import(db, out)
        check(report["outcome"] == "invalid_package",
              "changed parse digests must invalidate the package")
        codes = {problem["code"] for problem in report["package"]["problems"]}
        check("parse_digest_mismatch" in codes,
              f"the recomputed digest mismatch must be named: {codes}")
    finally:
        work.cleanup()


# --------------------------------------------------------------------------- #
# 5. same identity, different content in the ledger
# --------------------------------------------------------------------------- #
def test_same_identity_different_content_is_conflict():
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        # Change one stored value behind the ledger's back, simulating a fact
        # that carries the same identity but other content.
        conn = __import__("sqlite3").connect(db)
        try:
            conn.execute(
                "UPDATE dsn_line SET action='delivered'"
                " WHERE report_id=? AND item_id='item-2'", (MIXED_REPORT,))
            conn.commit()
        finally:
            conn.close()
        report = audit_archive_import(db, out)
        check(report["outcome"] == "conflict" and report["verified"] is False,
              f"an identity/content conflict must not verify: "
              f"{report['outcome']}")
        check(report["exit_code"] != 0, "conflict must exit non-zero")
        items = by_identity(report)
        check(items[(MIXED_REPORT, "item-2")]["result"] == "conflict",
              f"the conflicting identity must be named: "
              f"{items[(MIXED_REPORT, 'item-2')]}")
        check("action" in items[(MIXED_REPORT, "item-2")]["conflicting_fields"],
              "the differing field must be named")
        check(items[(MIXED_REPORT, "item-0")]["result"] ==
              "imported_by_this_batch",
              "the untouched receipt must stay clean")
    finally:
        work.cleanup()


def test_identity_used_by_correction_is_conflict():
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        # Replace item-0's receipt fact with a correction that reuses the same
        # identity (a ledger that could only arise from a direct write, but the
        # audit must still refuse to call the expected receipt imported).
        conn = __import__("sqlite3").connect(db)
        try:
            from receipt_ledger import ingest as ingest_mod
            gw_row = conn.execute("SELECT id FROM gateway").fetchone()[0]
            conn.execute("DELETE FROM dsn_line WHERE report_id=? AND"
                         " item_id='item-0'", (MIXED_REPORT,))
            corr = {"gateway_id": GATEWAY, "report_id": MIXED_REPORT,
                    "item_id": "item-0", "target_report_id": "rpt-other",
                    "target_item_id": "item-0",
                    "occurred_at": "2026-02-04T12:00:00Z",
                    "action": "withdraw"}
            parsed = ingest_mod.parse_correction(corr, "handmade")
            file_id = conn.execute(
                "INSERT INTO import_file (sha256, kind, source_name,"
                " line_count) VALUES ('f'*64, 'corrections', 'x', 1)"
            ).lastrowid
            conn.execute(
                "INSERT INTO correction_line (gateway_row, report_id,"
                " report_sig, item_id, item_sig, target_report_id,"
                " target_report_sig, target_item_id, target_item_sig,"
                " occurred_at_us, occurred_text, action, recipient_sig,"
                " recipient_text, queue_sig, queue_id, envelope_sig,"
                " envelope_id, canonical_hash, import_file)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (gw_row, parsed["report_id"], parsed["report_sig"],
                 parsed["item_id"], parsed["item_sig"],
                 parsed["target_report_id"], parsed["target_report_sig"],
                 parsed["target_item_id"], parsed["target_item_sig"],
                 parsed["occurred_at_us"], parsed["occurred_text"],
                 parsed["action"], None, None, None, None, None, None,
                 Ledger._correction_hash(GATEWAY, parsed), file_id))
            conn.commit()
        finally:
            conn.close()
        report = audit_archive_import(db, out)
        items = by_identity(report)
        check(items[(MIXED_REPORT, "item-0")]["result"] == "conflict"
              and items[(MIXED_REPORT, "item-0")].get(
                  "conflicting_identity_kind") == "correction",
              f"an identity reused by a correction is a conflict: "
              f"{items[(MIXED_REPORT, 'item-0')]}")
        check(report["outcome"] == "conflict", "must not verify")
    finally:
        work.cleanup()


# --------------------------------------------------------------------------- #
# 6. the batch was never imported
# --------------------------------------------------------------------------- #
def test_unimported_batch_is_not_verified():
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        report = audit_archive_import(db, out)
        check(report["outcome"] == "incomplete",
              f"an unimported batch must be incomplete: {report['outcome']}")
        check(report["exit_code"] != 0, "must exit non-zero")
        check(all(item["result"] == "missing" for item in report["records"]),
              "every valid receipt must be missing")
        kinds = [issue["kind"] for issue in report["issues"]]
        check("batch_file_not_imported" in kinds,
              f"the unimported file must be named: {kinds}")
        check(report["ledger"]["batch_file_registered"] is False,
              "the report must say the batch file is not registered")
        check(len(report["quarantine"]) == 1,
              "quarantined blocks are still reported, not turned into misses")
        check(report["summary"]["missing"] == 2
              and report["summary"]["quarantined_blocks"] == 1,
              f"summary must separate missing receipts from quarantine: "
              f"{report['summary']}")
    finally:
        work.cleanup()


def test_unimported_batch_with_preexisting_identical_fact():
    """The fact exists but the file was never registered: not "imported"."""
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        # write the same two receipts through a different file
        other = work.child("other.jsonl")
        rows = []
        for entry in MIXED_EXPECTED:
            row = {"gateway_id": GATEWAY, "report_id": MIXED_REPORT,
                   "item_id": entry["item_id"],
                   "recipient": entry["recipient"],
                   "occurred_at": entry["occurred_at"],
                   "action": entry["action"],
                   "queue_id": entry["queue_id"]}
            rows.append(row)
        write_jsonl(other, rows, sort_keys=False)
        check(_sha(other) != _sha(os.path.join(out, "dsn.jsonl")),
              "the other file must carry a different digest")
        import_dsn_file(db, other)
        report = audit_archive_import(db, out)
        check(report["outcome"] == "incomplete",
              f"the batch file itself is not registered: {report['outcome']}")
        check(all(item["result"] == "present_but_file_not_imported"
                  for item in report["records"]),
              f"facts present, file unimported: "
              f"{[i['result'] for i in report['records']]}")
        kinds = [issue["kind"] for issue in report["issues"]]
        check("batch_file_not_imported" in kinds and "file_not_imported" in kinds,
              f"both must be named: {kinds}")
    finally:
        work.cleanup()


# --------------------------------------------------------------------------- #
# 7. same file name is not the same batch
# --------------------------------------------------------------------------- #
def test_same_name_different_digest_is_not_a_batch_match():
    work = Workdir()
    try:
        out_a = work.child("out_a")
        input_a = work.child("in_a")
        os.makedirs(input_a)
        shutil.copy(os.path.join(FIXTURES, "mixed", "eml", "mixed.eml"),
                    os.path.join(input_a, "mixed.eml"))
        convert_archive(input_a, out_a, gateway_id=GATEWAY)

        # a second, changed message exported under the same file name
        source_b = work.child("in_b")
        os.makedirs(source_b)
        changed = SAMPLES["mixed"]["mixed.eml"].replace(b"Q-3", b"Q-33")
        with open(os.path.join(source_b, "mixed.eml"), "wb") as handle:
            handle.write(changed)
        out_b = work.child("out_b")
        convert_archive(source_b, out_b, gateway_id=GATEWAY)

        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out_a, "dsn.jsonl"))
        report = audit_archive_import(db, out_b)
        check(report["outcome"] == "incomplete",
              f"the other batch must not satisfy this one: "
              f"{report['outcome']}")
        check(all(item["result"] == "missing" for item in report["records"]),
              "different content cannot satisfy the changed identities")
        kinds = [issue["kind"] for issue in report["issues"]]
        check("same_name_other_digest" in kinds,
              f"the same-name/different-digest fact must be named: {kinds}")
    finally:
        work.cleanup()


# --------------------------------------------------------------------------- #
# 8. quarantine is not a missed import, even if the identity exists
# --------------------------------------------------------------------------- #
def test_quarantine_identity_coincidence_is_not_imported():
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        # Put an unrelated row in the ledger under the quarantined block's
        # identity.  The audit must not call the quarantined block imported.
        conn = __import__("sqlite3").connect(db)
        try:
            from receipt_ledger import ingest as ingest_mod
            gw_row = conn.execute("SELECT id FROM gateway").fetchone()[0]
            row = {"gateway_id": GATEWAY, "report_id": MIXED_REPORT,
                   "item_id": f"item-{MIXED_QUARANTINED_BLOCK}",
                   "recipient": "someone-else@example.com",
                   "occurred_at": "2026-02-04T10:01:00Z",
                   "action": "failed", "queue_id": "Q-2"}
            parsed = ingest_mod.parse_dsn(row, "manual")
            file_id = conn.execute(
                "INSERT INTO import_file (sha256, kind, source_name,"
                " line_count) VALUES ('e'*64, 'dsn', 'unrelated', 1)"
            ).lastrowid
            conn.execute(
                "INSERT INTO dsn_line (gateway_row, report_id, report_sig,"
                " item_id, item_sig, occurred_at_us, occurred_text, action,"
                " recipient_sig, recipient_text, queue_sig, queue_id,"
                " envelope_sig, envelope_id, canonical_hash, import_file)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (gw_row, parsed["report_id"], parsed["report_sig"],
                 parsed["item_id"], parsed["item_sig"],
                 parsed["occurred_at_us"], parsed["occurred_text"],
                 parsed["action"], parsed["recipient_sig"],
                 parsed["recipient"], parsed["queue_sig"],
                 parsed["queue_id"], parsed["envelope_sig"],
                 parsed["envelope_id"], Ledger._dsn_hash(GATEWAY, parsed),
                 file_id))
            conn.commit()
        finally:
            conn.close()
        report = audit_archive_import(db, out)
        quarantine = report["quarantine"][0]
        check(quarantine["expected_in_ledger"] is False,
              "the quarantine entry is still not expected")
        check(quarantine["ledger_identity_present"]["dsn"] is True,
              "the coincidence must be recorded")
        check("unrelated ledger row" in quarantine["note"],
              "the coincidence must not be described as an import")
        check(len(report["records"]) == 2,
              "the coincidental row is not a valid receipt of this batch")
        check(not any(i["kind"] == "missing_fact" for i in report["issues"]),
              "the quarantined block must never become a missing receipt")
    finally:
        work.cleanup()


# --------------------------------------------------------------------------- #
# 9. report-level failures are summarised and not counted as receipts
# --------------------------------------------------------------------------- #
def test_failed_message_batch_reports_whole_messages():
    work = Workdir()
    try:
        out = work.archive(case="not_a_report")
        db = work.ledger()
        Ledger.create(db).close()
        report = audit_archive_import(db, out)
        check(report["package"]["valid"] is True,
              f"a clean report-level failure is a valid package: "
              f"{report['package']['problems']}")
        check(report["records"] == [], "no receipts may be invented")
        check(report["summary"]["failed_messages"] == 1,
              f"the failed message must be counted: {report['summary']}")
        check(len(report["quarantine"]) == 1
              and report["quarantine"][0]["kind"] == "message",
              "the whole-message failure must be listed")
        check(report["quarantine"][0]["source"]["block_index"] is None,
              "a report-level failure has no block index")
        check(report["outcome"] == "incomplete",
              "a batch with a failed message is not fully accounted for")
        kinds = [issue["kind"] for issue in report["issues"]]
        check("report_level_failure" in kinds,
              f"the report-level failure must be an issue: {kinds}")
    finally:
        work.cleanup()


# --------------------------------------------------------------------------- #
# 10. the audit never changes the ledger
# --------------------------------------------------------------------------- #
def test_audit_does_not_modify_the_ledger():
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        write_outbound(db, [outbound(GATEWAY, "D-1", "att-1",
                                     "dave@example.com",
                                     "2026-02-01T00:00:00Z", queue="Q-1")])
        before = snapshot_facts(db)
        before_stat = os.stat(db)
        audit_archive_import(db, out)
        audit_archive_import(db, out)
        check(snapshot_facts(db) == before,
              "the audit must not add, delete or rewrite any fact row")
        after_stat = os.stat(db)
        check(before_stat.st_size == after_stat.st_size,
              "the audit must not grow the database file")
        # derived state is untouched too
        conn = __import__("sqlite3").connect(db)
        try:
            derived = [tuple(row) for row in conn.execute(
                "SELECT * FROM item_link ORDER BY line_key")]
        finally:
            conn.close()
        audit_archive_import(db, out)
        conn = __import__("sqlite3").connect(db)
        try:
            after = [tuple(row) for row in conn.execute(
                "SELECT * FROM item_link ORDER BY line_key")]
        finally:
            conn.close()
        check(derived == after, "the audit must not recompute or touch "
                                "derived state")
    finally:
        work.cleanup()


# --------------------------------------------------------------------------- #
# 11. later correction: the fact stays recorded, state may change
# --------------------------------------------------------------------------- #
def test_correction_after_import_keeps_fact_verdict():
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        first = audit_archive_import(db, out)
        check(first["outcome"] == "verified", "initial audit verifies")
        ledger = Ledger.open(db)
        try:
            ledger.import_corrections(jsonl({
                "gateway_id": GATEWAY, "report_id": "rpt-corr-1",
                "item_id": "item-corr-1", "target_report_id": MIXED_REPORT,
                "target_item_id": "item-0",
                "occurred_at": "2026-02-05T00:00:00Z", "action": "withdraw"}))
        finally:
            ledger.close()
        second = audit_archive_import(db, out)
        check(second["outcome"] == "verified",
              f"a later correction must not make the import fail: "
              f"{second['outcome']} {second['issues']}")
        check(all(item["result"] == "imported_by_this_batch"
                  for item in second["records"]),
              "the facts are still imported by this batch")
        # and the audit reports only the fact layer, not the new state
        check("effective_action" not in second["records"][0],
              "the audit must not restate delivery state")
    finally:
        work.cleanup()


# --------------------------------------------------------------------------- #
# 12. a commit during the audit: one snapshot, reported explicitly
# --------------------------------------------------------------------------- #
def test_concurrent_commit_during_audit():
    import receipt_ledger.audit as audit_mod

    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out, "dsn.jsonl"))

        def commit_during_audit():
            writer = Ledger.open(db)
            try:
                writer.import_dsn(jsonl({
                    "gateway_id": GATEWAY, "report_id": "rpt-late",
                    "item_id": "item-late", "recipient": "late@example.com",
                    "occurred_at": "2026-02-04T13:00:00Z",
                    "action": "delivered", "queue_id": "Q-LATE"}))
            finally:
                writer.close()

        audit_mod._after_snapshot_hook = commit_during_audit
        try:
            report = audit_archive_import(db, out)
        finally:
            audit_mod._after_snapshot_hook = None
        check(report["ledger"]["snapshot"]["concurrent_commit_observed"]
              is True, "the concurrent commit must be detected")
        check(report["outcome"] == "concurrent_change",
              f"a concurrent commit must not be silently verified: "
              f"{report['outcome']}")
        check(report["exit_code"] == 3, "concurrent change must exit 3")
        check("concurrent_commit_during_audit" in report["outcome_reasons"]
              or any(i["kind"] == "concurrent_commit_during_audit"
                     for i in report["issues"]),
              "the concurrent commit must be named, not just a boolean")
        # the verdicts describe the pre-commit instant only
        check(all(item["result"] == "imported_by_this_batch"
                  for item in report["records"]),
              "the snapshot must predate the concurrent commit")
        check(report["summary"]["missing"] == 0,
              "the late fact is not part of this batch and must not appear")
        check(all(item["business_identity"]["report_id"] != "rpt-late"
                  for item in report["records"]),
              "the later commit's fact must not leak into the report")
    finally:
        work.cleanup()


def test_two_process_commit_during_audit():
    """A real second process commits while the audit holds its snapshot."""
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        worker = work.child("_worker.py")
        with open(worker, "w", encoding="utf-8") as handle:
            handle.write(AUDIT_WORKER)
        signals = work.child("signals")
        os.makedirs(signals)
        auditor = subprocess.Popen(
            [sys.executable, "-I", worker, ROOT, "hold-snapshot", db, out,
             signals],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            writer = subprocess.Popen(
                [sys.executable, "-I", worker, ROOT, "writer", db, out,
                 signals],
                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True)
            out_text, err_text = auditor.communicate(timeout=60)
            writer_out, writer_err = writer.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            auditor.kill()
            writer.kill()
            raise
        check(auditor.returncode == 3,
              f"the paused audit must exit 3: {err_text}\n{out_text}")
        check(writer.returncode == 0,
              f"the writer failed: {writer_err}\n{writer_out}")
        report = json.loads(out_text)
        check(report["ledger"]["snapshot"]["concurrent_commit_observed"]
              is True, "the two-process commit must be detected")
        check(all(item["result"] == "imported_by_this_batch"
                  for item in report["records"]),
              "the report must describe the pre-commit snapshot")
    finally:
        work.cleanup()


AUDIT_WORKER = r'''
"""Two-process audit worker: hold the snapshot open while a peer commits."""

import json
import os
import sys
import time

sys.path.insert(0, sys.argv[1])

from receipt_ledger import audit as audit_mod
from receipt_ledger.cli import main


def main_worker():
    mode, db, out, signal_dir = sys.argv[2:6]

    def signal(name):
        with open(os.path.join(signal_dir, name), "x", encoding="utf-8") as h:
            h.write(str(os.getpid()))

    def wait(name, timeout=30):
        path = os.path.join(signal_dir, name)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(path):
                return
            time.sleep(0.01)
        raise SystemExit(f"timed out waiting for {name}")

    if mode == "hold-snapshot":
        done = {"paused": False}

        def pause():
            if done["paused"]:
                return
            done["paused"] = True
            signal("snapshot-taken")
            wait("writer-done")

        audit_mod._after_snapshot_hook = pause
        try:
            code = main(["audit-archive-import", db, out])
        finally:
            audit_mod._after_snapshot_hook = None
        raise SystemExit(code)
    elif mode == "writer":
        wait("snapshot-taken")
        from receipt_ledger import Ledger
        writer = Ledger.open(db)
        try:
            writer.import_dsn(
                b'{"gateway_id":"gw-main","report_id":"rpt-late",'
                b'"item_id":"item-late","recipient":"late@example.com",'
                b'"occurred_at":"2026-02-04T13:00:00Z","action":"delivered",'
                b'"queue_id":"Q-LATE"}\n')
        finally:
            writer.close()
        signal("writer-done")
    else:
        raise SystemExit(f"unknown mode {mode!r}")


if __name__ == "__main__":
    main_worker()
'''


# --------------------------------------------------------------------------- #
# 13. the CLI contract: exit codes and JSON on stdout
# --------------------------------------------------------------------------- #
def test_cli_exit_codes():
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()

        def run(*argv):
            return subprocess.run(
                [sys.executable, "-m", "receipt_ledger.cli", *argv],
                cwd=ROOT, capture_output=True, text=True)

        proc = run("audit-archive-import", db, out)
        check(proc.returncode == 1,
              f"unimported batch: expected exit 1, got {proc.returncode}")
        report = json.loads(proc.stdout)
        check(report["outcome"] == "incomplete", "CLI outcome")

        subprocess.run([sys.executable, "-m", "receipt_ledger.cli",
                        "import-dsn", db, os.path.join(out, "dsn.jsonl")],
                       cwd=ROOT, check=True, capture_output=True)
        proc = run("audit-archive-import", db, out)
        check(proc.returncode == 0,
              f"verified batch: expected exit 0, got {proc.returncode}: "
              f"{proc.stderr}")
        report = json.loads(proc.stdout)
        check(report["outcome"] == "verified" and report["verified"] is True,
              "CLI verified report")

        proc = run("audit-archive-import", db, work.child("no-such-dir"))
        check(proc.returncode == 2,
              "missing archive dir must exit 2 with an error object")
        error = json.loads(proc.stdout)
        check(error["code"] == "archive_not_found", f"error shape: {error}")
    finally:
        work.cleanup()


# --------------------------------------------------------------------------- #
# 14. identical content exported from two files: copies are kept per block
# --------------------------------------------------------------------------- #
def test_identical_content_two_files_keeps_per_block_mapping():
    work = Workdir()
    try:
        input_dir = work.child("in")
        os.makedirs(input_dir)
        with open(os.path.join(FIXTURES, "mixed", "eml", "mixed.eml"),
                  "rb") as handle:
            data = handle.read()
        for name in ("a.eml", "b.eml"):
            with open(os.path.join(input_dir, name), "wb") as handle:
                handle.write(data)
        out = work.child("out")
        convert_archive(input_dir, out, gateway_id=GATEWAY)
        db = work.ledger()
        Ledger.create(db).close()
        outcome = import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        check(outcome["inserted"] == 2 and outcome["duplicate_rows"] == 2,
              f"hand expectation: 2 facts, 2 deduplicated copies: {outcome}")
        report = audit_archive_import(db, out)
        check(report["outcome"] == "verified",
              f"identical copies across files are a valid package: "
              f"{report['outcome']} {report['package']['problems']}")
        check(len(report["records"]) == 4,
              "every emitted record keeps its own source block")
        check(report["summary"]["distinct_business_identities"] == 2,
              "the ledger holds two facts, not four")
        check(report["summary"]["identical_record_copies"] == 2,
              "the two duplicate copies are reported as copies")
        per_source = {(item["source"]["file"],
                       item["source"]["block_index"],
                       item["business_identity"]["item_id"])
                      for item in report["records"]}
        check(per_source == {
            ("a.eml", 0, "item-0"), ("a.eml", 2, "item-2"),
            ("b.eml", 0, "item-0"), ("b.eml", 2, "item-2")},
            f"each source block must keep its mapping: {per_source}")
        # one import file carries both copies; the second copy of each identity
        # is a row-level duplicate inside that same file, so every record is
        # attributed to this batch, while the ledger still holds two facts
        results = sorted(item["result"] for item in report["records"])
        check(results == ["imported_by_this_batch"] * 4,
              f"both copies come from the same batch file: {results}")
    finally:
        work.cleanup()


# --------------------------------------------------------------------------- #
# 15. the message digest is tied to the file bytes
# --------------------------------------------------------------------------- #
def test_report_id_must_match_file_sha():
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        manifest_path = os.path.join(out, "manifest.jsonl")
        manifest = read_jsonl(manifest_path)
        message = next(e for e in manifest if e["type"] == "message")
        message["file_sha256"] = "a" * 64
        write_jsonl(manifest_path, manifest)
        report = audit_archive_import(db, out)
        check(report["outcome"] == "invalid_package",
              "a file digest that no longer derives the report id must fail")
        codes = {problem["code"] for problem in report["package"]["problems"]}
        check("report_id_not_file_digest" in codes,
              f"the derivation break must be named: {codes}")
    finally:
        work.cleanup()


def test_cross_gateway_identity_is_not_the_same_fact():
    work = Workdir()
    try:
        out_a = work.child("out_a")
        convert_archive(os.path.join(FIXTURES, "mixed", "eml"), out_a,
                        gateway_id="gw-a")
        out_b = work.child("out_b")
        convert_archive(os.path.join(FIXTURES, "mixed", "eml"), out_b,
                        gateway_id="gw-b")
        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out_a, "dsn.jsonl"))
        report = audit_archive_import(db, out_b)
        check(report["outcome"] == "incomplete",
              "another gateway's facts cannot satisfy this batch")
        check(all(item["result"] == "missing" for item in report["records"]),
              "report identity alone is not a business identity")
    finally:
        work.cleanup()


def test_empty_batch_is_verified_with_no_receipts():
    work = Workdir()
    try:
        empty = work.child("in")
        os.makedirs(empty)
        out = work.child("out")
        convert_archive(empty, out, gateway_id=GATEWAY)
        db = work.ledger()
        Ledger.create(db).close()
        report = audit_archive_import(db, out)
        check(report["outcome"] == "verified" and report["verified"] is True,
              "an empty batch has nothing to be missing")
        check(report["records"] == [] and report["quarantine"] == [],
              "an empty batch produces no rows")
        check(report["summary"]["valid_receipts"] == 0,
              f"empty summary: {report['summary']}")
    finally:
        work.cleanup()


def test_missing_ledger_or_archive_raises():
    work = Workdir()
    try:
        out = work.archive()
        expect_audit_error(
            "ledger_not_found",
            lambda: audit_archive_import(work.child("absent.sqlite"), out))
        expect_audit_error(
            "archive_not_found",
            lambda: audit_archive_import(work.ledger(), work.child("absent")))
        # a non-ledger SQLite file is refused rather than half-read
        foreign = work.child("foreign.sqlite")
        conn = __import__("sqlite3").connect(foreign)
        conn.execute("CREATE TABLE unrelated (x)")
        conn.commit()
        conn.close()
        expect_audit_error(
            "ledger_unreadable",
            lambda: audit_archive_import(foreign, out))
    finally:
        work.cleanup()


def test_failed_message_cannot_carry_records():
    work = Workdir()
    try:
        out = work.archive(case="not_a_report")
        db = work.ledger()
        Ledger.create(db).close()
        manifest_path = os.path.join(out, "manifest.jsonl")
        manifest = read_jsonl(manifest_path)
        message = next(e for e in manifest if e["type"] == "message")
        check(message["status"] == "failed",
              "hand expectation: the fixture fails at report level")
        manifest.append({
            "type": "record", "record_index": 0,
            "file": message["file"], "file_sha256": message["file_sha256"],
            "message_index": message["message_index"], "block_index": 0,
            "parse_digest": "0" * 64, "report_id": "rpt-" + "0" * 64,
            "item_id": "item-0"})
        write_jsonl(manifest_path, manifest)
        report = audit_archive_import(db, out)
        check(report["outcome"] == "invalid_package",
              "a failed message with a record entry must be invalid")
        codes = {p["code"] for p in report["package"]["problems"]}
        check("record_from_failed_message" in codes,
              f"the forbidden record must be named: {codes}")
    finally:
        work.cleanup()


def test_quarantine_pointing_at_a_record_block_is_invalid():
    work = Workdir()
    try:
        out = work.archive()
        db = work.ledger()
        Ledger.create(db).close()
        import_dsn_file(db, os.path.join(out, "dsn.jsonl"))
        quarantine_path = os.path.join(out, "quarantine.jsonl")
        entries = read_jsonl(quarantine_path)
        check(len(entries) == 1 and entries[0]["block_index"] == 1,
              "hand expectation: block 1 is quarantined")
        entries[0]["block_index"] = 0  # block 0 is a valid record
        write_jsonl(quarantine_path, entries)
        rewrite_run_digest(out, "quarantine.jsonl")
        report = audit_archive_import(db, out)
        check(report["outcome"] == "invalid_package",
              "a quarantine entry aimed at a record block must be invalid")
        codes = {p["code"] for p in report["package"]["problems"]}
        check("quarantine_points_at_record" in codes,
              f"the misdirected quarantine must be named: {codes}")
    finally:
        work.cleanup()


ALL_TESTS = [
    test_basic_batch_is_verified_with_sources,
    test_original_eml_may_be_offline,
    test_deduplicated_earlier_import_is_not_missing,
    test_missing_and_unrelated_identities_are_both_reported,
    test_package_digest_tamper_is_invalid,
    test_manifest_index_tamper_is_invalid,
    test_duplicate_record_index_is_invalid,
    test_reordered_manifest_entries_are_invalid,
    test_parse_digest_tamper_is_invalid,
    test_same_identity_different_content_is_conflict,
    test_identity_used_by_correction_is_conflict,
    test_unimported_batch_is_not_verified,
    test_unimported_batch_with_preexisting_identical_fact,
    test_same_name_different_digest_is_not_a_batch_match,
    test_quarantine_identity_coincidence_is_not_imported,
    test_failed_message_batch_reports_whole_messages,
    test_audit_does_not_modify_the_ledger,
    test_correction_after_import_keeps_fact_verdict,
    test_concurrent_commit_during_audit,
    test_two_process_commit_during_audit,
    test_cli_exit_codes,
    test_identical_content_two_files_keeps_per_block_mapping,
    test_report_id_must_match_file_sha,
    test_cross_gateway_identity_is_not_the_same_fact,
    test_empty_batch_is_verified_with_no_receipts,
    test_missing_ledger_or_archive_raises,
    test_failed_message_cannot_carry_records,
    test_quarantine_pointing_at_a_record_block_is_invalid,
]


def main():
    for test in ALL_TESTS:
        test()
        print(f"ok {test.__name__}")
    print("all archive-import audit tests passed")


if __name__ == "__main__":
    main()
