"""Acceptance suite for the offline MTA event reconstruction.

Every expectation in this file is computed independently of the
reconstructor: the event samples are hand-written literals in
``tests/mta_samples.py``, delivery ids are recomputed here from a hand-built
canonical material, attempt ordinals are hand-numbered, and ledger checks use
the ledger's own public API.  The reconstructor's output is never used as its
own expectation.

Run: python3 -I tests/test_mta_events.py
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

from receipt_ledger import Ledger, MtaEventError, import_mta_events  # noqa: E402
from receipt_ledger.addr import identity_sig, recipient_sig  # noqa: E402
from receipt_ledger.jsonio import canonical_json  # noqa: E402
from receipt_ledger.mta_events import (  # noqa: E402
    CAT_AMBIGUOUS_ORDER,
    CAT_CONTENT_CONFLICT,
    CAT_INVALID_JSON,
    CAT_INVALID_RECIPIENT,
    CAT_MALFORMED,
    CAT_ORPHAN,
    CAT_REQUEUED,
    CAT_UNKNOWN_EVENT,
    MANIFEST_JSONL,
    OUTBOUND_JSONL,
    QUARANTINE_JSONL,
)
from tests import mta_samples as samples  # noqa: E402
from tests.helpers import check  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "fixtures", "mta_events")
GATEWAY = "gw-main"


# --------------------------------------------------------------------------- #
# small independent helpers (no reconstructor code)
# --------------------------------------------------------------------------- #
def sha_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def event_digest(event):
    """The digest the manifest must use: sha256 of canonical event JSON."""
    return sha_text(canonical_json(event))


def hand_delivery_id(host, queue_id, queued_ts, events):
    """Independent copy of the documented lifecycle id material."""
    material = [
        "receipt-ledger-mta-lifecycle-v1",
        host,
        queue_id,
        queued_ts,
        sorted(event_digest(e) for e in events),
    ]
    return "dlv-" + sha_text(canonical_json(material))[:16]


def read_jsonl(path):
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def read_text(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def write_scenario(workdir, name, scenario, *, subdir="in", extra_files=None):
    """Write a scenario's events to files; return the input directory."""
    input_dir = os.path.join(workdir, subdir)
    for rel, events in scenario.items():
        path = os.path.join(input_dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    for rel, data in (extra_files or {}).items():
        path = os.path.join(input_dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = "wb" if isinstance(data, bytes) else "w"
        with open(path, mode) as handle:
            handle.write(data)
    return input_dir


def run_convert(input_dir, workdir, gateway=GATEWAY, name="out"):
    output_dir = os.path.join(workdir, name)
    summary = import_mta_events(input_dir, output_dir, gateway_id=gateway)
    return summary, output_dir


def expect_mta_error(fn, *, code, label):
    try:
        fn()
    except MtaEventError as exc:
        check(exc.code == code,
              f"{label}: expected code {code}, got {exc.code}: {exc}")
        return exc
    raise AssertionError(f"{label}: expected MtaEventError({code})")


def load_products(out):
    return (read_jsonl(os.path.join(out, OUTBOUND_JSONL)),
            read_jsonl(os.path.join(out, QUARANTINE_JSONL)),
            read_jsonl(os.path.join(out, MANIFEST_JSONL)))


def index_attempts(rows):
    return {(r["delivery_id"], r["attempt_id"], r["recipient"]): r
            for r in rows}


def categories(quarantine):
    return sorted(q["category"] for q in quarantine)


# --------------------------------------------------------------------------- #
# 1. committed fixtures match the hand-written samples byte for byte
# --------------------------------------------------------------------------- #
def test_fixtures_fresh():
    for case, files in sorted(samples.SCENARIOS.items()):
        for name, events in sorted(files.items()):
            path = os.path.join(FIXTURES, case, name)
            check(os.path.isfile(path), f"fixture missing: {path}")
            expected = [json.dumps(e, ensure_ascii=False)
                        for e in events]
            actual = [line for line in read_text(path).splitlines()
                      if line.strip()]
            if case == "bad_lines":
                # the generator inserts one corrupted line before index 4
                actual = actual[:4] + actual[5:]
            check(actual == expected,
                  f"fixture {case}/{name} differs from the sample module")
    # corrupted line itself is present and undecodable-by-json
    bad = os.path.join(FIXTURES, "bad_lines", samples.BAD_LINES_FILE)
    lines = read_text(bad).splitlines()
    check(lines[4] == samples.BAD_LINES_CORRUPT.rstrip("\n"),
          "bad_lines: corrupted line position/content mismatch")
    und = os.path.join(FIXTURES, "undecodable", samples.UNDECODABLE_FILE)
    with open(und, "rb") as handle:
        check(handle.read() == samples.UNDECODABLE_BYTES,
              "undecodable fixture bytes mismatch")


# --------------------------------------------------------------------------- #
# 2. main sample: three per-recipient attempts, stable retry numbering, and
#    the boundary duplicate keeping both source coordinates
# --------------------------------------------------------------------------- #
def test_main_sample():
    workdir = tempfile.mkdtemp(prefix="mta-main-")
    try:
        input_dir = write_scenario(workdir, "main", samples.MAIN)
        summary, out = run_convert(input_dir, workdir)

        check(summary["input_files"] == ["mta-49-early.jsonl",
                                         "mta-50-late.jsonl"],
              f"main: sorted file order: {summary}")
        check(summary["records"] == 3, f"main: 3 attempts: {summary}")
        check(summary["source_lines"] == 6, f"main: 6 physical lines")
        check(summary["logical_events"] == 5,
              "main: 5 unique events after dedup")
        check(summary["lifecycles"] == 1 and summary["emitted_lifecycles"] == 1
              and summary["quarantined_lifecycles"] == 0,
              f"main: one clean lifecycle: {summary}")

        rows, quarantine, manifest = load_products(out)
        check(quarantine == [], f"main: no quarantine entries: {quarantine}")

        # hand-computed delivery id over the full five-event lifecycle
        all_events = {event_digest(e): e
                      for f in samples.MAIN.values() for e in f}
        delivery_id = hand_delivery_id(
            samples.MAIN_HOST, samples.MAIN_QUEUE,
            "2026-03-10T10:00:00Z", list(all_events.values()))

        # hand-numbered per-recipient sequences
        expected = {}
        for recipient, attempts in samples.MAIN_EXPECTED_ATTEMPTS.items():
            for ordinal, (attempt_id, sent_at, _result) in enumerate(
                    attempts, 1):
                expected[(delivery_id, attempt_id, recipient)] = sent_at
                check(attempt_id == f"att-{ordinal}",
                      "main: stable attempt numbering")
        check(len(rows) == len(expected) == 3,
              "main: exactly three per-recipient attempts")
        for row in rows:
            key = (row["delivery_id"], row["attempt_id"], row["recipient"])
            check(key in expected, f"main: unexpected attempt {key}")
            check(row["sent_at"] == expected[key],
                  f"main: sent_at for {key}: {row['sent_at']}")
            check(row["gateway_id"] == GATEWAY, "main: operator gateway")
            check(row["queue_id"] == samples.MAIN_QUEUE, "main: queue id")
            check(row["envelope_id"] == samples.MAIN_MESSAGE_ID,
                  "main: Message-ID travels as envelope_id")
            check(set(row) == {"gateway_id", "delivery_id", "attempt_id",
                               "recipient", "queue_id", "envelope_id",
                               "sent_at"},
                  f"main: outbound row schema: {sorted(row)}")

        # deferred then sent, per recipient, readable through the ledger later
        alice = sorted(
            (r for r in rows if r["recipient"] == "alice@example.com"),
            key=lambda r: r["attempt_id"])
        check([r["attempt_id"] for r in alice] == ["att-1", "att-2"],
              "main: alice has two retries")
        check([r["sent_at"] for r in alice] == [
            "2026-03-10T10:05:00Z", "2026-03-10T10:10:00Z"],
            "main: alice retry order by timestamp, not line order")

        # manifest: both copies of the boundary line point at the same attempt
        line_entries = [m for m in manifest if m["type"] == "event_line"]
        dup = [m for m in line_entries if m["duplicate_of"] is not None]
        check(len(dup) == 1, f"main: exactly one duplicate marker: {dup}")
        coords = sorted((m["file"], m["line"]) for m in line_entries
                        if m["event_digest"] == dup[0]["event_digest"])
        check(coords == sorted(samples.MAIN_DUPLICATE_COORDS),
              f"main: duplicate keeps both source coords: {coords}")
        first = min(samples.MAIN_DUPLICATE_COORDS)
        check(tuple(dup[0]["duplicate_of"][k] for k in ("file", "line"))
              == first,
              "main: duplicate_of points at the earliest coordinate")
        check(dup[0]["status"] == "duplicate"
              and dup[0]["outbound"]["attempt_id"] == "att-2",
              "main: duplicate line maps to alice att-2")
        owners = {m["event_digest"]: m["outbound"]
                  for m in line_entries if m.get("outbound")}
        check(len(owners) == 3, "main: three emitted logical deliveries")

        # lifecycle entry carries the same delivery id and all event digests
        life = [m for m in manifest if m["type"] == "lifecycle"]
        check(len(life) == 1 and life[0]["delivery_id"] == delivery_id,
              "main: manifest lifecycle id matches hand computation")
        check(sorted(life[0]["event_digests"])
              == sorted(all_events), "main: lifecycle lists all 5 events")
        check(life[0]["closed"] is True, "main: removed closes lifecycle")
        check(len(life[0]["sources"]) == 6,
              "main: lifecycle provenance keeps all six physical lines")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 3. queue id reused after a removed, same Message-ID: no merging
# --------------------------------------------------------------------------- #
def test_queue_id_reuse_same_message_id():
    workdir = tempfile.mkdtemp(prefix="mta-reuse-")
    try:
        input_dir = write_scenario(workdir, "reused", samples.REUSED)
        summary, out = run_convert(input_dir, workdir)
        rows, quarantine, manifest = load_products(out)
        check(summary["lifecycles"] == 2 and summary["records"] == 3,
              f"reuse: two lifecycles, three attempts: {summary}")
        check(quarantine == [], f"reuse: no quarantine: {quarantine}")

        ids = {r["delivery_id"] for r in rows}
        check(len(ids) == 2,
              f"reuse: two distinct delivery ids, got {ids}")
        # hand-compute both lifecycle ids from their own event sets
        first_events = samples.REUSED["reused.jsonl"][0:3]
        second_events = samples.REUSED["reused.jsonl"][3:7]
        id1 = hand_delivery_id("gw1", "Q-200",
                               "2026-03-11T08:00:00Z", first_events)
        id2 = hand_delivery_id("gw1", "Q-200",
                               "2026-03-11T09:00:00Z", second_events)
        check(ids == {id1, id2}, "reuse: ids equal hand computation")
        check(id1 != id2, "reuse: reused queue id cannot merge the mails")

        by_id = index_attempts(rows)
        check((id1, "att-1", "carol@example.org") in by_id,
              "reuse: first mail carol att-1")
        check(by_id[(id1, "att-1", "carol@example.org")]["sent_at"]
              == "2026-03-11T08:02:00Z", "reuse: carol time")
        dave = sorted(
            (r for r in rows if r["delivery_id"] == id2),
            key=lambda r: r["attempt_id"])
        check([(r["attempt_id"], r["recipient"], r["sent_at"]) for r in dave]
              == [("att-1", "dave@example.org", "2026-03-11T09:03:00Z"),
                  ("att-2", "dave@example.org", "2026-03-11T09:08:00Z")],
              "reuse: second mail dave has its own att-1/att-2 sequence")
        check({r["envelope_id"] for r in rows} == {"<msg-reused>"},
              "reuse: both mails really carry the same Message-ID")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 4. missing queued: orphan delivery and removal reported, nothing guessed
# --------------------------------------------------------------------------- #
def test_missing_queued_is_orphan():
    workdir = tempfile.mkdtemp(prefix="mta-orphan-")
    try:
        input_dir = write_scenario(workdir, "missing", samples.MISSING_QUEUED)
        summary, out = run_convert(input_dir, workdir)
        rows, quarantine, manifest = load_products(out)
        check(rows == [], "orphan: no outbound rows")
        check(summary["orphan_events"] == 2 and summary["records"] == 0,
              f"orphan: two orphan events: {summary}")
        cats = categories(quarantine)
        check(cats == [CAT_ORPHAN, CAT_ORPHAN], f"orphan: {cats}")
        kinds = sorted(q["event"] for q in quarantine)
        check(kinds == ["delivery", "removed"],
              f"orphan: both event kinds reported: {kinds}")
        for q in quarantine:
            check(q["host"] == "gw2" and q["queue_id"] == "Q-NOQ",
                  "orphan: coordinates retained")
            check(len(q["sources"]) == 1 and q["sources"][0]["line"] in (1, 2),
                  "orphan: source coordinate locates the line")
        line_entries = [m for m in manifest if m["type"] == "event_line"]
        check(all(m["status"] == "orphan" for m in line_entries),
              "orphan: manifest marks both lines orphan")
        check([m for m in manifest if m["type"] == "lifecycle"] == [],
              "orphan: no fabricated lifecycle")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 5. re-queued before removal: first lifecycle quarantined, second still emits
# --------------------------------------------------------------------------- #
def test_requeued_before_removed():
    workdir = tempfile.mkdtemp(prefix="mta-rq-")
    try:
        input_dir = write_scenario(workdir, "rq", samples.REQUEUED)
        summary, out = run_convert(input_dir, workdir)
        rows, quarantine, manifest = load_products(out)
        check(summary["lifecycles"] == 2
              and summary["quarantined_lifecycles"] == 1
              and summary["emitted_lifecycles"] == 1,
              f"rq: one quarantined, one emitted: {summary}")
        q = [x for x in quarantine if x["kind"] == "lifecycle"]
        check(len(q) == 1 and q[0]["category"] == CAT_REQUEUED,
              f"rq: quarantine category: {q}")
        # frank's delivery belonged to the ambiguous lifetime: no row
        check(not any(r["recipient"] == "frank@example.net" for r in rows),
              "rq: first lifetime's attempt is not guessed into the second")
        good = [r for r in rows
                if r["recipient"] == samples.REQUEUED_GOOD_RECIPIENT]
        check(len(good) == 1 and good[0]["attempt_id"] == "att-1",
              "rq: second lifetime emits independently with att-1")
        check(good[0]["envelope_id"] == "<msg-rq-2>",
              "rq: second lifetime keeps its own Message-ID")
        life = sorted((m for m in manifest if m["type"] == "lifecycle"),
                      key=lambda m: m["queued_at"])
        check([m["outcome"] for m in life] == ["quarantined", "emitted"],
              "rq: manifest dispositions")
        check(life[0]["category"] == CAT_REQUEUED, "rq: manifest category")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 6. content conflict on same time/identity; valid neighbor still emits
# --------------------------------------------------------------------------- #
def test_content_conflict_isolated_but_neighbor_emits():
    workdir = tempfile.mkdtemp(prefix="mta-cf-")
    try:
        input_dir = write_scenario(workdir, "cf", samples.CONTENT_CONFLICT)
        summary, out = run_convert(input_dir, workdir)
        rows, quarantine, manifest = load_products(out)
        check(summary["quarantined_lifecycles"] == 1
              and summary["emitted_lifecycles"] == 1
              and summary["records"] == 1,
              f"cf: isolation scoped to one lifecycle: {summary}")
        q = [x for x in quarantine if x["kind"] == "lifecycle"]
        check(len(q) == 1 and q[0]["category"] == CAT_CONTENT_CONFLICT
              and q[0]["queue_id"] == samples.CONFLICT_QUEUE,
              f"cf: quarantine: {q}")
        neighbor = index_attempts(rows)
        key = next(iter(neighbor))
        check(key[2] == samples.NEIGHBOR_RECIPIENT
              and key[1] == "att-1",
              "cf: independent neighbor lifecycle still emits att-1")
        check(neighbor[key]["queue_id"] == samples.NEIGHBOR_QUEUE,
              "cf: neighbor keeps its own queue id")
        # the quarantined lifecycle's lines are marked, never silently emitted
        line_entries = [m for m in manifest if m["type"] == "event_line"]
        cf_lines = [m for m in line_entries
                    if m["event_digest"] in set(q[0]["event_digests"])]
        check(cf_lines and all(
                m["status"] == "lifecycle_quarantined"
                and m["category"] == CAT_CONTENT_CONFLICT
                for m in cf_lines),
              "cf: every line of the bad lifecycle is marked in the manifest")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 7. same recipient, two distinct deliveries at one timestamp: ambiguous
# --------------------------------------------------------------------------- #
def test_ambiguous_delivery_order():
    workdir = tempfile.mkdtemp(prefix="mta-am-")
    try:
        input_dir = write_scenario(workdir, "am", samples.AMBIGUOUS)
        summary, out = run_convert(input_dir, workdir)
        rows, quarantine, _manifest = load_products(out)
        check(rows == [], "ambiguous: whole lifecycle excluded, no rows")
        q = [x for x in quarantine if x["kind"] == "lifecycle"]
        check(len(q) == 1 and q[0]["category"] == CAT_AMBIGUOUS_ORDER
              and q[0]["queue_id"] == samples.AMBIGUOUS_QUEUE,
              f"ambiguous: quarantine: {q}")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 8. line-level isolation: unknown event, malformed event, bad recipient,
#    corrupted JSON -- and the good lifecycle beside them still emits
# --------------------------------------------------------------------------- #
def test_line_level_isolation():
    workdir = tempfile.mkdtemp(prefix="mta-bad-")
    try:
        input_dir = write_scenario(
            workdir, "bad", samples.BAD_LINES,
            extra_files={})  # corrupt line is added below at fixed position
        bad_path = os.path.join(input_dir, samples.BAD_LINES_FILE)
        with open(bad_path, encoding="utf-8") as handle:
            lines = handle.readlines()
        lines.insert(4, samples.BAD_LINES_CORRUPT)
        with open(bad_path, "w", encoding="utf-8") as handle:
            handle.writelines(lines)

        summary, out = run_convert(input_dir, workdir)
        rows, quarantine, manifest = load_products(out)
        check(summary["quarantined_lines"] == 4,
              f"bad: four bad lines: {summary}")
        cats = categories(
            [q for q in quarantine if q["kind"] == "event_line"])
        check(cats == sorted([
            CAT_INVALID_JSON, CAT_UNKNOWN_EVENT, CAT_MALFORMED,
            CAT_INVALID_RECIPIENT]), f"bad: line categories: {cats}")
        # the good delivery beside the bad lines still emits
        good = [r for r in rows
                if r["recipient"] == samples.BAD_LINES_GOOD_RECIPIENT]
        check(len(good) == 1 and good[0]["attempt_id"] == "att-1",
              "bad: good lifecycle survives neighboring bad lines")
        check(summary["emitted_lifecycles"] == 1
              and summary["quarantined_lifecycles"] == 0,
              "bad: the lifecycle itself is valid; only lines were excluded")
        line_entries = [m for m in manifest if m["type"] == "event_line"]
        marked = {m["category"] for m in line_entries
                  if m["status"] == "quarantined_line"}
        check(marked == set(cats),
              f"bad: manifest records each line category: {marked}")
        # source coordinates locate every bad line precisely
        coords = sorted((q["source"]["file"], q["source"]["line"])
                        for q in quarantine if q["kind"] == "event_line")
        check(coords == [
            (samples.BAD_LINES_FILE, 2),   # unknown event
            (samples.BAD_LINES_FILE, 3),   # missing fields
            (samples.BAD_LINES_FILE, 4),   # corrupted JSON
            (samples.BAD_LINES_FILE, 5)],  # unsupported recipient
              f"bad: quarantine coordinates: {coords}")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 9. determinism: file order, line order and extra boundary copies cannot
#    change canonical business output or generated ids
# --------------------------------------------------------------------------- #
def test_determinism_and_rotation_independence():
    workdir = tempfile.mkdtemp(prefix="mta-det-")
    try:
        # layout A: scenario as authored
        in_a = write_scenario(os.path.join(workdir, "a"), "main",
                              samples.MAIN, subdir=".")
        _sum, out_a = run_convert(in_a, workdir, name="out_a")

        # layout B: one file, every line shuffled, duplicate boundary line
        # repeated a third time
        all_events = [e for f in samples.MAIN.values() for e in f]
        shuffled = [all_events[i] for i in (4, 1, 5, 0, 2, 3)]
        in_b = os.path.join(workdir, "b")
        os.makedirs(in_b, exist_ok=True)
        with open(os.path.join(in_b, "single.jsonl"), "w",
                  encoding="utf-8") as handle:
            for e in shuffled:
                handle.write(json.dumps(e) + "\n")
            handle.write(json.dumps(all_events[3]) + "\n")  # 3rd copy
        _sum, out_b = run_convert(in_b, workdir, name="out_b")

        # business output is byte-identical regardless of arrangement
        check(read_text(os.path.join(out_a, OUTBOUND_JSONL))
              == read_text(os.path.join(out_b, OUTBOUND_JSONL)),
              "det: outbound.jsonl identical across arrangements")
        check(read_text(os.path.join(out_a, QUARANTINE_JSONL))
              == read_text(os.path.join(out_b, QUARANTINE_JSONL)),
              "det: quarantine.jsonl identical across arrangements")

        # manifest: same line count grows with the extra copy; every copy of
        # the boundary event still resolves to the same attempt
        ma = read_jsonl(os.path.join(out_a, MANIFEST_JSONL))
        mb = read_jsonl(os.path.join(out_b, MANIFEST_JSONL))
        la = [m for m in ma if m["type"] == "event_line"]
        lb = [m for m in mb if m["type"] == "event_line"]
        check(len(la) == 6 and len(lb) == 7,
              "det: manifest keeps one entry per physical line")
        # every physical copy of an emitted logical event points at the same
        # attempt: 3 unique facts, with one (layout A) / two (layout B)
        # duplicate copies carrying the identical mapping
        attempts_a = sorted(
            (m["outbound"] for m in la if m.get("outbound")),
            key=lambda o: (o["delivery_id"], o["recipient"],
                           o["attempt_id"]))
        attempts_b = sorted(
            (m["outbound"] for m in lb if m.get("outbound")),
            key=lambda o: (o["delivery_id"], o["recipient"],
                           o["attempt_id"]))
        check(len(attempts_a) == 4 and len(attempts_b) == 5,
              "det: extra boundary copies add provenance, not business rows")
        unique_a = {json.dumps(o, sort_keys=True) for o in attempts_a}
        unique_b = {json.dumps(o, sort_keys=True) for o in attempts_b}
        check(len(unique_a) == len(unique_b) == 3
              and unique_a == unique_b,
              "det: all copies resolve to the same three attempt facts")
        check(sum(1 for m in lb if m["status"] == "duplicate") == 2,
              "det: the third copy becomes a second duplicate marker")

        # re-run onto the existing target is refused, products untouched
        expect_mta_error(
            lambda: import_mta_events(in_a, out_a, gateway_id=GATEWAY),
            code="output_exists", label="re-run onto existing target")
        check(sorted(os.listdir(out_a)) == sorted(
            [OUTBOUND_JSONL, QUARANTINE_JSONL, MANIFEST_JSONL]),
            "det: failed re-run leaves products untouched")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 10. batch-level failures publish nothing
# --------------------------------------------------------------------------- #
def test_batch_failures_leave_nothing():
    workdir = tempfile.mkdtemp(prefix="mta-fail-")
    try:
        # undecodable UTF-8 file: batch error, no output directory
        in_ud = os.path.join(workdir, "ud")
        os.makedirs(in_ud, exist_ok=True)
        with open(os.path.join(in_ud, samples.UNDECODABLE_FILE), "wb") as h:
            h.write(samples.UNDECODABLE_BYTES)
        out_ud = os.path.join(workdir, "out_ud")
        expect_mta_error(
            lambda: import_mta_events(in_ud, out_ud, gateway_id=GATEWAY),
            code="input_error", label="undecodable file")
        check(not os.path.exists(out_ud),
              "undecodable: no partial output directory")
        check(not [n for n in os.listdir(workdir) if ".tmp-" in n],
              "undecodable: no temp directory left behind")

        # empty directory and empty file
        in_empty = os.path.join(workdir, "empty_dir")
        os.makedirs(in_empty, exist_ok=True)
        expect_mta_error(
            lambda: import_mta_events(
                in_empty, os.path.join(workdir, "out_empty"),
                gateway_id=GATEWAY),
            code="input_error", label="directory without jsonl")
        in_blank = os.path.join(workdir, "blank")
        os.makedirs(in_blank, exist_ok=True)
        open(os.path.join(in_blank, "blank.jsonl"), "wb").close()
        expect_mta_error(
            lambda: import_mta_events(
                in_blank, os.path.join(workdir, "out_blank"),
                gateway_id=GATEWAY),
            code="input_error", label="file without JSON objects")

        # missing input / bad gateway / existing target
        expect_mta_error(
            lambda: import_mta_events(
                os.path.join(workdir, "nope"),
                os.path.join(workdir, "out_nope"), gateway_id=GATEWAY),
            code="input_not_found", label="missing input directory")
        in_main = write_scenario(workdir, "main2", samples.MAIN)
        expect_mta_error(
            lambda: import_mta_events(in_main, os.path.join(workdir, "x"),
                                      gateway_id=""),
            code="input_error", label="empty gateway id")
        existing = os.path.join(workdir, "existing")
        os.makedirs(existing, exist_ok=True)
        expect_mta_error(
            lambda: import_mta_events(in_main, existing,
                                      gateway_id=GATEWAY),
            code="output_exists", label="existing output target")
        check(os.listdir(existing) == [],
              "existing target is never modified")

        # write failure: parent directory does not exist
        expect_mta_error(
            lambda: import_mta_events(
                in_main, os.path.join(workdir, "no-parent", "out"),
                gateway_id=GATEWAY),
            code="output_error", label="missing output parent")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 11. ledger end to end: import the products and query hand-computed facts
# --------------------------------------------------------------------------- #
def test_ledger_end_to_end():
    workdir = tempfile.mkdtemp(prefix="mta-e2e-")
    try:
        input_dir = write_scenario(workdir, "in", samples.MAIN)
        _summary, out = run_convert(input_dir, workdir)
        db = os.path.join(workdir, "ledger.sqlite")
        ledger = Ledger.create(db)
        try:
            with open(os.path.join(out, OUTBOUND_JSONL), "rb") as handle:
                outcome = ledger.import_outbound(handle.read(),
                                                  source=OUTBOUND_JSONL)
            check(outcome["inserted"] == 3 and outcome["duplicate_rows"] == 0,
                  f"e2e: three facts imported: {outcome}")

            all_events = {event_digest(e): e
                          for f in samples.MAIN.values() for e in f}
            delivery_id = hand_delivery_id(
                samples.MAIN_HOST, samples.MAIN_QUEUE,
                "2026-03-10T10:00:00Z", list(all_events.values()))

            # independently hand-computed attempt facts, queried exactly as
            # the operations team will: gateway/delivery/attempt/recipient
            hand_facts = [
                ("alice@example.com", "att-1",
                 "2026-03-10T10:05:00Z"),
                ("alice@example.com", "att-2",
                 "2026-03-10T10:10:00Z"),
                ("bob@example.com", "att-1",
                 "2026-03-10T10:05:00Z"),
            ]
            for recipient, attempt_id, sent_at in hand_facts:
                status = ledger.attempt_status(
                    GATEWAY, delivery_id, attempt_id, recipient)
                check(status["status"] == "awaiting",
                      "e2e: no receipts yet -> awaiting")
                # the exact attempt row carries the SMTP delivery timestamp
                row = ledger.conn.execute(
                    "SELECT a.sent_at_text FROM outbound_attempt a"
                    " JOIN gateway g ON g.id=a.gateway_row"
                    " WHERE g.ident=? AND a.delivery_id=? AND a.attempt_id=?"
                    " AND a.recipient_sig=?",
                    (identity_sig(GATEWAY), delivery_id, attempt_id,
                     recipient_sig(recipient))).fetchone()
                check(row is not None and row[0] == sent_at,
                      f"e2e: stored sent_at {sent_at}")
            # per-recipient delivery view: counts and last attempt
            alice_delivery = ledger.delivery_status(
                GATEWAY, delivery_id, "alice@example.com")
            check(alice_delivery["attempt_count"] == 2,
                  "e2e: alice has two attempts")
            check(alice_delivery["latest_attempt_id"] == "att-2"
                  and alice_delivery["latest_sent_at"]
                  == "2026-03-10T10:10:00Z",
                  "e2e: deferred-then-sent ends on the sent retry")
            bob_delivery = ledger.delivery_status(
                GATEWAY, delivery_id, "bob@example.com")
            check(bob_delivery["attempt_count"] == 1
                  and bob_delivery["latest_attempt_id"] == "att-1"
                  and bob_delivery["latest_sent_at"]
                  == "2026-03-10T10:05:00Z",
                  "e2e: bob's single attempt is his last")

            # byte-identical re-import is a no-op at the ledger too
            with open(os.path.join(out, OUTBOUND_JSONL), "rb") as handle:
                again = ledger.import_outbound(handle.read(),
                                                source=OUTBOUND_JSONL)
            check(again["skipped"] is True,
                  f"e2e: re-import skipped: {again}")
        finally:
            ledger.close()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 12. CLI end to end, including the failed-publish guarantee
# --------------------------------------------------------------------------- #
def test_cli_end_to_end():
    workdir = tempfile.mkdtemp(prefix="mta-cli-")
    try:
        input_dir = write_scenario(workdir, "in", samples.MAIN)
        out = os.path.join(workdir, "out")
        db = os.path.join(workdir, "ledger.sqlite")

        def run_cli(*argv):
            return subprocess.run(
                [sys.executable, "-m", "receipt_ledger.cli", *argv],
                cwd=ROOT, capture_output=True, text=True)

        proc = run_cli("import-mta-events", input_dir, out,
                       "--gateway", GATEWAY)
        check(proc.returncode == 0,
              f"cli import-mta-events: {proc.stderr}{proc.stdout}")
        summary = json.loads(proc.stdout)
        check(summary["records"] == 3, f"cli: summary {summary}")

        # failed publish: existing target -> exit 2, still importable dir
        proc = run_cli("import-mta-events", input_dir, out,
                       "--gateway", GATEWAY)
        check(proc.returncode == 2, "cli re-run: must fail")
        check(json.loads(proc.stdout)["code"] == "output_exists",
              "cli re-run: output_exists")
        check(sorted(os.listdir(out)) == sorted(
            [OUTBOUND_JSONL, QUARANTINE_JSONL, MANIFEST_JSONL]),
            "cli re-run: products untouched")

        proc = run_cli("init", db)
        check(proc.returncode == 0, f"cli init: {proc.stderr}")
        proc = run_cli("import-outbound", db,
                       os.path.join(out, OUTBOUND_JSONL))
        check(proc.returncode == 0,
              f"cli import-outbound: {proc.stderr}{proc.stdout}")
        check(json.loads(proc.stdout)["inserted"] == 3,
              "cli: three attempts landed in the ledger")

        all_events = {event_digest(e): e
                      for f in samples.MAIN.values() for e in f}
        delivery_id = hand_delivery_id(
            samples.MAIN_HOST, samples.MAIN_QUEUE,
            "2026-03-10T10:00:00Z", list(all_events.values()))
        proc = run_cli("attempt-status", db, "--gateway", GATEWAY,
                       "--delivery", delivery_id, "--attempt", "att-2",
                       "--recipient", "alice@example.com")
        check(proc.returncode == 0, f"cli attempt-status: {proc.stderr}")
        answer = json.loads(proc.stdout)
        check(answer["status"] == "awaiting"
              and answer["recipient"] == "alice@example.com",
              f"cli: queried hand-computed attempt: {answer}")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


ALL_TESTS = [
    test_fixtures_fresh,
    test_main_sample,
    test_queue_id_reuse_same_message_id,
    test_missing_queued_is_orphan,
    test_requeued_before_removed,
    test_content_conflict_isolated_but_neighbor_emits,
    test_ambiguous_delivery_order,
    test_line_level_isolation,
    test_determinism_and_rotation_independence,
    test_batch_failures_leave_nothing,
    test_ledger_end_to_end,
    test_cli_end_to_end,
]


def main():
    for test in ALL_TESTS:
        test()
        print(f"ok {test.__name__}")
    print("all MTA event reconstruction acceptance tests passed")


if __name__ == "__main__":
    main()
