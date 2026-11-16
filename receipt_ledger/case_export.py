"""Investigation sub-ledger export (``export-case``).

Given an existing ledger and explicitly named delivery / receipt-item
selectors, produce a self-contained SQLite ledger holding the smallest
business closure that keeps the original interpretation of those facts.  It is
evidence for someone who cannot open the production ledger.

This module computes **which already-recorded facts must travel together**.  It
does not parse mail, re-define matching or invent missing facts: each group's
candidate set comes from the engine's own ``_evaluate_root`` (which runs the
existing ``_candidates`` query), chain structure from ``_load_graph`` /
``chains.analyse``, and fingerprints from ``fingerprint.fingerprint``.

Consistency
-----------
The source is copied exactly once with SQLite's online backup API, inside one
explicit read transaction, into a private temporary database.  Selector
resolution, closure expansion, fact copying and verification then read only
that snapshot.  A concurrent importer may keep committing to the source; the
snapshot cannot observe it, so a mixed "old candidates with new facts" view is
impossible.  The snapshot is re-derived with the engine's own ``rebuild`` so
comparisons use freshly computed facts, never stale materializations.

Closure (always evaluated against the complete snapshot, never against the
partially pruned sub-ledger)
--------------------------------------------------------------------------
* a selected delivery is ``(gateway, delivery, recipient)`` plus **all** of its
  retry attempts;
* a receipt item's correction group is taken in full, both directions:
  ancestors, every present branch and descendants.  An absent target stays a
  logical identity, so corrections sharing one absent target form one group;
  no missing fact is fabricated;
* every group containing an original DSN contributes its *current* candidate
  set as recomputed from the complete facts, whatever its mark (ambiguous,
  withdrawn, conflicted, unmatched).  A group with no original DSN contributes
  no candidates;
* any attempt carried in brings the rest of its delivery's retries; new
  attempts may be candidates of further groups, so expansion iterates to a
  fixed point (never just one level);
* every group carried in keeps **all** its human decisions -- live and stale --
  with the candidate set and chosen attempt each saved.  Historical
  competitors are never dropped and fingerprints are never re-signed.

Publication
-----------
The sub-ledger is built and verified inside a controlled temporary directory
and published with one atomic rename.  An existing target is refused; any
failure removes the temporary directory, so a failed run never leaves
something that could be mistaken for a finished export.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import tempfile
import uuid
from collections import defaultdict

from . import ingest
from .addr import AddressError, canonical_recipient, recipient_sig
from .engine import Ledger
from .errors import ExportError, LedgerError
from .jsonio import canonical_json, sha256_hex
from .schema import check_schema

__all__ = [
    "LEDGER_NAME",
    "SELECTION_NAME",
    "parse_selection",
    "export_case",
]

LEDGER_NAME = "ledger.sqlite"
SELECTION_NAME = "selection.json"

SEL_DELIVERIES = "deliveries"
SEL_ITEMS = "items"
_SELECTOR_KEYS = {
    SEL_DELIVERIES: ("gateway_id", "delivery_id", "recipient"),
    SEL_ITEMS: ("gateway_id", "report_id", "item_id"),
}

_FACT_TABLES = ("gateway", "import_file", "outbound_attempt", "dsn_line",
                "correction_line", "manual_decision")

# Test seams (default None, only set by the test suite): a controlled pause
# point after the snapshot is taken, and a controlled publish failure.
_after_snapshot_hook = None
_publish_hook = None


# --------------------------------------------------------------------------- #
# selector parsing (pure; no database access)
# --------------------------------------------------------------------------- #
def _fail(message, **details):
    raise ExportError("invalid_selection", message, details)


def _text(value):
    return isinstance(value, str) and value != ""


def parse_selection(raw):
    """Validate and normalize a selector document.

    ``raw`` may be a parsed object, JSON text or UTF-8 bytes.  Unknown
    top-level keys, non-array selector values, an empty document, unknown
    fields, non-string/empty values and unsupported addresses fail the whole
    export.  Duplicates are normalized away; addresses use the ledger's
    existing ``recipient_sig`` convention.
    """
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = bytes(raw).decode("utf-8")
        except UnicodeDecodeError as exc:
            _fail("selector document is not valid UTF-8", error=str(exc))
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            _fail("selector document is not valid JSON", error=str(exc))
    if not isinstance(raw, dict):
        _fail("selector document must be a JSON object")

    unknown = sorted(set(raw) - set(_SELECTOR_KEYS))
    if unknown:
        _fail(f"unknown selector array(s) {unknown}",
              allowed=sorted(_SELECTOR_KEYS))
    if not any(name in raw for name in _SELECTOR_KEYS):
        _fail("selector document must contain a deliveries or items array")

    deliveries, items = [], []
    seen_deliveries, seen_items = set(), set()
    for name, array in ((SEL_DELIVERIES, deliveries), (SEL_ITEMS, items)):
        if name not in raw:
            continue
        entries = raw[name]
        if not isinstance(entries, list):
            _fail(f"{name!r} must be an array")
        for index, entry in enumerate(entries):
            where = f"{name}[{index}]"
            if not isinstance(entry, dict):
                _fail(f"{where} must be a JSON object")
            expected = _SELECTOR_KEYS[name]
            missing = [key for key in expected if key not in entry]
            extra = sorted(set(entry) - set(expected))
            if missing:
                _fail(f"{where} is missing field(s) {missing}")
            if extra:
                _fail(f"{where} has unknown field(s) {extra}")
            values = {}
            for field in expected:
                value = entry[field]
                if not _text(value):
                    _fail(f"{where}.{field} must be a non-empty string")
                values[field] = value
            if name == SEL_DELIVERIES:
                try:
                    sig = recipient_sig(values["recipient"])
                except AddressError as exc:
                    _fail(f"{where}.recipient: {exc}")
                key = (values["gateway_id"], values["delivery_id"],
                       sig.hex())
                if key in seen_deliveries:
                    continue
                seen_deliveries.add(key)
                values["recipient_canonical"] = canonical_recipient(
                    values["recipient"]).decode("ascii")
                values["recipient_sig"] = sig.hex()
                array.append(values)
            else:
                key = (values["gateway_id"], values["report_id"],
                       values["item_id"])
                if key in seen_items:
                    continue
                seen_items.add(key)
                array.append(values)
    if not deliveries and not items:
        _fail("at least one delivery or item must be selected")
    return {SEL_DELIVERIES: deliveries, SEL_ITEMS: items}


# --------------------------------------------------------------------------- #
# snapshot
# --------------------------------------------------------------------------- #
def _unlink(path):
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(path + suffix)
        except FileNotFoundError:
            pass


def _open_source_snapshot(source_path):
    """Copy the live source once; return ``(snapshot_ledger, path, digest)``.

    The source is opened read-only and copied through SQLite's backup API
    inside one explicit read transaction, so the copy is a single instant and
    the source is never written.  A rollback-journal source serializes writers
    for the duration of the copy only; a WAL source keeps serving them.
    """
    if not os.path.isfile(source_path):
        raise ExportError("source_not_found",
                          f"source database {source_path!r} does not exist")
    try:
        source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True,
                                 isolation_level=None, timeout=30)
    except sqlite3.Error as exc:
        raise ExportError("source_error",
                          f"cannot open source database: {exc}") from exc
    handle, snap_path = tempfile.mkstemp(prefix="receipt-ledger-export-",
                                         suffix=".snapshot.sqlite")
    os.close(handle)
    os.unlink(snap_path)
    try:
        source.execute("BEGIN")
        source.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
        try:
            check_schema(source)
        except RuntimeError as exc:
            raise ExportError("source_error", str(exc)) from exc
        destination = sqlite3.connect(snap_path)
        try:
            with destination:
                source.backup(destination)
        finally:
            destination.close()
        source.execute("ROLLBACK")
    except ExportError:
        try:
            source.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        _unlink(snap_path)
        raise
    except sqlite3.Error as exc:
        try:
            source.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        _unlink(snap_path)
        raise ExportError("source_error",
                          f"cannot snapshot source database: {exc}") from exc
    finally:
        source.close()

    snapshot = Ledger.open(snap_path)
    try:
        check_schema(snapshot.conn)
        snapshot.rebuild()
    except (RuntimeError, sqlite3.Error) as exc:
        snapshot.close()
        _unlink(snap_path)
        raise ExportError("source_error",
                          f"cannot prepare source snapshot: {exc}") from exc
    digest = _snapshot_digest(snapshot.conn)
    return snapshot, snap_path, digest


def _jsonable(value):
    return value.hex() if isinstance(value, (bytes, bytearray)) else value


def _snapshot_digest(conn):
    """Content digest of the snapshot's fact layer, row ids included.

    Row ids are preserved by the export, so two snapshots of unchanged facts
    produce the same digest.  This is the "one instant" identifier recorded in
    ``selection.json``.
    """
    digest = {}
    for table, columns in (
            ("gateway", "id, ident"),
            ("import_file", "id, sha256, kind, source_name, line_count"),
            ("outbound_attempt", "id, gateway_row, delivery_id, attempt_id,"
                                 " recipient_sig, recipient_text, queue_id,"
                                 " envelope_id, sent_at_us, sent_at_text,"
                                 " canonical_hash"),
            ("dsn_line", "id, gateway_row, report_id, item_id, occurred_at_us,"
                         " occurred_text, action, recipient_text, queue_id,"
                         " envelope_id, canonical_hash"),
            ("correction_line", "id, gateway_row, report_id, item_id,"
                                " target_report_id, target_item_id,"
                                " occurred_at_us, occurred_text, action,"
                                " recipient_text, queue_id, envelope_id,"
                                " canonical_hash"),
            ("manual_decision", "id, line_key, requested_key, root_report_id,"
                                " root_item_id, delivery_id, attempt_id,"
                                " recipient_sig, candidate_fp, candidate_net,"
                                " decided_at_us, decided_text")):
        rows = [[_jsonable(value) for value in row]
                for row in conn.execute(f"SELECT {columns} FROM {table}"
                                        " ORDER BY id")]
        digest[table] = sha256_hex(canonical_json(rows))
    return digest


# --------------------------------------------------------------------------- #
# snapshot structure
# --------------------------------------------------------------------------- #
class _Snapshot:
    """Snapshot facts, chain structure and lazily evaluated root views."""

    def __init__(self, ledger):
        self.ledger = ledger
        self.conn = ledger.conn
        self.gateway_idents = {
            row["id"]: row["ident"].decode().removeprefix("i:")
            for row in self.conn.execute("SELECT id, ident FROM gateway")}
        self.ctx, self.info = ledger._load_graph()
        self.fields = self.ctx["fields"]
        self.present = {key for key, (kind, _row) in self.ctx["nodes"].items()}
        self.views = {}
        self._attempt_cache = {}
        self._line_cache = {}
        self._build_components()
        self._index_roots()
        self._load_decisions()

    # -- primitive lookups ------------------------------------------------- #
    def gateway_text(self, row):
        return self.gateway_idents.get(row, "<gateway:%s>" % row)

    def attempt(self, attempt_id):
        if attempt_id not in self._attempt_cache:
            self._attempt_cache[attempt_id] = self.conn.execute(
                "SELECT * FROM outbound_attempt WHERE id=?",
                (attempt_id,)).fetchone()
        return self._attempt_cache[attempt_id]

    def line(self, line_key):
        if line_key not in self._line_cache:
            kind, row_id = line_key.split(":", 1)
            table = "dsn_line" if kind == "dsn" else "correction_line"
            self._line_cache[line_key] = self.conn.execute(
                f"SELECT * FROM {table} WHERE id=?", (int(row_id),)).fetchone()
        return self._line_cache[line_key]

    def decision(self, decision_id):
        return self.decision_index.get(int(decision_id))

    def attempt_label(self, row):
        return "%s/%s/%s/%s" % (
            self.gateway_text(row["gateway_row"]), row["delivery_id"],
            row["attempt_id"], row["recipient_text"])

    def line_label(self, line_key):
        row = self.line(line_key)
        return "%s/%s/%s/%s" % (
            self.gateway_text(row["gateway_row"]),
            "dsn" if line_key.startswith("dsn:") else "correction",
            row["report_id"], row["item_id"])

    # -- views ------------------------------------------------------------- #
    def view(self, root):
        if root not in self.views:
            self.views[root] = self.ledger._evaluate_root(
                self.ctx, self.info, root)
        return self.views[root]

    def _index_roots(self):
        self.roots_by_recipient = defaultdict(list)
        for line_key in sorted(self.present):
            if not line_key.startswith("dsn:"):
                continue
            fields = self.fields[line_key]
            self.roots_by_recipient[
                (fields["gateway_row"], fields["recipient_sig"])].append(
                    line_key)

    def roots_candidate_of(self, attempt_id):
        """Roots of groups whose current candidate set includes ``attempt``.

        The bucket is pre-filtered with the same safe superset the engine uses
        for a new attempt (``lookup_at_us`` bounds ``sent_at``; supplied
        queue/envelope conditions must match); each surviving root still has to
        prove membership through its own freshly evaluated candidate set, so
        the pre-filter can never widen the result.
        """
        row = self.attempt(attempt_id)
        sig = bytes(row["recipient_sig"])
        bucket = self.roots_by_recipient.get((row["gateway_row"], sig), ())
        sent_at = row["sent_at_us"]
        queue_sig = row["queue_sig"]
        envelope_sig = row["envelope_sig"]
        found = []
        for root in bucket:
            fields = self.fields[root]
            if sent_at > self.view(root)["lookup_at_us"]:
                continue
            if fields["queue_sig"] is not None \
                    and fields["queue_sig"] != queue_sig:
                continue
            if fields["envelope_sig"] is not None \
                    and fields["envelope_sig"] != envelope_sig:
                continue
            if attempt_id in {int(member[0])
                              for member in self.view(root)["candidates"]}:
                found.append(root)
        return found

    # -- correction components -------------------------------------------- #
    def _build_components(self):
        adjacency = {key: set() for key in self.present}
        self.absent_meta = {}
        for child, parent in self.ctx["parent_of"].items():
            adjacency.setdefault(child, set()).add(parent)
            adjacency.setdefault(parent, set()).add(child)
            if parent not in self.present and parent not in self.absent_meta:
                row = self.line(child)
                self.absent_meta[parent] = {
                    "gateway_row": row["gateway_row"],
                    "report_id": row["target_report_id"],
                    "item_id": row["target_item_id"],
                    "report_sig": bytes(row["target_report_sig"]).hex(),
                    "item_sig": bytes(row["target_item_sig"]).hex()}
        self.node_component = {}
        self.components = []
        for start in sorted(adjacency):
            if start in self.node_component:
                continue
            index = len(self.components)
            stack = [start]
            present, absent = [], []
            self.node_component[start] = index
            while stack:
                node = stack.pop()
                (absent if node.startswith("ref:") else present).append(node)
                for neighbour in adjacency[node]:
                    if neighbour not in self.node_component:
                        self.node_component[neighbour] = index
                        stack.append(neighbour)
            present.sort()
            absent.sort()
            roots = [node for node in present if node.startswith("dsn:")]
            if len(roots) > 1:  # pragma: no cover - structurally impossible
                raise ExportError("source_error",
                                  "correction graph component has multiple "
                                  "original receipts")
            self.components.append({"present": present, "absent": absent,
                                    "root": roots[0] if roots else None})

    def _load_decisions(self):
        self.decisions_of = defaultdict(list)
        self.decision_index = {}
        for row in self.conn.execute(
                "SELECT * FROM manual_decision ORDER BY id"):
            self.decisions_of[row["line_key"]].append(row)
            self.decision_index[int(row["id"])] = row

    # -- business keys ----------------------------------------------------- #
    def business_key(self, line_key):
        row = self.line(line_key)
        return (self.gateway_text(row["gateway_row"]),
                "dsn" if line_key.startswith("dsn:") else "correction",
                row["report_id"], row["item_id"])

    def attempt_business_key(self, attempt_id):
        row = self.attempt(attempt_id)
        return (self.gateway_text(row["gateway_row"]), row["delivery_id"],
                row["attempt_id"], bytes(row["recipient_sig"]).hex())


# --------------------------------------------------------------------------- #
# closure
# --------------------------------------------------------------------------- #
class _Closure:
    def __init__(self, snapshot, selection):
        self.snap = snapshot
        self.selection = selection
        self.attempts = {}        # attempt id -> set(reason)
        self.items = {}           # line key -> set(reason)
        self.absent = {}          # synthetic key -> set(reason)
        self.decisions = {}       # decision id -> set(reason)
        self._queue = []
        self._queued_attempts = set()
        self._queued_items = set()
        self._queued_decisions = set()
        self.gateways = {}
        self.import_files = {}

    # -- entry points ------------------------------------------------------ #
    def resolve(self):
        for entry in self.selection[SEL_DELIVERIES]:
            self._selected_delivery(entry)
        for entry in self.selection[SEL_ITEMS]:
            self._selected_item(entry)
        while self._queue:
            kind, value = self._queue.pop(0)
            if kind == "attempt":
                self._process_attempt(value)
            elif kind == "item":
                self._process_item(value)
            else:
                self._process_decision(value)
        self._close_metadata()

    def _selected_delivery(self, entry):
        gateway_row = self._require_gateway(entry["gateway_id"])
        sig = bytes.fromhex(entry["recipient_sig"])
        rows = self.snap.conn.execute(
            "SELECT id FROM outbound_attempt WHERE gateway_row=? AND"
            " delivery_id=? AND recipient_sig=? ORDER BY id",
            (gateway_row, entry["delivery_id"], sig)).fetchall()
        if not rows:
            raise ExportError(
                "unknown_selection",
                f"selected delivery {entry['delivery_id']!r} for "
                f"{entry['recipient']!r} does not exist on gateway "
                f"{entry['gateway_id']!r}",
                {"gateway_id": entry["gateway_id"],
                 "delivery_id": entry["delivery_id"],
                 "recipient": entry["recipient"]})
        reason = "selected delivery %s/%s/%s" % (
            entry["gateway_id"], entry["delivery_id"], entry["recipient"])
        for row in rows:
            self._add_attempt(int(row[0]), reason)

    def _selected_item(self, entry):
        gateway_row = self._require_gateway(entry["gateway_id"])
        report_sig = ingest.identity_signature(entry["report_id"],
                                               "report_id")
        item_sig = ingest.identity_signature(entry["item_id"], "item_id")
        kind, row_id = self.snap.ledger._find_item(gateway_row, report_sig,
                                                   item_sig)
        if kind is None:
            raise ExportError(
                "unknown_selection",
                f"selected item {entry['report_id']!r}/{entry['item_id']!r} "
                f"does not exist on gateway {entry['gateway_id']!r}",
                {"gateway_id": entry["gateway_id"],
                 "report_id": entry["report_id"],
                 "item_id": entry["item_id"]})
        self._add_item(
            "%s:%s" % (kind, row_id),
            "selected item %s/%s/%s" % (entry["gateway_id"],
                                        entry["report_id"],
                                        entry["item_id"]))

    def _require_gateway(self, gateway_id):
        gateway_row = self.snap.ledger._gw(gateway_id)
        if gateway_row is None:
            raise ExportError("unknown_selection",
                              f"gateway {gateway_id!r} does not exist",
                              {"gateway_id": gateway_id})
        return gateway_row

    # -- worklist bookkeeping --------------------------------------------- #
    def _add_attempt(self, attempt_id, reason):
        if self.snap.attempt(attempt_id) is None:  # pragma: no cover
            raise ExportError("source_error",
                              f"attempt row {attempt_id} vanished from the "
                              "snapshot")
        self.attempts.setdefault(attempt_id, set()).add(reason)
        if attempt_id not in self._queued_attempts:
            self._queued_attempts.add(attempt_id)
            self._queue.append(("attempt", attempt_id))

    def _add_item(self, line_key, reason):
        if self.snap.line(line_key) is None:  # pragma: no cover
            raise ExportError("source_error",
                              f"receipt line {line_key} vanished from the "
                              "snapshot")
        self.items.setdefault(line_key, set()).add(reason)
        if line_key not in self._queued_items:
            self._queued_items.add(line_key)
            self._queue.append(("item", line_key))

    def _add_decision(self, decision_id, reason):
        self.decisions.setdefault(decision_id, set()).add(reason)
        if decision_id not in self._queued_decisions:
            self._queued_decisions.add(decision_id)
            self._queue.append(("decision", decision_id))

    def _add_absent(self, synthetic_key, reason):
        self.absent.setdefault(synthetic_key, set()).add(reason)

    # -- worklist processors ---------------------------------------------- #
    def _process_attempt(self, attempt_id):
        row = self.snap.attempt(attempt_id)
        label = self.snap.attempt_label(row)
        for sibling in self.snap.conn.execute(
                "SELECT id FROM outbound_attempt WHERE gateway_row=? AND"
                " delivery_id=? AND recipient_sig=? ORDER BY id",
                (row["gateway_row"], row["delivery_id"],
                 row["recipient_sig"])).fetchall():
            self._add_attempt(
                int(sibling[0]),
                "retry of delivery %s/%s/%s" % (
                    self.snap.gateway_text(row["gateway_row"]),
                    row["delivery_id"], row["recipient_text"]))
        for root in self.snap.roots_candidate_of(attempt_id):
            self._add_item(
                root,
                "receipt group whose current candidates include " + label)

    def _process_item(self, line_key):
        component = self.snap.components[self.snap.node_component[line_key]]
        label = self.snap.line_label(line_key)
        for node in component["present"]:
            if node != line_key:
                self._add_item(node,
                               "same correction group as " + label)
        for synthetic in component["absent"]:
            self._add_absent(
                synthetic,
                "missing target in the same correction group as " + label)
        root = component["root"]
        if root is None:
            return
        self._add_item(root, "chain root of the group containing " + label)
        for member in self.snap.view(root)["candidates"]:
            self._add_attempt(
                int(member[0]),
                "current candidate of " + self.snap.line_label(root))
        for decision in self.snap.decisions_of.get(root, ()):
            self._add_decision(
                int(decision["id"]),
                "human decision recorded on "
                + self.snap.line_label(root))

    def _process_decision(self, decision_id):
        row = self.snap.decision(decision_id)
        root = row["line_key"]
        root_label = self.snap.line_label(root)
        self._add_item(root, "chain root governed by a human decision")
        requested = row["requested_key"]
        if self.snap.line(requested) is not None:
            self._add_item(requested,
                           "item named by a human decision on " + root_label)
        self._decision_attempt(
            row, row["delivery_id"], row["attempt_id"],
            bytes(row["recipient_sig"]),
            "attempt chosen by a human decision on " + root_label)
        for member in json.loads(row["candidate_net"]):
            self._decision_attempt(
                row, member["delivery_id"], member["attempt_id"],
                bytes.fromhex(member["recipient"]),
                "candidate saved by a human decision on " + root_label)

    def _decision_attempt(self, decision, delivery, attempt, sig, reason):
        found = self.snap.conn.execute(
            "SELECT id FROM outbound_attempt WHERE gateway_row=? AND"
            " delivery_id=? AND attempt_id=? AND recipient_sig=?",
            (decision["gateway_row"], delivery, attempt, sig)).fetchone()
        if found is None:  # pragma: no cover - decisions quote existing rows
            raise ExportError(
                "source_error",
                "a human decision references an attempt that does not exist "
                "in the source snapshot",
                {"delivery_id": delivery, "attempt_id": attempt,
                 "recipient_sig": sig.hex()})
        self._add_attempt(int(found[0]), reason)

    # -- metadata ---------------------------------------------------------- #
    def _close_metadata(self):
        for attempt_id in sorted(self.attempts):
            row = self.snap.attempt(attempt_id)
            label = self.snap.attempt_label(row)
            self.gateways.setdefault(
                row["gateway_row"],
                {"gateway of carried attempt " + label})
            self.import_files.setdefault(
                row["import_file"],
                {"source of carried attempt " + label})
        for line_key in sorted(self.items):
            row = self.snap.line(line_key)
            label = self.snap.line_label(line_key)
            self.gateways.setdefault(
                row["gateway_row"],
                {"gateway of carried item " + label})
            self.import_files.setdefault(
                row["import_file"],
                {"source of carried item " + label})
        for decision_id in sorted(self.decisions):
            row = self.snap.decision(decision_id)
            root_label = self.snap.line_label(row["line_key"])
            self.gateways.setdefault(
                row["gateway_row"],
                {"gateway of carried human decision on " + root_label})
            self.import_files.setdefault(
                row["import_file"],
                {"source of carried human decision on " + root_label})

    def line_ids(self, kind):
        return sorted(int(key.split(":", 1)[1]) for key in self.items
                      if key.startswith(kind + ":"))


# --------------------------------------------------------------------------- #
# fact copy
# --------------------------------------------------------------------------- #
_COLUMNS = {
    "gateway": "id, ident",
    "import_file": "id, sha256, kind, source_name, line_count",
    "outbound_attempt": (
        "id, gateway_row, delivery_id, attempt_id, recipient_sig,"
        " recipient_text, queue_sig, queue_id, envelope_sig, envelope_id,"
        " sent_at_us, sent_at_text, canonical_hash, import_file"),
    "dsn_line": (
        "id, gateway_row, report_id, report_sig, item_id, item_sig,"
        " occurred_at_us, occurred_text, action, recipient_sig,"
        " recipient_text, queue_sig, queue_id, envelope_sig, envelope_id,"
        " canonical_hash, import_file"),
    "correction_line": (
        "id, gateway_row, report_id, report_sig, item_id, item_sig,"
        " target_report_id, target_report_sig, target_item_id,"
        " target_item_sig, occurred_at_us, occurred_text, action,"
        " recipient_sig, recipient_text, queue_sig, queue_id, envelope_sig,"
        " envelope_id, canonical_hash, import_file"),
    "manual_decision": (
        "id, line_key, requested_key, gateway_row, root_report_id,"
        " root_item_id, delivery_id, attempt_id, recipient_sig,"
        " candidate_fp, candidate_net, decided_at_us, decided_text,"
        " import_file"),
}


def _copy_facts(snapshot, closure, target):
    """Copy exactly the closure's fact rows, preserving row ids.

    Preserving ids keeps every internal reference (``line_key``,
    ``requested_key``, ``candidate_net`` recipient hex, FK columns) pointing at
    the same business fact, so a decision or candidate can never drift onto a
    different receipt after row numbering.
    """
    plan = {
        "outbound_attempt": sorted(closure.attempts),
        "dsn_line": closure.line_ids("dsn"),
        "correction_line": closure.line_ids("cor"),
        "manual_decision": sorted(closure.decisions),
    }

    def source_rows(table, ids):
        if not ids:
            return []
        placeholders = ",".join("?" * len(ids))
        return snapshot.conn.execute(
            f"SELECT {_COLUMNS[table]} FROM {table} WHERE id IN"
            f" ({placeholders}) ORDER BY id", ids).fetchall()

    fact_rows = {table: source_rows(table, ids)
                 for table, ids in plan.items()}
    gateway_ids, import_ids = set(), set()
    for rows in fact_rows.values():
        for row in rows:
            gateway_ids.add(int(row["gateway_row"]))
            import_ids.add(int(row["import_file"]))
    rows_by_table = {
        "gateway": source_rows("gateway", sorted(gateway_ids)),
        "import_file": source_rows("import_file", sorted(import_ids)),
        "outbound_attempt": fact_rows["outbound_attempt"],
        "dsn_line": fact_rows["dsn_line"],
        "correction_line": fact_rows["correction_line"],
        "manual_decision": fact_rows["manual_decision"],
    }
    counts = {}
    ids = {}
    for table in _FACT_TABLES:
        rows = rows_by_table[table]
        columns = [part.strip() for part in _COLUMNS[table].split(",")]
        target.conn.executemany(
            f"INSERT INTO {table} ({', '.join(columns)}) VALUES"
            f" ({', '.join('?' * len(columns))})",
            [tuple(row) for row in rows])
        counts[table] = len(rows)
        ids[table] = {int(row["id"]) for row in rows}
    return counts, ids


# --------------------------------------------------------------------------- #
# verification
# --------------------------------------------------------------------------- #
_KEY_RE = re.compile(r"\b(?:dsn|cor):\d+\b")


class _BusinessMap:
    """Map snapshot row ids to business identities (ids preserved)."""

    def __init__(self, snapshot):
        self.snapshot = snapshot

    def line_key(self, line_key):
        return self.snapshot.business_key(line_key)

    def text(self, text):
        if not text:
            return text

        def replace(match):
            key = match.group(0)
            if self.snapshot.line(key) is None:  # pragma: no cover
                return key
            return "<%s/%s/%s/%s>" % self.snapshot.business_key(key)

        return _KEY_RE.sub(replace, text)


def _link_view(ledger, business, wanted):
    if not wanted:
        return {}
    out = {}
    placeholders = ",".join("?" * len(wanted))
    for row in ledger.conn.execute(
            f"SELECT * FROM item_link WHERE line_key IN ({placeholders})",
            sorted(wanted)):
        key = row["line_key"]
        if key not in wanted:
            continue
        root = row["root_key"]
        chain_end = row["chain_end_key"]
        out[business.line_key(key)] = {
            "kind": row["kind"],
            "chain_state": row["chain_state"],
            "mark": row["mark"],
            "effective_action": row["effective_action"],
            "effective_at_us": row["effective_at_us"],
            "lookup_at_us": row["lookup_at_us"],
            "candidate_fp": row["candidate_fp"],
            "candidate_net": row["candidate_net"],
            "assigned_kind": row["assigned_kind"],
            "assigned": (None if row["delivery_id"] is None else
                         (row["delivery_id"], row["attempt_id"],
                          bytes(row["recipient_sig"]).hex())),
            "contributes": int(row["contributes"]),
            "root": (business.line_key(root) if root is not None else None),
            "chain_end": (business.line_key(chain_end)
                          if chain_end is not None else None),
            "chain_note": business.text(row["chain_note"]),
            "note": business.text(row["note"])}
    return out


def _candidate_view(ledger, business, wanted_roots):
    if not wanted_roots:
        return {}
    out = {}
    placeholders = ",".join("?" * len(wanted_roots))
    for row in ledger.conn.execute(
            f"SELECT * FROM item_candidate WHERE line_key IN"
            f" ({placeholders})", sorted(wanted_roots)):
        out.setdefault(business.line_key(row["line_key"]), set()).add(
            (row["delivery_id"], row["attempt_id"],
             bytes(row["recipient_sig"]).hex()))
    return {key: sorted(value) for key, value in out.items()}


def _attempt_status_view(ledger, wanted_rows, business):
    """Status rows for ``wanted_rows`` keyed by business identity.

    Row ids are preserved by the export, so selection by id is safe; the
    comparison key still uses the gateway/delivery/attempt/recipient tuple.
    """
    if not wanted_rows:
        return {}
    placeholders = ",".join("?" * len(wanted_rows))
    out = {}
    for row in ledger.conn.execute(
            "SELECT s.*, g.ident FROM derived_attempt_status s JOIN gateway g"
            f" ON g.id=s.gateway_row WHERE s.attempt_row IN ({placeholders})",
            sorted(wanted_rows)):
        key = (bytes(row["ident"]).decode().removeprefix("i:"),
               row["delivery_id"], row["attempt_id"],
               bytes(row["recipient_sig"]).hex())
        out[key] = {
            "status": row["status"],
            "effective_records": row["effective_records"],
            "contributors": _normalize_contributors(
                row["contributors"], business)}
    return out


def _decision_view(ledger, snapshot, wanted_roots):
    """Carried decisions keyed by business identity, never by row number."""
    if not wanted_roots:
        return {}
    out = {}
    for row in ledger.conn.execute("SELECT * FROM manual_decision"
                                   " ORDER BY id"):
        root = row["line_key"]
        if root not in wanted_roots:
            continue
        key = (snapshot.business_key(root), row["delivery_id"],
               row["attempt_id"], bytes(row["recipient_sig"]).hex(),
               row["candidate_fp"])
        out[key] = {
            "requested": (snapshot.business_key(row["requested_key"])
                          if snapshot.line(row["requested_key"]) is not None
                          else row["requested_key"]),
            "candidate_net": row["candidate_net"],
            "decided_at": row["decided_text"],
            "root_identity": (snapshot.business_key(root)[0],
                              row["root_report_id"], row["root_item_id"])}
    return out


def _normalize_contributors(text, business):
    """Contributors as business identities, order-independent."""
    normalized = []
    for entry in json.loads(text):
        root = entry["root"]
        normalized.append((
            entry["action"], entry["occurred_at_us"],
            business.line_key(root) if root is not None else None))
    return sorted(normalized)


def _delivery_view(ledger, delivery_keys):
    out = {}
    for gateway, delivery, sig_hex, recipient_text in delivery_keys:
        out[(gateway, delivery, sig_hex)] = ledger.delivery_status(
            gateway, delivery, recipient_text)
    return out


def _verify(source, target, snapshot, expected_ids, carried_deliveries):
    """Re-derive the sub-ledger and compare it with the snapshot.

    Comparisons use business identities only; physical row numbers and output
    order carry no meaning.
    """
    target.rebuild()
    problems = []

    for table in _FACT_TABLES:
        got = {int(row[0]) for row in
               target.conn.execute(f"SELECT id FROM {table}")}
        if got != expected_ids[table]:
            problems.append({
                "what": "fact_rows", "table": table,
                "unexpected": sorted(got - expected_ids[table]),
                "missing": sorted(expected_ids[table] - got)})
    if problems:
        return problems

    for table in ("gateway", "import_file"):
        column = "gateway_row" if table == "gateway" else "import_file"
        used = set()
        for fact in ("outbound_attempt", "dsn_line", "correction_line",
                     "manual_decision"):
            used |= {int(row[0]) for row in target.conn.execute(
                f"SELECT DISTINCT {column} FROM {fact}")}
        unused = expected_ids[table] - used
        if unused:
            problems.append({"what": "unreferenced_metadata", "table": table,
                             "ids": sorted(unused)})

    broken = [tuple(row) for row in
              target.conn.execute("PRAGMA foreign_key_check")]
    if broken:
        problems.append({"what": "foreign_key_check", "rows": broken})
    integrity = target.conn.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        problems.append({"what": "integrity_check", "result": integrity})

    business = _BusinessMap(snapshot)
    carried_items = set()
    for table in ("dsn_line", "correction_line"):
        prefix = "dsn" if table == "dsn_line" else "cor"
        carried_items |= {"%s:%s" % (prefix, row_id) for row_id in
                          expected_ids[table]}
    roots = {key for key in carried_items if key.startswith("dsn:")}

    # A decision's internal references must resolve to the same business fact
    # in the sub-ledger as in the source (never onto another receipt).
    for row in target.conn.execute("SELECT * FROM manual_decision"):
        root = row["line_key"]
        if root not in carried_items:
            problems.append({"what": "decision_root_out_of_scope",
                             "decision": int(row["id"])})
            continue
        identity = snapshot.business_key(root)
        if (identity[0], identity[2], identity[3]) != (
                snapshot.gateway_text(row["gateway_row"]),
                row["root_report_id"], row["root_item_id"]):
            problems.append({"what": "decision_root_identity",
                             "decision": int(row["id"])})
        requested = row["requested_key"]
        if requested not in carried_items and \
                snapshot.line(requested) is not None:
            problems.append({"what": "decision_requested_out_of_scope",
                             "decision": int(row["id"])})

    src_links = _link_view(source, business, carried_items)
    tgt_links = _link_view(target, business, carried_items)
    if set(src_links) != set(tgt_links):
        problems.append({"what": "item_links",
                         "only_source": sorted(str(k) for k in
                                               set(src_links) - set(tgt_links)),
                         "only_target": sorted(str(k) for k in
                                               set(tgt_links) - set(src_links))})
    for key in sorted(set(src_links) & set(tgt_links)):
        if src_links[key] != tgt_links[key]:
            problems.append({"what": "item_link", "key": list(key),
                             "source": src_links[key],
                             "target": tgt_links[key]})

    src_candidates = _candidate_view(source, business, roots)
    tgt_candidates = _candidate_view(target, business, roots)
    if src_candidates != tgt_candidates:
        problems.append({"what": "item_candidate",
                         "only_source": {str(k): v for k, v in
                                         src_candidates.items()
                                         if tgt_candidates.get(k) != v},
                         "only_target": {str(k): v for k, v in
                                         tgt_candidates.items()
                                         if src_candidates.get(k) != v}})

    carried_attempt_keys = {
        snapshot.attempt_business_key(attempt_id)
        for attempt_id in expected_ids["outbound_attempt"]}
    src_attempts = _attempt_status_view(
        source, expected_ids["outbound_attempt"], business)
    tgt_attempts = _attempt_status_view(
        target, expected_ids["outbound_attempt"], business)
    if src_attempts != tgt_attempts:
        problems.append({"what": "attempt_status",
                         "source": {str(k): v for k, v in
                                    sorted(src_attempts.items())},
                         "target": {str(k): v for k, v in
                                    sorted(tgt_attempts.items())}})
    del carried_attempt_keys

    carried_roots = {
        "%s:%s" % ("dsn", row_id) for row_id in expected_ids["dsn_line"]}
    src_decisions = _decision_view(source, snapshot, carried_roots)
    tgt_decisions = _decision_view(target, snapshot, carried_roots)
    if src_decisions != tgt_decisions:
        problems.append({"what": "human_decisions",
                         "source": {str(k): v for k, v in
                                    sorted(src_decisions.items())},
                         "target": {str(k): v for k, v in
                                    sorted(tgt_decisions.items())}})

    src_deliveries = _delivery_view(snapshot.ledger, carried_deliveries)
    tgt_deliveries = _delivery_view(target, carried_deliveries)
    if src_deliveries != tgt_deliveries:
        problems.append({"what": "delivery_status",
                         "source": {str(k): v for k, v in
                                    sorted(src_deliveries.items())},
                         "target": {str(k): v for k, v in
                                    sorted(tgt_deliveries.items())}})
    return problems


# --------------------------------------------------------------------------- #
# selection.json
# --------------------------------------------------------------------------- #
def _selection_document(snapshot, closure, selection, digest, counts,
                        source_path):
    business = _BusinessMap(snapshot)
    attempts = []
    for attempt_id in sorted(closure.attempts):
        row = snapshot.attempt(attempt_id)
        attempts.append({
            "gateway_id": snapshot.gateway_text(row["gateway_row"]),
            "delivery_id": row["delivery_id"],
            "attempt_id": row["attempt_id"],
            "recipient": row["recipient_text"],
            "reasons": sorted(closure.attempts[attempt_id])})
    attempts.sort(key=lambda entry: (entry["gateway_id"],
                                     entry["delivery_id"],
                                     entry["attempt_id"],
                                     entry["recipient"]))

    items = []
    for line_key in sorted(closure.items):
        row = snapshot.line(line_key)
        entry = {
            "kind": ("original" if line_key.startswith("dsn:")
                     else "correction"),
            "gateway_id": snapshot.gateway_text(row["gateway_row"]),
            "report_id": row["report_id"],
            "item_id": row["item_id"],
            "reasons": sorted(closure.items[line_key])}
        if line_key.startswith("cor:"):
            entry["target_report_id"] = row["target_report_id"]
            entry["target_item_id"] = row["target_item_id"]
        items.append(entry)
    items.sort(key=lambda entry: (entry["gateway_id"], entry["kind"],
                                  entry["report_id"], entry["item_id"]))

    decisions = []
    for decision_id in sorted(closure.decisions):
        row = snapshot.decision(decision_id)
        root = row["line_key"]
        current_fp = None
        if root.startswith("dsn:"):
            current_fp = snapshot.view(root)["candidate_fp"]
        decisions.append({
            "gateway_id": snapshot.gateway_text(row["gateway_row"]),
            "root": {"report_id": row["root_report_id"],
                     "item_id": row["root_item_id"]},
            "chosen": {"delivery_id": row["delivery_id"],
                       "attempt_id": row["attempt_id"],
                       "recipient_sig": bytes(row["recipient_sig"]).hex()},
            "candidate_fingerprint": row["candidate_fp"],
            "candidate_set": json.loads(row["candidate_net"]),
            "decided_at": row["decided_text"],
            "still_applies": bool(current_fp == row["candidate_fp"]),
            "reasons": sorted(closure.decisions[decision_id])})

    gateways = [{"gateway_id": snapshot.gateway_text(gateway_row),
                 "reasons": sorted(closure.gateways[gateway_row])}
                for gateway_row in sorted(closure.gateways)]

    # deliveries are the retry scopes actually carried (an attempt is always
    # carried together with its whole retry group)
    deliveries = {}
    for attempt_id in sorted(closure.attempts):
        row = snapshot.attempt(attempt_id)
        key = (snapshot.gateway_text(row["gateway_row"]),
               row["delivery_id"], bytes(row["recipient_sig"]).hex())
        entry = deliveries.setdefault(key, {
            "gateway_id": key[0], "delivery_id": key[1],
            "recipient": row["recipient_text"],
            "recipient_sig": key[2], "attempts": [], "reasons": set()})
        entry["attempts"].append(row["attempt_id"])
        entry["reasons"].update(closure.attempts[attempt_id])
    delivery_list = []
    for key in sorted(deliveries):
        entry = deliveries[key]
        entry["attempts"].sort()
        entry["reasons"] = sorted(entry["reasons"])
        delivery_list.append(entry)

    import_files = []
    for file_id in sorted(closure.import_files):
        row = snapshot.conn.execute(
            "SELECT * FROM import_file WHERE id=?", (file_id,)).fetchone()
        carried = {
            "outbound_attempts": sum(
                1 for attempt_id in closure.attempts
                if snapshot.attempt(attempt_id)["import_file"] == file_id),
            "dsn_originals": sum(
                1 for key in closure.items if key.startswith("dsn:")
                and snapshot.line(key)["import_file"] == file_id),
            "corrections": sum(
                1 for key in closure.items if key.startswith("cor:")
                and snapshot.line(key)["import_file"] == file_id),
            "human_decisions": sum(
                1 for decision_id in closure.decisions
                if snapshot.decision(decision_id)["import_file"] == file_id)}
        carried_total = sum(carried.values())
        import_files.append({
            "source_name": row["source_name"],
            "kind": row["kind"],
            "sha256": row["sha256"],
            "source_line_count": row["line_count"],
            "carried_rows": carried,
            "carried_total": carried_total,
            "partial": carried_total < row["line_count"],
            "note": ("sha256/source_name/source_line_count describe the "
                     "original imported file; carried_rows counts only the "
                     "rows present in this sub-ledger"),
            "reasons": sorted(closure.import_files[file_id])})
    import_files.sort(key=lambda entry: (entry["source_name"],
                                         entry["sha256"]))

    absent = []
    for synthetic in sorted(closure.absent):
        meta = snapshot.absent_meta[synthetic]
        absent.append({
            "gateway_id": snapshot.gateway_text(meta["gateway_row"]),
            "report_id": meta["report_id"],
            "item_id": meta["item_id"],
            "report_sig": meta["report_sig"],
            "item_sig": meta["item_sig"],
            "reasons": sorted(closure.absent[synthetic]),
            "note": "logical identity only; no missing fact is fabricated"})
    absent.sort(key=lambda entry: (entry["gateway_id"], entry["report_id"],
                                   entry["item_id"]))

    groups = []
    for line_key in sorted(closure.items):
        if not line_key.startswith("dsn:"):
            continue
        view = snapshot.view(line_key)
        row = snapshot.line(line_key)
        groups.append({
            "root": {"gateway_id": snapshot.gateway_text(row["gateway_row"]),
                     "report_id": row["report_id"],
                     "item_id": row["item_id"]},
            "chain_state": view["chain_state"],
            "mark": view["mark"],
            "effective_action": view["effective_action"],
            "effective_at_us": view["effective_at_us"],
            "candidate_fingerprint": view["candidate_fp"],
            "candidate_count": len(view["candidates"]),
            "candidates": [
                {"delivery_id": member[1], "attempt_id": member[2],
                 "recipient_sig": bytes(member[3]).hex()}
                for member in view["candidates"]],
            "contributes": bool(view["contributes"]),
            "note": business.text(view["note"])})
    groups.sort(key=lambda entry: (entry["root"]["gateway_id"],
                                   entry["root"]["report_id"],
                                   entry["root"]["item_id"]))

    selection_out = {
        "deliveries": [{
            "gateway_id": entry["gateway_id"],
            "delivery_id": entry["delivery_id"],
            "recipient": entry["recipient"],
            "recipient_canonical": entry["recipient_canonical"]}
            for entry in selection[SEL_DELIVERIES]],
        "items": [{
            "gateway_id": entry["gateway_id"],
            "report_id": entry["report_id"],
            "item_id": entry["item_id"]}
            for entry in selection[SEL_ITEMS]]}

    fact_counts = {
        "gateways": counts["gateway"],
        "import_files": counts["import_file"],
        "outbound_attempts": counts["outbound_attempt"],
        "dsn_originals": counts["dsn_line"],
        "corrections": counts["correction_line"],
        "human_decisions": counts["manual_decision"],
    }
    return {
        "tool": "receipt_ledger export-case",
        "format_version": 1,
        "source": {
            "path": os.path.abspath(source_path),
            "snapshot_fact_digest": digest,
            "note": ("all carried facts come from one SQLite read snapshot; "
                     "derivations in ledger.sqlite were regenerated from "
                     "these facts, not copied")},
        "selection": selection_out,
        "fact_counts": fact_counts,
        "carried": {
            "gateways": gateways,
            "deliveries": delivery_list,
            "attempts": attempts,
            "items": items,
            "human_decisions": decisions,
            "import_files": import_files,
            "absent_targets": absent,
            "receipt_groups": groups},
    }


# --------------------------------------------------------------------------- #
# publication
# --------------------------------------------------------------------------- #
def _write_json(path, document):
    data = json.dumps(document, indent=2, sort_keys=False,
                      ensure_ascii=False) + "\n"
    with open(path, "xb") as handle:
        handle.write(data.encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())


def _sync_dir(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish(temp_dir, output_dir):
    if os.path.lexists(output_dir):
        raise ExportError("output_exists",
                          f"output path {output_dir!r} already exists; "
                          "refusing to overwrite it")
    os.rename(temp_dir, output_dir)


# --------------------------------------------------------------------------- #
# public entry point
# --------------------------------------------------------------------------- #
def export_case(source_path, selectors, output_dir):
    """Export an investigation sub-ledger.

    ``selectors`` is a selector document (object, JSON text or UTF-8 bytes).
    Raises :class:`ExportError` on an invalid/unknown selection, an existing
    target, a snapshot/write failure or a verification mismatch.  Nothing is
    published in a failure case.
    """
    selection = parse_selection(selectors)
    if os.path.lexists(output_dir):
        raise ExportError("output_exists",
                          f"output path {output_dir!r} already exists; "
                          "refusing to overwrite it")
    parent = os.path.dirname(os.path.abspath(output_dir))
    if not os.path.isdir(parent):
        raise ExportError("output_error",
                          f"parent directory of {output_dir!r} does not exist")

    snapshot = snap_path = None
    temp_dir = None
    document = None
    try:
        snapshot, snap_path, digest = _open_source_snapshot(source_path)
        if _after_snapshot_hook is not None:
            _after_snapshot_hook()
        structure = _Snapshot(snapshot)
        closure = _Closure(structure, selection)
        closure.resolve()

        carried_ids = {
            "gateway": set(closure.gateways),
            "import_file": set(closure.import_files),
            "outbound_attempt": set(closure.attempts),
            "dsn_line": set(closure.line_ids("dsn")),
            "correction_line": set(closure.line_ids("cor")),
            "manual_decision": set(closure.decisions),
        }
        carried_deliveries = sorted({
            (structure.gateway_text(row["gateway_row"]), row["delivery_id"],
             bytes(row["recipient_sig"]).hex(), row["recipient_text"])
            for row in (structure.attempt(attempt_id)
                        for attempt_id in closure.attempts)})

        temp_dir = "%s.tmp-%s" % (output_dir, uuid.uuid4().hex)
        os.mkdir(temp_dir)
        target = Ledger.create(os.path.join(temp_dir, LEDGER_NAME))
        try:
            target._begin()
            try:
                counts, copied_ids = _copy_facts(structure, closure, target)
                target._commit()
            except Exception:
                target._rollback()
                raise
            if any(copied_ids[table] != carried_ids[table]
                   for table in _FACT_TABLES):  # pragma: no cover - guarded
                raise ExportError(
                    "verification_failed",
                    "copied fact rows differ from the computed closure",
                    {"expected": {k: sorted(v) for k, v in carried_ids.items()},
                     "copied": {k: sorted(v) for k, v in copied_ids.items()}})
            problems = _verify(snapshot, target, structure, carried_ids,
                               carried_deliveries)
            if problems:
                raise ExportError(
                    "verification_failed",
                    "the sub-ledger does not reproduce the source snapshot "
                    "for the carried facts",
                    {"problems": problems})
            document = _selection_document(
                structure, closure, selection, digest, counts, source_path)
            _write_json(os.path.join(temp_dir, SELECTION_NAME), document)
            _sync_dir(temp_dir)
            if _publish_hook is not None:
                _publish_hook()
            _publish(temp_dir, output_dir)
            temp_dir = None
        finally:
            target.close()
    except ExportError:
        raise
    except (LedgerError, sqlite3.Error, OSError) as exc:
        raise ExportError(getattr(exc, "code", None) or "output_error",
                          str(exc), getattr(exc, "details", None)) from exc
    finally:
        if snapshot is not None:
            snapshot.close()
        if snap_path is not None:
            _unlink(snap_path)
        if temp_dir is not None:
            shutil.rmtree(temp_dir, ignore_errors=True)

    return {
        "output_dir": output_dir,
        "ledger": os.path.join(output_dir, LEDGER_NAME),
        "selection": os.path.join(output_dir, SELECTION_NAME),
        "fact_counts": document["fact_counts"],
        "snapshot_fact_digest": digest,
    }
