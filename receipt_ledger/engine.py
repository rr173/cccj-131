"""Import and derivation engine.

Contract
--------
* Facts are append-only.  A byte-identical re-import is a no-op.  A row whose
  identity already exists with identical canonical content is a no-op for that
  row; the same identity with different content fails the whole file.
* Every import is atomic: the whole file is parsed and validated first and any
  failure rolls the file back completely (no partial data).
* Derivations are recomputed from facts.  After an import only the affected
  *chain roots* are re-evaluated.  Affected-root detection is one indexed join
  against a temp table of the new rows, never a Python loop per row and never a
  full scan of outbound attempts.
* No function here picks "the most plausible" candidate, correction branch or
  action.  Undecidable evidence keeps an explicit undecidable marker.
"""

from __future__ import annotations

import json
import sqlite3

from . import ingest
from .addr import recipient_sig
from .chains import CLEAN, CONFLICT, CYCLE, PENDING, analyse
from .errors import DecisionError, InputIdentityError
from .fingerprint import fingerprint
from .jsonio import canonical_json, read_jsonl_bytes, sha256_hex
from .schema import check_schema, create_schema

DEFAULT_GATEWAY = "default"
TERMINALS = ("delivered", "failed")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _key(kind, row_id):
    return f"{kind}:{row_id}"


def _ref_key(gateway_ident, report_sig, item_sig):
    """Key for an item identity that has not been imported yet."""
    return "ref:%s:%s:%s" % (
        gateway_ident.hex(), report_sig.hex(), item_sig.hex())


def _net_json(candidates):
    """Canonical JSON of a candidate set (order-independent)."""
    ordered = sorted(candidates, key=lambda m: (m[1], m[2], m[3]))
    return canonical_json([
        {"delivery_id": m[1], "attempt_id": m[2], "recipient": m[3].hex()}
        for m in ordered])


def _json_candidates(candidates):
    return [{"delivery_id": m[1], "attempt_id": m[2],
             "recipient_sig": m[3].hex()} for m in candidates]


class ImportOutcome(dict):
    """JSON-serializable import result."""


class Ledger:
    def __init__(self, conn):
        self.conn = conn
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")

    # -- lifecycle ---------------------------------------------------------- #
    @classmethod
    def create(cls, path=":memory:"):
        conn = sqlite3.connect(path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        create_schema(conn)
        return cls(conn)

    @classmethod
    def open(cls, path):
        conn = sqlite3.connect(path, isolation_level=None)
        check_schema(conn)
        return cls(conn)

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- transactions ------------------------------------------------------- #
    def _begin(self):
        self.conn.execute("BEGIN IMMEDIATE")

    def _rollback(self):
        try:
            self.conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _commit(self):
        self.conn.execute("COMMIT")

    def _gateway_row(self, ident, create=True):
        row = self.conn.execute(
            "SELECT id FROM gateway WHERE ident=?", (ident,)).fetchone()
        if row:
            return row[0]
        if not create:
            return None
        return self.conn.execute(
            "INSERT INTO gateway (ident) VALUES (?)", (ident,)).lastrowid

    def _gw(self, gateway_id):
        return self._gateway_row(
            ingest.gateway_signature(gateway_id, "gateway"), create=False)

    def _file_row(self, sha):
        return self.conn.execute(
            "SELECT id FROM import_file WHERE sha256=?", (sha,)).fetchone()

    def _record_file(self, kind, source, sha, line_count):
        return self.conn.execute(
            "INSERT INTO import_file (sha256, kind, source_name, line_count)"
            " VALUES (?,?,?,?)",
            (sha, kind, source, line_count)).lastrowid

    # ================================================================== #
    # OUTBOUND ATTEMPTS
    # ================================================================== #
    @staticmethod
    def _outbound_hash(gateway_text, p):
        return sha256_hex(canonical_json([
            "outbound", gateway_text, p["delivery_id"], p["attempt_id"],
            p["recipient"], p["queue_id"], p["envelope_id"], p["sent_at_us"]]))

    def import_outbound(self, data, *, source="<outbound>",
                        default_gateway=DEFAULT_GATEWAY):
        records, sha = read_jsonl_bytes(data, source=source)
        parsed, seen = [], {}
        for lineno, obj in records:
            where = f"{source}:{lineno}"
            p = ingest.parse_outbound(obj, where)
            gw_text = p["gateway_id"] or default_gateway
            p["gateway_text"] = gw_text
            p["gateway_sig"] = ingest.gateway_signature(gw_text, where)
            p["canonical_hash"] = self._outbound_hash(gw_text, p)
            ident = (gw_text, p["delivery_id"], p["attempt_id"],
                     p["recipient_sig"])
            if ident in seen and seen[ident] != p["canonical_hash"]:
                raise InputIdentityError(
                    f"{where}: attempt identity {p['delivery_id']}/"
                    f"{p['attempt_id']}/{p['recipient']} repeated within the "
                    "file with different content",
                    {"line": lineno, "delivery_id": p["delivery_id"],
                     "attempt_id": p["attempt_id"],
                     "recipient": p["recipient"]})
            seen.setdefault(ident, p["canonical_hash"])
            parsed.append(p)

        if self._file_row(sha):
            return ImportOutcome(kind="outbound", source=source, sha256=sha,
                                 skipped=True, inserted=0, duplicate_rows=0,
                                 affected_roots=0, affected_attempts=0)

        self._begin()
        try:
            file_id = self._record_file("outbound", source, sha, len(records))
            inserted = duplicates = 0
            self.conn.execute("CREATE TEMP TABLE IF NOT EXISTS new_attempt_ids"
                              " (id INTEGER PRIMARY KEY)")
            self.conn.execute("DELETE FROM new_attempt_ids")
            for p in parsed:
                gw_row = self._gateway_row(p["gateway_sig"])
                existing = self.conn.execute(
                    "SELECT canonical_hash FROM outbound_attempt WHERE"
                    " gateway_row=? AND delivery_id=? AND attempt_id=?"
                    " AND recipient_sig=?",
                    (gw_row, p["delivery_id"], p["attempt_id"],
                     p["recipient_sig"])).fetchone()
                if existing:
                    if existing["canonical_hash"] != p["canonical_hash"]:
                        raise InputIdentityError(
                            f"{source}: attempt {p['delivery_id']}/"
                            f"{p['attempt_id']}/{p['recipient']} already "
                            "exists with different content",
                            {"delivery_id": p["delivery_id"],
                             "attempt_id": p["attempt_id"],
                             "recipient": p["recipient"]})
                    duplicates += 1
                    continue
                rowid = self.conn.execute(
                    "INSERT INTO outbound_attempt (gateway_row, delivery_id,"
                    " attempt_id, recipient_sig, recipient_text, queue_sig,"
                    " queue_id, envelope_sig, envelope_id, sent_at_us,"
                    " sent_at_text, canonical_hash, import_file)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (gw_row, p["delivery_id"], p["attempt_id"],
                     p["recipient_sig"], p["recipient"], p["queue_sig"],
                     p["queue_id"], p["envelope_sig"], p["envelope_id"],
                     p["sent_at_us"], p["sent_at_text"], p["canonical_hash"],
                     file_id)).lastrowid
                self.conn.execute("INSERT INTO new_attempt_ids (id) VALUES (?)",
                                  (rowid,))
                inserted += 1
            # Default row for every attempt so "no evidence" is materialized as
            # awaiting even for attempts nothing ever references.
            self.conn.execute(
                "INSERT OR IGNORE INTO derived_attempt_status (attempt_row,"
                " gateway_row, delivery_id, attempt_id, recipient_sig,"
                " sent_at_us, effective_records, status, contributors)"
                " SELECT id, gateway_row, delivery_id, attempt_id,"
                " recipient_sig, sent_at_us, 0, 'awaiting', '[]'"
                " FROM outbound_attempt WHERE id IN (SELECT id FROM"
                " new_attempt_ids)")
            affected_roots = self._roots_for_new_attempts()
            self._refresh_roots(affected_roots)
            self.conn.execute("DROP TABLE IF EXISTS new_attempt_ids")
            self._commit()
        except Exception:
            self._rollback()
            raise
        return ImportOutcome(kind="outbound", source=source, sha256=sha,
                             skipped=False, inserted=inserted,
                             duplicate_rows=duplicates,
                             affected_roots=len(affected_roots),
                             affected_attempts=inserted)

    def _roots_for_new_attempts(self):
        """One indexed join: roots any newly inserted attempt could match.

        ``lookup_at_us`` is the maximum occurred_at in a chain, hence an upper
        bound on its effective time; a root below it cannot satisfy
        ``sent_at <= occurred_at``.  Queue/envelope predicates mirror the
        matcher's intersection.  The result is a safe superset of roots whose
        candidate set changed.
        """
        return {r[0] for r in self.conn.execute(
            "SELECT DISTINCT l.line_key"
            " FROM item_link l"
            " JOIN outbound_attempt a"
            "   ON a.gateway_row = l.gateway_row"
            "  AND a.recipient_sig = l.recipient_sig"
            " WHERE l.kind='dsn'"
            "   AND a.id IN (SELECT id FROM new_attempt_ids)"
            "   AND a.sent_at_us <= l.lookup_at_us"
            "   AND (l.cond_queue_sig IS NULL OR l.cond_queue_sig = a.queue_sig)"
            "   AND (l.cond_envelope_sig IS NULL"
            "        OR l.cond_envelope_sig = a.envelope_sig)")}

    # ================================================================== #
    # DSN ORIGINALS
    # ================================================================== #
    @staticmethod
    def _dsn_hash(gateway_text, p):
        return sha256_hex(canonical_json([
            "dsn", gateway_text, p["report_id"], p["item_id"],
            p["occurred_at_us"], p["action"], p["recipient"],
            p["queue_id"], p["envelope_id"]]))

    def import_dsn(self, data, *, source="<dsn>"):
        records, sha = read_jsonl_bytes(data, source=source)
        parsed, seen = [], {}
        for lineno, obj in records:
            where = f"{source}:{lineno}"
            p = ingest.parse_dsn(obj, where)
            p["canonical_hash"] = self._dsn_hash(p["gateway_id"], p)
            ident = (p["gateway_sig"], p["report_sig"], p["item_sig"])
            if ident in seen and seen[ident] != p["canonical_hash"]:
                raise InputIdentityError(
                    f"{where}: receipt identity {p['report_id']}/"
                    f"{p['item_id']} repeated within the file with different "
                    "content",
                    {"line": lineno, "report_id": p["report_id"],
                     "item_id": p["item_id"]})
            seen.setdefault(ident, p["canonical_hash"])
            parsed.append(p)

        if self._file_row(sha):
            return ImportOutcome(kind="dsn", source=source, sha256=sha,
                                 skipped=True, inserted=0, duplicate_rows=0,
                                 affected_roots=0, affected_attempts=0)

        self._begin()
        try:
            file_id = self._record_file("dsn", source, sha, len(records))
            inserted = duplicates = 0
            affected_roots = set()
            for p in parsed:
                gw_row = self._gateway_row(p["gateway_sig"])
                existing = self.conn.execute(
                    "SELECT canonical_hash FROM dsn_line WHERE gateway_row=?"
                    " AND report_sig=? AND item_sig=?",
                    (gw_row, p["report_sig"], p["item_sig"])).fetchone()
                if existing:
                    if existing["canonical_hash"] != p["canonical_hash"]:
                        raise InputIdentityError(
                            f"{source}: receipt {p['report_id']}/"
                            f"{p['item_id']} already exists with different "
                            "content",
                            {"report_id": p["report_id"],
                             "item_id": p["item_id"]})
                    duplicates += 1
                    continue
                self._assert_identity_free(gw_row, p["report_sig"],
                                           p["item_sig"], source,
                                           p["report_id"], p["item_id"])
                row_id = self.conn.execute(
                    "INSERT INTO dsn_line (gateway_row, report_id, report_sig,"
                    " item_id, item_sig, occurred_at_us, occurred_text, action,"
                    " recipient_sig, recipient_text, queue_sig, queue_id,"
                    " envelope_sig, envelope_id, canonical_hash, import_file)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (gw_row, p["report_id"], p["report_sig"], p["item_id"],
                     p["item_sig"], p["occurred_at_us"], p["occurred_text"],
                     p["action"], p["recipient_sig"], p["recipient"],
                     p["queue_sig"], p["queue_id"], p["envelope_sig"],
                     p["envelope_id"], p["canonical_hash"], file_id)).lastrowid
                inserted += 1
                affected_roots.add(_key("dsn", row_id))
            affected_attempts = self._refresh_roots(affected_roots)
            self._commit()
        except Exception:
            self._rollback()
            raise
        return ImportOutcome(kind="dsn", source=source, sha256=sha,
                             skipped=False, inserted=inserted,
                             duplicate_rows=duplicates,
                             affected_roots=len(affected_roots),
                             affected_attempts=affected_attempts)

    def _assert_identity_free(self, gw_row, report_sig, item_sig, source,
                              report_id, item_id):
        for table in ("dsn_line", "correction_line"):
            row = self.conn.execute(
                f"SELECT 1 FROM {table} WHERE gateway_row=? AND report_sig=?"
                f" AND item_sig=?", (gw_row, report_sig, item_sig)).fetchone()
            if row:
                kind = "receipt" if table == "dsn_line" else "correction"
                raise InputIdentityError(
                    f"{source}: identity {report_id}/{item_id} is already used"
                    f" by an existing {kind} in this gateway",
                    {"report_id": report_id, "item_id": item_id})

    # ================================================================== #
    # CORRECTIONS
    # ================================================================== #
    @staticmethod
    def _correction_hash(gateway_text, p):
        return sha256_hex(canonical_json([
            "correction", gateway_text, p["report_id"], p["item_id"],
            p["target_report_id"], p["target_item_id"], p["occurred_at_us"],
            p["action"], p["recipient"], p["queue_id"], p["envelope_id"]]))

    def import_corrections(self, data, *, source="<corrections>"):
        records, sha = read_jsonl_bytes(data, source=source)
        parsed, seen = [], {}
        for lineno, obj in records:
            where = f"{source}:{lineno}"
            p = ingest.parse_correction(obj, where)
            p["canonical_hash"] = self._correction_hash(p["gateway_id"], p)
            ident = (p["gateway_sig"], p["report_sig"], p["item_sig"])
            if ident in seen and seen[ident] != p["canonical_hash"]:
                raise InputIdentityError(
                    f"{where}: correction identity {p['report_id']}/"
                    f"{p['item_id']} repeated within the file with different "
                    "content",
                    {"line": lineno, "report_id": p["report_id"],
                     "item_id": p["item_id"]})
            seen.setdefault(ident, p["canonical_hash"])
            parsed.append(p)

        if self._file_row(sha):
            return ImportOutcome(kind="corrections", source=source, sha256=sha,
                                 skipped=True, inserted=0, duplicate_rows=0,
                                 affected_roots=0, affected_attempts=0)

        self._begin()
        try:
            file_id = self._record_file("corrections", source, sha,
                                        len(records))
            inserted = duplicates = 0
            affected_roots = set()
            inserted_keys = []
            orphaned = False
            for p in parsed:
                gw_row = self._gateway_row(p["gateway_sig"])
                existing = self.conn.execute(
                    "SELECT canonical_hash FROM correction_line WHERE"
                    " gateway_row=? AND report_sig=? AND item_sig=?",
                    (gw_row, p["report_sig"], p["item_sig"])).fetchone()
                if existing:
                    if existing["canonical_hash"] != p["canonical_hash"]:
                        raise InputIdentityError(
                            f"{source}: correction {p['report_id']}/"
                            f"{p['item_id']} already exists with different "
                            "content",
                            {"report_id": p["report_id"],
                             "item_id": p["item_id"]})
                    duplicates += 1
                    continue
                self._assert_identity_free(gw_row, p["report_sig"],
                                           p["item_sig"], source,
                                           p["report_id"], p["item_id"])
                row_id = self.conn.execute(
                    "INSERT INTO correction_line (gateway_row, report_id,"
                    " report_sig, item_id, item_sig, target_report_id,"
                    " target_report_sig, target_item_id, target_item_sig,"
                    " occurred_at_us, occurred_text, action, recipient_sig,"
                    " recipient_text, queue_sig, queue_id, envelope_sig,"
                    " envelope_id, canonical_hash, import_file)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (gw_row, p["report_id"], p["report_sig"], p["item_id"],
                     p["item_sig"], p["target_report_id"],
                     p["target_report_sig"], p["target_item_id"],
                     p["target_item_sig"], p["occurred_at_us"],
                     p["occurred_text"], p["action"], p["recipient_sig"],
                     p["recipient"], p["queue_sig"], p["queue_id"],
                     p["envelope_sig"], p["envelope_id"],
                     p["canonical_hash"], file_id)).lastrowid
                inserted += 1
                inserted_keys.append(_key("cor", row_id))
                # The target's chain root can only be found after the insert;
                # it is the chain whose action/time may change.
                root = self._climb_root(gw_row, p["target_report_sig"],
                                        p["target_item_sig"])
                if root:
                    affected_roots.add(root)
                else:
                    orphaned = True
            # Climbing from each target already yields the one chain a new
            # correction can reshape (it is a new child of that chain), and the
            # scoped graph walk reloads every node below that root -- including
            # corrections that were pending until this import.  Chains that
            # merely lost a pending child are found by re-climbing their
            # stored orphans.
            affected_roots |= self._roots_completed_by_pending()
            refreshed = self._refresh_roots(affected_roots)
            if orphaned:
                # a correction whose parent is still absent must stay queryable
                self._refresh_orphan_links()
            self._commit()
        except Exception:
            self._rollback()
            raise
        return ImportOutcome(kind="corrections", source=source, sha256=sha,
                             skipped=False, inserted=inserted,
                             duplicate_rows=duplicates,
                             affected_roots=len(affected_roots),
                             affected_attempts=refreshed)

    def _roots_completed_by_pending(self):
        """Roots of chains whose pending corrections may now resolve."""
        roots = set()
        for cor_key, in self.conn.execute(
                "SELECT DISTINCT line_key FROM item_link WHERE kind='cor'"
                " AND chain_state='pending'").fetchall():
            row = self.conn.execute(
                "SELECT gateway_row, target_report_sig, target_item_sig"
                " FROM correction_line WHERE id=?",
                (int(cor_key.split(":")[1]),)).fetchone()
            if row is None:
                continue
            root = self._climb_root(row[0], row[1], row[2])
            if root:
                roots.add(root)
        return roots

    def _climb_root(self, gw_row, report_sig, item_sig):
        """Walk parent pointers in the fact layer to the original item key."""
        seen = set()
        while True:
            hit = self.conn.execute(
                "SELECT id FROM dsn_line WHERE gateway_row=? AND report_sig=?"
                " AND item_sig=?", (gw_row, report_sig, item_sig)).fetchone()
            if hit:
                return _key("dsn", hit[0])
            cor = self.conn.execute(
                "SELECT id, target_report_sig, target_item_sig"
                " FROM correction_line WHERE gateway_row=? AND report_sig=?"
                " AND item_sig=?", (gw_row, report_sig, item_sig)).fetchone()
            if not cor:
                return None
            key = _key("cor", cor["id"])
            if key in seen:
                return None          # cycle: no original root exists
            seen.add(key)
            report_sig, item_sig = (cor["target_report_sig"],
                                    cor["target_item_sig"])

    # ================================================================== #
    # MANUAL DECISIONS
    # ================================================================== #
    def import_resolutions(self, data, *, source="<resolutions>"):
        records, sha = read_jsonl_bytes(data, source=source)
        parsed, seen = [], set()
        for lineno, obj in records:
            where = f"{source}:{lineno}"
            p = ingest.parse_resolve(obj, where)
            ident = (p["gateway_sig"], p["report_sig"], p["item_sig"],
                     p["delivery_id"], p["attempt_id"], p["recipient_sig"],
                     p["candidate_fingerprint"])
            if ident in seen:
                continue
            seen.add(ident)
            parsed.append(p)

        if self._file_row(sha):
            return ImportOutcome(kind="resolutions", source=source, sha256=sha,
                                 skipped=True, inserted=0, duplicate_rows=0,
                                 affected_roots=0, affected_attempts=0)

        self._begin()
        try:
            file_id = self._record_file("resolutions", source, sha,
                                        len(records))
            ctx, info = self._load_graph()
            inserted = 0
            affected_roots = set()
            for p in parsed:
                gw_row = self._gw(p["gateway_id"])
                if gw_row is None:
                    raise DecisionError(
                        f"{source}: decision names an unknown gateway "
                        f"{p['gateway_id']!r}")
                item_kind, item_id = self._find_item(
                    gw_row, p["report_sig"], p["item_sig"])
                if item_kind is None:
                    raise DecisionError(
                        f"{source}: decision names an item that has not been "
                        "imported")
                root = self._climb_root(gw_row, p["report_sig"], p["item_sig"])
                if root is None:
                    raise DecisionError(
                        f"{source}: decision names an item whose chain has no "
                        "original receipt (pending or cyclic)")
                if info.state.get(root) != CLEAN:
                    raise DecisionError(
                        f"{source}: chain {root} is "
                        f"{info.state.get(root)}; it cannot be resolved",
                        {"item": root, "chain_state": info.state.get(root)})
                view = self._evaluate_root(ctx, info, root)
                if view["candidate_fp"] != p["candidate_fingerprint"]:
                    raise DecisionError(
                        f"{source}: stale decision for {root}: the candidate "
                        "set changed after the fingerprint was issued",
                        {"item": root,
                         "supplied_fingerprint": p["candidate_fingerprint"],
                         "current_fingerprint": view["candidate_fp"],
                         "current_candidates": _json_candidates(
                             view["candidates"])})
                chosen = (p["delivery_id"], p["attempt_id"],
                          p["recipient_sig"])
                if not any((m[1], m[2], m[3]) == chosen
                           for m in view["candidates"]):
                    raise DecisionError(
                        f"{source}: chosen attempt is not in the current "
                        "candidate set",
                        {"item": root,
                         "current_candidates": _json_candidates(
                             view["candidates"])})
                root_dsn = self.conn.execute(
                    "SELECT report_id, item_id FROM dsn_line WHERE id=?",
                    (int(root.split(":")[1]),)).fetchone()
                root_report_id, root_item_id = root_dsn[0], root_dsn[1]
                dup = self.conn.execute(
                    "SELECT 1 FROM manual_decision WHERE line_key=?"
                    " AND delivery_id=? AND attempt_id=? AND recipient_sig=?"
                    " AND candidate_fp=?",
                    (root, p["delivery_id"], p["attempt_id"],
                     p["recipient_sig"], p["candidate_fingerprint"])).fetchone()
                if dup:
                    continue
                self.conn.execute(
                    "INSERT INTO manual_decision (line_key, requested_key,"
                    " gateway_row, root_report_id, root_item_id,"
                    " delivery_id, attempt_id, recipient_sig,"
                    " candidate_fp, candidate_net, decided_at_us, decided_text,"
                    " import_file) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (root, _key(item_kind, item_id), gw_row,
                     root_report_id, root_item_id,
                     p["delivery_id"], p["attempt_id"], p["recipient_sig"],
                     p["candidate_fingerprint"],
                     _net_json(view["candidates"]),
                     p["decided_at_us"], p["decided_text"], file_id))
                inserted += 1
                affected_roots.add(root)
            affected_attempts = self._refresh_roots(affected_roots)
            self._commit()
        except Exception:
            self._rollback()
            raise
        return ImportOutcome(kind="resolutions", source=source, sha256=sha,
                             skipped=False, inserted=inserted, duplicate_rows=0,
                             affected_roots=len(affected_roots),
                             affected_attempts=affected_attempts)

    def _find_item(self, gw_row, report_sig, item_sig):
        for kind, table in (("dsn", "dsn_line"),
                            ("cor", "correction_line")):
            row = self.conn.execute(
                f"SELECT id FROM {table} WHERE gateway_row=? AND report_sig=?"
                f" AND item_sig=?", (gw_row, report_sig, item_sig)).fetchone()
            if row:
                return kind, row[0]
        return None, None

    # ================================================================== #
    # GRAPH (structure only; no candidate lookups)
    # ================================================================== #
    def _load_graph(self, roots=None):
        """Load the correction graph.

        With ``roots`` given, only the chain components of those roots are
        loaded (each original plus every correction reachable downward).  Calls
        that need the whole graph -- a full rebuild, or "is anything still
        pending?" -- pass ``None``.  Scoped loading is what keeps a late import
        proportional to the affected chains rather than to the repository.
        """
        gateway_idents = {r["id"]: r["ident"] for r in self.conn.execute(
            "SELECT id, ident FROM gateway")}
        if roots is None:
            dsn_rows = self.conn.execute("SELECT * FROM dsn_line").fetchall()
        else:
            dsn_ids = sorted(int(r.split(":")[1]) for r in roots)
            if not dsn_ids:
                return self._empty_graph(gateway_idents)
            dsn_rows = self.conn.execute(
                "SELECT * FROM dsn_line WHERE id IN (%s)"
                % ",".join("?" * len(dsn_ids)), dsn_ids).fetchall()
        wanted_dsn = {_key("dsn", r["id"]) for r in dsn_rows}
        ident_index, nodes, fields = {}, {}, {}
        for r in dsn_rows:
            key = _key("dsn", r["id"])
            nodes[key] = ("dsn", r["id"])
            ident_index[(r["gateway_row"], r["report_sig"],
                         r["item_sig"])] = key
            fields[key] = self._fields_from_row("dsn", r)
        if roots is None:
            # whole graph: one scan, then resolve every correction target
            cor_rows = self.conn.execute(
                "SELECT * FROM correction_line").fetchall()
            for r in cor_rows:
                key = _key("cor", r["id"])
                nodes[key] = ("cor", r["id"])
                ident_index[(r["gateway_row"], r["report_sig"],
                             r["item_sig"])] = key
                fields[key] = self._fields_from_row("cor", r)
            parent_of = {}
            for r in cor_rows:
                key = _key("cor", r["id"])
                parent_of[key] = self._resolve_parent(
                    gateway_idents, ident_index, r)
        else:
            # scoped: walk children of the wanted originals, resolving each
            # target through indexed identity lookups only
            parent_of = self._walk_component(
                gateway_idents, ident_index, nodes, fields, wanted_dsn)
        info = analyse(set(nodes), parent_of)
        ctx = {
            "nodes": nodes,
            "fields": fields,
            "parent_of": parent_of,
            "ident_index": ident_index,
            "invalid": self._find_invalid_corrections(fields, parent_of),
        }
        return ctx, info

    @staticmethod
    def _empty_graph(gateway_idents):
        info = analyse(set(), {})
        return ({"nodes": {}, "fields": {}, "parent_of": {},
                 "ident_index": {}, "invalid": {}}, info)

    @staticmethod
    def _resolve_parent(gateway_idents, ident_index, cor_row):
        target = ident_index.get(
            (cor_row["gateway_row"], cor_row["target_report_sig"],
             cor_row["target_item_sig"]))
        if target is None:
            target = _ref_key(
                gateway_idents.get(cor_row["gateway_row"], b""),
                cor_row["target_report_sig"], cor_row["target_item_sig"])
        return target

    def _walk_component(self, gateway_idents, ident_index, nodes, fields,
                        wanted_dsn):
        """Load every correction below the given originals, recursively.

        Identity lookups use the indexed (gateway, report_id, item_id) columns,
        so this is a bounded number of probes per chain node -- not a scan of
        the correction table.
        """
        parent_of = {}
        frontier = set(wanted_dsn)
        while frontier:
            batch = sorted(frontier)
            frontier = set()
            for node_key in batch:
                kind, row_id = nodes[node_key]
                if kind == "dsn":
                    source = self.conn.execute(
                        "SELECT gateway_row, report_sig, item_sig FROM"
                        " dsn_line WHERE id=?", (row_id,)).fetchone()
                else:
                    source = self.conn.execute(
                        "SELECT gateway_row, report_sig, item_sig FROM"
                        " correction_line WHERE id=?", (row_id,)).fetchone()
                children = self.conn.execute(
                    "SELECT * FROM correction_line WHERE gateway_row=?"
                    " AND target_report_sig=? AND target_item_sig=?"
                    " ORDER BY id",
                    (source[0], source[1], source[2])).fetchall()
                for r in children:
                    key = _key("cor", r["id"])
                    parent_of[key] = node_key
                    if key not in nodes:
                        nodes[key] = ("cor", r["id"])
                        ident_index[(r["gateway_row"], r["report_sig"],
                                     r["item_sig"])] = key
                        fields[key] = self._fields_from_row("cor", r)
                        frontier.add(key)
        return parent_of

    @staticmethod
    def _fields_from_row(kind, r):
        return {
            "kind": kind,
            "row_id": r["id"],
            "gateway_row": r["gateway_row"],
            "recipient_sig": r["recipient_sig"],
            "queue_sig": r["queue_sig"],
            "envelope_sig": r["envelope_sig"],
            "action": r["action"],
            "occurred_at_us": r["occurred_at_us"],
            "occurred_text": r["occurred_text"],
            "report_id": r["report_id"],
            "item_id": r["item_id"],
        }

    def _find_invalid_corrections(self, fields, parent_of):
        """Corrections that rewrite recipient/queue/envelope.

        A correction may only replace ``action`` and ``occurred_at``.  Any
        matching field it states must equal the value inherited from the
        nearest ancestor that supplies one; stating a *new* value is equally a
        silent re-association.  Such a chain is error evidence and contributes
        nothing.
        """
        invalid = {}
        for key in sorted(fields):
            if fields[key]["kind"] != "cor":
                continue
            own = fields[key]
            parent = parent_of.get(key)
            problems = []
            for field in ("recipient_sig", "queue_sig", "envelope_sig"):
                supplied = own[field]
                if supplied is None:
                    continue
                inherited = self._nearest_ancestor_value(
                    fields, parent_of, parent, field)
                if inherited is None:
                    problems.append(f"{field} newly introduced")
                elif inherited != supplied:
                    problems.append(f"{field} rewritten")
            if problems:
                invalid[key] = ("correction may not change matching fields: "
                                + ", ".join(problems))
        return invalid

    @staticmethod
    def _nearest_ancestor_value(fields, parent_of, start, field):
        seen, cur = set(), start
        while cur is not None and cur not in seen:
            seen.add(cur)
            if cur not in fields:
                return None
            value = fields[cur][field]
            if value is not None:
                return value
            cur = parent_of.get(cur)
        return None

    # ================================================================== #
    # ROOT EVALUATION
    # ================================================================== #
    @staticmethod
    def _component(info, root):
        out, seen, stack = [], set(), [root]
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            out.append(node)
            stack.extend(info.children.get(node, []))
        return sorted(out)

    def _evaluate_root(self, ctx, info, root):
        fields = ctx["fields"]
        root_fields = fields[root]
        component = self._component(info, root)
        chain_state = info.state.get(root, CLEAN)
        chain_note = info.reason.get(root, "")
        if chain_state == CLEAN:
            for node in component:
                if node in ctx["invalid"]:
                    chain_state = "invalid"
                    chain_note = ctx["invalid"][node]
                    break
        end_key = info.end_of.get(root) if chain_state == CLEAN else None
        end_fields = fields[end_key] if end_key else None
        effective_at = effective_action = None
        if chain_state == CLEAN and end_fields is not None:
            effective_at = end_fields["occurred_at_us"]
            if end_fields["action"] != "withdraw":
                effective_action = end_fields["action"]
        query_at = (effective_at if effective_at is not None
                    else root_fields["occurred_at_us"])
        lookup_at = max(fields[n]["occurred_at_us"] for n in component)

        candidates = self._candidates(
            gateway_row=root_fields["gateway_row"],
            recipient_sig=root_fields["recipient_sig"],
            occurred_us=query_at,
            queue_sig=root_fields["queue_sig"],
            envelope_sig=root_fields["envelope_sig"])
        fp = fingerprint([(m[1], m[2], m[3]) for m in candidates])

        decisions = self.conn.execute(
            "SELECT * FROM manual_decision WHERE line_key=? ORDER BY id",
            (root,)).fetchall()
        live = [d for d in decisions if d["candidate_fp"] == fp]
        stale = [d for d in decisions if d["candidate_fp"] != fp]

        assignment = None
        assigned_kind = None
        decision_conflict = False
        if live:
            choices = {(d["delivery_id"], d["attempt_id"], d["recipient_sig"])
                       for d in live}
            if len(choices) != 1:
                decision_conflict = True
            else:
                choice = next(iter(choices))
                for m in candidates:
                    if (m[1], m[2], m[3]) == choice:
                        assignment, assigned_kind = m, "decision"
                        break
        if chain_state != CLEAN:
            mark = "excluded"
        elif effective_action is None:
            mark = "withdrawn"
        elif decision_conflict:
            mark = "ambiguous"
        else:
            if assignment is None and len(candidates) == 1:
                assignment, assigned_kind = candidates[0], "candidate"
            mark = ("unique" if len(candidates) == 1
                    else "unmatched" if not candidates else "ambiguous")
        contributes = int(chain_state == CLEAN and effective_action is not None
                          and assignment is not None and not decision_conflict)
        notes = []
        if chain_note:
            notes.append(chain_note)
        if stale:
            notes.append(f"{len(stale)} stale human decision(s) not applied")
        if decision_conflict:
            notes.append("conflicting human decisions for this candidate set")
        return {
            "root": root,
            "component": component,
            "chain_state": chain_state,
            "chain_end_key": end_key,
            "chain_note": chain_note,
            "query_at_us": query_at,
            "effective_at_us": effective_at,
            "effective_action": effective_action,
            "lookup_at_us": lookup_at,
            "candidates": candidates,
            "candidate_fp": fp,
            "mark": mark,
            "assignment": assignment,
            "assigned_kind": assigned_kind,
            "contributes": contributes,
            "stale_decisions": len(stale),
            "decision_conflict": decision_conflict,
            "note": "; ".join(notes),
        }

    def _candidates(self, *, gateway_row, recipient_sig, occurred_us,
                    queue_sig, envelope_sig):
        """Candidate set: same gateway + recipient, sent_at <= occurred_at, and
        the intersection of every supplied queue/envelope condition."""
        sql = ["SELECT id, delivery_id, attempt_id, recipient_sig",
               "FROM outbound_attempt",
               "WHERE gateway_row=? AND recipient_sig=? AND sent_at_us<=?"]
        params = [gateway_row, recipient_sig, occurred_us]
        if queue_sig is not None:
            sql.append("AND queue_sig=?")
            params.append(queue_sig)
        if envelope_sig is not None:
            sql.append("AND envelope_sig=?")
            params.append(envelope_sig)
        sql.append("ORDER BY delivery_id, attempt_id, recipient_sig")
        return [tuple(r) for r in self.conn.execute(" ".join(sql), params)]

    # ================================================================== #
    # WRITE DERIVATIONS
    # ================================================================== #
    def _refresh_roots(self, roots):
        """Re-evaluate the given roots and refresh the attempts they affect.

        Returns the number of attempt rows whose status was touched.
        """
        roots = {r for r in roots if r and r.startswith("dsn:")}
        attempt_universe = set()
        if not roots:
            return 0
        # scoped: only the components of the given roots are analysed
        ctx, info = self._load_graph(roots)
        roots = {r for r in roots
                 if r in ctx["nodes"] and ctx["nodes"][r][0] == "dsn"}
        if roots:
            placeholders = ",".join("?" * len(roots))
            prior = self.conn.execute(
                "SELECT DISTINCT attempt_row FROM item_link WHERE"
                f" contributes=1 AND attempt_row IS NOT NULL AND root_key IN"
                f" ({placeholders})", sorted(roots)).fetchall()
            attempt_universe |= {r[0] for r in prior}
            for root in sorted(roots):
                view = self._evaluate_root(ctx, info, root)
                attempt_universe |= {m[0] for m in view["candidates"]}
                if view["assignment"] is not None:
                    attempt_universe.add(view["assignment"][0])
                self._write_root(ctx, info, view)
        self._refresh_orphan_links(ctx, info, scoped=True)
        self._refresh_attempt_statuses(attempt_universe)
        return len(attempt_universe)

    def _write_root(self, ctx, info, view):
        root = view["root"]
        for node in view["component"]:
            self.conn.execute("DELETE FROM item_link WHERE line_key=?", (node,))
        self.conn.execute("DELETE FROM item_candidate WHERE line_key=?", (root,))
        for node in view["component"]:
            is_root = node == root
            fields = ctx["fields"][node]
            if is_root:
                assignment = view["assignment"]
                values = (
                    fields["recipient_sig"], fields["queue_sig"],
                    fields["envelope_sig"], view["effective_at_us"],
                    view["lookup_at_us"], view["effective_action"],
                    view["chain_state"], view["chain_end_key"],
                    view["chain_note"], view["mark"], view["candidate_fp"],
                    _net_json(view["candidates"]), view["assigned_kind"],
                    assignment[1] if assignment else None,
                    assignment[2] if assignment else None,
                    assignment[0] if assignment else None,
                    view["contributes"], view["note"])
            else:
                values = (
                    None, None, None, None, view["lookup_at_us"], None,
                    view["chain_state"], view["chain_end_key"], None,
                    "not_root", None, "[]", None, None, None, None, 0,
                    f"chain member of {root}; only the chain end supplies "
                    "action/time")
            self.conn.execute(
                "INSERT INTO item_link (line_key, kind, row_id, root_key,"
                " gateway_row, recipient_sig, cond_queue_sig,"
                " cond_envelope_sig, effective_at_us, lookup_at_us,"
                " effective_action, chain_state, chain_end_key, chain_note,"
                " mark, candidate_fp, candidate_net, assigned_kind,"
                " delivery_id, attempt_id, attempt_row, contributes, note)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (node, fields["kind"], fields["row_id"], root,
                 fields["gateway_row"]) + values)
        self.conn.executemany(
            "INSERT INTO item_candidate (line_key, idx, attempt_row,"
            " delivery_id, attempt_id, recipient_sig) VALUES (?,?,?,?,?,?)",
            [(root, idx, m[0], m[1], m[2], m[3])
             for idx, m in enumerate(view["candidates"])])

    def _refresh_orphan_links(self, ctx=None, info=None, scoped=False):
        """Correction nodes with no chain root: pending, cyclic or invalid.

        With ``scoped`` the caller passes a component loaded for specific
        roots; only orphan rows inside that component are rewritten, so a late
        import never disturbs unrelated pending evidence.  Without it the whole
        correction graph is rebuilt (used by a full rebuild and by correction
        imports, where a new orphan may belong to a chain that has no root at
        all).
        """
        if ctx is None or info is None:
            ctx, info = self._load_graph()
            scoped = False
        if scoped:
            touched = [key for key, (kind, _row) in ctx["nodes"].items()
                       if kind == "cor"]
            if touched:
                self.conn.execute(
                    "DELETE FROM item_link WHERE root_key IS NULL AND line_key"
                    " IN (%s)" % ",".join("?" * len(touched)), sorted(touched))
        else:
            self.conn.execute("DELETE FROM item_link WHERE root_key IS NULL")
        rows = []
        for key in sorted(ctx["nodes"]):
            kind, row_id = ctx["nodes"][key]
            if kind != "cor" or info.root_of.get(key) is not None:
                continue
            fields = ctx["fields"][key]
            state = info.state.get(key, PENDING)
            note = info.reason.get(key, "")
            if key in ctx["invalid"]:
                state, note = "invalid", ctx["invalid"][key]
            mark = "pending" if state == PENDING else "excluded"
            rows.append((
                key, "cor", row_id, None, fields["gateway_row"],
                fields["recipient_sig"], fields["queue_sig"],
                fields["envelope_sig"], None, fields["occurred_at_us"], None,
                state, None, note, mark, None, "[]", None, None, None, None, 0,
                note))
        self.conn.executemany(
            "INSERT INTO item_link (line_key, kind, row_id, root_key,"
            " gateway_row, recipient_sig, cond_queue_sig, cond_envelope_sig,"
            " effective_at_us, lookup_at_us, effective_action, chain_state,"
            " chain_end_key, chain_note, mark, candidate_fp, candidate_net,"
            " assigned_kind, delivery_id, attempt_id, attempt_row, contributes,"
            " note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows)

    # ================================================================== #
    # ATTEMPT / DELIVERY STATUS
    # ================================================================== #
    @staticmethod
    def _status_from_actions(actions):
        """Combine the effective actions of one attempt's unique evidence.

        ``delayed`` is non-terminal, so delayed-only means delayed.  Exactly one
        terminal verdict is that verdict.  Both terminal verdicts at once is
        ``inconsistent`` -- never resolved by the later timestamp.
        """
        terminals = set(actions) & set(TERMINALS)
        if len(terminals) == 2:
            return "inconsistent"
        if len(terminals) == 1:
            return next(iter(terminals))
        if "delayed" in actions:
            return "delayed"
        return "awaiting"

    def _refresh_attempt_statuses(self, attempt_rows):
        """Batch recompute; one evidence query + one executemany."""
        rows = sorted({x for x in attempt_rows if x is not None})
        if not rows:
            return
        placeholders = ",".join("?" * len(rows))
        evidence = {}
        for r in self.conn.execute(
                "SELECT attempt_row, line_key, effective_action,"
                " effective_at_us, root_key FROM item_link WHERE attempt_row"
                f" IN ({placeholders}) AND contributes=1"
                " ORDER BY attempt_row, line_key", rows):
            evidence.setdefault(r[0], []).append(r)
        payload = []
        for att in self.conn.execute(
                f"SELECT * FROM outbound_attempt WHERE id IN ({placeholders})",
                rows):
            ev = evidence.get(att["id"], [])
            payload.append((
                att["id"], att["gateway_row"], att["delivery_id"],
                att["attempt_id"], att["recipient_sig"], att["sent_at_us"],
                len(ev),
                self._status_from_actions([r["effective_action"] for r in ev]),
                canonical_json([
                    {"line_key": r["line_key"], "root": r["root_key"],
                     "action": r["effective_action"],
                     "occurred_at_us": r["effective_at_us"]} for r in ev])))
        self.conn.executemany(
            "INSERT INTO derived_attempt_status (attempt_row, gateway_row,"
            " delivery_id, attempt_id, recipient_sig, sent_at_us,"
            " effective_records, status, contributors)"
            " VALUES (?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(attempt_row) DO UPDATE SET"
            " effective_records=excluded.effective_records,"
            " status=excluded.status, contributors=excluded.contributors",
            payload)

    # ================================================================== #
    # QUERIES
    # ================================================================== #
    def attempt_status(self, gateway_id, delivery_id, attempt_id, recipient):
        gw = self._gw(gateway_id)
        if gw is None:
            raise KeyError(f"unknown gateway {gateway_id!r}")
        rec = recipient_sig(recipient)
        att = self.conn.execute(
            "SELECT id FROM outbound_attempt WHERE gateway_row=? AND"
            " delivery_id=? AND attempt_id=? AND recipient_sig=?",
            (gw, delivery_id, attempt_id, rec)).fetchone()
        if att is None:
            raise KeyError(f"attempt {delivery_id}/{attempt_id}/{recipient} "
                           "is not registered")
        row = self.conn.execute(
            "SELECT * FROM derived_attempt_status WHERE attempt_row=?",
            (att[0],)).fetchone()
        return {
            "gateway_id": gateway_id, "delivery_id": delivery_id,
            "attempt_id": attempt_id, "recipient": recipient,
            "status": row["status"] if row else "awaiting",
            "effective_records": row["effective_records"] if row else 0,
            "contributors": json.loads(row["contributors"]) if row else [],
        }

    def delivery_status(self, gateway_id, delivery_id, recipient):
        """Status of a (delivery, recipient) via its **last registered attempt**.

        Ordering is ``(sent_at, attempt_id)`` with attempt_id compared by raw
        lexicographic order of the recorded text.  That tie-break is this
        project's documented convention; it never consults evidence quality,
        arrival order or gateway reporting order.
        """
        gw = self._gw(gateway_id)
        if gw is None:
            raise KeyError(f"unknown gateway {gateway_id!r}")
        rec = recipient_sig(recipient)
        rows = self.conn.execute(
            "SELECT a.*, s.status FROM outbound_attempt a LEFT JOIN"
            " derived_attempt_status s ON s.attempt_row = a.id"
            " WHERE a.gateway_row=? AND a.delivery_id=?"
            " AND a.recipient_sig=? ORDER BY a.sent_at_us DESC,"
            " a.attempt_id DESC", (gw, delivery_id, rec)).fetchall()
        if not rows:
            raise KeyError("no attempt recorded for this delivery/recipient")
        latest = rows[0]
        return {
            "gateway_id": gateway_id,
            "delivery_id": delivery_id,
            "recipient": recipient,
            "status": latest["status"] or "awaiting",
            "latest_attempt_id": latest["attempt_id"],
            "latest_sent_at": latest["sent_at_text"],
            "attempt_count": len(rows),
            "attempts": [{
                "attempt_id": r["attempt_id"],
                "sent_at": r["sent_at_text"],
                "queue_id": r["queue_id"],
                "envelope_id": r["envelope_id"],
                "status": r["status"] or "awaiting"} for r in rows],
            "ordering": "sent_at desc, attempt_id desc (raw lexicographic)",
        }

    def recipient_timeline(self, recipient, gateway_id=None):
        """Every fact and derived annotation for one recipient, time ordered."""
        rec = recipient_sig(recipient)
        gw = self._gw(gateway_id) if gateway_id is not None else None
        if gateway_id is not None and gw is None:
            raise KeyError(f"unknown gateway {gateway_id!r}")
        gw_clause = " AND gateway_row=?" if gw is not None else ""
        gw_args = [gw] if gw is not None else []
        events = []
        for r in self.conn.execute(
                "SELECT a.*, s.status FROM outbound_attempt a LEFT JOIN"
                " derived_attempt_status s ON s.attempt_row=a.id"
                " WHERE a.recipient_sig=?" + gw_clause
                + " ORDER BY a.sent_at_us, a.attempt_id", [rec] + gw_args):
            events.append({
                "kind": "outbound_attempt", "at_us": r["sent_at_us"],
                "at": r["sent_at_text"], "gateway_row": r["gateway_row"],
                "delivery_id": r["delivery_id"],
                "attempt_id": r["attempt_id"], "queue_id": r["queue_id"],
                "envelope_id": r["envelope_id"],
                "status": r["status"] or "awaiting"})
        for r in self.conn.execute(
                "SELECT * FROM item_link WHERE kind='dsn' AND recipient_sig=?"
                + gw_clause + " ORDER BY lookup_at_us, line_key",
                [rec] + gw_args):
            net = json.loads(r["candidate_net"])
            events.append({
                "kind": "receipt_chain",
                "at_us": (r["effective_at_us"] if r["effective_at_us"]
                          is not None else r["lookup_at_us"]),
                "line_key": r["line_key"], "root_key": r["root_key"],
                "chain_state": r["chain_state"], "mark": r["mark"],
                "effective_action": r["effective_action"],
                "candidate_count": len(net),
                "candidate_fingerprint": r["candidate_fp"],
                "candidates": net,
                "assigned": ({"delivery_id": r["delivery_id"],
                              "attempt_id": r["attempt_id"],
                              "recipient": recipient}
                             if r["delivery_id"] else None),
                "assigned_kind": r["assigned_kind"],
                "contributes": bool(r["contributes"]),
                "note": r["note"]})
        for r in self.conn.execute(
                "SELECT * FROM correction_line WHERE recipient_sig=?"
                + gw_clause + " ORDER BY occurred_at_us, id",
                [rec] + gw_args):
            link = self.conn.execute(
                "SELECT root_key, chain_state, mark FROM item_link WHERE"
                " line_key=?", (_key("cor", r["id"]),)).fetchone()
            events.append({
                "kind": "correction", "at_us": r["occurred_at_us"],
                "at": r["occurred_text"], "line_key": _key("cor", r["id"]),
                "target": {"report_id": r["target_report_id"],
                           "item_id": r["target_item_id"]},
                "action": r["action"],
                "chain_state": link["chain_state"] if link else None,
                "mark": link["mark"] if link else None,
                "root": link["root_key"] if link else None})
        for r in self.conn.execute(
                "SELECT * FROM manual_decision WHERE recipient_sig=?"
                " ORDER BY decided_at_us, id", (rec,)):
            events.append({
                "kind": "manual_decision", "at_us": r["decided_at_us"],
                "at": r["decided_text"], "line_key": r["line_key"],
                "chosen": {"delivery_id": r["delivery_id"],
                           "attempt_id": r["attempt_id"]},
                "candidate_fingerprint": r["candidate_fp"]})
        events.sort(key=lambda e: (e["at_us"], e["kind"],
                                   e.get("line_key", "")))
        return events

    def pending_associations(self):
        """Everything that is not a clean, unique association, with reasons."""
        pending = []
        for r in self.conn.execute(
                "SELECT * FROM item_link WHERE kind='dsn' AND mark IN"
                " ('ambiguous','unmatched','excluded','withdrawn')"
                " ORDER BY gateway_row, lookup_at_us, line_key"):
            candidates = self.conn.execute(
                "SELECT delivery_id, attempt_id, recipient_sig"
                " FROM item_candidate WHERE line_key=? ORDER BY idx",
                (r["line_key"],)).fetchall()
            stale = self.conn.execute(
                "SELECT delivery_id, attempt_id, recipient_sig, candidate_fp"
                " FROM manual_decision WHERE line_key=? AND candidate_fp != ?"
                " ORDER BY id", (r["line_key"], r["candidate_fp"])).fetchall()
            pending.append({
                "category": r["mark"], "line_key": r["line_key"],
                "root_key": r["root_key"], "gateway_row": r["gateway_row"],
                "chain_state": r["chain_state"],
                "effective_action": r["effective_action"],
                "effective_at_us": r["effective_at_us"],
                "candidate_fingerprint": r["candidate_fp"],
                "candidates": [
                    {"delivery_id": c[0], "attempt_id": c[1],
                     "recipient_sig": c[2].hex() if c[2] else None}
                    for c in candidates],
                "stale_decisions": [
                    {"delivery_id": d[0], "attempt_id": d[1],
                     "recipient_sig": d[2].hex(),
                     "decided_fingerprint": d[3]}
                    for d in stale],
                "note": r["note"]})
        for r in self.conn.execute(
                "SELECT * FROM item_link WHERE kind='cor' AND mark IN"
                " ('pending','excluded') ORDER BY gateway_row, line_key"):
            pending.append({
                "category": ("correction_pending" if r["mark"] == "pending"
                             else "correction_excluded"),
                "line_key": r["line_key"], "gateway_row": r["gateway_row"],
                "chain_state": r["chain_state"], "note": r["note"]})
        return pending

    def correction_conflicts(self):
        """Conflicted / cyclic chains with every competing branch named."""
        conflicts = []
        ctx, info = self._load_graph()
        for root in sorted(info.state):
            if info.root_of.get(root) != root:
                continue
            state = info.state[root]
            if state not in (CONFLICT, CYCLE):
                continue
            node = info.conflict_node_of_root.get(root)
            branches = []
            for child in (info.children.get(node, []) if node else []):
                f = ctx["fields"][child]
                branches.append({
                    "line_key": child, "report_id": f["report_id"],
                    "item_id": f["item_id"], "action": f["action"],
                    "occurred_at_us": f["occurred_at_us"]})
            conflicts.append({
                "root": root, "state": state,
                "note": info.reason.get(root, ""),
                "conflict_node": node, "branches": branches})
        return conflicts

    def _stale_decisions(self):
        """Human decisions whose candidate set no longer exists.

        They are reported, never silently applied or deleted: a decision that
        no longer matches still documents what a human saw at the time.
        """
        rows = []
        for r in self.conn.execute(
                "SELECT d.*, l.candidate_fp AS current_fp, l.mark"
                " FROM manual_decision d LEFT JOIN item_link l"
                " ON l.line_key = d.line_key"
                " WHERE l.candidate_fp IS NULL OR l.candidate_fp != d.candidate_fp"
                " ORDER BY d.line_key, d.id"):
            rows.append({
                "line_key": r["line_key"],
                "delivery_id": r["delivery_id"],
                "attempt_id": r["attempt_id"],
                "decided_fingerprint": r["candidate_fp"],
                "current_fingerprint": r["current_fp"],
                "current_mark": r["mark"]})
        return rows

    def _evidence_rows(self, mark):
        rows = []
        for r in self.conn.execute(
                "SELECT line_key, gateway_row, chain_state, effective_action,"
                " effective_at_us, candidate_fp, candidate_net, note"
                " FROM item_link WHERE kind='dsn' AND mark=?"
                " ORDER BY gateway_row, line_key", (mark,)):
            rows.append({
                "line_key": r["line_key"],
                "gateway_row": r["gateway_row"],
                "chain_state": r["chain_state"],
                "effective_action": r["effective_action"],
                "effective_at_us": r["effective_at_us"],
                "candidate_fingerprint": r["candidate_fp"],
                "candidate_count": len(json.loads(r["candidate_net"])),
                "note": r["note"]})
        return rows

    def explain_summary(self):
        """Delivery-status totals plus receipt-evidence buckets.

        Success is only a ``delivered`` status on a proven, unique association.
        Ambiguous / unmatched / excluded receipts and awaiting / delayed /
        inconsistent deliveries are reported separately and are never folded
        into the success count.
        """
        statuses, deliveries = {}, []
        for r in self.conn.execute(
                "SELECT * FROM ("
                "  SELECT a.gateway_row, a.delivery_id, a.recipient_sig,"
                "         a.recipient_text, a.attempt_id, s.status,"
                "         ROW_NUMBER() OVER ("
                "           PARTITION BY a.gateway_row, a.delivery_id,"
                "                        a.recipient_sig"
                "           ORDER BY a.sent_at_us DESC, a.attempt_id DESC"
                "         ) AS rn"
                "  FROM outbound_attempt a"
                "  LEFT JOIN derived_attempt_status s ON s.attempt_row=a.id"
                ") WHERE rn=1"
                " ORDER BY gateway_row, delivery_id, recipient_sig"):
            status = r["status"] or "awaiting"
            statuses[status] = statuses.get(status, 0) + 1
            deliveries.append({
                "gateway_row": r["gateway_row"],
                "delivery_id": r["delivery_id"],
                "recipient": r["recipient_text"],
                "latest_attempt_id": r["attempt_id"],
                "status": status})
        buckets = {r[0]: r[1] for r in self.conn.execute(
            "SELECT mark, COUNT(*) FROM item_link WHERE kind='dsn'"
            " GROUP BY mark")}
        chain_states = {r[0]: r[1] for r in self.conn.execute(
            "SELECT chain_state, COUNT(*) FROM item_link WHERE kind='dsn'"
            " GROUP BY chain_state")}
        evidence = {mark: self._evidence_rows(mark) for mark in
                    ("ambiguous", "unmatched", "excluded", "withdrawn")}
        return {
            "deliveries_total": len(deliveries),
            "delivery_counts": {
                "awaiting": statuses.get("awaiting", 0),
                "delayed": statuses.get("delayed", 0),
                "delivered": statuses.get("delivered", 0),
                "failed": statuses.get("failed", 0),
                "inconsistent": statuses.get("inconsistent", 0)},
            "proven_delivered": statuses.get("delivered", 0),
            "not_proven": {
                "awaiting": statuses.get("awaiting", 0),
                "delayed": statuses.get("delayed", 0),
                "ambiguous_evidence": buckets.get("ambiguous", 0),
                "unmatched_evidence": buckets.get("unmatched", 0),
                "excluded_evidence": buckets.get("excluded", 0),
                "inconsistent": statuses.get("inconsistent", 0)},
            "receipt_buckets": buckets,
            "chain_states": chain_states,
            "stale_decisions": self._stale_decisions(),
            "evidence_not_counted_as_success": evidence,
            "inconsistent_deliveries": [
                d for d in deliveries if d["status"] == "inconsistent"],
            "handling": (
                "ambiguous/unmatched/excluded receipts and awaiting/delayed"
                " deliveries are excluded from the success count; inconsistent"
                " deliveries are reported separately and are never overwritten"
                " by whichever terminal action arrived later"),
        }

    def explain_item(self, gateway_id, report_id, item_id):
        """Full evidence for one receipt item: chain, candidates, decisions."""
        gw = self._gw(gateway_id)
        if gw is None:
            raise KeyError(f"unknown gateway {gateway_id!r}")
        report_sig = ingest.identity_signature(report_id, "report_id")
        item_sig = ingest.identity_signature(item_id, "item_id")
        kind, row_id = self._find_item(gw, report_sig, item_sig)
        if kind is None:
            raise KeyError(f"unknown item {report_id}/{item_id}")
        key = _key(kind, row_id)
        root = self._climb_root(gw, report_sig, item_sig)
        link = self.conn.execute(
            "SELECT * FROM item_link WHERE line_key=?", (key,)).fetchone()
        root_link = self.conn.execute(
            "SELECT * FROM item_link WHERE line_key=?", (root,)).fetchone() \
            if root else None
        chain = []
        if root:
            ctx, info = self._load_graph()
            path = info.path(root) or self._component(info, root)
            for node in path:
                f = ctx["fields"][node]
                chain.append({
                    "line_key": node, "kind": f["kind"],
                    "report_id": f["report_id"], "item_id": f["item_id"],
                    "action": f["action"],
                    "occurred_at": f["occurred_text"],
                    "invalid_reason": ctx["invalid"].get(node)})
        candidates = []
        if root:
            for c in self.conn.execute(
                    "SELECT * FROM item_candidate WHERE line_key=?"
                    " ORDER BY idx", (root,)):
                candidates.append({
                    "delivery_id": c["delivery_id"],
                    "attempt_id": c["attempt_id"],
                    "recipient_sig": c["recipient_sig"].hex()})
        decisions = []
        for d in self.conn.execute(
                "SELECT * FROM manual_decision WHERE line_key=? ORDER BY id",
                (root,)):
            decisions.append({
                "delivery_id": d["delivery_id"],
                "attempt_id": d["attempt_id"],
                "candidate_fingerprint": d["candidate_fp"],
                "decided_at": d["decided_text"],
                "matches_current_set": bool(
                    root_link and d["candidate_fp"]
                    == root_link["candidate_fp"])})
        return {
            "item": key, "root": root,
            "item_mark": link["mark"] if link else None,
            "chain": chain,
            "chain_state": root_link["chain_state"] if root_link else None,
            "chain_end": root_link["chain_end_key"] if root_link else None,
            "chain_note": root_link["chain_note"] if root_link else None,
            "effective_action": (root_link["effective_action"]
                                 if root_link else None),
            "effective_at_us": (root_link["effective_at_us"]
                                if root_link else None),
            "mark": root_link["mark"] if root_link else None,
            "candidate_fingerprint": (root_link["candidate_fp"]
                                      if root_link else None),
            "candidates": candidates,
            "decisions": decisions,
            "assignment": ({
                "delivery_id": root_link["delivery_id"],
                "attempt_id": root_link["attempt_id"],
                "assigned_by": root_link["assigned_kind"]}
                if root_link and root_link["delivery_id"] else None),
            "contributes": (bool(root_link["contributes"])
                            if root_link else False),
            "note": root_link["note"] if root_link else None,
        }

    # ================================================================== #
    def rebuild(self):
        """Recompute every derivation from the fact layer."""
        self._begin()
        try:
            self.conn.execute("DELETE FROM item_link")
            self.conn.execute("DELETE FROM item_candidate")
            self.conn.execute("DELETE FROM derived_attempt_status")
            self.conn.execute(
                "INSERT INTO derived_attempt_status (attempt_row, gateway_row,"
                " delivery_id, attempt_id, recipient_sig, sent_at_us,"
                " effective_records, status, contributors)"
                " SELECT id, gateway_row, delivery_id, attempt_id,"
                " recipient_sig, sent_at_us, 0, 'awaiting', '[]'"
                " FROM outbound_attempt")
            ctx, info = self._load_graph()
            attempt_universe = set()
            roots = sorted(k for k, v in ctx["nodes"].items() if v[0] == "dsn")
            for root in roots:
                view = self._evaluate_root(ctx, info, root)
                attempt_universe |= {m[0] for m in view["candidates"]}
                self._write_root(ctx, info, view)
            self._refresh_orphan_links(ctx, info)
            self._refresh_attempt_statuses(attempt_universe)
            self._commit()
        except Exception:
            self._rollback()
            raise
        return ImportOutcome(kind="rebuild", roots=len(roots),
                             attempts=len(attempt_universe))
