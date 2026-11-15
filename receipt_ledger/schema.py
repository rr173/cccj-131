"""SQLite schema for the receipt-evidence ledger.

Two layers, deliberately separated:

**facts** (append-only, never rewritten by derivation)
    ``import_file``      one row per successfully ingested file (SHA-256 unique)
    ``gateway``          gateway identities
    ``outbound_attempt`` one row per (gateway, delivery, attempt, recipient)
    ``dsn_line``         one deduplicated original receipt item
    ``correction_line``  one correcting item, with its own identity and a
                         declared target
    ``manual_decision``  immutable human association decisions

**derivations** (recomputable, always safe to delete)
    ``item_link``              per-line candidate evaluation + effective chain
                               action/time (roots carry the status-bearing view)
    ``item_candidate``         materialized candidate set of every clean root
    ``derived_attempt_status`` status of each attempt that evidence can name

Delivery status is *not* materialized: it is the status of the last registered
attempt for a (gateway, delivery, recipient) triple, read through the retry
index.  A late outbound row therefore never triggers a repo-wide rewrite.

Nothing in the schema stores a guess as fact: an undecidable receipt keeps an
explicit ``ambiguous``/``unmatched``/``conflict`` marker instead of a chosen
attempt.
"""

from __future__ import annotations

SCHEMA_VERSION = 2

DDL = """
PRAGMA foreign_keys = ON;

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE import_file (
    id          INTEGER PRIMARY KEY,
    sha256      TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL,
    source_name TEXT NOT NULL,
    line_count  INTEGER NOT NULL
);

-- ------------------------------------------------------------------ facts --
CREATE TABLE gateway (
    id    INTEGER PRIMARY KEY,
    ident BLOB NOT NULL UNIQUE
);

CREATE TABLE outbound_attempt (
    id             INTEGER PRIMARY KEY,
    gateway_row    INTEGER NOT NULL REFERENCES gateway(id),
    delivery_id    TEXT NOT NULL,
    attempt_id     TEXT NOT NULL,
    recipient_sig  BLOB NOT NULL,
    recipient_text TEXT NOT NULL,
    queue_sig      BLOB,
    queue_id       TEXT,
    envelope_sig   BLOB,
    envelope_id    TEXT,
    sent_at_us     INTEGER NOT NULL,
    sent_at_text   TEXT NOT NULL,
    canonical_hash TEXT NOT NULL,
    import_file    INTEGER NOT NULL REFERENCES import_file(id),
    UNIQUE (gateway_row, delivery_id, attempt_id, recipient_sig)
);
CREATE INDEX idx_attempt_match
    ON outbound_attempt (gateway_row, recipient_sig, sent_at_us);
CREATE INDEX idx_attempt_match_queue
    ON outbound_attempt (gateway_row, recipient_sig, queue_sig, sent_at_us);
CREATE INDEX idx_attempt_match_envelope
    ON outbound_attempt (gateway_row, recipient_sig, envelope_sig, sent_at_us);
CREATE INDEX idx_attempt_retry
    ON outbound_attempt (delivery_id, recipient_sig, sent_at_us DESC,
                         attempt_id DESC);

CREATE TABLE dsn_line (
    id             INTEGER PRIMARY KEY,
    gateway_row    INTEGER NOT NULL REFERENCES gateway(id),
    report_id      TEXT NOT NULL,
    report_sig     BLOB NOT NULL,
    item_id        TEXT NOT NULL,
    item_sig       BLOB NOT NULL,
    occurred_at_us INTEGER NOT NULL,
    occurred_text  TEXT NOT NULL,
    action         TEXT NOT NULL CHECK (action IN ('delayed','delivered','failed')),
    recipient_sig  BLOB NOT NULL,
    recipient_text TEXT NOT NULL,
    queue_sig      BLOB,
    queue_id       TEXT,
    envelope_sig   BLOB,
    envelope_id    TEXT,
    canonical_hash TEXT NOT NULL,
    import_file    INTEGER NOT NULL REFERENCES import_file(id),
    UNIQUE (gateway_row, report_sig, item_sig)
);

CREATE TABLE correction_line (
    id                INTEGER PRIMARY KEY,
    gateway_row       INTEGER NOT NULL REFERENCES gateway(id),
    report_id         TEXT NOT NULL,
    report_sig        BLOB NOT NULL,
    item_id           TEXT NOT NULL,
    item_sig          BLOB NOT NULL,
    target_report_id  TEXT NOT NULL,
    target_report_sig BLOB NOT NULL,
    target_item_id    TEXT NOT NULL,
    target_item_sig   BLOB NOT NULL,
    occurred_at_us    INTEGER NOT NULL,
    occurred_text     TEXT NOT NULL,
    action            TEXT CHECK (action IN ('delayed','delivered','failed','withdraw')),
    recipient_sig     BLOB,
    recipient_text    TEXT,
    queue_sig         BLOB,
    queue_id          TEXT,
    envelope_sig      BLOB,
    envelope_id       TEXT,
    canonical_hash    TEXT NOT NULL,
    import_file       INTEGER NOT NULL REFERENCES import_file(id),
    UNIQUE (gateway_row, report_sig, item_sig)
);
CREATE INDEX idx_cor_target
    ON correction_line (gateway_row, target_report_sig, target_item_sig);

CREATE TABLE manual_decision (
    id            INTEGER PRIMARY KEY,
    line_key      TEXT NOT NULL,       -- chain root the decision governs
    requested_key TEXT NOT NULL,       -- item named by the resolve record
    gateway_row   INTEGER NOT NULL,
    root_report_id TEXT NOT NULL,      -- chain root identity (fact-level, so
    root_item_id   TEXT NOT NULL,      -- an independent reader can find it)
    delivery_id   TEXT NOT NULL,
    attempt_id    TEXT NOT NULL,
    recipient_sig BLOB NOT NULL,
    candidate_fp  TEXT NOT NULL,
    candidate_net TEXT NOT NULL,       -- canonical JSON of the accepted set
    decided_at_us INTEGER NOT NULL,
    decided_text  TEXT NOT NULL,
    import_file   INTEGER NOT NULL REFERENCES import_file(id)
);
CREATE UNIQUE INDEX idx_decision_unique ON manual_decision (
    line_key, delivery_id, attempt_id, recipient_sig, candidate_fp
);
CREATE INDEX idx_decision_line ON manual_decision (line_key, candidate_fp);

-- ----------------------------------------------------------- derivations --
CREATE TABLE item_link (
    line_key          TEXT PRIMARY KEY,
    kind              TEXT NOT NULL,          -- 'dsn' | 'cor'
    row_id            INTEGER NOT NULL,
    root_key          TEXT,                   -- NULL for orphan corrections
    gateway_row       INTEGER NOT NULL,
    recipient_sig     BLOB,
    cond_queue_sig    BLOB,
    cond_envelope_sig BLOB,
    effective_at_us   INTEGER,
    lookup_at_us      INTEGER NOT NULL,
    effective_action  TEXT,                   -- NULL if withdrawn/undecided
    chain_state       TEXT NOT NULL,          -- clean|conflict|cycle|pending|invalid
    chain_end_key     TEXT,
    chain_note        TEXT,
    mark              TEXT NOT NULL,          -- unique|ambiguous|unmatched|withdrawn|
                                              -- excluded|not_root|pending
    candidate_fp      TEXT,
    candidate_net     TEXT NOT NULL,
    assigned_kind     TEXT,                   -- 'candidate' | 'decision' | NULL
    delivery_id       TEXT,
    attempt_id        TEXT,
    attempt_row       INTEGER,
    contributes       INTEGER NOT NULL DEFAULT 0,
    note              TEXT
);
CREATE INDEX idx_link_root ON item_link (root_key);
CREATE INDEX idx_link_attempt ON item_link (attempt_row);
CREATE INDEX idx_link_affected
    ON item_link (kind, gateway_row, recipient_sig, lookup_at_us);
CREATE INDEX idx_link_recipient
    ON item_link (kind, recipient_sig, lookup_at_us);
CREATE INDEX idx_link_mark ON item_link (mark);

CREATE TABLE item_candidate (
    line_key      TEXT NOT NULL,
    idx           INTEGER NOT NULL,
    attempt_row   INTEGER NOT NULL,
    delivery_id   TEXT NOT NULL,
    attempt_id    TEXT NOT NULL,
    recipient_sig BLOB NOT NULL,
    PRIMARY KEY (line_key, idx)
);
CREATE INDEX idx_cand_attempt ON item_candidate (attempt_row);
CREATE INDEX idx_cand_delivery
    ON item_candidate (delivery_id, recipient_sig);

CREATE TABLE derived_attempt_status (
    attempt_row       INTEGER PRIMARY KEY,
    gateway_row       INTEGER NOT NULL,
    delivery_id       TEXT NOT NULL,
    attempt_id        TEXT NOT NULL,
    recipient_sig     BLOB NOT NULL,
    sent_at_us        INTEGER NOT NULL,
    effective_records INTEGER NOT NULL,
    status            TEXT NOT NULL,
    contributors      TEXT NOT NULL            -- canonical JSON
);
CREATE INDEX idx_das_delivery
    ON derived_attempt_status (delivery_id, recipient_sig, sent_at_us DESC,
                               attempt_id DESC);
"""


def create_schema(conn):
    conn.executescript(DDL)
    conn.execute("INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
                 (str(SCHEMA_VERSION),))
    conn.commit()


def check_schema(conn):
    row = conn.execute(
        "SELECT value FROM meta WHERE key='schema_version'"
    ).fetchone()
    if row is None:
        raise RuntimeError("database is not a receipt ledger database")
    if int(row[0]) != SCHEMA_VERSION:
        raise RuntimeError(f"unsupported schema version {row[0]}")
