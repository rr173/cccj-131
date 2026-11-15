"""Candidate enumeration and candidate-set classification.

A receipt item matches an outbound attempt only when **all** of the following
hold:

* same gateway;
* same canonical recipient signature;
* ``sent_at <= occurred_at``;
* every queue/envelope condition the item supplies agrees with the attempt.

The candidate set is the **intersection** of all supplied conditions -- never a
union, and never "pick the most trusted field".  Contradictory conditions
therefore yield an empty intersection (``unmatched``), not a guess.

The reference implementation in ``receipt_ledger.reference`` deliberately does
*not* import this module: it re-derives the same rule with a plain Python loop
so the two can be compared.
"""

from __future__ import annotations

MARK_UNMATCHED = "unmatched"
MARK_UNIQUE = "unique"
MARK_AMBIGUOUS = "ambiguous"

__all__ = [
    "MARK_UNMATCHED",
    "MARK_UNIQUE",
    "MARK_AMBIGUOUS",
    "candidate_rows",
    "classify",
]


def candidate_rows(conn, *, gateway_row, recipient_sig, occurred_us,
                   queue_sig=None, envelope_sig=None):
    """Rows ``(attempt_row, delivery_id, attempt_id, recipient_sig)``.

    Conditions whose signature is ``None`` were not supplied by the receipt and
    therefore do not constrain the result.  Ordering is deterministic so callers
    never depend on SQLite's row order.
    """
    sql = [
        "SELECT id, delivery_id, attempt_id, recipient_sig",
        "FROM outbound_attempt",
        "WHERE gateway_row = ? AND recipient_sig = ? AND sent_at_us <= ?",
    ]
    params = [gateway_row, recipient_sig, occurred_us]
    if queue_sig is not None:
        sql.append("AND queue_sig = ?")
        params.append(queue_sig)
    if envelope_sig is not None:
        sql.append("AND envelope_sig = ?")
        params.append(envelope_sig)
    sql.append("ORDER BY delivery_id, attempt_id, recipient_sig")
    return [tuple(row) for row in conn.execute(" ".join(sql), params)]


def classify(candidates):
    """Return ``(mark, members)`` for a candidate list.

    ``members`` are ``(delivery_id, attempt_id, recipient_sig)`` triples, the
    only ordering the rest of the code relies on.
    """
    members = tuple((row[1], row[2], row[3]) for row in candidates)
    if not members:
        return MARK_UNMATCHED, members
    if len(members) == 1:
        return MARK_UNIQUE, members
    return MARK_AMBIGUOUS, members
