"""Candidate-set fingerprints.

A human decision quotes the fingerprint of the candidate set it was made
against.  The fingerprint must therefore:

* change whenever any member is added, removed or changed (the set is quoted
  *exactly*, not approximately);
* not depend on the order rows came back from SQLite;
* not include the decision itself, the delivery status, or anything that the
  decision is supposed to fix.

Documented format (implemented twice on purpose: here and, independently, in
``receipt_ledger.reference``)::

    member := json array [delivery_id, attempt_id, recipient_hex]
              serialized with separators (",", ":") and ensure_ascii=False
    body   := "\\n".join(sorted(member strings))
    digest := sha256(body.encode("utf-8")).hexdigest()

An empty candidate set has the digest of the empty string, so "0 candidates"
also has a stable fingerprint rather than a NULL.
"""

from __future__ import annotations

import hashlib
import json

__all__ = ["member_string", "fingerprint"]


def member_string(delivery_id, attempt_id, recipient_sig):
    """Canonical serialization of one candidate."""
    return json.dumps(
        [delivery_id, attempt_id, recipient_sig.hex()],
        separators=(",", ":"), ensure_ascii=False)


def fingerprint(members):
    """Digest of an unordered candidate set.

    ``members`` is an iterable of ``(delivery_id, attempt_id, recipient_sig)``.
    Duplicate members are a programming error: one attempt appearing twice is
    not a candidate set, so this raises instead of silently collapsing them.
    """
    strings = [member_string(*m) for m in members]
    if len(strings) != len(set(strings)):
        raise ValueError("duplicate candidate in fingerprint input")
    body = "\n".join(sorted(strings))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()
