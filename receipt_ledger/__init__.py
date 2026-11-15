"""Per-recipient delivery receipt evidence ledger.

Public surface::

    from receipt_ledger import Ledger, reference
    with Ledger.create("ledger.sqlite") as ledger:
        ledger.import_outbound(open("outbound.jsonl", "rb").read())
        ledger.import_dsn(open("dsn.jsonl", "rb").read())
        ledger.explain_summary()

Facts (outbound attempts, parsed DSN items, corrections, human decisions) are
kept apart from derivations (candidate sets, chain state, per-attempt status).
Derivations are recomputable with ``rebuild()`` and never contradict the
recorded evidence.
"""

from .addr import AddressError, canonical_recipient
from .engine import ImportOutcome, Ledger
from .errors import (
    CorrectionError,
    DecisionError,
    InputFormatError,
    InputIdentityError,
    LedgerError,
)
from .fingerprint import fingerprint as candidate_fingerprint
from . import reference

__all__ = [
    "Ledger",
    "ImportOutcome",
    "LedgerError",
    "InputFormatError",
    "InputIdentityError",
    "DecisionError",
    "CorrectionError",
    "AddressError",
    "canonical_recipient",
    "candidate_fingerprint",
    "reference",
]
