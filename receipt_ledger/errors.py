"""Error taxonomy.

Two families are kept strictly apart:

``InputFormatError``
    Malformed input.  The whole input file is rejected atomically; nothing from
    it remains in the ledger.

``InputIdentityError``
    Structurally valid but conflicting identity/content (the same gateway
    report/item delivered with different content, a correction that tries to
    rewrite its target, ...).  Also atomic per file.

Business ambiguity (unmatched / ambiguous / inconsistent / correction
conflict / over-due human decision) is *not* an error: the facts stay in the
ledger with an explicitly undetermined status.  See ``ledger.DecisionError``
for the one non-file rejection: a human decision whose candidate set changed.
"""

from __future__ import annotations


class LedgerError(Exception):
    """Base class for ledger errors."""

    code = "ledger_error"

    def __init__(self, message, details=None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self):
        return {"code": self.code, "message": self.message, "details": self.details}


class InputFormatError(LedgerError):
    code = "input_format_error"


class InputIdentityError(LedgerError):
    code = "input_identity_error"


class DecisionError(LedgerError):
    code = "decision_error"


class CorrectionError(LedgerError):
    code = "correction_error"


class ExportError(LedgerError):
    """A case-export failure; nothing is published when this is raised.

    ``code`` is supplied per failure (invalid selection, missing source fact,
    existing target, write failure, verification mismatch) so callers can tell
    "the selector was wrong" apart from "the destination was unavailable".
    """

    code = "export_error"

    def __init__(self, code, message, details=None):
        super().__init__(message, details)
        self.code = code
