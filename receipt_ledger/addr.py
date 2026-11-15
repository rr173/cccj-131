"""Recipient address normalization and comparison.

Project convention (documented, deliberately not configurable):

* Only an ASCII domain is case-folded.  The local part is kept byte-for-byte,
  because RFC 5321 local parts may be case-sensitive and this project refuses
  to guess.
* Only a bare ``local@domain`` address is accepted.  Quoted local parts,
  address literals (``[1.2.3.4]``), comments, trailing dots, empty local parts,
  source routes and non-ASCII input are rejected as unsupported forms rather
  than quietly "repaired".
* Signatures are compared after prefixing the exact bytes with ``b"r:"`` so an
  address can never be mistaken for a queue/envelope identifier.
* Identity keys are compared after prefixing the exact bytes with ``b"i:"``.
  Identity keys (``gateway_id``, ``report_id``, ``item_id``) are compared as
  raw UTF-8 (no Unicode normalization and no case folding): two byte sequences
  that merely look alike are two different identities.
"""

from __future__ import annotations

import re
import unicodedata

__all__ = [
    "AddressError",
    "canonical_recipient",
    "recipient_sig",
    "identity_sig",
    "id_sig",
]

# ASCII-only, single @, non-empty local, dotted domain labels of [a-z0-9-].
_LOCAL_RE = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+", re.ASCII)
_DOMAIN_RE = re.compile(
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
    re.ASCII,
)
# anything outside printable ASCII is unsupported (IDN / non-ASCII local part)
_NON_ASCII_RE = re.compile(r"[^\x20-\x7e]")
_CTRL_OR_SPACE_RE = re.compile(r"[\x00-\x1f\x7f ]")


class AddressError(ValueError):
    """The recipient address is not a supported address form."""

    code = "invalid_recipient"


def canonical_recipient(raw):
    """Return ``b"<local>@<lowercased-domain>"`` for a supported address."""
    if not isinstance(raw, (str, bytes)):
        raise AddressError("recipient must be a string")
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AddressError("recipient is not valid UTF-8") from exc
    else:
        text = raw
    if _NON_ASCII_RE.search(text):
        raise AddressError(
            "recipient contains non-ASCII text (IDN/quoted forms are unsupported)"
        )
    if _CTRL_OR_SPACE_RE.search(text):
        raise AddressError("recipient contains control characters or whitespace")
    # deliberately NOT NFKC-normalized: identity is exact bytes
    if unicodedata.normalize("NFC", text) != text:
        raise AddressError("recipient is not NFC; exact bytes are required")
    if text.count("@") != 1:
        raise AddressError("recipient must contain exactly one @")
    local, domain = text.split("@")
    if not local or not domain:
        raise AddressError("recipient needs non-empty local and domain parts")
    if not _LOCAL_RE.fullmatch(local):
        raise AddressError("unsupported local-part form")
    # a dot-atom local part may not start/end with '.' nor contain '..'
    if local.startswith(".") or local.endswith(".") or ".." in local:
        raise AddressError("unsupported local-part dot placement")
    if not _DOMAIN_RE.fullmatch(domain):
        raise AddressError("unsupported domain form")
    return (local + "@" + domain.lower()).encode("ascii")


def recipient_sig(raw):
    """Stored signature used in every index/lookup on recipient."""
    return b"r:" + canonical_recipient(raw)


def _text_bytes(raw, what):
    if not isinstance(raw, str):
        raise AddressError(f"{what} must be a JSON string")
    try:
        data = raw.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AddressError(f"{what} is not valid UTF-8") from exc
    if not data:
        raise AddressError(f"{what} must be non-empty")
    return data


def identity_sig(raw, what="identity"):
    """Signature for gateway/report/item identities: exact UTF-8 bytes."""
    return b"i:" + _text_bytes(raw, what)


def id_sig(raw, what):
    """Signature for queue/envelope ids: opaque exact bytes (may contain @)."""
    return b"q:" + _text_bytes(raw, what)
