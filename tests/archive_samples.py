"""Acceptance samples for the offline archive import: real MIME bytes.

Every sample is hand-written message material as a gateway would export it
(CRLF or LF line endings, folded fields, base64 parts, attachments).  The
expected conversion results are *not* derived here; tests/test_archive.py
carries independently hand-computed expectations.
"""

from __future__ import annotations

import base64

CRLF = b"\r\n"


def _crlf(*lines):
    return CRLF.join(lines) + CRLF


# --------------------------------------------------------------------------- #
# main drill: folded fields, several recipients, message-level context,
# a human-readable part that merely *looks* like DSN data, and an embedded
# message/rfc822 attachment.  Everything valid -> three records.
# --------------------------------------------------------------------------- #
MAIN_EML = _crlf(
    b"From: MAILER-DAEMON@gw-main.example.com",
    b"To: sender@example.com",
    b"Subject: Undelivered mail returned to sender",
    b"Date: Tue, 03 Feb 2026 09:00:00 +0000",
    b"MIME-Version: 1.0",
    b"Content-Type: multipart/report;",
    b"\treport-type=delivery-status;",
    b' boundary="main-boundary-42"',
    b"",
    b"This preamble is ignored.",
    b"--main-boundary-42",
    b"Content-Type: text/plain; charset=us-ascii",
    b"",
    b"This is the human-readable explanation.  It is NOT receipt data,",
    b"even though it mentions fields that look like a DSN:",
    b"Final-Recipient: rfc822; not-a-receipt@example.com",
    b"Action: failed",
    b"Status: 9.9.9",
    b"--main-boundary-42",
    b"Content-Type: message/delivery-status",
    b"",
    b"Reporting-MTA: dns;",
    b"\tgw-main.example.com",
    b"Original-Envelope-ID: ENV-A",
    b"Arrival-Date: Tue,",
    b"\t03 Feb 2026 08:15:00 +0000",
    b"",
    b"Final-Recipient: rfc822;",
    b"\tAlice@Example.COM",
    b"Action: delivered",
    b"Status: 2.0.0",
    b"Last-Attempt-Date: Tue, 03 Feb",
    b"\t2026 09:30:00 +0530",
    b"X-Queue-ID: QUEUE-9",
    b"",
    b"Final-Recipient: rfc822; bob@example.net",
    b"Action: failed",
    b"Status: 5.1.1",
    b"Last-Attempt-Date: Tue, 03 Feb 2026 09:31:00 +0000",
    b"X-Queue-ID: QUEUE-10",
    b"X-Envelope-ID: ENV-B",
    b"",
    b"Original-Recipient: rfc822; carol@example.org",
    b"Action: delayed",
    b"Status: 4.4.1",
    b"Last-Attempt-Date: Tue, 03 Feb 2026 09:32:00 +0000",
    b"X-Queue-ID: QUEUE-11",
    b"--main-boundary-42",
    b"Content-Type: message/rfc822",
    b"",
    b"From: sender@example.com",
    b"To: alice@example.com",
    b"Subject: original message",
    b"",
    b"the original message body",
    b"Final-Recipient: rfc822; nested@example.com",
    b"--main-boundary-42--",
    b"This epilogue is ignored.",
)

# --------------------------------------------------------------------------- #
# mixed: LF-only line endings; the middle recipient block contradicts itself
# (Action: failed with a 2.x.x status) and must be quarantined alone.
# --------------------------------------------------------------------------- #
MIXED_EML = b"\n".join([
    b"Content-Type: multipart/report; report-type=delivery-status; boundary=mix-b",
    b"MIME-Version: 1.0",
    b"",
    b"--mix-b",
    b"Content-Type: message/delivery-status",
    b"",
    b"Reporting-MTA: dns; gw2.example.com",
    b"",
    b"Final-Recipient: rfc822; dave@example.com",
    b"Action: delivered",
    b"Status: 2.0.0",
    b"Last-Attempt-Date: Wed, 04 Feb 2026 10:00:00 +0000",
    b"X-Queue-ID: Q-1",
    b"",
    b"Final-Recipient: rfc822; erin@example.com",
    b"Action: failed",
    b"Status: 2.1.5",
    b"Last-Attempt-Date: Wed, 04 Feb 2026 10:01:00 +0000",
    b"X-Queue-ID: Q-2",
    b"",
    b"Final-Recipient: rfc822; frank@example.com",
    b"Action: failed",
    b"Status: 5.1.2",
    b"Last-Attempt-Date: Wed, 04 Feb 2026 10:02:00 +0000",
    b"X-Queue-ID: Q-3",
    b"--mix-b--",
    b"",
])

# --------------------------------------------------------------------------- #
# report-level failures, one message each
# --------------------------------------------------------------------------- #
MISSING_DSN_PART_EML = _crlf(
    b"Content-Type: multipart/report; report-type=delivery-status; boundary=n1",
    b"",
    b"--n1",
    b"Content-Type: text/plain",
    b"",
    b"your message could not be delivered",
    b"--n1",
    b"Content-Type: message/rfc822",
    b"",
    b"Subject: original",
    b"",
    b"body",
    b"--n1--",
    b"",
)

DUPLICATE_DSN_PART_EML = _crlf(
    b"Content-Type: multipart/report; report-type=delivery-status; boundary=d1",
    b"",
    b"--d1",
    b"Content-Type: message/delivery-status",
    b"",
    b"Reporting-MTA: dns; gw1.example.com",
    b"--d1",
    b"Content-Type: message/delivery-status",
    b"",
    b"Reporting-MTA: dns; gw1.example.com",
    b"--d1--",
    b"",
)

UNCLOSED_BOUNDARY_EML = _crlf(
    b"Content-Type: multipart/report; report-type=delivery-status; boundary=u1",
    b"",
    b"--u1",
    b"Content-Type: message/delivery-status",
    b"",
    b"Reporting-MTA: dns; gw1.example.com",
    b"",
    b"Final-Recipient: rfc822; alice@example.com",
    b"Action: failed",
    b"Status: 5.1.1",
    b"Last-Attempt-Date: Tue, 03 Feb 2026 09:31:00 +0000",
    b"X-Queue-ID: QUEUE-10",
    # no closing delimiter: the report is structurally incomplete
)

BAD_TRANSFER_ENCODING_EML = _crlf(
    b"Content-Type: multipart/report; report-type=delivery-status; boundary=t1",
    b"",
    b"--t1",
    b"Content-Type: message/delivery-status",
    b"Content-Transfer-Encoding: base64",
    b"",
    b"!!!!this-is-not-valid-base64!!!!",
    b"--t1--",
    b"",
)

UNKNOWN_CHARSET_EML = _crlf(
    b"Content-Type: multipart/report; report-type=delivery-status; boundary=c1",
    b"",
    b"--c1",
    b"Content-Type: message/delivery-status; charset=x-weird-charset",
    b"",
    b"Reporting-MTA: dns; gw1.example.com",
    b"--c1--",
    b"",
)

NOT_A_REPORT_EML = _crlf(
    b"From: alice@example.com",
    b"To: bob@example.net",
    b"Subject: lunch?",
    b"Content-Type: text/plain; charset=us-ascii",
    b"",
    b"Final-Recipient: rfc822; bob@example.net",
    b"Action: delivered",
    b"Status: 2.0.0",
    b"",
)

EMPTY_DSN_PART_EML = _crlf(
    b"Content-Type: multipart/report; report-type=delivery-status; boundary=e1",
    b"",
    b"--e1",
    b"Content-Type: message/delivery-status",
    b"",
    b"--e1--",
    b"",
)

# --------------------------------------------------------------------------- #
# block-level failures with valid siblings (isolation must keep the rest)
# --------------------------------------------------------------------------- #
CONFLICTING_FIELDS_EML = _crlf(
    b"Content-Type: multipart/report; report-type=delivery-status; boundary=f1",
    b"",
    b"--f1",
    b"Content-Type: message/delivery-status",
    b"",
    b"Reporting-MTA: dns; gw1.example.com",
    b"",
    b"Final-Recipient: rfc822; gina@example.com",
    b"Action: delivered",
    b"Status: 2.0.0",
    b"Last-Attempt-Date: Thu, 05 Feb 2026 11:00:00 +0000",
    b"X-Queue-ID: Q-10",
    b"",
    b"Final-Recipient: rfc822; harry@example.com",
    b"Final-Recipient: rfc822; henry@example.com",
    b"Action: failed",
    b"Status: 5.1.1",
    b"Last-Attempt-Date: Thu, 05 Feb 2026 11:01:00 +0000",
    b"X-Queue-ID: Q-11",
    b"--f1--",
    b"",
)

UNSUPPORTED_ADDR_TYPE_EML = _crlf(
    b"Content-Type: multipart/report; report-type=delivery-status; boundary=a1",
    b"",
    b"--a1",
    b"Content-Type: message/delivery-status",
    b"",
    b"Reporting-MTA: dns; gw1.example.com",
    b"",
    b"Final-Recipient: rfc822; iris@example.com",
    b"Action: delivered",
    b"Status: 2.0.0",
    b"Last-Attempt-Date: Thu, 05 Feb 2026 12:00:00 +0000",
    b"X-Queue-ID: Q-20",
    b"",
    b"Final-Recipient: x400; /C=US/O=ORG/PN=JANE",
    b"Action: failed",
    b"Status: 5.1.1",
    b"Last-Attempt-Date: Thu, 05 Feb 2026 12:01:00 +0000",
    b"X-Queue-ID: Q-21",
    b"--a1--",
    b"",
)

# --------------------------------------------------------------------------- #
# a valid report whose delivery-status part is base64-encoded; the encoded
# content itself uses CRLF line endings, as a real gateway would emit
# --------------------------------------------------------------------------- #
_BASE64_DSN_BODY = b"\r\n".join([
    b"Reporting-MTA: dns; gw3.example.com",
    b"",
    b"Final-Recipient: rfc822; jack@example.com",
    b"Action: failed",
    b"Status: 5.4.4",
    b"Last-Attempt-Date: Fri, 06 Feb 2026 13:00:00 +0000",
    b"X-Queue-ID: Q-30",
    b"",
])
BASE64_DSN_EML = _crlf(
    b"Content-Type: multipart/report; report-type=delivery-status; boundary=b1",
    b"",
    b"--b1",
    b"Content-Type: message/delivery-status",
    b"Content-Transfer-Encoding: base64",
    b"",
    base64.b64encode(_BASE64_DSN_BODY),
    b"--b1--",
    b"",
)

# a structurally valid report with a per-message block but no recipients
NO_RECIPIENTS_EML = _crlf(
    b"Content-Type: multipart/report; report-type=delivery-status; boundary=z1",
    b"",
    b"--z1",
    b"Content-Type: message/delivery-status",
    b"",
    b"Reporting-MTA: dns; gw1.example.com",
    b"Arrival-Date: Fri, 06 Feb 2026 14:00:00 +0000",
    b"--z1--",
    b"",
)

#: case name -> {relative file name: message bytes}
SAMPLES = {
    "main": {"bounce.eml": MAIN_EML},
    "mixed": {"mixed.eml": MIXED_EML},
    "missing_dsn_part": {"broken.eml": MISSING_DSN_PART_EML},
    "duplicate_dsn_part": {"broken.eml": DUPLICATE_DSN_PART_EML},
    "unclosed_boundary": {"broken.eml": UNCLOSED_BOUNDARY_EML},
    "bad_transfer_encoding": {"broken.eml": BAD_TRANSFER_ENCODING_EML},
    "unknown_charset": {"broken.eml": UNKNOWN_CHARSET_EML},
    "not_a_report": {"broken.eml": NOT_A_REPORT_EML},
    "empty_dsn_part": {"broken.eml": EMPTY_DSN_PART_EML},
    "conflicting_fields": {"broken.eml": CONFLICTING_FIELDS_EML},
    "unsupported_addr_type": {"broken.eml": UNSUPPORTED_ADDR_TYPE_EML},
    "base64_dsn": {"encoded.eml": BASE64_DSN_EML},
    "no_recipients": {"empty.eml": NO_RECIPIENTS_EML},
}
