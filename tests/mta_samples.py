"""Hand-written Postfix MTA event samples for the acceptance suite.

These are literal log events -- never output of the reconstructor -- grouped by
scenario.  A scenario is ``{file_name: [event dict, ...]}`` where list order is
the intended physical line order.  The tests deliberately write scenarios with
reverse-time file order and shuffled lines, because directory and line order
must carry no meaning.

Run fixtures regeneration: python3 scripts/make_mta_fixtures.py
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# main sample: two recipients, alice deferred then sent, one rotation-boundary
# duplicate line, file order opposite to event time.
#
#   gw1 / Q-100 / Message-ID <msg-main-1>, sender ops@example.com
#     10:00:00 queued
#     10:05:00 delivery alice@example.com  deferred
#     10:05:00 delivery bob@example.com    sent        (parallel recipient)
#     10:10:00 delivery alice@example.com  sent        (boundary duplicate)
#     10:15:00 removed
# --------------------------------------------------------------------------- #
MAIN = {
    "mta-50-late.jsonl": [
        {"timestamp": "2026-03-10T10:15:00Z", "host": "gw1",
         "queue_id": "Q-100", "event": "removed"},
        {"timestamp": "2026-03-10T10:10:00Z", "host": "gw1",
         "queue_id": "Q-100", "event": "delivery",
         "recipient": "alice@example.com", "relay": "mx.alice.example",
         "result": "sent"},
    ],
    "mta-49-early.jsonl": [
        {"timestamp": "2026-03-10T10:10:00Z", "host": "gw1",
         "queue_id": "Q-100", "event": "delivery",
         "recipient": "alice@example.com", "relay": "mx.alice.example",
         "result": "sent"},
        {"timestamp": "2026-03-10T10:05:00Z", "host": "gw1",
         "queue_id": "Q-100", "event": "delivery",
         "recipient": "bob@example.com", "relay": "mx.bob.example",
         "result": "sent"},
        {"timestamp": "2026-03-10T10:05:00Z", "host": "gw1",
         "queue_id": "Q-100", "event": "delivery",
         "recipient": "alice@example.com", "relay": "mx.alice.example",
         "result": "deferred"},
        {"timestamp": "2026-03-10T10:00:00Z", "host": "gw1",
         "queue_id": "Q-100", "event": "queued",
         "message_id": "<msg-main-1>", "sender": "ops@example.com"},
    ],
}

# hand-computed expectations for the main sample (recipient -> attempts)
MAIN_EXPECTED_ATTEMPTS = {
    "alice@example.com": [
        ("att-1", "2026-03-10T10:05:00Z", "deferred"),
        ("att-2", "2026-03-10T10:10:00Z", "sent"),
    ],
    "bob@example.com": [
        ("att-1", "2026-03-10T10:05:00Z", "sent"),
    ],
}
MAIN_HOST = "gw1"
MAIN_QUEUE = "Q-100"
MAIN_MESSAGE_ID = "<msg-main-1>"
MAIN_DUPLICATE_COORDS = [
    ("mta-49-early.jsonl", 1),
    ("mta-50-late.jsonl", 2),
]

# --------------------------------------------------------------------------- #
# queue-id reuse: gw1 / Q-200 has two complete lifetimes, both carrying the
# SAME Message-ID <msg-reused>.  They must produce two different deliveries.
# --------------------------------------------------------------------------- #
REUSED = {
    "reused.jsonl": [
        {"timestamp": "2026-03-11T08:00:00Z", "host": "gw1",
         "queue_id": "Q-200", "event": "queued",
         "message_id": "<msg-reused>", "sender": "ops@example.com"},
        {"timestamp": "2026-03-11T08:02:00Z", "host": "gw1",
         "queue_id": "Q-200", "event": "delivery",
         "recipient": "carol@example.org", "relay": "mx-carol",
         "result": "sent"},
        {"timestamp": "2026-03-11T08:05:00Z", "host": "gw1",
         "queue_id": "Q-200", "event": "removed"},
        {"timestamp": "2026-03-11T09:00:00Z", "host": "gw1",
         "queue_id": "Q-200", "event": "queued",
         "message_id": "<msg-reused>", "sender": "ops@example.com"},
        {"timestamp": "2026-03-11T09:03:00Z", "host": "gw1",
         "queue_id": "Q-200", "event": "delivery",
         "recipient": "dave@example.org", "relay": "mx-dave",
         "result": "deferred"},
        {"timestamp": "2026-03-11T09:08:00Z", "host": "gw1",
         "queue_id": "Q-200", "event": "delivery",
         "recipient": "dave@example.org", "relay": "mx-dave",
         "result": "sent"},
        {"timestamp": "2026-03-11T09:10:00Z", "host": "gw1",
         "queue_id": "Q-200", "event": "removed"},
    ],
}

# --------------------------------------------------------------------------- #
# missing queued: delivery + removed events with no lifecycle.  Both become
# orphan reports; nothing is guessed into a queue id.
# --------------------------------------------------------------------------- #
MISSING_QUEUED = {
    "missing_queued.jsonl": [
        {"timestamp": "2026-03-12T07:00:00Z", "host": "gw2",
         "queue_id": "Q-NOQ", "event": "delivery",
         "recipient": "erin@example.net", "relay": "mx-erin",
         "result": "sent"},
        {"timestamp": "2026-03-12T07:05:00Z", "host": "gw2",
         "queue_id": "Q-NOQ", "event": "removed"},
    ],
}

# --------------------------------------------------------------------------- #
# re-queued before removal: a second queued on the same host/queue while the
# first lifetime is still open.  The first lifetime is quarantined whole; the
# second still resolves cleanly and emits.
# --------------------------------------------------------------------------- #
REQUEUED = {
    "requeued.jsonl": [
        {"timestamp": "2026-03-12T08:00:00Z", "host": "gw2",
         "queue_id": "Q-RQ", "event": "queued",
         "message_id": "<msg-rq-1>", "sender": "ops@example.com"},
        {"timestamp": "2026-03-12T08:02:00Z", "host": "gw2",
         "queue_id": "Q-RQ", "event": "delivery",
         "recipient": "frank@example.net", "relay": "mx-frank",
         "result": "sent"},
        {"timestamp": "2026-03-12T08:10:00Z", "host": "gw2",
         "queue_id": "Q-RQ", "event": "queued",
         "message_id": "<msg-rq-2>", "sender": "ops@example.com"},
        {"timestamp": "2026-03-12T08:12:00Z", "host": "gw2",
         "queue_id": "Q-RQ", "event": "delivery",
         "recipient": "grace@example.net", "relay": "mx-grace",
         "result": "sent"},
        {"timestamp": "2026-03-12T08:15:00Z", "host": "gw2",
         "queue_id": "Q-RQ", "event": "removed"},
    ],
}
REQUEUED_GOOD_RECIPIENT = "grace@example.net"

# --------------------------------------------------------------------------- #
# content conflict: same timestamp and recipient, contradictory results.
# Whole lifecycle quarantined; an independent lifecycle in the same batch
# still emits (isolation must not wipe valid neighbors).
# --------------------------------------------------------------------------- #
CONTENT_CONFLICT = {
    "conflict.jsonl": [
        {"timestamp": "2026-03-12T09:00:00Z", "host": "gw2",
         "queue_id": "Q-CF", "event": "queued",
         "message_id": "<msg-cf>", "sender": "ops@example.com"},
        {"timestamp": "2026-03-12T09:03:00Z", "host": "gw2",
         "queue_id": "Q-CF", "event": "delivery",
         "recipient": "heidi@example.net", "relay": "mx-h",
         "result": "sent"},
        {"timestamp": "2026-03-12T09:03:00Z", "host": "gw2",
         "queue_id": "Q-CF", "event": "delivery",
         "recipient": "heidi@example.net", "relay": "mx-h",
         "result": "deferred"},
        {"timestamp": "2026-03-12T09:06:00Z", "host": "gw2",
         "queue_id": "Q-CF", "event": "removed"},
    ],
    "neighbor.jsonl": [
        {"timestamp": "2026-03-12T09:01:00Z", "host": "gw2",
         "queue_id": "Q-OK", "event": "queued",
         "message_id": "<msg-ok>", "sender": "ops@example.com"},
        {"timestamp": "2026-03-12T09:04:00Z", "host": "gw2",
         "queue_id": "Q-OK", "event": "delivery",
         "recipient": "ivan@example.net", "relay": "mx-i",
         "result": "sent"},
        {"timestamp": "2026-03-12T09:07:00Z", "host": "gw2",
         "queue_id": "Q-OK", "event": "removed"},
    ],
}
CONFLICT_QUEUE = "Q-CF"
NEIGHBOR_QUEUE = "Q-OK"
NEIGHBOR_RECIPIENT = "ivan@example.net"

# --------------------------------------------------------------------------- #
# ambiguous retry order: one recipient, two distinct delivery events at the
# same timestamp with the same result.  Quarantined whole (line numbers must
# not decide retry order).
# --------------------------------------------------------------------------- #
AMBIGUOUS = {
    "ambiguous.jsonl": [
        {"timestamp": "2026-03-12T10:00:00Z", "host": "gw3",
         "queue_id": "Q-AM", "event": "queued",
         "message_id": "<msg-am>", "sender": "ops@example.com"},
        {"timestamp": "2026-03-12T10:04:00Z", "host": "gw3",
         "queue_id": "Q-AM", "event": "delivery",
         "recipient": "judy@example.io", "relay": "mx-j-1",
         "result": "sent"},
        {"timestamp": "2026-03-12T10:04:00Z", "host": "gw3",
         "queue_id": "Q-AM", "event": "delivery",
         "recipient": "judy@example.io", "relay": "mx-j-2",
         "result": "sent"},
        {"timestamp": "2026-03-12T10:09:00Z", "host": "gw3",
         "queue_id": "Q-AM", "event": "removed"},
    ],
}
AMBIGUOUS_QUEUE = "Q-AM"

# --------------------------------------------------------------------------- #
# line-level isolation in one batch, alongside a fully valid lifecycle:
# unknown event kind, structurally malformed event, unsupported recipient,
# and an undecodable byte line.  The bad lines never participate in
# reconstruction; the good lifecycle next to them still emits.
# --------------------------------------------------------------------------- #
BAD_LINES = {
    "bad_lines.jsonl": [
        {"timestamp": "2026-03-12T11:00:00Z", "host": "gw3",
         "queue_id": "Q-BL", "event": "queued",
         "message_id": "<msg-bl>", "sender": "ops@example.com"},
        {"timestamp": "2026-03-12T11:02:00Z", "host": "gw3",
         "queue_id": "Q-BL", "event": "bounced"},  # unknown event
        {"timestamp": "2026-03-12T11:03:00Z", "host": "gw3",
         "queue_id": "Q-BL", "event": "delivery",
         "recipient": "kyle@example.io"},          # missing relay/result
        {"timestamp": "2026-03-12T11:04:00Z", "host": "gw3",
         "queue_id": "Q-BL", "event": "delivery",
         "recipient": "not-an-address", "relay": "mx-k",
         "result": "sent"},                        # unsupported recipient
        {"timestamp": "2026-03-12T11:05:00Z", "host": "gw3",
         "queue_id": "Q-BL", "event": "delivery",
         "recipient": "leo@example.io", "relay": "mx-l",
         "result": "sent"},
        {"timestamp": "2026-03-12T11:09:00Z", "host": "gw3",
         "queue_id": "Q-BL", "event": "removed"},
    ],
}
# physical file adds one corrupted JSON line (raw bytes, not in this dict)
BAD_LINES_FILE = "bad_lines.jsonl"
BAD_LINES_CORRUPT = '{"timestamp": "2026-03-12T11:06:00Z", broken\n'
BAD_LINES_GOOD_RECIPIENT = "leo@example.io"

# a whole file that cannot be decoded as UTF-8: batch-level failure
UNDECODABLE_FILE = "undecodable.jsonl"
UNDECODABLE_BYTES = (
    b'{"timestamp":"2026-03-12T12:00:00Z","host":"gw3","queue_id":"Q-UD",'
    b'"event":"queued","message_id":"<m>","sender":"\xff\xfe ops@x.io"}\n')

SCENARIOS = {
    "main": MAIN,
    "reused": REUSED,
    "missing_queued": MISSING_QUEUED,
    "requeued": REQUEUED,
    "content_conflict": CONTENT_CONFLICT,
    "ambiguous": AMBIGUOUS,
    "bad_lines": BAD_LINES,
}
