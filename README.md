# Per-recipient delivery receipt evidence ledger

A local Python + SQLite tool that answers one question honestly:

> For **this delivery attempt to this recipient**, did a gateway receipt prove
> delivery — and if not, exactly why not?

It explicitly does *not* answer "some email with a similar name was delivered".
Nothing here guesses: an ambiguous, unmatched, withdrawn, conflicted or stale
piece of evidence keeps an explicit marker and is excluded from the success
count, while remaining fully queryable.

Everything is offline and deterministic: no service, no queue, no mail sending,
no use of the current time.

---

## 1. Quick start

```bash
cd /workspace

# the whole verification suite (tests, drill, CLI replay, bulk scenario)
bash scripts/verify_all.sh

# the main drill as a readable transcript
python3 -I tests/drill.py

# the 100,000-recipient bulk scenario with query plans
python3 -I tests/bulk.py
```

CLI, one command per material type:

```bash
python3 -m receipt_ledger.cli init ledger.sqlite
python3 -m receipt_ledger.cli import-outbound     ledger.sqlite outbound.jsonl
python3 -m receipt_ledger.cli import-dsn          ledger.sqlite dsn.jsonl
python3 -m receipt_ledger.cli import-corrections  ledger.sqlite corrections.jsonl
python3 -m receipt_ledger.cli import-resolutions  ledger.sqlite resolutions.jsonl

# offline archive import: raw gateway .eml exports -> dsn.jsonl (see §14)
python3 -m receipt_ledger.cli convert-archive eml_in/ archive_out/ --gateway gw-main
python3 -m receipt_ledger.cli import-dsn ledger.sqlite archive_out/dsn.jsonl

python3 -m receipt_ledger.cli status      ledger.sqlite --delivery D-100 --recipient Alice@example.com
python3 -m receipt_ledger.cli attempt-status ledger.sqlite --delivery D-100 --attempt att-2 --recipient Alice@example.com
python3 -m receipt_ledger.cli timeline    ledger.sqlite --recipient Alice@example.com
python3 -m receipt_ledger.cli pending     ledger.sqlite
python3 -m receipt_ledger.cli conflicts   ledger.sqlite
python3 -m receipt_ledger.cli explain-item ledger.sqlite --report RPT-1 --item ITEM-1
python3 -m receipt_ledger.cli fingerprint ledger.sqlite --report RPT-1 --item ITEM-1
python3 -m receipt_ledger.cli summary     ledger.sqlite
python3 -m receipt_ledger.cli rebuild     ledger.sqlite

# investigation evidence package: a self-contained sub-ledger (see §15)
python3 -m receipt_ledger.cli export-case ledger.sqlite selectors.json case_out/
```

The shell-replayable drills are `scripts/drill_cli.sh` (state transitions) and
`scripts/drill_export_case.sh` (export an investigation case, move the source
away, query the sub-ledger).

Python API:

```python
from receipt_ledger import Ledger

with Ledger.create("ledger.sqlite") as ledger:
    ledger.import_outbound(open("outbound.jsonl", "rb").read())
    ledger.import_dsn(open("dsn.jsonl", "rb").read())
    ledger.import_corrections(open("corrections.jsonl", "rb").read())
    ledger.import_resolutions(open("resolutions.jsonl", "rb").read())
    ledger.delivery_status("gw-main", "D-100", "Alice@example.com")
    ledger.explain_summary()
```

---

## 2. Input formats (JSONL, one object per line)

### Outbound attempts

```json
{"delivery_id":"D-100","attempt_id":"att-1","recipient":"Alice@Example.COM",
 "queue_id":"QUEUE-9","envelope_id":"ENV-A","sent_at":"2026-02-01T00:00:00Z",
 "gateway_id":"gw-main"}
```

| field | required | notes |
|---|---|---|
| `delivery_id` | yes | business delivery, one per logical message |
| `attempt_id` | yes | unique **within** a delivery |
| `recipient` | yes | one address; see the address rules below |
| `sent_at` | yes | RFC 3339 with an explicit offset |
| `queue_id`, `envelope_id` | no | opaque; only unique **within a gateway** |
| `gateway_id` | no | defaults to `--default-gateway` (`default`) |

`attempt_id` is unique per `(gateway, delivery_id, attempt_id, recipient)`; one
attempt may carry several recipient rows. Attempts are never identified by
Message-ID, subject or sender.

`queue_id` / `envelope_id` are meaningful **only inside one gateway**. Two
gateways using the same number are two unrelated identifiers.

### Parsed DSN items (receipt items)

```json
{"gateway_id":"gw-main","report_id":"RPT-1","item_id":"ITEM-1",
 "recipient":"Alice@example.com","occurred_at":"2026-02-01T01:00:00Z",
 "action":"delivered","queue_id":"QUEUE-9"}
```

`action` is `delayed`, `delivered` or `failed`. At least one of `queue_id` /
`envelope_id` is required (a receipt with no matching condition at all could
never be associated). MIME/RFC parsing is out of scope: **this tool consumes the
already-parsed item**.

Identity is `(gateway_id, report_id, item_id)`, compared as exact bytes (no
case folding, no Unicode normalization).

### Corrections

```json
{"gateway_id":"gw-main","report_id":"RPT-1-COR1","item_id":"ITEM-1-COR1",
 "target_report_id":"RPT-1","target_item_id":"ITEM-1",
 "occurred_at":"2026-02-01T03:00:00Z","action":"withdraw"}
```

A correction has its **own** identity and points precisely at the item it
corrects via `target_report_id` / `target_item_id` in the same gateway.
`action` is `delayed`, `delivered`, `failed` or `withdraw`. A correction may
replace **`action` and `occurred_at` only**; if it also states `recipient`,
`queue_id` or `envelope_id`, the value must restate what the corrected item
already says. Introducing or changing one is a silent re-association, so the
whole chain becomes error evidence (`chain_state = invalid`).

### Human decisions

```json
{"gateway_id":"gw-main","report_id":"RPT-1","item_id":"ITEM-1",
 "delivery_id":"D-100","attempt_id":"att-2","recipient":"Alice@example.com",
 "candidate_fingerprint":"<64 hex chars>","decided_at":"2026-02-01T02:00:00Z"}
```

The fingerprint is mandatory and is quoted from the candidate set as it was when
the human looked at it (`explain-item` / `fingerprint` prints it). If the set
has changed since, the decision is **rejected** (`decision_error`) and nothing
is written — it is never quietly re-pointed at a new attempt.

---

## 3. Address convention (deliberately narrow)

* Only an ASCII `local@domain` dot-atom address is accepted.
* The **domain is lowercased**; the **local part is compared byte-for-byte**
  (RFC 5321 allows case-sensitive local parts, so folding it would be a guess).
* Rejected as unsupported, with a format error: quoted local parts, address
  literals (`a@[192.0.2.1]`), non-ASCII / IDN text, comments, whitespace,
  control characters, trailing dots, empty parts, single-label domains, and
  more than one `@`.

Address comparisons use the signature `r:<canonical>`; queue/envelope
comparisons use `q:<raw>`; gateway/report/item identities use `i:<raw>`. The
tags are part of the canonical form and make it impossible for an address to
compare equal to an identifier.

---

## 4. Matching rule

A receipt item (or, after a clean chain, its end node) is a candidate for an
attempt when **all** of these hold:

1. same `gateway_id`;
2. same canonical recipient;
3. `sent_at <= occurred_at` (the attempt existed when the receipt was made);
4. **every** queue/envelope condition the item supplies equals the attempt's.

The candidate set is the **intersection** of all supplied conditions, never a
union. Consequences:

* contradictory conditions → **empty** intersection → `unmatched`;
* fields not supplied by the receipt do not narrow and do not widen;
* no "most trusted field" is picked to hide a contradiction;
* no nearest-timestamp tie-break: the time condition is a hard bound, not a
  ranking.

| candidates | mark | status contribution |
|---|---|---|
| 0 | `unmatched` | none |
| 1 | `unique` | this attempt gets the action |
| >1 | `ambiguous` | none until a human decides |

Late outbound rows can move 0 → 1 **or** 1 → 2, so every import re-evaluates
the affected receipts; a previously published state is never an irreversible
match.

**Time** comes from the chain end. A correction that changes `occurred_at`
therefore re-runs the candidate query — a receipt can become unmatched purely
because its corrected time moved before the attempt.

---

## 5. Correction chains

* A correction has its own identity and targets one item exactly (same gateway).
* Each node has at most one successor. Two **different** corrections targeting
  the same parent is a `correction_conflict`.
* A directed cycle is an error; every node on it is excluded.
* A correction whose parent is absent is **pending** — kept, never dropped,
  because the parent may arrive later (corrections may arrive in reverse).
* Only a chain that is clean — no conflict, no cycle, no pending parent, no
  invalid correction — contributes, and only through its **end** node.
* Withdrawing the end leaves the original receipt with **no effective action**;
  the original and intermediate events remain queryable.
* A conflicted, cyclic or invalid whole chain contributes nothing. No branch is
  preferred by import order or timestamp.
* **Taint is transitive**: a correction under a conflicted or cyclic node is
  unusable too, because its chain root is undecided.

Importing a correction only re-evaluates the chains it can affect (its target's
root, any chain that gained or lost a branch, and any chain whose pending
correction may now resolve) — not the whole repository.

---

## 6. Delivery status

Status is computed **per exact attempt and recipient** from effective, uniquely
associated receipts:

| effective actions on the attempt | attempt status |
|---|---|
| none | `awaiting` |
| only `delayed` | `delayed` (non-terminal) |
| `delayed` + one terminal | that terminal |
| only `delivered` | `delivered` |
| only `failed` | `failed` |
| `delivered` **and** `failed` | `inconsistent` |

`inconsistent` is never resolved by "whichever came later": two gateways
contradicting each other is a real signal that must be seen, not averaged away.

**Delivery status = the status of the last registered attempt** for that
`(gateway, delivery, recipient)`. "Last" means the maximum of
`(sent_at, attempt_id)` where `attempt_id` is compared by **raw lexicographic
order** of the recorded text.

> That tie-break (raw string order, so `"att-9"` > `"att-10"`) is a documented
> project convention. It is deterministic and independent of import order; it
> is not a claim about which attempt is "really" later.

An older attempt's success never makes a newer in-flight retry look delivered:
the delivery follows only its last attempt, while per-attempt detail keeps each
attempt's own proven status visible.

---

## 7. Summary semantics

`explain_summary` / `summary` reports:

* `delivery_counts` — `awaiting`, `delayed`, `delivered`, `failed`,
  `inconsistent` over deliveries (each delivery counted once, via its last
  attempt);
* `proven_delivered` — **only** `delivered`;
* `not_proven` — awaiting + delayed + ambiguous/unmatched/excluded receipt
  counts + inconsistent, each listed separately;
* `evidence_not_counted_as_success` — the actual ambiguous / unmatched /
  excluded / withdrawn receipt rows, with their fingerprints and candidate
  counts;
* `inconsistent_deliveries` — listed by name.

Ambiguous, unmatched, withdrawn, conflicted or stale evidence is **never** part
of the success count, and no attempt is credited on the strength of a guess.

---

## 8. Guarantees about inputs

* Whole-file validation before any write; a format or identity conflict aborts
  the file **atomically** and leaves nothing behind (`import_file` is not even
  recorded).
* A byte-identical re-import is a no-op. A row whose identity already exists
  with identical canonical content is a no-op for that row. The same identity
  with **different** content fails the whole file — last-write-wins is never
  used.
* Valid but non-unique business evidence (unmatched / ambiguous / pending /
  conflicted) is **kept**, not rejected: it is a business fact, not a format
  error.
* All derivations are recomputable (`rebuild`); facts are never rewritten by
  derivation.

---

## 9. Recompute vs. incremental

Facts are stored once. Derivations (`item_link`, `item_candidate`,
`derived_attempt_status`) are recomputed from facts and are the only place a
status exists.

After an import, only affected chains are re-evaluated:

* a new outbound attempt → one indexed join against a temp table of the new
  rows, restricted to the same gateway/recipient and to receipts whose chain
  upper-bound time is not earlier than the attempt;
* a new receipt → its own chain only;
* a correction → the chains it touches (target root, chains that gained/lost a
  branch, chains whose pending child may resolve);
* a decision → its own chain.

`tests/bulk.py` demonstrates this on 100,000 outbound recipient rows:
one late attempt re-evaluates **one** root and does not scan
`outbound_attempt`; the query plans are printed and checked.

`rebuild()` is the escape hatch and always reproduces the same state (checked in
`tests/test_status.py::test_rebuild_matches_incremental_state`), and import
order never changes the final state (checked in
`test_import_order_does_not_change_final_state`).

---

## 10. Interface reference

| method | purpose |
|---|---|
| `import_outbound(data, *, source, default_gateway)` | outbound attempts |
| `import_dsn(data, *, source)` | parsed receipt items |
| `import_corrections(data, *, source)` | corrections |
| `import_resolutions(data, *, source)` | human decisions |
| `attempt_status(gateway, delivery, attempt, recipient)` | one exact attempt |
| `delivery_status(gateway, delivery, recipient)` | last attempt + per-attempt detail |
| `recipient_timeline(recipient, gateway=None)` | attempts, chains, corrections, decisions, time ordered |
| `pending_associations()` | unmatched / ambiguous / excluded / withdrawn / pending / stale decisions |
| `correction_conflicts()` | conflicted and cyclic chains with every branch |
| `explain_item(gateway, report, item)` | chain, effective action/time, candidate set, decisions, assignment and provenance |
| `explain_summary()` | status totals and the exclusions |
| `rebuild()` | recompute all derivations |

Every query can be followed back to the original item (`item_link.root_key`),
the correction chain (`explain_item.chain`), the candidate set
(`item_candidate`, `candidate_fingerprint`) and the human decision
(`manual_decision`, including the fingerprint it was made against).

---

## 11. Errors

| code | meaning | what happens |
|---|---|---|
| `input_format_error` | malformed JSONL / field / timestamp / address | whole file rejected, nothing written |
| `input_identity_error` | same identity, different content; identity reused across receipts and corrections | whole file rejected, nothing written |
| `decision_error` | unknown item/gateway, non-candidate choice, conflicted chain, **stale fingerprint** | file rejected, nothing written |
| `correction_error` | reserved for correction-specific rejections | file rejected |

Business ambiguity is **not** an error — it is a recorded state.

---

## 12. Layout

```
receipt_ledger/
  addr.py        address canonicalization + identity signatures
  jsonio.py      strict JSONL reading, RFC 3339 integer-microsecond parsing
  ingest.py      per-record parsing/validation (pure, no DB)
  matching.py    candidate query (indexed intersection)
  chains.py      correction graph analysis (conflict / cycle / pending)
  fingerprint.py candidate-set fingerprint (documented format)
  schema.py      SQLite schema: facts vs derivations
  engine.py      imports, incremental derivation, status, queries
  reference.py   independent brute-force oracle (no engine imports)
  dsnmime.py     offline .eml -> DSN parsing (pure MIME/DSN, no I/O)
  archive.py     batch directory conversion + atomic publish + manifest
  case_export.py investigation sub-ledger export (snapshot + closure + verify)
  cli.py         command line interface
tests/
  test_inputs.py                  format/identity/atomicity
  test_status.py                  matching, terminals, retries, chains, decisions
  test_reference_crosscheck.py    step-by-step engine vs oracle (incl. 40 random runs)
  test_reference_independence.py  guard: oracle must not use engine code
  test_archive.py                 archive-import acceptance (hand-computed expectations)
  test_export_case.py             export-case acceptance (hand-written scopes)
  archive_samples.py              real MIME byte samples used by the acceptance tests
  drill.py                        the main tracked drill
  bulk.py                         100k-recipient scenario + query plans
scripts/
  verify_all.sh   run everything
  drill_cli.sh    the drill through the CLI on a real SQLite file (fail-fast)
  drill_export_case.sh  export-case replay, source moved away, sub-ledger queried
  make_fixtures.py regenerate fixtures/
  make_archive_fixtures.py regenerate fixtures/archive/**.eml
fixtures/         reusable JSONL materials per scenario
fixtures/archive/ real .eml acceptance samples per case
```

---

## 13. Documented conventions (all deliberate)

1. Domain lowercased, local part byte-exact, dot-atom only.
2. Identity = exact bytes; Unicode is not normalized.
3. `queue_id` / `envelope_id` scoped to a gateway.
4. Candidates = intersection of supplied conditions; no tie-break by recency.
5. `sent_at <= occurred_at` uses the **chain end** time, to the microsecond.
6. Last attempt = `(sent_at, attempt_id)` with lexicographic `attempt_id`
   (so `"att-9" > "att-10"`; deterministic, independent of import order).
7. `delivered` + `failed` on one attempt = `inconsistent` (not "latest wins").
8. Corrected action/time only; recipient/queue/envelope must be restated.
9. Conflicted / cyclic / pending / invalid chains contribute nothing.
10. Fingerprints are mandatory for human decisions and are never repaired.

---

## 14. Offline archive import (.eml → DSN JSONL)

The bounce-handling team receives raw `.eml` exports from the gateway, while
the ledger only consumes already-split DSN items.  `convert-archive` bridges
that gap **offline**: it never connects to a mailbox, never sends mail and
never touches ledger state.  Ledger state is entirely determined by a
subsequent, independent `import-dsn` of the produced file.

```bash
python3 -m receipt_ledger.cli convert-archive eml_in/ archive_out/ --gateway gw-main
python3 -m receipt_ledger.cli import-dsn ledger.sqlite archive_out/dsn.jsonl
```

`archive_out/` must be a **new** path.  The whole batch is parsed and
validated first and written inside a controlled temporary directory next to
the target; a single atomic rename publishes it.  If the target already
exists or any read/write fails, the command fails and leaves nothing behind —
the target never appears with a half batch.  Input files are only read.

### What is accepted as a receipt carrier

* top-level `Content-Type: multipart/report` with
  `report-type=delivery-status`, and
* **exactly one** `message/delivery-status` part among its direct parts.

Plain bodies, attachments and embedded `message/rfc822` content are never
treated as receipt data, and nothing is guessed from the Subject, the body
or attachment names.  Report-level structural or decoding damage —
`report_type_mismatch`, `malformed_headers`, `mime_boundary` (incl. an
unclosed boundary), `transfer_encoding`, `unsupported_charset`,
`charset_decode`, `dsn_part_missing`, `dsn_part_duplicate`, `dsn_structure` —
means the whole message yields **no** canonical receipts and gets one
quarantine entry instead.

### Field rules (RFC 3464, deliberately strict)

* Field names are case-insensitive.  Unfolding removes the line break plus
  the continuation's leading whitespace and joins directly; a line that does
  not start with whitespace always starts a new field, so adjacent fields are
  never glued together.
* The recipient comes from `Final-Recipient`, else `Original-Recipient`
  (documented precedence).  The address type must be `rfc822` and the address
  must satisfy §3; the emitted value is the ledger-canonical form.
* `Action` must agree with the `Status` class: `delivered`/2.x.x,
  `failed`/5.x.x, `delayed`/4.x.x.  `relayed`/`expanded`, unknown actions,
  malformed statuses and contradictions are quarantined, not mapped.
* `occurred_at` is the block's own `Last-Attempt-Date` (RFC 2822) converted
  to RFC 3339 UTC.  Message-level fields (`Reporting-MTA`,
  `Original-Envelope-ID`, `Arrival-Date`, …) are report-wide **context**:
  they are recorded in the manifest, never copied into per-recipient records.
* `queue_id` / `envelope_id` come only from the per-recipient extension
  fields `X-Queue-ID` / `X-Envelope-ID`.  The ledger requires at least one
  matching condition, so a block with neither is quarantined rather than
  widened by a guess.
* A recognized field repeated with conflicting values quarantines the block
  (`conflicting_fields`); no value is ever picked silently.

When the structure is intact, a bad recipient block quarantines only that
block (categories: `malformed_field`, `conflicting_fields`, `missing_field`,
`invalid_field_value`, `unsupported_address_type`, `unsupported_address`,
`unsupported_action`, `invalid_status`, `action_status_mismatch`,
`invalid_date`, `missing_condition`); the remaining blocks still convert, in
their original order.  Quarantine entries carry only the diagnosable facts —
relative file path, file SHA-256, message index, block index, category,
detail — never the body or other recipients' addresses.

### Identity and provenance

* `report_id` = `"rpt-" + sha256(raw message bytes)` (content-derived:
  changed content can never impersonate an earlier report);
  `item_id` = `"item-<n>"` for the n-th recipient block; `gateway_id` is the
  operator-supplied `--gateway` value, never parsed from the message.
* `dsn.jsonl` contains only ledger-known fields, so it imports directly.
* `quarantine.jsonl` lists every block/message that could not be converted,
  with its category.
* `manifest.jsonl` keeps the provenance the ledger must not see: a `run`
  entry (tallies + output digests), one `message` entry per input file
  (status, report-level context, per-block outcomes, digest of the message's
  parse result) and one `record` entry per emitted record mapping it to its
  source (relative path, file SHA-256, message index, block index, parse
  digest).  Identical content in two files yields two distinct provenance
  chains; files are processed in sorted relative-path order, so directory
  enumeration order never changes record content, block order or where
  provenance points.

Acceptance samples with real MIME bytes live in `fixtures/archive/`
(regenerate with `python3 scripts/make_archive_fixtures.py`); the
hand-computed expectations are in `tests/test_archive.py`.

---

## 15. Investigation sub-ledger export (`export-case`)

```bash
python3 -m receipt_ledger.cli export-case SOURCE_DB SELECTORS_JSON OUTPUT_DIR
```

A colleague investigating one incident may need the evidence but must not
receive the whole production ledger.  `export-case` takes explicitly named
deliveries and/or receipt items and writes a **new directory** containing:

```
OUTPUT_DIR/
  ledger.sqlite    a standalone ledger (same schema; query/rebuild tools work)
  selection.json   what was carried, why, and from which import files
```

`OUTPUT_DIR` must not exist.  An invalid selector, a selector absent from the
source, an existing target or any write failure aborts the whole export and
publishes nothing.

### Selector document

```json
{"deliveries": [{"gateway_id": "gw-main", "delivery_id": "D-100",
                 "recipient": "Alice@example.com"}],
 "items":      [{"gateway_id": "gw-main", "report_id": "RPT-1",
                 "item_id": "ITEM-1"}]}
```

At least one delivery or item must be named.  Duplicates collapse; addresses
use the normal §3 convention (ASCII domain folded, local part byte-exact).
Unknown fields, empty values and unsupported addresses are rejected -- the
export never silently skips a selector.

### What travels, and why (`selection.json`)

The closure is computed against a **single consistent read snapshot** of the
whole source (SQLite's online backup inside one read transaction), never
against the partially built sub-ledger.  Concurrent imports may keep
committing; the snapshot cannot see them, so a mixed "old candidates + new
facts" view is impossible.  The source is opened read-only and never modified.

Expansion iterates to a fixed point over these rules, and nothing else:

* a selected delivery is `(gateway, delivery, recipient)` plus **all** its
  retry attempts;
* a receipt's correction group is carried in full, in both directions:
  ancestors, every present branch and descendants.  An **absent** target is
  kept as a logical identity only (never fabricated), so corrections sharing
  the same missing target stay one group;
* every group containing an original DSN contributes its **current candidate
  set**, recomputed from the complete facts, whatever its mark -- ambiguous,
  unmatched, withdrawn or conflicted.  A group with no original DSN
  contributes no candidates;
* a carried attempt brings its delivery's retries, which can pull in further
  groups, so expansion is not one level deep;
* a carried group keeps **all** its human decisions, live and stale, together
  with the candidate set and chosen attempt each saved.  Historical
  competitors are never deleted and fingerprints are never re-signed.

`selection.json` records the normalized selection, every carried business
identity with the reason it was added, the fact counts actually carried, the
receipt groups with their state/candidates/fingerprint, the absent logical
targets, and the referenced `import_file` rows.  `import_file.sha256`,
`source_name` and `source_line_count` still describe the **original** file
history; `carried_rows`/`carried_total`/`partial` say how much of it is
actually present here, so a partial cut is never passed off as the whole file.
Facts from the same import file that are outside the closure are **not**
carried.

### Guarantees

* Facts keep their business values; row ids are preserved so every internal
  reference (`line_key`, `requested_key`, `candidate_fp`, FK columns) points
  at the same business fact -- a decision can never drift onto another
  receipt.  Row numbers and output order carry no semantic meaning.
* Derivations are **regenerated** by the engine's own `rebuild` in the
  sub-ledger; old materialized state is never copied.  Before publishing, the
  export rebuilds the sub-ledger and compares it with a freshly re-derived
  snapshot: per-attempt and per-delivery status, each group's candidate set,
  fingerprint, mark, effective end, conflict/exclusion reason and decisions,
  all compared by business identity.  A mismatch aborts the export.
* No out-of-scope originals, attempts, decisions, or unreferenced
  gateways/import-file rows exist in the sub-ledger (`foreign_key_check` and
  `integrity_check` are also run).
* After the export the source may be moved away; `status`, `attempt-status`,
  `explain-item`, `pending`, `conflicts`, `summary` and `rebuild` all work on
  the sub-ledger.  `summary` counts only the carried range (it is not expected
  to equal the source totals).
* Importing the original files into a sub-ledger is out of scope: this is a
  frozen package for investigation and independent recomputation.

`tests/test_export_case.py` hand-writes the expected business identities (no
exporter-computed set is used as its own expectation) and covers the main
drill, a withdrawn group, a stale decision's non-current candidate, two
gateways with equal numbers, selector/target/write failures, and a real
two-process concurrent-import run.  `scripts/drill_export_case.sh` is the
re-runnable transcript.
