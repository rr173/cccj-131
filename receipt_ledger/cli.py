"""Command line interface for the receipt-evidence ledger.

All commands are alongside one SQLite file, so the entire drill can be replayed
with shell commands::

    python -m receipt_ledger.cli init ledger.sqlite
    python -m receipt_ledger.cli import-outbound ledger.sqlite f.jsonl
    python -m receipt_ledger.cli import-dsn ledger.sqlite f.jsonl
    python -m receipt_ledger.cli import-corrections ledger.sqlite f.jsonl
    python -m receipt_ledger.cli import-resolutions ledger.sqlite f.jsonl
    python -m receipt_ledger.cli status ledger.sqlite --delivery D1 --recipient a@b.c
    python -m receipt_ledger.cli timeline ledger.sqlite --recipient a@b.c
    python -m receipt_ledger.cli pending ledger.sqlite
    python -m receipt_ledger.cli conflicts ledger.sqlite
    python -m receipt_ledger.cli explain-item ledger.sqlite --report R1 --item I1
    python -m receipt_ledger.cli summary ledger.sqlite
    python -m receipt_ledger.cli rebuild ledger.sqlite
    python -m receipt_ledger.cli audit-archive-import ledger.sqlite archive_out/

Every command prints JSON on stdout.  Errors print a JSON object with a
``code`` and exit non-zero; a failed import writes nothing.
"""

from __future__ import annotations

import argparse
import json
import sys

from .archive import ArchiveError, convert_archive
from .audit import AuditError, audit_archive_import
from .case_export import export_case
from .engine import Ledger
from .errors import ExportError, LedgerError


def _dump(value):
    print(json.dumps(value, indent=2, sort_keys=False, ensure_ascii=False))


def _read(path):
    with open(path, "rb") as handle:
        return handle.read()


def _open(path):
    return Ledger.open(path)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m receipt_ledger.cli",
        description="Per-recipient delivery receipt evidence ledger")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create a new ledger database")
    p.add_argument("db")

    p = sub.add_parser(
        "convert-archive",
        help="convert a directory of raw .eml bounce exports into canonical "
             "DSN JSONL plus a quarantine list and a provenance manifest, "
             "written to a NEW directory (offline; touches no ledger)")
    p.add_argument("input_dir", help="directory of exported .eml files")
    p.add_argument("output_dir", help="new output directory (must not exist)")
    p.add_argument("--gateway", required=True,
                   help="gateway_id stamped on every produced record; the "
                        "operator-declared source of the export, never "
                        "parsed from the messages")

    for name, kind in (("import-outbound", "outbound"),
                       ("import-dsn", "dsn"),
                       ("import-corrections", "corrections"),
                       ("import-resolutions", "resolutions")):
        p = sub.add_parser(name, help=f"import a {kind} JSONL file")
        p.add_argument("db")
        p.add_argument("file")
        if kind == "outbound":
            p.add_argument("--default-gateway", default="default",
                           help="gateway_id for rows that omit it")

    p = sub.add_parser("status", help="status of one delivery/recipient")
    p.add_argument("db")
    p.add_argument("--delivery", required=True)
    p.add_argument("--recipient", required=True)
    p.add_argument("--gateway", default="default")

    p = sub.add_parser("attempt-status", help="status of one exact attempt")
    p.add_argument("db")
    p.add_argument("--delivery", required=True)
    p.add_argument("--attempt", required=True)
    p.add_argument("--recipient", required=True)
    p.add_argument("--gateway", default="default")

    p = sub.add_parser("timeline", help="all evidence for one recipient")
    p.add_argument("db")
    p.add_argument("--recipient", required=True)
    p.add_argument("--gateway", default=None)

    p = sub.add_parser("pending", help="unmatched/ambiguous/pending evidence")
    p.add_argument("db")

    p = sub.add_parser("conflicts", help="correction conflicts and cycles")
    p.add_argument("db")

    p = sub.add_parser("explain-item", help="full chain for one receipt item")
    p.add_argument("db")
    p.add_argument("--report", required=True)
    p.add_argument("--item", required=True)
    p.add_argument("--gateway", default="default")

    p = sub.add_parser("summary", help="aggregate statuses with exclusions")
    p.add_argument("db")

    p = sub.add_parser("rebuild", help="recompute all derivations from facts")
    p.add_argument("db")

    p = sub.add_parser("fingerprint", help="candidate fingerprint of an item")
    p.add_argument("db")
    p.add_argument("--report", required=True)
    p.add_argument("--item", required=True)
    p.add_argument("--gateway", default="default")

    p = sub.add_parser(
        "export-case",
        help="export the minimal related evidence for named deliveries / "
             "items into a standalone sub-ledger (a new directory)")
    p.add_argument("source_db")
    p.add_argument("selectors_json",
                   help="path to a JSON document with 'deliveries' and/or "
                        "'items' selector arrays")
    p.add_argument("output_dir", help="new output directory (must not exist)")

    p = sub.add_parser(
        "audit-archive-import",
        help="read-only reconciliation of one convert-archive output "
             "directory against the ledger: per-receipt provenance, "
             "dedup, missing/conflict, quarantines and failed messages")
    p.add_argument("db", metavar="LEDGER")
    p.add_argument("output_dir", metavar="ARCHIVE_OUTPUT_DIR",
                   help="an existing convert-archive output directory "
                        "(dsn.jsonl, quarantine.jsonl, manifest.jsonl)")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            ledger = Ledger.create(args.db)
            ledger.close()
            _dump({"created": args.db})
            return 0
        if args.command == "convert-archive":
            _dump(convert_archive(args.input_dir, args.output_dir,
                                  gateway_id=args.gateway))
            return 0
        if args.command == "audit-archive-import":
            report = audit_archive_import(args.db, args.output_dir)
            _dump(report)
            return report["exit_code"]
        if args.command == "export-case":
            _dump(export_case(args.source_db, _read(args.selectors_json),
                              args.output_dir))
            return 0
        ledger = _open(args.db)
        try:
            return _dispatch(ledger, args)
        finally:
            ledger.close()
    except ArchiveError as exc:
        _dump(exc.to_dict())
        return 2
    except AuditError as exc:
        _dump(exc.to_dict())
        return 2
    except ExportError as exc:
        _dump(exc.to_dict())
        return 2
    except LedgerError as exc:
        _dump(exc.to_dict())
        return 2
    except (KeyError, FileNotFoundError) as exc:
        _dump({"code": "not_found", "message": str(exc)})
        return 3


def _dispatch(ledger, args):
    if args.command == "import-outbound":
        _dump(ledger.import_outbound(
            _read(args.file), source=args.file,
            default_gateway=args.default_gateway))
    elif args.command == "import-dsn":
        _dump(ledger.import_dsn(_read(args.file), source=args.file))
    elif args.command == "import-corrections":
        _dump(ledger.import_corrections(_read(args.file), source=args.file))
    elif args.command == "import-resolutions":
        _dump(ledger.import_resolutions(_read(args.file), source=args.file))
    elif args.command == "status":
        _dump(ledger.delivery_status(args.gateway, args.delivery,
                                     args.recipient))
    elif args.command == "attempt-status":
        _dump(ledger.attempt_status(args.gateway, args.delivery, args.attempt,
                                    args.recipient))
    elif args.command == "timeline":
        _dump(ledger.recipient_timeline(args.recipient, args.gateway))
    elif args.command == "pending":
        _dump(ledger.pending_associations())
    elif args.command == "conflicts":
        _dump(ledger.correction_conflicts())
    elif args.command == "explain-item":
        _dump(ledger.explain_item(args.gateway, args.report, args.item))
    elif args.command == "summary":
        _dump(ledger.explain_summary())
    elif args.command == "rebuild":
        _dump(ledger.rebuild())
    elif args.command == "fingerprint":
        item = ledger.explain_item(args.gateway, args.report, args.item)
        _dump({"candidate_fingerprint": item["candidate_fingerprint"],
               "candidates": item["candidates"]})
    else:  # pragma: no cover - argparse enforces the set
        raise SystemExit(f"unknown command {args.command}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
