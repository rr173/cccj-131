"""Guard rail: the reference implementation must stay independent.

The reference is the oracle for the incremental engine, so it may not import or
call the engine, the matcher, the chain analyser, the fingerprint function or
the merge/status logic.  It re-implements all of that from raw SELECTs.
"""

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

FORBIDDEN_MODULES = {
    "receipt_ledger.engine",
    "receipt_ledger.matching",
    "receipt_ledger.chains",
    "receipt_ledger.fingerprint",
    "receipt_ledger.ingest",
    "receipt_ledger.addr",
    "receipt_ledger",
}
FORBIDDEN_NAMES = [
    "candidate_rows", "fingerprint", "analyse", "ChainInfo", "Ledger",
    "ImportOutcome", "canonical_recipient", "recipient_sig", "candidate_fingerprint",
]


def check_source(path):
    with open(path, encoding="utf-8") as handle:
        source = handle.read()
    problems = []
    for match in re.finditer(r"^\s*(?:from|import)\s+([\w.]+)", source,
                             re.MULTILINE):
        module = match.group(1)
        if module in FORBIDDEN_MODULES or module.split(".")[0] == \
                "receipt_ledger":
            problems.append(f"imports forbidden module {module!r}")
    for match in re.finditer(r"\b(?:receipt_ledger|engine|matching|chains)\."
                             r"(\w+)\s*\(", source):
        problems.append(f"calls {match.group(0)}")
    for name in FORBIDDEN_NAMES:
        # calling a formal function by name, not merely mentioning it
        if re.search(r"\b%s\s*\(" % re.escape(name), source):
            problems.append(f"calls forbidden function {name}()")
    return source, problems


def main():
    path = os.path.join(ROOT, "receipt_ledger", "reference.py")
    source, problems = check_source(path)
    # the only permitted imports are the standard library
    stdlib = {"__future__", "hashlib", "json"}
    for match in re.finditer(r"^\s*import\s+([\w.]+)", source,
                             re.MULTILINE):
        if match.group(1) not in stdlib:
            problems.append(f"non-stdlib import {match.group(1)!r}")
    if problems:
        for problem in problems:
            print("FAIL:", problem)
        return 1
    print("reference independence: OK "
          "(imports only hashlib/json; no engine/matcher/chain calls)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
