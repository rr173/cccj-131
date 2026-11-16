#!/usr/bin/env python3
"""Write the MTA JSONL acceptance fixtures.

Run: python3 scripts/make_mta_fixtures.py
Everything is deterministic, so re-running rewrites identical bytes.

Files are written into fixtures/mta_events/<case>/<name>.jsonl.  The
bad_lines scenario additionally gets one physically corrupted JSON line, and
the undecodable case is raw non-UTF-8 bytes.
"""

from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests.mta_samples import (  # noqa: E402
    BAD_LINES_CORRUPT,
    BAD_LINES_FILE,
    SCENARIOS,
    UNDECODABLE_BYTES,
    UNDECODABLE_FILE,
)

FIXTURES = os.path.join(ROOT, "fixtures", "mta_events")


def main():
    written = []
    for case, files in sorted(SCENARIOS.items()):
        for name, events in sorted(files.items()):
            path = os.path.join(FIXTURES, case, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            text = "".join(json.dumps(e, ensure_ascii=False) + "\n"
                           for e in events)
            if case == "bad_lines":
                # insert the physically corrupted line in the middle
                lines = text.splitlines(keepends=True)
                lines.insert(4, BAD_LINES_CORRUPT)
                text = "".join(lines)
            with open(path, "wb") as handle:
                handle.write(text.encode("utf-8"))
            written.append(path)
    undecodable = os.path.join(FIXTURES, "undecodable", UNDECODABLE_FILE)
    os.makedirs(os.path.dirname(undecodable), exist_ok=True)
    with open(undecodable, "wb") as handle:
        handle.write(UNDECODABLE_BYTES)
    written.append(undecodable)
    for path in written:
        print(os.path.relpath(path, ROOT))
    print(f"{len(written)} fixture files written")


if __name__ == "__main__":
    main()
