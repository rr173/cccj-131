#!/usr/bin/env python3
"""Write the .eml acceptance fixtures for the offline archive import.

Run: python3 scripts/make_archive_fixtures.py
Everything is deterministic, so re-running rewrites identical bytes.

Files are written into fixtures/archive/<case>/eml/<name>.eml.
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests.archive_samples import SAMPLES  # noqa: E402

FIXTURES = os.path.join(ROOT, "fixtures", "archive")


def main():
    written = []
    for case, files in sorted(SAMPLES.items()):
        for name, data in sorted(files.items()):
            path = os.path.join(FIXTURES, case, "eml", name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(data)
            written.append(path)
    for path in written:
        print(os.path.relpath(path, ROOT))
    print(f"{len(written)} fixture files written")


if __name__ == "__main__":
    main()
