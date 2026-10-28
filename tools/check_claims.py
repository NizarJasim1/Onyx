#!/usr/bin/env python3
"""CI gate: every judge-facing claim file must pass the RL20 no-bare-metrics check
(every metric carries an evidence tier). Exits non-zero on the first violation."""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from authpath.evidence import assert_no_bare_metrics

FILES = ["docs/CLAIMS.md", "README.md", "docs/overview.md"]

def main() -> int:
    bad = 0
    for rel in FILES:
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            continue
        try:
            with open(p, encoding="utf-8") as fh:
                assert_no_bare_metrics(fh.read())
            print(f"  [ok] {rel} is tier-clean")
        except AssertionError as e:
            bad += 1; print(f"  [VIOLATION] {rel}: {e}")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
