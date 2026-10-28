#!/usr/bin/env python3
"""verify.py (AHP-Ω) — the trust-no-one bundle verifier. ANYONE runs this on a
prove.py bundle; it re-derives the result from the raw evidence and reports whether
the runner's claims hold. No trust in the runner, the author, or the host."""
import argparse, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.dirname(HERE)); sys.path.insert(0, HERE)
import pcm
from seal import verify as seal_verify

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle", nargs="?", default=os.path.join(HERE, "bundle.json"))
    a = ap.parse_args()
    bundle = json.load(open(a.bundle))
    sealv = lambda s: bool(s) and s == bundle.get("oracle_seal") and seal_verify()
    v = pcm.verify_bundle(bundle, sealv)
    print(f"VERDICT: {'VERIFIED (trust no one)' if v['verified'] else 'NOT VERIFIED'}")
    for k, val in v["checks"].items():
        if isinstance(val, bool):
            print(f"  {'PASS' if val else 'FAIL'}  {k}")
    print(f"  reproduced findings: {v['checks'].get('reproduced_findings')}")
    sys.exit(0 if v["verified"] else 1)

if __name__ == "__main__":
    main()
