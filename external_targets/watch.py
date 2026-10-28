#!/usr/bin/env python3
"""
watch.py — Phase 6 (part 3): CONTINUOUS DIFF MODE.

A giant target changes weekly: new endpoints ship, old gates regress. Watch turns ONYX from a
one-shot scan into a monitor: it diffs a fresh dissection against a stored baseline and alerts
ONLY on what is NEW — a newly appeared surface, or (the one that matters) a newly CONFIRMED
vulnerability. Nothing here judges: it diffs the Conductor's own outputs, so every alert is
already Δstate-proven and deduped.
"""
from __future__ import annotations
import json, argparse, sys, os
from urllib.parse import urlparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _confirmed_keys(packet):
    return {(r["effect"], r["actor"], r["target"]) for r in packet.get("confirmed", [])}


def _endpoints(packet):
    al = packet.get("anatomy", {}).get("layer1", {})
    eps = set()
    for t in al.get("object_types", []):
        eps.add(t.get("type", ""))
    for r in packet.get("confirmed", []):
        eps.add(r.get("path", ""))
    return {e for e in eps if e}


def diff(baseline_packet, new_packet):
    """Return {new_confirmed:[...], resolved:[...], new_endpoints:[...]}. new_confirmed is the
    alert that matters (a freshly proven bug); resolved = a baseline finding no longer present."""
    b_keys = _confirmed_keys(baseline_packet)
    n_keys = _confirmed_keys(new_packet)
    new_map = {(r["effect"], r["actor"], r["target"]): r for r in new_packet.get("confirmed", [])}
    base_map = {(r["effect"], r["actor"], r["target"]): r for r in baseline_packet.get("confirmed", [])}
    new_confirmed = [new_map[k] for k in (n_keys - b_keys)]
    resolved = [base_map[k] for k in (b_keys - n_keys)]
    new_endpoints = sorted(_endpoints(new_packet) - _endpoints(baseline_packet))
    return {"new_confirmed": new_confirmed, "resolved": resolved, "new_endpoints": new_endpoints}


def watch_once(base_url, principals, har, *, baseline_path=None, token_map=None, scope=None,
               researcher=""):
    """Run one dissection, diff against the stored baseline (if any), persist the new baseline,
    and return the diff. First run establishes the baseline (everything is 'new')."""
    import conductor as COND
    packet = COND.run(base_url, principals, har=har, token_map=token_map, scope=scope, researcher=researcher)
    baseline = {}
    if baseline_path and os.path.exists(baseline_path):
        try:
            baseline = json.load(open(baseline_path))
        except Exception:
            baseline = {}
    d = diff(baseline, packet)
    if baseline_path:
        json.dump({"confirmed": packet["confirmed"], "anatomy": packet["anatomy"]},
                  open(baseline_path, "w"), default=list)
    return d, packet


def main(argv=None):
    ap = argparse.ArgumentParser(description="ONYX watch — continuous diff; alert on newly confirmed findings.")
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--base-url", required=True); ap.add_argument("--har", required=True)
    ap.add_argument("--baseline", required=True, help="path to the stored baseline JSON")
    ap.add_argument("--scope"); ap.add_argument("--principal", action="append", default=[])
    ap.add_argument("--tokens"); ap.add_argument("--researcher", default="")
    args = ap.parse_args(argv)
    if not args.authorized:
        sys.exit("Refusing to run: pass --authorized.")
    principals = dict(s.split(":", 1) for s in args.principal)
    har = json.load(open(args.har))
    token_map = json.loads(args.tokens) if args.tokens else {t: p for p, t in principals.items()}
    scope = [h.strip() for h in args.scope.split(",")] if args.scope else None
    d, _ = watch_once(args.base_url, principals, har, baseline_path=args.baseline,
                      token_map=token_map, scope=scope, researcher=args.researcher)
    print(f"NEW confirmed={len(d['new_confirmed'])}  resolved={len(d['resolved'])}  new_endpoints={len(d['new_endpoints'])}")
    for r in d["new_confirmed"]:
        print(f"  [ALERT new bug] {r['effect']} {r['endpoint']} {r['actor']}→{r['target']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
