#!/usr/bin/env python3
"""
race.py — Phase 5 (part 1): CONCURRENCY / TOCTOU double-spend.

Time-of-check/time-of-use bugs (double-spend, limit bypass, coupon re-use, oversell) are a huge
class on mature targets and are INVISIBLE to sequential testing — they only appear under
concurrency. This module fires K identical operations in parallel against the live target, then
CONFIRMS strictly by a MEASURED CONSERVED-QUANTITY BREACH in the server's own post-state — never
by timing and never by counting 200s.

ZERO-FALSE-POSITIVE by the doubled-signal rule (a FP must fool TWO independent measures):
  A race is confirmed ONLY when, after the parallel burst, BOTH independent server-side conserved
  quantities exceed what a single legitimate operation allows — e.g. a single-use coupon whose
  `times_used` went to 2+ AND whose value effect (balance/discount) was applied 2+ times. A server
  that serialised the burst correctly leaves both at 1 → nothing is confirmed. The proof is Δstate
  (read back from the server), exactly the engine's conservation principle, applied to concurrency.

Safety: mutating, so it requires explicit authorization and runs only on the tester's own
resources; it is the classic self-abuse shape (you race YOUR OWN coupon/withdrawal).
"""
from __future__ import annotations
import json, argparse, sys, os, threading
from urllib.parse import urlparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import onyx_recon as OR


def _get_field(client, url, token, field):
    try:
        r = client.req("GET", url, token=token)
        if not (200 <= r.status_code < 300):
            return None
        body = r.json()
    except Exception:
        return None
    cur = body
    for part in field.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _fire_parallel(client, url, token, body, k):
    """Fire k identical requests as simultaneously as possible; return (successes, statuses)."""
    results = [None] * k
    barrier = threading.Barrier(k)
    def worker(i):
        try:
            barrier.wait(timeout=5)
        except Exception:
            pass
        try:
            r = client.req("POST", url, token=token, json=body)
            results[i] = r.status_code
        except Exception:
            results[i] = 0
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(k)]
    for t in threads: t.start()
    for t in threads: t.join()
    successes = sum(1 for s in results if s and 200 <= s < 300)
    return successes, results


def run_race(base_url, token, op, signals, *, allowed=1, k=10, scope=None, researcher="", verify=True):
    """Fire `op` (a mutating request dict {path, body}) k-way parallel, then read the two
    independent conserved SIGNALS and confirm a breach.

    signals: {"count": {"path","field"}, "value": {"path","field","single"}}
      count.field  → server-side application count of the single-use action (limit=`allowed`)
      value.field  → the value effect (balance/discount total); `single` = its legitimate 1× value
    Returns a verdict dict. Confirmed ⟺ BOTH signals exceed the single-operation bound.
    """
    host = urlparse(base_url).hostname
    cli = OR.Client(scope or [host], researcher=researcher, verify=verify)
    base = base_url.rstrip("/")

    # baseline value (before), to measure the delta effect
    v0 = _get_field(cli, base + signals["value"]["path"], token, signals["value"]["field"]) or 0
    successes, statuses = _fire_parallel(cli, base + op["path"], token, op.get("body"), k)
    count_after = _get_field(cli, base + signals["count"]["path"], token, signals["count"]["field"])
    v1 = _get_field(cli, base + signals["value"]["path"], token, signals["value"]["field"]) or 0

    single = signals["value"].get("single")
    value_applied = (v1 - v0)
    value_breach = (single is not None and single > 0 and value_applied > single * 1.5)
    count_breach = (count_after is not None and count_after > allowed)

    confirmed = bool(count_breach and value_breach)   # BOTH independent signals (doubled gate)
    return {
        "confirmed": confirmed,
        "successes": successes, "parallel": k, "allowed": allowed,
        "count_after": count_after, "count_breach": count_breach,
        "value_before": v0, "value_after": v1, "value_applied": value_applied,
        "value_single": single, "value_breach": value_breach,
        "proof": (f"parallel burst produced {count_after} applications (limit {allowed}) "
                  f"and a {value_applied} value effect (single={single}) — conserved-quantity "
                  f"breach on TWO independent measures" if confirmed else
                  "no conserved-quantity breach (server serialised the burst)"),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="ONYX race prober — TOCTOU double-spend via measured conserved-quantity breach (two independent signals).")
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--token", required=True, help="the tester's OWN token (self-abuse only)")
    ap.add_argument("--spec", required=True, help="JSON: {op, signals, allowed, k}")
    ap.add_argument("--scope"); ap.add_argument("--researcher", default="")
    args = ap.parse_args(argv)
    if not args.authorized:
        sys.exit("Refusing to run: pass --authorized. Race probes MUTATE — self-owned resources only.")
    spec = json.load(open(args.spec))
    scope = [h.strip() for h in args.scope.split(",")] if args.scope else None
    res = run_race(args.base_url, args.token, spec["op"], spec["signals"],
                   allowed=spec.get("allowed", 1), k=spec.get("k", 10),
                   scope=scope, researcher=args.researcher)
    print(f"CONFIRMED={res['confirmed']}  {res['proof']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
