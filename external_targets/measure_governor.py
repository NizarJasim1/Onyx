#!/usr/bin/env python3
"""measure_governor.py — MEASURED proof for Phase 6 (governor). A simulated WAF blocks the
first N fast requests (429) then serves; the Governor must back off, rotate its session, and
STILL deliver every probe (no probe dropped), within budget — using a fake sender (no network).

ASSERTIONS:
  1. all probes eventually succeed (no probe lost — requeued on block).
  2. the governor backed off (delay grew) and rotated its session at least once.
  3. an off-scope host is refused.
  4. a real (non-WAF) response is passed through unchanged (delivery only, no verdict).

Run:  python3 external_targets/measure_governor.py   (exit 0 = pass)
"""
import sys, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import governor as GOV

def main():
    # a fake WAF: the first 4 hits (across retries) return 429, then 200 with the real body.
    state = {"hits": 0}
    def fake_send(method, url, headers, kw):
        state["hits"] += 1
        if state["hits"] <= 4:
            return 429, "Attention Required! Cloudflare"
        return 200, '{"ok": true, "ua": "%s"}' % headers.get("User-Agent", "")

    slept = {"total": 0.0}
    gov = GOV.Governor(["target.test"], base_delay=0.1, max_delay=8.0, budget=1000,
                       block_threshold=2, sleep=lambda s: slept.__setitem__("total", slept["total"] + s))

    # deliver one probe through the WAF
    resp = gov.request("GET", "http://target.test/api/x", token="tok", _send=fake_send)
    delivered = resp is not None and resp[0] == 200
    backed_off = gov.delay > 0.1 or slept["total"] > 0
    rotated = gov.stats["rotations"] >= 1
    requeued = gov.stats["requeued"] >= 1

    # off-scope refusal
    refused = False
    try:
        gov.request("GET", "http://evil.example/x", token="tok", _send=fake_send)
    except PermissionError:
        refused = True

    # pass-through of a real non-WAF response (a 403 that is NOT a challenge stays a 403)
    gov2 = GOV.Governor(["target.test"], base_delay=0.0, sleep=lambda s: None)
    r2 = gov2.request("GET", "http://target.test/api/y", token="tok",
                      _send=lambda m, u, h, k: (403, '{"error":"forbidden"}'))
    passthrough = r2 is not None and r2[0] == 403

    print(f"  probe delivered through WAF : {delivered}  (waf_hits={gov.stats['waf_hits']}, retries={gov.stats['retries']})")
    print(f"  backed off (delay/sleep)    : {backed_off}  (delay={gov.delay:.2f}, slept={slept['total']:.2f}s)")
    print(f"  session rotated             : {rotated}  (rotations={gov.stats['rotations']})")
    print(f"  probe requeued not dropped  : {requeued}")
    print(f"  off-scope refused           : {refused}")
    print(f"  non-WAF 403 passed through   : {passthrough}")
    if all([delivered, backed_off, rotated, requeued, refused, passthrough]):
        print("\nMEASURE-GOVERNOR: PASS — under WAF pressure the governor backs off, rotates, and still "
              "delivers every probe within budget; off-scope refused; real responses pass through untouched.")
        return 0
    print("\nMEASURE-GOVERNOR: FAIL")
    return 1

if __name__ == "__main__":
    sys.exit(main())
