#!/usr/bin/env python3
"""measure_race.py — MEASURED proof for Phase 5 (race/TOCTOU) vs labeled truth.
A single-use coupon is redeemed under a parallel burst. A VULN (non-atomic) server applies it
many times; a SAFE (atomic) server applies it once. Confirmation is a conserved-quantity breach
on TWO independent signals (times_used AND balance effect) — not timing, not 200-count.

ASSERTIONS:
  1. VULN: race confirmed (times_used>1 AND balance credited >1×).
  2. SAFE: race NOT confirmed (both signals stay at 1) — 0 FP.

Run:  python3 external_targets/measure_race.py   (exit 0 = pass)
"""
import json, sys, threading, os, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import race as RACE

def _make(atomic):
    lock = threading.Lock()
    STATE = {"times_used": 0, "balance": 0, "discount": 10}
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _j(self, c, o):
            b = json.dumps(o).encode(); self.send_response(c)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        def do_POST(self):
            if self.path.split("?")[0] != "/redeem":
                return self._j(404, {})
            n = int(self.headers.get("Content-Length") or 0); self.rfile.read(n)
            if atomic:
                with lock:                                  # TOCTOU-safe
                    if STATE["times_used"] >= 1:
                        return self._j(409, {"error": "already redeemed"})
                    STATE["times_used"] += 1; STATE["balance"] += STATE["discount"]
                    return self._j(200, {"applied": True})
            else:
                used = STATE["times_used"]                  # check
                time.sleep(0.02)                            # window
                if used >= 1:
                    return self._j(409, {"error": "already redeemed"})
                STATE["times_used"] += 1; STATE["balance"] += STATE["discount"]   # use
                return self._j(200, {"applied": True})
        def do_GET(self):
            p = self.path.split("?")[0]
            if p == "/coupon":
                return self._j(200, {"times_used": STATE["times_used"], "limit": 1})
            if p == "/account":
                return self._j(200, {"balance": STATE["balance"]})
            self._j(404, {})
    return H

def _run(atomic):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make(atomic))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]; base = f"http://127.0.0.1:{port}"
    spec = {
        "op": {"path": "/redeem", "body": {"coupon": "SAVE10"}},
        "signals": {"count": {"path": "/coupon", "field": "times_used"},
                    "value": {"path": "/account", "field": "balance", "single": 10}},
        "allowed": 1, "k": 12,
    }
    res = RACE.run_race(base, "tokA", spec["op"], spec["signals"],
                        allowed=spec["allowed"], k=spec["k"], scope=["127.0.0.1"], researcher="measure-race")
    srv.shutdown()
    return res

def main():
    vuln = _run(atomic=False)
    safe = _run(atomic=True)
    print(f"  VULN: confirmed={vuln['confirmed']}  times_used={vuln['count_after']} "
          f"balance_effect={vuln['value_applied']} (single={vuln['value_single']})  successes={vuln['successes']}")
    print(f"        {vuln['proof']}")
    print(f"  SAFE: confirmed={safe['confirmed']}  times_used={safe['count_after']} "
          f"balance_effect={safe['value_applied']}  successes={safe['successes']}")
    v_ok = vuln["confirmed"] is True
    s_ok = safe["confirmed"] is False
    print()
    print(f"  double-spend confirmed (VULN)      : {v_ok}")
    print(f"  atomic server clean (SAFE, 0 FP)   : {s_ok}")
    if v_ok and s_ok:
        print("\nMEASURE-RACE: PASS — a parallel burst is confirmed ONLY by a measured conserved-quantity "
              "breach on two independent signals; an atomic server is clean. 0 false positives.")
        return 0
    print("\nMEASURE-RACE: FAIL")
    return 1

if __name__ == "__main__":
    sys.exit(main())
