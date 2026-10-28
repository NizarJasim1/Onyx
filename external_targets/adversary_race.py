#!/usr/bin/env python3
"""adversary_race.py — adversarial self-critique of Phase 5 (race). Two traps; each 0-confirm.

  A) IDEMPOTENT 200s: the server returns 200 to ALL k parallel requests (looks like success!)
     but APPLIES the coupon exactly once (times_used=1, balance +1×). Counting 200s would cry
     wolf; the conserved-quantity read-back must keep it clean.
  B) SLOW BUT CORRECT: the server is slow (latency) yet serialises correctly — one application.
     Latency/timing is not a vulnerability; only a conserved breach is.
"""
import json, sys, threading, os, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import race as RACE

def _make(mode):
    lock = threading.Lock()
    STATE = {"times_used": 0, "balance": 0, "discount": 10}
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _j(self, c, o):
            b = json.dumps(o).encode(); self.send_response(c)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        def do_POST(self):
            if self.path.split("?")[0] != "/redeem": return self._j(404, {})
            n = int(self.headers.get("Content-Length") or 0); self.rfile.read(n)
            if mode == "idempotent":
                with lock:
                    if STATE["times_used"] == 0:
                        STATE["times_used"] = 1; STATE["balance"] += STATE["discount"]
                # ALL callers get 200 OK, but the effect applied exactly once
                return self._j(200, {"applied": True, "idempotent": True})
            if mode == "slow":
                time.sleep(0.03)
                with lock:                                   # correct serialisation, just slow
                    if STATE["times_used"] >= 1:
                        return self._j(409, {"error": "already"})
                    STATE["times_used"] += 1; STATE["balance"] += STATE["discount"]
                    return self._j(200, {"applied": True})
            return self._j(404, {})
        def do_GET(self):
            p = self.path.split("?")[0]
            if p == "/coupon": return self._j(200, {"times_used": STATE["times_used"], "limit": 1})
            if p == "/account": return self._j(200, {"balance": STATE["balance"]})
            self._j(404, {})
    return H

def _run(mode):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]; base = f"http://127.0.0.1:{port}"
    res = RACE.run_race(base, "tokA",
                        {"path": "/redeem", "body": {"coupon": "SAVE10"}},
                        {"count": {"path": "/coupon", "field": "times_used"},
                         "value": {"path": "/account", "field": "balance", "single": 10}},
                        allowed=1, k=12, scope=["127.0.0.1"], researcher="adv-race")
    srv.shutdown()
    return res

def main():
    ok = True
    a = _run("idempotent")
    print(f"A) idempotent 200s : confirmed={a['confirmed']} successes={a['successes']} "
          f"times_used={a['count_after']} value={a['value_applied']} -> {'PASS' if not a['confirmed'] else 'FAIL'}")
    ok &= not a["confirmed"]
    b = _run("slow")
    print(f"B) slow but correct: confirmed={b['confirmed']} times_used={b['count_after']} "
          f"value={b['value_applied']} -> {'PASS' if not b['confirmed'] else 'FAIL'}")
    ok &= not b["confirmed"]
    print("\nADVERSARY-RACE:", "PASS — idempotent 200-floods and mere latency confirm nothing; only a "
          "measured conserved-quantity breach does. 0 false positives." if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
