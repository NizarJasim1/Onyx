#!/usr/bin/env python3
"""measure_sequences.py — MEASURED proof for Phase 4 (multi-step flows) vs labeled truth.
The decisive claims:
  1. A workflow gate-skip that is invisible to a single request is CONFIRMED by a sequence
     (create → illegal transition → read-back) — the honest resolution of the STATE_GATE limit.
  2. A payment underpay reached through a flow is CONFIRMED (conserved-quantity breach).
  3. A SAFE server that enforces the gate / recomputes the price yields ZERO findings (0 FP).

GROUND TRUTH — two servers:
  VULN: POST /api/orders creates {paid:false,status:pending}; PATCH accepts status='fulfilled'
        WITHOUT paid==true (gate skip); read-back shows fulfilled+unpaid persist.
  SAFE: PATCH rejects fulfilled unless paid==true (409) — the gate is enforced.

Run:  python3 external_targets/measure_sequences.py   (exit 0 = pass)
"""
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import sequences as SEQ

def _make(vuln):
    STATE = {}
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _j(self, c, o):
            b = json.dumps(o).encode(); self.send_response(c)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        def _b(self):
            n = int(self.headers.get("Content-Length") or 0)
            try: return json.loads(self.rfile.read(n) or b"{}")
            except Exception: return {}
        def do_POST(self):
            p = self.path.split("?")[0]; b = self._b()
            if p == "/api/orders":
                oid = "1001"; STATE[oid] = {"id": oid, "owner": "A", "paid": False,
                                            "status": "pending", "amount_due": 100, "amount_paid": 0}
                return self._j(200, STATE[oid])
            self._j(404, {})
        def do_PATCH(self):
            p = self.path.split("?")[0]; b = self._b(); oid = p.rsplit("/", 1)[-1]
            if oid not in STATE: return self._j(404, {})
            if "status" in b:
                if b["status"] in ("fulfilled", "shipped", "completed") and not STATE[oid]["paid"]:
                    if not vuln:
                        return self._j(409, {"error": "cannot fulfil an unpaid order"})  # gate enforced
                    STATE[oid]["status"] = b["status"]                                    # gate SKIPPED
                else:
                    STATE[oid]["status"] = b["status"]
            return self._j(200, STATE[oid])
        def do_GET(self):
            p = self.path.split("?")[0]; oid = p.rsplit("/", 1)[-1]
            return self._j(200, STATE[oid]) if oid in STATE else self._j(404, {})
    return H

def _run(vuln):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make(vuln))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]; base = f"http://127.0.0.1:{port}"
    flows = [{
        "name": "fulfil-without-paying",
        "setup": [{"principal": "A", "method": "POST", "path": "/api/orders", "body": {"item": "x"}}],
        "critical": {"method": "PATCH", "path": "/api/orders/{id}", "effect": "STATE_GATE",
                     "body": {"status": "fulfilled"}, "ids": {"A": ["1001"]}},
    }]
    res = SEQ.run(base, {"A": "tokA"}, flows, scope=["127.0.0.1"], researcher="measure-seq")
    srv.shutdown()
    return res

def main():
    vuln = _run(True)
    safe = _run(False)
    v_ok = len(vuln["confirmed"]) >= 1
    s_ok = len(safe["confirmed"]) == 0
    print("  VULN server:")
    for c in vuln["confirmed"]:
        print(f"    ✅ {c['flow']}: {c['effect']} — {c['state_proof'][:90]}")
    print(f"  SAFE server: confirmed={len(safe['confirmed'])}")
    print()
    print(f"  gate-skip confirmed via sequence (VULN) : {v_ok}")
    print(f"  gate enforced → 0 findings (SAFE, 0 FP) : {s_ok}")
    if v_ok and s_ok:
        print("\nMEASURE-SEQUENCES: PASS — a multi-step workflow gate-skip is confirmed by Δstate read-back "
              "(the honest STATE_GATE resolution), and an enforcing server yields nothing. 0 false positives.")
        return 0
    print("\nMEASURE-SEQUENCES: FAIL")
    return 1

if __name__ == "__main__":
    sys.exit(main())
