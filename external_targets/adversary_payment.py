#!/usr/bin/env python3
"""adversary_payment.py — adversarial self-critique of payment_guard.

Two attacks on the gate itself:
  A) MIXED SCAN: one engagement probes a TRUE endpoint AND a SAFE endpoint together.
     The per-finding exchange match must not cross-contaminate: TRUE kept, SAFE dropped.
  B) NESTED CURRENCY (Adyen shape): server response nests {"amount":{"value..,currency..}}.
     due=100 USD, paid=10 USD in nested form -> gate must KEEP (parser handles nesting).
     control: due=100 USD, paid=100 USD nested -> gate must DROP.
"""
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
from authpath import serve
from authpath.models import Principal
from authpath.transport import HTTPTarget
from authpath.scope_guard import ScopeConfig
from payment_guard import filter_payment_findings

def _who(h):
    a = h.get("Authorization", ""); t = a.split(" ", 1)[1] if a.startswith("Bearer ") else ""
    return {"tokA": "A"}.get(t)

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
        if not _who(self.headers): return self._j(401, {})
        if p == "/api/true":                 # bypass: response echoes low paid
            return self._j(200, {"status":"paid","amount_due":100,"amount_paid":b.get("amount_paid",100)})
        if p == "/api/safe":                 # safe: response shows corrected paid==due
            return self._j(200, {"status":"paid","amount_due":100,"amount_paid":100})
        if p == "/api/nested_true":          # nested Adyen shape, real underpayment
            return self._j(200, {"status":"paid",
                                 "amount_due":{"value":100,"currency":"USD"},
                                 "amount_paid":{"value":10,"currency":"USD"}})
        if p == "/api/nested_safe":          # nested shape, corrected
            return self._j(200, {"status":"paid",
                                 "amount_due":{"value":100,"currency":"USD"},
                                 "amount_paid":{"value":100,"currency":"USD"}})
        return self._j(404, {})

def _scan(endpoints):
    port = _srv.server_address[1]; host = "127.0.0.1"
    tgt = HTTPTarget(f"http://127.0.0.1:{port}", scope=ScopeConfig(
        allowed_hosts=[host], automation_permitted=True,
        target_provenance="third_party", dry_run=False))
    pr = {"A": Principal("A","A",auth={"Authorization":"Bearer tokA"})}
    contract = {f"{e['method']} {e['path']}":{"effect":"PAYMENT",
                "critical_params":list((e.get("body") or {}).keys())} for e in endpoints}
    eng,_ = serve.run_engagement(tgt, pr, host, dry_run=False, test_resources=["1"],
                                 endpoints=endpoints, contract=contract, engagement_id="ADV")
    kept, dropped = filter_payment_findings(eng.findings, eng.capture)
    kept_paths = set()
    for f in kept:
        for s in (getattr(f.poc,"steps",[]) or []):
            for v in ("POST","PUT","PATCH","DELETE"):
                if v in s and "/api/" in s:
                    kept_paths.add("/api/"+s.split("/api/",1)[1].split()[0].split('"')[0])
    return len(eng.findings), kept, dropped, kept_paths

def main():
    global _srv
    _srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=_srv.serve_forever, daemon=True).start()
    ok = True

    # ---- Attack A: mixed scan, true + safe together ----
    eps = [
        {"method":"POST","path":"/api/true","effect":"PAYMENT","ids":{"A":["1"]},"body":{"amount_paid":10}},
        {"method":"POST","path":"/api/safe","effect":"PAYMENT","ids":{"A":["1"]},"body":{"amount_paid":10}},
    ]
    raw, kept, dropped, kept_paths = _scan(eps)
    a_ok = (len(kept) == 1) and any("/api/true" in p for p in kept_paths)
    print(f"A) MIXED SCAN     raw={raw}  kept={len(kept)}  kept_paths={sorted(kept_paths)}")
    for _, r in dropped: print(f"     DROP: {r}")
    print(f"   -> {'PASS' if a_ok else 'FAIL'} (expect exactly 1 kept = /api/true)\n")
    ok &= a_ok

    # ---- Attack B: nested-currency Adyen shape ----
    raw_t, kept_t, drop_t, _ = _scan([{"method":"POST","path":"/api/nested_true","effect":"PAYMENT","ids":{"A":["1"]},"body":{"amount_paid":{"value":10,"currency":"USD"}}}])
    raw_s, kept_s, drop_s, _ = _scan([{"method":"POST","path":"/api/nested_safe","effect":"PAYMENT","ids":{"A":["1"]},"body":{"amount_paid":{"value":100,"currency":"USD"}}}])
    b_ok = (len(kept_t) == 1) and (len(kept_s) == 0)
    print(f"B) NESTED true    raw={raw_t}  kept={len(kept_t)} (expect 1)")
    for _, r in drop_t: print(f"     DROP: {r}")
    print(f"   NESTED safe    raw={raw_s}  kept={len(kept_s)} (expect 0)")
    for _, r in drop_s: print(f"     DROP: {r}")
    print(f"   -> {'PASS' if b_ok else 'FAIL'}\n")
    ok &= b_ok

    _srv.shutdown()
    print("ADVERSARY-PAYMENT:", "PASS — gate resists cross-contamination and parses nested amounts." if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
