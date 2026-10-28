#!/usr/bin/env python3
"""measure_payment.py — MEASURED answer to HANDOFF §5:
   does the ENGINE confirm a payment bypass (effect=PAYMENT, paid < due)?

We do NOT assume. We stand up a labeled localhost mock with three checkout
endpoints and drive the PROVEN path (serve.run_engagement) — engine untouched.

GROUND TRUTH:
  * TRUE  : /api/checkout_true   accepts underpayment; success body exposes
            amount_due=100, amount_paid=10  -> real value-conservation breach.
            EXPECT: engine CONFIRMS (PaymentLaw fires).
  * SAFE  : /api/checkout_safe   server recomputes; success body amount_due=100,
            amount_paid=100.               -> nothing to prove.
            EXPECT: engine PASSES (no finding).
  * HIDDEN: /api/checkout_hidden accepts underpayment but success body hides the
            amounts ({"status":"ok"}).     -> real breach, but UNPROVABLE from Δstate.
            EXPECT: engine ABSTAINS (no finding, no FP) -> stays a the analyst hypothesis.

PASS = TRUE confirmed  AND  SAFE not flagged  AND  HIDDEN not flagged (0 FP).
Run:  python3 external_targets/measure_payment.py   (exit 0 = pass)
"""
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from authpath import serve
from authpath.models import Principal
from authpath.transport import HTTPTarget
from authpath.scope_guard import ScopeConfig

TOK = {"tokA": "A"}
def _who(h):
    a = h.get("Authorization", ""); t = a.split(" ", 1)[1] if a.startswith("Bearer ") else ""
    return TOK.get(t)

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
        p = self.path.split("?")[0]; b = self._b(); u = _who(self.headers)
        if not u: return self._j(401, {})
        # TRUE bypass: server trusts client amount; success reveals paid<due.
        if p == "/api/checkout_true":
            paid = b.get("amount_paid", 100)
            return self._j(200, {"status": "paid", "order": "o-A",
                                 "amount_due": 100, "amount_paid": paid})
        # SAFE: server recomputes — always charges the real due; paid==due.
        if p == "/api/checkout_safe":
            return self._j(200, {"status": "paid", "order": "o-A",
                                 "amount_due": 100, "amount_paid": 100})
        # HIDDEN: underpayment accepted but the amounts are not in the response.
        if p == "/api/checkout_hidden":
            return self._j(200, {"status": "ok", "order": "o-A"})
        return self._j(404, {})

def _run(cfg_ep):
    port = _srv.server_address[1]
    base = f"http://127.0.0.1:{port}"
    host = "127.0.0.1"
    scope = ScopeConfig(allowed_hosts=[host], automation_permitted=True,
                        target_provenance="third_party", dry_run=False)
    target = HTTPTarget(base, scope=scope)
    principals = {"A": Principal("A", "A", auth={"Authorization": "Bearer tokA"})}
    contract = {f"{cfg_ep['method']} {cfg_ep['path']}":
                {"effect": cfg_ep["effect"], "critical_params": list((cfg_ep.get("body") or {}).keys())}}
    eng, _ = serve.run_engagement(
        target, principals, host, dry_run=False,
        test_resources=["1"], endpoints=[cfg_ep], contract=contract,
        researcher="measure@onyx", engagement_id="MEASURE-PAY")
    from payment_guard import filter_payment_findings
    kept, dropped = filter_payment_findings(eng.findings, eng.capture)
    return eng.findings, kept, dropped

def main():
    global _srv
    _srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=_srv.serve_forever, daemon=True).start()

    cases = {
        "TRUE":   {"method": "POST", "path": "/api/checkout_true",   "effect": "PAYMENT",
                   "ids": {"A": ["1"]}, "body": {"amount_paid": 10}},
        "SAFE":   {"method": "POST", "path": "/api/checkout_safe",   "effect": "PAYMENT",
                   "ids": {"A": ["1"]}, "body": {"amount_paid": 10}},
        "HIDDEN": {"method": "POST", "path": "/api/checkout_hidden", "effect": "PAYMENT",
                   "ids": {"A": ["1"]}, "body": {"amount_paid": 10}},
    }
    print("  case    endpoint                  raw(engine)  gated(+money-gate)")
    gated = {}
    for label, ep in cases.items():
        raw, kept, dropped = _run(ep)
        gated[label] = kept
        rtag = "CONFIRM" if raw else "abstain"
        gtag = "CONFIRM" if kept else "abstain/drop"
        print(f"  {label:6s}  {ep['path']:24s}  {len(raw)} {rtag:8s}    {len(kept)} {gtag}")
        for _, reason in dropped:
            print(f"           gate DROP: {reason}")
        for fi in kept:
            print(f"           gate KEEP: {getattr(fi,'impact','?')}")

    _srv.shutdown()
    # Ground-truth assertions on the GATED (shippable) output:
    ok_true   = len(gated["TRUE"])   >= 1     # real bypass must survive both gates
    ok_safe   = len(gated["SAFE"])   == 0     # safe server must be dropped (FP eliminated)
    ok_hidden = len(gated["HIDDEN"]) == 0     # hidden amounts -> abstain (unprovable)
    print()
    print(f"  TRUE   confirmed (kept)  : {ok_true}")
    print(f"  SAFE   dropped (no FP)   : {ok_safe}")
    print(f"  HIDDEN abstained         : {ok_hidden}")
    if ok_true and ok_safe and ok_hidden:
        print("\nMEASURE-PAYMENT: PASS — with the independent money gate, ONYX CONFIRMS a real "
              "payment bypass from the server's own Δstate, DROPS the safe server (client "
              "amount corrected), and ABSTAINS when amounts are hidden. 0 false positives.")
        return 0
    print("\nMEASURE-PAYMENT: FAIL")
    return 1

if __name__ == "__main__":
    sys.exit(main())
