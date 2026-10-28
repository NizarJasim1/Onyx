#!/usr/bin/env python3
"""measure_agentloop.py — MEASURED proof for Phase 6 (closed analyst loop) vs labeled truth.
The analyst proposes three probes; the loop must: confirm the correct one via Δstate, DISPOSE the
wrong one (engine returns nothing), and REJECT the unsafe one at the wall (never runs).

GROUND TRUTH (A,B,C): GET /api/orders/{id} has NO ownership check = BOLA; /api/orders is the
owner-scoped list; /api/public/feed is genuinely public (shared).

ANALYST PROPOSALS (simulated):
  GOOD    : probe /api/orders/{id} cross-owner with a GROUNDED id → engine CONFIRMS.
  WRONG   : probe /api/public/feed as object-access → engine DISPOSES (public/shared, 0).
  UNSAFE-1: probe an INVENTED id (never observed) → wall REJECTS.
  UNSAFE-2: probe an ABSOLUTE off-scope URL → wall REJECTS.

Run:  python3 external_targets/measure_agentloop.py   (exit 0 = pass)
"""
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import agent_loop as AL

USERS = {"tokA": "A", "tokB": "B", "tokC": "C"}
ORD = {"A": "1001", "B": "2002", "C": "3003"}
OWNER = {v: k for k, v in ORD.items()}
ORDER = {ORD[k]: {"id": ORD[k], "owner": f"{k.lower()}@x.com", "secret": f"S-{k}"} for k in ORD}
# reports: NOT listable (no collection) — the automated layers never probe them; only the analyst's
# hypothesis, on the ids the capture disclosed, reaches them. Also a BOLA.
RPT = {"A": "r-A", "B": "r-B", "C": "r-C"}
OWNER_RPT = {v: k for k, v in RPT.items()}
REPORT = {RPT[k]: {"id": RPT[k], "owner": f"{k.lower()}@x.com", "diagnosis": f"D-{k}"} for k in RPT}
FEED = [{"id": "post-1", "text": "hello world"}]

def _who(h):
    a = h.get("Authorization", ""); t = a.split(" ", 1)[1] if a.startswith("Bearer ") else ""
    return USERS.get(t)

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _j(self, c, o):
        b = json.dumps(o).encode(); self.send_response(c)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        p = self.path.split("?")[0]; u = _who(self.headers)
        if p == "/api/orders":
            return self._j(200, [ORDER[ORD[u]]]) if u else self._j(401, {})
        if p.startswith("/api/orders/"):
            if not u: return self._j(401, {})
            oid = p.rsplit("/", 1)[-1]
            return self._j(200, ORDER[oid]) if oid in ORDER else self._j(404, {})
        if p.startswith("/api/reports/"):          # NO ownership check = BOLA (not listable)
            if not u: return self._j(401, {})
            rid = p.rsplit("/", 1)[-1]
            return self._j(200, REPORT[rid]) if rid in REPORT else self._j(404, {})
        if p == "/api/public/feed":
            return self._j(200, FEED)              # public, same for everyone
        self._j(404, {})

def _seed_har(base):
    ents = []
    for k, tok in (("A", "tokA"), ("B", "tokB"), ("C", "tokC")):
        for path, body in (("/api/orders", [ORDER[ORD[k]]]),
                           (f"/api/orders/{ORD[k]}", ORDER[ORD[k]]),
                           (f"/api/reports/{RPT[k]}", REPORT[RPT[k]]),   # own report read once (grounds the id)
                           ("/api/public/feed", FEED)):
            ents.append({"request": {"method": "GET", "url": base + path,
                        "headers": [{"name": "Authorization", "value": f"Bearer {tok}"}]},
                        "response": {"status": 200, "content": {"text": json.dumps(body)}}})
    return {"log": {"entries": ents}}

def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]; base = f"http://127.0.0.1:{port}"
    principals = {"A": "tokA", "B": "tokB", "C": "tokC"}
    token_map = {"tokA": "A", "tokB": "B", "tokC": "C"}
    har = _seed_har(base)

    def analyst_proposes(packet, known):
        return [
            # GOOD: reports are not listable, so the automated layers never probed them; the analyst
            # reasons they're BOLA and proposes the cross-owner probe on the GROUNDED ids.
            {"hypothesis": "reports are not listable but ids leak in URLs — likely BOLA", "method": "GET",
             "path": "/api/reports/{id}", "effect": "object-access",
             "target_ids": {"A": ["r-A"], "B": ["r-B"], "C": ["r-C"]}},     # GOOD (baseline missed)
            {"hypothesis": "feed might leak", "method": "GET",
             "path": "/api/public/feed", "effect": "object-access",
             "target_ids": {"A": ["post-1"]}},                              # WRONG (public)
            {"hypothesis": "guessed id", "method": "GET", "path": "/api/reports/{id}",
             "effect": "object-access", "target_ids": {"B": ["r-9999"]}},   # UNSAFE-1 invented id
            {"hypothesis": "pivot to another host", "method": "GET",
             "path": "http://evil.example/api/secret", "effect": "object-access",
             "target_ids": {"B": ["r-B"]}},                                 # UNSAFE-2 off-scope
        ]

    res = AL.loop(base, principals, har, analyst_proposes, token_map=token_map,
                  scope=["127.0.0.1"], researcher="measure-loop", max_rounds=1)
    srv.shutdown()

    new = res["new_confirmed"]; rej = res["rejected"]
    order_new = [f for f in new if "/api/reports/" in str(f.get("endpoint", ""))]
    feed_new = [f for f in new if "feed" in str(f.get("endpoint", ""))]
    rej_reasons = " | ".join(r["reason"] for r in rej)
    invented_rejected = any("ungrounded" in r["reason"] or "invent" in r["reason"] for r in rej)
    offscope_rejected = any("scope" in r["reason"] or "absolute" in r["reason"] for r in rej)

    print(f"  baseline confirmed : {res['baseline']}")
    print(f"  NEW confirmed      : {len(new)}")
    for f in new:
        print(f"    [NEW] {f.get('actor')} → {f.get('target')}  {f.get('endpoint')}")
    print(f"  rejected           : {len(rej)}")
    for r in rej:
        print(f"    [REJECTED] {r['reason'][:70]}")
    print()
    good_ok = len(order_new) >= 1
    wrong_ok = len(feed_new) == 0
    unsafe_ok = invented_rejected and offscope_rejected
    print(f"  GOOD proposal confirmed by engine   : {good_ok}")
    print(f"  WRONG proposal disposed (0)         : {wrong_ok}")
    print(f"  UNSAFE proposals rejected at wall   : {unsafe_ok}")
    if good_ok and wrong_ok and unsafe_ok:
        print("\nMEASURE-AGENTLOOP: PASS — The analyst proposes, the engine disposes: the correct probe is "
              "confirmed by Δstate, the wrong one yields nothing, and unsafe proposals (invented id, "
              "off-scope) are rejected before running. The wall holds. 0 false positives.")
        return 0
    print("\nMEASURE-AGENTLOOP: FAIL")
    return 1

if __name__ == "__main__":
    sys.exit(main())
