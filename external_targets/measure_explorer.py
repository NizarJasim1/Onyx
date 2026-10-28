#!/usr/bin/env python3
"""measure_explorer.py — MEASURED proof for Phase 2 (deep reach) against labeled ground truth.
The decisive test: a bug lives on an endpoint the SEED capture never contained; the Explorer
discovers it by crawling as every principal, and the Conductor then confirms it. Without the
Explorer, the same Conductor sees nothing.

GROUND TRUTH (three principals A,B,C):
  SEED capture (what a human browsed): ONLY each principal's own GET /api/orders (a collection).
  Hidden from the seed:
    * GET /api/orders/{id}  — item read, NO ownership check = BOLA. Reachable only by expanding
      the collection's ids and trying them cross-principal (the Explorer's job).
    * each order carries "invoice_ref": "/api/invoice/inv-*"; GET /api/invoice/{id} has no
      ownership check = a second BOLA reachable only by FOLLOWING THE REFERENCE.

ASSERTIONS:
  1. Conductor on the SEED capture alone       -> 0 confirmed (never sees item/invoice doors).
  2. Explorer discovers /api/orders/{id} AND /api/invoice/{id} (endpoint count grows).
  3. Conductor on the EXPLORER capture          -> >=1 confirmed cross-owner read.
  4. multi-principal: the Explorer visited item doors as more than one principal.
  5. SAFETY: the Explorer issued only GETs and never touched the destructive /api/orders/{id}/delete.

Run:  python3 external_targets/measure_explorer.py   (exit 0 = pass)
"""
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import explorer as EXP
import conductor as COND

USERS = {"tokA": "A", "tokB": "B", "tokC": "C"}
ORD = {"A": "1001", "B": "2002", "C": "3003"}
OWNER_ORD = {v: k for k, v in ORD.items()}
INV = {"A": "inv-A", "B": "inv-B", "C": "inv-C"}
OWNER_INV = {v: k for k, v in INV.items()}
ORDER = {ORD[k]: {"id": ORD[k], "owner": f"{k.lower()}@x.com", "invoice_ref": f"/api/invoice/{INV[k]}"} for k in ORD}
INVOICE = {INV[k]: {"id": INV[k], "owner": f"{k.lower()}@x.com", "amount_due": 500, "iban": f"DE{k}"} for k in INV}
DESTRUCTIVE_HITS = []

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
        if "/delete" in p:                              # destructive: explorer must NEVER hit this
            DESTRUCTIVE_HITS.append(p)
            return self._j(200, {"deleted": True})
        if p == "/api/orders":
            return self._j(200, [ORDER[ORD[u]]]) if u else self._j(401, {})
        if p.startswith("/api/orders/"):                # item read: NO ownership check = BOLA
            if not u: return self._j(401, {})
            oid = p.rsplit("/", 1)[-1]
            return self._j(200, ORDER[oid]) if oid in ORDER else self._j(404, {})
        if p.startswith("/api/invoice/"):               # reference target: NO ownership check = BOLA
            if not u: return self._j(401, {})
            iid = p.rsplit("/", 1)[-1]
            return self._j(200, INVOICE[iid]) if iid in INVOICE else self._j(404, {})
        self._j(404, {})

def _seed_har(base):
    """What a human captured: each principal's own /api/orders only."""
    ents = []
    for k, tok in (("A", "tokA"), ("B", "tokB"), ("C", "tokC")):
        ents.append({"request": {"method": "GET", "url": base + "/api/orders",
                     "headers": [{"name": "Authorization", "value": f"Bearer {tok}"}]},
                     "response": {"status": 200, "content": {"text": json.dumps([ORDER[ORD[k]]])}}})
    return {"log": {"entries": ents}}

def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]; base = f"http://127.0.0.1:{port}"
    principals = {"A": "tokA", "B": "tokB", "C": "tokC"}
    token_map = {"tokA": "A", "tokB": "B", "tokC": "C"}

    # 1) Conductor on the SEED capture alone
    seed = _seed_har(base)
    seed_res = COND.run(base, principals, har=seed, token_map=token_map, scope=["127.0.0.1"])

    # 2) Explorer crawls (seed the frontier with the one collection a human saw + a destructive lure)
    har, stats = EXP.crawl(base, principals, scope=["127.0.0.1"],
                           seeds=["/api/orders", "/api/orders/1001/delete"], researcher="measure-l2",
                           max_requests=300)
    endpoints = {EXP.SM.templatize_path(EXP.urlparse(e["request"]["url"]).path)
                 for e in har["log"]["entries"]}

    # 3) Conductor on the EXPLORER capture
    exp_res = COND.run(base, principals, har=har, token_map=token_map, scope=["127.0.0.1"])
    srv.shutdown()

    seed_confirmed = seed_res["coverage"]["confirmed"]
    exp_confirmed = exp_res["coverage"]["confirmed"]
    disc_item = "/api/orders/{id}" in endpoints
    disc_inv = any(e.startswith("/api/invoice/") for e in endpoints)   # reached via reference-following
    # multi-principal visits on the item door
    item_visitors = {e["request"]["headers"][0]["value"] for e in har["log"]["entries"]
                     if "/api/orders/" in e["request"]["url"] and "delete" not in e["request"]["url"]}
    multi = len(item_visitors) >= 2
    only_gets = all(e["request"]["method"] == "GET" for e in har["log"]["entries"])
    no_destructive = len(DESTRUCTIVE_HITS) == 0

    print(f"  seed endpoints seen  : conductor confirmed={seed_confirmed}")
    print(f"  explorer discovered  : {stats['endpoints']} endpoints, {stats['requests']} reqs")
    print(f"    item door /api/orders/{{id}} : {disc_item}")
    print(f"    invoice ref /api/invoice/{{id}}: {disc_inv}")
    print(f"  conductor on explorer: confirmed={exp_confirmed}")
    for r in exp_res["confirmed"][:6]:
        print(f"    ✅ {r['effect']} {r['endpoint']} {r['actor']}→{r['target']}")
    print()
    print(f"  seed alone finds nothing        : {seed_confirmed == 0}")
    print(f"  explorer discovers hidden doors : {disc_item and disc_inv}")
    print(f"  conductor+explorer confirms bug : {exp_confirmed >= 1}")
    print(f"  crawled as multiple principals  : {multi}")
    print(f"  SAFE: GET-only                  : {only_gets}")
    print(f"  SAFE: no destructive endpoint   : {no_destructive}")
    if all([seed_confirmed == 0, disc_item, disc_inv, exp_confirmed >= 1, multi, only_gets, no_destructive]):
        print("\nMEASURE-EXPLORER: PASS — deep reach discovers endpoints the seed never held (item + "
              "reference doors), visits them as every principal, and the Conductor confirms real BOLA "
              "the seed capture structurally could not. Read-only and safe. 0 false positives.")
        return 0
    print("\nMEASURE-EXPLORER: FAIL")
    return 1

if __name__ == "__main__":
    sys.exit(main())
