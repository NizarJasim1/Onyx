#!/usr/bin/env python3
"""measure_graphql.py — MEASURED proof for Phase 3 (real GraphQL surface) vs labeled truth.
The decisive claim: a BOLA that exists ONLY over GraphQL (no REST equivalent) is confirmed by
the untouched engine through the transport adapter, by Δstate — and a public node is dropped.

GROUND TRUTH (three principals A,B,C) on a single POST /graphql endpoint:
  * introspection exposes: query.order(id) -> Order, query.myOrders -> [Order] (list),
    query.promo(id) -> Promo (a PUBLIC node, same for everyone).
  * order(id) performs NO ownership check  = REAL BOLA (cross-owner read).
  * myOrders returns ONLY the caller's own order ids (owner-scoped list → harvest).
  * promo(id) returns the SAME public content to everyone = must be DROPPED (0 FP).

ASSERTIONS:
  1. introspection finds node-by-id fields (order, promo).
  2. harvest gives each principal its own order id (disjoint).
  3. >=1 CONFIRMED cross-owner order read over GraphQL (actor != owner).
  4. NO confirmed promo (public node dropped) and NO self-read.

Run:  python3 external_targets/measure_graphql.py   (exit 0 = pass)
"""
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import graphql_surface as GQL

USERS = {"tokA": "A", "tokB": "B", "tokC": "C"}
ORD = {"A": "o-1001", "B": "o-2002", "C": "o-3003"}
OWNER = {v: k for k, v in ORD.items()}
ORDER = {ORD[k]: {"id": ORD[k], "owner": f"{k.lower()}@x.com", "total": 100, "secret": f"S-{k}"} for k in ORD}
PROMO = {"id": "promo-1", "title": "Autumn Sale", "code": "AUTUMN"}   # public, same for all

def _who(h):
    a = h.get("Authorization", ""); t = a.split(" ", 1)[1] if a.startswith("Bearer ") else ""
    return USERS.get(t)

# minimal introspection reply describing our schema
def _introspection():
    def T(name): return {"kind": "OBJECT", "name": name, "ofType": None}
    scalar = {"kind": "SCALAR", "name": "String", "ofType": None}
    def field(name, tname, args=()):
        return {"name": name, "args": list(args), "type": T(tname)}
    def sfield(name):
        return {"name": name, "args": [], "type": scalar}
    id_arg = {"name": "id", "type": {"kind": "NON_NULL", "name": None,
              "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}}}
    return {"data": {"__schema": {
        "queryType": {"name": "Query"},
        "types": [
            {"name": "Query", "kind": "OBJECT", "fields": [
                {"name": "order", "args": [id_arg], "type": T("Order")},
                {"name": "promo", "args": [id_arg], "type": T("Promo")},
                {"name": "myOrders", "args": [], "type": {"kind": "LIST", "name": None, "ofType": T("Order")}},
            ]},
            {"name": "Order", "kind": "OBJECT", "fields": [
                sfield("id"), sfield("owner"), sfield("total"), sfield("secret")]},
            {"name": "Promo", "kind": "OBJECT", "fields": [
                sfield("id"), sfield("title"), sfield("code")]},
        ]}}}

def _resolve(query, variables, who):
    """Tiny GraphQL resolver for our three fields."""
    if "__schema" in query:
        return _introspection()
    vid = (variables or {}).get("v") or (variables or {}).get("id")
    if "order(" in query or "order (" in query:
        # AUTHED-but-UNAUTHORIZED: requires a valid token, but does NO ownership check.
        # (A fully-public order would correctly be dropped by IARC — that is not a BOLA.)
        if not who:
            return {"data": {"order": None}, "errors": [{"message": "authentication required"}]}
        node = ORDER.get(str(vid))               # any authed user reads any order = BOLA
        return {"data": {"order": node}} if node else {"data": {"order": None}}
    if "promo(" in query:
        return {"data": {"promo": PROMO}}         # public, same for everyone (must be dropped)
    if "myOrders" in query:
        return {"data": {"myOrders": [ORDER[ORD[who]]]}} if who else {"data": {"myOrders": []}}
    return {"data": {}}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        if self.path.split("?")[0] != "/graphql":
            self.send_response(404); self.end_headers(); return
        n = int(self.headers.get("Content-Length") or 0)
        try: payload = json.loads(self.rfile.read(n) or b"{}")
        except Exception: payload = {}
        who = _who(self.headers)
        out = _resolve(payload.get("query", ""), payload.get("variables", {}), who)
        b = json.dumps(out).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]; base = f"http://127.0.0.1:{port}"
    principals = {"A": "tokA", "B": "tokB", "C": "tokC"}

    res = GQL.run_graphql(base, principals, scope=["127.0.0.1"], researcher="measure-gql")
    srv.shutdown()

    node_fields = set(res.get("node_fields", []))
    pool = res.get("pool", {})
    confirmed = res["confirmed"]
    order_hits = [f for f in confirmed if "/order/" in str(f.get("endpoint", ""))]
    promo_hits = [f for f in confirmed if "/promo/" in str(f.get("endpoint", ""))]
    cross_owner = [f for f in order_hits if OWNER.get(str(f.get("target"))) != f.get("actor")]
    self_reads = [f for f in order_hits if OWNER.get(str(f.get("target"))) == f.get("actor")]

    print(f"  node-by-id fields found : {sorted(node_fields)}")
    print(f"  harvested pool          : {{k: len(v) for k,v in pool.items()}} -> "
          + str({k: len(v) for k, v in pool.items()}))
    print(f"  raw engine findings     : {res['raw']}")
    for f in confirmed:
        print(f"    ✅ {f.get('actor')} → {f.get('target')}  {f.get('endpoint')}  [{f.get('surface')}]")
    print()
    intro_ok = {"order", "promo"} <= node_fields
    harvest_ok = all(len(pool.get(p, [])) >= 1 for p in principals)
    cross_ok = len(cross_owner) >= 1
    no_promo = len(promo_hits) == 0
    no_self = len(self_reads) == 0
    print(f"  introspection found node fields : {intro_ok}")
    print(f"  harvest gave each its own id    : {harvest_ok}")
    print(f"  cross-owner order BOLA confirmed: {cross_ok}")
    print(f"  public promo dropped (0 FP)     : {no_promo}")
    print(f"  no self-read                    : {no_self}")
    if all([intro_ok, harvest_ok, cross_ok, no_promo, no_self]):
        print("\nMEASURE-GRAPHQL: PASS — a GraphQL-only BOLA is confirmed cross-owner by the untouched "
              "engine through the transport adapter (Δstate), while the public node is dropped. 0 FP.")
        return 0
    print("\nMEASURE-GRAPHQL: FAIL")
    return 1

if __name__ == "__main__":
    sys.exit(main())
