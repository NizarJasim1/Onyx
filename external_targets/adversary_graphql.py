#!/usr/bin/env python3
"""adversary_graphql.py — adversarial self-critique of Phase 3 (GraphQL surface).
Three GraphQL-specific false-positive traps; each must yield 0 confirmed.

  A) SERVER-IGNORES-ID: order(id) returns the CALLER'S OWN order regardless of the id argument
     (not object-scoped). GraphQL-IARC must drop it.
  B) FULLY-PUBLIC NODE: order(id) returns data to an anonymous caller too (no auth). IARC's
     anonymous-baseline must drop it (public, not a BOLA).
  C) PROPER-AUTHZ: order(id) enforces ownership (403 for non-owner). The engine must confirm
     nothing (no cross-owner Δstate).
"""
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import graphql_surface as GQL

USERS = {"tokA": "A", "tokB": "B", "tokC": "C"}
ORD = {"A": "o-1", "B": "o-2", "C": "o-3"}
OWNER = {v: k for k, v in ORD.items()}
ORDER = {ORD[k]: {"id": ORD[k], "owner": f"{k.lower()}@x.com", "secret": f"S-{k}"} for k in ORD}

def _who(h):
    a = h.get("Authorization", ""); t = a.split(" ", 1)[1] if a.startswith("Bearer ") else ""
    return USERS.get(t)

def _introspection():
    def T(n): return {"kind": "OBJECT", "name": n, "ofType": None}
    scalar = {"kind": "SCALAR", "name": "String", "ofType": None}
    id_arg = {"name": "id", "type": {"kind": "NON_NULL", "name": None,
              "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}}}
    sf = lambda n: {"name": n, "args": [], "type": scalar}
    return {"data": {"__schema": {"queryType": {"name": "Query"}, "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "order", "args": [id_arg], "type": T("Order")},
            {"name": "myOrders", "args": [], "type": {"kind": "LIST", "name": None, "ofType": T("Order")}}]},
        {"name": "Order", "kind": "OBJECT", "fields": [sf("id"), sf("owner"), sf("secret")]}]}}}

def _make_handler(mode):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            try: payload = json.loads(self.rfile.read(n) or b"{}")
            except Exception: payload = {}
            q = payload.get("query", ""); v = payload.get("variables", {}) or {}
            who = _who(self.headers)
            vid = str(v.get("v") or v.get("id") or "")
            if "__schema" in q:
                out = _introspection()
            elif "myOrders" in q:
                out = {"data": {"myOrders": [ORDER[ORD[who]]]}} if who else {"data": {"myOrders": []}}
            elif "order(" in q or "order (" in q:
                if mode == "ignore_id":                       # A: returns caller's own regardless of id
                    out = {"data": {"order": ORDER[ORD[who]]}} if who else {"data": {"order": None}}
                elif mode == "public":                         # B: anyone (even anon) reads any order
                    out = {"data": {"order": ORDER.get(vid)}}
                elif mode == "authz_ok":                       # C: proper ownership enforcement
                    if who and OWNER.get(vid) == who:
                        out = {"data": {"order": ORDER[vid]}}
                    else:
                        out = {"data": {"order": None}, "errors": [{"message": "forbidden"}]}
                else:
                    out = {"data": {"order": None}}
            else:
                out = {"data": {}}
            b = json.dumps(out).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    return H

def _run(mode):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]; base = f"http://127.0.0.1:{port}"
    res = GQL.run_graphql(base, {"A": "tokA", "B": "tokB", "C": "tokC"},
                          scope=["127.0.0.1"], researcher="adv-gql")
    srv.shutdown()
    return res

def main():
    ok = True
    for label, mode, why in [
        ("A) server-ignores-id", "ignore_id", "returns caller's own regardless of id"),
        ("B) fully-public node ", "public", "anonymous reproduces the data"),
        ("C) proper authz      ", "authz_ok", "ownership enforced, no cross-owner Δstate"),
    ]:
        res = _run(mode)
        n = len(res["confirmed"])
        good = n == 0
        ok &= good
        print(f"{label}: confirmed={n} raw={res['raw']} -> {'PASS' if good else 'FAIL'}  ({why})")
    print("\nADVERSARY-GRAPHQL:", "PASS — GraphQL surface resists id-ignoring, fully-public, and "
          "properly-authorized nodes. 0 false positives." if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
