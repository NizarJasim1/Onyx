#!/usr/bin/env python3
"""
audit_fp_advanced.py — FP audit for the STANDALONE advanced layers on HARDENED targets.

Complements audit_fp.py (which audits the integrated capture pipeline). Here every advanced
entry point — GraphQL surface, race/TOCTOU, token primitives, multi-step sequences — is pointed
at a correctly-implemented server. Each MUST confirm ZERO. This proves the advanced additions
never manufacture a finding on a safe target.
"""
import json, sys, threading, os, base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)

def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"

# ---------- GraphQL: hardened (ownership-enforced node) ----------
def audit_graphql():
    import graphql_surface as GQL
    USERS = {"tokA": "A", "tokB": "B", "tokC": "C"}
    ORD = {"A": "o-1", "B": "o-2", "C": "o-3"}; OWN = {v: k for k, v in ORD.items()}
    ORDER = {ORD[k]: {"id": ORD[k], "owner": f"{k}", "secret": f"S-{k}"} for k in ORD}
    def who(h):
        a = h.get("Authorization", ""); t = a.split(" ", 1)[1] if a.startswith("Bearer ") else ""
        return USERS.get(t)
    def _intro():
        def T(n): return {"kind": "OBJECT", "name": n, "ofType": None}
        sc = {"kind": "SCALAR", "name": "String", "ofType": None}
        idarg = {"name": "id", "type": {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}}}
        sf = lambda n: {"name": n, "args": [], "type": sc}
        return {"data": {"__schema": {"queryType": {"name": "Query"}, "types": [
            {"name": "Query", "kind": "OBJECT", "fields": [
                {"name": "order", "args": [idarg], "type": T("Order")},
                {"name": "myOrders", "args": [], "type": {"kind": "LIST", "name": None, "ofType": T("Order")}}]},
            {"name": "Order", "kind": "OBJECT", "fields": [sf("id"), sf("owner"), sf("secret")]}]}}}
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            try: pl = json.loads(self.rfile.read(n) or b"{}")
            except Exception: pl = {}
            q = pl.get("query", ""); v = pl.get("variables", {}) or {}; u = who(self.headers)
            if "__schema" in q: out = _intro()
            elif "myOrders" in q: out = {"data": {"myOrders": [ORDER[ORD[u]]]}} if u else {"data": {"myOrders": []}}
            elif "order(" in q:
                vid = str(v.get("v") or v.get("id") or "")
                if u and OWN.get(vid) == u: out = {"data": {"order": ORDER[vid]}}   # ENFORCED
                else: out = {"data": {"order": None}, "errors": [{"message": "forbidden"}]}
            else: out = {"data": {}}
            b = json.dumps(out).encode(); self.send_response(200)
            self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
    srv, base = _serve(H)
    res = GQL.run_graphql(base, {"A": "tokA", "B": "tokB", "C": "tokC"}, scope=["127.0.0.1"], researcher="audit")
    srv.shutdown()
    return len(res["confirmed"])

# ---------- Race: atomic coupon ----------
def audit_race():
    import race as RACE, threading as _t
    lock = _t.Lock(); STATE = {"times_used": 0, "balance": 0, "discount": 10}
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _j(self, c, o):
            b = json.dumps(o).encode(); self.send_response(c); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0); self.rfile.read(n)
            with lock:
                if STATE["times_used"] >= 1: return self._j(409, {})
                STATE["times_used"] += 1; STATE["balance"] += STATE["discount"]; return self._j(200, {"ok": True})
        def do_GET(self):
            p = self.path.split("?")[0]
            if p == "/coupon": return self._j(200, {"times_used": STATE["times_used"], "limit": 1})
            if p == "/account": return self._j(200, {"balance": STATE["balance"]})
            self._j(404, {})
    srv, base = _serve(H)
    res = RACE.run_race(base, "tokA", {"path": "/redeem", "body": {"c": "X"}},
                        {"count": {"path": "/coupon", "field": "times_used"},
                         "value": {"path": "/account", "field": "balance", "single": 10}},
                        allowed=1, k=12, scope=["127.0.0.1"])
    srv.shutdown()
    return 1 if res["confirmed"] else 0

# ---------- Token: verified JWT + token-scoped ----------
def audit_token():
    import token_probes as TP
    def dec(auth):
        t = auth[7:] if auth.lower().startswith("bearer ") else auth; parts = t.split(".")
        return json.loads(base64.urlsafe_b64decode(parts[0] + "==")), json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    PROFILE = {"a@x": {"owner": "a@x", "ssn": "AAA"}, "v@x": {"owner": "v@x", "ssn": "VVV"}}
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _j(self, c, o):
            b = json.dumps(o).encode(); self.send_response(c); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        def do_GET(self):
            p = self.path.split("?")[0]; auth = self.headers.get("Authorization", "")
            try: hdr, pay = dec(auth)
            except Exception: return self._j(401, {})
            if hdr.get("alg", "").lower() == "none": return self._j(401, {})     # reject alg=none
            sub = pay.get("sub")
            if p == "/api/me/profile": return self._j(200, PROFILE.get(sub)) if sub in PROFILE else self._j(404, {})
            if p.startswith("/api/users/"): return self._j(200, PROFILE.get(sub))  # token-scoped, ignores path
            self._j(404, {})
    def jwt(alg, sub):
        b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
        return f"{b({'alg':alg,'typ':'JWT'})}.{b({'sub':sub})}.sig"
    att = jwt("HS256", "a@x")
    srv, base = _serve(H)
    r1 = TP.probe_alg_none(base, att, {"sub": "v@x", "read_path": "/api/me/profile", "expect_owner_field": {"owner": "v@x"}}, scope=["127.0.0.1"])
    r2 = TP.probe_tenant_mismatch(base, att, {"read_path": "/api/users/v@x", "oid": "v@x", "own_path": "/api/users/a@x", "own_oid": "a@x", "expect_owner_field": {"owner": "v@x"}}, scope=["127.0.0.1"])
    srv.shutdown()
    return (1 if r1["confirmed"] else 0) + (1 if r2["confirmed"] else 0)

# ---------- Sequences: enforced gate ----------
def audit_sequences():
    import sequences as SEQ
    STATE = {}
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _j(self, c, o):
            b = json.dumps(o).encode(); self.send_response(c); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        def _b(self):
            n = int(self.headers.get("Content-Length") or 0)
            try: return json.loads(self.rfile.read(n) or b"{}")
            except Exception: return {}
        def do_POST(self):
            if self.path.split("?")[0] == "/api/orders":
                STATE["1001"] = {"id": "1001", "owner": "A", "paid": False, "status": "pending"}; return self._j(200, STATE["1001"])
            self._j(404, {})
        def do_PATCH(self):
            b = self._b(); oid = self.path.split("?")[0].rsplit("/", 1)[-1]
            if oid not in STATE: return self._j(404, {})
            if b.get("status") in ("fulfilled", "shipped") and not STATE[oid]["paid"]:
                return self._j(409, {"error": "unpaid"})            # gate ENFORCED
            STATE[oid]["status"] = b.get("status"); return self._j(200, STATE[oid])
        def do_GET(self):
            oid = self.path.split("?")[0].rsplit("/", 1)[-1]
            return self._j(200, STATE[oid]) if oid in STATE else self._j(404, {})
    srv, base = _serve(H)
    res = SEQ.run(base, {"A": "tokA"}, [{"name": "f", "setup": [{"principal": "A", "method": "POST", "path": "/api/orders", "body": {}}],
          "critical": {"method": "PATCH", "path": "/api/orders/{id}", "effect": "STATE_GATE", "body": {"status": "fulfilled"}, "ids": {"A": ["1001"]}}}],
          scope=["127.0.0.1"])
    srv.shutdown()
    return len(res["confirmed"])

def main():
    results = {"graphql": audit_graphql(), "race": audit_race(),
               "token": audit_token(), "sequences": audit_sequences()}
    ok = all(v == 0 for v in results.values())
    for k, v in results.items():
        print(f"  hardened {k:10s}: confirmed={v} -> {'PASS' if v == 0 else 'FAIL'}")
    print("\nAUDIT-FP-ADVANCED:", "PASS — every advanced layer confirms ZERO on a correctly-implemented "
          "target. No standalone layer manufactures a finding." if ok else "FAIL — a layer produced a false positive.")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
