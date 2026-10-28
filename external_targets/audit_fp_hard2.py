#!/usr/bin/env python3
"""
audit_fp_hard2.py — SECOND-WAVE adversarial FP hunt: the subtle, nasty ones.

These target the exact seams where a zero-FP claim usually dies on real targets.

  H1 disjoint-but-public : a PUBLIC recommendations feed that is PERSONALISED — each principal
        sees DIFFERENT public ids. Disjointness makes it LOOK owner-scoped, but an anonymous
        client reads the same items → it is public. The pipeline must NOT confirm a "BOLA".
  H2 empty-200          : cross-owner attempt returns 200 with an EMPTY body {} — a success
        status with no data. Must not be counted as a leak.
  H3 null-field-200     : cross-owner returns 200 but every substantive field is null/redacted
        ({"id":X,"owner":null,"secret":null}) — nothing actually disclosed. Must not confirm.
  H4 gql-introspection-off : GraphQL __schema returns errors (introspection disabled). The
        surface must degrade gracefully and confirm nothing (no fabrication).
  H5 token-alg-none-generic: server accepts alg=none but returns GENERIC data (not the victim's).
        Accepting a forged token is NOT a finding without victim-specific Δstate.
  H6 seq-legit-terminal : a 'cancelled' state that legitimately needs NO predecessor (cancel an
        unpaid order is fine). Reaching it must NOT be flagged as a gate skip.

Exit 0 ⟺ every scenario confirms ZERO.
"""
import json, sys, threading, os, base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import explorer as EXP
import conductor as COND

USERS = {"tokA": "A", "tokB": "B", "tokC": "C"}
OID = {"A": "1", "B": "2", "C": "3"}; OWNER = {v: k for k, v in OID.items()}

def _who(h):
    a = h.get("Authorization", ""); t = a.split(" ", 1)[1] if a.startswith("Bearer ") else ""
    return USERS.get(t)

# ---------------- H1..H3 via the capture pipeline ----------------
def _make_pipe(mode):
    # personalised-public: each principal sees a different PUBLIC rec id; anon sees them too
    RECS = {"A": "rec-101", "B": "rec-102", "C": "rec-103"}
    REC_BODY = {v: {"id": v, "title": "Trending article", "public": True} for v in RECS.values()}
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _j(self, c, o):
            b = json.dumps(o).encode() if o is not None else b""
            self.send_response(c)
            if o is not None: self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers()
            if b: self.wfile.write(b)
        def do_GET(self):
            p = self.path.split("?")[0]; u = _who(self.headers)
            if mode == "disjoint_public":
                if p == "/api/recommendations":
                    # personalised list; anon also gets a (different) personalised list of PUBLIC ids
                    who = u or "A"
                    return self._j(200, [REC_BODY[RECS[who]]])
                if p.startswith("/api/recommendations/"):
                    rid = p.rsplit("/", 1)[-1]
                    return self._j(200, REC_BODY[rid]) if rid in REC_BODY else self._j(404, {})  # PUBLIC: anyone reads any
                return self._j(404, {})
            # H2/H3 use an owner-scoped orders collection + a tricky item read
            if p == "/api/orders":
                return self._j(200, [{"id": OID[u], "owner": f"{u.lower()}@x.com"}]) if u else self._j(401, {})
            if p.startswith("/api/orders/"):
                if not u: return self._j(401, {})
                oid = p.rsplit("/", 1)[-1]; owner = OWNER.get(oid)
                if owner == u:
                    return self._j(200, {"id": oid, "owner": f"{u.lower()}@x.com", "secret": f"S-{u}"})
                if mode == "empty_200":
                    return self._j(200, {})                                  # success, no data
                if mode == "null_fields":
                    return self._j(200, {"id": oid, "owner": None, "secret": None})  # redacted
                return self._j(403, {})
            return self._j(404, {})
    return H

def _run_pipe(mode, seeds):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_pipe(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    principals = {"A": "tokA", "B": "tokB", "C": "tokC"}; tm = {"tokA": "A", "tokB": "B", "tokC": "C"}
    har, _ = EXP.crawl(base, principals, scope=["127.0.0.1"], seeds=seeds, researcher="h2", max_requests=300)
    pkt = COND.run(base, principals, har=har, token_map=tm, scope=["127.0.0.1"], researcher="h2")
    srv.shutdown()
    return pkt["coverage"]["confirmed"], pkt["confirmed"]

# ---------------- H4 GraphQL introspection disabled ----------------
def _h4_graphql():
    import graphql_surface as GQL
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0); self.rfile.read(n)
            out = {"errors": [{"message": "introspection is disabled"}]}   # no __schema
            b = json.dumps(out).encode(); self.send_response(200)
            self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    res = GQL.run_graphql(base, {"A": "tokA", "B": "tokB", "C": "tokC"}, scope=["127.0.0.1"])
    srv.shutdown()
    return len(res["confirmed"])

# ---------------- H5 token alg=none accepted but generic data ----------------
def _h5_token():
    import token_probes as TP
    def dec(auth):
        t = auth[7:] if auth.lower().startswith("bearer ") else auth; parts = t.split(".")
        return json.loads(base64.urlsafe_b64decode(parts[0] + "==")), json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    GENERIC = {"id": "self", "welcome": "hello", "tier": "free"}   # same for everyone, no PII
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _j(self, c, o):
            b = json.dumps(o).encode(); self.send_response(c); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        def do_GET(self):
            auth = self.headers.get("Authorization", "")
            try: dec(auth)
            except Exception: return self._j(401, {})
            if self.path.split("?")[0] == "/api/me/profile":
                return self._j(200, GENERIC)     # accepts anything, returns generic (no victim data)
            self._j(404, {})
    def jwt(alg, sub):
        b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
        return f"{b({'alg':alg,'typ':'JWT'})}.{b({'sub':sub})}.sig"
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    r = TP.probe_alg_none(base, jwt("HS256", "a@x"),
                          {"sub": "v@x", "read_path": "/api/me/profile", "expect_owner_field": {"owner": "v@x"}},
                          scope=["127.0.0.1"])
    srv.shutdown()
    return 1 if r["confirmed"] else 0

# ---------------- H6 sequence: legitimate terminal state (cancel unpaid) ----------------
def _h6_sequence():
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
                STATE["1"] = {"id": "1", "owner": "A", "paid": False, "status": "pending"}; return self._j(200, STATE["1"])
            self._j(404, {})
        def do_PATCH(self):
            b = self._b(); oid = self.path.split("?")[0].rsplit("/", 1)[-1]
            if oid not in STATE: return self._j(404, {})
            STATE[oid]["status"] = b.get("status")   # 'cancelled' is a legit terminal needing no predecessor
            return self._j(200, STATE[oid])
        def do_GET(self):
            oid = self.path.split("?")[0].rsplit("/", 1)[-1]
            return self._j(200, STATE[oid]) if oid in STATE else self._j(404, {})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    res = SEQ.run(base, {"A": "tokA"}, [{"name": "cancel-unpaid",
          "setup": [{"principal": "A", "method": "POST", "path": "/api/orders", "body": {}}],
          "critical": {"method": "PATCH", "path": "/api/orders/{id}", "effect": "STATE_GATE",
                       "body": {"status": "cancelled"}, "ids": {"A": ["1"]}}}], scope=["127.0.0.1"])
    srv.shutdown()
    return len(res["confirmed"])

def main():
    checks = []
    n, conf = _run_pipe("disjoint_public", ["/api/recommendations", "/api/recommendations/rec-101",
                        "/api/recommendations/rec-102", "/api/recommendations/rec-103"])
    checks.append(("H1 disjoint-but-public", n, conf))
    n, conf = _run_pipe("empty_200", ["/api/orders", "/api/orders/1", "/api/orders/2", "/api/orders/3"])
    checks.append(("H2 empty-200", n, conf))
    n, conf = _run_pipe("null_fields", ["/api/orders", "/api/orders/1", "/api/orders/2", "/api/orders/3"])
    checks.append(("H3 null-fields-200", n, conf))
    checks.append(("H4 gql-introspection-off", _h4_graphql(), []))
    checks.append(("H5 token-alg-none-generic", _h5_token(), []))
    checks.append(("H6 seq-legit-terminal", _h6_sequence(), []))

    print("=== SECOND-WAVE ADVERSARIAL FP HUNT ===\n")
    ok = True
    for label, n, conf in checks:
        status = "PASS" if n == 0 else "FALSE POSITIVE!"
        if n != 0: ok = False
        print(f"  {label:28s}: confirmed={n} -> {status}")
        for r in (conf or [])[:4]:
            print(f"        !! {r.get('effect')} {r.get('endpoint')} {r.get('actor')}→{r.get('target')}")
    print()
    if ok:
        print("AUDIT-FP-HARD2: PASS — the subtle traps (personalised-public, empty/null success, "
              "introspection-off, generic-forgery, legit terminal state) all confirm ZERO.")
        return 0
    print("AUDIT-FP-HARD2: FAIL — a subtle false positive slipped through. FIX REQUIRED.")
    return 1

if __name__ == "__main__":
    sys.exit(main())
