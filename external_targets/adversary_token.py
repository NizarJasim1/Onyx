#!/usr/bin/env python3
"""adversary_token.py — adversarial self-critique of Phase 5 (token primitives). Two traps.

  A) ACCEPTS-BUT-IGNORES-CLAIM: the server accepts an alg=none token (returns 200) but resolves
     identity from the SESSION, not the token — so it returns the ATTACKER'S OWN data. A naive
     "forged token accepted → bug" would fire; the cross-owner Δstate check must NOT (same data
     as the attacker's own read).
  B) ECHO-ONLY: the /api/users/{id} endpoint echoes the requested id but returns the caller's own
     profile fields regardless — no cross-tenant data. Must not confirm.
"""
import json, sys, threading, os, base64
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import token_probes as TP

def _jwt(alg, sub):
    def b(o): return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    return f"{b({'alg':alg,'typ':'JWT'})}.{b({'sub':sub}) }.sig".replace(" ", "")
ATTACKER = _jwt("HS256", "a@x")
OWN = {"owner": "a@x", "ssn": "AAA"}

def _decode(auth):
    t = auth[7:] if auth.lower().startswith("bearer ") else auth
    parts = t.split(".")
    return (json.loads(base64.urlsafe_b64decode(parts[0] + "==")),
            json.loads(base64.urlsafe_b64decode(parts[1] + "==")))

def _make(mode):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _j(self, c, o):
            b = json.dumps(o).encode(); self.send_response(c)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        def do_GET(self):
            p = self.path.split("?")[0]; auth = self.headers.get("Authorization", "")
            try: _decode(auth)
            except Exception: return self._j(401, {})
            if mode == "ignore_claim" and p == "/api/me/profile":
                return self._j(200, OWN)                 # 200, but always the attacker's own data
            if mode == "echo" and p.startswith("/api/users/"):
                target = p.rsplit("/", 1)[-1]
                return self._j(200, {"id": target, **OWN})   # echoes id, own fields otherwise
            self._j(404, {})
    return H

def _serve(mode):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"

def main():
    ok = True
    srv, base = _serve("ignore_claim")
    a = TP.probe_alg_none(base, ATTACKER, {"sub": "v@x", "read_path": "/api/me/profile",
                          "expect_owner_field": {"owner": "v@x"}}, scope=["127.0.0.1"])
    srv.shutdown()
    print(f"A) accepts-but-ignores-claim: confirmed={a['confirmed']} -> {'PASS' if not a['confirmed'] else 'FAIL'}  ({a['reason'][:56]})")
    ok &= not a["confirmed"]

    srv, base = _serve("echo")
    b = TP.probe_tenant_mismatch(base, ATTACKER, {"read_path": "/api/users/v@x", "oid": "v@x",
                          "own_path": "/api/users/a@x", "own_oid": "a@x",
                          "expect_owner_field": {"owner": "v@x"}}, scope=["127.0.0.1"])
    srv.shutdown()
    print(f"B) echo-only id             : confirmed={b['confirmed']} -> {'PASS' if not b['confirmed'] else 'FAIL'}  ({b['reason'][:56]})")
    ok &= not b["confirmed"]

    print("\nADVERSARY-TOKEN:", "PASS — accepting a manipulated token is not enough; without cross-owner "
          "Δstate nothing is confirmed. 0 false positives." if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
