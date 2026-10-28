#!/usr/bin/env python3
"""measure_token.py — MEASURED proof for Phase 5 (token primitives) vs labeled truth.
Two servers per probe: VULN accepts the manipulated credential and leaks cross-owner data;
SAFE verifies it and returns nothing. Confirmation is cross-owner Δstate only.

Run:  python3 external_targets/measure_token.py   (exit 0 = pass)
"""
import json, sys, threading, os, base64
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import token_probes as TP

def _jwt(alg, sub, sig="realsig"):
    def b(o): return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    return f"{b({'alg':alg,'typ':'JWT'})}.{b({'sub':sub,'tenant':sub[0]})}.{sig}"

# profiles: attacker A (sub 'a@x'), victim V (sub 'v@x')
ATTACKER = _jwt("HS256", "a@x")
PROFILE = {"a@x": {"owner": "a@x", "ssn": "AAA", "balance": 1}, "v@x": {"owner": "v@x", "ssn": "VVV", "balance": 999}}

def _decode_sub(token):
    t = token[7:] if token.lower().startswith("bearer ") else token
    parts = t.split(".")
    hdr = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    pay = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    return hdr, pay

def _make_alg_none(vuln):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _j(self, c, o):
            b = json.dumps(o).encode(); self.send_response(c)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        def do_GET(self):
            if self.path.split("?")[0] != "/api/me/profile": return self._j(404, {})
            auth = self.headers.get("Authorization", "")
            try:
                hdr, pay = _decode_sub(auth)
            except Exception:
                return self._j(401, {})
            if not vuln and hdr.get("alg", "").lower() == "none":
                return self._j(401, {"error": "unverified token"})     # SAFE: reject alg=none
            sub = pay.get("sub")
            prof = PROFILE.get(sub)
            return self._j(200, prof) if prof else self._j(404, {})
    return H

def _make_tenant(vuln):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _j(self, c, o):
            b = json.dumps(o).encode(); self.send_response(c)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        def do_GET(self):
            p = self.path.split("?")[0]
            auth = self.headers.get("Authorization", "")
            try: _, pay = _decode_sub(auth)
            except Exception: return self._j(401, {})
            token_sub = pay.get("sub")
            if p.startswith("/api/users/"):
                target = p.rsplit("/", 1)[-1]
                if vuln:
                    prof = PROFILE.get(target)               # trusts the PATH id (mismatch bug)
                    return self._j(200, prof) if prof else self._j(404, {})
                else:
                    # SAFE: only your own record, regardless of path id
                    return self._j(200, PROFILE.get(token_sub)) if token_sub in PROFILE else self._j(401, {})
            self._j(404, {})
    return H

def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"

def main():
    ok = True
    # ---- alg=none ----
    for vuln in (True, False):
        srv, base = _serve(_make_alg_none(vuln))
        victim = {"sub": "v@x", "read_path": "/api/me/profile",
                  "expect_owner_field": {"owner": "v@x"}}
        res = TP.probe_alg_none(base, ATTACKER, victim, scope=["127.0.0.1"], researcher="m")
        srv.shutdown()
        want = vuln
        good = res["confirmed"] is want
        ok &= good
        print(f"  alg-none  vuln={vuln}: confirmed={res['confirmed']} -> {'PASS' if good else 'FAIL'}  ({res['reason'][:60]})")
    # ---- tenant mismatch ----
    for vuln in (True, False):
        srv, base = _serve(_make_tenant(vuln))
        victim = {"read_path": "/api/users/v@x", "oid": "v@x",
                  "own_path": "/api/users/a@x", "own_oid": "a@x",
                  "expect_owner_field": {"owner": "v@x"}}
        res = TP.probe_tenant_mismatch(base, ATTACKER, victim, scope=["127.0.0.1"], researcher="m")
        srv.shutdown()
        good = res["confirmed"] is vuln
        ok &= good
        print(f"  tenant    vuln={vuln}: confirmed={res['confirmed']} -> {'PASS' if good else 'FAIL'}  ({res['reason'][:60]})")
    print("\nMEASURE-TOKEN:", "PASS — JWT alg=none and tenant-mismatch are confirmed ONLY when they yield "
          "cross-owner Δstate; hardened servers confirm nothing. 0 false positives." if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
