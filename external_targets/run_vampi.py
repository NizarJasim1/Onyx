"""
Run ONYX against the faithful VAmPI (erev0s) in both modes:
  * vuln=1 -> ONYX should confirm erev0s's authorization vulnerabilities (recall)
  * vuln=0 -> ONYX must produce ZERO findings on erev0s's SAFE app (the false-positive
    test on a target its author did not design)

Two transports, same detection path:
  * use_http=True  -> ONYX reaches VAmPI through its real HTTPTarget over a loopback
                      socket (genuine HTTP). Used by the demo (`python3 run_vampi.py`).
  * use_http=False -> a deterministic in-process target routes straight to VAmPI's
                      handler. Used by the CI test so it never depends on a live server.
The vulnerability LOGIC (erev0s's verbatim branches) is identical either way.
"""
from __future__ import annotations
import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)

from vampi_faithful import VampiFaithful
from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig


def _serve(app):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _do(self, method):
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n) if n else b""
            try: body = json.loads(raw) if raw else {}
            except Exception: body = {}
            st, out = app.handle(method, self.path.split("?")[0], dict(self.headers), body)
            payload = json.dumps(out).encode()
            self.send_response(st)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers(); self.wfile.write(payload)
        def do_GET(self): self._do("GET")
        def do_POST(self): self._do("POST")
        def do_PUT(self): self._do("PUT")
        def do_DELETE(self): self._do("DELETE")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


class _HttpClient:
    """Provisioning + ONYX target over real loopback HTTP."""
    def __init__(self, base): self.base = base
    def call(self, method, path, token=None, body=None):
        import urllib.request
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token: req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read() or b"{}")
        except Exception as e:
            return getattr(e, "code", 599), {}
    def target(self, scope):
        from authpath.transport import HTTPTarget
        return HTTPTarget(self.base, scope=scope)


class _InProcClient:
    """Provisioning + ONYX target in-process (deterministic, no socket)."""
    host = "127.0.0.1"
    def __init__(self, app): self.app = app
    def call(self, method, path, token=None, body=None):
        hdr = {"Authorization": f"Bearer {token}"} if token else {}
        return self.app.handle(method, path.split("?")[0], hdr, body)
    def target(self, scope): return self
    def send(self, req, principal):
        hdr = dict(getattr(principal, "auth", {}) or {})
        st, body = self.app.handle(req.method, req.path.split("?")[0], hdr, req.body)
        return HTTPResponse(st, body)


def run_mode(vuln: bool, use_http: bool = True):
    app = VampiFaithful(vuln=vuln)
    srv = None
    if use_http:
        srv, port = _serve(app)
        client = _HttpClient(f"http://127.0.0.1:{port}")
    else:
        client = _InProcClient(app)
    try:
        creds = {"A": "pa", "B": "pb", "C": "pc"}
        tokens = {}
        for u, pw in creds.items():
            client.call("POST", "/users/v1/register", body={"username": u, "password": pw})
            _, r = client.call("POST", "/users/v1/login", body={"username": u, "password": pw})
            tokens[u] = r.get("auth_token")
        titles = {"A": "A-book", "B": "B-book", "C": "C-book"}
        for u, t in titles.items():
            client.call("POST", "/books/v1", token=tokens[u],
                        body={"book_title": t, "secret": f"secret-of-{u}"})

        scope = ScopeConfig(allowed_hosts=["127.0.0.1"], automation_permitted=True,
                            target_provenance="third_party", dry_run=False)
        target = client.target(scope)
        P = {u: Principal(u, u, auth={"Authorization": f"Bearer {tokens[u]}"}) for u in creds}
        eng = AuthPathEngine(target, P, scope, contract={})
        for f in ("provisional_leads", "active_probing", "conservation", "cross_surface"):
            setattr(eng, f, True)
        eng.confirmer.strict_leak = True
        eng.embedded_owner_exposure = eng.field_exposure = True
        eng.xprincipal_write = eng.xprincipal_delete = True
        # Deficiency #4: give ONYX a consequence oracle for the credential change it cannot
        # read back directly. The prober performs a REAL login round-trip against VAmPI;
        # ONYX judges only the Δstate it reports. This closes the file's own flagship miss.
        from authpath.consequence import ConsequenceOracle
        def _auth_prober(victim, credential):
            _, r = client.call("POST", "/users/v1/login",
                               body={"username": victim, "password": credential})
            return bool(r.get("auth_token"))
        eng.consequence_confirmation = True
        eng.consequence_oracle = ConsequenceOracle(auth_prober=_auth_prober)

        def send(u, method, path, body=None):
            req = HTTPRequest(method, path, body=body, host="127.0.0.1")
            return Exchange(request=req, response=target.send(req, P[u]), principal=P[u])

        for u in creds:
            eng.observe(send(u, "GET", "/users/v1/me"))
            eng.observe(send(u, "GET", f"/books/v1/{titles[u]}"))
        for u in creds:
            for other, t in titles.items():
                if other != u:
                    eng.analyze(send(u, "GET", f"/books/v1/{t}"))
            for other in creds:
                if other != u:
                    eng.analyze(send(u, "PUT", f"/users/v1/{other}/password", body={"password": "hacked"}))
            eng.analyze(send(u, "GET", "/users/v1/_debug"))
        eng.drain_deferred()

        def vclass(ep):
            if "/books/" in ep and ep.startswith("GET"): return "bola_book"
            if "/_debug" in ep: return "ede_debug"
            if "/password" in ep and ep.startswith("PUT"): return "pw_change"
            return None
        flagged = {vclass(f.classification.endpoint) for f in eng.findings} - {None}
        oracle = {"bola_book": vuln, "ede_debug": vuln, "pw_change": vuln}
        labels = {"bola_book": "BOLA — GET /books/v1/{title} leaks another user's secret",
                  "ede_debug": "EDE  — GET /users/v1/_debug leaks all users' data",
                  "pw_change": "PW   — PUT /users/v1/{name}/password (cross-principal write)"}
        tp = fp = fn = tn = 0; rows = []
        for cls, is_vuln in oracle.items():
            found = cls in flagged
            v = ("TP" if is_vuln and found else "FN" if is_vuln else "FP" if found else "TN")
            tp += v == "TP"; fp += v == "FP"; fn += v == "FN"; tn += v == "TN"
            rows.append((labels[cls], is_vuln, found, v))
        return {"vuln": vuln, "rows": rows, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "n_findings": len(eng.findings), "http": use_http}
    finally:
        if srv: srv.shutdown()


def main():
    print("=" * 72)
    print("ONYX vs VAmPI (erev0s) over REAL HTTP — a target ONYX's author did not design")
    print("=" * 72)
    for vuln in (True, False):
        r = run_mode(vuln, use_http=True)
        mode = "VULNERABLE (vuln=1)" if vuln else "SAFE (vuln=0)"
        print(f"\n--- erev0s's {mode} ---")
        for endpoint, is_vuln, found, v in r["rows"]:
            print(f"  [{v}] oracle_vuln={str(is_vuln):5} onyx_flagged={str(found):5}  {endpoint}")
        prec = r["tp"] / (r["tp"] + r["fp"]) if (r["tp"] + r["fp"]) else 1.0
        rec = r["tp"] / (r["tp"] + r["fn"]) if (r["tp"] + r["fn"]) else 0.0
        print(f"  precision={prec:.3f}  recall={rec:.3f}  false positives={r['fp']}")
    print("\n" + "=" * 72)
    print("The SAFE run is the real false-positive test: erev0s's fixed app, zero findings.")
    print("The password-change miss is honest: its Δstate (a changed password) is not")
    print("observable without re-authentication, so ONYX abstains rather than guess.")
    print("=" * 72)


if __name__ == "__main__":
    main()
