#!/usr/bin/env python3
"""adversary_explorer.py — adversarial self-critique of Phase 2 (the deep-reach crawler).
The Explorer touches a live target, so its SAFETY is the thing to attack. Four attacks; each
must hold.

  A) NO WRITES / NO DESTRUCTIVE: a page links to logout, delete, deactivate, and a POST form.
     The Explorer must issue GET only and never request any destructive path — even when it is
     linked from a visited response.
  B) SCOPE CONTAINMENT: a response links to an OFF-SCOPE host (evil.example). The Explorer must
     never request it (Scope-Guard).
  C) BUDGET / NO EXPLOSION: a server that returns a fresh unique id on every read (infinite
     surface) must not make the Explorer loop forever — it stops at the request budget.
  D) NO FABRICATION: every capture entry corresponds to a real request the server logged;
     the Explorer never emits an endpoint the server was not actually asked for.
"""
import json, sys, threading, os, itertools
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import explorer as EXP

SERVER_LOG = []          # every path the server was actually asked for
DESTRUCTIVE = []
OFFSCOPE_HIT = []

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _j(self, c, o):
        b = json.dumps(o).encode(); self.send_response(c)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        SERVER_LOG.append("POST " + self.path)      # a write ever reaching us is a failure
        self._j(200, {})
    def do_DELETE(self):
        SERVER_LOG.append("DELETE " + self.path)
        self._j(200, {})
    def do_GET(self):
        p = self.path.split("?")[0]; SERVER_LOG.append("GET " + p)
        if any(x in p for x in ("logout", "delete", "deactivate", "destroy", "revoke")):
            DESTRUCTIVE.append(p); return self._j(200, {"ok": True})
        if p == "/api/root":
            return self._j(200, {
                "links": ["/api/logout", "/api/users/1/delete", "/api/account/deactivate",
                          "http://evil.example/steal", "/api/item/1"],
                "post_to": "/api/transfer"})
        if p == "/api/item/1":
            # infinite surface: each read reveals a brand-new child id
            nxt = next(_COUNTER)
            return self._j(200, {"id": "1", "child": f"/api/item/child-{nxt}-9"})
        if p.startswith("/api/item/"):
            nxt = next(_COUNTER)
            return self._j(200, {"id": p.rsplit("/", 1)[-1], "child": f"/api/item/child-{nxt}-9"})
        self._j(404, {})

_COUNTER = itertools.count()

def main():
    global _COUNTER
    _COUNTER = itertools.count()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]; base = f"http://127.0.0.1:{port}"
    har, stats = EXP.crawl(base, {"A": "tokA", "B": "tokB"}, scope=["127.0.0.1"],
                           seeds=["/api/root"], researcher="adv", max_requests=40)
    srv.shutdown()

    methods = {e["request"]["method"] for e in har["log"]["entries"]}
    only_get = methods == {"GET"}
    no_writes = not any(m.startswith(("POST", "DELETE")) for m in SERVER_LOG)
    no_destructive = len(DESTRUCTIVE) == 0
    # off-scope: evil.example must never be in any requested URL
    no_offscope = not any("evil.example" in e["request"]["url"] for e in har["log"]["entries"])
    budget_ok = stats["requests"] <= 40
    # no fabrication: every captured GET path was actually seen by the server
    server_gets = {s.split(" ", 1)[1] for s in SERVER_LOG if s.startswith("GET ")}
    from urllib.parse import urlparse
    captured = {urlparse(e["request"]["url"]).path for e in har["log"]["entries"]}
    no_fab = captured.issubset(server_gets)

    print(f"A) GET-only                 : {only_get}   writes-reaching-server: {SERVER_LOG.count('POST')+sum(1 for s in SERVER_LOG if s.startswith(('POST','DELETE')))}")
    print(f"   no destructive path hit  : {no_destructive}  (hits={DESTRUCTIVE})")
    print(f"B) scope contained          : {no_offscope}")
    print(f"C) budget respected         : {budget_ok}  (requests={stats['requests']}, cap=40)")
    print(f"D) no fabricated endpoints  : {no_fab}")
    ok = all([only_get, no_writes, no_destructive, no_offscope, budget_ok, no_fab])
    print("\nADVERSARY-EXPLORER:", "PASS — read-only, destructive-safe, scope-contained, budget-bounded, "
          "no fabricated endpoints." if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
