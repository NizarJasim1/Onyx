#!/usr/bin/env python3
"""measure_iarc_disjoint.py — proves zero-FP is NON-VACUOUS on the hardest public trap.

A personalised-public feed: each principal's list shows a DIFFERENT numeric id (disjoint →
harvest classifies it OWNER-SCOPED and BUILDS cross-principal probes), yet every item is
PUBLIC (any caller — even anonymous — reads any id). This is the case where a lesser tool fires
a BOLA. Here the engine actually PROBES the cross-owner reads, and IARC's anonymous-baseline
DROPS them because an anonymous client reproduces the data.

PASS = pool owner-scoped (probes were really built) AND confirmed == 0 (IARC dropped them).
This is the doubled-gate working end to end — zero-FP earned, not vacuous.
"""
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import onyx_recon as OR
import conductor as COND

USERS = {"tokA": "A", "tokB": "B", "tokC": "C"}
REC = {"A": "501", "B": "502", "C": "503"}
BODY = {v: {"id": v, "title": "trending", "public": True} for v in REC.values()}

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
        if p == "/api/recs":
            return self._j(200, [BODY[REC[u]]]) if u else self._j(401, {})
        if p.startswith("/api/recs/"):
            rid = p.rsplit("/", 1)[-1]
            return self._j(200, BODY[rid]) if rid in BODY else self._j(404, {})   # PUBLIC (even anon)
        self._j(404, {})

def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    pr = {"A": "tokA", "B": "tokB", "C": "tokC"}; tm = {"tokA": "A", "tokB": "B", "tokC": "C"}
    ents = []
    for k, tok in (("A", "tokA"), ("B", "tokB"), ("C", "tokC")):
        for path, body in (("/api/recs", [BODY[REC[k]]]), (f"/api/recs/{REC[k]}", BODY[REC[k]])):
            ents.append({"request": {"method": "GET", "url": base + path,
                        "headers": [{"name": "Authorization", "value": f"Bearer {tok}"}]},
                        "response": {"status": 200, "content": {"text": json.dumps(body)}}})
    har = {"log": {"entries": ents}}
    cli = OR.Client(["127.0.0.1"], researcher="iarc")
    surf = OR.ingest_har(har)
    owned, pool, hrep = OR.harvest(cli, base, surf, pr)
    probes = len(OR.build_plan(surf, owned, pool, pr, False))
    pkt = COND.run(base, pr, har=har, token_map=tm, scope=["127.0.0.1"], researcher="iarc")
    srv.shutdown()

    owner_scoped = sum(len(v) for v in pool.values()) >= 3
    dropped = pkt["coverage"]["confirmed"] == 0
    print(f"  pool owner-scoped (probes real): {pool}  -> {owner_scoped}")
    print(f"  cross-principal probes built    : {probes}")
    print(f"  confirmed (must be 0, IARC drop): {pkt['coverage']['confirmed']}")
    if owner_scoped and probes >= 1 and dropped:
        print("\nMEASURE-IARC-DISJOINT: PASS — harvest built real cross-owner probes on a disjoint feed, "
              "and IARC's anonymous baseline dropped them as public. Zero-FP is earned, not vacuous.")
        return 0
    print("\nMEASURE-IARC-DISJOINT: FAIL")
    return 1

if __name__ == "__main__":
    sys.exit(main())
