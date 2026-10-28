#!/usr/bin/env python3
"""adversary_altpaths_deep.py — adversarial self-critique of LAYER 4-X (alt_paths_deep).

Four attacks on the deep layer itself. Each must produce ZERO confirmed false positives.

  A) SELF-LEAK (not cross-owner): the activity feed leaks the caller's OWN invoice id. A
     naive pivot would probe it and 'succeed' (you can read your own object). EXPECT: no
     cross-owner claim -> 0 confirmed (ownership==actor is filtered).

  B) PUBLIC ALTERNATE via pivot: the leaked id is real and cross-owner, but the ONLY door to
     it returns the SAME public document to everyone (not object-scoped). EXPECT: IARC drops
     it -> 0 confirmed.

  C) UNKNOWN-OWNER leak: an id is leaked to Q but NO principal ever self-read it (owner cannot
     be established from the capture). EXPECT: the layer refuses to assume ownership -> the id
     is not pivoted as cross-owner -> 0 confirmed.

  D) SERVER-IGNORES-ID alternate: the alternate door returns the CALLER'S OWN invoice
     regardless of the id in the path. EXPECT: IARC 'server ignores id' drops it -> 0 confirmed.
"""
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import alt_paths_deep as DEEP

USERS = {"tokA": "A", "tokB": "B", "tokC": "C"}
INV = {"A": "inv-A-1", "B": "inv-B-2", "C": "inv-C-3"}
OWNER_INV = {v: k for k, v in INV.items()}
INVOICE = {INV[k]: {"id": INV[k], "owner": f"{k.lower()}@x.com", "amount_due": 500, "iban": f"DE{k}"} for k in INV}
PUBLIC = {"id": "public-doc", "note": "same for everyone", "promo": "X"}

def _who(h):
    a = h.get("Authorization", ""); t = a.split(" ", 1)[1] if a.startswith("Bearer ") else ""
    return USERS.get(t)

def _mk(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]

def _entry(base, method, path, status, body, tok):
    return {"request": {"method": method, "url": base + path,
            "headers": [{"name": "Authorization", "value": f"Bearer {tok}"}]},
            "response": {"status": status, "content": {"text": json.dumps(body) if body is not None else ""}}}

def _J(h, c, o):
    b = json.dumps(o).encode(); h.send_response(c); h.send_header("Content-Type", "application/json")
    h.send_header("Content-Length", str(len(b))); h.end_headers(); h.wfile.write(b)

# ---- Attack A: self-leak (activity shows caller's OWN id) ----
class HA(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        p = self.path.split("?")[0]; u = _who(self.headers)
        if p == "/api/activity":
            return _J(self, 200, [{"invoice_id": INV[u]}]) if u else _J(self, 401, {})
        if p.startswith("/admin/api/invoice/"):
            if not u: return _J(self, 401, {})
            iid = p.rsplit("/", 1)[-1]
            return _J(self, 200, INVOICE[iid]) if OWNER_INV.get(iid) == u else _J(self, 403, {"error": "f"})
        if p.startswith("/api/billing/invoice/"):
            if not u: return _J(self, 401, {})
            iid = p.rsplit("/", 1)[-1]
            return _J(self, 200, INVOICE[iid]) if iid in INVOICE else _J(self, 404, {})
        _J(self, 404, {})

def attack_A():
    srv, port = _mk(HA); base = f"http://127.0.0.1:{port}"; ents = []
    for k, tok in (("A","tokA"),("B","tokB"),("C","tokC")):
        ents.append(_entry(base,"GET","/api/activity",200,[{"invoice_id":INV[k]}],tok))         # OWN id
        ents.append(_entry(base,"GET",f"/admin/api/invoice/{INV[k]}",200,INVOICE[INV[k]],tok))    # self-read
        other = INV["B"] if k!="B" else INV["A"]
        ents.append(_entry(base,"GET",f"/admin/api/invoice/{other}",403,{"error":"f"},tok))
        ents.append(_entry(base,"GET",f"/api/billing/invoice/{INV[k]}",200,INVOICE[INV[k]],tok))
    res = DEEP.run_deep(base, {"A":"tokA","B":"tokB","C":"tokC"}, har={"log":{"entries":ents}},
                        token_map={"tokA":"A","tokB":"B","tokC":"C"}, scope=["127.0.0.1"])
    srv.shutdown()
    ok = len(res["confirmed"]) == 0
    print(f"A) self-leak         pivots={res['pivots']} confirmed={len(res['confirmed'])} "
          f"-> {'PASS' if ok else 'FAIL'} (expect 0: leaked id is caller's own)")
    return ok

# ---- Attack B: cross-owner leak but only a PUBLIC door exists ----
class HB(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        p = self.path.split("?")[0]; u = _who(self.headers)
        if p == "/api/activity":
            nxt = {"A":"B","B":"C","C":"A"}[u] if u else None
            return _J(self, 200, [{"invoice_id": INV[nxt]}]) if u else _J(self, 401, {})
        if p.startswith("/admin/api/invoice/"):
            if not u: return _J(self, 401, {})
            iid = p.rsplit("/", 1)[-1]
            return _J(self, 200, INVOICE[iid]) if OWNER_INV.get(iid) == u else _J(self, 403, {"error":"f"})
        if p.startswith("/api/billing/invoice/"):     # returns SAME public doc for everyone
            return _J(self, 200, PUBLIC) if u else _J(self, 401, {})
        _J(self, 404, {})

def attack_B():
    srv, port = _mk(HB); base = f"http://127.0.0.1:{port}"; ents = []; nxt={"A":"B","B":"C","C":"A"}
    for k, tok in (("A","tokA"),("B","tokB"),("C","tokC")):
        ents.append(_entry(base,"GET","/api/activity",200,[{"invoice_id":INV[nxt[k]]}],tok))
        ents.append(_entry(base,"GET",f"/admin/api/invoice/{INV[k]}",200,INVOICE[INV[k]],tok))
        ents.append(_entry(base,"GET",f"/admin/api/invoice/{INV[nxt[k]]}",403,{"error":"f"},tok))
        ents.append(_entry(base,"GET",f"/api/billing/invoice/{INV[k]}",200,PUBLIC,tok))
    res = DEEP.run_deep(base, {"A":"tokA","B":"tokB","C":"tokC"}, har={"log":{"entries":ents}},
                        token_map={"tokA":"A","tokB":"B","tokC":"C"}, scope=["127.0.0.1"])
    srv.shutdown()
    ok = len(res["confirmed"]) == 0
    print(f"B) public-alternate  pivots={res['pivots']} confirmed={len(res['confirmed'])} "
          f"-> {'PASS' if ok else 'FAIL'} (expect 0: IARC drops public)")
    return ok

# ---- Attack C: leaked id with UNKNOWN owner (no self-read anywhere) ----
class HC(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        p = self.path.split("?")[0]; u = _who(self.headers)
        if p == "/api/activity":
            return _J(self, 200, [{"invoice_id": "inv-ghost-9"}]) if u else _J(self, 401, {})
        if p.startswith("/api/billing/invoice/"):
            if not u: return _J(self, 401, {})
            iid = p.rsplit("/", 1)[-1]
            # ghost id returns data, but NO principal ever self-read it -> owner unknown
            return _J(self, 200, {"id": iid, "owner": "ghost@x.com", "secret": "z"}) if "ghost" in iid else _J(self, 404, {})
        _J(self, 404, {})

def attack_C():
    srv, port = _mk(HC); base = f"http://127.0.0.1:{port}"; ents = []
    for k, tok in (("A","tokA"),("B","tokB"),("C","tokC")):
        ents.append(_entry(base,"GET","/api/activity",200,[{"invoice_id":"inv-ghost-9"}],tok))
        # note: NO self-read of inv-ghost-9 by anyone -> ownership cannot be established
    res = DEEP.run_deep(base, {"A":"tokA","B":"tokB","C":"tokC"}, har={"log":{"entries":ents}},
                        token_map={"tokA":"A","tokB":"B","tokC":"C"}, scope=["127.0.0.1"])
    srv.shutdown()
    ok = len(res["confirmed"]) == 0
    print(f"C) unknown-owner     pivots={res['pivots']} confirmed={len(res['confirmed'])} "
          f"-> {'PASS' if ok else 'FAIL'} (expect 0: owner not established)")
    return ok

# ---- Attack D: alternate ignores the id (returns caller's own) ----
class HD(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        p = self.path.split("?")[0]; u = _who(self.headers)
        if p == "/api/activity":
            nxt = {"A":"B","B":"C","C":"A"}[u] if u else None
            return _J(self, 200, [{"invoice_id": INV[nxt]}]) if u else _J(self, 401, {})
        if p.startswith("/admin/api/invoice/"):
            if not u: return _J(self, 401, {})
            iid = p.rsplit("/", 1)[-1]
            return _J(self, 200, INVOICE[iid]) if OWNER_INV.get(iid) == u else _J(self, 403, {"error":"f"})
        if p.startswith("/api/billing/invoice/"):     # ignores path id: always caller's OWN
            return _J(self, 200, INVOICE[INV[u]]) if u else _J(self, 401, {})
        _J(self, 404, {})

def attack_D():
    srv, port = _mk(HD); base = f"http://127.0.0.1:{port}"; ents = []; nxt={"A":"B","B":"C","C":"A"}
    for k, tok in (("A","tokA"),("B","tokB"),("C","tokC")):
        ents.append(_entry(base,"GET","/api/activity",200,[{"invoice_id":INV[nxt[k]]}],tok))
        ents.append(_entry(base,"GET",f"/admin/api/invoice/{INV[k]}",200,INVOICE[INV[k]],tok))
        ents.append(_entry(base,"GET",f"/admin/api/invoice/{INV[nxt[k]]}",403,{"error":"f"},tok))
        ents.append(_entry(base,"GET",f"/api/billing/invoice/{INV[k]}",200,INVOICE[INV[k]],tok))
    res = DEEP.run_deep(base, {"A":"tokA","B":"tokB","C":"tokC"}, har={"log":{"entries":ents}},
                        token_map={"tokA":"A","tokB":"B","tokC":"C"}, scope=["127.0.0.1"])
    srv.shutdown()
    ok = len(res["confirmed"]) == 0
    print(f"D) ignores-id-alt    pivots={res['pivots']} confirmed={len(res['confirmed'])} "
          f"-> {'PASS' if ok else 'FAIL'} (expect 0: IARC server-ignores-id)")
    return ok

def main():
    ok = True
    ok &= attack_A(); ok &= attack_B(); ok &= attack_C(); ok &= attack_D()
    print("\nADVERSARY-ALTPATHS-DEEP:", "PASS — the deep pivot resists self-leak, public doors, "
          "unknown ownership, and id-ignoring alternates. 0 false positives." if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
