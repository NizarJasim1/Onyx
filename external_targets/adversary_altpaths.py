#!/usr/bin/env python3
"""adversary_altpaths.py — adversarial self-critique of Layer 4 (alt_paths).

Three attacks on the layer itself. Each must NOT produce a false positive.

  A) SERVER-IGNORES-ID alternate: the refused admin door has an alternate that returns the
     CALLER'S OWN order regardless of the id in the path (not object-scoped). A naive layer
     would flag a cross-principal 'success'. EXPECT: IARC drops it -> 0 confirmed.

  B) 404-NOT-403 refusal: the 'refused' door only ever returned 404 (missing resource), never
     401/403. That is NOT an authorization rule. EXPECT: 0 refusals learned from it, so no
     alternate is manufactured off a non-authz refusal.

  C) NO-ALTERNATE refusal: a door is genuinely refused and there is NO other door to that
     object type. EXPECT: refusal learned, but 0 alternate doors, 0 confirmed (nothing to
     route to — the layer does not invent a surface).
"""
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import alt_paths as L4

USERS = {"tokA": "A", "tokB": "B", "tokC": "C"}
ORD = {"A": "1001", "B": "2002", "C": "3003"}
OWNER_OF = {v: k for k, v in ORD.items()}
OBJ = {ORD[k]: {"id": ORD[k], "owner": f"{k.lower()}@x.com", "total": 100, "item": f"w-{k}"} for k in ORD}

def _who(h):
    a = h.get("Authorization", ""); t = a.split(" ", 1)[1] if a.startswith("Bearer ") else ""
    return USERS.get(t)

def _mk_server(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]

def _entry(base, method, path, status, body, tok):
    return {"request": {"method": method, "url": base + path,
            "headers": [{"name": "Authorization", "value": f"Bearer {tok}"}]},
            "response": {"status": status, "content": {"text": json.dumps(body) if body is not None else ""}}}

# ---------------- Attack A: server-ignores-id alternate ----------------
class HA(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _j(self, c, o):
        b = json.dumps(o).encode(); self.send_response(c); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        p = self.path.split("?")[0]; u = _who(self.headers)
        if p == "/shop/api/orders":
            return self._j(200, [OBJ[ORD[u]]]) if u else self._j(401, {})
        if p.startswith("/admin/api/order/"):
            if not u: return self._j(401, {})
            oid = p.rsplit("/",1)[-1]
            return self._j(200, OBJ[oid]) if OWNER_OF.get(oid)==u else self._j(403, {"error":"forbidden"})
        if p.startswith("/shop/api/order/"):
            # NOT object-scoped: always returns the CALLER'S OWN order, ignoring the path id
            return self._j(200, OBJ[ORD[u]]) if u else self._j(401, {})
        self._j(404, {})

def attack_A():
    srv, port = _mk_server(HA); base = f"http://127.0.0.1:{port}"
    ents = []
    for k, tok in (("A","tokA"),("B","tokB"),("C","tokC")):
        ents.append(_entry(base,"GET","/shop/api/orders",200,[OBJ[ORD[k]]],tok))
        other = "2002" if k!="B" else "1001"
        ents.append(_entry(base,"GET",f"/admin/api/order/{other}",403,{"error":"forbidden"},tok))
        ents.append(_entry(base,"GET",f"/shop/api/order/{ORD[k]}",200,OBJ[ORD[k]],tok))
    res = L4.run(base, {"A":"tokA","B":"tokB","C":"tokC"}, har={"log":{"entries":ents}},
                 token_map={"tokA":"A","tokB":"B","tokC":"C"}, scope=["127.0.0.1"])
    srv.shutdown()
    ok = len(res["confirmed"]) == 0
    print(f"A) server-ignores-id  refusals={res['refusals']} alts={res['alternates']} "
          f"confirmed={len(res['confirmed'])} -> {'PASS' if ok else 'FAIL'} (expect 0 confirmed)")
    return ok

# ---------------- Attack B: 404 is not an authz refusal ----------------
class HB(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _j(self, c, o):
        b = json.dumps(o).encode(); self.send_response(c); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        p = self.path.split("?")[0]; u = _who(self.headers)
        if p == "/shop/api/orders":
            return self._j(200, [OBJ[ORD[u]]]) if u else self._j(401, {})
        if p.startswith("/legacy/api/order/"):
            return self._j(404, {"error":"not found"})     # only ever 404, never 403
        if p.startswith("/shop/api/order/"):
            if not u: return self._j(401, {})
            oid = p.rsplit("/",1)[-1]
            return self._j(200, OBJ[oid]) if oid in OBJ else self._j(404, {})
        self._j(404, {})

def attack_B():
    srv, port = _mk_server(HB); base = f"http://127.0.0.1:{port}"
    ents = []
    for k, tok in (("A","tokA"),("B","tokB"),("C","tokC")):
        ents.append(_entry(base,"GET","/shop/api/orders",200,[OBJ[ORD[k]]],tok))
        ents.append(_entry(base,"GET",f"/legacy/api/order/{ORD[k]}",404,{"error":"not found"},tok))
        ents.append(_entry(base,"GET",f"/shop/api/order/{ORD[k]}",200,OBJ[ORD[k]],tok))
    res = L4.run(base, {"A":"tokA","B":"tokB","C":"tokC"}, har={"log":{"entries":ents}},
                 token_map={"tokA":"A","tokB":"B","tokC":"C"}, scope=["127.0.0.1"])
    srv.shutdown()
    # the 404 legacy door must NOT be counted as an authz refusal
    ok = res["refusals"] == 0
    print(f"B) 404-not-403        refusals={res['refusals']} alts={res['alternates']} "
          f"confirmed={len(res['confirmed'])} -> {'PASS' if ok else 'FAIL'} (expect 0 refusals)")
    return ok

# ---------------- Attack C: refusal with no alternate door ----------------
class HC(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _j(self, c, o):
        b = json.dumps(o).encode(); self.send_response(c); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        p = self.path.split("?")[0]; u = _who(self.headers)
        if p == "/shop/api/invoices":
            return self._j(200, [{"invoice_id": f"inv-{u}", "owner": f"{u}"}]) if u else self._j(401, {})
        if p.startswith("/admin/api/invoice/"):
            if not u: return self._j(401, {})
            return self._j(403, {"error":"forbidden"})       # refused, and the ONLY door
        self._j(404, {})

def attack_C():
    srv, port = _mk_server(HC); base = f"http://127.0.0.1:{port}"
    ents = []
    for k, tok in (("A","tokA"),("B","tokB"),("C","tokC")):
        ents.append(_entry(base,"GET","/shop/api/invoices",200,[{"invoice_id":f"inv-{k}"}],tok))
        ents.append(_entry(base,"GET",f"/admin/api/invoice/inv-{k}",403,{"error":"forbidden"},tok))
    res = L4.run(base, {"A":"tokA","B":"tokB","C":"tokC"}, har={"log":{"entries":ents}},
                 token_map={"tokA":"A","tokB":"B","tokC":"C"}, scope=["127.0.0.1"])
    srv.shutdown()
    ok = (res["refusals"] >= 1) and (len(res["confirmed"]) == 0)
    print(f"C) refusal-no-alt     refusals={res['refusals']} alts={res['alternates']} "
          f"confirmed={len(res['confirmed'])} -> {'PASS' if ok else 'FAIL'} (expect >=1 refusal, 0 confirmed)")
    return ok

def main():
    ok = True
    ok &= attack_A()
    ok &= attack_B()
    ok &= attack_C()
    print("\nADVERSARY-ALTPATHS:", "PASS — Layer 4 resists ignore-id, non-authz 404s, and never "
          "invents an alternate surface." if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
