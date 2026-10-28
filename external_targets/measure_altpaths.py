#!/usr/bin/env python3
"""measure_altpaths.py — MEASURED proof for LAYER 4 (alt_paths) against labeled ground truth.

We do NOT assume Layer 4 finds anything. We stand up a labeled localhost mock whose HAR
capture contains a REFUSED door plus two alternate doors to the SAME object type, then drive
the real Layer-4 code (alt_paths.run) — which confirms only through the PROVEN path.

GROUND TRUTH (three principals A,B,C):
  * REFUSED door : GET /admin/api/order/{id}   -> 403 for non-owners (an authz RULE)
  * ALT-TRUE     : GET /shop/api/order/{id}     -> no ownership check = REAL BOLA to the
                   same order object. EXPECT: Layer 4 proposes it AND the engine CONFIRMS
                   (cross-principal Delta-state read of another owner's order).
  * ALT-SAFE     : GET /shop/api/order/{id}/summary -> returns the SAME public marketing
                   blurb for every order regardless of owner (truly public).
                   EXPECT: Layer 4 may propose it, but IARC DROPS it (anonymous baseline
                   reproduces the data) -> 0 false positives.

PASS = ALT-TRUE confirmed  AND  ALT-SAFE not confirmed  AND  >=1 refusal learned.
Run:  python3 external_targets/measure_altpaths.py   (exit 0 = pass)
"""
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import alt_paths as L4

USERS = {"tokA": "A", "tokB": "B", "tokC": "C"}
# labeled ground truth: each principal owns exactly one order
ORD = {"A": "1001", "B": "2002", "C": "3003"}
OWNER_OF = {v: k for k, v in ORD.items()}
ORDER_OBJ = {ORD[k]: {"id": ORD[k], "owner": f"{k.lower()}@x.com", "total": 100 + i, "item": f"widget-{k}"}
             for i, k in enumerate(ORD)}
PUBLIC_BLURB = {"id": "marketing", "note": "Thanks for shopping with us!", "promo": "SUMMER"}

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
        # list endpoint so ONYX can harvest each principal's own order id
        if p == "/shop/api/orders":
            return self._j(200, [ORDER_OBJ[ORD[u]]]) if u else self._j(401, {})
        # REFUSED admin door: ownership enforced -> 403 for anyone but the owner
        if p.startswith("/admin/api/order/"):
            if not u: return self._j(401, {})
            oid = p.rsplit("/", 1)[-1]
            if oid in ORDER_OBJ and OWNER_OF.get(oid) == u:
                return self._j(200, ORDER_OBJ[oid])
            return self._j(403, {"error": "forbidden"})       # the RULE
        # ALT-SAFE public summary: same blurb for everyone (truly public)
        if p.startswith("/shop/api/order/") and p.endswith("/summary"):
            if not u: return self._j(401, {})
            return self._j(200, PUBLIC_BLURB)
        # ALT-TRUE shop door: NO ownership check -> real BOLA
        if p.startswith("/shop/api/order/"):
            if not u: return self._j(401, {})
            oid = p.rsplit("/", 1)[-1]
            return self._j(200, ORDER_OBJ[oid]) if oid in ORDER_OBJ else self._j(404, {})
        self._j(404, {})

def _build_har(port):
    """A capture where each principal (A,B,C) hits the admin door on ANOTHER owner's order
    (gets 403), reads its own via the list, and where the alt doors were exercised too —
    exactly what a proxy would record during browsing."""
    base = f"http://127.0.0.1:{port}"
    entries = []
    def E(method, url, status, body, tok):
        entries.append({"request": {"method": method, "url": url,
                        "headers": [{"name": "Authorization", "value": f"Bearer {tok}"}]},
                        "response": {"status": status,
                        "content": {"text": json.dumps(body) if body is not None else ""}}})
    for k, tok in (("A", "tokA"), ("B", "tokB"), ("C", "tokC")):
        E("GET", f"{base}/shop/api/orders", 200, [ORDER_OBJ[ORD[k]]], tok)
        # this principal is refused on the admin door for someone else's order
        other = "2002" if k != "B" else "1001"
        E("GET", f"{base}/admin/api/order/{other}", 403, {"error": "forbidden"}, tok)
        # and (as the owner) is allowed on the admin door for its OWN order
        E("GET", f"{base}/admin/api/order/{ORD[k]}", 200, ORDER_OBJ[ORD[k]], tok)
        # alt doors appear in the capture as normal browsing (own ids)
        E("GET", f"{base}/shop/api/order/{ORD[k]}", 200, ORDER_OBJ[ORD[k]], tok)
        E("GET", f"{base}/shop/api/order/{ORD[k]}/summary", 200, PUBLIC_BLURB, tok)
    return {"log": {"entries": entries}}

def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    base = f"http://127.0.0.1:{port}"
    har = _build_har(port)
    token_map = {"tokA": "A", "tokB": "B", "tokC": "C"}
    principals = {"A": "tokA", "B": "tokB", "C": "tokC"}

    res = L4.run(base, principals, har=har, token_map=token_map, scope=["127.0.0.1"],
                 researcher="measure-l4")
    srv.shutdown()

    print(f"  refusals learned   : {res['refusals']}")
    print(f"  alternate doors     : {res['alternates']}")
    for tag, note in res["notes"]:
        print(f"    plan[{tag}]: {note}")
    print(f"  raw engine cands    : {res['raw']}")
    confirmed_paths = set()
    for f in res["confirmed"]:
        ep = str(f.get("endpoint", "")); tgt = f.get("target")
        confirmed_paths.add(ep)
        print(f"    [CONFIRMED] {f.get('actor')} -> {tgt}  {ep}")

    got_true = any("/shop/api/order/{id}" in p and "summary" not in p for p in confirmed_paths)
    no_safe  = not any("summary" in p for p in confirmed_paths)
    learned  = res["refusals"] >= 1
    print()
    print(f"  ALT-TRUE confirmed (real BOLA via alternate door) : {got_true}")
    print(f"  ALT-SAFE dropped   (public summary, 0 FP)         : {no_safe}")
    print(f"  refusal learned    (>=1 authz rule seen)          : {learned}")
    if got_true and no_safe and learned:
        print("\nMEASURE-ALTPATHS: PASS — Layer 4 learns the refused admin door, routes to the "
              "same object via an alternate REST door, and the PROVEN path CONFIRMS the real "
              "BOLA while IARC drops the public summary. 0 false positives.")
        return 0
    print("\nMEASURE-ALTPATHS: FAIL")
    return 1

if __name__ == "__main__":
    sys.exit(main())
