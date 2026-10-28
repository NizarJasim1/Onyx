#!/usr/bin/env python3
"""measure_altpaths_deep.py — MEASURED proof for LAYER 4-X against labeled ground truth,
including the decisive test: the DEEP layer confirms a bug the BASE layer structurally MISSES.

Three principals A,B,C. Object types: order (listable) and invoice (NOT listable — you can
only reach an invoice by id).

GROUND TRUTH:
  * REFUSED direct door : GET /admin/api/invoice/{id}  -> 403 for non-owner (an authz RULE);
                          the OWNER can self-read it (200) — that establishes ownership.
  * LEAK door           : GET /api/activity            -> returns another owner's invoice id
                          (over-sharing feed). This is how A learns B's invoice id exists.
  * ALTERNATE door      : GET /api/billing/invoice/{id} -> NO ownership check = REAL BOLA.
  * invoices appear in NO owner-scoped collection, so BASE Layer 4 never probes them.

DECISIVE ASSERTIONS:
  1. BASE alt_paths.run(...)      -> 0 invoice findings   (it cannot reach the id).
  2. DEEP alt_paths_deep.run_deep -> >=1 CONFIRMED cross-owner invoice read via the pivot.
  3. A public 'summary' alternate is present -> DEEP must NOT confirm it (IARC drops) = 0 FP.

PASS = base misses it  AND  deep confirms the real pivot  AND  deep drops the public one.
Run:  python3 external_targets/measure_altpaths_deep.py   (exit 0 = pass)
"""
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import alt_paths as BASE
import alt_paths_deep as DEEP

USERS = {"tokA": "A", "tokB": "B", "tokC": "C"}
ORD = {"A": "1001", "B": "2002", "C": "3003"}
OWNER_ORD = {v: k for k, v in ORD.items()}
ORDER = {ORD[k]: {"id": ORD[k], "owner": f"{k.lower()}@x.com", "total": 100} for k in ORD}
INV = {"A": "inv-A-111", "B": "inv-B-222", "C": "inv-C-333"}
OWNER_INV = {v: k for k, v in INV.items()}
INVOICE = {INV[k]: {"id": INV[k], "owner": f"{k.lower()}@x.com", "amount_due": 500 + i, "iban": f"DE{k}"}
           for i, k in enumerate(INV)}
SUMMARY = {"id": "promo", "note": "Thank you for your business", "promo": "AUTUMN"}

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
        if p == "/api/orders":                                  # owner-scoped collection (orders only)
            return self._j(200, [ORDER[ORD[u]]]) if u else self._j(401, {})
        if p == "/api/activity":                                # LEAK: over-shares another owner's invoice id
            if not u: return self._j(401, {})
            # each principal's activity shows the NEXT principal's invoice id (cross-owner disclosure)
            nxt = {"A": "B", "B": "C", "C": "A"}[u]
            return self._j(200, [{"event": "invoice_issued", "invoice_id": INV[nxt], "for": nxt}])
        if p.startswith("/admin/api/invoice/"):                 # REFUSED direct door (owner may self-read)
            if not u: return self._j(401, {})
            iid = p.rsplit("/", 1)[-1]
            if iid in INVOICE and OWNER_INV.get(iid) == u:
                return self._j(200, INVOICE[iid])               # self-read -> establishes ownership
            return self._j(403, {"error": "forbidden"})         # the RULE
        if p.startswith("/api/billing/invoice/") and p.endswith("/summary"):
            if not u: return self._j(401, {})
            return self._j(200, SUMMARY)                        # public-ish alternate (IARC must drop)
        if p.startswith("/api/billing/invoice/"):               # ALTERNATE door: no ownership check = BOLA
            if not u: return self._j(401, {})
            iid = p.rsplit("/", 1)[-1]
            return self._j(200, INVOICE[iid]) if iid in INVOICE else self._j(404, {})
        self._j(404, {})

def _har(base):
    ents = []
    def E(method, path, status, body, tok):
        ents.append({"request": {"method": method, "url": base + path,
                     "headers": [{"name": "Authorization", "value": f"Bearer {tok}"}]},
                     "response": {"status": status, "content": {"text": json.dumps(body) if body is not None else ""}}})
    nxt = {"A": "B", "B": "C", "C": "A"}
    for k, tok in (("A", "tokA"), ("B", "tokB"), ("C", "tokC")):
        E("GET", "/api/orders", 200, [ORDER[ORD[k]]], tok)
        E("GET", "/api/activity", 200, [{"event": "invoice_issued", "invoice_id": INV[nxt[k]], "for": nxt[k]}], tok)
        # owner self-reads its own invoice via the admin door (establishes ownership)
        E("GET", f"/admin/api/invoice/{INV[k]}", 200, INVOICE[INV[k]], tok)
        # this principal is refused on the admin door for the leaked (other owner's) invoice
        E("GET", f"/admin/api/invoice/{INV[nxt[k]]}", 403, {"error": "forbidden"}, tok)
        # normal browsing touched the alternate + its summary on its OWN invoice
        E("GET", f"/api/billing/invoice/{INV[k]}", 200, INVOICE[INV[k]], tok)
        E("GET", f"/api/billing/invoice/{INV[k]}/summary", 200, SUMMARY, tok)
    return {"log": {"entries": ents}}

def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]; base = f"http://127.0.0.1:{port}"
    har = _har(base)
    principals = {"A": "tokA", "B": "tokB", "C": "tokC"}
    token_map = {"tokA": "A", "tokB": "B", "tokC": "C"}

    base_res = BASE.run(base, principals, har=har, token_map=token_map, scope=["127.0.0.1"])
    deep_res = DEEP.run_deep(base, principals, har=har, token_map=token_map, scope=["127.0.0.1"])
    srv.shutdown()

    def _invoice_hits(res):
        return [f for f in res["confirmed"]
                if "invoice" in str(f.get("endpoint", "")) and "summary" not in str(f.get("endpoint", ""))]

    base_inv = _invoice_hits(base_res)
    deep_inv = _invoice_hits(deep_res)
    deep_summary = [f for f in deep_res["confirmed"] if "summary" in str(f.get("endpoint", ""))]

    print(f"  BASE   confirmed={len(base_res['confirmed'])}  invoice-hits={len(base_inv)}")
    print(f"  DEEP   refusals={deep_res['refusals']}  id-links={deep_res['id_links']}  "
          f"pivots={deep_res['pivots']}  authz-keys={len(deep_res['authz_keys'])}  "
          f"confirmed={len(deep_res['confirmed'])}  invoice-hits={len(deep_inv)}")
    for tag, n in deep_res["notes"]:
        if tag == "pivot":
            print(f"    {n}")
    for f in deep_inv:
        print(f"    [CONFIRMED pivot] {f.get('actor')} -> {f.get('target')}  {f.get('endpoint')}")

    base_misses = len(base_inv) == 0
    deep_finds  = len(deep_inv) >= 1
    no_fp       = len(deep_summary) == 0
    print()
    print(f"  BASE misses the invoice pivot (id in no collection) : {base_misses}")
    print(f"  DEEP confirms the cross-owner invoice read (pivot)  : {deep_finds}")
    print(f"  DEEP drops the public summary alternate (0 FP)      : {no_fp}")
    if base_misses and deep_finds and no_fp:
        print("\nMEASURE-ALTPATHS-DEEP: PASS — Layer 4-X pivots through a leaked cross-owner id that "
              "the base layer structurally cannot reach, confirms the real BOLA via the proven path, "
              "and IARC still drops the public alternate. Qualitative leap, 0 false positives.")
        return 0
    print("\nMEASURE-ALTPATHS-DEEP: FAIL")
    return 1

if __name__ == "__main__":
    sys.exit(main())
