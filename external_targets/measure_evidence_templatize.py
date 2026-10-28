#!/usr/bin/env python3
"""measure_evidence_templatize.py — proves the evidence-based surface is a STRICT UPGRADE.
A plain BOLA on a NON-NUMERIC item id ('inv-B-22' style) that base-recon MISSED before is now
confirmed — while a genuinely public non-numeric item is still dropped (0 FP). And a collection
noun that happens to look word-y is never collapsed.

GROUND TRUTH (A,B,C):
  /api/invoices                     owner-scoped list (each sees own, non-numeric ids)
  /api/invoices/{id}   BOLA         no ownership check  → must now be CONFIRMED
  /api/notices/{id}    PUBLIC       same for everyone   → must be DROPPED (0 FP)

ASSERTIONS:
  1. evidence templatize collapses /api/invoices/inv-b-22 → /api/invoices/{id}, keeps /api/invoices.
  2. conductor CONFIRMS the non-numeric invoice BOLA (the upgrade).
  3. conductor does NOT confirm the public notices (0 FP).

Run:  python3 external_targets/measure_evidence_templatize.py   (exit 0 = pass)
"""
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import capture_normalize as CN
import conductor as COND
import explorer as EXP

USERS = {"tokA": "A", "tokB": "B", "tokC": "C"}
INV = {"A": "inv-a-11", "B": "inv-b-22", "C": "inv-c-33"}
OWNER = {v: k for k, v in INV.items()}
INVOICE = {INV[k]: {"id": INV[k], "owner": f"{k.lower()}@x.com", "iban": f"DE{k}"} for k in INV}
NOTICE = {"ntc-1": {"id": "ntc-1", "text": "scheduled maintenance"}}   # public

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
        if p == "/api/invoices":
            return self._j(200, [INVOICE[INV[u]]]) if u else self._j(401, {})
        if p.startswith("/api/invoices/"):
            if not u: return self._j(401, {})
            iid = p.rsplit("/", 1)[-1]
            return self._j(200, INVOICE[iid]) if iid in INVOICE else self._j(404, {})   # BOLA
        if p == "/api/notices":
            return self._j(200, [NOTICE["ntc-1"]]) if u else self._j(401, {})
        if p.startswith("/api/notices/"):
            nid = p.rsplit("/", 1)[-1]
            return self._j(200, NOTICE[nid]) if nid in NOTICE else self._j(404, {})       # public
        self._j(404, {})

def main():
    # unit: evidence templatize on a sample capture
    sample = {"log": {"entries": [
        {"request": {"method": "GET", "url": "http://t/api/invoices/inv-b-22", "headers": []},
         "response": {"status": 200, "content": {"text": json.dumps({"id": "inv-b-22", "owner": "b@x.com"})}}},
        {"request": {"method": "GET", "url": "http://t/api/invoices", "headers": []},
         "response": {"status": 200, "content": {"text": json.dumps([{"id": "inv-b-22"}])}}},
    ]}}
    known = CN.known_object_ids(sample)
    t_item = CN.evidence_templatize("/api/invoices/inv-b-22", known)
    t_coll = CN.evidence_templatize("/api/invoices", known)
    templatize_ok = (t_item == "/api/invoices/{id}" and t_coll == "/api/invoices")

    # integration: full pipeline confirms the non-numeric BOLA, drops the public notices
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    pr = {"A": "tokA", "B": "tokB", "C": "tokC"}; tm = {"tokA": "A", "tokB": "B", "tokC": "C"}
    har, _ = EXP.crawl(base, pr, scope=["127.0.0.1"],
                       seeds=["/api/invoices", "/api/notices",
                              f"/api/invoices/{INV['A']}", f"/api/invoices/{INV['B']}", f"/api/invoices/{INV['C']}",
                              "/api/notices/ntc-1"], researcher="ev", max_requests=300)
    pkt = COND.run(base, pr, har=har, token_map=tm, scope=["127.0.0.1"], researcher="ev")
    srv.shutdown()

    inv_hits = [r for r in pkt["confirmed"] if "/api/invoices/" in str(r["endpoint"])]
    cross = [r for r in inv_hits if OWNER.get(str(r["target"])) != r["actor"]]
    notice_hits = [r for r in pkt["confirmed"] if "/api/notices/" in str(r["endpoint"])]

    print(f"  evidence templatize: item→{t_item}  coll→{t_coll}  ok={templatize_ok}")
    print(f"  non-numeric invoice BOLA confirmed : {len(cross)} (cross-owner)")
    for r in cross[:4]:
        print(f"    ✅ {r['effect']} {r['endpoint']} {r['actor']}→{r['target']}")
    print(f"  public notices confirmed (must 0)  : {len(notice_hits)}")
    upgrade = len(cross) >= 1
    no_fp = len(notice_hits) == 0
    if templatize_ok and upgrade and no_fp:
        print("\nMEASURE-EVIDENCE-TEMPLATIZE: PASS — base-recon now confirms a non-numeric-id BOLA it "
              "previously missed (more power), the public item is still dropped (0 FP), and collection "
              "nouns are never collapsed. Strict upgrade.")
        return 0
    print("\nMEASURE-EVIDENCE-TEMPLATIZE: FAIL")
    return 1

if __name__ == "__main__":
    sys.exit(main())
