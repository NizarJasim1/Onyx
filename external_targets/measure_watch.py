#!/usr/bin/env python3
"""measure_watch.py — MEASURED proof for Phase 6 (continuous diff). Two scans of the same
target: the second introduces a NEW BOLA (a regression). Watch must alert on exactly the new
confirmed finding, and stay silent when nothing changed.

Run:  python3 external_targets/measure_watch.py   (exit 0 = pass)
"""
import json, sys, threading, os, tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import watch as WATCH

USERS = {"tokA": "A", "tokB": "B", "tokC": "C"}
ORD = {"A": "1001", "B": "2002", "C": "3003"}
ORDER = {ORD[k]: {"id": ORD[k], "owner": f"{k.lower()}@x.com"} for k in ORD}
INV = {"A": "5001", "B": "5002", "C": "5003"}
INVOICE = {INV[k]: {"id": INV[k], "owner": f"{k.lower()}@x.com", "note": f"invoice-{k}"} for k in INV}
FLAGS = {"invoices_bolable": False}   # flipped on for the 2nd scan (a regression)

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
        if p == "/api/orders":
            return self._j(200, [ORDER[ORD[u]]]) if u else self._j(401, {})
        if p.startswith("/api/orders/"):            # always safe (ownership enforced)
            if not u: return self._j(401, {})
            oid = p.rsplit("/", 1)[-1]
            return self._j(200, ORDER[oid]) if (oid in ORDER and ORDER[oid]["owner"] == f"{u.lower()}@x.com") else self._j(403, {})
        if p == "/api/invoices":
            return self._j(200, [INVOICE[INV[u]]]) if u else self._j(401, {})
        if p.startswith("/api/invoices/"):
            if not u: return self._j(401, {})
            iid = p.rsplit("/", 1)[-1]
            if FLAGS["invoices_bolable"]:            # REGRESSION: ownership check removed
                return self._j(200, INVOICE[iid]) if iid in INVOICE else self._j(404, {})
            return self._j(200, INVOICE[iid]) if (iid in INVOICE and INVOICE[iid]["owner"] == f"{u.lower()}@x.com") else self._j(403, {})
        self._j(404, {})

def _har(base):
    ents = []
    for k, tok in (("A", "tokA"), ("B", "tokB"), ("C", "tokC")):
        for path, body in (("/api/orders", [ORDER[ORD[k]]]), (f"/api/orders/{ORD[k]}", ORDER[ORD[k]]),
                           ("/api/invoices", [INVOICE[INV[k]]]), (f"/api/invoices/{INV[k]}", INVOICE[INV[k]])):
            ents.append({"request": {"method": "GET", "url": base + path,
                        "headers": [{"name": "Authorization", "value": f"Bearer {tok}"}]},
                        "response": {"status": 200, "content": {"text": json.dumps(body)}}})
    return {"log": {"entries": ents}}

def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]; base = f"http://127.0.0.1:{port}"
    principals = {"A": "tokA", "B": "tokB", "C": "tokC"}; token_map = {"tokA": "A", "tokB": "B", "tokC": "C"}
    har = _har(base)
    bl = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name

    # scan 1 — establish baseline (both endpoints safe)
    FLAGS["invoices_bolable"] = False
    d1, _ = WATCH.watch_once(base, principals, har, baseline_path=bl, token_map=token_map, scope=["127.0.0.1"])
    # scan 2 — no change → must be silent
    d2, _ = WATCH.watch_once(base, principals, har, baseline_path=bl, token_map=token_map, scope=["127.0.0.1"])
    # scan 3 — a regression introduces invoice BOLA → must alert on exactly that
    FLAGS["invoices_bolable"] = True
    d3, _ = WATCH.watch_once(base, principals, har, baseline_path=bl, token_map=token_map, scope=["127.0.0.1"])
    srv.shutdown(); os.unlink(bl)

    quiet_when_unchanged = len(d2["new_confirmed"]) == 0
    alerted_on_regression = len(d3["new_confirmed"]) >= 1 and all(
        "/api/invoices/" in str(r["endpoint"]) for r in d3["new_confirmed"])
    print(f"  scan1 baseline new-confirmed : {len(d1['new_confirmed'])} (first run seeds baseline)")
    print(f"  scan2 unchanged              : new={len(d2['new_confirmed'])}  -> silent={quiet_when_unchanged}")
    print(f"  scan3 regression             : new={len(d3['new_confirmed'])}")
    for r in d3["new_confirmed"]:
        print(f"    [ALERT] {r['effect']} {r['endpoint']} {r['actor']}→{r['target']}")
    if quiet_when_unchanged and alerted_on_regression:
        print("\nMEASURE-WATCH: PASS — continuous diff is silent when nothing changes and alerts on exactly "
              "the newly confirmed regression (invoice BOLA). Alerts are Δstate-proven (Conductor output).")
        return 0
    print("\nMEASURE-WATCH: FAIL")
    return 1

if __name__ == "__main__":
    sys.exit(main())
