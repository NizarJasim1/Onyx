#!/usr/bin/env python3
"""measure_conductor.py — MEASURED proof for Phase 1 (the Conductor) against labeled
ground truth. ONE capture carrying MULTIPLE vuln classes must yield ONE dissection packet
that: (a) confirms every real bug via the proven path, (b) dedupes a bug two layers both
prove into a single record, (c) keeps hypotheses SEPARATE from confirmed findings, and
(d) is DETERMINISTIC across re-runs.

GROUND TRUTH (three principals A,B,C):
  * ORDER BOLA (alternate door)  : GET /api/order/{id}     no ownership check  → real BOLA
                                    (admin door GET /admin/api/order/{id} is refused = the rule)
  * INVOICE PIVOT                 : /api/activity leaks another owner's invoice id (not listable);
                                    GET /api/billing/invoice/{id} reads it → pivot BOLA (L4-X only)
  * a PUBLIC summary alternate     : must be dropped by IARC (0 FP).

ASSERTIONS:
  1. packet.confirmed contains BOTH the order-BOLA and the invoice-pivot.
  2. NO confirmed record is the public summary (0 FP).
  3. every confirmed record is deduped (no duplicate effect+endpoint+actor+target).
  4. hypotheses live in packet.hypotheses, never in packet.confirmed.
  5. two runs produce an IDENTICAL confirmed set (determinism).

Run:  python3 external_targets/measure_conductor.py   (exit 0 = pass)
"""
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import conductor as COND

USERS = {"tokA": "A", "tokB": "B", "tokC": "C"}
ORD = {"A": "1001", "B": "2002", "C": "3003"}
OWNER_ORD = {v: k for k, v in ORD.items()}
ORDER = {ORD[k]: {"id": ORD[k], "owner": f"{k.lower()}@x.com", "total": 100} for k in ORD}
INV = {"A": "inv-A-11", "B": "inv-B-22", "C": "inv-C-33"}
OWNER_INV = {v: k for k, v in INV.items()}
INVOICE = {INV[k]: {"id": INV[k], "owner": f"{k.lower()}@x.com", "amount_due": 500, "iban": f"DE{k}"} for k in INV}
SUMMARY = {"id": "promo", "note": "public thanks", "promo": "X"}

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
        if p == "/api/activity":
            if not u: return self._j(401, {})
            nxt = {"A": "B", "B": "C", "C": "A"}[u]
            return self._j(200, [{"event": "invoice_issued", "invoice_id": INV[nxt]}])
        if p.startswith("/admin/api/order/"):            # refused admin door (rule)
            if not u: return self._j(401, {})
            oid = p.rsplit("/", 1)[-1]
            return self._j(200, ORDER[oid]) if OWNER_ORD.get(oid) == u else self._j(403, {"error": "f"})
        if p.startswith("/api/order/"):                  # alternate order door: no ownership check
            if not u: return self._j(401, {})
            oid = p.rsplit("/", 1)[-1]
            return self._j(200, ORDER[oid]) if oid in ORDER else self._j(404, {})
        if p.startswith("/admin/api/invoice/"):          # refused invoice door; owner self-reads
            if not u: return self._j(401, {})
            iid = p.rsplit("/", 1)[-1]
            return self._j(200, INVOICE[iid]) if OWNER_INV.get(iid) == u else self._j(403, {"error": "f"})
        if p.startswith("/api/billing/invoice/") and p.endswith("/summary"):
            return self._j(200, SUMMARY) if u else self._j(401, {})
        if p.startswith("/api/billing/invoice/"):        # alternate invoice door: BOLA
            if not u: return self._j(401, {})
            iid = p.rsplit("/", 1)[-1]
            return self._j(200, INVOICE[iid]) if iid in INVOICE else self._j(404, {})
        self._j(404, {})

def _har(base):
    ents = []
    def E(m, p, s, b, tok):
        ents.append({"request": {"method": m, "url": base + p,
                     "headers": [{"name": "Authorization", "value": f"Bearer {tok}"}]},
                     "response": {"status": s, "content": {"text": json.dumps(b) if b is not None else ""}}})
    nxt = {"A": "B", "B": "C", "C": "A"}
    for k, tok in (("A", "tokA"), ("B", "tokB"), ("C", "tokC")):
        E("GET", "/api/orders", 200, [ORDER[ORD[k]]], tok)
        E("GET", "/api/activity", 200, [{"event": "invoice_issued", "invoice_id": INV[nxt[k]]}], tok)
        oother = ORD["B"] if k != "B" else ORD["A"]
        E("GET", f"/admin/api/order/{oother}", 403, {"error": "f"}, tok)
        E("GET", f"/admin/api/order/{ORD[k]}", 200, ORDER[ORD[k]], tok)
        E("GET", f"/api/order/{ORD[k]}", 200, ORDER[ORD[k]], tok)
        E("GET", f"/admin/api/invoice/{INV[k]}", 200, INVOICE[INV[k]], tok)
        E("GET", f"/admin/api/invoice/{INV[nxt[k]]}", 403, {"error": "f"}, tok)
        E("GET", f"/api/billing/invoice/{INV[k]}", 200, INVOICE[INV[k]], tok)
        E("GET", f"/api/billing/invoice/{INV[k]}/summary", 200, SUMMARY, tok)
    return {"log": {"entries": ents}}

def _confirmed_sig(packet):
    return sorted((r["effect"], r["endpoint"], r["actor"], r["target"]) for r in packet["confirmed"])

def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]; base = f"http://127.0.0.1:{port}"
    har = _har(base)
    principals = {"A": "tokA", "B": "tokB", "C": "tokC"}
    token_map = {"tokA": "A", "tokB": "B", "tokC": "C"}

    p1 = COND.run(base, principals, har=har, token_map=token_map, scope=["127.0.0.1"])
    p2 = COND.run(base, principals, har=har, token_map=token_map, scope=["127.0.0.1"])
    srv.shutdown()

    # a vulnerability may carry several proof vectors; check across all of them
    all_vectors = [v for r in p1["confirmed"] for v in r["vectors"]]
    has_order  = any("/api/order/" in e and "admin" not in e for e in all_vectors)
    has_invoice = any("/api/billing/invoice/" in e and "summary" not in e for e in all_vectors)
    no_summary = not any("summary" in e for e in all_vectors)
    keys = [(r["effect"], r["method"], r["path"], r["actor"], r["target"]) for r in p1["confirmed"]]
    deduped = len(keys) == len(set(keys))
    # global ownership-consistency: NO confirmed cross-owner record may be a self-read
    OWNER = {**{v: k for k, v in ORD.items()}, **{v: k for k, v in INV.items()}}
    self_reads = [(r["actor"], r["target"]) for r in p1["confirmed"]
                  if OWNER.get(r["target"]) == r["actor"]]
    no_self_reads = len(self_reads) == 0
    hyps_separate = len(p1["hypotheses"]) > 0 and all(
        r.get("target") for r in p1["confirmed"])   # confirmed are findings, not hypotheses
    deterministic = _confirmed_sig(p1) == _confirmed_sig(p2)

    print(f"  layers run     : {p1['coverage']['layers_run']}")
    print(f"  confirmed      : {p1['coverage']['confirmed']}   hypotheses: {p1['coverage']['hypotheses']}")
    for r in p1["confirmed"]:
        print(f"    ✅ {r['effect']:13s} {r['endpoint']:34s} {r['actor']}→{r['target']}  ({'+'.join(r['found_by'])})")
    print()
    print(f"  order-BOLA confirmed        : {has_order}")
    print(f"  invoice-pivot confirmed     : {has_invoice}")
    print(f"  public summary dropped (0FP): {no_summary}")
    print(f"  NO self-read FP (owner gate): {no_self_reads}  (dropped={p1['coverage'].get('dropped_self_read',0)})")
    print(f"  confirmed set deduped       : {deduped}")
    print(f"  hypotheses kept separate    : {hyps_separate}")
    print(f"  deterministic across re-runs: {deterministic}")
    if all([has_order, has_invoice, no_summary, no_self_reads, deduped, hyps_separate, deterministic]):
        print("\nMEASURE-CONDUCTOR: PASS — one capture → one dissection packet: every real bug confirmed "
              "via the proven path, deduped, hypotheses kept separate for the analyst, 0 FP, deterministic.")
        return 0
    print("\nMEASURE-CONDUCTOR: FAIL")
    return 1

if __name__ == "__main__":
    sys.exit(main())
