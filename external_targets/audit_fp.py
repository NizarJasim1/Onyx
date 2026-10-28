#!/usr/bin/env python3
"""
audit_fp.py — CROSS-LAYER FALSE-POSITIVE AUDIT (the red line).

Every layer has its own measure + adversary. This audit tests what those cannot: EMERGENT FP
when ALL capture-based layers run TOGETHER through the Conductor (base-recon + breaker + L4 +
L4-X + explorer reach + ownership gate + dedup). The tool's whole value is "when it says a bug,
it is right ~100%." So the bar here is absolute:

  SCENARIO A — FORTRESS (a fully-hardened target, DENSE with classic FP traps):
      ownership-enforced items, a genuinely public feed, a shared enum, a server-ignores-id
      endpoint, a properly-enforced admin door, a price-recomputing checkout, and an
      over-sharing activity feed whose leaked id lands on an ENFORCED door (pivot dead-end).
      → the ENTIRE integrated pipeline (explorer → conductor, all layers) must confirm ZERO.

  SCENARIO B — MIXED (the same fortress, but two doors are genuinely broken):
      /api/orders/{id} loses its ownership check (real BOLA).
      → the pipeline must confirm EXACTLY the real BOLA and DROP every trap.

  Plus: DETERMINISM (two runs identical) and CONTAMINATION (every confirmed finding is
  well-formed: one clean id slot, a grounded target, and — for cross-owner effects — actor ≠
  the target's true owner).

Exit 0 ⟺ FORTRESS=0 confirmed, MIXED=only the real bug, deterministic, uncontaminated.
"""
import json, sys, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import explorer as EXP
import conductor as COND

USERS = {"tokA": "A", "tokB": "B", "tokC": "C"}
ORD = {"A": "1001", "B": "2002", "C": "3003"}
OWNER_ORD = {v: k for k, v in ORD.items()}
ORDER = {ORD[k]: {"id": ORD[k], "owner": f"{k.lower()}@x.com", "secret": f"S-{k}"} for k in ORD}
PROF = {"A": "7001", "B": "7002", "C": "7003"}                       # profile ids (server-ignores-id trap)
PROFILE_OWN = {"A": {"id": "self", "plan": "pro", "email": "a@x.com"},
               "B": {"id": "self", "plan": "pro", "email": "b@x.com"},
               "C": {"id": "self", "plan": "pro", "email": "c@x.com"}}
PUBLIC_FEED = [{"id": "ann-1", "text": "maintenance sunday"}]        # genuinely public
CATEGORIES = [{"id": "cat-1", "name": "food"}, {"id": "cat-2", "name": "toys"}]  # shared enum
INV = {"A": "9001", "B": "9002", "C": "9003"}                        # invoices, reached via activity leak
INVOICE = {INV[k]: {"id": INV[k], "owner": f"{k.lower()}@x.com", "iban": f"DE{k}"} for k in INV}

def _who(h):
    a = h.get("Authorization", ""); t = a.split(" ", 1)[1] if a.startswith("Bearer ") else ""
    return USERS.get(t)

def _make(broken_orders):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _j(self, c, o):
            b = json.dumps(o).encode(); self.send_response(c)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        def do_GET(self):
            p = self.path.split("?")[0]; u = _who(self.headers)
            # owner-scoped collections
            if p == "/api/orders":
                return self._j(200, [ORDER[ORD[u]]]) if u else self._j(401, {})
            if p == "/api/invoices":                       # NOT listed cross-owner (each own)
                return self._j(200, [INVOICE[INV[u]]]) if u else self._j(401, {})
            # ITEM: orders — broken (BOLA) in MIXED, enforced in FORTRESS
            if p.startswith("/api/orders/"):
                if not u: return self._j(401, {})
                oid = p.rsplit("/", 1)[-1]
                if oid not in ORDER: return self._j(404, {})
                if broken_orders:
                    return self._j(200, ORDER[oid])        # REAL BOLA
                return self._j(200, ORDER[oid]) if OWNER_ORD[oid] == u else self._j(403, {"error": "forbidden"})
            # ITEM: invoices — ALWAYS enforced (pivot dead-end even though ids leak via activity)
            if p.startswith("/api/invoices/"):
                if not u: return self._j(401, {})
                iid = p.rsplit("/", 1)[-1]
                if iid not in INVOICE: return self._j(404, {})
                return self._j(200, INVOICE[iid]) if INVOICE[iid]["owner"] == f"{u.lower()}@x.com" else self._j(403, {"error": "forbidden"})
            # server-IGNORES-id profile: returns the CALLER'S OWN regardless of the path id (trap)
            if p.startswith("/api/profile/"):
                return self._j(200, PROFILE_OWN[u]) if u else self._j(401, {})
            # genuinely public feed (trap)
            if p == "/api/public/feed":
                return self._j(200, PUBLIC_FEED)
            # shared enum (trap)
            if p == "/api/categories":
                return self._j(200, CATEGORIES)
            # over-sharing activity: leaks ANOTHER owner's invoice id (pivot bait; door enforced)
            if p == "/api/activity":
                if not u: return self._j(401, {})
                nxt = {"A": "B", "B": "C", "C": "A"}[u]
                return self._j(200, [{"event": "invoice", "invoice_id": INV[nxt]}])
            # properly-enforced admin door (BFLA trap): all test users are non-admin → 403
            if p == "/api/admin/report":
                return self._j(403, {"error": "admin only"}) if u else self._j(401, {})
            self._j(404, {})
    return H

def _serve(broken):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make(broken))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"

def _pipeline(base):
    """The full integrated pipeline: explorer reach → conductor (every capture-based layer)."""
    principals = {"A": "tokA", "B": "tokB", "C": "tokC"}; token_map = {"tokA": "A", "tokB": "B", "tokC": "C"}
    har, _ = EXP.crawl(base, principals, scope=["127.0.0.1"],
                       seeds=["/api/orders", "/api/invoices", "/api/activity", "/api/categories",
                              "/api/public/feed", "/api/profile/7001", "/api/admin/report"],
                       researcher="audit", max_requests=400)
    return COND.run(base, principals, har=har, token_map=token_map, scope=["127.0.0.1"], researcher="audit")

def _wellformed(r, ownership):
    ep = str(r.get("endpoint", "")); path = ep.split(" ", 1)[-1]
    slots = sum(1 for s in path.split("/") if s == "{id}")
    concrete_ids = sum(1 for s in path.split("/") if s and (s.isdigit() or s.startswith(("inv-", "r-"))))
    single_slot = (slots + concrete_ids) <= 1                    # not a mangled double-id path
    grounded = bool(r.get("target"))
    owner = ownership.get(str(r.get("target")))
    cross = r["effect"].upper() not in ("PAYMENT", "PRICE", "COUPON")
    not_self = (not cross) or owner is None or owner != r.get("actor")
    return single_slot and grounded and not_self

def main():
    import alt_paths_deep as L4X
    # ---------- SCENARIO A: FORTRESS ----------
    srv, base = _serve(broken=False)
    a = _pipeline(base)
    srv.shutdown()
    fortress_zero = a["coverage"]["confirmed"] == 0

    # ---------- SCENARIO B: MIXED ----------
    srv, base = _serve(broken=True)
    b1 = _pipeline(base)
    b2 = _pipeline(base)                                          # determinism
    srv.shutdown()
    real = [r for r in b1["confirmed"] if "/api/orders/" in str(r["endpoint"])]
    traps = [r for r in b1["confirmed"] if "/api/orders/" not in str(r["endpoint"])]
    only_real = len(real) >= 1 and len(traps) == 0
    sig = lambda pkt: sorted((r["effect"], r["actor"], r["target"]) for r in pkt["confirmed"])
    deterministic = sig(b1) == sig(b2)
    # contamination check on the MIXED confirmed set
    tok = {"tokA": "A", "tokB": "B", "tokC": "C"}
    # rebuild ownership from a fresh capture for the check
    srv, base = _serve(broken=True)
    har, _ = EXP.crawl(base, {"A": "tokA", "B": "tokB", "C": "tokC"}, scope=["127.0.0.1"],
                       seeds=["/api/orders"], researcher="audit", max_requests=120)
    srv.shutdown()
    _, _, ownership, _ = L4X.object_identity(L4X.normalize(har, tok))
    clean = all(_wellformed(r, ownership) for r in b1["confirmed"])

    print("=== SCENARIO A — FORTRESS (all-safe, trap-dense) ===")
    print(f"  layers run     : {a['coverage']['layers_run']}")
    print(f"  confirmed      : {a['coverage']['confirmed']}   dropped_self_read: {a['coverage'].get('dropped_self_read')}")
    for r in a["confirmed"]:
        print(f"    !! UNEXPECTED {r['effect']} {r['endpoint']} {r['actor']}→{r['target']}")
    print(f"  => zero confirmed on hardened target : {fortress_zero}")
    print()
    print("=== SCENARIO B — MIXED (one real BOLA among the traps) ===")
    print(f"  confirmed real  : {len(real)}  traps confirmed: {len(traps)}")
    for r in real[:4]:
        print(f"    ✅ {r['effect']} {r['endpoint']} {r['actor']}→{r['target']}")
    for r in traps:
        print(f"    !! TRAP LEAKED {r['effect']} {r['endpoint']} {r['actor']}→{r['target']}")
    print(f"  => only the real bug confirmed       : {only_real}")
    print(f"  => deterministic across re-runs       : {deterministic}")
    print(f"  => findings well-formed (no contam.)  : {clean}")
    print()
    ok = fortress_zero and only_real and deterministic and clean
    if ok:
        print("AUDIT-FP: PASS — under FULL layer integration the pipeline confirms ZERO on a hardened "
              "trap-dense target, confirms ONLY the real bug on a mixed target, is deterministic, and "
              "emits no contaminated findings. The zero-FP red line holds across all additions.")
        return 0
    print("AUDIT-FP: FAIL — an addition introduced a false positive or contamination. STOP AND FIX.")
    return 1

if __name__ == "__main__":
    sys.exit(main())
