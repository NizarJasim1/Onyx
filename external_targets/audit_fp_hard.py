#!/usr/bin/env python3
"""
audit_fp_hard.py — DEEP ADVERSARIAL FALSE-POSITIVE HUNT.

This is the "try hard to break it" audit. Each scenario is a SAFE server built to LOOK like a
bug to a naive scanner — the exact shapes that make lesser tools cry wolf. The full pipeline
(explorer reach → conductor: base-recon + breaker + L4 + L4-X + ownership gate + dedup) runs
against each. A real zero-FP tool must confirm ZERO on every trap. A POSITIVE CONTROL (a genuine
BOLA) must still confirm — otherwise "zero FP" would be the empty triumph of a tool that finds
nothing.

TRAPS (all safe):
  T01 seq-ids-enforced   : guessable 1,2,3 ids, but every item read is ownership-checked (403).
  T02 echo-id            : item echoes the REQUESTED id in the body but returns the CALLER'S data.
  T03 field-collision    : cross-readable, but all substantive fields identical across owners
                           (no owner-distinguishing data → nothing PROVABLE → must abstain).
  T04 volatile-fields    : enforced item whose response carries a fresh nonce/timestamp each read.
  T05 shared-tenant      : an object BOTH A and B legitimately list & read (shared by design).
  T06 error-body-with-id : cross-owner attempt returns 403 whose JSON body echoes the victim id.
  T07 redirect-302       : cross-owner attempt 302-redirects to /login (no data).
  T08 empty-204          : cross-owner attempt returns 204 No Content.
  T09 public-cdn         : /api/assets/{id} fully public (no auth), identical for everyone.
  T10 pagination-cursor  : collection returns an id-shaped `next_cursor` that must not be probed.
  CTRL positive-control  : /api/orders/{id} with NO ownership check — a REAL BOLA (must confirm).

Exit 0 ⟺ every trap = 0 confirmed AND the positive control > 0.
"""
import json, sys, threading, os, time, itertools
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import explorer as EXP
import conductor as COND

USERS = {"tokA": "A", "tokB": "B", "tokC": "C"}
# per-owner numeric ids
OID = {"A": "1", "B": "2", "C": "3"}
OWNER = {v: k for k, v in OID.items()}
_counter = itertools.count()

def _who(h):
    a = h.get("Authorization", ""); t = a.split(" ", 1)[1] if a.startswith("Bearer ") else ""
    return USERS.get(t)

def _own_obj(u, oid):
    return {"id": oid, "owner": f"{u.lower()}@x.com", "secret": f"S-{u}", "plan": "pro"}

def _make(mode):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _j(self, c, o, headers=None):
            b = json.dumps(o).encode() if o is not None else b""
            self.send_response(c)
            for k, v in (headers or {}).items(): self.send_header(k, v)
            if o is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers()
            if b: self.wfile.write(b)
        def do_GET(self):
            p = self.path.split("?")[0]; u = _who(self.headers)

            # collection each principal owns (drives harvest) — used by most traps
            if p == "/api/orders":
                return self._j(200, [{"id": OID[u], "owner": f"{u.lower()}@x.com"}]) if u else self._j(401, {})

            if p.startswith("/api/orders/"):
                if not u: return self._j(401, {})
                oid = p.rsplit("/", 1)[-1]
                owner = OWNER.get(oid)
                # ---- CONTROL: real BOLA (no ownership check) ----
                if mode == "control":
                    return self._j(200, _own_obj(owner, oid)) if owner else self._j(404, {})
                # ---- T01 seq-ids-enforced / default enforced ----
                if mode in ("seq_enforced", "volatile", "error_body", "redirect", "empty204", "field_collision", "echo_id", "shared_tenant"):
                    is_owner = (owner == u)
                    if is_owner:
                        if mode == "volatile":
                            obj = _own_obj(u, oid); obj["nonce"] = next(_counter); obj["ts"] = time.time()
                            return self._j(200, obj)
                        if mode == "field_collision":
                            return self._j(200, {"id": oid, "status": "active", "tier": "gold"})  # identical for all owners
                        return self._j(200, _own_obj(u, oid))
                    # non-owner (the cross-principal attack):
                    if mode == "echo_id":
                        # returns the CALLER'S OWN data but echoes the requested (victim) id
                        return self._j(200, {"id": oid, "owner": f"{u.lower()}@x.com", "secret": f"S-{u}", "plan": "pro"})
                    if mode == "field_collision":
                        return self._j(200, {"id": oid, "status": "active", "tier": "gold"})  # readable but nothing distinguishing
                    if mode == "error_body":
                        return self._j(403, {"error": "forbidden", "requested_id": oid, "owner_hint": owner})
                    if mode == "redirect":
                        return self._j(302, None, headers={"Location": "/login"})
                    if mode == "empty204":
                        return self._j(204, None)
                    if mode == "shared_tenant":
                        return self._j(200, _own_obj(u, oid))  # returns own; (shared handled at collection)
                    return self._j(403, {"error": "forbidden"})  # seq_enforced, volatile default
                return self._j(404, {})

            # ---- T05 shared-tenant: A and B BOTH list & read the SAME shared object X ----
            if p == "/api/shared":
                if u in ("A", "B"): return self._j(200, [{"id": "X-9", "owner": "team", "doc": "roadmap"}])
                return self._j(200, []) if u else self._j(401, {})
            if p.startswith("/api/shared/"):
                if not u: return self._j(401, {})
                sid = p.rsplit("/", 1)[-1]
                if sid == "X-9" and u in ("A", "B"):
                    return self._j(200, {"id": "X-9", "owner": "team", "doc": "roadmap"})  # legit shared
                return self._j(403, {})

            # ---- T09 public-cdn: fully public asset, identical for all, no auth ----
            if p.startswith("/api/assets/"):
                aid = p.rsplit("/", 1)[-1]
                return self._j(200, {"id": aid, "url": "https://cdn/x.png", "kind": "logo"})

            # ---- T10 pagination-cursor ----
            if p == "/api/feed":
                if not u: return self._j(401, {})
                return self._j(200, {"data": [{"id": f"post-{OID[u]}"}],
                                     "next_cursor": "eyJvZmZzZXQiOjEwfQ"})   # base64-ish cursor, not an object id

            self._j(404, {})
    return H

def _serve(mode):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"

def _pipeline(base, seeds):
    principals = {"A": "tokA", "B": "tokB", "C": "tokC"}; token_map = {"tokA": "A", "tokB": "B", "tokC": "C"}
    har, _ = EXP.crawl(base, principals, scope=["127.0.0.1"], seeds=seeds, researcher="hard", max_requests=400)
    pkt = COND.run(base, principals, har=har, token_map=token_map, scope=["127.0.0.1"], researcher="hard")
    return pkt

TRAPS = [
    ("T01 seq-ids-enforced", "seq_enforced", ["/api/orders", "/api/orders/1", "/api/orders/2", "/api/orders/3"]),
    ("T02 echo-id",          "echo_id",      ["/api/orders", "/api/orders/1", "/api/orders/2", "/api/orders/3"]),
    ("T03 field-collision",  "field_collision", ["/api/orders", "/api/orders/1", "/api/orders/2", "/api/orders/3"]),
    ("T04 volatile-fields",  "volatile",     ["/api/orders", "/api/orders/1", "/api/orders/2", "/api/orders/3"]),
    ("T05 shared-tenant",    "shared_tenant",["/api/shared", "/api/shared/X-9", "/api/orders"]),
    ("T06 error-body-with-id","error_body",  ["/api/orders", "/api/orders/1", "/api/orders/2", "/api/orders/3"]),
    ("T07 redirect-302",     "redirect",     ["/api/orders", "/api/orders/1", "/api/orders/2", "/api/orders/3"]),
    ("T08 empty-204",        "empty204",     ["/api/orders", "/api/orders/1", "/api/orders/2", "/api/orders/3"]),
    ("T09 public-cdn",       "control",      ["/api/assets/logo-1", "/api/assets/logo-2"]),  # assets public; orders control off here
    ("T10 pagination-cursor","seq_enforced", ["/api/feed"]),
]

def main():
    results = []
    # traps
    for label, mode, seeds in TRAPS:
        srv, base = _serve(mode)
        pkt = _pipeline(base, seeds)
        srv.shutdown()
        # for T09 we only seeded assets (public) — orders control not reachable, so expect 0
        n = pkt["coverage"]["confirmed"]
        # exclude the /api/orders control leakage for T09 by construction (not seeded)
        results.append((label, n, pkt["confirmed"]))
    # positive control (must confirm)
    srv, base = _serve("control")
    ctrl = _pipeline(base, ["/api/orders", "/api/orders/1", "/api/orders/2", "/api/orders/3"])
    srv.shutdown()
    ctrl_n = ctrl["coverage"]["confirmed"]

    print("=== DEEP ADVERSARIAL FP HUNT ===\n")
    all_traps_clean = True
    for label, n, conf in results:
        status = "PASS" if n == 0 else "FALSE POSITIVE!"
        if n != 0:
            all_traps_clean = False
        print(f"  {label:26s}: confirmed={n}  -> {status}")
        for r in conf[:4]:
            print(f"        !! {r['effect']} {r['endpoint']} {r['actor']}→{r['target']}")
    print(f"\n  CTRL positive-control     : confirmed={ctrl_n}  -> {'PASS (real bug caught)' if ctrl_n >= 1 else 'FAIL (missed a real bug!)'}")
    ok = all_traps_clean and ctrl_n >= 1
    print()
    if ok:
        print("AUDIT-FP-HARD: PASS — zero false positives across 10 diverse realistic traps, and the "
              "positive control is still caught. This is real zero-FP, not vacuous.")
        return 0
    print("AUDIT-FP-HARD: FAIL — " + ("a trap produced a false positive. " if not all_traps_clean else "")
          + ("the positive control was missed. " if ctrl_n < 1 else ""))
    return 1

if __name__ == "__main__":
    sys.exit(main())
