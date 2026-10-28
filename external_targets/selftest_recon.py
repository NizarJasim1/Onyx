#!/usr/bin/env python3
"""selftest_recon.py — MEASURED proof for onyx_recon against labeled ground truth.

TRUE POSITIVES (must ALL be found):
  * vehicle-location BOLA   GET /identity/api/v2/vehicle/{id}/location            (mid-path id)
  * mechanic-report BOLA    GET /workshop/api/mechanic/mechanic_report?report_id= (QUERY id)
  * cross-account write     PUT /workshop/api/shop/orders/{id}                    (BFLA write)
FALSE POSITIVES (must be ZERO): auth/login (JWT), forget-password (revocation-shaped),
  change-email (message), shared community feed, public post reads, shared enum in a
  collection. Three principals (A,B,C) exercise the engine's three-way audit.
Run:  python3 external_targets/selftest_recon.py   (exit 0 = pass)
"""
import json, sys, threading, time, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import onyx_recon as R

JWT = "eyJhbGciOiJSUzI1NiJ9." + "x" * 300 + ".sig"
USERS = {"a@x.com": ("tokA", "A"), "b@x.com": ("tokB", "B"), "c@x.com": ("tokC", "C")}
VEH = {"A": "aaaa1111-1111-1111-1111-111111111111", "B": "bbbb2222-2222-2222-2222-222222222222",
       "C": "cccc3333-3333-3333-3333-333333333333"}
LOC = {VEH[k]: {"carId": VEH[k], "fullName": f"Name-{k}", "owner": f"{k.lower()}@x.com", "lat": k} for k in VEH}
RPT = {"A": "rep-A-777", "B": "rep-B-888", "C": "rep-C-999"}
REPORTS = {RPT[k]: {"report_id": RPT[k], "owner": f"{k.lower()}@x.com", "problem": f"issue-{k}"} for k in RPT}
ORD = {"A": {"id": "1001", "owner": "A", "status": "delivered"},
       "B": {"id": "2002", "owner": "B", "status": "delivered"},
       "C": {"id": "3003", "owner": "C", "status": "delivered"}}
BYID = {o["id"]: o for o in ORD.values()}
SHARED = "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"
SPEC = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {
    "/identity/api/auth/login": {"post": {}},
    "/identity/api/auth/forget-password": {"post": {}},
    "/identity/api/v2/user/change-email": {"post": {}},
    "/identity/api/v2/vehicle/vehicles": {"get": {}},
    "/identity/api/v2/vehicle/{vehicleId}/location": {"get": {}},
    "/workshop/api/mechanic/reports": {"get": {}},
    "/workshop/api/mechanic/mechanic_report": {"get": {"parameters": [
        {"name": "report_id", "in": "query", "required": True}]}},
    "/workshop/api/shop/orders": {"get": {}},
    "/workshop/api/shop/orders/{orderId}": {
        "put": {"requestBody": {"content": {"application/json": {"example": {"status": "returned"}}}}}},
    "/community/api/v2/community/posts/recent": {"get": {}},
    "/community/api/v2/community/posts/{postId}": {"get": {}},
}}
def _who(h):
    a = h.get("Authorization", ""); t = a.split(" ", 1)[1] if a.startswith("Bearer ") else ""
    return {"tokA": "A", "tokB": "B", "tokC": "C"}.get(t)
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _j(self, c, o):
        b = json.dumps(o).encode(); self.send_response(c)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def _b(self):
        n = int(self.headers.get("Content-Length") or 0)
        try: return json.loads(self.rfile.read(n) or b"{}")
        except Exception: return {}
    def do_POST(self):
        p = self.path.split("?")[0]; b = self._b()
        if p == "/identity/api/auth/login":
            u = USERS.get(b.get("email")); return self._j(200, {"token": u[0]}) if u else self._j(403, {})
        if p == "/identity/api/auth/forget-password":
            return self._j(200, {"message": "OTP Sent on the provided email, adam007@example.com"})
        if p == "/identity/api/v2/user/change-email":
            return self._j(200, {"message": "token sent to your email.", "token": JWT})
        self._j(404, {})
    def do_PUT(self):
        p = self.path.split("?")[0]; b = self._b()
        if p.startswith("/workshop/api/shop/orders/"):
            oid = p.split("/")[5]
            if oid in BYID:                        # BFLA: no ownership check on write
                BYID[oid].update({k: b[k] for k in ("status",) if k in b}); return self._j(200, BYID[oid])
        self._j(404, {})
    def do_GET(self):
        p = self.path.split("?")[0]; u = _who(self.headers)
        q = parse_qs(urlparse(self.path).query)
        if p == "/openapi.json": return self._j(200, SPEC)
        if p == "/identity/api/v2/vehicle/vehicles":
            return self._j(200, [{"uuid": VEH[u], "categoryId": "1"}]) if u else self._j(401, {})
        if p.startswith("/identity/api/v2/vehicle/") and p.endswith("/location"):
            if not u: return self._j(401, {})            # BOLA is authed-but-unauthorized
            vid = p.split("/")[5]; return self._j(200, LOC[vid]) if vid in LOC else self._j(404, {})
        if p == "/workshop/api/mechanic/reports":
            return self._j(200, [{"report_id": RPT[u]}]) if u else self._j(401, {})
        if p == "/workshop/api/mechanic/mechanic_report":
            if not u: return self._j(401, {})
            rid = (q.get("report_id") or [None])[0]
            return self._j(200, REPORTS[rid]) if rid in REPORTS else self._j(404, {})   # BOLA via query id
        if p == "/workshop/api/shop/orders":
            return self._j(200, {"orders": [ORD[u]]}) if u else self._j(401, {})
        if p.startswith("/workshop/api/shop/orders/"):
            if not u: return self._j(401, {})
            oid = p.split("/")[5]; return self._j(200, BYID[oid]) if oid in BYID else self._j(404, {})
        if p == "/community/api/v2/community/posts/recent":
            return self._j(200, [{"id": "HVB2eBQh5Pg7qyeFSpMEbV", "vehicleid": SHARED, "authortoken": JWT}])
        if p.startswith("/community/api/v2/community/posts/"):
            return self._j(200, {"id": "HVB2eBQh5Pg7qyeFSpMEbV", "title": "public", "body": "same for all"})
        if p.startswith("/api/public/"):
            pid_ = p.split("/")[3]; return self._j(200, {"id": pid_, "secret": "PUBLIC-SECRET-DATA"})  # anon-readable
        if p.startswith("/api/whoami/"):
            if not u: return self._j(401, {})
            return self._j(200, {"id": p.split("/")[3], "owner": f"{u.lower()}@x.com", "me": u})  # ignores id, returns caller
        self._j(404, {})


def run(port=8787):
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start(); time.sleep(0.4)
    base = f"http://127.0.0.1:{port}"
    cli = R.Client(["127.0.0.1"], researcher="selftest")
    principals = {"A": "tokA", "B": "tokB", "C": "tokC"}
    doc = R._load_doc(base + "/openapi.json", cli); surface = R.ingest_openapi(doc)
    owned, pool, hrep = R.harvest(cli, base, surface, principals)
    plan = R.build_plan(surface, owned, pool, principals, confirm=True)
    owner_scoped = set(hrep["owner_scoped"])
    seeds = [(pid, "GET", e["path"]) for e in surface
             if e["method"] == "GET" and e["path"] in owner_scoped for pid in principals]
    cfg = {"base_url": base, "authorized": True, "dry_run": False, "researcher": "s", "program": "s",
           "principals": {p: {"value": t, "type": "bearer"} for p, t in principals.items()},
           "endpoints": plan, "seeds": seeds,
           "test_resources": sorted({i for e in plan for v in e["ids"].values() for i in v}),
           "engagement_id": "selftest"}
    from authpath.serve import _build_scan
    engine, _ = _build_scan(cfg)
    snap = engine.snapshot()
    grounded = {str(i) for v in pool.values() for i in v} | \
               {str(i) for e in plan for v in e.get("ids", {}).values() for i in v}
    gate_kept = [f for f in snap["findings"]
                 if R._is_probeable(str(f.get("endpoint", ""))) and R._looks_like_id(f.get("target", ""))
                 and str(f.get("target", "")) in grounded]
    ep_meta = R._ep_meta(plan)
    kept = []
    for f in gate_kept:
        ok, _why = R.reconfirm(cli, base, principals, pool, f, ep_meta)
        if ok:
            kept.append(f)
    return {"srv": srv, "surface": len(surface), "owned": owned, "pool": pool, "hrep": hrep,
            "plan": plan, "raw": snap["findings"], "kept": kept, "cli": cli,
            "principals": principals, "base": base, "ep_meta": ep_meta}


def main():
    r = run()
    cli, base, principals, pool, ep_meta = r["cli"], r["base"], r["principals"], r["pool"], r["ep_meta"]
    fails = []
    def kept_on(sub): return [f for f in r["kept"] if sub in f["endpoint"]]

    # ---- zero false positives (structural gate) ----
    if any("forget-password" in e["path"] for e in r["plan"]):
        fails.append("forget-password was probed (ledger poison)")
    if any(not R._is_probeable(e["path"]) for e in r["plan"]):
        fails.append("an auth/account/action endpoint was probed")
    if any("1" in v for v in r["pool"].values()):
        fails.append("shared enum '1' leaked into an ownership pool")
    bad = [f for f in r["kept"] if not (
        ("/vehicle/" in f["endpoint"] and f["endpoint"].endswith("/location")) or
        ("mechanic_report" in f["endpoint"]) or ("/shop/orders/{id}" in f["endpoint"]))]
    if bad:
        fails.append("false-positive(s) survived: " + "; ".join(f"{f['effect']} {f['endpoint']}" for f in bad))

    # ---- recall: all three labeled true positives SURVIVE the IARC (power preserved) ----
    if not any(f["endpoint"].endswith("/location") for f in r["kept"]):
        fails.append("MISS: vehicle-location BOLA dropped")
    if not kept_on("mechanic_report"):
        fails.append("MISS: query-id mechanic-report BOLA dropped")
    if not kept_on("/shop/orders/{id}"):
        fails.append("MISS: cross-account order WRITE (BFLA) dropped")

    # ---- MEASURED IARC discrimination (independent power): it must DROP a public
    #      resource and a server-ignores-id endpoint, and KEEP a real BOLA ----
    def synth(endpoint, method, target, actor, query_id=None):
        ep_meta[endpoint] = {"method": method, "path": endpoint, "query_id": query_id}
        return {"endpoint": endpoint, "target": target, "actor": actor, "owner": "B"}
    pub_keep, pub_why = R.reconfirm(cli, base, principals, pool,
                                    synth("/api/public/{id}", "GET", "pubobj9", "A"), ep_meta)
    who_keep, who_why = R.reconfirm(cli, base, principals, pool,
                                    synth("/api/whoami/{id}", "GET", pool["B"][0], "A"), ep_meta)
    real_keep, real_why = R.reconfirm(cli, base, principals, pool,
                                      synth("/identity/api/v2/vehicle/{id}/location", "GET",
                                            pool["B"][0], "A"), ep_meta)
    if pub_keep:
        fails.append(f"IARC failed to drop a PUBLIC resource (got: {pub_why})")
    if who_keep:
        fails.append(f"IARC failed to drop a server-ignores-id endpoint (got: {who_why})")
    if not real_keep:
        fails.append(f"IARC wrongly dropped a REAL BOLA (reduced power!): {real_why}")

    r["srv"].shutdown()

    print(f"principals=3(A,B,C)  surface={r['surface']}")
    print(f"owner-scoped={[x.split('/')[-1] for x in r['hrep']['owner_scoped']]}  "
          f"shared={[x.split('/')[-1] for x in r['hrep']['shared']]}")
    print(f"pool={ {p: v for p, v in r['pool'].items()} }")
    print(f"probes planned={len(r['plan'])}  raw findings={len(r['raw'])}  kept={len(r['kept'])}")
    for f in r["kept"]:
        print(f"   KEEP  {f['effect']:<14} {f['actor']} \u25b8 {str(f['target'])[:30]}  {f['endpoint']}")
    print(f"IARC discrimination:  public->{'DROP' if not pub_keep else 'KEEP'}   "
          f"server-ignores->{'DROP' if not who_keep else 'KEEP'}   real-BOLA->{'KEEP' if real_keep else 'DROP'}")
    print()
    if fails:
        print("SELF-TEST: FAIL")
        for x in fails: print("  \u2717", x)
        return 1
    print(f"SELF-TEST: PASS \u2014 {len(r['kept'])} genuine findings survive gate + independent "
          f"re-confirmation, 0 false positives; IARC drops public & server-ignores, keeps real BOLA.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
