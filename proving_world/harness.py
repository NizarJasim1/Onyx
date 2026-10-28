"""
PROVING-WORLD HARNESS — drives ONYX against the live isolated app as a black box.
=================================================================================
The attacker discovers object ids the way a real attacker does — by ENUMERATION
(sequential ids) and by reading LEAKED ids out of responses (a community feed that
exposes vehicle uuids) — NEVER from the oracle. ONYX observes each principal's own
legitimate access, then the cross-principal attacks, and confirms by Δstate using
the live app's real read-backs. Findings are scored against the oracle that was
SEALED before the run.

This is the ONYX side; it imports authpath. The target (`world.py`) does not import
authpath. The only channel between them is HTTP-shaped request/response.
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig

from world import World


class WorldTarget:
    """Adapts the live World to ONYX's Target protocol. ONYX sees only responses;
    the app computes them from real state (so confirmer read-backs are genuine)."""
    host = "world.test"

    def __init__(self, world: World):
        self.world = world

    def send(self, req: HTTPRequest, principal: Principal) -> HTTPResponse:
        status, body = self.world.handle(req.method, req.path, principal.pid,
                                          dict(req.query or {}), req.body)
        return HTTPResponse(status, body)


def _endpoint_of(path: str, method: str) -> str | None:
    """Map a request path to its guarded-endpoint key (for scoring)."""
    if path.startswith("/world/vehicle/") and path.endswith("/location"):
        return "vehicle_location"
    if path == "/world/report":
        return "mechanic_report"
    if path.startswith("/world/order/"):
        return "order_status" if method == "PUT" else "order_read"
    if path.startswith("/world/video/"):
        return "video_read"
    if path.startswith("/world/admin/videos/"):
        return "admin_delete_video"
    if path == "/world/feed":
        return "community_feed"
    if path == "/world/management/users":
        return "users_directory"
    return None


def run_world(seed: int, n_users: int = 3) -> dict:
    world = World(seed, n_users)
    oracle = world.oracle()
    seal = world.oracle_seal()                      # sealed BEFORE any attack
    target = WorldTarget(world)
    pids = list(world.users.keys())
    P = {pid: Principal(pid, pid, auth={"Authorization": f"Bearer {pid}"}) for pid in pids}

    eng = AuthPathEngine(target, P, ScopeConfig(
        allowed_hosts=["world.test"], automation_permitted=True,
        target_provenance="third_party", dry_run=False), contract={})
    for f in ("provisional_leads", "active_probing", "conservation", "cross_surface"):
        setattr(eng, f, True)
    eng.confirmer.strict_leak = True
    eng.embedded_owner_exposure = True
    eng.field_exposure = True
    eng.xprincipal_write = True
    eng.xprincipal_delete = True

    def send(pid, method, path, query=None, body=None):
        req = HTTPRequest(method, path, query=query or {}, body=body, host="world.test")
        st, bd = world.handle(method, path, pid, query or {}, body)
        return Exchange(request=req, response=HTTPResponse(st, bd), principal=P[pid])

    # ---- OBSERVE: each principal's own legitimate access (provenance/envelope) --
    for pid in pids:
        u = world.users[pid]
        eng.observe(send(pid, "GET", "/world/user/dashboard"))
        eng.observe(send(pid, "GET", f"/world/vehicle/{u['vehicle_uuid']}/location"))
        eng.observe(send(pid, "GET", "/world/report", {"report_id": u["report_id"]}))
        eng.observe(send(pid, "GET", f"/world/order/{u['order_id']}"))
        eng.observe(send(pid, "GET", f"/world/video/{u['video_id']}"))

    # ---- DISCOVERY: black-box id harvesting (no oracle access) ---------------
    n = len(pids)
    leaked_uuids = {}                                # attacker -> {uuid: seen}
    for pid in pids:
        ex = send(pid, "GET", "/world/feed")
        eng.analyze(ex)
        for post in (ex.response.body or {}).get("posts", []):
            vu = post.get("author", {}).get("vehicleid")
            if vu:
                leaked_uuids.setdefault(pid, set()).add(vu)
        eng.analyze(send(pid, "GET", "/world/management/users"))

    # ---- ATTACK: cross-principal probes on enumerated / leaked ids -----------
    for pid in pids:
        # sequential-id BOLA: read every report / order id (1..n), not just own
        for rid in range(1, n + 1):
            eng.analyze(send(pid, "GET", "/world/report", {"report_id": rid}))
        for oid in range(1, n + 1):
            eng.analyze(send(pid, "GET", f"/world/order/{oid}"))
            # mass-assign: try to flip status to returned (refund)
            eng.analyze(send(pid, "PUT", f"/world/order/{oid}", body={"status": "returned"}))
        # admin BFLA: try to delete videos by enumerated id
        for vid in range(1, n + 1):
            eng.analyze(send(pid, "GET", f"/world/video/{vid}"))       # video_read BOLA
            eng.analyze(send(pid, "DELETE", f"/world/admin/videos/{vid}"))
        # vehicle-location BOLA: attack any uuid the feed leaked
        for vu in leaked_uuids.get(pid, ()):
            eng.analyze(send(pid, "GET", f"/world/vehicle/{vu}/location"))

    # ---- READ-BACK: every owner re-checks own state, exposing write-effect Δstate
    # (a real user noticing their order was changed / video deleted by someone else).
    for pid in pids:
        u = world.users[pid]
        eng.analyze(send(pid, "GET", "/world/user/dashboard"))       # credit refunded?
        for oid in range(1, n + 1):
            eng.analyze(send(pid, "GET", f"/world/order/{oid}"))     # status flipped?

    eng.drain_deferred()

    # ---- SCORE: which endpoints did ONYX flag vs the sealed oracle -----------
    flagged = set()
    for f in eng.findings:
        ek = f.classification.endpoint            # e.g. "GET /world/report"
        parts = ek.split(" ", 1)
        if len(parts) == 2:
            m, p = parts
            ep = _endpoint_of(p, m)
            if ep:
                flagged.add(ep)

    # reachability: vehicle_location is only reachable if the feed leaked a uuid
    feed_leaks = bool(any(leaked_uuids.values()))
    reachable = {e: True for e in World.GUARDED_ENDPOINTS}
    if not feed_leaks:
        reachable["vehicle_location"] = False       # no black-box path to a foreign uuid

    tp = fp = fn = tn = 0
    rows = []
    for e in World.GUARDED_ENDPOINTS:
        vuln = oracle["vuln"][e]
        found = e in flagged
        if not reachable[e]:
            rows.append((e, vuln, found, "unreachable"))
            continue
        if vuln and found: tp += 1; verdict = "TP"
        elif vuln and not found: fn += 1; verdict = "FN"
        elif not vuln and found: fp += 1; verdict = "FP"
        else: tn += 1; verdict = "TN"
        rows.append((e, vuln, found, verdict))

    recall = tp / (tp + fn) if (tp + fn) else None
    precision = tp / (tp + fp) if (tp + fp) else None
    return {"seed": seed, "seal": seal, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "recall": recall, "precision": precision, "rows": rows,
            "flagged": sorted(flagged), "feed_leaks": feed_leaks,
            "n_findings": len(eng.findings)}


if __name__ == "__main__":
    import statistics
    seeds = list(range(1, 26))
    results = [run_world(s) for s in seeds]
    TP = sum(r["tp"] for r in results); FP = sum(r["fp"] for r in results)
    FN = sum(r["fn"] for r in results); TN = sum(r["tn"] for r in results)
    micro_recall = TP / (TP + FN) if (TP + FN) else 0
    micro_prec = TP / (TP + FP) if (TP + FP) else 0
    print(f"PROVING WORLD — {len(seeds)} randomized sealed instances")
    print(f"  aggregate: TP={TP} FP={FP} FN={FN} TN={TN}")
    print(f"  micro-recall    = {micro_recall:.3f}   ({TP}/{TP+FN} vulnerable endpoints found)")
    print(f"  micro-precision = {micro_prec:.3f}   ({FP} false positives on safe endpoints)")
    print()
    print("  sample seed 1:")
    for e, vuln, found, v in results[0]["rows"]:
        print(f"    {e:20} oracle_vuln={str(vuln):5} onyx_flagged={str(found):5} -> {v}")
