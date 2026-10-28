"""
CHAOS HARNESS — run ONYX against the anvil-wrapped world across chaos intensities.
The oracle is the SAME sealed ground truth; only the transport is made hostile. Both
the attacker's probes AND ONYX's confirmer read-backs pass through the reality layer,
so stale reads / cache bleed / retries / 429 / timeouts hit the exact step ONYX's
confirmation depends on. We report the precision/recall curve vs intensity — the
question that matters is whether PRECISION stays 1.0 as chaos rises.
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig

from world import World
from anvil import RealityLayer
from harness import _endpoint_of


class ChaosTarget:
    host = "world.test"

    def __init__(self, reality):
        self.reality = reality

    def send(self, req, principal):
        st, bd = self.reality.handle(req.method, req.path, principal.pid,
                                     dict(req.query or {}), req.body)
        return HTTPResponse(st, bd)


def chaos_run(seed: int, intensity: float, n_users: int = 3, _stealth=None) -> dict:
    world = World(seed, n_users)
    oracle = world.oracle()
    reality = RealityLayer(world, intensity=intensity, seed=seed)
    target = ChaosTarget(reality)
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
    eng.confirmer.stability_k = 7   # RL24: majority-vote read-backs to defeat chaos
    if _stealth is not None:
        eng.confirmer.stealth = _stealth   # deficiency #6: quiet delivery, same semantics

    def send(pid, method, path, query=None, body=None):
        st, bd = reality.handle(method, path, pid, query or {}, body)
        req = HTTPRequest(method, path, query=query or {}, body=body, host="world.test")
        return Exchange(request=req, response=HTTPResponse(st, bd), principal=P[pid])

    for pid in pids:
        u = world.users[pid]
        eng.observe(send(pid, "GET", "/world/user/dashboard"))
        eng.observe(send(pid, "GET", f"/world/vehicle/{u['vehicle_uuid']}/location"))
        eng.observe(send(pid, "GET", "/world/report", {"report_id": u["report_id"]}))
        eng.observe(send(pid, "GET", f"/world/order/{u['order_id']}"))
        eng.observe(send(pid, "GET", f"/world/video/{u['video_id']}"))

    n = len(pids)
    leaked = {}
    for pid in pids:
        ex = send(pid, "GET", "/world/feed")
        eng.analyze(ex)
        for post in (ex.response.body or {}).get("posts", []) if isinstance(ex.response.body, dict) else []:
            vu = post.get("author", {}).get("vehicleid")
            if vu:
                leaked.setdefault(pid, set()).add(vu)
        eng.analyze(send(pid, "GET", "/world/management/users"))

    for pid in pids:
        for rid in range(1, n + 1):
            eng.analyze(send(pid, "GET", "/world/report", {"report_id": rid}))
        for oid in range(1, n + 1):
            eng.analyze(send(pid, "GET", f"/world/order/{oid}"))
            eng.analyze(send(pid, "PUT", f"/world/order/{oid}", body={"status": "returned"}))
        for vid in range(1, n + 1):
            eng.analyze(send(pid, "GET", f"/world/video/{vid}"))
            eng.analyze(send(pid, "DELETE", f"/world/admin/videos/{vid}"))
        for vu in leaked.get(pid, ()):
            eng.analyze(send(pid, "GET", f"/world/vehicle/{vu}/location"))

    for pid in pids:
        eng.analyze(send(pid, "GET", "/world/user/dashboard"))
        for oid in range(1, n + 1):
            eng.analyze(send(pid, "GET", f"/world/order/{oid}"))

    eng.drain_deferred()

    flagged = set()
    for f in eng.findings:
        parts = f.classification.endpoint.split(" ", 1)
        if len(parts) == 2:
            ep = _endpoint_of(parts[1], parts[0])
            if ep:
                flagged.add(ep)

    feed_leaks = bool(any(leaked.values()))
    tp = fp = fn = tn = 0
    for e in World.GUARDED_ENDPOINTS:
        if e == "vehicle_location" and not feed_leaks:
            continue
        vuln = oracle["vuln"][e]; found = e in flagged
        if vuln and found: tp += 1
        elif vuln and not found: fn += 1
        elif not vuln and found: fp += 1
        else: tn += 1
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "n_findings": len(eng.findings)}


def sweep(intensities=(0.0, 0.25, 0.5, 0.75, 1.0), seeds=range(1, 21)):
    print("ANVIL — precision/recall vs chaos intensity")
    print(f"  (each cell aggregates {len(list(seeds))} randomized sealed worlds)\n")
    print(f"  {'intensity':>10} | {'recall':>7} | {'precision':>9} | {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3}")
    print("  " + "-" * 58)
    rows = []
    for inten in intensities:
        TP = FP = FN = TN = 0
        for s in seeds:
            r = chaos_run(s, inten)
            TP += r["tp"]; FP += r["fp"]; FN += r["fn"]; TN += r["tn"]
        recall = TP / (TP + FN) if (TP + FN) else 0
        prec = TP / (TP + FP) if (TP + FP) else 1.0
        rows.append((inten, recall, prec, TP, FP, FN, TN))
        print(f"  {inten:>10.2f} | {recall:>7.3f} | {prec:>9.3f} | {TP:>3} {FP:>3} {FN:>3} {TN:>3}")
    return rows


if __name__ == "__main__":
    sweep()
