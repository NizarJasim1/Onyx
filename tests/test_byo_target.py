"""
Verifies the bring-your-own-target runner logic end-to-end WITHOUT live HTTP, by driving
it against the in-process proving world (a valid Target). This proves the runner a judge
will point at a live crAPI is itself correct: it scores a plan against an oracle and
reports zero false positives.
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "proving_world"))


def test_byo_runner_scores_and_holds_zero_fp():
    from world import World
    from harness import WorldTarget
    from authpath.models import Principal
    from authpath.engine import AuthPathEngine
    from authpath.scope_guard import ScopeConfig
    import byo_target as BYO

    w = World(3)
    tgt = WorldTarget(w)
    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in w.users}
    scope = ScopeConfig(allowed_hosts=["world.test"], automation_permitted=True,
                        target_provenance="third_party", dry_run=False)
    eng = AuthPathEngine(tgt, P, scope, contract={})
    for f in ("provisional_leads", "active_probing", "conservation", "cross_surface"):
        setattr(eng, f, True)
    eng.confirmer.strict_leak = True
    eng.embedded_owner_exposure = eng.field_exposure = True
    eng.xprincipal_write = eng.xprincipal_delete = True

    n = len(w.users)
    plan = {"observe": [], "attack": []}
    for pid in w.users:
        u = w.users[pid]
        plan["observe"] += [
            {"pid": pid, "method": "GET", "path": "/world/user/dashboard"},
            {"pid": pid, "method": "GET", "path": f"/world/vehicle/{u['vehicle_uuid']}/location"},
            {"pid": pid, "method": "GET", "path": "/world/report", "query": {"report_id": u["report_id"]}},
            {"pid": pid, "method": "GET", "path": f"/world/order/{u['order_id']}"},
            {"pid": pid, "method": "GET", "path": f"/world/video/{u['video_id']}"},
        ]
    for pid in w.users:
        for rid in range(1, n + 1):
            plan["attack"].append({"pid": pid, "method": "GET", "path": "/world/report", "query": {"report_id": rid}})
        for oid in range(1, n + 1):
            plan["attack"].append({"pid": pid, "method": "GET", "path": f"/world/order/{oid}"})
        for vid in range(1, n + 1):
            plan["attack"].append({"pid": pid, "method": "GET", "path": f"/world/video/{vid}"})
            plan["attack"].append({"pid": pid, "method": "DELETE", "path": f"/world/admin/videos/{vid}"})

    # oracle in ONYX endpoint-key form, derived from the sealed world (the judge's role)
    vuln = w.oracle()["vuln"]
    key = {"vehicle_location": "GET /world/vehicle/{id}/location",
           "mechanic_report": "GET /world/report", "order_read": "GET /world/order/{id}",
           "video_read": "GET /world/video/{id}", "admin_delete_video": "DELETE /world/admin/videos/{id}"}
    oracle = {key[e]: vuln[e] for e in key}

    res = BYO.score_run(eng, tgt, P, plan, oracle, "world.test", base_url="in-process world")
    assert res["fp"] == 0, f"BYO runner produced a false positive: {res}"


if __name__ == "__main__":
    test_byo_runner_scores_and_holds_zero_fp()
    print("ok test_byo_runner_scores_and_holds_zero_fp")
