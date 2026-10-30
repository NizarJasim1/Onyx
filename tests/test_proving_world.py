"""
Proving-world regression: ONYX attacks randomized, sealed, LIVE vulnerable apps it
cannot see (world.py imports no authpath). Asserts the crown jewel — ZERO false
positives on an independent target — and a recall floor. Also unit-tests RL23
cross-principal write.
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "proving_world"))


def test_world_imports_no_authpath():
    import ast
    src = open(os.path.join(ROOT, "proving_world", "world.py"), encoding="utf-8").read()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            assert all(a.name.split(".")[0] != "authpath" for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] != "authpath"


def test_zero_false_positives_on_independent_targets():
    from harness import run_world
    fp = 0
    for seed in range(1, 11):
        r = run_world(seed)
        fp += r["fp"]
    assert fp == 0, f"crown jewel breached: {fp} false positives on live sealed worlds"


def test_recall_floor_on_independent_targets():
    from harness import run_world
    tp = fn = 0
    for seed in range(1, 11):
        r = run_world(seed)
        tp += r["tp"]; fn += r["fn"]
    recall = tp / (tp + fn) if (tp + fn) else 0
    assert recall >= 0.85, f"recall regressed below floor: {recall:.3f}"


def test_rl23_cross_principal_write_confirms_and_is_fp_safe():
    from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange
    from authpath.engine import AuthPathEngine
    from authpath.scope_guard import ScopeConfig
    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "AB"}

    state = {"1": {"status": "delivered", "owner_email": "a@t.com"}}
    class T:
        host = "h"
        def send(self, req, principal):
            o = state.get(req.path.split("/")[-1])
            if o is None: return HTTPResponse(404, {"error": "x"})
            if req.method == "PUT":
                o["status"] = (req.body or {}).get("status", o["status"])
                return HTTPResponse(200, {"id": 1, "status": o["status"]})
            return HTTPResponse(200, {"id": 1, "status": o["status"],
                                      "user": {"email": o["owner_email"]}})
    e = AuthPathEngine(T(), P, ScopeConfig(allowed_hosts=["h"], automation_permitted=True,
                       target_provenance="third_party", dry_run=False), contract={})
    for f in ("provisional_leads", "active_probing", "conservation", "cross_surface"):
        setattr(e, f, True)
    e.confirmer.strict_leak = True
    e.xprincipal_write = True

    def ex(pid, m, b=None):
        r = T().send(HTTPRequest(m, "/order/1", body=b, host="h"), P[pid])
        return Exchange(request=HTTPRequest(m, "/order/1", body=b, host="h"),
                        response=r, principal=P[pid])
    # A (owner) reads own order -> establishes a@t.com is A's
    e.observe(Exchange(request=HTTPRequest("GET", "/order/1", host="h"),
                       response=HTTPResponse(200, {"id": 1, "status": "delivered",
                                                   "user": {"email": "a@t.com"}}),
                       principal=P["A"]))
    e.observe(Exchange(request=HTTPRequest("GET", "/user/dashboard", host="h"),
                       response=HTTPResponse(200, {"id": 1, "email": "a@t.com"}),
                       principal=P["A"]))
    # B (non-owner) writes A's order
    e.analyze(ex("B", "PUT", {"status": "returned"}))
    e.drain_deferred()
    assert len(e.findings) >= 1, "cross-principal write not confirmed"


def test_rl23_flag_off_silent():
    from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange
    from authpath.engine import AuthPathEngine
    from authpath.scope_guard import ScopeConfig
    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "AB"}
    class T:
        host = "h"
        def send(self, req, principal): return HTTPResponse(200, {"id": 1, "status": "returned",
                                                                   "user": {"email": "a@t.com"}})
    e = AuthPathEngine(T(), P, ScopeConfig(allowed_hosts=["h"], automation_permitted=True,
                       target_provenance="third_party", dry_run=False), contract={})
    for f in ("provisional_leads", "active_probing", "conservation", "cross_surface"):
        setattr(e, f, True)
    e.confirmer.strict_leak = True    # xprincipal_write left OFF
    e.observe(Exchange(request=HTTPRequest("GET", "/user/dashboard", host="h"),
                       response=HTTPResponse(200, {"email": "a@t.com"}), principal=P["A"]))
    e.analyze(Exchange(request=HTTPRequest("PUT", "/order/1", body={"status": "returned"}, host="h"),
                       response=HTTPResponse(200, {"id": 1, "status": "returned"}), principal=P["B"]))
    e.drain_deferred()
    assert len(e.findings) == 0


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    p = 0
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as ex: print(f"  FAIL {fn.__name__}: {ex}")
    print(f"\n{p}/{len(fns)} passed")
