"""
RL25 cross-principal destruction (FP-safe admin-delete BFLA). Confirms the OBSERVABLE
consequence of a broken function-level check — a non-owner destroyed an owner's object
— via Δstate + legitimate (observe-phase) ownership, with NO role/path heuristic.
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig


def _world():
    # tiny live object store: video 1 owned by A; deletable by anyone (the BFLA).
    state = {"1": {"owner": "A", "alive": True}}
    class T:
        host = "h"
        def send(self, req, principal):
            vid = req.path.rstrip("/").split("/")[-1]
            o = state.get(vid)
            if req.method == "GET" and req.path.startswith("/video/"):
                if not o or not o["alive"]:
                    return HTTPResponse(404, {"error": "gone"})
                return HTTPResponse(200, {"id": int(vid), "owner": {"email": f"{o['owner']}@t"}})
            if req.method == "DELETE" and req.path.startswith("/admin/videos/"):
                if o and o["alive"]:
                    o["alive"] = False
                    return HTTPResponse(200, {"deleted": int(vid)})
                return HTTPResponse(404, {"error": "gone"})
            return HTTPResponse(404, {})
    return T(), state


def _eng():
    T, state = _world()
    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "AB"}
    e = AuthPathEngine(T, P, ScopeConfig(allowed_hosts=["h"], automation_permitted=True,
                       target_provenance="third_party", dry_run=False), contract={})
    for f in ("provisional_leads", "active_probing", "conservation", "cross_surface"):
        setattr(e, f, True)
    e.confirmer.strict_leak = True
    e.xprincipal_delete = True
    return e, P, T


def _get(P, who, path):
    return Exchange(request=HTTPRequest("GET", path, host="h"),
                    response=None, principal=P[who])


def _run(e, T, who, method, path):
    r = T.send(HTTPRequest(method, path, host="h"), None)
    return Exchange(request=HTTPRequest(method, path, host="h"), response=r,
                    principal=e.principals[who] if hasattr(e, "principals") else None)


def test_cross_principal_delete_confirms():
    e, P, T = _eng()
    # A establishes ownership by legitimately reading its own video
    r = T.send(HTTPRequest("GET", "/video/1", host="h"), None)
    e.observe(Exchange(request=HTTPRequest("GET", "/video/1", host="h"),
                       response=r, principal=P["A"]))
    # B (non-owner) deletes A's video
    rd = T.send(HTTPRequest("DELETE", "/admin/videos/1", host="h"), None)
    e.analyze(Exchange(request=HTTPRequest("DELETE", "/admin/videos/1", host="h"),
                       response=rd, principal=P["B"]))
    e.drain_deferred()
    assert len(e.findings) >= 1, "cross-principal destruction not confirmed"


def test_owner_deleting_own_object_abstains():
    e, P, T = _eng()
    r = T.send(HTTPRequest("GET", "/video/1", host="h"), None)
    e.observe(Exchange(request=HTTPRequest("GET", "/video/1", host="h"),
                       response=r, principal=P["A"]))
    # A (owner) deletes its OWN video -> authorized, must NOT fire
    rd = T.send(HTTPRequest("DELETE", "/admin/videos/1", host="h"), None)
    e.analyze(Exchange(request=HTTPRequest("DELETE", "/admin/videos/1", host="h"),
                       response=rd, principal=P["A"]))
    e.drain_deferred()
    assert len(e.findings) == 0, "must not flag an owner deleting its own object"


def test_no_established_owner_abstains():
    e, P, T = _eng()
    # nobody legitimately established ownership of video 1 -> cannot attribute -> abstain
    rd = T.send(HTTPRequest("DELETE", "/admin/videos/1", host="h"), None)
    e.analyze(Exchange(request=HTTPRequest("DELETE", "/admin/videos/1", host="h"),
                       response=rd, principal=P["B"]))
    e.drain_deferred()
    assert len(e.findings) == 0, "no established owner -> must abstain (RL5)"


def test_flag_off_is_byte_identical_silent():
    e, P, T = _eng(); e.xprincipal_delete = False
    r = T.send(HTTPRequest("GET", "/video/1", host="h"), None)
    e.observe(Exchange(request=HTTPRequest("GET", "/video/1", host="h"),
                       response=r, principal=P["A"]))
    rd = T.send(HTTPRequest("DELETE", "/admin/videos/1", host="h"), None)
    e.analyze(Exchange(request=HTTPRequest("DELETE", "/admin/videos/1", host="h"),
                       response=rd, principal=P["B"]))
    e.drain_deferred()
    assert len(e.findings) == 0


if __name__ == "__main__":
    p = 0; fns = [g for n, g in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as ex: print(f"  FAIL {fn.__name__}: {ex}")
    print(f"{p}/{len(fns)} passed")
