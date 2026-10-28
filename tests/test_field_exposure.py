"""
Regression tests for RL22 field-exposure / EDE (GAP #4).

A response the actor may fetch that embeds a DISCRIMINATING PII field provably
private to ANOTHER tracked principal is Excessive Data Exposure. Default-OFF
(byte-identical); FP-guarded: self / broadly-shared / untracked-third-party /
non-PII all abstain. The untracked case is the HONEST BOUNDARY — black-box replay
cannot prove an untracked party's field is private, so it is never a finding.
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig


def _eng(flag=True):
    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "ABC"}
    sc = ScopeConfig(allowed_hosts=["h"], automation_permitted=True,
                     target_provenance="third_party", dry_run=False)
    class T:
        host = "h"
        def send(self, req, principal): return HTTPResponse(200, {})
    e = AuthPathEngine(T(), P, sc, contract={})
    for f in ("provisional_leads", "active_probing", "conservation", "cross_surface"):
        setattr(e, f, True)
    e.confirmer.strict_leak = True
    e.field_exposure = flag
    return e, P


def _ex(P, who, path, body):
    return Exchange(request=HTTPRequest("GET", path, host="h"),
                    response=HTTPResponse(200, body), principal=P[who])


def _feed(email):
    return {"posts": [{"id": "p", "author": {"nickname": "x", "email": email}}]}


def _dash(email):
    return {"id": 1, "email": email, "name": "u"}


def test_tracked_principal_pii_leak_confirms():
    e, P = _eng()
    e.observe(_ex(P, "B", "/identity/api/v2/user/dashboard", _dash("b@t.com")))
    e.analyze(_ex(P, "A", "/community/api/v2/community/posts/recent", _feed("b@t.com")))
    assert len(e.findings) >= 1


def test_flag_off_silent_byte_identical():
    e, P = _eng(flag=False)
    e.observe(_ex(P, "B", "/identity/api/v2/user/dashboard", _dash("b@t.com")))
    e.analyze(_ex(P, "A", "/community/api/v2/community/posts/recent", _feed("b@t.com")))
    assert len(e.findings) == 0


def test_actor_own_pii_abstains():
    e, P = _eng()
    e.observe(_ex(P, "A", "/identity/api/v2/user/dashboard", _dash("a@t.com")))
    e.analyze(_ex(P, "A", "/community/api/v2/community/posts/recent", _feed("a@t.com")))
    assert len(e.findings) == 0


def test_broadly_shared_pii_abstains():
    e, P = _eng()
    for who in "ABC":
        e.observe(_ex(P, who, "/identity/api/v2/user/dashboard", _dash("shared@t.com")))
    e.analyze(_ex(P, "A", "/community/api/v2/community/posts/recent", _feed("shared@t.com")))
    assert len(e.findings) == 0


def test_untracked_third_party_is_honest_boundary():
    """The real-capture case: a feed of UNTRACKED authors is NOT a confirmed finding
    (their privacy is unprovable by black-box replay)."""
    e, P = _eng()
    e.observe(_ex(P, "A", "/identity/api/v2/user/dashboard", _dash("a@t.com")))
    e.analyze(_ex(P, "A", "/community/api/v2/community/posts/recent", _feed("robot001@example.com")))
    assert len(e.findings) == 0


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    p = 0
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as ex: print(f"  FAIL {fn.__name__}: {ex}")
    print(f"\n{p}/{len(fns)} passed")
