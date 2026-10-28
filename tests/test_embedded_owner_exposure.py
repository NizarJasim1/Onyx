"""
Regression tests for RL21 embedded-owner exposure (GAP #3 — cold-start ownership).

A foreign-owned object (body declares a discriminating owner-identity held by NO
tracked principal) read by >=2 non-owner principals is a broken-authorization
exposure. This closes the mechanic-report BOLA on a flat capture. The gate is
default-OFF (byte-identical) and heavily FP-guarded: self / shared / public /
single-reader / shared-default-owner all abstain.
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
    e.embedded_owner_exposure = flag
    return e, P


def _ex(P, who, rid, body):
    return Exchange(request=HTTPRequest("GET", "/workshop/api/mechanic/mechanic_report",
                    query={"report_id": rid}, host="h"),
                    response=HTTPResponse(200, body), principal=P[who])


def _rep(owner="victim@example.com"):
    return {"id": 1, "vehicle": {"owner": {"email": owner}}, "problem_details": "x"}


def test_two_nonowners_foreign_object_confirms():
    e, P = _eng(); e.analyze(_ex(P, "A", "1", _rep())); e.analyze(_ex(P, "B", "1", _rep()))
    assert len(e.findings) >= 1


def test_flag_off_is_byte_identical_silent():
    e, P = _eng(flag=False)
    e.analyze(_ex(P, "A", "1", _rep())); e.analyze(_ex(P, "B", "1", _rep()))
    assert len(e.findings) == 0             # default off -> nothing (byte-identical)


def test_single_reader_abstains():
    e, P = _eng(); e.analyze(_ex(P, "A", "1", _rep()))
    assert len(e.findings) == 0


def test_shared_object_abstains():
    e, P = _eng()
    b = _rep(); b["shared_with"] = ["A", "B"]
    e.analyze(_ex(P, "A", "1", b)); e.analyze(_ex(P, "B", "1", b))
    assert len(e.findings) == 0


def test_public_object_abstains():
    e, P = _eng()
    b = _rep(); b["visibility"] = "public"
    e.analyze(_ex(P, "A", "1", b)); e.analyze(_ex(P, "B", "1", b))
    assert len(e.findings) == 0


def test_shared_default_owner_value_abstains():
    e, P = _eng()
    b = {"id": 1, "vehicle": {"owner": {"id": 0}}, "problem_details": "x"}
    e.analyze(_ex(P, "A", "1", b)); e.analyze(_ex(P, "B", "1", b))
    assert len(e.findings) == 0             # owner value 0 not discriminating (Gap#2)


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    p = 0
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as ex: print(f"  FAIL {fn.__name__}: {ex}")
    print(f"\n{p}/{len(fns)} passed")
