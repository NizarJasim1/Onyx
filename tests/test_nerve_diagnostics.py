"""
Nerve diagnostics export regression — the JSON the EXPORT-JSON path ships so the
operator can see, on a real target, where the nerve had reach and where it was blind.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fixtures import nerve_blind_range as M
from fixtures.nerve_blind_range import NerveBlindRange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.models import HTTPRequest, Exchange, Principal


def _H(m, p):
    return HTTPRequest(m, p, host="nerve.local")


def _run(nerve_on):
    t = NerveBlindRange()
    A = Principal("A", "A", {"Authorization": "Bearer A"})
    B = Principal("B", "B", {"Authorization": "Bearer B"})
    C = Principal("C", "C", {"Authorization": "Bearer C"})
    anon = Principal("anon", "anon", {}, is_anonymous=True)
    eng = AuthPathEngine(t, {"A": A, "B": B, "C": C, "anon": anon},
                         ScopeConfig(allowed_hosts=["nerve.local"], dry_run=True,
                                     automation_permitted=True))
    if nerve_on:
        eng.nerve = True

    def obs(pr, path):
        r = _H("GET", path)
        eng.observe(Exchange(r, t.send(r, pr), pr))

    M._NOTE_OWNER["n0"] = "u-1"
    for pr in (A, B, C):
        obs(pr, "/api/me")
    obs(A, "/api/notes/n1")
    obs(A, "/api/notes/n0")
    for path in ("notes/n2", "notes/n3", "files/f1", "bulletins/b1", "accounts/ac2"):
        obs(A, f"/api/{path}")
    return eng


def test_diagnostics_coverage_signals():
    d = _run(nerve_on=True).nerve_diagnostics()
    cov = d["coverage"]
    assert cov["identities_attested"] == 3
    assert cov["ownership_pointer_learned"] is True
    assert cov["ownership_pointer_field"] == "owner_id"
    assert cov["owner_declared_ratio_pct"] > 50          # this target exposes ownership
    assert cov["owners_provisioned_for_readback"] == 3


def test_diagnostics_funnel_and_taxonomy():
    d = _run(nerve_on=True).nerve_diagnostics()
    fun = d["funnel"]
    assert fun["candidates_raised"] == 4
    assert fun["confirmed_findings"] == 2
    # the two decoys that reached confirmation abstained at their correct guard
    assert fun["abstained_by_reason"].get("X2_object_public") == 1
    assert fun["abstained_by_reason"].get("X3_no_substantive_leak") == 1


def test_diagnostics_reach_note_positive():
    d = _run(nerve_on=True).nerve_diagnostics()
    assert "had reach" in d["reach_note"]


def test_diagnostics_empty_when_flag_off():
    d = _run(nerve_on=False).nerve_diagnostics()
    assert d["enabled"] is False
