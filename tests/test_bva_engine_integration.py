"""
FORGE — Broadcast-vs-Act engine integration regression (step 4).

Pins the separate-channel wiring:
  * flag OFF → observe() never feeds BvA; bva_findings() empty; engine byte-identical.
  * flag ON  → catches a real broadcast-vs-act contradiction (inconsistent field
    projection: the field is broadcast hidden to a member but the act leaks it with the
    privileged viewer's real value) through engine.observe, WITHOUT writing engine.findings.
  * a consistent single-endpoint target yields NO finding (zero false positive — a
    same-endpoint field difference is nerve-1 territory or no bug, not a BvA contradiction).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.models import HTTPRequest, HTTPResponse, Exchange, Principal


def _H(m, p):
    return HTTPRequest(m, p, host="t.local")


class _InconsistentTarget:
    """Real BvA bug: member's FIRST read of doc:1 hides salary (the broadcast), but a
    re-read LEAKS it (the act). admin always sees it."""
    host = "t.local"

    def __init__(self):
        self.member_reads = 0

    def send(self, req, p):
        if req.path == "/api/me":
            role = {"admin": "admin", "alice": "member"}.get(p.pid)
            return HTTPResponse(200, {"id": {"admin": "u-admin", "alice": "u-alice"}.get(p.pid),
                                      "role": role})
        if req.path == "/api/docs/1":
            base = {"id": "1", "title": "Q4"}
            if p.pid == "admin":
                base["salary"] = 99000
            elif p.pid == "alice":
                self.member_reads += 1
                if self.member_reads >= 2:
                    base["salary"] = 99000              # leaks on re-read (the act)
            return HTTPResponse(200, base)
        return HTTPResponse(404, {})


class _ConsistentTarget:
    """No BvA contradiction: member never sees salary on any read of doc:1."""
    host = "t.local"

    def send(self, req, p):
        if req.path == "/api/me":
            role = {"admin": "admin", "alice": "member"}.get(p.pid)
            return HTTPResponse(200, {"id": {"admin": "u-admin", "alice": "u-alice"}.get(p.pid),
                                      "role": role})
        if req.path == "/api/docs/1":
            base = {"id": "1", "title": "Q4"}
            if p.pid == "admin":
                base["salary"] = 99000
            return HTTPResponse(200, base)
        return HTTPResponse(404, {})


def _run(target, bva_on):
    admin = Principal("admin", "Ad", {"Authorization": "Bearer a"})
    alice = Principal("alice", "Al", {"Authorization": "Bearer al"})
    eng = AuthPathEngine(target, {"admin": admin, "alice": alice},
                         ScopeConfig(allowed_hosts=["t.local"], dry_run=True,
                                     automation_permitted=True))
    if bva_on:
        eng.bva = True

    def obs(p, path):
        r = _H("GET", path)
        eng.observe(Exchange(r, target.send(r, p), p))

    for p in (admin, alice):
        obs(p, "/api/me")
    for p in (admin, alice):
        obs(p, "/api/docs/1")
    return eng


def test_flag_off_silent():
    eng = _run(_InconsistentTarget(), bva_on=False)
    assert eng.bva_findings() == []
    assert getattr(eng, "_bva", None) is None       # channel never even constructed


def test_flag_on_catches_broadcast_vs_act_contradiction():
    eng = _run(_InconsistentTarget(), bva_on=True)
    fs = eng.bva_findings()
    assert len(fs) == 1
    assert fs[0].field == "salary" and fs[0].accessor == "u-alice"
    assert eng.findings == []                       # separate channel — never written


def test_consistent_target_no_false_positive():
    eng = _run(_ConsistentTarget(), bva_on=True)
    assert eng.bva_findings() == []                 # member never leaked → no contradiction
    assert eng.findings == []
