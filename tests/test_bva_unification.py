"""
FORGE — Broadcast-vs-Act unification + diagnostics regression (step 5, final).

Pins (a) the meta-unification: both nerves read the declaration channel, the four engines
are act-vs-act, all under one law; with an empirical check that the first nerve's owner
field really is in the declaration channel; and (b) the bva diagnostics export shape.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.bva_unification import (THE_LAW, INSTANCES, instance_names,
                                      declaration_channel_instances)
from authpath.broadcast import _present_fields
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.models import HTTPRequest, HTTPResponse, Exchange, Principal


def test_unification_covers_both_nerves_and_four_engines():
    names = instance_names()
    assert "identity-ownership (nerve 1)" in names
    assert "broadcast-vs-act (nerve 2)" in names
    for rl in ("cross-surface (RL15)", "temporal (RL16)",
               "combinatorial (RL17)", "hierarchy (RL18)"):
        assert rl in names
    assert len(INSTANCES) == 6


def test_only_the_two_nerves_read_the_declaration_channel():
    decl = declaration_channel_instances()
    assert decl == {"identity-ownership (nerve 1)", "broadcast-vs-act (nerve 2)"}


def test_empirical_first_nerve_owner_field_is_a_broadcast():
    """The first nerve's signal (owner field in the body) is literally in the declaration
    channel — proving it is a broadcast-vs-act instance, not just asserted."""
    resp = HTTPResponse(200, {"id": "9", "owner_id": "u-2", "ssn": "x"})
    assert "owner_id" in _present_fields(resp.body)


def _H(m, p):
    return HTTPRequest(m, p, host="t.local")


class _T:
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
                    base["salary"] = 99000
            return HTTPResponse(200, base)
        return HTTPResponse(404, {})


def _run(bva_on):
    t = _T()
    admin = Principal("admin", "Ad", {"Authorization": "Bearer a"})
    alice = Principal("alice", "Al", {"Authorization": "Bearer al"})
    eng = AuthPathEngine(t, {"admin": admin, "alice": alice},
                         ScopeConfig(allowed_hosts=["t.local"], dry_run=True,
                                     automation_permitted=True))
    if bva_on:
        eng.bva = True
    for p in (admin, alice):
        r = _H("GET", "/api/me")
        eng.observe(Exchange(r, t.send(r, p), p))
    for p in (admin, alice):
        r = _H("GET", "/api/docs/1")
        eng.observe(Exchange(r, t.send(r, p), p))
    return eng


def test_bva_diagnostics_shape_when_on():
    d = _run(bva_on=True).bva_diagnostics()
    assert d["enabled"] is True
    assert d["coverage"]["roles_declared"] >= 2
    assert d["funnel"]["confirmed_findings"] == 1
    assert d["funnel"]["broadcast_candidates"] >= 1


def test_bva_diagnostics_empty_when_off():
    assert _run(bva_on=False).bva_diagnostics()["enabled"] is False


def test_export_includes_bva_block():
    from authpath.diag_export import build_export
    eng = _run(bva_on=True)
    exp = build_export(eng, [], meta={"tool": "ONYX/AuthPath"})
    assert "bva" in exp["metrics"]
    assert exp["metrics"]["bva"]["enabled"] is True
