"""
FORGE step 4c — nerve↔engine integration regression.

Pins the safety contract of wiring the nerve into the live engine:
  * flag OFF  → observe() never feeds the bridge; nerve_findings() is empty; the
    engine is byte-identical (the rest of the suite + demo prove the byte-identity).
  * flag ON   → the nerve catches real owner-field BOLAs through engine.observe and
    engine.nerve_findings(), with ZERO false positives, and engine.findings (the
    existing channel) is NEVER written to — the nerve is a strictly separate channel.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fixtures import nerve_blind_range as M
from fixtures.nerve_blind_range import (NerveBlindRange, ORACLE_FINDINGS,
                                        ORACLE_MUST_NOT_FLAG)
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.models import HTTPRequest, Exchange, Principal


def _H(m, p):
    return HTTPRequest(m, p, host="nerve.local")


def _engine(nerve_on):
    t = NerveBlindRange()
    A = Principal("A", "A", {"Authorization": "Bearer A"})
    B = Principal("B", "B", {"Authorization": "Bearer B"})
    C = Principal("C", "C", {"Authorization": "Bearer C"})
    anon = Principal("anon", "anon", {}, is_anonymous=True)
    scope = ScopeConfig(allowed_hosts=["nerve.local"], dry_run=True,
                        automation_permitted=True)
    eng = AuthPathEngine(t, {"A": A, "B": B, "C": C, "anon": anon}, scope)
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


def test_flag_off_nerve_is_silent():
    eng = _engine(nerve_on=False)
    assert eng.nerve_findings() == []           # nothing fed ⇒ nothing to confirm
    assert getattr(eng, "_nerve", None) is None  # bridge never even constructed


def test_flag_on_catches_bolas_via_engine():
    eng = _engine(nerve_on=True)
    got = {(f.resource, f.accessor) for f in eng.nerve_findings()}
    assert got == ORACLE_FINDINGS               # exactly the planted BOLAs


def test_flag_on_zero_false_positives_and_findings_channel_untouched():
    eng = _engine(nerve_on=True)
    got = {(f.resource, f.accessor) for f in eng.nerve_findings()}
    assert {res for res, _ in got} & ORACLE_MUST_NOT_FLAG == set()   # no decoy flagged
    assert eng.findings == []                   # the existing channel is never written
