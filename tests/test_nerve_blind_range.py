"""
FORGE step 4b — nerve blind-range regression.

Drives the NerveBridge BLIND (no oracle access) over a target that plants owner-field
BOLAs alongside adversarial legitimate decoys, then scores against the hidden oracle.
Proves the nerve catches real cross-principal access AND produces zero false positives
on the decoys — each decoy suppressed at its correct guard (grant / X-2 / X-3).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fixtures import nerve_blind_range as M
from fixtures.nerve_blind_range import (NerveBlindRange, ORACLE_FINDINGS,
                                        ORACLE_MUST_NOT_FLAG)
from authpath.nerve_bridge import NerveBridge
from authpath.confirmer import Confirmer
from authpath.scope_guard import ScopeConfig, ScopeGuard
from authpath.models import HTTPRequest, Principal


def _H(m, p):
    return HTTPRequest(m, p, host="nerve.local")


def _drive():
    t = NerveBlindRange()
    A = Principal("A", "A", {"Authorization": "Bearer A"})
    B = Principal("B", "B", {"Authorization": "Bearer B"})
    C = Principal("C", "C", {"Authorization": "Bearer C"})
    anon = Principal("anon", "anon", {}, is_anonymous=True)
    sg = ScopeGuard(ScopeConfig(allowed_hosts=["nerve.local"], dry_run=True,
                                automation_permitted=True))
    conf = Confirmer(t, {"A": A, "B": B, "C": C, "anon": anon}, sg)
    br = NerveBridge(conf, principals_by_identity={"u-1": A, "u-2": B, "u-3": C},
                     anon_principal=anon)
    for fp, pr in [("fpA", A), ("fpB", B), ("fpC", C)]:
        br.feed_self(fp, _H("GET", "/api/me"), t.send(_H("GET", "/api/me"), pr))
    M._NOTE_OWNER["n0"] = "u-1"                        # a 2nd self-owned note for corroboration
    for d in ("n1", "n0"):
        r = _H("GET", f"/api/notes/{d}")
        br.feed_owned(r, t.send(r, A), "fpA")
    for path in ("notes/n1", "notes/n2", "notes/n3",
                 "files/f1", "bulletins/b1", "accounts/ac2"):
        r = _H("GET", f"/api/{path}")
        br.feed_access(r, t.send(r, A), "fpA")
    return br


def test_blind_range_catches_all_real_bolas():
    br = _drive()
    got = {(f.resource, f.accessor) for f in br.confirmed_findings()}
    assert got == ORACLE_FINDINGS                      # exactly the planted BOLAs, no more


def test_blind_range_zero_false_positives():
    br = _drive()
    got = {(f.resource, f.accessor) for f in br.confirmed_findings()}
    flagged_resources = {res for res, _ in got}
    assert flagged_resources & ORACLE_MUST_NOT_FLAG == set()      # no decoy flagged


def test_blind_range_decoys_suppressed_at_correct_guard():
    br = _drive()
    br.confirmed_findings()
    reasons = {res: why for res, why in br.abstained}
    # public decoy abstains at X-2; redacted decoy at X-3
    assert "public" in reasons.get("bulletin:b1", "")
    assert "no substantive" in reasons.get("account:ac2", "")
    # the legitimate-share decoy never even becomes a candidate (grant suppression)
    cands = {c["resource"] for c in br.equiv.ownership_mismatch_candidates()}
    assert "file:f1" not in cands
