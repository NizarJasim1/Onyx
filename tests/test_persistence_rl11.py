"""
RL11 regression suite — SEALED CROSS-SESSION MEMORY.

D10 rejected a persistent cross-session graph (a raw-payload lake) and so left
ONYX with no memory across process runs, blinding it to temporal vulnerabilities.
RL11 resolves D10 properly: it adds a small store of DERIVED, FINGERPRINTED facts
(and nothing else), enabling cross-session detection without a data lake.

Properties under guard:
  1. DISABLED  — no store path ⇒ no-op (byte-identical; the whole suite stays green).
  2. PRIVACY   — only fingerprints/counts/timestamps hit disk; raw values never do.
  3. FAIL-SAFE — a missing/corrupt store loads as empty, never an error.
  4. RESURRECT — a credential DENIED in a prior session, now ALLOWED, is flagged
                 (a contradiction no single run could observe). No FP otherwise.
  5. REPLAY    — a single-use token redeemed across sessions exceeds its limit and
                 is confirmed; within-limit stays clean (no double-count).
"""
import json
import os
import tempfile

from authpath.persistence import (
    SealedStore, fingerprint, ALLOWED, DENIED, _assert_sealed,
)
from authpath.models import Principal, HTTPRequest, HTTPResponse, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.economy import BudgetLedger

A = Principal("A", "Alice")


def _tmp():
    return os.path.join(tempfile.mkdtemp(), "store.json")


# --- (1) DISABLED no-op ----------------------------------------------------- #
def test_disabled_store_is_noop():
    s = SealedStore(None)
    assert s.enabled is False
    assert s.record_credential("tok", ALLOWED, "GET /x", 1.0) is None
    assert s.record_artifact("c", 1.0) == 0
    s.save()                       # must not raise / must not write anything


# --- (2) PRIVACY ------------------------------------------------------------ #
def test_fingerprint_is_one_way():
    fp = fingerprint("super-secret-token")
    assert fp.startswith("fp_") and "super-secret-token" not in fp


def test_no_raw_value_on_disk():
    sp = _tmp()
    s = SealedStore(sp)
    s.record_credential("Bearer RAW-SECRET-123", DENIED, "GET /x", 1.0)
    s.record_artifact("COUPON-RAW-XYZ", 1.0)
    s.save()
    raw = open(sp).read()
    assert "RAW-SECRET-123" not in raw
    assert "COUPON-RAW-XYZ" not in raw
    assert "fp_" in raw


def test_privacy_audit_rejects_raw_key():
    try:
        _assert_sealed({"credentials": {"Bearer raw": {"fp": "Bearer raw"}}})
        assert False, "should have raised"
    except ValueError:
        pass


# --- (3) FAIL-SAFE ---------------------------------------------------------- #
def test_missing_file_loads_empty():
    s = SealedStore(_tmp())        # path does not exist yet
    assert s.credentials == {} and s.artifacts == {}


def test_corrupt_file_loads_empty():
    sp = _tmp()
    with open(sp, "w") as fh:
        fh.write("{ this is not valid json ]")
    s = SealedStore(sp)            # must not raise
    assert s.credentials == {}


# --- (4) CREDENTIAL RESURRECTION ------------------------------------------- #
def test_denied_then_allowed_flags_resurrection():
    sp = _tmp()
    s1 = SealedStore(sp)
    assert s1.record_credential("tok", DENIED, "GET /x", 100.0) is None
    s1.save()
    s2 = SealedStore(sp)           # new "session"
    anomaly = s2.record_credential("tok", ALLOWED, "GET /x", 200.0)
    assert anomaly and anomaly["kind"] == "credential_resurrection"


def test_allowed_then_allowed_no_anomaly():
    sp = _tmp()
    s1 = SealedStore(sp); s1.record_credential("tok", ALLOWED, "GET /x", 1.0); s1.save()
    s2 = SealedStore(sp)
    assert s2.record_credential("tok", ALLOWED, "GET /x", 2.0) is None   # no FP


def test_engine_emits_resurrection_lead_cross_session():
    sp = _tmp()

    def eng(status):
        t = type("T", (), {"send": lambda s, r, p: HTTPResponse(status, {})})()
        return AuthPathEngine(t, {"A": A},
                              ScopeConfig(allowed_hosts=["h"], dry_run=False),
                              contract={}, ledger=BudgetLedger.unbounded(), store_path=sp)

    e1 = eng(401)
    ex1 = Exchange(HTTPRequest("GET", "/api/data", headers={"Authorization": "Bearer T"}, host="h"),
                   HTTPResponse(401, {}), A); ex1.observed_at = 1.0
    e1.observe(ex1); e1.save_store()
    e2 = eng(200)
    ex2 = Exchange(HTTPRequest("GET", "/api/data", headers={"Authorization": "Bearer T"}, host="h"),
                   HTTPResponse(200, {"data": "x"}), A); ex2.observed_at = 2.0
    e2.observe(ex2)
    assert any(getattr(l, "kind", "") == "CREDENTIAL_RESURRECTION" for _t, l in e2.leads)


# --- (5) SINGLE-USE REPLAY -------------------------------------------------- #
def test_two_layer_count_no_double_count():
    sp = _tmp()
    s = SealedStore(sp)
    s.record_artifact("c", 1.0)            # this session
    assert s.prior_redemptions("c") == 0   # prior sessions only ⇒ still 0
    s.save()
    s2 = SealedStore(sp)
    assert s2.prior_redemptions("c") == 1  # now a prior-session fact


def test_cross_session_coupon_replay_confirms():
    sp = _tmp()
    COUPON = "SAVE50-ONETIME"

    def eng():
        t = type("T", (), {"send": lambda s, r, p: HTTPResponse(200, {"ok": True})})()
        return AuthPathEngine(t, {"A": A},
                              ScopeConfig(allowed_hosts=["h"], dry_run=False),
                              contract={"POST /api/redeem": {"effect": "COUPON",
                                                             "critical_params": ["coupon"]}},
                              ledger=BudgetLedger.unbounded(), store_path=sp)

    def redeem(e, ts):
        ex = Exchange(HTTPRequest("POST", "/api/redeem", body={"coupon": COUPON, "limit": 1}, host="h"),
                      HTTPResponse(200, {"ok": True}), A); ex.observed_at = ts
        e.observe(ex)
        return e.analyze(ex)

    e1 = eng(); redeem(e1, 1.0); e1.save_store()
    assert len(e1.findings) == 0           # first redemption is within limit
    e2 = eng(); tr = redeem(e2, 2.0)       # new session, same coupon
    assert tr.outcome == "finding"         # cross-session single-use replay
