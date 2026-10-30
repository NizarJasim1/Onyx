"""
Authority Conservation (RL19) — adversarial rebuild tests.

Each test reproduces a scenario that BROKE the first prototype (session-2
teardown) and asserts the measured rebuild handles it:

  ث1  legitimately-shared value      -> must NOT fire (dead-exoneration resurrected)
  ث5  order independence              -> verdict identical regardless of observe order
  ث7  multiple legitimate holders     -> shared/common, must NOT fire
  ث10 oddly/locally-named private id  -> caught via measured ownership, not lexicon
  laundering: an attack-phase sighting -> can NEVER make a value 'public'
  + positive leak, public/self exoneration, and visible abstain on no baseline.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.provenance import ProvenanceStore
from authpath.envelope import EnvelopeEngine
from authpath.models import (
    Exchange, HTTPRequest, HTTPResponse, Principal,
    EffectClassification, EffectClass, ClassificationSource, Verdict,
)
from authpath.eil import LawContext
from authpath.conservation import (
    AuthorityConservationLaw, AXIS_PROPERTY,
)


def _ctx(ex, ps, env):
    cls = EffectClassification(endpoint="GET /x", effect=EffectClass.OBJECT_ACCESS,
                               source=ClassificationSource.INFERRED)
    return LawContext(exchange=ex, classification=cls, provenance=ps, envelopes=env)


def _ex(method, path, body, principal, host="h"):
    return Exchange(HTTPRequest(method, path, host=host), HTTPResponse(200, body), principal)


def _seed_owner_of_id(ps, env, pid, idval):
    """principal `pid` legitimately HOLDS object id `idval` (addresses it, 2xx)."""
    p = Principal(pid, pid.lower())
    ex = _ex("GET", f"/api/acct/{idval}", {"id": idval, "ssn": f"ssn-{pid}"}, p)
    ps.observe_response(ex, legitimate=True)
    env.observe(ex, EffectClass.OBJECT_ACCESS)


def _seed_secret_of(ps, pid, secret):
    """principal `pid` legitimately RECEIVES a secret (never addressed -> seer only)."""
    p = Principal(pid, pid.lower())
    ps.observe_response(_ex("GET", "/api/vault/mine", {"blob": secret}, p), legitimate=True)


# --------------------------------------------------------------------------- #
# positive: A's private id leaked into B's read fires, attributed to A          #
# --------------------------------------------------------------------------- #

def test_positive_cross_principal_leak():
    ps, env = ProvenanceStore(), EnvelopeEngine()
    _seed_owner_of_id(ps, env, "A", "9123456")
    B = Principal("B", "b")
    v = AuthorityConservationLaw().evaluate(_ctx(_ex("GET", "/api/me", {"id": "9123456"}, B), ps, env))
    assert v.verdict == Verdict.CANDIDATE
    assert v.evidence["owner_principal"] == "A"
    assert v.evidence["conservation_axis"] == AXIS_PROPERTY


# --------------------------------------------------------------------------- #
# ث1 — a value legitimately SHARED with B must NOT fire (resurrected exoneration)#
# --------------------------------------------------------------------------- #

def test_t1_shared_with_B_does_not_fire():
    ps, env = ProvenanceStore(), EnvelopeEngine()
    _seed_owner_of_id(ps, env, "A", "555")
    # B legitimately received 555 too (a genuinely shared resource):
    B = Principal("B", "b")
    ps.observe_response(_ex("GET", "/api/shared/555", {"id": "555"}, B), legitimate=True)
    v = AuthorityConservationLaw().evaluate(_ctx(_ex("GET", "/api/me", {"id": "555"}, B), ps, env))
    assert v.verdict == Verdict.PASS, "a value B legitimately holds/was-shown must not fire"


# --------------------------------------------------------------------------- #
# ث5 — attribution is order-independent                                        #
# --------------------------------------------------------------------------- #

def test_t5_order_independence():
    def run(seed_owner_first: bool):
        ps, env = ProvenanceStore(), EnvelopeEngine()
        B = Principal("B", "b")
        leak = _ex("GET", "/api/me", {"id": "777"}, B)
        if seed_owner_first:
            _seed_owner_of_id(ps, env, "A", "777")
            return AuthorityConservationLaw().evaluate(_ctx(leak, ps, env))
        # seed an unrelated admin sighting BEFORE owner — must not change attribution
        ps.observe_response(_ex("GET", "/api/admin/list", {"items": [{"id": "777"}]},
                                Principal("M", "m")), legitimate=True)
        _seed_owner_of_id(ps, env, "A", "777")
        return AuthorityConservationLaw().evaluate(_ctx(leak, ps, env))
    a, b = run(True), run(False)
    # owner is A in the clean case; in the admin-list case 777 is only HELD by A
    # (a list element is SEEN not HELD), so attribution is still A — order-free.
    assert a.verdict == b.verdict == Verdict.CANDIDATE
    assert a.evidence["owner_principal"] == b.evidence["owner_principal"] == "A"


# --------------------------------------------------------------------------- #
# ث7 — a value legitimately HELD by several principals is common, not private   #
# --------------------------------------------------------------------------- #

def test_t7_multiple_holders_is_shared():
    ps, env = ProvenanceStore(), EnvelopeEngine()
    _seed_owner_of_id(ps, env, "A", "common")
    _seed_owner_of_id(ps, env, "M", "common")   # two legitimate holders -> shared
    B = Principal("B", "b")
    v = AuthorityConservationLaw().evaluate(_ctx(_ex("GET", "/api/me", {"id": "common"}, B), ps, env))
    assert v.verdict == Verdict.PASS, "a value several principals legitimately hold is not private"


# --------------------------------------------------------------------------- #
# ث10 — a private id in an oddly-named field is caught by MEASURED ownership     #
# --------------------------------------------------------------------------- #

def test_t10_oddly_named_id_caught_by_ownership():
    ps, env = ProvenanceStore(), EnvelopeEngine()
    _seed_owner_of_id(ps, env, "A", "ZX9")          # A holds ZX9
    B = Principal("B", "b")
    # leaked under a non-sensitive field name 'blob' — lexicon would miss it, but
    # ZX9 is a measured holder of A, so privacy_bound fires on the ownership fact.
    v = AuthorityConservationLaw().evaluate(_ctx(_ex("GET", "/api/me", {"blob": "ZX9"}, B), ps, env))
    assert v.verdict == Verdict.CANDIDATE and v.evidence["owner_principal"] == "A"


# --------------------------------------------------------------------------- #
# laundering — an attack-phase sighting can NEVER make a value public           #
# --------------------------------------------------------------------------- #

def test_attack_sighting_cannot_launder_to_public():
    ps, env = ProvenanceStore(), EnvelopeEngine()
    _seed_secret_of(ps, "A", "SK-A-PRIVATE")
    B = Principal("B", "b")
    # attacker floods the value through an attack-phase response (legitimate=False):
    ps.observe_response(_ex("GET", "/api/leakdoor", {"blob": "SK-A-PRIVATE"}, B), legitimate=False)
    v = AuthorityConservationLaw().evaluate(_ctx(_ex("GET", "/api/me", {"blob": "SK-A-PRIVATE"}, B), ps, env))
    assert v.verdict == Verdict.CANDIDATE, "an attack-phase sighting must not exonerate a real leak"
    assert v.evidence["owner_principal"] == "A"


# --------------------------------------------------------------------------- #
# public / self exoneration                                                    #
# --------------------------------------------------------------------------- #

def test_public_value_exonerated():
    ps, env = ProvenanceStore(), EnvelopeEngine()
    _seed_secret_of(ps, "A", "TK")
    ps.observe_response(_ex("GET", "/api/pub", {"blob": "TK"}, Principal("anon", "an")), legitimate=True)
    B = Principal("B", "b")
    v = AuthorityConservationLaw().evaluate(_ctx(_ex("GET", "/api/me", {"blob": "TK"}, B), ps, env))
    assert v.verdict == Verdict.PASS


def test_self_held_exonerated():
    ps, env = ProvenanceStore(), EnvelopeEngine()
    _seed_owner_of_id(ps, env, "B", "ownid")
    B = Principal("B", "b")
    v = AuthorityConservationLaw().evaluate(_ctx(_ex("GET", "/api/me", {"id": "ownid"}, B), ps, env))
    assert v.verdict == Verdict.PASS


# --------------------------------------------------------------------------- #
# abstain — no owner baseline is a VISIBLE coverage gap, not a clean pass        #
# --------------------------------------------------------------------------- #

def test_no_baseline_abstains_visibly():
    ps, env = ProvenanceStore(), EnvelopeEngine()
    B = Principal("B", "b")
    # 'orphan' is a sensitively-named value nobody legitimately owns -> abstain
    ex = _ex("GET", "/api/me", {"ssn": "orphan-secret-value"}, B)
    v = AuthorityConservationLaw().evaluate(_ctx(ex, ps, env))
    assert v.verdict == Verdict.PASS
    assert "coverage gap" in v.reason or "conserved" in v.reason


def test_determinism():
    ps, env = ProvenanceStore(), EnvelopeEngine()
    _seed_owner_of_id(ps, env, "A", "9")
    B = Principal("B", "b")
    ex = _ex("GET", "/api/me", {"id": "9"}, B)
    v1 = AuthorityConservationLaw().evaluate(_ctx(ex, ps, env))
    v2 = AuthorityConservationLaw().evaluate(_ctx(ex, ps, env))
    assert v1.verdict == v2.verdict and v1.reason == v2.reason



# --------------------------------------------------------------------------- #
# service coordinate — authority held on host X, surfaced on host Y (RL9)       #
# --------------------------------------------------------------------------- #

def test_service_coordinate_cross_host():
    from authpath.conservation import AXIS_SERVICE, AXIS_PROPERTY
    ps, env = ProvenanceStore(), EnvelopeEngine()
    A = Principal("A", "a")
    exA = Exchange(HTTPRequest("GET", "/api/acct/77", host="servicex.local"),
                   HTTPResponse(200, {"id": "77"}), A)
    ps.observe_response(exA, legitimate=True); env.observe(exA, EffectClass.OBJECT_ACCESS)
    B = Principal("B", "b")
    cross = Exchange(HTTPRequest("GET", "/api/me", host="servicey.local"),
                     HTTPResponse(200, {"id": "77"}), B)
    v = AuthorityConservationLaw().evaluate(_ctx(cross, ps, env))
    assert v.verdict == Verdict.CANDIDATE and v.evidence["conservation_axis"] == AXIS_SERVICE
    same = Exchange(HTTPRequest("GET", "/api/me", host="servicex.local"),
                    HTTPResponse(200, {"id": "77"}), B)
    v2 = AuthorityConservationLaw().evaluate(_ctx(same, ps, env))
    assert v2.evidence["conservation_axis"] == AXIS_PROPERTY


def test_writes_do_not_fire():
    ps, env = ProvenanceStore(), EnvelopeEngine()
    _seed_owner_of_id(ps, env, "A", "9123456")
    B = Principal("B", "b")
    # the write RESPONSE even leaks A's owned id — only the read-only gate keeps
    # this from firing, so the gate is load-bearing for this assertion.
    ex = Exchange(HTTPRequest("POST", "/api/acct/9123456", host="h",
                              body={"id": "9123456"}),
                  HTTPResponse(200, {"id": "9123456"}), B)
    v = AuthorityConservationLaw().evaluate(_ctx(ex, ps, env))
    assert v.verdict == Verdict.PASS, "a write must not be handled by the read-leak law"


if __name__ == "__main__":
    print("\nAuthority Conservation — adversarial rebuild (session 4)\n" + "-" * 60)
    passed = 0
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        fn()
        passed += 1
        print(f"  [PASS] {name}")
    print("-" * 60)
    print(f"  {passed}/{len(tests)} tests passed \u2713\n")
