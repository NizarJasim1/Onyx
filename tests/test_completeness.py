"""
ASSURANCE-3 — completeness: closed oracle + spec-relative coverage certificate.

Proves the oracle recognizes violations by EFFECT without being told the class
(so there are no unknown violation TYPES for content-observable effects), that
completeness OVER THE DOCUMENTED SURFACE is enumerable and certifiable, and that the
irreducible residual is enumerated with each item's basis.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from authpath import certificate as C
from authpath import completeness as K


# --------------------------------------------------------------------------- #
# The closed oracle — class-agnostic detection by effect.                      #
# --------------------------------------------------------------------------- #

def _leak_transcript(secret="SEC-1", anon=False):
    return {
        "attacker": {"principal": ("anon" if anon else "bob"),
                     "request": {"method": "GET", "path": "/whatever"},
                     "response": {"status": 200, "body": {"id": "ALICE", "iban": secret}}},
        "owner_view": {"response": {"status": 200, "body": {"id": "ALICE", "iban": secret}}},
    }


def _write_transcript():
    return {
        "attacker": {"principal": "bob", "request": {"method": "PUT", "path": "/whatever"},
                     "response": {"status": 200, "body": {"ok": True}}},
        "victim_readback_before": {"response": {"status": 200, "body": {"id": "D", "v": "orig"}}},
        "victim_readback_after": {"response": {"status": 200, "body": {"id": "D", "v": "PWNED"}}},
    }


def test_universal_detects_leak_without_being_told_the_class():
    kind, r = K.check_universal(_leak_transcript(), read_as="alice", sensitive_field="iban")
    assert kind == C.KIND_READ_LEAK and r["status"] == C.CERTIFIED, (kind, r)


def test_universal_detects_anonymous_leak_without_being_told_the_class():
    kind, r = K.check_universal(_leak_transcript(anon=True), read_as="alice",
                                sensitive_field="iban", attacker_anonymous=True)
    assert kind == C.KIND_AUTHN_GAP and r["status"] == C.CERTIFIED, (kind, r)


def test_universal_detects_write_without_being_told_the_class():
    kind, r = K.check_universal(_write_transcript(), read_as="alice")
    assert kind == C.KIND_XPRINCIPAL_WRITE and r["status"] == C.CERTIFIED, (kind, r)


def test_universal_abstains_without_owner_evidence():
    kind, r = K.check_universal({"attacker": {"principal": "bob", "request": {}, "response": {"status": 200, "body": {}}}},
                                read_as="alice")
    assert kind is None and r["status"] == C.ABSTAIN, (kind, r)


# --------------------------------------------------------------------------- #
# Spec-relative coverage certificate.                                          #
# --------------------------------------------------------------------------- #

_SPEC = [{"endpoint": "GET /api/orders/{id}", "ref_params": ["id"]},
         {"endpoint": "PUT /api/docs/{id}", "ref_params": ["id"]}]
_PRINCIPALS = ["alice", "bob", "carol"]


def test_obligations_enumerate_the_documented_surface_completely():
    obs = K.authorization_obligations(_SPEC, _PRINCIPALS)
    # 2 endpoints x (3*2 ordered actor!=owner pairs) x 1 ref each = 12
    assert len(obs) == 12, len(obs)


def test_coverage_is_incomplete_when_obligations_remain():
    obs = K.authorization_obligations(_SPEC, _PRINCIPALS)
    cov = K.coverage_certificate(obs, discharged=obs[:5])
    assert cov["complete_over_documented_surface"] is False
    assert len(cov["remaining"]) == 7 and cov["discharged"] == 5


def test_coverage_is_complete_over_documented_surface_when_all_discharged():
    obs = K.authorization_obligations(_SPEC, _PRINCIPALS)
    cov = K.coverage_certificate(obs, discharged=obs)
    assert cov["complete_over_documented_surface"] is True
    assert cov["fraction_documented"] == 1.0


# --------------------------------------------------------------------------- #
# The irreducible residual — precise and honest.                              #
# --------------------------------------------------------------------------- #

def test_residual_enumerates_out_of_invariant_and_coverage_bounded():
    kinds = {kind for _, kind, _ in K.IRREDUCIBLE_RESIDUALS}
    assert "out-of-invariant" in kinds and "coverage-bounded" in kinds
    assert len(K.IRREDUCIBLE_RESIDUALS) >= 4


def test_completeness_statement_is_honest_about_the_limit():
    obs = K.authorization_obligations(_SPEC, _PRINCIPALS)
    cov = K.coverage_certificate(obs, discharged=obs)
    text = K.completeness_statement(cov)
    assert "documented surface" in text.lower()
    assert "unknown-unknowns" in text.lower()
    assert "unattainable offline" in text.lower()  # never claims literal 100%


if __name__ == "__main__":
    import traceback
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    print("\nASSURANCE-3 completeness tests\n" + "-" * 60)
    p = _fail = 0
    for n, f in fns:
        try:
            f(); p += 1; print(f"  [PASS] {n}")
        except Exception:
            _fail += 1; print(f"  [FAIL] {n}"); traceback.print_exc()
    print("-" * 60); print(f"  {p}/{len(fns)} passed\n")
    sys.exit(1 if _fail else 0)
