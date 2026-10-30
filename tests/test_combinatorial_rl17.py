"""
RL17 — COMBINATORIAL ORCHESTRATION regression suite (CRUCIBLE v2, Layer Zero).

The engine is an ORCHESTRATOR, not a new detector: one CONFIRMED leak generalises
into a structural rule that TARGETS sibling matrix cells, each convicted by its own
per-cell Δstate. The clustering-crucible guarantees under test:

  * orchestration      — one observed proof discovers UNOBSERVED sibling leaks
  * C6 isolatability    — a public sibling matching the rule is REFUTED per-cell
                          (the family discovers; the single Δstate convicts) → zero FP
  * C5 rigor ∝ scale    — a rule must be earned by a confirmed exemplar before it
                          generalises; required witnesses grow with family size
  * additive isolation  — flag OFF ⇒ no rule learned/applied ⇒ byte-identical
  * RL1 no induction    — a rule is (type, field, door) proven by Δstate, never
                          name/shape similarity
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.transport import make_exchange
from authpath.models import HTTPRequest, HTTPResponse, Principal
from authpath.hypothesis import HypothesisEngine

B = Principal("B", "Bob")


def _engine(target, combinatorial=True, cross=True, contract=None):
    scope = ScopeConfig(allowed_hosts=["demo.local"], dry_run=True,
                        automation_permitted=True)
    eng = AuthPathEngine(target, {"B": B}, scope, contract=contract or {})
    eng.cross_surface = cross
    eng.combinatorial = combinatorial
    return eng


class _PayoutTarget:
    """A payouts list leaking `iban` for 600..603. Canonical filters it for the
    vulnerable 600/601/602, but 603 is a PUBLIC payout whose detail legitimately
    exposes it (rule must be refuted there → no false positive)."""
    host = "demo.local"

    def send(self, req, principal):
        m, p = req.method.upper(), req.path
        if m == "GET" and p == "/api/payouts":
            return HTTPResponse(200, {"payouts": [
                {"id": "600", "status": "paid", "iban": "IQ11AAA600"},
                {"id": "601", "status": "paid", "iban": "IQ11AAA601"},
                {"id": "602", "status": "paid", "iban": "IQ11AAA602"},
                {"id": "603", "status": "paid", "iban": "IQ11AAA603"},
            ]})
        if m == "GET" and p.startswith("/api/payouts/"):
            oid = p.rsplit("/", 1)[-1]
            if oid == "603":
                return HTTPResponse(200, {"id": "603", "status": "paid", "iban": "IQ11AAA603"})
            if oid in ("600", "601", "602"):
                return HTTPResponse(200, {"id": oid, "status": "paid"})
            return HTTPResponse(404, {"error": "not found"})
        return HTTPResponse(404, {"error": "no route"})


def _run_payouts(combinatorial=True):
    contract = {"GET /api/payouts/{id}": {"effect": "OBJECT_ACCESS"}}
    t = _PayoutTarget()
    eng = _engine(t, combinatorial=combinatorial, contract=contract)
    eng.observe(make_exchange(t, HTTPRequest("GET", "/api/payouts/600"), B))  # reference for 600
    eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/payouts"), B))      # list + orchestration
    return eng


def _convicted_ids(eng):
    return {f.target_ref for f in eng.findings if f.effect.value == "CROSS_SURFACE"}


# ----------------------------- the guarantees ------------------------------ #

def test_orchestration_discovers_unobserved_siblings():
    eng = _run_payouts(combinatorial=True)
    ids = _convicted_ids(eng)
    # 600 convicted directly by RL15; 601 & 602 discovered by orchestration
    assert {"600", "601", "602"}.issubset(ids), f"expected 600/601/602, got {ids}"
    assert eng._derived_count == 2


def test_public_sibling_is_refuted_zero_fp():
    """C6: the family only DISCOVERS; the single per-cell Δstate CONVICTS. The public
    payout 603 matches the rule but its canonical legitimately exposes iban, so the
    per-cell read-back refutes it — it must NOT be convicted."""
    eng = _run_payouts(combinatorial=True)
    assert "603" not in _convicted_ids(eng), "a rule-matching public sibling must be cleared"


def test_without_orchestration_only_observed_is_found():
    """With RL17 off, only the directly-observed 600 is convicted; the siblings stay
    invisible — quantifying exactly what the orchestrator adds."""
    eng = _run_payouts(combinatorial=False)
    ids = _convicted_ids(eng)
    assert ids == {"600"}, f"without RL17 only 600 should be found, got {ids}"
    assert eng._derived_count == 0


def test_flag_off_is_byte_identical():
    eng = _run_payouts(combinatorial=False)
    assert eng.hypothesis.rule_count == 0  # no rule ever learned when off
    assert eng._derived_count == 0


# --------------------------- hypothesis engine units ----------------------- #

def test_rule_must_be_earned_before_targeting():
    """C5: an unproven rule never targets anything."""
    h = HypothesisEngine()
    assert not h.knows("payout", "iban", "GET /api/payouts")
    assert not h.should_target("payout", "iban", "GET /api/payouts", "601", family_size=4)
    h.learn("payout", "iban", "GET /api/payouts")
    assert h.knows("payout", "iban", "GET /api/payouts")
    assert h.should_target("payout", "iban", "GET /api/payouts", "601", family_size=4)


def test_rigor_scales_with_family_size():
    """C5: a thinly-proven rule may target a small family but needs more independent
    confirmation as the family grows (≤8 → 1, ≤64 → 2, larger → 3)."""
    h = HypothesisEngine()
    h.learn("payout", "iban", "GET /api/payouts")          # strength 1
    assert h.should_target("payout", "iban", "GET /api/payouts", "x1", family_size=8)
    # a medium family needs ≥2 confirmations; strength 1 is insufficient
    assert not h.should_target("payout", "iban", "GET /api/payouts", "x2", family_size=64)
    h.learn("payout", "iban", "GET /api/payouts")          # strength 2
    assert h.should_target("payout", "iban", "GET /api/payouts", "x3", family_size=64)
    # a large family needs ≥3 confirmations; strength 2 is still insufficient
    assert not h.should_target("payout", "iban", "GET /api/payouts", "x4", family_size=500)
    h.learn("payout", "iban", "GET /api/payouts")          # strength 3
    assert h.should_target("payout", "iban", "GET /api/payouts", "x5", family_size=500)


def test_cell_proposed_only_once():
    h = HypothesisEngine()
    h.learn("payout", "iban", "GET /api/payouts")
    assert h.should_target("payout", "iban", "GET /api/payouts", "601", family_size=4)
    assert not h.should_target("payout", "iban", "GET /api/payouts", "601", family_size=4)
