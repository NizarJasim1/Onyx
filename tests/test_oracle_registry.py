"""
GAP-5 — Oracle Registry tests.

These exist to prove the registry is a BEHAVIOUR-PRESERVING generalisation of the
single Confirmer (no regression) AND that its structural zero-FP guard actually
bites (a check only counts if it could have failed — so one test deliberately feeds
the guard a CONFIRMED-without-proof and requires it to be downgraded).
"""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.models import EffectClass, StateProof
from authpath.oracle_registry import (
    DELTA_STATE_EFFECTS, DeltaStateOracle, Oracle, OracleRegistry, OracleVerdict,
    VerdictKind, build_default_registry,
)


def _cand(effect, evidence=None):
    """Duck-typed candidate: the registry only reads verdict.effect / verdict.evidence
    / classification.effect, so this stays decoupled from the full engine model."""
    return SimpleNamespace(
        verdict=SimpleNamespace(effect=effect, evidence=evidence or {}),
        classification=SimpleNamespace(effect=effect),
    )


class _StubConfirmer:
    """Stand-in for the real Confirmer. Returns whatever StateProof (or None) it is
    told, and records how many times it was called."""
    def __init__(self, proof):
        self._proof = proof
        self.calls = 0

    def confirm(self, cand):
        self.calls += 1
        return self._proof


def test_delta_oracle_confirmed_passthrough():
    proof = StateProof(confirmed=True, method="read-back", before=1, after=2, read_as="A")
    reg = build_default_registry(_StubConfirmer(proof))
    v = reg.confirm(_cand(EffectClass.OBJECT_ACCESS))
    assert v.kind is VerdictKind.CONFIRMED
    assert v.as_state_proof() is proof
    assert v.observed_out_of_band and v.expected_value_known_in_advance and v.boundary_owned_both_sides


def test_delta_oracle_abstain_passthrough():
    reg = build_default_registry(_StubConfirmer(None))
    v = reg.confirm(_cand(EffectClass.OWNERSHIP))
    assert v.kind is VerdictKind.ABSTAIN
    assert v.as_state_proof() is None


def test_backward_compat_equivalence_over_all_delta_effects():
    """registry.confirm(...).as_state_proof() == confirmer.confirm(...) for every
    legacy effect — the proof that wiring the registry in changes no verdict."""
    proof = StateProof(confirmed=True, method="rb", before=0, after=1, read_as="A")
    for eff in DELTA_STATE_EFFECTS:
        # confirmed case
        reg = build_default_registry(_StubConfirmer(proof))
        assert reg.confirm(_cand(eff)).as_state_proof() is proof, eff
        # abstain case
        reg2 = build_default_registry(_StubConfirmer(None))
        assert reg2.confirm(_cand(eff)).as_state_proof() is None, eff


def test_zero_fp_guard_downgrades_confirmed_without_proof():
    """THE could-have-failed test. A rogue oracle claims CONFIRMED but supplies no
    out-of-band proof. If the guard were absent this would surface as a finding (a
    false positive). The registry MUST downgrade it to ABSTAIN."""
    class _Rogue(Oracle):
        name = "rogue"
        effects = frozenset({EffectClass.OBJECT_ACCESS})
        def confirm(self, cand, ctx=None):
            return OracleVerdict(kind=VerdictKind.CONFIRMED, effect=EffectClass.OBJECT_ACCESS,
                                 oracle_name=self.name, proof=None,
                                 observed_out_of_band=False,
                                 expected_value_known_in_advance=False,
                                 boundary_owned_both_sides=False)
    reg = OracleRegistry().register(_Rogue())
    v = reg.confirm(_cand(EffectClass.OBJECT_ACCESS))
    assert v.kind is VerdictKind.ABSTAIN
    assert "zero-FP guard" in v.reason


def test_zero_fp_guard_downgrades_partial_preconditions():
    """A real proof but the boundary is NOT tester-owned => still downgraded. Each
    precondition is load-bearing."""
    class _Partial(Oracle):
        name = "partial"
        effects = frozenset({EffectClass.AUTHORITY})
        def confirm(self, cand, ctx=None):
            p = StateProof(confirmed=True, method="rb", before=0, after=1, read_as="X")
            return OracleVerdict(kind=VerdictKind.CONFIRMED, effect=EffectClass.AUTHORITY,
                                 oracle_name=self.name, proof=p,
                                 observed_out_of_band=True,
                                 expected_value_known_in_advance=True,
                                 boundary_owned_both_sides=False)  # <-- the one that fails
    reg = OracleRegistry().register(_Partial())
    v = reg.confirm(_cand(EffectClass.AUTHORITY))
    assert v.kind is VerdictKind.ABSTAIN
    assert "tester-owned" in v.reason


def test_unconfirmable_blackbox_is_declared_not_clean():
    """An effect with no registered oracle returns UNCONFIRMABLE_BLACKBOX — ONYX
    declares the blind spot instead of passing it silently as safe (GAP-12)."""
    reg = OracleRegistry()  # nothing registered
    v = reg.confirm(_cand(EffectClass.PAYMENT))
    assert v.kind is VerdictKind.UNCONFIRMABLE_BLACKBOX
    assert v.as_state_proof() is None
    assert "declared coverage limit" in v.reason


def test_coverage_map_lists_covered_and_declared():
    reg = build_default_registry(_StubConfirmer(None))
    cov = reg.coverage()
    assert EffectClass.OBJECT_ACCESS.value in cov["covered"]
    assert "delta-state" in cov["covered"][EffectClass.OBJECT_ACCESS.value]
    # READ / NONE are never security effects, so they are not "unconfirmable gaps"
    assert EffectClass.READ.value not in cov["declared_unconfirmable"]
    assert EffectClass.NONE.value not in cov["declared_unconfirmable"]
    # before the identity oracle is added, IDENTITY_SPOOF is an honest declared gap
    assert EffectClass.IDENTITY_SPOOF.value in cov["declared_unconfirmable"]
