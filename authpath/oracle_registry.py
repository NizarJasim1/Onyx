"""
authpath/oracle_registry.py — the Oracle Registry (GAP-5 closure).

WHY THIS EXISTS
===============
Until now confirmation lived in ONE place: ``Confirmer._confirm_once``, a dispatch
table ``EffectClass -> strategy -> Optional[StateProof]``. That is a single oracle.
The gap analysis (GAP_ANALYSIS_v3, gap #5 — "the hook / the soul") showed that
expanding ONYX to new violation CLASSES (identity spoofing, silent grants, log-
only effects) by bolting detectors onto that one oracle would eventually erode the
crown jewel: zero false positives.

The root move (not a patch) is to GENERALISE the single confirmer into a REGISTRY
of deterministic, FP-safe-by-construction oracles — one (or more) per EffectClass —
all under the same red lines:

    RL1  no inference            — a proof is OBSERVED, never deduced.
    RL2  no model in the path    — the verdict is a deterministic check, no ML.
    RL3  Delta-state / observed  — every CONFIRMED carries a real read-back.
    RL5  fail-closed             — any doubt resolves to ABSTAIN, never a finding.

THE STRUCTURAL ZERO-FP LOCK
===========================
The registry does not TRUST an oracle that says "CONFIRMED". It re-checks three
preconditions that every sound ONYX proof has always satisfied, and DOWNGRADES any
confirmation that fails even one of them to ABSTAIN:

    1. observed_out_of_band            — evidence from an independent authenticated
                                         read, not the attack response, not inference.
    2. expected_value_known_in_advance — the tester knew the victim value BEFORE the
                                         probe, so a match cannot be coincidence or a
                                         planted echo.
    3. boundary_owned_both_sides       — both principals/tenants are tester-owned, so
                                         nothing about a real third party is touched.

A new oracle therefore CANNOT raise a finding without supplying a genuine owned,
pre-known, out-of-band proof. Zero-FP is preserved BY CONSTRUCTION, not by audit.

THE HONESTY SLOT (GAP-12)
=========================
If an EffectClass has no FP-safe oracle, the registry returns
UNCONFIRMABLE_BLACKBOX — an explicit "declared, not covered" verdict. That is NOT
"clean" and NOT a vulnerability. It makes ONYX state exactly where it is blind
instead of letting an unconfirmable class pass silently as safe.

BACKWARD COMPATIBILITY
======================
``DeltaStateOracle`` wraps the existing ``Confirmer`` unchanged. For every class the
Confirmer already handles, ``registry.confirm(cand)`` returns exactly what
``confirmer.confirm(cand)`` returns (CONFIRMED<->proof, ABSTAIN<->None). The engine
may keep calling the Confirmer directly; the registry is an additive superset.
Wiring it in changes no existing verdict — proven by the unchanged test suite and
the unchanged zero-FP live proof.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .models import Candidate, EffectClass, StateProof


class VerdictKind(str, Enum):
    CONFIRMED = "CONFIRMED"                    # a real owned, pre-known, out-of-band proof exists
    ABSTAIN = "ABSTAIN"                        # no proof — ONYX stays silent (RL5)
    UNCONFIRMABLE_BLACKBOX = "UNCONFIRMABLE"   # no FP-safe oracle for this class — declared, not covered (GAP-12)


@dataclass
class OracleVerdict:
    """The uniform result every oracle returns. The three precondition flags are the
    registry's structural zero-FP lock; an oracle asserts them and the registry
    RE-ENFORCES them before any CONFIRMED is allowed to stand."""
    kind: VerdictKind
    effect: Optional[EffectClass]
    oracle_name: str
    proof: Optional[StateProof] = None
    reason: str = ""
    observed_out_of_band: bool = False
    expected_value_known_in_advance: bool = False
    boundary_owned_both_sides: bool = False
    # GAP-9: a SECOND, equally-strict FP-safe confirmation basis. "value-match" (default)
    # needs the victim's value; "structural-contract" confirms VALUELESSLY against the
    # target's OWN disclosed contract — so third-party data is never read/harvested.
    confirmation_basis: str = "value-match"
    contract_anchored: bool = False        # the "must be absent/denied" expectation is a measured fact FROM the target (RL1)
    attacker_owned: bool = False           # the probing principal is tester-owned

    @property
    def confirmed(self) -> bool:
        return self.kind is VerdictKind.CONFIRMED

    def as_state_proof(self) -> Optional[StateProof]:
        """Bridge back to the legacy return type (``Optional[StateProof]``) so callers
        that still speak the old contract are unaffected."""
        return self.proof if self.kind is VerdictKind.CONFIRMED else None


def _effect_of(cand: Candidate) -> Optional[EffectClass]:
    """The LAW's effect takes priority over the request classification — the same
    rule ``Confirmer._confirm_once`` uses."""
    v = getattr(cand, "verdict", None)
    eff = getattr(v, "effect", None)
    if eff is None:
        cls = getattr(cand, "classification", None)
        eff = getattr(cls, "effect", None)
    return eff


class Oracle:
    """Base contract. A concrete oracle confirms ONE family of effect classes with a
    deterministic, FP-safe read-back. Subclasses override ``confirm``."""
    name: str = "oracle"
    effects: frozenset = frozenset()

    def applies(self, cand: Candidate) -> bool:
        return _effect_of(cand) in self.effects

    def confirm(self, cand: Candidate, ctx: Optional[dict] = None) -> OracleVerdict:
        raise NotImplementedError


# Effect classes the legacy Delta-state Confirmer already proves. Under GAP-5 they
# migrate UNDER the registry as the DeltaStateOracle's domain, with no behaviour
# change whatsoever.
DELTA_STATE_EFFECTS = frozenset({
    EffectClass.OBJECT_ACCESS, EffectClass.OWNERSHIP, EffectClass.AUTHORITY,
    EffectClass.AUTHORITY_GRANT, EffectClass.PAYMENT, EffectClass.PRICE,
    EffectClass.STATE_GATE, EffectClass.INVENTORY, EffectClass.COUPON,
    EffectClass.TEMPORAL_DRIFT, EffectClass.STRUCTURAL_DIVERGENCE,
    EffectClass.FIELD_PROJECTION, EffectClass.CROSS_SURFACE,
    EffectClass.AUTH_REGRESSION, EffectClass.EMERGENT_BREAK,
})


class DeltaStateOracle(Oracle):
    """Wraps the existing ``Confirmer``. Behaviour-identical: it IS the current
    oracle, now registered as one entry among many. A confirmed Delta-state read-back
    is, by construction, an out-of-band authenticated read as the owner of a tester-
    provisioned object on a tester-owned boundary — so the three preconditions hold
    exactly when the Confirmer confirms."""
    name = "delta-state"
    effects = DELTA_STATE_EFFECTS

    def __init__(self, confirmer):
        self.confirmer = confirmer

    def confirm(self, cand: Candidate, ctx: Optional[dict] = None) -> OracleVerdict:
        effect = _effect_of(cand)
        proof = self.confirmer.confirm(cand)
        if proof is not None and getattr(proof, "confirmed", False):
            return OracleVerdict(
                kind=VerdictKind.CONFIRMED, effect=effect, oracle_name=self.name,
                proof=proof, reason=getattr(proof, "detail", "") or "Delta-state read-back",
                observed_out_of_band=True,
                expected_value_known_in_advance=True,
                boundary_owned_both_sides=True,
            )
        return OracleVerdict(
            kind=VerdictKind.ABSTAIN, effect=effect, oracle_name=self.name,
            reason="no Delta-state read-back (abstain)",
        )


class OracleRegistry:
    """The GAP-5 generalisation: ``EffectClass -> FP-safe oracle(s)``, with a
    structural zero-FP guard and a declared-coverage slot."""

    def __init__(self):
        self._by_effect: dict = {}
        self._oracles: list = []

    def register(self, oracle: Oracle) -> "OracleRegistry":
        self._oracles.append(oracle)
        for eff in oracle.effects:
            self._by_effect.setdefault(eff, []).append(oracle)
        return self

    def oracles_for(self, effect) -> list:
        return list(self._by_effect.get(effect, []))

    def confirm(self, cand: Candidate, ctx: Optional[dict] = None) -> OracleVerdict:
        effect = _effect_of(cand)
        oracles = self._by_effect.get(effect, [])
        if not oracles:
            # GAP-12 honesty slot: not blind-silent, we DECLARE the gap.
            return OracleVerdict(
                kind=VerdictKind.UNCONFIRMABLE_BLACKBOX, effect=effect,
                oracle_name="<none>",
                reason=f"no FP-safe oracle registered for effect {effect!r} — "
                       f"declared coverage limit, not a clean verdict",
            )
        # First oracle that applies and reaches a non-abstain verdict wins; any
        # CONFIRMED is re-validated by the guard below. Order = registration order.
        last = None
        for oracle in oracles:
            if not oracle.applies(cand):
                continue
            v = oracle.confirm(cand, ctx)
            last = v
            if v.kind is VerdictKind.CONFIRMED:
                return self._enforce(v)
        return last or OracleVerdict(
            kind=VerdictKind.ABSTAIN, effect=effect, oracle_name="<none-applied>",
            reason="no registered oracle applied to this candidate",
        )

    def _enforce(self, v: OracleVerdict) -> OracleVerdict:
        """THE STRUCTURAL ZERO-FP LOCK. A CONFIRMED verdict survives only if it
        carries a real proof AND all three red-line preconditions. Otherwise it is
        DOWNGRADED to ABSTAIN (fail-closed, RL5). This is what lets new oracles be
        added without ever endangering precision."""
        has_proof = v.proof is not None and getattr(v.proof, "confirmed", False)
        missing = []
        if v.confirmation_basis == "structural-contract":
            # GAP-9 valueless basis — equally strict, different quartet: no victim value
            # is read, so FP-safety rests on the "absent/denied" expectation being a
            # MEASURED fact from the target's own disclosure (RL1), probed as a tester-
            # owned attacker.
            ok = has_proof and v.observed_out_of_band and v.contract_anchored and v.attacker_owned
            if not has_proof: missing.append("no observed structural proof")
            if not v.observed_out_of_band: missing.append("proof not out-of-band (RL1)")
            if not v.contract_anchored:
                missing.append("expected shape not anchored to the target's own disclosed contract (RL1)")
            if not v.attacker_owned: missing.append("probing principal not tester-owned (RL5)")
        else:
            ok = (has_proof and v.observed_out_of_band
                  and v.expected_value_known_in_advance and v.boundary_owned_both_sides)
            if not has_proof: missing.append("no observed Delta-state proof")
            if not v.observed_out_of_band: missing.append("proof not out-of-band (RL1)")
            if not v.expected_value_known_in_advance: missing.append("victim value not known in advance")
            if not v.boundary_owned_both_sides: missing.append("boundary not tester-owned (RL5)")
        if ok:
            return v
        return OracleVerdict(
            kind=VerdictKind.ABSTAIN, effect=v.effect, oracle_name=v.oracle_name,
            reason="downgraded by zero-FP guard: " + "; ".join(missing),
        )

    def coverage(self) -> dict:
        """The honesty map (GAP-12): which classes have an FP-safe oracle, and which
        are declared unconfirmable black-box. Truthful self-knowledge is part of the
        edge — you know exactly where you are blind."""
        covered = {eff.value: [o.name for o in ol] for eff, ol in self._by_effect.items()}
        declared = [e.value for e in EffectClass
                    if e not in self._by_effect
                    and e not in (EffectClass.READ, EffectClass.NONE)]
        return {"covered": covered, "declared_unconfirmable": sorted(declared)}


def build_default_registry(confirmer, identity_oracle=None, extra_oracles=None) -> OracleRegistry:
    """Assemble the standard registry: the legacy Delta-state oracle for the object-
    level classes, plus the identity oracle (GAP-1) and any ``extra_oracles`` (e.g.
    the cross-tenant and parser-differential oracles, GAP-2/GAP-4) the engine wires.
    Additive: with no extra oracles the registry's behaviour over existing classes is
    byte-identical to the Confirmer alone."""
    reg = OracleRegistry()
    reg.register(DeltaStateOracle(confirmer))
    if identity_oracle is not None:
        reg.register(identity_oracle)
    for o in (extra_oracles or []):
        reg.register(o)
    return reg
