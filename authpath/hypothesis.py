"""
authpath.hypothesis — STRUCTURAL HYPOTHESIS ENGINE (RL17, the combinatorial orchestrator).

THE SHIFT THIS MODULE ENCODES
-----------------------------
On a hyperscale target the surviving vulnerability lives in cell #743,219 of a
million-cell (resource × door × role) matrix — not hidden, just never reached,
because a human holds ~50 cells in their head and a per-observation tool only
catches what it happened to look at. RL15/RL16 detect a leak WHERE THEY OBSERVED
it; the leak lives WHERE THEY DID NOT.

This engine is NOT a new detector. It is an ORCHESTRATOR. When RL15/RL16 prove a
leak on one resource, it generalises that single proof into a STRUCTURAL RULE
— "(door D, sensitive field F, resource-type T) leaks" — and uses the rule to
TARGET the matrix cells most likely to repeat it, turning one confirmed finding
into a directed campaign across the resource family. It widens coverage from "what
we observed" to "what the proof implies we should check."

THE ZERO-FALSE-POSITIVE DISCIPLINE (CRUCIBLE v2, Layer Zero)
-----------------------------------------------------------
The combinatorial dimension is the most dangerous for false positives, so the
clustering crucible governs every step:

  * C1 (reverse burden): two endpoints are assumed DIFFERENT until equivalence is
    structurally proven. The only family is "same ResourceIdentity TYPE reached by
    the same door" — never name/shape similarity (that would be induction, RL1).
  * C4 (cross-witness): a derived candidate needs TWO independent witnesses:
      witness-1 = the rule, already PROVEN by a real Δstate finding on an exemplar;
      witness-2 = THIS resource's own canonical read-back contradicting its door.
    Two independent proofs do not coincide by accident — this is what preserves
    zero-FP across the whole matrix.
  * C5 (rigor ∝ scale): a rule only generalises AFTER it is confirmed (a proven
    exemplar). Strength grows with each independent confirmation; the engine never
    convicts on the family "looking wrong" in aggregate.
  * C6 (isolatability): THE FAMILY ONLY DISCOVERS — THE SINGLE Δstate CONVICTS.
    Every derived candidate is one isolated resource proven by the SAME RL15
    confirmer (a live canonical read-back). The combinatorial layer contributes
    targeting only; it adds NO new proof path, hence no new false-positive surface.

Disabled by default at the engine (`combinatorial` flag) ⇒ no rule is ever learned
or applied ⇒ byte-identical to the pre-RL17 engine.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class StructuralRule:
    """A generalisation of a single proven leak: this door over-exposes this
    sensitive field for this resource-type. Derived ONLY from a confirmed Δstate
    finding (never hypothesised from similarity)."""
    resource_type: str
    field_leaf: str
    door_endpoint: str          # the leaking door's endpoint_key (e.g. "GET /api/accounts")

    def __str__(self) -> str:   # pragma: no cover - cosmetic
        return f"{self.door_endpoint} leaks {self.field_leaf} for {self.resource_type}:*"


class HypothesisEngine:
    """Learns structural rules from confirmed findings and proposes the matrix cells
    a rule implies should be re-examined. Holds only derived facts (type/field/
    endpoint names + counts) — no values, no payloads."""

    def __init__(self) -> None:
        # rule -> number of independent resources on which it has been CONFIRMED
        self._rules: dict = {}
        # (rule, object_id) already proposed, so we never re-target the same cell
        self._targeted: set = set()

    # -- learning (only from a real, confirmed Δstate finding) -------------- #
    def learn(self, resource_type: str, field_leaf: str, door_endpoint: str) -> StructuralRule:
        """Record that a leak of `field_leaf` via `door_endpoint` was CONFIRMED on a
        resource of `resource_type`. Each call is one independent confirmation
        (strength ↑). Returns the rule."""
        rule = StructuralRule(str(resource_type), str(field_leaf).lower(), str(door_endpoint))
        self._rules[rule] = self._rules.get(rule, 0) + 1
        return rule

    def knows(self, resource_type: str, field_leaf: str, door_endpoint: str) -> bool:
        """Has this exact (type, field, door) been proven on at least one exemplar?
        (C5: a rule must be earned by a confirmed exemplar before it generalises.)"""
        return StructuralRule(str(resource_type), str(field_leaf).lower(),
                              str(door_endpoint)) in self._rules

    def strength(self, resource_type: str, field_leaf: str, door_endpoint: str) -> int:
        return self._rules.get(
            StructuralRule(str(resource_type), str(field_leaf).lower(), str(door_endpoint)), 0)

    def required_independent_witnesses(self, rule_strength: int, family_size: int) -> int:
        """C5: rigor ∝ scale. The larger the family a rule is about to be applied
        across, the more independent confirmation the rule itself must already carry
        before we trust its TARGETING. (Conviction is always still per-cell Δstate;
        this only governs how widely a thinly-proven rule may be extrapolated.)"""
        if family_size <= 8:
            return 1
        if family_size <= 64:
            return 2
        return 3

    def should_target(self, resource_type: str, field_leaf: str, door_endpoint: str,
                      object_id: str, family_size: int) -> bool:
        """Decide whether to PROPOSE re-examining this matrix cell. True only when:
          * the rule is known (proven on an exemplar), AND
          * its independent-confirmation strength meets the scale-scaled bar (C5), AND
          * this exact cell has not been proposed before.
        Proposing only marks WHERE to look; the per-cell Δstate confirmer decides
        guilt (C6) — so a wrong proposal costs a wasted read, never a false finding."""
        if not self.knows(resource_type, field_leaf, door_endpoint):
            return False
        need = self.required_independent_witnesses(
            self.strength(resource_type, field_leaf, door_endpoint), family_size)
        if self.strength(resource_type, field_leaf, door_endpoint) < need:
            return False
        key = (resource_type, field_leaf.lower(), door_endpoint, str(object_id))
        if key in self._targeted:
            return False
        self._targeted.add(key)
        return True

    @property
    def rule_count(self) -> int:
        return len(self._rules)
