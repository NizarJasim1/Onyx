"""
authpath/state_driver.py — law<->required-state driving planner (GAP-8).

THE MISSING HALF (named by the project itself)
==============================================
`completeness.py` states the one genuinely open part plainly: "can we drive the system
into every violating state? This is the genuinely open part." `composite_sequences`
already FINDS the paths that need writes, but marks them ``executable=False,
requires_writes=True`` — a worklist, not a plan. `state_machine` emits
``prior_state_requirements`` ("the PRIOR state was P") but does not reach it.

What was missing is ONYX's half of the drive: binding a law L to the state S it needs,
and composing LEGITIMATE, consent-gated primitives into an EXECUTABLE ordered plan that
reaches S — so a context-dependent BAC (create -> pay partially -> open a refund window
-> NOW the authz bug appears) can be reached instead of skipped. This closes that half.

RED LINES
=========
- RL5 (consent/scope): a plan may use ONLY consent-gated primitives — writes the tester
  is authorized to perform on their OWN resources to set up the state. A non-consented
  primitive is refused and the plan reports it; it is never silently included.
- RL3: the plan is a LEAD (a reach path), not a finding. The law still fires through the
  deterministic Δstate / Oracle-Registry confirmation, unchanged.
- Honest unreachability: if S cannot be reached with the available consent-gated
  primitives, the planner says so and NAMES the missing facts — a bounded, stated residual
  in the exact spirit of `completeness.py`, never a false "covered".

Deterministic forward chaining, pure stdlib.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Primitive:
    """One legitimate setup action. ``requires`` facts must hold to apply it; ``provides``
    facts it establishes. ``creates_objects`` are dynamic object refs it brings into being
    (to be pinned in time — see state_pin, GAP L1-8). ``consent_gated`` MUST be True for the
    primitive to be usable (RL5)."""
    name: str
    requires: frozenset = frozenset()
    provides: frozenset = frozenset()
    consent_gated: bool = True
    creates_objects: tuple = ()


@dataclass
class DrivePlan:
    reachable: bool
    steps: list                      # ordered primitive names to execute
    created_objects: list            # dynamic objects the plan will create (pin these)
    law: str = ""
    reason: str = ""


class LawStatePlanner:
    """Composes consent-gated primitives into an ordered plan that drives the target from
    its current facts to the state a law requires."""

    def plan(self, current_facts, required_facts, primitives, law_name: str = "") -> DrivePlan:
        current = set(current_facts)
        required = set(required_facts)
        usable = [p for p in primitives if p.consent_gated]
        refused = sorted(p.name for p in primitives if not p.consent_gated)   # RL5

        steps: list = []
        created: list = []
        used: set = set()
        progress = True
        # deterministic forward chaining: apply any consent-gated primitive whose
        # requirements hold and that adds something new, until S is reached or stuck.
        while not required.issubset(current) and progress:
            progress = False
            for p in sorted(usable, key=lambda x: x.name):
                if p.name in used:
                    continue
                if p.requires.issubset(current) and not set(p.provides).issubset(current):
                    current |= set(p.provides)
                    steps.append(p.name)
                    created.extend(p.creates_objects)
                    used.add(p.name)
                    progress = True

        if required.issubset(current):
            reason = "reached required state via consent-gated writes"
            if refused:
                reason += f"; non-consented primitives left out (RL5): {refused}"
            return DrivePlan(True, steps, created, law=law_name, reason=reason)

        missing = sorted(required - current)
        reason = (f"cannot reach required state with available consent-gated primitives; "
                  f"missing facts: {missing}")
        if refused:
            reason += f"; non-consented primitives refused (RL5): {refused}"
        return DrivePlan(False, steps, created, law=law_name, reason=reason)


def required_facts_from_prior_state(prior_state_requirements) -> set:
    """Adapter: turn `state_machine.prior_state_requirements` shapes
    ({'field': 'paid', 'equals': True}) into planner facts ('paid=True'). Lets the driver
    consume what the existing layer-E machine already emits — binding law<->state."""
    facts = set()
    for r in (prior_state_requirements or []):
        if not isinstance(r, dict):
            continue
        f = r.get("field")
        if f is None:
            continue
        facts.add(f"{f}={r.get('equals')}")
    return facts
