"""
authpath.nerve_unification — the single law under which RL15-18 are special cases.

This module is DESCRIPTIVE ONLY. It adds no detection and no conviction; it records,
and lets a test pin, the architectural fact the FORGE build established:

    ONE CONSERVED QUANTITY — DECISION CONSISTENCY.
    For the same (declared-authority, object, permission), the target must make the
    SAME authorization decision regardless of the PATH taken to it. A vulnerability is
    the target contradicting that decision across a path-transformation, proven by
    Δstate. Every existing ONYX engine enforces this law along ONE path-transformation
    axis; the nerve adds the IDENTITY/ownership axis and supplies the general frame.

The empirical proof that these are genuinely the same law (not just a tidy story):
the nerve's own `EquivalenceLedger.decision_conflict_pairs()` — using the SAME audited
`surface_map.identify` the engines use — surfaces the RL15 (representation) and RL16
(time) inconsistencies as candidates. See tests/test_nerve_unification.py.

Nothing in the live pipeline imports this module, so it is byte-identical inert.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Dimension:
    axis: str            # the path-transformation that must not change the decision
    law: str             # the conserved invariant, stated as decision-consistency
    engine_flag: str     # the existing engine/flag that CONVICTS along this axis today
    note: str


# The conserved quantity, stated once.
CONSERVED_LAW = (
    "For a fixed (declared-authority, object, permission), the target's authorization "
    "decision is invariant under the path taken to it; a vulnerability is a decision "
    "the target contradicts across a path-transformation, confirmed by Δstate."
)

# The five path-transformation axes. The first four are the existing engines; the
# fifth is the nerve. All are instances of CONSERVED_LAW.
DIMENSIONS = (
    Dimension(
        axis="representation / door",
        law="same object via two surfaces (REST vs GraphQL/BFF) ⇒ same decision",
        engine_flag="cross_surface (RL15)",
        note="identity unified by surface_map.identify — the SAME primitive the nerve uses"),
    Dimension(
        axis="time",
        law="same object across observations in time ⇒ same decision (absent a declared change)",
        engine_flag="temporal_shape (RL16)",
        note="value-blind authorization-shape snapshot diffed across reads"),
    Dimension(
        axis="sibling / combinatorial",
        law="sibling objects under the same authority relation ⇒ same decision",
        engine_flag="combinatorial (RL17)",
        note="boundary generalisation across an object family"),
    Dimension(
        axis="hierarchy / composition",
        law="a child inherits its parent's decision; a re-homed parent must move the child's",
        engine_flag="global_invariants (RL18)",
        note="emergent parent/child break detected from the observed access sequence"),
    Dimension(
        axis="identity / ownership",
        law="an object's declared owner ≠ the accessor (with no declared grant) ⇒ deny; "
            "serving it is a contradiction",
        engine_flag="nerve (identity⇄ownership)",
        note="the target attests identity and declares ownership; the nerve holds it to both"),
)


def covered_axes() -> set:
    return {d.axis for d in DIMENSIONS}


def engine_for_axis(axis: str) -> str:
    for d in DIMENSIONS:
        if d.axis == axis:
            return d.engine_flag
    raise KeyError(axis)
