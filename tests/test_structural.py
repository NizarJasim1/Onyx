"""
Unit self-tests for SAIE Layer 0 + Layer 1 + the divergence primitive (Part F
Step 1).  These prove the pure module in isolation BEFORE any engine wiring.

Run: python tests/test_structural.py    (or under pytest)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.structural import (
    AbsenceState, NodeStability, StabilityGate, divergence, fingerprint,
)


# ---- worked-example shapes (Part B intent, built to the prose, not the literal
# JSON: no substantive top-level scalar is shared between privileged and filtered) #
PRIVILEGED = {
    "id": "50", "status": "shipped", "total": 91.0,
    "buyer": {"id": "50", "tier": "gold"},
    "internal": {"margin": 22.4, "risk_score": 0.1, "fraud_flags": []},
    "audit": {"by": "sys", "at": "2026-01-02T00:00:00Z"},
}
# same SHAPE as privileged, sensitive values nulled (the leak signature)
FILTERED = {
    "id": "50", "status": "shipped", "total": None,
    "buyer": {"id": "50", "tier": None},
    "internal": {"margin": None, "risk_score": None, "fraud_flags": []},
    "audit": {"by": None, "at": None},
}
# genuine low-priv own-grammar shape: privileged branches ABSENT entirely
LEAN = {
    "id": "60", "status": "pending", "total": 12.0,
    "buyer": {"id": "60", "tier": "silver"},
}


def test_fingerprint_is_value_blind():
    """Two bodies differing ONLY in scalar values are structurally identical."""
    a = fingerprint({"id": "1", "total": 10.0, "buyer": {"tier": "gold"}})
    b = fingerprint({"id": "2", "total": 99.9, "buyer": {"tier": "silver"}})
    assert a.absence_map == b.absence_map
    assert a.types == b.types
    assert a.order == b.order
    assert not divergence(a, b).diverged, "value-only difference must not diverge"


def test_identical_bodies_no_divergence():
    a = fingerprint(PRIVILEGED)
    b = fingerprint(PRIVILEGED)
    assert not divergence(a, b).diverged


def test_present_null_vs_absent_is_the_decisive_signal():
    """FILTERED keeps internal.*/audit.* as PRESENT_NULL; LEAN lacks them (ABSENT).
    That difference is the core SAIE signal and MUST surface in absence_div."""
    fp_filtered = fingerprint(FILTERED)
    fp_lean = fingerprint(LEAN)
    rep = divergence(fp_filtered, fp_lean)
    diverging_paths = {p for (p, _sa, _sb) in rep.absence_div}
    assert "internal.margin" in diverging_paths
    assert "audit.by" in diverging_paths
    # specifically PRESENT_NULL on one side, ABSENT on the other
    states = {p: (sa, sb) for (p, sa, sb) in rep.absence_div}
    assert states["internal.margin"] == (AbsenceState.PRESENT_NULL, AbsenceState.ABSENT)


def test_privileged_vs_filtered_diverges_on_absence_state():
    """Same shape, populated vs nulled values -> divergence ON absence_map
    (state differs) even though present-path SETS are equal."""
    fp_priv = fingerprint(PRIVILEGED)
    fp_filt = fingerprint(FILTERED)
    assert fp_priv.present_paths() == fp_filt.present_paths(), "same shape"
    rep = divergence(fp_priv, fp_filt)
    assert rep.diverged
    assert any(sa == AbsenceState.PRESENT_POPULATED and sb == AbsenceState.PRESENT_NULL
               for (_p, sa, sb) in rep.absence_div)
    assert not rep.topology_div, "shape (types) identical -> no topology divergence"


def test_stability_gate_struct_like_on_identical_repeats():
    g = StabilityGate()
    fam = "GET /api/widgets/{id}"
    g.observe_repeat(fam, "A::w::50", PRIVILEGED)
    g.observe_repeat(fam, "A::w::50", PRIVILEGED)
    mask = g.trust_mask(fam)
    assert mask.stable and mask.samples == 1
    assert mask.node_stability["internal"] == NodeStability.STRUCT_LIKE
    assert "internal.margin" in mask.state_trusted
    assert mask.admissible("internal.margin")


def test_stability_gate_single_observation_trusts_nothing():
    g = StabilityGate()
    fam = "GET /api/widgets/{id}"
    g.observe_repeat(fam, "A::w::50", PRIVILEGED)   # only once
    mask = g.trust_mask(fam)
    assert not mask.stable and mask.samples == 0
    assert mask.node_stability.get("internal") == NodeStability.VOLATILE


def test_value_variation_across_repeats_stays_struct_like():
    """A scalar whose VALUE changes across identical requests is still stable
    (the gate compares value-blind fingerprints)."""
    g = StabilityGate()
    fam = "GET /api/widgets/{id}"
    g.observe_repeat(fam, "B::w::70", {"id": "70", "total": 12.0, "buyer": {"tier": "silver"}})
    g.observe_repeat(fam, "B::w::70", {"id": "70", "total": 13.5, "buyer": {"tier": "silver"}})
    mask = g.trust_mask(fam)
    assert mask.node_stability["buyer"] == NodeStability.STRUCT_LIKE
    assert mask.admissible("total")
    # but the STATE of a field that didn't change is trusted; here total stayed populated
    assert "total" in mask.state_trusted


def test_map_like_reorder_disables_order_only():
    """Identical topology + keys, different serialization order -> MAP_LIKE.
    Order signal disabled; absence/topology still trusted; reorder does NOT
    diverge when comparing through the mask."""
    g = StabilityGate()
    fam = "GET /api/config"
    g.observe_repeat(fam, "A::c::", {"a": 1, "b": 2, "c": 3})
    g.observe_repeat(fam, "A::c::", {"c": 3, "a": 1, "b": 2})   # reordered
    mask = g.trust_mask(fam)
    assert mask.node_stability["$"] == NodeStability.MAP_LIKE
    assert "$" not in mask.order_trusted
    # a reordered pair must NOT diverge under this mask
    fp1 = fingerprint({"a": 1, "b": 2, "c": 3}, mask)
    fp2 = fingerprint({"b": 2, "c": 3, "a": 1}, mask)
    assert not divergence(fp1, fp2, mask).diverged


def test_volatile_topology_excluded():
    """Topology that varies across identical requests -> VOLATILE -> excluded, so
    the node never reaches a divergence decision."""
    g = StabilityGate()
    fam = "GET /api/feed"
    g.observe_repeat(fam, "A::f::", {"items": [{"x": 1}], "ts": "t1"})
    g.observe_repeat(fam, "A::f::", {"items": [{"x": 1}, {"x": 2}], "ts": "t2", "extra": {"k": 1}})
    mask = g.trust_mask(fam)
    assert mask.node_stability["items"] == NodeStability.VOLATILE      # element count varied
    assert not mask.admissible("items")
    assert not mask.admissible("items[0].x")                          # ancestor volatile
    assert mask.node_stability.get("extra") == NodeStability.VOLATILE  # appeared/disappeared


def _build_widget_scenario():
    """Seed the canonical SAIE widget family at the unit level:
      A (owner, privileged widget 50) x2  -> rich grammar
      B (attacker, own std widget 70) x2  -> lean grammar
      C (control, own std widget 60) x2   -> lean grammar
    Returns (gate, coherence, family, mask)."""
    from authpath.structural import CoherenceModel
    fam = "GET /api/widgets/{id}"
    gate = StabilityGate()
    coh = CoherenceModel(gate)
    for _ in range(2):
        gate.observe_repeat(fam, "A::w::50", PRIVILEGED)
        coh.add("A", fam, "A::w::50", PRIVILEGED)
        gate.observe_repeat(fam, "B::w::70", LEAN)
        coh.add("B", fam, "B::w::70", LEAN)
        gate.observe_repeat(fam, "C::w::60", LEAN)
        coh.add("C", fam, "C::w::60", LEAN)
    return gate, coh, fam, gate.trust_mask(fam)


def test_coherence_rank_orders_privilege():
    gate, coh, fam, mask = _build_widget_scenario()
    assert coh.privilege_rank("A", fam, mask) > coh.privilege_rank("B", fam, mask)
    assert coh.privilege_rank("B", fam, mask) == coh.privilege_rank("C", fam, mask)


def test_filtered_response_fits_privileged_grammar_not_own():
    """The crux: B's value-filtered read of A's widget 50 FITS A's privileged
    grammar (same shape, nulled values) yet does NOT fit B's own lean grammar."""
    gate, coh, fam, mask = _build_widget_scenario()
    fp_probe = fingerprint(FILTERED, mask)          # B reads widget 50, values nulled
    assert coh.fits(fp_probe, "A", fam, mask), "must fit privileged grammar"
    assert not coh.fits(fp_probe, "B", fam, mask), "must NOT fit own lean grammar"


def test_gate1_breach_is_detectable():
    """Gate 1 condition: fp doesn't fit acting's grammar, fits a strictly
    higher-privilege grammar."""
    gate, coh, fam, mask = _build_widget_scenario()
    fp_probe = fingerprint(FILTERED, mask)
    acting = "B"
    breach = (not coh.fits(fp_probe, acting, fam, mask)) and any(
        coh.fits(fp_probe, q, fam, mask)
        and coh.privilege_rank(q, fam, mask) > coh.privilege_rank(acting, fam, mask)
        for q in coh.principals_with_grammar(fam) if q != acting)
    assert breach
    diverging = coh.grammar_present_paths("A", fam, mask) - \
        coh.grammar_present_paths("B", fam, mask)
    assert {"internal.margin", "audit.by", "internal.risk_score"} <= diverging


def test_lean_reread_fits_own_grammar_no_breach():
    """Value-only negative: B re-reads a lean widget -> fits own grammar -> no breach."""
    gate, coh, fam, mask = _build_widget_scenario()
    fp_probe = fingerprint({"id": "70", "status": "x", "total": 5.0,
                            "buyer": {"id": "70", "tier": "bronze"}}, mask)
    assert coh.fits(fp_probe, "B", fam, mask)


def test_clean_control_exists_for_positive():
    """Gate 2 prerequisite: a genuinely lower-priv control (C) exists whose grammar
    lacks the privileged paths."""
    gate, coh, fam, mask = _build_widget_scenario()
    diverging = coh.grammar_present_paths("A", fam, mask) - \
        coh.grammar_present_paths("B", fam, mask)
    c_paths = coh.grammar_present_paths("C", fam, mask)
    assert coh.privilege_rank("C", fam, mask) < coh.privilege_rank("A", fam, mask)
    assert not (diverging & c_paths), "control must lack the privileged paths"


def test_object_driven_richness_has_no_clean_control():
    """By-design negative (reports family): a public-rich object 80 is served rich
    to EVERYONE who reads it.  B reading 80 fits A's rich grammar (breach fires),
    but control C ALSO has the rich shape in its grammar -> no clean control ->
    Gate 2 will suppress (object-driven richness, not an authz flaw)."""
    from authpath.structural import CoherenceModel
    fam = "GET /api/reports/{id}"
    RICH = {"id": "80", "title": "Q", "body": "...",
            "internal": {"margin": 1.0}, "audit": {"by": "s"}}
    LEAN_R = {"id": "90", "title": "Q", "body": "..."}
    gate = StabilityGate()
    coh = CoherenceModel(gate)
    for _ in range(2):
        gate.observe_repeat(fam, "A::r::80", RICH);  coh.add("A", fam, "A::r::80", RICH)
        gate.observe_repeat(fam, "B::r::90", LEAN_R); coh.add("B", fam, "B::r::90", LEAN_R)
        gate.observe_repeat(fam, "C::r::80", RICH);  coh.add("C", fam, "C::r::80", RICH)
    mask = gate.trust_mask(fam)
    fp_probe = fingerprint(RICH, mask)              # B reads public-rich report 80
    assert not coh.fits(fp_probe, "B", fam, mask)   # breach fires at Gate 1
    assert coh.fits(fp_probe, "A", fam, mask)
    diverging = coh.grammar_present_paths("A", fam, mask) - \
        coh.grammar_present_paths("B", fam, mask)
    # Gate 2 search: no control that is lower-priv AND lacks the diverging paths
    matched_rank = coh.privilege_rank("A", fam, mask)
    clean_control = None
    for pid in coh.principals_with_grammar(fam):
        if pid in ("B", "A"):
            continue
        if coh.privilege_rank(pid, fam, mask) >= matched_rank:
            continue
        if diverging & coh.grammar_present_paths(pid, fam, mask):
            continue
        clean_control = pid
    assert clean_control is None, "object-driven richness must have NO clean control"


def test_provisional_tier_single_observation_relational():
    """PROVISIONAL queries work on single-observation grammars (lead-only) where
    the CONFIRMED tier is silent: a 1-shot privileged grammar outranks a 1-shot
    lean grammar, and a filtered probe fits the privileged one, not its own."""
    from authpath.structural import CoherenceModel
    fam = "GET /api/vault/{id}"
    gate = StabilityGate()
    coh = CoherenceModel(gate)
    coh.add("A", fam, "A::v::200", PRIVILEGED)     # ONE observation each
    coh.add("B", fam, "B::v::210", LEAN)
    # CONFIRMED tier sees nothing (no >=2-repeat grammar)
    assert not coh.has_grammar("A", fam) and not coh.has_grammar("B", fam)
    # PROVISIONAL tier still reasons
    assert coh.has_provisional("A", fam) and coh.has_provisional("B", fam)
    assert coh.privilege_rank_provisional("A", fam) > coh.privilege_rank_provisional("B", fam)
    fp = fingerprint(FILTERED)                      # B reads A's vault, values nulled
    assert coh.fits_provisional(fp, "A", fam)
    assert not coh.fits_provisional(fp, "B", fam)
    diverging = coh.provisional_present_paths("A", fam) - coh.provisional_present_paths("B", fam)
    assert {"internal.margin", "audit.by"} <= diverging


def test_normalize_flags_intermittent_presence_only_on_presence_axis():
    """Value churn with stable presence => STRUCT_LIKE (entropy normalised away);
    flickering presence under identical input => INTERMITTENT (a signal)."""
    from authpath.structural import NodeStability
    g = StabilityGate()
    fam = "GET /api/session"
    # value-entropy node 'expires' present every time (value differs); 'internal_token'
    # flickers in/out; 'user' constant.
    g.observe_repeat(fam, "B::s::", {"user": "B", "expires": 10, "internal_token": "a"})
    g.observe_repeat(fam, "B::s::", {"user": "B", "expires": 99})
    g.observe_repeat(fam, "B::s::", {"user": "B", "expires": 41, "internal_token": "c"})
    prof = g.normalize(fam)
    assert prof["internal_token"].kind == NodeStability.INTERMITTENT
    assert round(prof["internal_token"].present_ratio, 2) == 0.67
    # 'expires' value churns but presence is stable -> NOT intermittent
    assert prof["expires"].kind == NodeStability.STRUCT_LIKE
    assert prof["user"].kind == NodeStability.STRUCT_LIKE
    # the CONFIRMED mask is unchanged: internal_token stays excluded (volatile)
    mask = g.trust_mask(fam)
    assert not mask.admissible("internal_token")
    assert mask.admissible("user")


def test_object_presence_maps_field_level_differential_same_object():
    """The 'missing shadow': on the SAME object, object_presence reports which
    principal received a privileged branch and which had it entirely ABSENT —
    a measured field-level authorization map (no PRESENT_NULL needed)."""
    from authpath.structural import CoherenceModel
    fam = "GET /api/cases/{id}"
    objsig = "300"
    base = {"id": "300", "title": "Case 300", "status": "open"}
    junior = {**base, "internal": {"notes": "sealed"}}     # over-exposed
    coh = CoherenceModel(StabilityGate())
    coh.add("A", fam, f"A::{fam}::{objsig}", base)          # senior — no internal
    coh.add("C", fam, f"C::{fam}::{objsig}", junior)        # junior — has internal
    presence = coh.object_presence(fam, objsig)
    assert set(presence) == {"A", "C"}
    a_present, _ = presence["A"]
    c_present, c_pop = presence["C"]
    # shared base proves it is the same logical object
    assert {"id", "title", "status"} <= (a_present & c_present)
    # the differential: 'internal' present+populated for C, absent for A
    assert "internal" in c_pop and "internal.notes" in c_pop
    assert "internal" not in a_present and "internal.notes" not in a_present


if __name__ == "__main__":
    print("\nSAIE STEP 1 — structural.py self-tests\n" + "-" * 60)
    passed = 0
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        fn()
        passed += 1
        print(f"  [PASS] {name}")
    print("-" * 60)
    print(f"  {passed}/{len(tests)} self-tests passed \u2713\n")
