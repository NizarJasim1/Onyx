"""
VERITAS — blind real-world range regression suite.

Locks the faithful internal predictor: an architecture-faithful black-box target whose
authorization bugs EMERGE from a realistic authz engine (transitive ownership tree,
per-door checks, RBAC), scored against a hidden oracle ONYX never sees. Also locks the
real ONYX bug this range surfaced — the `_singular` mis-normalisation of common REST
collection names (resources/devices/services/invoices) that silently broke identity
unification.

Guarantees:
  * the four reachable emergent bug classes (B1 cross-door, B2 list over-projection,
    B3 ownership anomaly, B4 deploy drift) are all caught, by the CORRECT mechanism;
  * ZERO false positives and the decoys stay clean;
  * the declared blind spot (U1 cross-operation leak) is empirically missed — the
    honest limit is proven, not assumed;
  * `_singular` normalises the real-world collection names correctly.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures"))

from authpath.surface_map import _singular


def _run():
    from fixtures.run_blind_range import run_blind
    return run_blind(verbose=False)


def test_all_reachable_emergent_bugs_caught():
    r = _run()
    assert r["tp"] == 5, f"expected all 5 reachable emergent bugs caught, got {r['tp']}"


def test_zero_false_positives_on_the_range():
    r = _run()
    assert r["fp"] == 0, f"the range must produce ZERO false positives, got {r['fp']}"


def test_no_false_negatives_among_reachable():
    r = _run()
    assert r["fn"] == 0, f"no reachable bug may be missed, got {r['fn']} FN"


def test_declared_blind_spot_is_really_unreachable():
    """VERITAS V6: the cross-operation leak ONYX cannot unify must be empirically
    missed — if it were suddenly 'caught' the harness would be leaking an oracle."""
    r = _run()
    assert r["u1_missed"] is True, "U1 must be missed (honest limit), not silently 'found'"


def test_no_pass_errors_on_the_range():
    r = _run()
    assert r["pass_errors"] == 0, "the faithful range must analyse cleanly (no coverage gaps)"


# --- the real ONYX bug the range surfaced: _singular over-stripping '-es' --- #

def test_singular_handles_real_collection_names():
    cases = {"resources": "resource", "devices": "device", "services": "service",
             "invoices": "invoice", "orders": "order", "projects": "project",
             "categories": "category", "houses": "house", "cases": "case"}
    for plural, want in cases.items():
        assert _singular(plural) == want, f"_singular({plural!r}) → {_singular(plural)!r}, want {want!r}"


def test_singular_still_handles_sibilant_plurals():
    cases = {"classes": "class", "boxes": "box", "addresses": "address",
             "watches": "watch", "dishes": "dish"}
    for plural, want in cases.items():
        assert _singular(plural) == want, f"_singular({plural!r}) → {_singular(plural)!r}, want {want!r}"
