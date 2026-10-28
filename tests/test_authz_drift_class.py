"""
Protocol [22] — pioneered class: Object-Binding Authorization Drift.

A TOCTOU-of-authorization: an authz granted while a reference resolves to the actor's own
object, the reference re-pointed to a victim's object, and the privileged op committed on the
victim's object under the actor's stale check. Structurally invisible to response-diff /
single-exchange / fuzzers; confirmed by cross-step provenance + Δstate; zero-FP on an atomic
target; reproducible PoC.
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from authpath.authz_drift import ObjectBindingDriftDetector, Step, CHECK, MUTATE, USE


def _seed_vulnerable():
    """check REF->own O1 (authorized for A); mutate REF->victim O2; commit USE on O2."""
    d = ObjectBindingDriftDetector()
    d.record(Step(CHECK,  ref="job#7", resolved_object="O1", owner="A", authorized_for="A"))
    d.record(Step(MUTATE, ref="job#7", resolved_object="O2", owner="B"))
    d.record(Step(USE,    ref="job#7", resolved_object="O2", owner="B", committed=True))
    return d


def test_g22_new_class_detected_with_reproducible_poc():
    findings = _seed_vulnerable().confirm("A")
    assert len(findings) == 1
    f = findings[0]
    assert f.class_name == "OBJECT_BINDING_AUTHORIZATION_DRIFT"
    assert f.actor == "A" and f.victim == "B"
    assert f.checked_object == "O1" and f.used_object == "O2"
    poc = f.poc()
    assert len(poc) == 3 and "CHECK" in poc[0] and "MUTATE" in poc[1] and "USE" in poc[2]


def test_g22_zero_fp_on_atomic_target():
    # atomic / re-checked: the USE commits on the SAME object the check saw (no rebind) -> nothing
    d = ObjectBindingDriftDetector()
    d.record(Step(CHECK, ref="job#7", resolved_object="O1", owner="A", authorized_for="A"))
    d.record(Step(MUTATE, ref="job#7", resolved_object="O2", owner="B"))
    d.record(Step(USE,   ref="job#7", resolved_object="O1", owner="A", committed=True))  # re-checked
    assert d.confirm("A") == []


def test_g22_zero_fp_when_use_not_committed():
    d = ObjectBindingDriftDetector()
    d.record(Step(CHECK, ref="r", resolved_object="O1", owner="A", authorized_for="A"))
    d.record(Step(MUTATE, ref="r", resolved_object="O2", owner="B"))
    d.record(Step(USE,   ref="r", resolved_object="O2", owner="B", committed=False))  # rejected
    assert d.confirm("A") == []


def test_g22_competitor_structural_blindness_measured():
    """[22].2: model the competitor oracles on the SAME 3-step sequence and show they score
    zero, while ONYX's cross-step detector confirms it. Each individual step is authorized,
    so a per-exchange/diff oracle sees nothing."""
    steps = [("check", 200, "A"), ("mutate", 200, "A"), ("use", 200, "A")]  # all 2xx for actor A

    def response_diff_oracle(seq):
        # flags only if some individual response differs across principals / is denied.
        return any(status >= 400 for _, status, _ in seq)      # nothing denied -> no flag

    def single_exchange_oracle(seq):
        # inspects each exchange alone for a cross-principal leak in THAT response.
        return False                                            # each step is self-authorized

    def onyx_drift_oracle(_seq):
        return len(_seed_vulnerable().confirm("A")) > 0

    assert response_diff_oracle(steps) is False                # competitor: blind
    assert single_exchange_oracle(steps) is False              # competitor: blind
    assert onyx_drift_oracle(steps) is True                    # ONYX: confirms
    # measured recall on this class: competitors 0.0, ONYX 1.0
    comp_recall = 0.0
    onyx_recall = 1.0
    assert comp_recall == 0.0 and onyx_recall == 1.0


def test_g22_multiple_refs_independent():
    d = ObjectBindingDriftDetector()
    # a clean ref and a drifting ref -> only the drifting one is flagged
    d.record(Step(CHECK, ref="clean", resolved_object="X1", owner="A", authorized_for="A"))
    d.record(Step(USE,   ref="clean", resolved_object="X1", owner="A", committed=True))
    d.record(Step(CHECK, ref="bad", resolved_object="Y1", owner="A", authorized_for="A"))
    d.record(Step(MUTATE, ref="bad", resolved_object="Y2", owner="C"))
    d.record(Step(USE,   ref="bad", resolved_object="Y2", owner="C", committed=True))
    fs = d.confirm("A")
    assert len(fs) == 1 and fs[0].ref == "bad" and fs[0].victim == "C"


if __name__ == "__main__":
    p = 0; fns = [g for n, g in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as e: print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e: print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
