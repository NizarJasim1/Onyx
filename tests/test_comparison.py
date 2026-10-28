"""P2 — the ONYX-vs-baseline comparison. Asserts the STRUCTURAL result honestly:
the baseline is not a strawman (high recall), ONYX's precision exceeds it on the
same traffic, and the result is tier-stamped T2 (not presented as independent)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.comparison import run_comparison, format_report, Metrics

def _run():
    return run_comparison(lambda t,p,c: AuthPathEngine(
        t, p, ScopeConfig(allowed_hosts=["demo.local"], automation_permitted=True), contract=c))

def test_baseline_is_not_a_strawman():
    # CRITICAL fairness gate: the baseline must catch most true positives, else the
    # whole comparison is rigged. >0.8 recall proves it is a real, working detector.
    res = _run()
    assert res["baseline"]["recall"] > 0.8, \
        f"baseline recall {res['baseline']['recall']} too low — would be a strawman"

def test_onyx_precision_exceeds_baseline():
    res = _run()
    assert res["onyx"]["precision"] > res["baseline"]["precision"], \
        "the structural claim: Δstate confirmation must out-precision the heuristic"
    # the gap should be large because the heuristic false-positives on benign 2xx
    assert res["baseline"]["fp"] >= 5, "the heuristic must visibly false-positive on benign cases"
    assert res["onyx"]["fp"] == 0, "ONYX must add no false positive (zero-FP by construction)"

def test_onyx_recall_at_least_baseline():
    res = _run()
    assert res["onyx"]["recall"] >= res["baseline"]["recall"]

def test_result_is_tier_stamped_t2_not_independent():
    res = _run()
    assert res["evidence_tier"] == "T2_SELF_MEASURED"
    assert "P0" in res["evidence_note"] and "independent" in res["evidence_note"].lower()
    # the rendered report must carry the tier (no bare metric presented as proof)
    assert "T2_SELF_MEASURED" in format_report(res)

def test_metrics_math():
    m = Metrics()
    for pred, act in [(True,True),(True,False),(False,True),(False,False)]:
        m.add(pred, act)
    assert m.tp==1 and m.fp==1 and m.fn==1 and m.tn==1
    assert abs(m.precision-0.5)<1e-9 and abs(m.recall-0.5)<1e-9

if __name__ == "__main__":
    fns=[(n,f) for n,f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    print("\nP2 comparison (session 5)\n"+"-"*50); p=0; fail=0
    for n,f in fns:
        try: f(); p+=1; print(f"  [PASS] {n}")
        except Exception as e: fail+=1; print(f"  [FAIL] {n}: {e!r}")
    print("-"*50); print(f"  {p}/{len(fns)} passed\n"); sys.exit(1 if fail else 0)
