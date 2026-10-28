"""
Chaos-precision regression (RL24). Under realistic production chaos (stale reads,
shared-cache bleed, retries, async-202, rate-limit, timeouts) ONYX's zero-false-
positive core must hold. This asserts PERFECT precision through moderate chaos — the
band real systems actually operate in — and no precision collapse at extreme chaos.
Recall may degrade under chaos (honest fail-safe); precision is the invariant.
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "proving_world"))


def _prec(intensity, seeds):
    import chaos_harness
    TP = FP = 0
    for s in seeds:
        r = chaos_harness.chaos_run(s, intensity)
        TP += r["tp"]; FP += r["fp"]
    return TP, FP


def test_perfect_precision_at_all_chaos_intensities():
    """Iron discipline: ZERO false positives at EVERY intensity from clean (0.0) to
    harder-than-reality extreme (1.0). Precision is the invariant; recall may degrade
    (an honest fail-safe). This is the crown jewel under any transport condition."""
    for inten in (0.0, 0.25, 0.5, 0.75, 1.0):
        tp, fp = _prec(inten, range(1, 13))
        assert fp == 0, f"precision breached at intensity {inten}: {fp} false positive(s)"


def test_stability_defaults_off_are_byte_identical():
    """RL24 must be default-off: a fresh confirmer does single, un-voted read-backs."""
    from authpath.confirmer import Confirmer
    import inspect
    src = inspect.getsource(Confirmer.__init__)
    assert "self.stability_k = 1" in src


if __name__ == "__main__":
    for n, g in sorted(globals().items()):
        if n.startswith("test_"):
            try: g(); print(f"  ok  {n}")
            except AssertionError as e: print(f"  FAIL {n}: {e}")
