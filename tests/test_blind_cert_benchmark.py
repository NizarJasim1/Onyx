"""
BLIND-CERT — the external-taxonomy blind benchmark for the certifying layer.

Asserts the layer's behaviour matches its DECLARED coverage under blindly-authored,
sealed, randomised faults: zero decoys ever certified (precision), in-boundary
genuine cases certified (recall floor), out-of-boundary cases correctly abstained
(coverage honesty), and generalisation across strange forms. Also enforces that the
benchmark itself imports none of ONYX's decision code (isolation).
"""
import ast
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_BENCH_PATH = os.path.join(ROOT, "proving_world", "blind_cert_benchmark.py")
_spec = importlib.util.spec_from_file_location("blind_cert_benchmark", _BENCH_PATH)
B = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(B)

_SEEDS = range(1, 13)
_DECISION_MODULES = {"confirmer", "eil", "engine", "provenance", "envelope",
                     "contract", "conservation", "nerve_bridge", "broadcast"}


def test_blind_precision_is_perfect():
    agg = B.aggregate(_SEEDS)
    assert agg["precision"] == 1.0, agg
    assert agg["decoys_certified"] == 0, agg


def test_blind_recall_in_boundary_meets_floor():
    agg = B.aggregate(_SEEDS)
    assert agg["recall_in_boundary"] >= 0.95, agg


def test_blind_coverage_boundary_is_honest():
    # out-of-boundary classes must ABSTAIN, never falsely certify.
    agg = B.aggregate(_SEEDS)
    assert agg["boundary_correct"] == 1.0, agg


def test_blind_generalises_to_strange_forms():
    agg = B.aggregate(_SEEDS)
    strange = agg["by_form"].get("strange", {"ok": 0, "n": 0})
    assert strange["n"] > 0 and strange["ok"] == strange["n"], strange


def test_blind_oracle_is_sealed_before_detection():
    r = B.run(3)
    assert isinstance(r["sealed_oracle"], str) and len(r["sealed_oracle"]) == 16, r


def test_blind_benchmark_imports_no_decision_code():
    with open(_BENCH_PATH, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("authpath"):
            imported.add((node.module or "").split(".")[-1])
    leaked = imported & _DECISION_MODULES
    assert not leaked, f"blind benchmark leaked decision-code imports: {leaked}"


if __name__ == "__main__":
    import traceback
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    print("\nBLIND-CERT benchmark tests\n" + "-" * 60)
    p = _fail = 0
    for n, f in fns:
        try:
            f(); p += 1; print(f"  [PASS] {n}")
        except Exception:
            _fail += 1; print(f"  [FAIL] {n}"); traceback.print_exc()
    print("-" * 60); print(f"  {p}/{len(fns)} passed\n")
    sys.exit(1 if _fail else 0)
