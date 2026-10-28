"""Assurance report — measure real evidence, then compose the evidence-backed case.

Runs (a) the certificate-layer blind benchmark, (b) the full-engine proving_world
harness, (c) the certificate self-test + coverage self-consistency check, folds the
measured numbers (each tier-stamped) into the two-column assurance case, and prints
it. Nothing is hardcoded — every number is measured at report time. This tool only
measures and composes; it changes no decision code.

    python tools/assurance_report.py            # measured, evidence-backed case
"""
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from authpath import certificate as C


def _load(modname, relpath):
    spec = importlib.util.spec_from_file_location(modname, os.path.join(ROOT, relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def measure(cert_seeds=range(1, 16), world_seeds=range(1, 16)) -> dict:
    """Measure every fact the assurance case can carry. Failures degrade to
    'not measured' rather than crashing the report."""
    facts = {}

    # (c) certificate self-test + coverage self-consistency (by-construction checks).
    try:
        st = C.run_selftest(iterations=200, seed=11)
        facts["cert_selftest_ok"] = (st["certified_without_delta"] == 0
                                     and st["genuine_missed"] == 0
                                     and st["mutation_survivors"] == 0)
        facts["coverage_consistent"] = C.verify_coverage()["consistent"]
    except Exception as e:
        facts["cert_selftest_ok"] = False
        facts["_selftest_error"] = repr(e)

    # (a) certificate-layer blind benchmark (external-taxonomy, sealed).
    try:
        B = _load("blind_cert_benchmark", os.path.join("proving_world", "blind_cert_benchmark.py"))
        agg = B.aggregate(cert_seeds)
        facts["cert_blind_precision"] = agg["precision"]
        facts["cert_blind_recall"] = agg["recall_in_boundary"]
    except Exception as e:
        facts["_cert_blind_error"] = repr(e)

    # (b) full-engine proving_world recall/precision over sealed randomized worlds.
    try:
        sys.path.insert(0, os.path.join(ROOT, "proving_world"))  # harness imports sibling 'world'
        H = _load("pw_harness", os.path.join("proving_world", "harness.py"))
        TP = FP = FN = TN = 0
        for s in world_seeds:
            r = H.run_world(s)
            TP += r["tp"]; FP += r["fp"]; FN += r["fn"]; TN += r["tn"]
        facts["engine_recall"] = TP / (TP + FN) if (TP + FN) else None
        facts["engine_precision"] = TP / (TP + FP) if (TP + FP) else None
        facts["_engine_counts"] = {"tp": TP, "fp": FP, "fn": FN, "tn": TN}
    except Exception as e:
        facts["_engine_error"] = repr(e)

    return facts


def main():
    facts = measure()
    print("=" * 72)
    print("ONYX ASSURANCE REPORT — measured at report time (nothing hardcoded)")
    print("=" * 72)
    print(f"  certificate self-test invariants held : {facts.get('cert_selftest_ok')}")
    print(f"  coverage self-consistent              : {facts.get('coverage_consistent')}")
    if "_engine_counts" in facts:
        c = facts["_engine_counts"]
        print(f"  full-engine sealed worlds             : tp={c['tp']} fp={c['fp']} "
              f"fn={c['fn']} tn={c['tn']}")
    for k in ("_selftest_error", "_cert_blind_error", "_engine_error"):
        if k in facts:
            print(f"  [warn] {k}: {facts[k]}")
    print("-" * 72)
    print(C.assurance_case(facts))
    ok = bool(facts.get("cert_selftest_ok")) and bool(facts.get("coverage_consistent"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
