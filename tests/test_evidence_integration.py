"""RL20 integration: the evidence discipline is SELF-APPLIED on a real ONYX run —
the demo's own 19 findings are stamped T2 (anti-hypocrisy), the honest surface
passes the no-bare-metrics gate, and the sealed manifest catches an overclaim."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.evidence import (assert_no_bare_metrics, ClaimManifest, EvidenceTier)
from fixtures import demo_scenario as ds

def _demo_engine(provenance="self"):
    SC = ScopeConfig(allowed_hosts=["demo.local"], automation_permitted=True,
                     target_provenance=provenance)
    return ds.run_demo(lambda t, p, c: AuthPathEngine(t, p, SC, contract=c))[0]

def test_self_run_findings_are_stamped_t2_not_t1():
    rep = _demo_engine("self").evidence_report()
    assert rep["target_provenance"] == "self"
    assert rep["evidence_ceiling"] == "T2_SELF_MEASURED"
    assert rep["findings_total"] >= 1
    assert all(s["tier"] == "T2_SELF_MEASURED" for s in rep["per_finding"]), \
        "ONYX's OWN demo findings must be self-measured, never independent proof"
    assert rep["overclaims_detected"] == []
    assert "independent proof" in rep["strongest_honest_claim"]

def test_third_party_target_promotes_findings_to_t1():
    rep = _demo_engine("third_party").evidence_report()
    assert rep["evidence_ceiling"] == "T1_INDEPENDENT"
    assert any(s["tier"] == "T1_INDEPENDENT" for s in rep["per_finding"])

def test_honest_surface_passes_no_bare_metrics_gate():
    rep = _demo_engine("self").evidence_report()
    # the system's own honest output must itself be tier-clean
    assert_no_bare_metrics(rep["evidence_map"])
    assert_no_bare_metrics(rep["strongest_honest_claim"])
    for line in rep["false_positive_claim"]:
        assert_no_bare_metrics(line)

def test_fp_claim_is_decomposed_in_report():
    rep = _demo_engine("self").evidence_report()
    joined = " ".join(rep["false_positive_claim"])
    assert "construction" in joined.lower()           # T4 piece
    assert "T3_MECHANISM_ESTIMATE" in joined or "pending" in joined.lower()  # independent pending

def test_project_manifest_seal_and_overclaim_gate():
    # the real project headline claims, sealed; CI re-grades and fails on overclaim
    m = (ClaimManifest()
         .add("precision is guaranteed by Δstate construction", EvidenceTier.T4_BY_CONSTRUCTION)
         .add("deterministic, order-free attribution", EvidenceTier.T4_BY_CONSTRUCTION)
         .add("39/39 byte-identical calibration", EvidenceTier.T2_SELF_MEASURED)
         .add("read-leak coordinate beyond mutation verifiers", EvidenceTier.T4_BY_CONSTRUCTION)
         .add("independent recall on a third-party target", EvidenceTier.T3_MECHANISM_ESTIMATE))
    h = m.seal()
    assert m.verify(h)
    # with no independent target yet, nothing may stand above T2
    assert m.overclaims(EvidenceTier.T2_SELF_MEASURED) == []
    # inject the classic fatal overclaim -> seal breaks AND it is flagged
    m.add("beats Hadrian everywhere, proven", EvidenceTier.T1_INDEPENDENT)
    assert not m.verify(h)
    assert m.overclaims(EvidenceTier.T2_SELF_MEASURED)

if __name__ == "__main__":
    import traceback
    fns=[(n,f) for n,f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    print("\nRL20 integration (session 5)\n"+"-"*55); p=0; _fail=0
    for n,f in fns:
        try: f(); p+=1; print(f"  [PASS] {n}")
        except Exception: _fail += 1; print(f"  [FAIL] {n}"); traceback.print_exc()
    print("-"*55); print(f"  {p}/{len(fns)} passed\n")
    sys.exit(1 if _fail else 0)


def test_claims_sheet_is_tier_clean():
    """The judge-facing CLAIMS.md must pass the no-bare-metrics gate — every metric
    in it carries an evidence tier. This is the CI enforcement on the real pitch."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "docs", "CLAIMS.md"), encoding="utf-8") as fh:
        assert_no_bare_metrics(fh.read())
