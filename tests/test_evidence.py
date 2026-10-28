"""Evidence Discipline (RL20) — adversarial: the tier is derived not chosen, the
'zero-FP' claim is decomposed, bare metrics are rejected, and the manifest is sealed."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import contextlib
@contextlib.contextmanager
def _raises(exc):
    try:
        yield
    except exc:
        return
    raise AssertionError("expected %s but none raised" % exc.__name__)
from authpath.evidence import (
    EvidenceTier, EvidenceKind, TargetProvenance, coerce_provenance,
    grade, grade_structural, Claim, decompose_fp_claim, EvidenceLedger,
    ClaimManifest, assert_no_bare_metrics, strongest_honest_claim, evidence_stamp,
)

def test_same_finding_t2_self_t1_thirdparty():
    assert grade(True, TargetProvenance.SELF) is EvidenceTier.T2_SELF_MEASURED
    assert grade(True, TargetProvenance.THIRD_PARTY) is EvidenceTier.T1_INDEPENDENT
    assert grade(True, TargetProvenance.LIVE_BOUNTY) is EvidenceTier.T1_INDEPENDENT

def test_unconfirmed_capped_at_t3():
    assert grade(False, TargetProvenance.THIRD_PARTY) is EvidenceTier.T3_MECHANISM_ESTIMATE

def test_unknown_is_humble():
    assert coerce_provenance("garbage") is TargetProvenance.UNKNOWN
    assert grade(True, TargetProvenance.UNKNOWN) is EvidenceTier.T2_SELF_MEASURED

def test_only_t1_says_proven_and_is_empirical_independent():
    assert EvidenceTier.T1_INDEPENDENT.may_say_proven
    assert EvidenceTier.T1_INDEPENDENT.kind is EvidenceKind.EMPIRICAL
    assert EvidenceTier.T1_INDEPENDENT.independent
    assert not EvidenceTier.T2_SELF_MEASURED.may_say_proven
    assert EvidenceTier.T4_BY_CONSTRUCTION.kind is EvidenceKind.STRUCTURAL

def test_structural_is_t4():
    assert grade_structural() is EvidenceTier.T4_BY_CONSTRUCTION

def test_claim_render_binds_language():
    c = Claim("recall 5/5", EvidenceTier.T2_SELF_MEASURED)
    r = c.render()
    assert "self-authored simulation" in r and "T2_SELF_MEASURED" in r
    assert c.overclaims_at(EvidenceTier.T1_INDEPENDENT)
    assert not c.overclaims_at(EvidenceTier.T2_SELF_MEASURED)

def test_fp_claim_decomposes_into_three_tiers():
    parts = decompose_fp_claim(demo_n=39, independent_measured=False)
    tiers = {c.tier for c in parts}
    assert EvidenceTier.T4_BY_CONSTRUCTION in tiers      # by construction
    assert EvidenceTier.T2_SELF_MEASURED in tiers        # observed on demo
    assert EvidenceTier.T3_MECHANISM_ESTIMATE in tiers   # independent pending
    # promoted only with a real independent measurement
    parts2 = decompose_fp_claim(demo_n=39, independent_measured=True,
                                provenance=TargetProvenance.THIRD_PARTY)
    assert any(c.tier is EvidenceTier.T1_INDEPENDENT for c in parts2)

def test_ledger_audit_flags_overclaims():
    led = EvidenceLedger()
    led.add("recall on crAPI", EvidenceTier.T1_INDEPENDENT)
    led.add("recall on own demo", EvidenceTier.T2_SELF_MEASURED)
    flagged = led.audit(max_allowed=EvidenceTier.T2_SELF_MEASURED)
    assert len(flagged) == 1 and "crAPI" in flagged[0].statement

def test_no_bare_metrics_rejects_untiered_number():
    with _raises(AssertionError):
        assert_no_bare_metrics("ONYX achieves 98% recall on the suite.")
    with _raises(AssertionError):
        assert_no_bare_metrics("reported FP=0 across all runs")
    # tiered metric passes
    assert_no_bare_metrics("[T2_SELF_MEASURED] 39/39 byte-identical (self-authored simulation)")
    assert_no_bare_metrics("0 FP by construction (T4): no Δstate, no finding")

def test_manifest_seal_detects_tampering():
    m = ClaimManifest().add("precision by construction", EvidenceTier.T4_BY_CONSTRUCTION) \
                       .add("recall pending independent target", EvidenceTier.T3_MECHANISM_ESTIMATE)
    h = m.seal()
    assert m.verify(h)
    m.add("beats Hadrian everywhere", EvidenceTier.T1_INDEPENDENT)  # sneaky overclaim added
    assert not m.verify(h)                                          # seal breaks -> CI fails
    assert m.overclaims(EvidenceTier.T2_SELF_MEASURED)              # and it is caught as overclaim

def test_strongest_claim_current_state_refuses_independent_proof():
    s = strongest_honest_claim(False, False, False)
    assert "BY CONSTRUCTION" in s and "next step" in s and "independent proof" in s

def test_evidence_stamp_wording():
    assert "T2_SELF_MEASURED" in evidence_stamp(True, TargetProvenance.SELF)
    assert "T1_INDEPENDENT" in evidence_stamp(True, TargetProvenance.THIRD_PARTY)

if __name__ == "__main__":
    import traceback
    fns = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    print("\nEvidence Discipline (RL20) — session 4\n" + "-"*60)
    p = 0; _fail = 0
    for n, f in fns:
        try: f(); p += 1; print(f"  [PASS] {n}")
        except Exception: _fail += 1; print(f"  [FAIL] {n}"); traceback.print_exc()
    print("-"*60); print(f"  {p}/{len(fns)} passed\n")
    sys.exit(1 if _fail else 0)
