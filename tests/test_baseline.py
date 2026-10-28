"""P2 — fairness tests for the Autorize-equivalent baseline. CRITICAL: these prove
the baseline is NOT a strawman (it catches real bypasses) BEFORE any precision
number is compared, and that it false-positives exactly where a status/length/
fingerprint heuristic must — which is where ONYX's Δstate drops it."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from authpath.models import HTTPResponse
from authpath.baseline import AutorizeBaseline

B = AutorizeBaseline()

def _r(status, body): return HTTPResponse(status, body)

# --- the baseline is NOT crippled: it catches real bypasses (non-zero recall) ---
def test_baseline_catches_real_bypass():
    # attacker reads another user's order: 200 + the victim's data, no enforcement
    owner = _r(200, {"order_id": "101", "owner": "alice", "total": 90.0})
    attack = _r(200, {"order_id": "101", "owner": "alice", "total": 90.0})
    assert B.predict(attack, owner) == "bypassed", "must flag a genuine BOLA (not a strawman)"

def test_baseline_respects_status_enforcement():
    assert B.predict(_r(403, {"error": "nope"}), None) == "enforced"
    assert B.predict(_r(401, {}), None) == "enforced"

def test_baseline_respects_fingerprint_enforcement():
    assert B.predict(_r(200, {"message": "You are not authorized to perform action"}), None) == "enforced"
    assert B.predict(_r(200, {"detail": "Access denied"}), None) == "enforced"

def test_baseline_respects_length_discriminator():
    owner = _r(200, {"a": "x"*500})              # large legitimate body
    attack = _r(200, {"a": "x"*5})               # tiny -> different -> enforced
    assert B.predict(attack, owner) == "enforced"

# --- the FP traps: where the heuristic MUST false-positive (and ONYX drops) ---
def test_baseline_false_positives_on_soft_deny():
    # a 200 that denies in the body but with NO standard fingerprint the detector knows
    soft = _r(200, {"status": "request not processed", "data": None})
    assert B.predict(soft, None) == "bypassed", "soft-deny 200 => Autorize false positive"

def test_baseline_false_positives_on_benign_200():
    # a benign self-access 200 looks identical to a bypass to a status/length heuristic
    benign = _r(200, {"order_id": "202", "owner": "bob", "total": 12.0})
    ref = _r(200, {"order_id": "202", "owner": "bob", "total": 12.0})
    assert B.predict(benign, ref) == "bypassed", "benign look-alike 200 => false positive"

def test_other_errors_not_a_bypass():
    assert B.predict(_r(404, {"error": "not found"}), None) == "enforced"
    assert B.predict(_r(500, {}), None) == "enforced"

if __name__ == "__main__":
    fns=[(n,f) for n,f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    print("\nP2 baseline fairness (session 4)\n"+"-"*50); p=0; fail=0
    for n,f in fns:
        try: f(); p+=1; print(f"  [PASS] {n}")
        except Exception as e: fail+=1; print(f"  [FAIL] {n}: {e!r}")
    print("-"*50); print(f"  {p}/{len(fns)} passed\n"); sys.exit(1 if fail else 0)
