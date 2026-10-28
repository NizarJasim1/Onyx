"""AHP-Ω spec-conformance: ONYX vs crAPI's official-spec-documented behavior, offline,
with a negative control. Scored only on harness-faithful challenges; honest by design."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "p0"))
from conformance import run_conformance, CrapiReplayTarget

def test_readleak_bola_conforms_to_crapi_spec():
    r = run_conformance()
    assert r["tier"] == "SPEC_CONFORMANCE"
    assert r["recall"] == 1.0 and r["precision"] == 1.0, r
    assert r["fp"] == 0

def test_negative_control_passes():
    # ONYX must fire on the real vulnerable shape AND go silent when the ownership
    # check is added — proof it tracks the authorization property, not an artifact.
    r = run_conformance()
    assert r["negative_control_total"] >= 2
    assert r["negative_control_passed"] == r["negative_control_total"], r

def test_clean_cases_never_fire():
    r = run_conformance()
    cleans = [x for x in r["scored"] if x["label"] == "CLEAN"]
    assert len(cleans) >= 3 and all(x["correct"] for x in cleans)

def test_under_exercised_are_reported_not_hidden():
    # honesty: BFLA/mass-assign are transparently reported, never silently scored as pass
    r = run_conformance()
    reported = {x["challenge"] for x in r["transparently_reported_not_scored"]}
    assert "BFLA-ADMIN-DELETE-VIDEO" in reported

def test_target_shapes_match_crapi_spec_fields():
    # the replay target uses crAPI's real field names (carId/fullName/vehicleLocation)
    t = CrapiReplayTarget()
    from authpath.models import HTTPRequest, Principal
    r = t.send(HTTPRequest("GET", "/identity/api/v2/vehicle/x/location", query={"_res": "vehicleA"}),
               Principal("B", "B user", auth={}))
    assert set(r.body.keys()) == {"carId", "fullName", "vehicleLocation"}

if __name__ == "__main__":
    fns=[(n,f) for n,f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    print("\nAHP-Ω conformance (session 4)\n"+"-"*55); p=0; fail=0
    for n,f in fns:
        try: f(); p+=1; print(f"  [PASS] {n}")
        except Exception as e: fail+=1; print(f"  [FAIL] {n}: {e!r}")
    print("-"*55); print(f"  {p}/{len(fns)} passed\n"); sys.exit(1 if fail else 0)
