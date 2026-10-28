"""
Protocol [21] gap G5 — the maximum honest INDEPENDENT anchor with GIANT PROPERTIES.

A live independent T1 number needs egress + a live target — absent in this sandbox, and [16]
forbids claiming one. What IS built and proven here: the full giant-scale pipeline (G1 triage
+ G2 protocol carriers + G3 volume gate + the deficiency solutions) runs end-to-end against
an INDEPENDENT-LOGIC target (the VAmPI-faithful replica — vuln logic authored by erev0s, not
by ONYX), confirms the known vulns at precision 1.0, and emits a sealed scorecard whose tier
is honestly T2 (independent logic, but in-process — NOT a live T1). The live T1 stays the
operator's, one command via byo_runner.
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "external_targets"))
from authpath.triage import RiskTriage
from authpath.differential import measure, standard_suite


def test_g5_full_giant_pipeline_on_independent_logic_precision_1():
    """The independent anchor: run ONYX against the erev0s-authored VAmPI-faithful logic.
    The load-bearing claim is PRECISION 1.0 (the crown jewel) — it holds deterministically.
    The deterministic BOLA and EDE leaks must be confirmed. The consequence-confirmed
    password-change (the 3rd true positive) is owned and asserted at 3/3 by
    test_consequence_confirmation; it depends on a login round-trip whose in-suite ordering
    is asserted there, so here we require recall >= 2/3 and precision 1.0."""
    import run_vampi
    r = run_vampi.run_mode(vuln=True, use_http=False)
    precision = r["tp"] / (r["tp"] + r["fp"]) if (r["tp"] + r["fp"]) else 1.0
    recall = r["tp"] / (r["tp"] + r["fn"])
    assert r["fp"] == 0 and precision == 1.0, f"precision must be 1.0 on independent logic: {r}"
    assert recall >= 2/3, f"the deterministic BOLA+EDE leaks must be confirmed: {recall}"
    # the fixed branch stays clean (no finding) -> zero-FP both ways
    s = run_vampi.run_mode(vuln=False, use_http=False)
    assert s["fp"] == 0 and s["n_findings"] == 0


def test_g5_giant_property_triage_ranks_real_vulns_above_decoys():
    """Layer giant VOLUME on the independent target: the real VAmPI authz endpoints must
    triage ABOVE thousands of low-risk decoys, so the confirmation budget reaches them."""
    t = RiskTriage()
    # the real VAmPI authz-risk endpoints (from erev0s's ground truth)
    real = [("GET", "/books/v1/9"), ("PUT", "/users/v1/9/password"), ("GET", "/users/v1/_debug")]
    for m, p in real:
        t.add(m, p)
    # thousands of low-risk decoys (giant volume)
    for i in range(5000):
        t.add("GET", f"/static/asset{i}")
    top = [r.endpoint for r in t.budget(len(real))]
    real_keys = {f"{m} {p}" for m, p in real}
    assert all(e in real_keys for e in top), f"real authz endpoints must rank at the top: {top}"


def test_g5_measured_differential_holds_on_the_suite():
    """The G4 differential (independent of who authored the suite) still shows the structural
    advantage: ONYX clean, the diffing class shows FP+FN."""
    m = measure(standard_suite())
    assert m["onyx_delta_state"]["fp"] == 0 and m["onyx_delta_state"]["fn"] == 0
    assert (m["response_diff"]["fp"] + m["response_diff"]["fn"]) >= 2


def test_g5_sealed_scorecard_is_tier_honest_T2_not_T1():
    """The anchor's LOGIC is independent, but it runs in-process -> the scorecard MUST be T2,
    and cannot be stamped T1 (that needs the operator asserting live+independent)."""
    from byo_runner import TargetConfig, run_target, TIER_T1, TIER_T2
    from authpath.models import HTTPRequest, HTTPResponse, Principal

    class IndependentReplica:
        """Wraps independent-logic behaviour; in-process => T2 by construction."""
        host = "vampi-faithful.local"
        def send(self, req, principal):
            rid = req.path.rstrip("/").split("/")[-1]
            if rid == "9":
                return HTTPResponse(200, {"title": "9", "secret": "owner-B-secret", "owner": "B"})
            return HTTPResponse(404, {})

    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "AB"}
    # even asserting independent authorship, in-process (live_networked=False) => T2
    cfg = TargetConfig(name="vampi-faithful", client=IndependentReplica(), principals=P,
                       independently_authored=True, live_networked=False)
    obs = [("B", HTTPRequest("GET", "/books/v1/9", host="vampi-faithful.local"))]
    atk = [("A", HTTPRequest("GET", "/books/v1/9", host="vampi-faithful.local"))]
    s = run_target(cfg, obs, atk)
    assert s["tier"] == TIER_T2 and s["tier"] != TIER_T1     # honest: not a live T1
    assert s["tamper_evident"] is True                        # sealed
    assert s["n_findings"] >= 1                               # pipeline confirmed the leak


if __name__ == "__main__":
    p = 0; fns = [g for n, g in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as e: print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e: print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
