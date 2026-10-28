"""
Falsification suite for the nine remaining recall-gap modules (G3,G4,G5,G7,G8,G9,
G11,G12,G15). Each encodes an FP-gate clause. Pure logic, no network.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.convergence import converged_persisted
from authpath.idempotency import extract_idempotency_key, replay_drift_confirmed
from authpath.deep_provenance import ProvenanceLedger
from authpath.discriminating import DiscriminatingValueLearner
from authpath.state_inference import infer_producer_consumer, find_validate_commit_seams
from authpath.ownership_sparse import owns_via_attestation, ownership_confidence
from authpath.drift_chain import drift_to_capability_edge, compose_path
from authpath.graphql_interleave import build_aliased_mutation_probe, confirm_interleave_drift
from authpath.window_opener import plan_single_packet_batch, deferred_collision_plan, race_result_confirmed
from authpath.nonce_provenance import NonceAuthority, NonceSeeker


# ── G3 convergence ──
def test_g3_effect_present_at_convergence_confirms():
    reads = iter([{"ctrl": False}, {"ctrl": True, "eff": True}])
    assert converged_persisted(lambda: next(reads), lambda r: r.get("eff"),
                               lambda r: r.get("ctrl"), max_polls=3) is True

def test_g3_transient_gone_before_convergence_abstains():
    reads = iter([{"ctrl": False, "eff": True}, {"ctrl": True, "eff": False}])
    assert converged_persisted(lambda: next(reads), lambda r: r.get("eff"),
                               lambda r: r.get("ctrl"), max_polls=3) is False

def test_g3_never_converges_abstains():
    assert converged_persisted(lambda: {"ctrl": False, "eff": True}, lambda r: r["eff"],
                               lambda r: r["ctrl"], max_polls=3) is False


# ── G7 idempotency ──
def test_g7_no_key_returns_none():
    assert extract_idempotency_key({"Content-Type": "json"}) is None
    a = NonceAuthority(); s = NonceSeeker(a); n = a.mint("x"); s.register_planted(n)
    assert replay_drift_confirmed(original_headers={}, seeker=s, planted=n,
                                  readback_as_victim={}, cross_principal_ok=True) is None

def test_g7_key_detected():
    assert extract_idempotency_key({"Idempotency-Key": "abc"}) == ("Idempotency-Key", "abc")

def test_g7_replay_confirms_only_attributed_cross_principal():
    a = NonceAuthority(); s = NonceSeeker(a); n = a.mint("x"); s.register_planted(n)
    r = replay_drift_confirmed(original_headers={"Idempotency-Key": "k"}, seeker=s, planted=n,
                               readback_as_victim={"note": n.as_text()}, cross_principal_ok=True)
    assert r is not None and r.attributed is True
    r2 = replay_drift_confirmed(original_headers={"Idempotency-Key": "k"}, seeker=s, planted=n,
                                readback_as_victim={"note": "nothing"}, cross_principal_ok=True)
    assert r2.attributed is False


# ── G8 deep provenance ──
def test_g8_traces_early_to_late():
    a = NonceAuthority(); L = ProvenanceLedger(a)
    n = L.plant("step1", "order")
    hit = L.confirm_second_order({"export": n.as_text()}, "step5", cross_principal_ok=True)
    assert hit is not None and hit[1] == "step1"

def test_g8_no_link_without_nonce():
    a = NonceAuthority(); L = ProvenanceLedger(a); L.plant("s1", "x")
    assert L.confirm_second_order({"export": "unrelated"}, "s5", cross_principal_ok=True) is None

def test_g8_link_without_cross_principal_abstains():
    a = NonceAuthority(); L = ProvenanceLedger(a); n = L.plant("s1", "x")
    assert L.confirm_second_order({"e": n.as_text()}, "s5", cross_principal_ok=False) is None


# ── G12 discriminating value ──
def test_g12_discriminating_vs_shared():
    d = DiscriminatingValueLearner()
    d.observe("A", "email", "a@x"); d.observe("B", "email", "b@x")
    assert d.is_discriminating("email") is True
    d.observe("A", "role", "user"); d.observe("B", "role", "user")
    assert d.is_shared_default("role", "user") is True
    assert d.should_suppress("role", "user") is True
    assert d.should_suppress("email", "a@x") is False

def test_g12_single_principal_is_conservative():
    d = DiscriminatingValueLearner(); d.observe("A", "x", "1")
    assert d.is_discriminating("x") is False


# ── G9 state inference (candidates only) ──
def test_g9_infers_producer_consumer_and_seams():
    spec = {"paths": {
        "/orders": {"post": {"responses": {"201": {}}}},
        "/orders/{orderId}": {"get": {"responses": {"200": {}}}},
        "/jobs": {"post": {"responses": {"202": {}}}},
    }}
    edges = infer_producer_consumer(spec)
    assert any(c.endswith("/orders/{orderId}") for _, c, _ in edges)
    seams = find_validate_commit_seams(spec)
    assert ("POST /jobs", "async-commit-seam") in seams

def test_g9_empty_spec_no_candidates():
    assert infer_producer_consumer({}) == [] and find_validate_commit_seams(None) == []


# ── G11 sparse ownership ──
def test_g11_two_source_and_attested():
    assert ownership_confidence({"A": {"a-id"}, "B": {"b-id"}}) == "confirmed_two_source"
    assert ownership_confidence({"A": {"me-123"}}, attested="me-123") == "confirmed_attested"
    assert ownership_confidence({"A": {"x"}}) == "abstain"
    assert ownership_confidence({"A": {"x"}}, attested="other") == "abstain"

def test_g11_attestation_exact_match_only():
    assert owns_via_attestation("me-123", "me-123") is True
    assert owns_via_attestation("me-123", "me-999") is False
    assert owns_via_attestation("", "me") is False


# ── G15 drift × chain ──
def test_g15_confirmed_edge_and_composition():
    class F: kind="authz_drift"; accessor="B"; resource="/o/1"; why="proven"
    e = drift_to_capability_edge(F())
    assert e and e["confirmed"] is True
    assert compose_path([e, e]) is not None

def test_g15_unconfirmed_drops_path():
    class F: kind="not_a_drift"; accessor="B"; resource="/o/1"; why=""
    assert drift_to_capability_edge(F()) is None
    assert drift_to_capability_edge(None) is None
    good = {"from":"B","to":"/o/1","capability":"authz_drift","confirmed":True}
    bad = {"from":"B","to":"/o/2","capability":"x","confirmed":False}
    assert compose_path([good, bad]) is None


# ── G5 GraphQL interleave ──
def test_g5_builds_aliased_and_confirms_via_victim_readback():
    op = build_aliased_mutation_probe(["setRole(id:1,role:admin){id}", "noop{id}"])
    assert "m0:" in op and "m1:" in op
    a = NonceAuthority(); s = NonceSeeker(a); n = a.mint("gql"); s.register_planted(n)
    class R:
        def __init__(self, b): self.body = b
    r = confirm_interleave_drift(victim_readback_query="{me{role bio}}",
                                 send_as_victim=lambda q: R({"bio": n.as_text(), "role": "admin"}),
                                 seeker=s, planted=n, cross_principal_ok=True)
    assert r.attributed is True

def test_g5_no_nonce_in_victim_abstains():
    a = NonceAuthority(); s = NonceSeeker(a); n = a.mint("gql"); s.register_planted(n)
    class R:
        def __init__(self, b): self.body = b
    r = confirm_interleave_drift(victim_readback_query="q",
                                 send_as_victim=lambda q: R({"role": "admin"}),
                                 seeker=s, planted=n, cross_principal_ok=True)
    assert r.attributed is False


# ── G4 window-opener (timing never in verdict) ──
def test_g4_plans_and_confirms_only_via_persisted_readback():
    assert len(plan_single_packet_batch("REQ", n=20)) == 20
    plan = deferred_collision_plan("A", "B", 60)
    assert plan["gap_s"] == 60 and plan["then"] == "readback"
    # confirm only when the post-race read-back shows a persisted effect at convergence
    assert race_result_confirmed(post_race_readback={"ctrl": True, "eff": True},
                                 persisted=lambda r: r.get("eff"),
                                 control_visible=lambda r: r.get("ctrl")) is True

def test_g4_race_not_landed_abstains():
    assert race_result_confirmed(post_race_readback={"ctrl": True, "eff": False},
                                 persisted=lambda r: r.get("eff"),
                                 control_visible=lambda r: r.get("ctrl")) is False


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    p = 0
    for fn in fns:
        try:
            fn(); print(f"PASS  {fn.__name__}"); p += 1
        except Exception:
            print(f"FAIL  {fn.__name__}"); traceback.print_exc()
    print(f"\n{p}/{len(fns)} passed")
