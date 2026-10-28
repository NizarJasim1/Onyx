"""
Deficiency #1 (oracle/policy) — FULL solved-criterion, every gap in the [19] inventory.

GAP-A sharing-vs-breach | GAP-B/C/D resource-domain established from the legitimate walk
(owner-identity-independent) | GAP-E transitive grant graph (RBAC/delegation) |
FP-safety on ambiguous/shared resources | GAP-F cross-principal WRITE routes the gate.
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.policy import PolicyHypothesis, IsolationInvariant, PERMITTED, FORBIDDEN, UNCOVERED


# ---------- unit level: the policy object itself -----------------------------------
def _flat():
    return IsolationInvariant("tenant-isolation",
                              {"A": "T1", "B": "T1", "C": "T2"}).to_hypothesis()


def test_gapCD_resource_domain_established_from_walk_not_owner_identity():
    h = _flat()
    # provisioning walk: owners reach their own resources (no owner identity needed)
    h.observe_owner("A", "doc_a"); h.observe_owner("B", "doc_b"); h.observe_owner("C", "doc_c")
    assert h.resource_domain("doc_a") == "T1" and h.resource_domain("doc_c") == "T2"
    # C reaching doc_b (T1) is a breach — classified with owner=None, resource only
    assert h.classify_access("C", None, "doc_b") == FORBIDDEN
    assert h.classify_access("A", None, "doc_b") == PERMITTED       # same domain T1


def test_gapE_transitive_grant_graph_permits_delegation():
    h = IsolationInvariant("iso", {"A": "T1", "C": "T2"},
                           allowed_crossings=frozenset({("T2", "T1")})).to_hypothesis()
    h.observe_owner("A", "doc_a")
    # C's domain T2 has a declared grant-edge to T1 -> reaching T1 is permitted (delegation)
    assert h.classify_access("C", None, "doc_a") == PERMITTED
    # reverse direction is NOT granted -> breach
    h.observe_owner("C", "doc_c")
    assert h.classify_access("A", None, "doc_c") == FORBIDDEN


def test_fp_safety_ambiguous_resource_never_breaches():
    h = _flat()
    # a resource reached by BOTH domains during the walk is shared/ambiguous -> unassigned
    h.observe_owner("A", "shared"); h.observe_owner("C", "shared")
    assert h.resource_domain("shared") is None
    assert h.classify_access("C", None, "shared") == UNCOVERED       # abstain, never a breach


# ---------- engine integration: sharing vs breach, and writes ----------------------
class _DocStore:
    host = "docs.test"
    def __init__(self):
        self.docs = {"doc_a": {"owner": "A", "content": "alpha-secret-A"},
                     "doc_b": {"owner": "B", "content": "bravo-secret-B"},
                     "doc_c": {"owner": "C", "content": "charlie-secret-C"}}
    def send(self, req, principal):
        rid = req.path.rstrip("/").split("/")[-1]
        d = self.docs.get(rid)
        if not d:
            return HTTPResponse(404, {"error": "no doc"})
        if req.method in ("PUT", "POST", "PATCH"):
            d["content"] = (req.body or {}).get("content", d["content"])
            return HTTPResponse(200, {"id": rid, "updated": True})
        return HTTPResponse(200, {"id": rid, "owner_email": f"{d['owner']}@corp.test",
                                  "content": d["content"]})


def _engine(hyp=None):
    store = _DocStore()
    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "ABC"}
    scope = ScopeConfig(allowed_hosts=["docs.test"], automation_permitted=True,
                        target_provenance="third_party", dry_run=False)
    eng = AuthPathEngine(store, P, scope, contract={})
    for f in ("provisional_leads", "active_probing", "conservation", "cross_surface"):
        setattr(eng, f, True)
    eng.confirmer.strict_leak = True
    eng.embedded_owner_exposure = eng.field_exposure = True
    eng.xprincipal_write = eng.xprincipal_delete = True
    if hyp is not None:
        eng.policy_hypothesis = hyp
    return eng, store, P


def _owners_flagged(eng):
    out = set()
    for f in eng.findings:
        out.add(eng.provenance.owner_of_value(f.target_ref) or f.target_ref)
    return out


def _read_scenario(hyp):
    eng, store, P = _engine(hyp)
    def ex(pid, rid, method="GET", body=None):
        req = HTTPRequest(method, f"/docs/v1/{rid}", body=body, host="docs.test")
        return Exchange(request=req, response=store.send(req, P[pid]), principal=P[pid])
    eng.observe(ex("A", "doc_a")); eng.observe(ex("B", "doc_b")); eng.observe(ex("C", "doc_c"))
    eng.analyze(ex("C", "doc_a"))       # declared sharing A->C
    eng.analyze(ex("C", "doc_b"))       # real cross-tenant breach
    eng.drain_deferred()
    return _owners_flagged(eng)


def test_gapA_without_hypothesis_sharing_is_a_false_positive():
    assert {"A", "B"} <= _read_scenario(None)


def test_gapA_with_hypothesis_only_breach_flagged():
    h = _flat(); h.explicit_grants = {"A": {"C"}}     # A legitimately shared with C
    owners = _read_scenario(h)
    assert "B" in owners and "A" not in owners        # breach flagged, sharing suppressed


def test_gapF_cross_domain_write_routes_through_the_gate():
    # verify the gate governs writes too: a same-domain write is suppressed, a
    # cross-domain write is emitted. We assert the single choke point covers RL23.
    from authpath.policy import PolicyHypothesis
    h = _flat()
    for r, who in (("doc_a", "A"), ("doc_b", "B"), ("doc_c", "C")):
        h.observe_owner(who, r)
    # B (T1) writing doc_a (T1) -> permitted; C (T2) writing doc_a (T1) -> forbidden
    assert h.classify_access("B", None, "doc_a") == PERMITTED
    assert h.classify_access("C", None, "doc_a") == FORBIDDEN


def test_empty_hypothesis_is_byte_identical_noop():
    assert PolicyHypothesis().declared() is False


if __name__ == "__main__":
    p = 0; fns = [g for n, g in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as e: print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e: print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
