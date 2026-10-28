"""
FORGE — equivalence / ownership-reconciliation regression suite (nerve build, step 3).

Locks the nerve's core signal — "the target served Y an object its own data says is
X's, with no grant to Y" — and every F7 guard, plus the safety contract that this
layer can never produce a verdict.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.equivalence import EquivalenceLedger
from authpath.ownership_pointer import OwnershipPointerLedger
from authpath.models import HTTPRequest, HTTPResponse


def _G(path, body, status=200):
    return HTTPRequest("GET", path), HTTPResponse(status, body)


def _with_pointer():
    own = OwnershipPointerLedger()
    own.observe_owned(*_G("/api/docs/1", {"id": "d1", "owner_id": "u-100"}), "u-100", "doc:1")
    own.observe_owned(*_G("/api/docs/2", {"id": "d2", "owner_id": "u-100"}), "u-100", "doc:2")
    return EquivalenceLedger(ownership=own)


def test_core_ownership_mismatch_is_a_candidate():
    L = _with_pointer()
    L.record_access(*_G("/api/docs/9", {"id": "d9", "owner_id": "u-200"}), "u-100")
    c = L.ownership_mismatch_candidates()
    assert len(c) == 1
    assert c[0]["accessor"] == "u-100" and c[0]["declared_owner"] == "u-200"


def test_self_owned_is_not_a_candidate():
    L = _with_pointer()
    L.record_access(*_G("/api/docs/3", {"id": "d3", "owner_id": "u-100"}), "u-100")
    assert L.ownership_mismatch_candidates() == []


def test_shared_resource_is_not_a_candidate():
    L = _with_pointer()
    L.record_access(*_G("/api/docs/5", {"id": "d5", "owner_id": "u-200",
                                        "shared_with": ["u-100"]}), "u-100")
    assert L.ownership_mismatch_candidates() == []


def test_no_attested_identity_abstains():
    L = _with_pointer()
    L.record_access(*_G("/api/docs/9", {"id": "d9", "owner_id": "u-200"}), None)
    assert L.ownership_mismatch_candidates() == []


def test_owner_not_declared_abstains():
    L = _with_pointer()
    L.record_access(*_G("/api/docs/9", {"id": "d9", "title": "no owner"}), "u-100")
    assert L.ownership_mismatch_candidates() == []


def test_no_pointer_learned_abstains():
    L = EquivalenceLedger()        # ownership ledger empty → no pointer
    L.record_access(*_G("/api/docs/9", {"id": "d9", "owner_id": "u-200"}), "u-100")
    assert L.ownership_mismatch_candidates() == []


def test_forbidden_access_is_not_a_leak():
    L = _with_pointer()
    L.record_access(*_G("/api/docs/9", {"error": "forbidden"}, 403), "u-100")
    assert L.ownership_mismatch_candidates() == []


def test_read_write_not_conflated():
    L = _with_pointer()
    L.record_access(HTTPRequest("GET", "/api/docs/7"), HTTPResponse(200, {"id": "d7", "owner_id": "u-100"}), "u-100")
    L.record_access(HTTPRequest("DELETE", "/api/docs/7"), HTTPResponse(403, {"error": "no"}), "u-100")
    # different permission classes ⇒ NOT a self-contradiction pair
    assert L.decision_conflict_pairs() == []


def test_decision_conflict_pair_same_permission():
    L = _with_pointer()
    L.record_access(*_G("/api/docs/7", {"id": "d7", "owner_id": "u-100"}), "u-100")
    L.record_access(*_G("/api/docs/7", {"error": "forbidden"}, 403), "u-100")
    assert len(L.decision_conflict_pairs()) == 1


def test_safety_contract_no_verdict_method():
    L = _with_pointer()
    public = [n for n in dir(L) if not n.startswith("_")]
    assert set(public) <= {"ownership", "record_access",
                           "ownership_mismatch_candidates", "decision_conflict_pairs"}
    for banned in ("finding", "confirm", "verdict", "report", "convict"):
        assert not any(banned in n.lower() for n in public)
