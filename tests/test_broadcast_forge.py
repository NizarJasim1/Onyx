"""
FORGE — broadcast extractor regression (Broadcast-vs-Act nerve, step 1).

Locks the declaration channel: ONYX reads the target's broadcast authorization decision
(present/absent fields across principals, _links, named 403s) and emits the differences
as CANDIDATES — but only when tied to a declared identity/role signal (the killer FP
guard). It never convicts; the act channel + Δstate judge.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.broadcast import BroadcastLedger, _withheld_permission
from authpath.models import HTTPResponse


def _r(body, status=200, headers=None):
    return HTTPResponse(status, body, headers=headers or {})


def test_killer_legitimate_difference_abstains():
    """The trap that would kill the nerve: a broadcast difference between two SAME-role
    principals (feature flag / A-B / null value) is NOT an authorization claim → abstain."""
    L = BroadcastLedger()
    L.note_declared_role("uA", "member")
    L.note_declared_role("uB", "member")
    L.record("uA", "doc:1", _r({"id": "1", "title": "t", "beta_widget": "on"}))
    L.record("uB", "doc:1", _r({"id": "1", "title": "t"}))
    assert L.broadcast_difference_candidates() == []


def test_true_authz_field_broadcast_is_candidate():
    L = BroadcastLedger()
    L.note_declared_role("admin", "admin")
    L.note_declared_role("user", "member")
    L.record("admin", "doc:1", _r({"id": "1", "salary": 5000, "ssn": "x"}))
    L.record("user", "doc:1", _r({"id": "1"}))
    c = L.broadcast_difference_candidates()
    assert len(c) == 1
    assert "salary" in c[0]["fields_only_a"] and "ssn" in c[0]["fields_only_a"]


def test_explicit_named_403_is_candidate_without_role_data():
    L = BroadcastLedger()
    L.record("uA", "doc:9", _r({"id": "9", "secret": "s"}))
    L.record("uB", "doc:9", _r({"error": "requires permission docs:admin"}, status=403))
    c = L.broadcast_difference_candidates()
    assert len(c) == 1
    assert c[0]["withheld_b"] == "docs:admin"


def test_hateoas_action_broadcast_is_candidate():
    L = BroadcastLedger()
    L.note_declared_role("editor", "editor")
    L.note_declared_role("viewer", "viewer")
    L.record("editor", "doc:1", _r({"id": "1", "_links": {"edit": {"href": "/d/1/edit"},
                                                          "delete": {"href": "/d/1"}}}))
    L.record("viewer", "doc:1", _r({"id": "1", "_links": {"self": {"href": "/d/1"}}}))
    c = L.broadcast_difference_candidates()
    assert len(c) == 1
    assert "edit" in c[0]["actions_only_a"] and "delete" in c[0]["actions_only_a"]


def test_same_role_identical_broadcast_no_candidate():
    L = BroadcastLedger()
    L.note_declared_role("u1", "member")
    L.note_declared_role("u2", "member")
    L.record("u1", "doc:1", _r({"id": "1", "title": "t"}))
    L.record("u2", "doc:1", _r({"id": "1", "title": "t"}))
    assert L.broadcast_difference_candidates() == []


def test_withheld_extraction_precision():
    assert _withheld_permission(_r({"error": "requires permission docs:admin"}, 403)) == "docs:admin"
    assert _withheld_permission(_r({"message": "missing scope orders:write"}, 403)) == "orders:write"
    assert _withheld_permission(_r({"detail": "requires role admin"}, 403)) == "admin"
    assert _withheld_permission(_r({"error": "access denied"}, 403)) is None      # generic → abstain
    assert _withheld_permission(_r({"error": "x"}, 200)) is None                   # not a denial


def test_no_verdict_contract():
    L = BroadcastLedger()
    public = [n for n in dir(L) if not n.startswith("_")]
    assert set(public) <= {"record", "note_declared_role", "broadcast_difference_candidates"}
    for banned in ("finding", "confirm", "verdict", "report", "convict"):
        assert not any(banned in n.lower() for n in public)
