"""
FORGE — ownership-pointer discovery regression suite (nerve build, step 2).

Locks the discovery of the target's ownership-pointer field by identity-correlation,
and — critically — the SAFETY CONTRACT: this layer emits candidates only and can
never, by construction, produce a finding or a false positive. Every guard from the
F7 pre-mortem is pinned.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.ownership_pointer import (OwnershipPointerLedger, register_ownership_fields,
                                        _CUSTOM_OWNERSHIP_FIELDS)
from authpath.models import HTTPRequest, HTTPResponse


def _R(path, body, q=None):
    return HTTPRequest("GET", path, query=q or {}), HTTPResponse(200, body)


def test_pointer_learned_from_two_resources():
    L = OwnershipPointerLedger()
    L.observe_owned(*_R("/api/docs/1", {"id": "doc1", "owner_id": "u-100"}), "u-100", "doc:1")
    L.observe_owned(*_R("/api/docs/2", {"id": "doc2", "owner_id": "u-100"}), "u-100", "doc:2")
    assert L.pointer() == "owner_id"
    assert L.declared_owner(HTTPResponse(200, {"id": "d9", "owner_id": "u-200"})) == "u-200"


def test_fp_a_single_coincidence_is_not_a_pointer():
    L = OwnershipPointerLedger()
    L.observe_owned(*_R("/api/docs/1", {"owner_id": "u-100", "version": "u-100"}), "u-100", "doc:1")
    assert L.pointer() is None              # one resource ⇒ no corroboration


def test_fp_e_reflected_input_excluded():
    L = OwnershipPointerLedger()
    L.observe_owned(*_R("/api/users/u-100", {"user_id": "u-100"}), "u-100", "user:u-100")
    L.observe_owned(*_R("/api/users/u-100/prefs", {"user_id": "u-100"}), "u-100", "prefs:u-100")
    assert L.pointer() is None              # u-100 was in the request path ⇒ reflection


def test_fp_b_non_ownership_named_field_rejected():
    L = OwnershipPointerLedger()
    L.observe_owned(*_R("/api/docs/1", {"owner_id": "u-1", "region": "u-1"}), "u-1", "doc:1")
    L.observe_owned(*_R("/api/docs/2", {"owner_id": "u-1", "region": "u-1"}), "u-1", "doc:2")
    assert L.pointer() == "owner_id"        # region equals id but is not owner-named


def test_fp_c_shared_resource_grant_detected():
    L = OwnershipPointerLedger()
    shared = HTTPResponse(200, {"id": "d5", "owner_id": "u-999", "shared_with": ["u-100", "u-7"]})
    assert L.grant_includes(shared, "u-100") is True
    assert L.grant_includes(shared, "u-3") is False


def test_nested_owner_pointer():
    L = OwnershipPointerLedger()
    L.observe_owned(*_R("/api/posts/1", {"id": "p1", "user": {"id": "u-5"}}), "u-5", "post:1")
    L.observe_owned(*_R("/api/posts/2", {"id": "p2", "user": {"id": "u-5"}}), "u-5", "post:2")
    assert L.pointer() == "user.id"


def test_distinguishes_two_owners():
    L = OwnershipPointerLedger()
    L.observe_owned(*_R("/api/docs/1", {"owner_id": "u-1"}), "u-1", "doc:1")
    L.observe_owned(*_R("/api/docs/2", {"owner_id": "u-1"}), "u-1", "doc:2")
    L.observe_owned(*_R("/api/docs/3", {"owner_id": "u-2"}), "u-2", "doc:3")
    L.observe_owned(*_R("/api/docs/4", {"owner_id": "u-2"}), "u-2", "doc:4")
    assert L.pointer() == "owner_id"        # distinguished two owners → canonical


def test_bespoke_ownership_field_extensible():
    L = OwnershipPointerLedger()
    L.observe_owned(*_R("/api/x/1", {"belongsToUser": "u-1"}), "u-1", "x:1")
    L.observe_owned(*_R("/api/x/2", {"belongsToUser": "u-1"}), "u-1", "x:2")
    assert L.pointer() is None              # unknown field name ⇒ abstain
    try:
        register_ownership_fields(["belongsToUser"])
        L2 = OwnershipPointerLedger()
        L2.observe_owned(*_R("/api/x/1", {"belongsToUser": "u-1"}), "u-1", "x:1")
        L2.observe_owned(*_R("/api/x/2", {"belongsToUser": "u-1"}), "u-1", "x:2")
        assert L2.pointer() == "belongsToUser"
    finally:
        _CUSTOM_OWNERSHIP_FIELDS.discard("belongstouser")


def test_safety_contract_no_verdict_method():
    """META-GUARD: this layer must expose NO way to produce a finding/verdict — its
    only outputs are the pointer, a declared owner, and a grant check. Conviction is
    the Δstate confirmer's job alone, so a wrong correlation can never be a false
    positive."""
    L = OwnershipPointerLedger()
    public = [n for n in dir(L) if not n.startswith("_")]
    assert set(public) <= {"observe_owned", "pointer", "declared_owner", "grant_includes"}
    for banned in ("finding", "confirm", "verdict", "report", "convict", "flag"):
        assert not any(banned in n.lower() for n in public)
