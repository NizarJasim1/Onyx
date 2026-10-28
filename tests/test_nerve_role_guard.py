"""
Peer-role guard regression (CRUCIBLE problem #2).

A BOLA ownership mismatch is confirmed only between PEERS (same declared role). A role
DIFFERENCE (e.g. admin reading a member's object) is a plausible role-based grant → the
nerve abstains (RL5), killing the false positive that real-HTTP measurement exposed —
while still catching genuine member→member BOLA. Unknown role must NOT suppress.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.nerve_bridge import NerveBridge, _declared_role
from authpath.models import HTTPRequest, HTTPResponse, Principal


def _self_resp(identity, role=None):
    body = {"id": identity}
    if role is not None:
        body["role"] = role
    return HTTPResponse(200, body)


def test_declared_role_extraction():
    assert _declared_role(HTTPResponse(200, {"id": "u1", "role": "admin"})) == "admin"
    assert _declared_role(HTTPResponse(200, {"id": "u1", "tier": "premium"})) == "premium"
    assert _declared_role(HTTPResponse(200, {"id": "u1"})) is None


class _Confirmer:
    """Minimal confirmer: owner read-back returns the owner's private object; the accessor
    already reproduced it (set on the candidate)."""
    def __init__(self, owner_body):
        self.owner_body = owner_body

    def _read(self, req, principal):
        return HTTPResponse(200, self.owner_body)


def _bridge_with_roles(acc_id, acc_role, own_id, own_role):
    owner_body = {"id": "9", "owner_id": own_id, "salary": 5000}
    br = NerveBridge(_Confirmer(owner_body), {}, anon_principal=None)
    # provision the owner principal so X-1 passes
    br.by_identity[own_id] = Principal(own_id, own_id, {"Authorization": "Bearer o"})
    # declare roles as the target's /me would
    if acc_role is not None:
        br.declared_role[acc_id] = acc_role
    if own_role is not None:
        br.declared_role[own_id] = own_role
    # ownership pointer + a mismatch candidate the accessor reproduced
    br.ownership._pointer = "owner_id"
    cand = {"resource": "doc:9", "accessor": acc_id, "declared_owner": own_id,
            "request": HTTPRequest("GET", "/api/docs/9", host="t"),
            "response": HTTPResponse(200, owner_body)}
    return br, cand


def test_peer_same_role_confirms():
    br, cand = _bridge_with_roles("u-bob", "member", "u-alice", "member")
    assert br._confirm(cand) is not None                 # real peer-to-peer BOLA


def test_role_difference_abstains():
    br, cand = _bridge_with_roles("u-admin", "admin", "u-alice", "member")
    assert br._confirm(cand) is None                     # admin grant ⇒ abstain (no FP)
    assert any("role-difference" in why for _, why in br.abstained)


def test_unknown_role_does_not_suppress():
    br, cand = _bridge_with_roles("u-bob", None, "u-alice", None)
    assert br._confirm(cand) is not None                 # unknown ≠ elevated → proceed
