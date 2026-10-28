"""
Order-independent ownership regression — CRUCIBLE problem #5.

The ownership pointer is learned incrementally. An access filed BEFORE the pointer
stabilises must NOT be permanently blind: declared_owner is recomputed lazily at
candidate-generation time with the final pointer, so a cross-owner access recorded early
still becomes a candidate. Same pointer ⇒ no new false positive, only recall.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.equivalence import EquivalenceLedger
from authpath.ownership_pointer import OwnershipPointerLedger
from authpath.models import HTTPRequest, HTTPResponse


def _req(path):
    return HTTPRequest("GET", path, host="t.local")


def test_access_filed_before_pointer_learned_still_becomes_candidate():
    own = OwnershipPointerLedger()
    eq = EquivalenceLedger(ownership=own)

    # 1) FIRST, a cross-owner access is filed while the pointer is NOT yet learned:
    #    alice receives an object whose owner_id is u-bob.
    eq.record_access(_req("/api/docs/2"),
                     HTTPResponse(200, {"id": "2", "owner_id": "u-bob", "title": "Bob"}),
                     "u-alice")

    # 2) THEN enough self-owned accesses arrive to teach the pointer (owner_id == accessor).
    for ident in ("u-alice", "u-bob"):
        own.observe_owned(_req(f"/api/docs/own-{ident}"),
                          HTTPResponse(200, {"id": "x", "owner_id": ident}), ident,
                          f"docs/own-{ident}")

    assert own.pointer() == "owner_id"                 # pointer learned AFTER the first access
    cands = eq.ownership_mismatch_candidates()
    hit = [c for c in cands if c["accessor"] == "u-alice"
           and str(c["declared_owner"]) == "u-bob"]
    assert hit, "early cross-owner access was permanently blind (the order-dependent bug)"


def test_self_owned_access_never_a_candidate():
    own = OwnershipPointerLedger()
    eq = EquivalenceLedger(ownership=own)
    for ident in ("u-alice", "u-bob"):
        own.observe_owned(_req("/api/docs/own"),
                          HTTPResponse(200, {"id": "own", "owner_id": ident}), ident,
                          f"docs/own-{ident}")
        eq.record_access(_req("/api/docs/own"),
                         HTTPResponse(200, {"id": "own", "owner_id": ident}), ident)
    # everyone read only their own → no mismatch candidate
    assert eq.ownership_mismatch_candidates() == []
