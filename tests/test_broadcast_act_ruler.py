"""
Broadcast-vs-Act nerve — end-to-end ruler regression (T4: running is the final judge).

A ruler with REAL-shaped broadcast and KNOWN ground truth, NOT designed as the detector:
  * roles differ (admin / member), so the FP guard's declared-role signal is present;
  * PLANTED contradiction: the field `salary` is broadcast hidden to members, and the
    act leaks it — a real declaration-vs-act contradiction;
  * DECOY: `beta_widget` differs between two MEMBERS (same role) — a feature flag, which
    the FP guard must abstain on.

This validates that the two channels (broadcast extractor + act confronter) work
together on broadcast the author did not design as the detector, before the Δstate
bridge is built.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.broadcast import BroadcastLedger
from authpath.act_confront import confrontations_from_candidate
from authpath.models import HTTPResponse


def _ledger():
    L = BroadcastLedger()
    L.note_declared_role("admin", "admin")
    L.note_declared_role("alice", "member")
    L.note_declared_role("bob", "member")
    L.record("admin", "doc:1", HTTPResponse(200, {
        "id": "1", "title": "Q4 plan", "salary": 99000,
        "_links": {"edit": {"href": "/d/1"}, "delete": {"href": "/d/1"}}}))
    L.record("alice", "doc:1", HTTPResponse(200, {
        "id": "1", "title": "Q4 plan", "_links": {"self": {"href": "/d/1"}}}))
    L.record("bob", "doc:1", HTTPResponse(200, {
        "id": "1", "title": "Q4 plan", "beta_widget": "on",
        "_links": {"self": {"href": "/d/1"}}}))
    return L


def test_feature_flag_decoy_abstained():
    """Two members differing only by a feature flag must NOT produce a candidate."""
    cands = _ledger().broadcast_difference_candidates()
    assert not any({c["accessor_a"], c["accessor_b"]} == {"alice", "bob"} for c in cands)


def test_true_role_broadcast_difference_is_candidate():
    cands = _ledger().broadcast_difference_candidates()
    salary_cands = [c for c in cands if "salary" in c["fields_only_a"]]
    assert salary_cands                                  # admin-vs-member salary candidate exists
    assert all(self_role_pair(c) for c in salary_cands)  # always across differing roles


def self_role_pair(c):
    return {c["accessor_a"], c["accessor_b"]} & {"admin"} and \
           ({c["accessor_a"], c["accessor_b"]} & {"alice", "bob"})


def test_act_confrontation_generated_for_hidden_field():
    cands = _ledger().broadcast_difference_candidates()
    salary_cand = next(c for c in cands if "salary" in c["fields_only_a"])
    confs = confrontations_from_candidate(salary_cand)
    field_confs = [c for c in confs if c.kind == "hidden_field" and c.declared == "salary"]
    assert field_confs                                   # the member is set to attempt the read
    assert all(c.verb == "GET" for c in field_confs)     # read-only — always safe
