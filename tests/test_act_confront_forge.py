"""
FORGE — act-confronter regression (Broadcast-vs-Act nerve, step 2).

Locks the move from the declaration channel to the act channel: a broadcast difference
becomes a set of SAFE confrontations (B attempts what the target declared B may not),
gated by the SAME audited destructive controls the rest of the engine uses. Candidates
only — the Δstate confirmer judges.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.act_confront import (confrontations_from_candidate, safe_confrontations,
                                    _verb_for_action, Confrontation)
from authpath.scope_guard import ScopeConfig, ScopeGuard


def _cand():
    return {"resource": "doc:1", "accessor_a": "editor", "accessor_b": "viewer",
            "actions_only_a": ["edit", "delete"], "actions_only_b": [],
            "fields_only_a": ["salary"], "fields_only_b": [],
            "withheld_a": None, "withheld_b": None}


def test_verb_mapping_unknown_is_mutating():
    assert _verb_for_action("edit") == "PATCH"
    assert _verb_for_action("delete") == "DELETE"
    assert _verb_for_action("view") == "GET"
    assert _verb_for_action("wibble") == "POST"        # unknown ⇒ mutating (safer gate)


def test_confrontations_generated_from_candidate():
    confs = confrontations_from_candidate(_cand(), owner_of=lambda r: "u-owner")
    kinds = {(c.kind, c.verb, c.declared, c.accessor) for c in confs}
    assert ("hidden_action", "PATCH", "edit", "viewer") in kinds
    assert ("hidden_action", "DELETE", "delete", "viewer") in kinds
    assert ("hidden_field", "GET", "salary", "viewer") in kinds
    assert all(c.owner_hint == "u-owner" for c in confs)


def test_dry_run_blocks_mutation_allows_read():
    confs = confrontations_from_candidate(_cand())
    sg = ScopeGuard(ScopeConfig(allowed_hosts=["t.local"], dry_run=True,
                                allow_destructive=False, automation_permitted=True))
    run, block = safe_confrontations(confs, sg, host="t.local")
    assert [c.verb for c in run] == ["GET"]            # only the read-back is runnable
    assert {c.verb for c, _ in block} == {"PATCH", "DELETE"}


def test_armed_allows_all_mutations():
    confs = confrontations_from_candidate(_cand())
    sg = ScopeGuard(ScopeConfig(allowed_hosts=["t.local"], dry_run=False,
                                allow_destructive=True, automation_permitted=True))
    run, block = safe_confrontations(confs, sg, host="t.local")
    assert block == []
    assert {c.verb for c in run} == {"PATCH", "DELETE", "GET"}


def test_destructive_unarmed_blocks_only_irreversible():
    confs = confrontations_from_candidate(_cand())
    sg = ScopeGuard(ScopeConfig(allowed_hosts=["t.local"], dry_run=False,
                                allow_destructive=False, automation_permitted=True))
    run, block = safe_confrontations(confs, sg, host="t.local")
    assert "PATCH" in {c.verb for c in run}            # reversible edit allowed
    assert {c.verb for c, _ in block} == {"DELETE"}    # irreversible delete blocked


def test_no_verdict_symbols_in_module():
    import authpath.act_confront as M
    src = open(M.__file__).read()
    # ScopeVerdict (the safety gate) is legitimate; only true conviction symbols are banned
    for banned in ("self.findings", "Finding(", "def confirm", "report_markdown"):
        assert banned not in src
