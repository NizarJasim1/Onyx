"""
GAP-7 — relationship-based (ReBAC) transitive-authorization oracle tests.

The decisive pair: a legitimate DERIVED access (member -> group -> folder -> doc) must
ABSTAIN (it is authorized, flagging it would be a false positive), while access with NO
relationship path, Δstate-confirmed to belong to another principal, CONFIRMS. The first
is the FP-suppression that the whole ReBAC model exists to provide.
"""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.models import EffectClass
from authpath.rebac import ReBACOracle, ReBACProbe, RelationGraph
from authpath.oracle_registry import VerdictKind, build_default_registry


def _cand(effect, evidence=None):
    return SimpleNamespace(
        verdict=SimpleNamespace(effect=effect, evidence=evidence or {}),
        classification=SimpleNamespace(effect=effect),
    )


class _StubConfirmer:
    def confirm(self, cand):
        return None


def _reg():
    return build_default_registry(_StubConfirmer(), extra_oracles=[ReBACOracle()])


# user X is a member of group G, which owns folder F, which contains doc1.
_LEGIT_EDGES = [("X", "G"), ("G", "F"), ("F", "doc1")]


def test_relation_graph_transitive_closure():
    g = RelationGraph()
    for a, b in _LEGIT_EDGES:
        g.add_edge(a, b)
    assert g.reaches("X", "doc1") is True      # X -> G -> F -> doc1
    assert g.reaches("X", "doc2") is False


def test_legitimate_derived_access_abstains_no_fp():
    """X has a real path to doc1 — authorized derived access, NOT a finding."""
    probe = ReBACProbe(principal_pid="X", object_ref="doc1", observed_edges=_LEGIT_EDGES,
                       delta_owner_differs=True, victim_pid="Y")
    v = _reg().confirm(_cand(EffectClass.REBAC_BYPASS), ctx={"rebac_probe": probe})
    assert v.kind is VerdictKind.ABSTAIN
    assert "relationship path exists" in v.reason


def test_unbacked_access_confirmed():
    """Z has NO path to doc1 and Δstate shows doc1 belongs to Y — transitive bypass."""
    probe = ReBACProbe(principal_pid="Z", object_ref="doc1", observed_edges=_LEGIT_EDGES,
                       delta_owner_differs=True, victim_pid="Y")
    v = _reg().confirm(_cand(EffectClass.REBAC_BYPASS), ctx={"rebac_probe": probe})
    assert v.kind is VerdictKind.CONFIRMED
    assert v.as_state_proof().read_as == "Y"


def test_no_path_but_owner_not_confirmed_abstains():
    probe = ReBACProbe(principal_pid="Z", object_ref="doc1", observed_edges=_LEGIT_EDGES,
                       delta_owner_differs=False, victim_pid="Y")
    v = _reg().confirm(_cand(EffectClass.REBAC_BYPASS), ctx={"rebac_probe": probe})
    assert v.kind is VerdictKind.ABSTAIN


def test_malformed_edges_tolerated():
    probe = ReBACProbe(principal_pid="Z", object_ref="doc1",
                       observed_edges=[("X", "G"), "bad", ("G",)],  # junk entries ignored
                       delta_owner_differs=True, victim_pid="Y")
    v = _reg().confirm(_cand(EffectClass.REBAC_BYPASS), ctx={"rebac_probe": probe})
    assert v.kind is VerdictKind.CONFIRMED      # Z still has no path -> confirmed


def test_rebac_in_coverage_map():
    cov = _reg().coverage()
    assert EffectClass.REBAC_BYPASS.value in cov["covered"]
    assert "rebac-path" in cov["covered"][EffectClass.REBAC_BYPASS.value]
