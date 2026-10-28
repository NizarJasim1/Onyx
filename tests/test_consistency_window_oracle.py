"""
GAP-10 — consistency-window ("new enemy") oracle tests.

Decisive pair: after a relationship is revoked, access that STILL works => CONFIRMED
(stale decision within the propagation window); access that is correctly DENIED =>
ABSTAIN (the revocation was enforced, no window bug). The second is the zero-FP control.
"""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.models import EffectClass
from authpath.rebac import ConsistencyWindowOracle, ConsistencyWindowProbe
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
    return build_default_registry(_StubConfirmer(), extra_oracles=[ConsistencyWindowOracle()])


def test_stale_access_after_revocation_confirmed():
    probe = ConsistencyWindowProbe(
        subject_pid="X", relation_source="G", object_ref="doc1",
        access_after_revocation_fn=lambda: True,        # still works after revoke -> stale
    )
    v = _reg().confirm(_cand(EffectClass.CONSISTENCY_WINDOW), ctx={"window_probe": probe})
    assert v.kind is VerdictKind.CONFIRMED
    assert v.observed_out_of_band and v.boundary_owned_both_sides


def test_revocation_enforced_abstains_zero_fp():
    probe = ConsistencyWindowProbe(
        subject_pid="X", relation_source="G", object_ref="doc1",
        access_after_revocation_fn=lambda: False,       # correctly denied -> no bug
    )
    v = _reg().confirm(_cand(EffectClass.CONSISTENCY_WINDOW), ctx={"window_probe": probe})
    assert v.kind is VerdictKind.ABSTAIN
    assert "revocation enforced" in v.reason


def test_post_revocation_read_error_abstains():
    def _boom():
        raise RuntimeError("timeout")
    probe = ConsistencyWindowProbe(subject_pid="X", relation_source="G", object_ref="doc1",
                                   access_after_revocation_fn=_boom)
    v = _reg().confirm(_cand(EffectClass.CONSISTENCY_WINDOW), ctx={"window_probe": probe})
    assert v.kind is VerdictKind.ABSTAIN


def test_same_endpoint_not_owned_both_abstains():
    probe = ConsistencyWindowProbe(subject_pid="X", relation_source="X", object_ref="doc1",
                                   access_after_revocation_fn=lambda: True)
    v = _reg().confirm(_cand(EffectClass.CONSISTENCY_WINDOW), ctx={"window_probe": probe})
    assert v.kind is VerdictKind.ABSTAIN


def test_consistency_window_in_coverage_map():
    cov = _reg().coverage()
    assert EffectClass.CONSISTENCY_WINDOW.value in cov["covered"]
    assert "consistency-window" in cov["covered"][EffectClass.CONSISTENCY_WINDOW.value]
