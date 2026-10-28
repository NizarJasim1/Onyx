"""
GAP-2 — cross-tenant isolation oracle tests.

Decisive pair: a wildcard/sibling key that returns ANOTHER tenant's object (breach,
CONFIRMED) vs the same shape returning the caller's OWN tenant object (no breach,
ABSTAIN). The second is the zero-FP negative control — a shared/wildcard endpoint is
not a vulnerability until a PROVEN owned tenant boundary is crossed.
"""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.models import EffectClass, StateProof
from authpath.tenant import CrossTenantOracle, TenantIsolationProbe
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
    return build_default_registry(_StubConfirmer(), extra_oracles=[CrossTenantOracle()])


def test_cross_tenant_confirmed_when_object_owned_by_other_tenant():
    probe = TenantIsolationProbe(
        attacker_pid="A", attacker_tenant="orgA", victim_tenant="orgB",
        object_ref="obj-77", attacker_obtained=True,
        owner_tenant_readback_fn=lambda ref: "orgB",     # independent read: obj belongs to orgB
    )
    v = _reg().confirm(_cand(EffectClass.CROSS_TENANT), ctx={"tenant_probe": probe})
    assert v.kind is VerdictKind.CONFIRMED
    assert v.observed_out_of_band and v.boundary_owned_both_sides
    assert v.as_state_proof().read_as == "tenant:orgB"


def test_cross_tenant_abstains_when_object_is_own_tenant_zero_fp():
    """Negative control: the wildcard only ever returned the caller's OWN object."""
    probe = TenantIsolationProbe(
        attacker_pid="A", attacker_tenant="orgA", victim_tenant="orgB",
        object_ref="obj-1", attacker_obtained=True,
        owner_tenant_readback_fn=lambda ref: "orgA",     # it's the caller's own tenant
    )
    v = _reg().confirm(_cand(EffectClass.CROSS_TENANT), ctx={"tenant_probe": probe})
    assert v.kind is VerdictKind.ABSTAIN
    assert "own tenant" in v.reason


def test_cross_tenant_abstains_when_not_obtained():
    probe = TenantIsolationProbe(
        attacker_pid="A", attacker_tenant="orgA", victim_tenant="orgB",
        object_ref="obj-5", attacker_obtained=False,     # attack did not actually get the object
        owner_tenant_readback_fn=lambda ref: "orgB",
    )
    v = _reg().confirm(_cand(EffectClass.CROSS_TENANT), ctx={"tenant_probe": probe})
    assert v.kind is VerdictKind.ABSTAIN


def test_cross_tenant_abstains_same_tenant():
    """A == B can never be a cross-tenant breach (boundary not two owned sides)."""
    probe = TenantIsolationProbe(
        attacker_pid="A", attacker_tenant="orgA", victim_tenant="orgA",
        object_ref="obj-9", attacker_obtained=True,
        owner_tenant_readback_fn=lambda ref: "orgA",
    )
    v = _reg().confirm(_cand(EffectClass.CROSS_TENANT), ctx={"tenant_probe": probe})
    assert v.kind is VerdictKind.ABSTAIN


def test_cross_tenant_readback_error_abstains():
    def _boom(ref):
        raise RuntimeError("403")
    probe = TenantIsolationProbe(
        attacker_pid="A", attacker_tenant="orgA", victim_tenant="orgB",
        object_ref="obj-3", attacker_obtained=True, owner_tenant_readback_fn=_boom,
    )
    v = _reg().confirm(_cand(EffectClass.CROSS_TENANT), ctx={"tenant_probe": probe})
    assert v.kind is VerdictKind.ABSTAIN


def test_cross_tenant_in_coverage_map():
    cov = _reg().coverage()
    assert EffectClass.CROSS_TENANT.value in cov["covered"]
    assert "cross-tenant-delta" in cov["covered"][EffectClass.CROSS_TENANT.value]
