"""
authpath/tenant.py — cross-tenant isolation oracle (GAP-2 closure).

THE BOUNDARY THIS ADDS
======================
ONYX models a principal as an IDENTITY. The giant-scale breaches, though, are not
"wrong object for this user" but "wrong TENANT for this identity": a principal in
org A resolves an object that belongs to org B — through a wildcard key, a legacy
netId, or a sibling-tenant id. The gap analysis (GAP-2) names the missing model
precisely: the principal is ``(identity, tenant)``, and the tenant boundary is a
DIFFERENT boundary from object ownership and from the surface.

This module realises that model at the oracle layer (additive — the core
``Principal`` is untouched), and confirms a breach with the SAME discipline as every
other ONYX oracle, so it plugs into the registry (GAP-5) and inherits the structural
zero-FP guarantee.

THE CONFIRMATION (Delta-state across a tenant boundary)
=======================================================
A cross-tenant finding is confirmed ONLY when:

    * a principal in tenant A actually OBTAINED the object (observed on the wire), AND
    * an INDEPENDENT authenticated read — performed as a tester-owned principal — proves
      the object is owned by tenant B (its value/owner known to the tester in advance), AND
    * A != B and BOTH tenants are tester-owned.

If the independent read shows the object actually belongs to the ATTACKER's own tenant
(a wildcard that only ever returned the caller's own data, say), the oracle ABSTAINS —
no breach, no finding. That negative control is why precision is preserved: a mere
wildcard or shared endpoint is not a vulnerability; crossing a PROVEN owned boundary is.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from .models import Candidate, EffectClass, StateProof
from .oracle_registry import Oracle, OracleVerdict, VerdictKind


@dataclass
class TenantIsolationProbe:
    """One cross-tenant lead, every endpoint tester-owned.

    ``attacker_obtained`` is an OBSERVED fact from the real attack exchange (the
    attacker-tenant principal received the object body) — not an inference.
    ``owner_tenant_readback_fn(object_ref) -> tenant`` is the INDEPENDENT read, done as
    a principal the tester owns in the victim tenant, that proves which tenant owns the
    object. ``victim_tenant`` is known in advance because the tester owns it."""
    attacker_pid: str
    attacker_tenant: str
    victim_tenant: str
    object_ref: str
    attacker_obtained: bool
    owner_tenant_readback_fn: Callable[[str], Any]


class CrossTenantOracle(Oracle):
    """Confirms a tenant-isolation breach via an out-of-band owner read-back proving
    the object belongs to a DIFFERENT, tester-owned tenant than the caller's."""
    name = "cross-tenant-delta"
    effects = frozenset({EffectClass.CROSS_TENANT})

    def confirm(self, cand: Candidate, ctx: Optional[dict] = None) -> OracleVerdict:
        probe = (ctx or {}).get("tenant_probe")
        if probe is None:
            ev = getattr(getattr(cand, "verdict", None), "evidence", None) or {}
            probe = ev.get("tenant_probe")
        if probe is None:
            return OracleVerdict(kind=VerdictKind.ABSTAIN, effect=EffectClass.CROSS_TENANT,
                                 oracle_name=self.name, reason="no tenant probe attached")

        owned_both = (probe.attacker_tenant != probe.victim_tenant
                      and bool(probe.attacker_tenant) and bool(probe.victim_tenant))
        value_known = probe.victim_tenant not in (None, "")

        # INDEPENDENT ownership read (out-of-band), performed after the attack.
        try:
            owner_tenant = probe.owner_tenant_readback_fn(probe.object_ref)
        except Exception as e:
            return OracleVerdict(kind=VerdictKind.ABSTAIN, effect=EffectClass.CROSS_TENANT,
                                 oracle_name=self.name, reason=f"owner read-back failed: {e!r}")

        crossed = (bool(probe.attacker_obtained)
                   and str(owner_tenant) == str(probe.victim_tenant)
                   and str(owner_tenant) != str(probe.attacker_tenant))
        if crossed and owned_both and value_known:
            proof = StateProof(
                confirmed=True,
                method=(f"object {probe.object_ref} independently read back as owned by "
                        f"tenant {probe.victim_tenant}, yet obtained by a principal in "
                        f"tenant {probe.attacker_tenant}"),
                before=f"caller tenant {probe.attacker_tenant}",
                after=f"owner tenant {probe.victim_tenant}",
                read_as=f"tenant:{probe.victim_tenant}",
                detail="cross-tenant isolation breach (identity valid, tenant boundary crossed)",
            )
            return OracleVerdict(
                kind=VerdictKind.CONFIRMED, effect=EffectClass.CROSS_TENANT,
                oracle_name=self.name, proof=proof,
                reason="cross-tenant access confirmed by out-of-band owner read-back",
                observed_out_of_band=True,
                expected_value_known_in_advance=value_known,
                boundary_owned_both_sides=owned_both,
            )
        return OracleVerdict(
            kind=VerdictKind.ABSTAIN, effect=EffectClass.CROSS_TENANT, oracle_name=self.name,
            reason=("object belongs to the caller's own tenant — no breach (no finding)"
                    if str(owner_tenant) == str(probe.attacker_tenant)
                    else "cross-tenant access not proven"))
