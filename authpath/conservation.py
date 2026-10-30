"""
Authority Conservation (RL19) — rebuilt on MEASURED ownership, not value-order.
==============================================================================

Position. Every prior tool — including the 2026 state-of-the-art mutation verifier
Hadrian (setup->attack->verify) — answers a per-action question: "did THIS action
change state / did the response differ?". Hadrian proves WRITE/DELETE by verifying
a state change; a READ changes nothing, so for the dominant BOLA shape (a body that
over-exposes another principal's private field) it falls back to response-template
matching — the very 200-OK heuristic it rightly mocks Autorize for.

ONYX reframes up a level: authority is a CONSERVED quantity. A principal's exercised
authority must be a subset of its conserved (measured + granted) authority, at a
coordinate (object x property x function x service x time). A read that surfaces a
value provably belonging to another principal's private authority violates the
invariant — proven by cross-principal differential, no mutation, no resource
creation. Hadrian's "did the write succeed" is the single object/write special case.

This rebuild fixes the flat first-seen attribution of the prototype. Ownership is
now established by the MEASURED, order-independent, laundering-proof relations the
provenance store already records during the legitimate (observe) phase only:

  * legitimate_holders(V): principals who legitimately ADDRESSED+received V as
    their own object (the ownership signal for id/owner values).
  * legitimate_seers(V):  principals who legitimately received V in a body (a
    single non-anon seer owns a secret that is never 'addressed').

An attack-phase response never enters either index, so a value cannot be laundered
into 'public' by surfacing it through an attacker-reachable endpoint.

RED LINES. RL1 every decision is a measured fact (held/seen sets, anon receipt) or
a fixed lexicon — zero learned thresholds, zero behavioural baseline. RL2 the
relations are set-membership, not temporal 'first' — deterministic, order-free.
RL3 emits a CANDIDATE only; a cross-principal differential confirmer proves it.
RL5 any ambiguity (no owner baseline, multiple legitimate holders) -> abstain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import EffectClass, ImpactClass, LawVerdict, ValueOrigin
from .provenance import ValueClass
from .eil import Law, LawContext


# --------------------------------------------------------------------------- #
# Coordinate frame — every ONYX effect-class is one coordinate of one invariant#
# --------------------------------------------------------------------------- #

AXIS_OBJECT = "object"
AXIS_PROPERTY = "property"
AXIS_FUNCTION = "function"
AXIS_SERVICE = "service"
AXIS_TIME = "time"
AXIS_GRANT = "grant"

EFFECT_TO_AXIS: dict[EffectClass, str] = {
    EffectClass.OBJECT_ACCESS: AXIS_OBJECT,
    EffectClass.OWNERSHIP: AXIS_PROPERTY,
    EffectClass.FIELD_PROJECTION: AXIS_PROPERTY,
    EffectClass.CROSS_SURFACE: AXIS_PROPERTY,
    EffectClass.AUTHORITY: AXIS_FUNCTION,
    EffectClass.STRUCTURAL_DIVERGENCE: AXIS_FUNCTION,
    EffectClass.AUTHORITY_GRANT: AXIS_GRANT,
    EffectClass.TEMPORAL_DRIFT: AXIS_TIME,
    EffectClass.AUTH_REGRESSION: AXIS_TIME,
    EffectClass.COUPON: AXIS_TIME,
}

_AUTHORITY_BOUND = (
    ValueClass.ID, ValueClass.OWNER, ValueClass.TOKEN,
    ValueClass.ROLE, ValueClass.AMOUNT, ValueClass.STATE,
)
_SENS_THRESHOLD = 7


@dataclass
class LeakedValue:
    value: Any
    field_path: str
    value_class: str
    owner: str              # the principal whose private authority this belongs to
    origin: ValueOrigin     # a measured origin under `owner` (for the confirmer)
    axis: str = "property"  # property (same service) or service (cross-host)


@dataclass
class AttributionResult:
    leaked: list[LeakedValue] = field(default_factory=list)
    exonerated_public: int = 0    # an anonymous principal legitimately received it
    exonerated_self: int = 0      # B legitimately holds / was shared / its envelope holds it
    exonerated_shared: int = 0    # legitimately held by multiple principals -> common, not private
    unattributed: int = 0         # no owner baseline -> abstain (visible coverage gap)

    @property
    def violates(self) -> bool:
        return len(self.leaked) > 0


def _is_anon(pid: str) -> bool:
    p = (pid or "").strip().lower()
    return p in ("anon", "anonymous", "public", "") or p.startswith("anon")


def _privacy_bound(tv, ctx: LawContext) -> bool:
    """Privacy-relevant if it carries authority by CLASS, sits in a sensitively
    named field, OR is a value some principal MEASURABLY owns (kills the lexicon
    blind spot: an oddly/locally named id that another principal legitimately
    holds is still authority-bound, by fact not by name)."""
    if tv.value_class in _AUTHORITY_BOUND:
        return True
    leaf = tv.field_path.split(".")[-1].split("[")[0]
    from .intrinsic import name_sensitivity
    if name_sensitivity(leaf) >= _SENS_THRESHOLD:
        return True
    if ctx.provenance.legitimate_holders(tv.value):
        return True
    # a secret is privacy-bound if legitimately received by exactly ONE non-anon
    # principal and never by anon — i.e. it is measurably private to that principal
    # (secrets are never 'addressed', so they never appear in the holder index).
    seers = ctx.provenance.legitimate_seers(tv.value)
    if seers and not any(_is_anon(p) for p in seers):
        nonanon = [p for p in seers if not _is_anon(p)]
        if len(nonanon) == 1:
            return True
    return False


def _origin_for(ctx: LawContext, value: Any, owner: str) -> ValueOrigin:
    """A measured origin under `owner` (so the confirmer reads back as the right
    principal). Prefer a recorded origin; synthesize a minimal one only if needed."""
    for o in ctx.provenance.origins_of(value):
        if o.principal_id == owner:
            return o
    return ValueOrigin(value=value, response_id="", principal_id=owner,
                       endpoint="", field_path="", session_id="", observed_at=0.0)


def differential_authority_attribution(ctx: LawContext) -> AttributionResult:
    """Attribute every privacy-bound value in B's response to the principal whose
    authority MEASURABLY owns it. A value owned by exactly one other principal A,
    that B neither holds nor was legitimately shared, and that no anonymous
    principal legitimately received, is a conservation violation surfaced in B's
    read. Ambiguity -> abstain (RL5)."""
    res = AttributionResult()
    if not ctx.succeeded():
        return res

    acting = ctx.exchange.principal.pid
    env = ctx.acting_envelope()

    for tv in ctx.resp_values():
        if not _privacy_bound(tv, ctx):
            continue
        V = tv.value

        holders = ctx.provenance.legitimate_holders(V)   # measured owners (id/owner)
        seers = ctx.provenance.legitimate_seers(V)        # measured legitimate receivers

        # public — an anonymous principal legitimately received it (laundering-proof:
        # attack responses never enter the legitimate index).
        if any(_is_anon(p) for p in seers):
            res.exonerated_public += 1
            continue

        # self/shared — B legitimately holds it, was legitimately shown it, or its
        # envelope holds it. (This is the exoneration the prototype left as dead
        # code; it is now a live, measured check — no false positive on shared data.)
        try:
            env_holds = env.holds_object(V)
        except Exception:
            env_holds = False
        if acting in holders or acting in seers or env_holds:
            res.exonerated_self += 1
            continue

        # owners: measured holders if any (strongest), else non-anon legitimate
        # seers (covers secrets, which are never 'addressed' so never HELD).
        base = holders if holders else seers
        owners = frozenset(p for p in base if p != acting and not _is_anon(p))

        if len(owners) == 0:
            res.unattributed += 1          # no owner baseline -> abstain (coverage gap)
            continue
        if len(owners) > 1:
            res.exonerated_shared += 1     # legitimately held by several -> common, not private
            continue

        owner = next(iter(owners))
        # coordinate: if the owner held V on a DIFFERENT host than this request, the
        # authority crossed a SERVICE boundary (RL9) — a stronger, distinct finding
        # than a same-service property leak. Measured from host-scoped holds.
        req_host = (getattr(ctx.exchange.request, "host", "") or "").strip().lower()
        owner_hosts = ctx.provenance.legitimate_hold_hosts(V, owner)
        axis = AXIS_PROPERTY
        if owner_hosts and req_host and req_host not in owner_hosts:
            axis = AXIS_SERVICE
        res.leaked.append(LeakedValue(
            value=V, field_path=tv.field_path, value_class=tv.value_class,
            owner=owner, origin=_origin_for(ctx, V, owner), axis=axis,
        ))

    return res


# --------------------------------------------------------------------------- #
# The unifying law (RL19)                                                      #
# --------------------------------------------------------------------------- #

class AuthorityConservationLaw(Law):
    """RL19 — exercised authority must be a subset of conserved authority at the
    PROPERTY coordinate of a READ. Catches field-level cross-principal private
    leaks even when B legitimately addressed the object — the dominant BOLA shape
    the object-id law passes and a mutation verifier cannot see. CANDIDATE only;
    a cross-principal differential confirmer proves it (RL3)."""
    effect = EffectClass.OBJECT_ACCESS
    name = "CONSERVATION: read exposes no other principal's private authority"
    impact = ImpactClass.DATA_EXPOSURE

    def evaluate(self, ctx: LawContext) -> LawVerdict:
        method = (getattr(ctx.exchange.request, "method", "") or "").upper()
        if method not in ("GET", "QUERY", "") and not ctx.exchange.request.is_graphql():
            return self._pass("conservation read-leak law applies to reads only")

        att = differential_authority_attribution(ctx)
        if not att.violates:
            note = ("authority is conserved"
                    if not att.unattributed else
                    f"authority is conserved on measured values; {att.unattributed} "
                    f"value(s) had no owner baseline (coverage gap, not certified clean)")
            return self._pass(note)

        top = att.leaked[0]
        acting = ctx.exchange.principal.pid
        reason = (
            f"read by '{acting}' exposes {len(att.leaked)} value(s) provably owned by "
            f"another principal's private authority — e.g. {top.value_class} at "
            f"'{top.field_path}' is legitimately owned by principal '{top.owner}'; "
            f"authority is NOT conserved at the property coordinate"
        )
        evidence = {
            "conservation_axis": top.axis,
            "object_id": top.value,
            "laundered_from": top.origin,
            "owner_principal": top.owner,
            "leaked_fields": [lv.field_path for lv in att.leaked],
            "leaked_count": len(att.leaked),
            "coverage_gap_values": att.unattributed,
        }
        return self._candidate(reason, evidence)


# --------------------------------------------------------------------------- #
# Unifying reporter                                                            #
# --------------------------------------------------------------------------- #

def coordinate_for(effect: EffectClass) -> str:
    return EFFECT_TO_AXIS.get(effect, AXIS_OBJECT)


def conservation_statement(effect: EffectClass, acting: str, detail: str = "") -> str:
    axis = coordinate_for(effect)
    base = (f"Authority Conservation violated at the {axis} coordinate: "
            f"principal '{acting}' exercised authority outside its conserved set")
    return f"{base} ({detail})" if detail else base


def register(eil) -> None:
    eil.register(AuthorityConservationLaw())
