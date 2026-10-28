"""
authpath.global_invariants — GLOBAL INVARIANT ENGINE (RL18, the 4th dimension).

THE SHIFT THIS MODULE ENCODES
-----------------------------
RL15/16/17 all ask "is THIS state broken?" — across doors, across time, across the
family. They share the field's deepest assumption: a vulnerability is a property of
a STATE. But the surviving class on a hyperscale target is EMERGENT: a sequence of
individually-permitted operations that accumulates into a state no single operation
would ever have granted. Every step preserves its own local rule; the SEQUENCE
breaks a GLOBAL invariant that no single step owns or checks.

Canonical example (the parent/child ownership invariant):
  1. principal X owns folder F and reads doc D inside it        — permitted
  2. F's ownership is transferred away from X                    — permitted
  → D should have followed F. If X can still read D while F is now forbidden to X,
    the authority transfer did not propagate to the child. No single operation
    broke a rule; the global invariant "a child's authority follows its parent's"
    was broken by the COMPOSITION. A per-request scanner and an atomically-thinking
    researcher are both structurally blind to it.

This engine is the 4th dimension above boundary (RL15), time (RL16) and family
(RL17): the SEQUENCE.

AEGIS DISCIPLINE — this is the only engine whose subject is multi-operation, so it
is the most dangerous, and is held to the strictest bar:
  * Execution level 1 (read-only): the engine OBSERVES the sequence in legitimate
    traffic — it NEVER generates the transfer. Confirmation is a read-only read-back
    only. No state is written, so no state can be damaged (AEGIS gate 3).
  * Invariant soundness (gate 2): the parent→child link is DECLARED (the contract's
    resource_parents map / the path hierarchy), never inferred statistically (RL1).
  * Δstate (gate 4): a break is a finding only when a live read-back proves the
    child is accessible to X while the parent is forbidden to X — and the child
    declares NO independent grant to X (the refutation that defuses legitimately
    shared children).
  * Additive & flag-gated: disabled by default ⇒ never consulted ⇒ byte-identical.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AccessObservation:
    """The most recent observed access outcome of one principal to one resource."""
    accessible: bool           # last observed 2xx (True) vs 4xx-forbidden (False)
    seq: int                   # observation order (the time axis of the sequence)


@dataclass
class EmergentBreak:
    """A child whose authority did not follow its parent across a transfer."""
    child: str                 # child ResourceIdentity string ("type:id")
    parent: str                # parent ResourceIdentity string
    principal: str


class InvariantLedger:
    """Records, per principal, the observed access outcome to each resource over the
    sequence, and detects the parent/child authority-propagation break. The parent
    map is DECLARED (resource_parents); the engine never invents a parent link."""

    def __init__(self, parent_map: Optional[dict] = None) -> None:
        # parent_map: child-identity-string -> parent-identity-string (declared)
        self._parent = dict(parent_map or {})
        # (principal, identity-string) -> AccessObservation
        self._access: dict = {}
        self._seq = 0

    @staticmethod
    def _ident(request) -> Optional[str]:
        from .surface_map import identify
        ri = identify(request)
        return str(ri) if ri is not None else None

    def observe(self, request, response, principal_id: str) -> None:
        """Record this principal's access outcome to the addressed resource."""
        ident = self._ident(request)
        if ident is None:
            return
        self._seq += 1
        status = getattr(response, "status", 0)
        accessible = 200 <= status < 300
        forbidden = status in (401, 403)
        if not (accessible or forbidden):
            return  # 404 / 5xx etc. carry no authority signal
        self._access[(principal_id, ident)] = AccessObservation(accessible, self._seq)

    def parent_of(self, child_ident: str) -> Optional[str]:
        return self._parent.get(child_ident)

    def break_for(self, request, response, principal_id: str) -> Optional[EmergentBreak]:
        """Detect an emergent parent/child break for the CURRENT exchange: the
        principal is successfully accessing a child whose DECLARED parent it has been
        observed to be FORBIDDEN. Returns the break to be Δstate-confirmed, or None.

        Fail-safe: requires (a) a declared parent link, (b) a successful child access
        now, and (c) a prior observed FORBIDDEN on the parent for this principal. If
        the parent was never observed forbidden, there is no sequence to break — abstain."""
        child = self._ident(request)
        if child is None:
            return None
        status = getattr(response, "status", 0)
        if not (200 <= status < 300):
            return None                      # child not accessible now → nothing to break
        parent = self._parent.get(child)
        if parent is None:
            return None                      # no declared parent → no invariant here
        pobs = self._access.get((principal_id, parent))
        if pobs is None or pobs.accessible:
            return None                      # parent not observed forbidden → no break
        return EmergentBreak(child=child, parent=parent, principal=principal_id)
