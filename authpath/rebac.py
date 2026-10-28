"""
authpath/rebac.py — relationship-based authorization oracles (GAP-7 + GAP-10).

ONE SEAM, TWO SIDES
===================
The giants moved to relationship-based access control (Zanzibar / Cedar / OPA):
access is DERIVED from a graph — member of a group, the group owns a folder, the
folder contains the document. ONYX had direct ownership and explicit grants, but not
the derived, transitive layer. That same graph has two failure modes, two sides of
one boundary:

    GAP-7  — the graph's STRUCTURE: access that no relationship path justifies.
    GAP-10 — the graph in TIME: a relationship revoked at T still grants access until
             the cache propagates (zookie / snapshot staleness — the "new enemy").

RL1 — OBSERVED EDGES ONLY, NEVER A REBUILT POLICY
=================================================
The red-team objection the gap analysis anticipated: "reconstructing the policy is
inference, it breaks RL1." We do NOT reconstruct policy. ``RelationGraph`` is built
only from relationship edges the target DISCLOSED (memberships, ownership, containment
read off the wire — the ``ownership_pointer`` discipline), and we compute the
transitive closure of THOSE edges only. An observed path => legitimate (so we never
flag legitimate derived access — the main FP pressure). Access with NO observed path,
Δstate-confirmed to belong to another principal => the breach.

Both oracles register through the Oracle Registry (GAP-5) and inherit its structural
zero-FP guard.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .models import Candidate, EffectClass, StateProof
from .oracle_registry import Oracle, OracleVerdict, VerdictKind


# --------------------------------------------------------------------------- #
# RL1 — transitive closure over OBSERVED declared edges only                  #
# --------------------------------------------------------------------------- #
class RelationGraph:
    """Directed reachability over edges the target disclosed. ``add_edge(a, b)`` means
    "a can reach b" after relation semantics are normalised (member->group,
    group->folder, folder->doc all become reach edges). Nothing is assumed."""

    def __init__(self):
        self._adj: dict = {}

    def add_edge(self, a, b) -> None:
        self._adj.setdefault(a, set()).add(b)

    def reaches(self, src, dst) -> bool:
        if src == dst:
            return True
        seen, stack = {src}, [src]
        while stack:
            node = stack.pop()
            for nxt in self._adj.get(node, ()):  # transitive closure (DFS, cycle-safe)
                if nxt == dst:
                    return True
                if nxt not in seen:
                    seen.add(nxt); stack.append(nxt)
        return False


# --------------------------------------------------------------------------- #
# GAP-7 — the relationship graph's STRUCTURE                                  #
# --------------------------------------------------------------------------- #
@dataclass
class ReBACProbe:
    """One derived-access lead. ``observed_edges`` are relationship edges read off the
    wire (RL1). ``delta_owner_differs`` is the normal Δstate read-back result: the
    object was independently confirmed to belong to a DIFFERENT principal."""
    principal_pid: str
    object_ref: str
    observed_edges: list                     # list[(a, b)] disclosed reach edges
    delta_owner_differs: bool
    victim_pid: str = ""


class ReBACOracle(Oracle):
    """Confirms a transitive-authz bypass ONLY when there is NO observed relationship
    path from the principal to the object AND Δstate proved the object belongs to
    another principal. A legitimate derived access (a path exists) ABSTAINS — that is
    the FP suppression the ReBAC model exists for."""
    name = "rebac-path"
    effects = frozenset({EffectClass.REBAC_BYPASS})

    def confirm(self, cand: Candidate, ctx: Optional[dict] = None) -> OracleVerdict:
        probe = (ctx or {}).get("rebac_probe")
        if probe is None:
            ev = getattr(getattr(cand, "verdict", None), "evidence", None) or {}
            probe = ev.get("rebac_probe")
        if probe is None:
            return OracleVerdict(kind=VerdictKind.ABSTAIN, effect=EffectClass.REBAC_BYPASS,
                                 oracle_name=self.name, reason="no rebac probe attached")

        g = RelationGraph()
        for edge in (probe.observed_edges or []):
            try:
                a, b = edge
            except (TypeError, ValueError):
                continue
            g.add_edge(a, b)
        has_path = g.reaches(probe.principal_pid, probe.object_ref)

        if has_path:
            return OracleVerdict(
                kind=VerdictKind.ABSTAIN, effect=EffectClass.REBAC_BYPASS, oracle_name=self.name,
                reason="legitimate derived access — an observed relationship path exists (no finding)")

        owned_both = (probe.principal_pid != probe.victim_pid
                      and bool(probe.principal_pid) and bool(probe.victim_pid))
        if probe.delta_owner_differs and owned_both:
            proof = StateProof(
                confirmed=True,
                method=(f"principal {probe.principal_pid} reached {probe.object_ref} with NO "
                        f"relationship path in the observed graph; Δstate read-back shows it "
                        f"belongs to {probe.victim_pid}"),
                before=f"no observed edge path {probe.principal_pid} -> {probe.object_ref}",
                after=f"access granted; true owner {probe.victim_pid}",
                read_as=probe.victim_pid,
                detail="relationship-based authorization bypass (transitive, unbacked access)",
            )
            return OracleVerdict(
                kind=VerdictKind.CONFIRMED, effect=EffectClass.REBAC_BYPASS, oracle_name=self.name,
                proof=proof, reason="derived access with no observed relationship path",
                observed_out_of_band=True,
                expected_value_known_in_advance=True,
                boundary_owned_both_sides=owned_both)

        return OracleVerdict(
            kind=VerdictKind.ABSTAIN, effect=EffectClass.REBAC_BYPASS, oracle_name=self.name,
            reason="no path, but object ownership not Δstate-confirmed to differ (no finding)")


# --------------------------------------------------------------------------- #
# GAP-10 — the relationship graph in TIME (consistency window / new enemy)    #
# --------------------------------------------------------------------------- #
@dataclass
class ConsistencyWindowProbe:
    """A just-revoked relationship. ``subject_pid`` and ``relation_source`` are the two
    tester-owned endpoints of the edge that was removed (e.g. a user removed from a
    group). ``access_after_revocation_fn() -> bool`` is an INDEPENDENT read performed
    AFTER the revocation: True iff access/derivation still works. The correct state
    after a revocation is DENY — known in advance."""
    subject_pid: str
    relation_source: str
    object_ref: str
    access_after_revocation_fn: Callable[[], bool]


class ConsistencyWindowOracle(Oracle):
    """Confirms a stale-relationship decision: an edge was revoked (both endpoints
    tester-owned) yet an out-of-band post-revocation read still shows access. If the
    revocation is enforced immediately, the oracle ABSTAINS — the zero-FP control."""
    name = "consistency-window"
    effects = frozenset({EffectClass.CONSISTENCY_WINDOW})

    def confirm(self, cand: Candidate, ctx: Optional[dict] = None) -> OracleVerdict:
        probe = (ctx or {}).get("window_probe")
        if probe is None:
            ev = getattr(getattr(cand, "verdict", None), "evidence", None) or {}
            probe = ev.get("window_probe")
        if probe is None:
            return OracleVerdict(kind=VerdictKind.ABSTAIN, effect=EffectClass.CONSISTENCY_WINDOW,
                                 oracle_name=self.name, reason="no window probe attached")

        owned_both = (probe.subject_pid != probe.relation_source
                      and bool(probe.subject_pid) and bool(probe.relation_source))

        try:
            still_allowed = bool(probe.access_after_revocation_fn())
        except Exception as e:
            return OracleVerdict(kind=VerdictKind.ABSTAIN, effect=EffectClass.CONSISTENCY_WINDOW,
                                 oracle_name=self.name, reason=f"post-revocation read failed: {e!r}")

        if still_allowed and owned_both:
            proof = StateProof(
                confirmed=True,
                method=(f"relationship {probe.relation_source} -> {probe.subject_pid} was "
                        f"revoked, yet an out-of-band read still grants access to "
                        f"{probe.object_ref}"),
                before="relationship revoked (expected: access DENIED)",
                after="access still granted (stale decision within the window)",
                read_as=probe.subject_pid,
                detail="consistency-window / new-enemy: authz decision rode a stale relationship snapshot",
            )
            return OracleVerdict(
                kind=VerdictKind.CONFIRMED, effect=EffectClass.CONSISTENCY_WINDOW, oracle_name=self.name,
                proof=proof, reason="revoked relationship still grants access out-of-band",
                observed_out_of_band=True,
                expected_value_known_in_advance=True,     # correct post-revocation state (DENY) is known
                boundary_owned_both_sides=owned_both)

        return OracleVerdict(
            kind=VerdictKind.ABSTAIN, effect=EffectClass.CONSISTENCY_WINDOW, oracle_name=self.name,
            reason="revocation enforced — access denied after revoke (no window bug, no finding)")
