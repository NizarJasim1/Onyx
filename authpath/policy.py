"""
Policy hypothesis (deficiency #1 — the oracle problem). Full model.
================================================================================
Real authorization policy lives OUT-OF-BAND (tenant membership, server-side ACLs, RBAC
inheritance, delegation, sharing links); a black-box observer cannot see it. ONYX must
NOT infer it (probabilistic -> breaks zero-FP; self-judging -> circular). Instead it
consumes an EXPLICIT hypothesis from the operator and emits every finding as a **breach
relative to a declared invariant**, abstaining where nothing is declared.

This module closes the full set of gaps, not just the first:

  * PRINCIPAL domains (declared, small, human): principal_id -> domain (tenant/org).
  * RESOURCE domains (ESTABLISHED mechanically, not hand-fed): during the legitimate
    provisioning walk each tenant's own principals read their OWN resources; a resource
    unambiguously reached by exactly one domain is assigned that domain. This resolves
    ownership even when the owner's identity never appears in any body (server-side
    binding) — the #1/#7 residue. Ambiguous resources (reached by >1 domain during
    observe) are treated as shared -> never a breach (zero-FP preserved).
  * A declared GRANT GRAPH (RBAC / group nesting / delegation): directed edges between
    domains/principals. An access is permitted if the actor's domain can REACH the
    resource's domain through declared edges (transitive closure). A breach is an access
    NOT reachable through any declared grant-path.

The module makes no authorization decision on its own: it answers, for a concrete access,
FORBIDDEN / PERMITTED / UNCOVERED, strictly from declared + observed-legitimate data.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

PERMITTED = "permitted"
FORBIDDEN = "forbidden"
UNCOVERED = "uncovered"


@dataclass
class PolicyHypothesis:
    principal_domain: dict = field(default_factory=dict)     # principal_id -> domain (declared)
    isolated: bool = False                                   # domains are isolated by default?
    grant_edges: frozenset = field(default_factory=frozenset)  # directed (domain_a, domain_b): a may reach b
    explicit_grants: dict = field(default_factory=dict)      # owner/resource -> {principal_id,...}
    name: str = "isolation"

    # established mechanically from the legitimate provisioning walk (not declared):
    _resource_domain: dict = field(default_factory=dict)     # resource_id -> domain (unambiguous)
    _resource_seen: dict = field(default_factory=dict)       # resource_id -> set(domains) seen legit

    def declared(self) -> bool:
        return bool(self.principal_domain or self.explicit_grants)

    # ---- establishment (called by the engine during OBSERVE only) -------------------
    def observe_owner(self, principal_id: str, resource_id: str) -> None:
        """Record that `principal_id` legitimately reached `resource_id` as its own during
        the provisioning walk. A resource reached by exactly one domain is assigned it;
        one reached by several domains is ambiguous (shared) and never yields a breach."""
        dom = self.principal_domain.get(str(principal_id))
        if dom is None:
            return
        seen = self._resource_seen.setdefault(str(resource_id), set())
        seen.add(dom)
        if len(seen) == 1:
            self._resource_domain[str(resource_id)] = dom
        else:
            self._resource_domain.pop(str(resource_id), None)   # ambiguous -> unassigned

    def resource_domain(self, resource_id: str) -> Optional[str]:
        return self._resource_domain.get(str(resource_id))

    # ---- grant-graph reachability (RBAC / delegation / group nesting) ----------------
    def _reaches(self, src: str, dst: str) -> bool:
        if src == dst:
            return True
        adj = {}
        for a, b in self.grant_edges:
            adj.setdefault(a, set()).add(b)
        seen, stack = set(), [src]
        while stack:
            n = stack.pop()
            if n == dst:
                return True
            if n in seen:
                continue
            seen.add(n)
            stack.extend(adj.get(n, ()))
        return False

    # ---- classification --------------------------------------------------------------
    def classify_access(self, actor: str, owner: Optional[str], resource_id: str = "") -> str:
        """FORBIDDEN / PERMITTED / UNCOVERED for a concrete access. Prefers the resource's
        ESTABLISHED domain (owner-identity-independent); falls back to the owner principal's
        declared domain when the resource domain is unknown."""
        a = str(actor)
        # declared per-resource / per-owner sharing links win outright
        for key in (str(resource_id), str(owner) if owner else None):
            if key and a in self.explicit_grants.get(key, ()):
                return PERMITTED
        actor_dom = self.principal_domain.get(a)
        res_dom = self.resource_domain(resource_id)
        if res_dom is None and owner is not None:
            res_dom = self.principal_domain.get(str(owner))
        if actor_dom is None or res_dom is None:
            return UNCOVERED
        if actor_dom == res_dom:
            return PERMITTED
        if self._reaches(actor_dom, res_dom):
            return PERMITTED                    # declared grant-path (delegation/nesting)
        return FORBIDDEN if self.isolated or self.grant_edges or True else UNCOVERED

    def breach_reason(self, actor: str, owner: Optional[str], resource_id: str = "") -> Optional[str]:
        if self.classify_access(actor, owner, resource_id) != FORBIDDEN:
            return None
        a = str(actor)
        ad = self.principal_domain.get(a)
        rd = self.resource_domain(resource_id) or (self.principal_domain.get(str(owner)) if owner else None)
        return (f"breach of declared isolation invariant '{self.name}': actor '{a}' "
                f"(domain {ad}) reached resource '{resource_id}' owned in domain {rd} "
                f"with no declared grant-path")


# convenience for tests / callers building a simple flat multi-tenant hypothesis
@dataclass(frozen=True)
class IsolationInvariant:
    name: str
    principal_domain: dict
    allowed_crossings: frozenset = field(default_factory=frozenset)

    def to_hypothesis(self, explicit_grants=None) -> "PolicyHypothesis":
        return PolicyHypothesis(principal_domain=dict(self.principal_domain), isolated=True,
                                grant_edges=frozenset(self.allowed_crossings),
                                explicit_grants=dict(explicit_grants or {}), name=self.name)
