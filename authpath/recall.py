"""
authpath/recall.py — high-recall candidate generation & ranking (GAP-6).

WHAT THIS IS, AND THE RED LINE IT RESPECTS
==========================================
This is a COMPETITIVE lever, not a detection capability: it decides WHICH leads to probe
and in WHAT ORDER so ONYX does not miss a high-probability bug inside a finite budget
(recall), and spends the first probes where bugs cluster. It is strictly on the
GENERATION/RANKING path, NEVER the decision path:

    RL2 — no model in the confirmation path. An external (even offline-LLM) scorer MAY
          influence the ORDER of probing here; it can NEVER make or confirm a finding.
          Every lead this module emits still goes through the deterministic Δstate /
          Oracle-Registry confirmation unchanged. So recall rises while precision is
          untouched — exactly the split the gap analysis prescribed (#6).

Pure stdlib, deterministic by default. The optional ``external_scorer`` is bounded so it
re-orders but never dominates, and any exception from it is ignored (fail-safe).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class CandidateLead:
    endpoint: str
    method: str = "GET"
    param: str = ""                       # the param/field that likely references a protected object
    effect_hint: str = "OBJECT_ACCESS"    # routed later by the real classifier; here only a prior
    tier: str = "referenced"              # observed|spec|referenced|lineage|js (how grounded the lead is)
    signals: dict = field(default_factory=dict)
    score: float = 0.0


# How grounded the lead is: something the target actually emitted outranks a guess.
_TIER_WEIGHT = {"observed": 1.0, "spec": 0.8, "referenced": 0.6, "lineage": 0.5, "js": 0.4}

# Effect-class prior: probe the higher-impact / higher-base-rate classes sooner. Pure
# ordering heuristic — it changes nothing about how a finding is confirmed.
_EFFECT_PRIOR = {
    "OBJECT_ACCESS": 1.0, "OWNERSHIP": 1.1, "FIELD_PROJECTION": 1.05,
    "AUTHORITY": 1.2, "AUTHORITY_GRANT": 1.3, "PAYMENT": 1.2, "PRICE": 1.1,
    "STATE_GATE": 1.1, "INVENTORY": 1.0, "COUPON": 1.0, "TEMPORAL_DRIFT": 1.1,
    "CROSS_SURFACE": 1.15, "AUTH_REGRESSION": 1.1, "EMERGENT_BREAK": 1.15,
    "IDENTITY_SPOOF": 1.4, "CROSS_TENANT": 1.4, "PARSER_DIFFERENTIAL": 1.25,
    "REBAC_BYPASS": 1.2, "CONSISTENCY_WINDOW": 1.15, "GRAPHQL_FIELD_AUTHZ": 1.2,
}


class RecallPlanner:
    """Generates cross-principal probe leads from observed references and ranks them so
    the finite probe budget is spent on the highest-probability objects first."""

    def __init__(self, external_scorer: Optional[Callable[[CandidateLead], float]] = None,
                 family_confirmations: Optional[dict] = None):
        # external_scorer: OPTIONAL offline callable(lead)->[0,1]. Ranking ONLY. Never in
        # the confirmation path. None => pure deterministic ranking.
        self.external_scorer = external_scorer
        # effect/family -> prior confirmed-hit count; bugs cluster, so a family that has
        # already paid off is probed sooner (recall), never confirmed differently.
        self.family_confirmations = family_confirmations or {}

    def score(self, lead: CandidateLead) -> float:
        s = _TIER_WEIGHT.get(lead.tier, 0.5)
        s *= _EFFECT_PRIOR.get(lead.effect_hint, 1.0)
        if lead.signals.get("id_bearing"):
            s *= 1.5
        if lead.signals.get("ownership_pointer_hit"):
            s *= 1.6
        if lead.signals.get("cross_principal_swappable"):
            s *= 1.4
        s *= (1.0 + 0.1 * float(self.family_confirmations.get(lead.effect_hint, 0)))
        if self.external_scorer is not None:
            try:
                ext = float(self.external_scorer(lead))
                ext = max(0.0, min(1.0, ext))
                s *= (0.5 + ext)                  # bounded [0.5, 1.5]: re-orders, never dominates
            except Exception:
                pass                              # fail-safe: a bad scorer cannot break ranking
        return s

    def rank(self, leads: list) -> list:
        for l in leads:
            l.score = self.score(l)
        return sorted(leads, key=lambda l: (-l.score, l.endpoint, l.param))

    def generate(self, observed_refs: list) -> list:
        """Turn observed id-bearing references into ranked cross-principal probe leads.
        ``observed_refs`` is a list of dicts the discovery/observation layer produced."""
        out = []
        for r in observed_refs:
            out.append(CandidateLead(
                endpoint=r.get("endpoint", ""), method=r.get("method", "GET"),
                param=r.get("param", ""), effect_hint=r.get("effect_hint", "OBJECT_ACCESS"),
                tier=r.get("tier", "referenced"),
                signals={k: r[k] for k in
                         ("id_bearing", "ownership_pointer_hit", "cross_principal_swappable")
                         if k in r}))
        return self.rank(out)
