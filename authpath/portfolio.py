"""
authpath/portfolio.py — portfolio-level expected-value planning + known-CVE dedup (GAP-11).

WHAT THIS IS, AND THE RED LINE IT RESPECTS
==========================================
Another COMPETITIVE lever (to be "faster and deeper than a human hunter"), not a
detection capability. `economy.py` already spends per host; this plans across the WHOLE
portfolio (which asset/program deserves the next budget unit first), and a `DedupIndex`
skips leads that are already a published/known class so no effort is burned on them.

Strictly off the confirmation path (RL2): this changes only WHERE budget goes and WHICH
leads are worth probing. Nothing here makes or confirms a finding. Deterministic, stdlib.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional


# --------------------------------------------------------------------------- #
# Portfolio EV allocation (global, not per-host)                              #
# --------------------------------------------------------------------------- #
@dataclass
class Asset:
    aid: str
    name: str = ""
    est_value: float = 1.0        # expected reward if a confirmable bug is found here
    p_success: float = 0.1        # prior probability a probe yields a confirmable bug
    est_cost: float = 1.0         # budget units to meaningfully probe it
    prior_yield: int = 0          # confirmed findings previously (assets that paid off get priority)


@dataclass
class Allocation:
    asset: Asset
    ev: float
    budget: float


class PortfolioPlanner:
    """Rank and fund assets across the whole surface by expected value per budget unit."""

    def ev(self, a: Asset) -> float:
        p = max(0.0, min(1.0, a.p_success))
        base = a.est_value * p / max(1e-9, a.est_cost)
        return base * (1.0 + 0.15 * max(0, a.prior_yield))

    def allocate(self, assets: Iterable[Asset], budget: float) -> list:
        ranked = sorted(assets, key=lambda a: (-self.ev(a), a.aid))
        allocs, remaining = [], float(budget)
        for a in ranked:
            if remaining <= 0:
                break
            give = min(a.est_cost, remaining)
            allocs.append(Allocation(asset=a, ev=self.ev(a), budget=give))
            remaining -= give
        return allocs


# --------------------------------------------------------------------------- #
# Known-CVE / published-report dedup                                          #
# --------------------------------------------------------------------------- #
_ID_SEG = re.compile(r"^(?:\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{16,})$")


def _normalize_endpoint(endpoint: str) -> str:
    """Collapse id-like path segments to ``{id}`` so /orders/123 and /orders/456 share
    one signature. Cosmetic grouping only — touches no security decision."""
    parts = []
    for seg in str(endpoint).strip("/").split("/"):
        parts.append("{id}" if _ID_SEG.match(seg) else seg)
    return "/" + "/".join(parts)


class DedupIndex:
    """Tag a lead as KNOWN (already a published CVE/report class) vs NOVEL, so budget is
    not spent re-finding a burned class. The corpus is operator-supplied; empty => every
    lead is novel."""

    def __init__(self, known_signatures: Optional[Iterable[str]] = None):
        self._known = set(known_signatures or ())

    @staticmethod
    def signature(effect: str, endpoint: str, param: str = "") -> str:
        return f"{effect}|{_normalize_endpoint(endpoint)}|{param}".lower()

    def add_known(self, effect: str, endpoint: str, param: str = "") -> None:
        self._known.add(self.signature(effect, endpoint, param))

    def is_known(self, effect: str, endpoint: str, param: str = "") -> bool:
        return self.signature(effect, endpoint, param) in self._known

    def filter_novel(self, leads: list) -> list:
        """Keep only leads whose (effect, normalized-endpoint, param) is not already known."""
        out = []
        for l in leads:
            eff = getattr(l, "effect_hint", "OBJECT_ACCESS")
            ep = getattr(l, "endpoint", "")
            pm = getattr(l, "param", "")
            if not self.is_known(eff, ep, pm):
                out.append(l)
        return out
