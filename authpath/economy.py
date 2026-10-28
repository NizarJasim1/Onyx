"""
authpath.economy — the COST model (RL6: BOUNDED ECONOMIC SPENDING).

ONYX's engine is a *correctness* model: it answers "is this exchange a finding?".
It never modelled *cost* — every candidate was confirmed with the same network
spend regardless of its probability of confirming. On a small/clean target the
budget never binds, so this was invisible. On a giant surface it is existential:
spend is O(endpoints x principals x candidates), unbounded, locally issued, with
no global accounting — meaning months of scanning or an IP/reputation ban long
before completion.

This module adds the missing peer layer to the correctness model. It is PURELY
ADDITIVE and FAIL-SAFE: when no budget is configured every primitive below is a
no-op, so the streaming engine behaves byte-for-byte as before (the calibration
is unchanged). It only ENGAGES when a caller opts into a budgeted run.

Three independent slices, each usable alone:

  * BudgetLedger     — Slice 1+4: a global + per-host request budget with a
                       closed-loop reputation governor. The single authority that
                       every network read must acquire from. Exhaustion fails safe
                       to abstain (never a silent skip, never a status-only stamp).
  * yield_score      — Slice 2: a passive, zero-network valuation of a candidate
                       from signals already in hand (field sensitivity, effect
                       severity, provenance laundering, authority gap, structural
                       divergence). Estimates P(confirm) x impact.
  * (allocator)      — Slice 3 lives in the engine's BudgetedScanner, which drains
                       buffered candidates in yield-descending order under the
                       ledger; this module supplies the score and the ledger it
                       spends against.

RL6 invariant (enforced here + in the BudgetedScanner):
  Every network request is drawn from a global budget and allocated in
  value-descending order. No request is spent on a candidate while a
  higher-value candidate is unspent. On exhaustion, unconfirmed candidates
  degrade to honest LEADS. Reputation degradation only ever TIGHTENS the budget.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .models import Candidate, EffectClass


# --------------------------------------------------------------------------- #
# Slice 1+4 — the Budget Ledger (global accountant + reputation governor)      #
# --------------------------------------------------------------------------- #

class SpendDenied(Enum):
    """Why a request was refused — surfaced honestly in the run report so a
    deferred candidate is never confused with a clean verdict."""
    GLOBAL_EXHAUSTED = "global request budget exhausted"
    HOST_EXHAUSTED = "per-host request budget exhausted"
    REPUTATION_FROZEN = "host frozen after repeated challenges/blocks (back-off)"


@dataclass
class HostState:
    spent: int = 0
    budget: int = 0
    consecutive_strikes: int = 0     # blocks/challenges/429s in a row
    frozen: bool = False             # tripped by the reputation governor


@dataclass
class BudgetLedger:
    """The single authority for network spend. Deterministic and event-driven —
    no wall-clock in any decision, so a re-run of the same capture spends
    identically. `acquire()` is the gate every `_read` consults; `record()` feeds
    the reputation governor back into the budget.

    Reputation governor (closed loop, monotone-tightening):
      * each strike (block / auth-expiry / 429) on a host increments its strike
        counter AND debits extra budget (a strike is expensive — it signals the
        path is hostile); `strike_freeze` consecutive strikes FREEZE the host.
      * a clean (substantive) read resets the host's strike counter but never
        refunds budget. Reputation can only ever cost budget, never grant it
        (RL6: degradation tightens, never loosens)."""
    global_budget: int = 0
    per_host_budget: int = 0
    strike_freeze: int = 3           # consecutive strikes that freeze a host
    strike_penalty: int = 5          # extra budget a strike costs (hostile path)

    spent: int = 0
    denials: dict = field(default_factory=dict)   # reason -> count
    hosts: dict = field(default_factory=dict)
    enabled: bool = True

    @classmethod
    def unbounded(cls) -> "BudgetLedger":
        """A ledger that never denies — the DEFAULT for the streaming engine, so
        behaviour is byte-identical to the pre-economy code."""
        led = cls(global_budget=0, per_host_budget=0)
        led.enabled = False
        return led

    def _host(self, host: str) -> HostState:
        h = self.hosts.get(host)
        if h is None:
            h = HostState(budget=self.per_host_budget)
            self.hosts[host] = h
        return h

    def can_spend(self, host: str) -> Optional[SpendDenied]:
        """Return None if a request is allowed, else the reason it is denied.
        Pure inspection — does not consume budget."""
        if not self.enabled:
            return None
        h = self._host(host)
        if h.frozen:
            return SpendDenied.REPUTATION_FROZEN
        if self.global_budget and self.spent >= self.global_budget:
            return SpendDenied.GLOBAL_EXHAUSTED
        if self.per_host_budget and h.spent >= h.budget:
            return SpendDenied.HOST_EXHAUSTED
        return None

    def acquire(self, host: str) -> bool:
        """Atomically charge one request against the global + host budget. Returns
        False (and records the denial) when refused — the caller MUST then abstain
        (fail-safe), never proceed with an unbudgeted send."""
        if not self.enabled:
            return True
        reason = self.can_spend(host)
        if reason is not None:
            self.denials[reason.value] = self.denials.get(reason.value, 0) + 1
            return False
        self.spent += 1
        self._host(host).spent += 1
        return True

    def record(self, host: str, *, struck: bool) -> None:
        """Feed the reputation governor. `struck` is True when the response was a
        block/challenge/auth-expiry (detect_block/detect_auth_expiry). Strikes
        cost extra budget and, when they pile up, freeze the host."""
        if not self.enabled:
            return
        h = self._host(host)
        if struck:
            h.consecutive_strikes += 1
            # debit extra budget — a hostile path is expensive to keep probing
            self.spent += self.strike_penalty
            h.spent += self.strike_penalty
            if h.consecutive_strikes >= self.strike_freeze:
                h.frozen = True
        else:
            h.consecutive_strikes = 0

    # -- reporting ---------------------------------------------------------- #
    def summary(self) -> dict:
        return {
            "enabled": self.enabled,
            "global_budget": self.global_budget,
            "spent": self.spent,
            "remaining": (self.global_budget - self.spent) if self.global_budget else None,
            "denials": dict(self.denials),
            "frozen_hosts": sorted(h for h, s in self.hosts.items() if s.frozen),
            "per_host": {h: {"spent": s.spent, "budget": s.budget,
                             "strikes": s.consecutive_strikes, "frozen": s.frozen}
                         for h, s in self.hosts.items()},
        }


# --------------------------------------------------------------------------- #
# Slice 2 — the Yield Estimator (passive, zero-network valuation)              #
# --------------------------------------------------------------------------- #

# Base value per effect class: how much a CONFIRMED finding of this class is worth
# x how likely a candidate of this class is to confirm. Deterministic priors,
# not learned — a closed table that goes through review (same discipline as the
# EIL law set and the SENSITIVE_FIELDS dict).
_EFFECT_VALUE = {
    EffectClass.OBJECT_ACCESS: 1.00,   # IDOR/BOLA — the canonical high-value class
    EffectClass.AUTHORITY: 1.00,       # BFLA — function-level authz failure
    EffectClass.OWNERSHIP: 0.95,       # mass-assignment privilege escalation
    EffectClass.PAYMENT: 0.90,         # financial integrity
    EffectClass.PRICE: 0.85,
    EffectClass.STATE_GATE: 0.70,      # workflow bypass
    EffectClass.COUPON: 0.60,
    EffectClass.INVENTORY: 0.55,
}


def _effect_value(effect) -> float:
    try:
        return _EFFECT_VALUE.get(effect, 0.50)
    except Exception:
        return 0.50


def yield_score(cand: Candidate) -> float:
    """Passive priority in [0, ~3]. Computed entirely from signals already in the
    captured candidate — ZERO network cost — so it can rank thousands of
    candidates before a single request is spent. Higher = confirm first.

    The score is an explainable sum of independent, capped signals (no opaque
    weighting, no learning):
      base       — effect-class value/confirm-likelihood prior
      sensitive  — count of sensitive fields visible in the response (capped)
      laundered  — provenance shows the id/value crossed from another step/principal
      anon       — an anonymous/under-privileged actor obtained data (authority gap)
      structural — the structural/projection channel already diverged (strong prior)
    """
    score = _effect_value(cand.verdict.effect)
    ev = cand.verdict.evidence or {}

    # field sensitivity — reuse the confirmer's closed sensitive vocabulary
    try:
        from .confirmer import _is_sensitive_key
        body = (cand.exchange.response.body or {})
        sens_hits = _count_sensitive(body, _is_sensitive_key)
        score += min(sens_hits, 4) * 0.25            # up to +1.0
    except Exception:
        pass

    # provenance laundering — the value/id did not originate with this actor
    if cand.causal_origin or ev.get("laundered_from"):
        score += 0.5

    # authority gap — an anonymous or clearly under-privileged actor holds data
    try:
        if cand.exchange.principal.is_anonymous:
            score += 0.5
    except Exception:
        pass

    # structural prior — divergence/over-projection already observed passively
    if cand.verdict.effect in (EffectClass.OBJECT_ACCESS,) and ev.get("object_id"):
        score += 0.25
    if ev.get("diverging_paths") or ev.get("fp_present_paths"):
        score += 0.5

    return round(score, 4)


def _count_sensitive(node, is_sensitive, depth: int = 0) -> int:
    """Count distinct sensitive field names present anywhere in a JSON body.
    Bounded depth so a pathological body cannot blow up the (free) estimator."""
    if depth > 6:
        return 0
    found = 0
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str) and is_sensitive(k):
                found += 1
            found += _count_sensitive(v, is_sensitive, depth + 1)
    elif isinstance(node, list):
        for v in node[:50]:
            found += _count_sensitive(v, is_sensitive, depth + 1)
    return found
