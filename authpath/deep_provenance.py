"""
⑳ Deep async provenance (Gap G8) — stored-ID-abused-later, pure logic.

An ID captured/planted at step 1 is abused at step N across a long async/session gap.
A provenance ledger links an early planted value to its later appearance ANYWHERE,
by exact nonce only (G14). This also realises the ISOLATION strategy left pending in
G14: a freshly-minted nonce whose later appearance is attributable by exclusion.

FP gate: DP-0 every link tagged by a unique nonce; DP-1 no causal link without an
exact nonce match; DP-2 the final effect still requires a cross-principal read-back
(attribution != authorization); DP-3 default-OFF.
"""
from __future__ import annotations
from typing import Optional


class ProvenanceLedger:
    """Links an early planted value to its later appearance across any async/session
    boundary, by exact nonce only."""

    def __init__(self, authority):
        self._authority = authority
        self._chain = []      # list of (step_label, Nonce)

    def plant(self, step: str, purpose: str):
        n = self._authority.mint(f"{purpose}@{step}")
        self._chain.append((step, n))
        return n

    def trace(self, later_payload, later_step: str) -> Optional[tuple]:
        """Return (nonce, early_step, later_step) for the first planted link that
        appears exactly in later_payload — a causal proof — else None (DP-1)."""
        for step, n in self._chain:
            if n.appears_in(later_payload):
                return (n, step, later_step)
        return None

    def confirm_second_order(self, later_payload, later_step: str,
                             cross_principal_ok: bool) -> Optional[tuple]:
        """A confirmed second-order chain requires both an exact-nonce causal link
        AND a proven cross-principal read-back (DP-2)."""
        hit = self.trace(later_payload, later_step)
        if hit is None:
            return None                     # DP-1: no causal link
        if not cross_principal_ok:
            return None                     # DP-2: attribution != authorization
        return hit
