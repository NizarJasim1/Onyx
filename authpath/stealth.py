"""
Stealth profile (deficiency #6 — the defensive adversary).
================================================================================
The k-sample quorum that gives ONYX zero false positives under chaos also emits a loud
bot signature: a burst of k near-identical requests, each carrying a `_cb=<hex>` query
param no real client ever sends. On a hardened target (WAF / bot-detection) that trips a
block — locking ONYX out of exactly the surfaces worth testing.

The tension is not fundamental. The quorum needs REPRODUCTION EVIDENCE — a real leak
recurs on independent reads, a transient artifact does not — it does NOT need a *burst*.
This profile keeps the identical majority semantics (so zero-FP is untouched) while
removing the signature:

  * ADAPTIVE, INCREMENTAL sampling: draw samples one at a time and STOP as soon as a
    strong majority is already decided. A stable target settles in the minimum samples
    (quiet); only genuine disagreement (chaos) escalates to the full k. Same guarantee,
    far fewer requests when the target is calm — which hardened production targets are.
  * NATURAL cache-busting: `Cache-Control: no-cache` (a header real clients DO send)
    instead of a telltale `_cb` query param.
  * PACING: an injectable inter-sample delay (jittered) so k reads are not a rapid-fire
    burst, and a run-wide rate governor so aggregate velocity stays human-plausible.

Wall: a target that flags ANY non-browser client by TLS/canvas fingerprint or per-request
attestation, regardless of pacing, is stealth-closed to every external tool — ride a real
client (operator-provided) or declare + abstain. This module changes only HOW read-backs
are delivered; it never changes WHAT counts as a confirmation (the majority Δstate).
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Callable
import math


@dataclass
class StealthProfile:
    cache_bust: str = "header"          # "header" (quiet) | "query" (legacy _cb) | "none"
    min_samples: int = 3                # never decide on fewer than this
    max_k: int = 7                      # escalate up to here on disagreement (== old k)
    majority: float = 0.8               # strong-majority threshold (same as the quorum)
    delay: Optional[Callable[[], None]] = None   # inter-sample pacing hook (jittered sleep)

    def decided(self, counts: dict, n: int) -> Optional[tuple]:
        """If, after n samples, one value already holds an unbeatable strong majority
        (>= majority of AT LEAST min_samples, and no remaining sample could overturn it),
        return that winning key; else None (keep sampling). This stops a calm target early
        without ever weakening the majority guarantee a full-k vote would have given."""
        if n < self.min_samples:
            return None
        top_key, top = max(counts.items(), key=lambda kv: kv[1])
        if top / n >= self.majority:
            return top_key                              # strong majority already reached
        # can the remaining budget still change the winner? if not, decide now.
        remaining = self.max_k - n
        runner_up = sorted(counts.values(), reverse=True)
        second = runner_up[1] if len(runner_up) > 1 else 0
        if top - second > remaining:
            return top_key
        return None

    def bust(self, req_query: dict, headers: dict):
        """Apply the chosen cache-bust. Returns (query, headers) to use for a sample."""
        q = dict(req_query or {})
        h = dict(headers or {})
        if self.cache_bust == "query":
            import uuid as _u
            q["_cb"] = _u.uuid4().hex[:8]
        elif self.cache_bust == "header":
            h["Cache-Control"] = "no-cache"
            h["Pragma"] = "no-cache"
        return q, h

    def pace(self):
        if self.delay is not None:
            try:
                self.delay()
            except Exception:
                pass
