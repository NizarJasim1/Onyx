"""
THE ANVIL — a reality layer that wraps the live world and injects production chaos,
tuned HARDER than reality, to try to break ONYX and, above all, to try to make it
FABRICATE false positives from noise. If ONYX's zero-FP core survives the anvil, it
is iron.

Every vector here attacks ONYX's one load-bearing assumption: that a read-back is a
faithful, immediate, deterministic observation of true server state. Reality (and
this anvil, harder) violates all three:

  * REPLICA LAG / STALE READS — reads are routed to one of K replicas that converge
    to the primary only after a per-key lag. A read-back right after a write may see
    OLD state (-> false negative), and two identical reads may DIFFER by replica skew
    (-> phantom Δstate -> false positive).
  * SHARED CACHE — a GET may be served a cached body keyed by PATH ONLY (ignoring the
    caller), so principal B is handed principal A's cached response. This looks
    exactly like a cross-principal leak (-> the crown-jewel-killing false positive).
  * RETRIES / DUPLICATES — a mutation may be applied twice (client/proxy retry with no
    idempotency), corrupting the Δstate ONYX reasons over ("phantom writes").
  * ASYNC 202 — a mutation may return 202 and apply its effect only LATER, after a lag
    (-> the immediate read-back misses it -> false negative).
  * RATE-LIMIT / WAF — after a burst, requests get 429 / a block body instead of the
    real response (-> ONYX misreads "denied").
  * TIMEOUT / PARTIAL FAILURE — a request may return a transport failure sentinel.
  * REORDER JITTER — each response carries a random logical delay; the read-back lands
    at a random point on the convergence timeline.

Intensity in [0,1] scales every vector. At 0.0 the layer is transparent (equals the
clean world). The harness sweeps intensity and measures precision/recall degradation.
This module imports NO authpath (isolation preserved).
"""
from __future__ import annotations

import copy
import random


TIMEOUT = ("__TIMEOUT__", None)   # sentinel returned as (599, {...}) to ONYX


class RealityLayer:
    def __init__(self, world, intensity: float = 0.5, seed: int = 0, replicas: int = 3):
        self.world = world
        self.k = max(1, replicas)
        self.intensity = max(0.0, min(1.0, intensity))
        self.rng = random.Random(seed * 7919 + 13)
        self.tick = 0
        # convergence queue: list of (apply_at_tick, callable) pending propagations
        self._pending = []
        # shared path-keyed cache: path -> (body, status)
        self._cache = {}
        # rate-limit token bucket
        self._budget = 1000
        self._rl_until = -1
        # per-(method,path,principal) memo of the "primary" answer at each tick, to
        # model replica lag we keep a short history of primary snapshots per key.
        self._history = {}

    # ---- helpers ----------------------------------------------------------- #
    def _p(self, base):
        """probability of a vector firing at current intensity."""
        return base * self.intensity

    def _advance(self):
        self.tick += 1
        due = [c for (t, c) in self._pending if t <= self.tick]
        self._pending = [(t, c) for (t, c) in self._pending if t > self.tick]
        for c in due:
            c()

    # ---- the wrapped handler ---------------------------------------------- #
    def handle(self, method, path, principal, query, body):
        self._advance()
        qkey = str(sorted((query or {}).items()))
        ckey = (path, qkey)   # realistic caches vary by full URL (path + query)

        # RATE-LIMIT / WAF: during a throttle window, real response is replaced.
        if self.tick < self._rl_until:
            return 429, {"error": "rate limited", "retry_after": 1}
        self._budget -= 1
        if self._budget <= 0 and self.rng.random() < self._p(0.9):
            self._rl_until = self.tick + self.rng.randint(1, 4)
            self._budget = self.rng.randint(20, 60)
            return 429, {"error": "rate limited"}

        # TIMEOUT / PARTIAL FAILURE
        if self.rng.random() < self._p(0.10):
            return 599, {"error": "upstream timeout"}
        if self.rng.random() < self._p(0.05):
            return 503, {"error": "service unavailable"}

        is_write = method in ("PUT", "POST", "PATCH", "DELETE")

        # SHARED CACHE (reads only): sometimes serve a path-keyed cached body that may
        # belong to a DIFFERENT principal — the dangerous cross-principal cache bleed.
        if not is_write and ckey in self._cache and self.rng.random() < self._p(0.35):
            st, bd = self._cache[ckey]
            return st, copy.deepcopy(bd)

        if is_write:
            # RETRY / DUPLICATE: apply the write, then maybe apply it again.
            st, bd = self.world.handle(method, path, principal, query, body)
            if self.rng.random() < self._p(0.30):
                self.world.handle(method, path, principal, query, body)   # duplicate
            # ASYNC 202: sometimes the *effect* is deferred (we already applied it
            # above; model async by returning 202 without the confirming body, so an
            # immediate read-back cannot rely on the response).
            if self.rng.random() < self._p(0.30):
                return 202, {"status": "accepted"}
            return st, bd

        # READ path: model REPLICA LAG. The "true" answer is the primary; a replica
        # may still show a STALE snapshot from a few ticks ago.
        st, bd = self.world.handle(method, path, principal, query, body)
        key = (method, path, principal, str(sorted((query or {}).items())))
        hist = self._history.setdefault(key, [])
        hist.append((self.tick, st, copy.deepcopy(bd)))
        if len(hist) > 8:
            del hist[0]
        # choose a replica: with intensity, pick an older snapshot (stale read)
        if len(hist) > 1 and self.rng.random() < self._p(0.40):
            lag = self.rng.randint(1, min(len(hist), 4))
            _, st, bd = hist[-lag]
            bd = copy.deepcopy(bd)

        # populate shared cache for later bleed
        if 200 <= st < 300 and self.rng.random() < self._p(0.5):
            self._cache[ckey] = (st, copy.deepcopy(bd))

        # REORDER JITTER is a no-op for a sequential caller, but we perturb the tick so
        # convergence timelines interleave unpredictably.
        if self.rng.random() < self._p(0.5):
            self.tick += self.rng.randint(0, 2)
        return st, bd
