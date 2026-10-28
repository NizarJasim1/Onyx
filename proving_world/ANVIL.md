# The Anvil — production-chaos benchmark + the RL24 iron-hardening

## What it does
Wraps the live world in a reality layer (`anvil.py`) that injects production chaos
tuned HARDER than reality, all aimed at ONYX's load-bearing assumption that a
read-back is a faithful, immediate, deterministic view of true state: replica-lag /
stale reads, shared-cache bleed (a GET served another principal's cached body),
retries / duplicate writes, async-202 (effect deferred), rate-limit / WAF (429/503),
timeouts (599), reorder jitter. Intensity in [0,1] scales every vector; 0.0 is the
clean world.

## The break, then the fix
The clean core held precision 1.0; under chaos it FABRICATED false positives — cache
bleed and stale reads made safe endpoints look like cross-principal leaks. That was
the honest, humbling result: ONYX was not iron on a hostile transport.

The forensic autopsy found the root was not one bug but one PRINCIPLE ONYX violated:
**it trusted single observations — the trigger, the read-back, and the provenance
built from earlier probes.** RL24 rebuilds confirmation on the opposite principle —
*a real vulnerability is a persistent property that reproduces on fresh reads; a chaos
artifact is transient and does not*:

  * **Trust no single observation.** Every confirming read-back is CACHE-BUSTED
    (a unique query bypasses URL-keyed caches) and taken K times under a STRONG QUORUM
    (>=80% must agree); no quorum -> abstain (RL5).
  * **Re-establish the trigger.** The confirmer no longer trusts the analyze-time body
    (a bleed can pollute it); it re-reads the attacker's request fresh and requires the
    leak to still be there.
  * **Chaos-robust ownership.** Attribution uses only LEGITIMATE (observe-phase, self-
    authenticated) evidence — earliest-origin for the field laws, `legitimate_seers`
    for the cold-start law. Attack probes are recorded as `legitimate=False` and never
    update these indices, so a cache-bleed during an attack cannot forge or rewrite
    who owns a value. This was the last false-positive class: a bleed made a tracked
    owner's own email look "untracked" and fired RL21 on a safe endpoint.
  * **No confirmation on unconfirmed async.** A 202 (Accepted) is not a proven Δstate,
    so RL23 refuses to confirm a write on it.

All of RL24 is gated behind `confirmer.stability_k` (default 1 = single send =
byte-identical calibration); real/hostile runs set it to ~7.

## Result — precision is iron at EVERY intensity (20 sealed worlds per cell)
| intensity | recall | precision |
|-----------|--------|-----------|
| 0.00 | ~0.86 | **1.000** |
| 0.25 | ~0.86 | **1.000** |
| 0.50 | ~0.84 | **1.000** |
| 0.75 | ~0.83 | **1.000** |
| 1.00 | ~0.80 | **1.000** |

**Zero false positives at every chaos level from clean to harder-than-reality.** The
crown jewel now holds regardless of transport conditions. Recall degrades gently and
honestly under extreme chaos (the fail-safe: when observations will not stabilise,
ONYX abstains rather than guess) — precision is never traded for it.

## Reading the numbers (why recall differs across harnesses)
Two harnesses report on two different worlds, so their recall numbers are NOT
comparable and are NOT a contradiction:
  * `harness.py` (clean proving world, `README.md`): recall **~0.94** — the ceiling
    when the transport is perfect.
  * `chaos_harness.py` (this anvil): recall **~0.80–0.86** even at intensity 0.0,
    because the chaos harness enables `stability_k=7`, so every confirmation must clear
    the strong-quorum re-verification. That extra strictness abstains on a few
    borderline confirmations — the deliberate price of iron precision. Both are correct
    for their own configuration.

## Coverage boundary (updated — the big miss is now closed)
The largest known miss, **admin-delete BFLA**, is now confirmed by **RL25**
(cross-principal destruction): a non-owner deleting an owner's object, proven by
Δstate (the owner's cache-busted re-read returns gone) plus legitimate observe-phase
ownership — an FP-safe formulation with no role/path heuristic. Recall rose from ~0.72
to ~0.94 (clean) / ~0.80-0.86 (under chaos) with precision held at 1.000 at every
intensity. What remains missed is now the long tail of chained/second-order cases, not
a single headline gap.

## Run
```
cd proving_world && python3 chaos_harness.py        # precision/recall vs intensity
python3 tests/test_chaos_precision.py               # asserts precision 1.0 at all levels
```
