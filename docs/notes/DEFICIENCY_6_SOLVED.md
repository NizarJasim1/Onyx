# Deficiency #6 (defensive adversary / stealth) — SOLVED under [18]+[19]+[20]

The k-sample quorum that gives ONYX zero false positives under chaos also emitted a loud
bot signature — a burst of k near-identical reads, each carrying a `_cb=<hex>` query param
no real client sends — which trips WAF / bot-detection on hardened targets and locks ONYX
out of exactly the surfaces worth testing.

## The root move ([4].R5 / [12]) — decouple reproduction from the burst
The quorum needs REPRODUCTION EVIDENCE (a real leak recurs on independent reads), not a
*burst*. A stealth profile keeps the identical majority semantics — so zero-FP is
untouched — while removing the signature:
adaptive incremental sampling that STOPS as soon as a strong majority is settled (quiet on
stable targets), a natural `Cache-Control: no-cache` cache-bust (a header real clients send)
instead of the telltale `_cb` param, and paced sampling so k reads are not a rapid-fire
burst.

## Gap inventory ([19] band 1) and closure

| Gap | Was | Closure |
|-----|-----|---------|
| **1 burst velocity** | k=7 rapid-fire reads | **SOLVED.** Adaptive early-stop + a pacing hook between samples — no velocity spike. |
| **2 `_cb` fingerprint** | every read carried `_cb=<hex>` | **SOLVED.** Cache-bust via `Cache-Control: no-cache`; the test asserts `_cb` is never sent. |
| **3 fixed high k on calm targets** | 7 reads even when stable | **SOLVED.** A stable endpoint settles in ≤3 reads (verified); only real disagreement escalates to max_k. |
| **4 ungoverned velocity** | no pacing | **SOLVED.** Injectable jittered inter-sample delay + run-wide rate governor. |
| **5 behavioral / crypto detection** | TLS/canvas fingerprint, per-request attestation, biometrics | **REAL WALL, worked around + declared.** Rides a real client the operator provides; else the surface is stealth-closed and ONYX abstains. Overlaps #3's attestation wall. |

**The load-bearing guarantee (verified on the real anvil):** with the stealth profile enabled,
precision stays **1.000 at every chaos intensity** (0.0 / 0.5 / 1.0), zero FP, recall ~0.82–0.87.
The profile changes only HOW read-backs are delivered, never WHAT counts as a confirmation.

Tests: `tests/test_stealth_profile.py` (4 cases incl. the anvil-under-stealth precision run).
MSI byte-identical (stealth default OFF); full suite 513 green; dedup lint clean.

## The wall ([19] band 3) — proven, worked around, declared
A target that flags ANY non-browser client by TLS-JA3 / canvas fingerprint or per-request
attestation, regardless of pacing, is stealth-closed to every external tool — an
information wall, not laziness. Work-around: drive ONYX's reads through a real client the
operator controls; absent that, the surface is declared stealth-closed and ONYX abstains.

## The [18] card
- **(أ) Structural constraint removed:** ONYX's own confirmation no longer betrays it — the
  quorum's reproduction evidence is decoupled from a detectable burst, so the zero-FP method
  can run on defended production surfaces instead of being blocked at the door.
- **(ب) Hypothesis the solution requires:** for the hardest surfaces, an operator-supplied
  real client to ride (for the attestation/fingerprint wall); otherwise the stealth profile
  alone suffices for rate/pattern defences.
- **(ج) Weakest remaining link:** pure behavioral/cryptographic client attestation stays a
  wall for any external tool (declared), same ~30% as #3.

## Graduation
Proven on the anvil (precision 1.0 under chaos with stealth) and on stable targets (quiet
signature). Next honest station: a real WAF-fronted target with an operator client — not a
Google/Microsoft claim.
