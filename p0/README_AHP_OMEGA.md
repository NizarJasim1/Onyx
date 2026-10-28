# AHP-Ω — Adversarial Hermetic Proof for ONYX

ONYX's thesis is "prove, don't guess." AHP-Ω applies that to ONYX's OWN evidence: a
measurement is worth nothing unless an adversary can verify it without trusting the
person who ran it. This directory makes ONYX's results **proof-carrying**.

## The honest evidence ladder
Every ONYX number is stamped with exactly one tier — never inflated:

| Tier | What it means | How it is earned here |
|------|---------------|-----------------------|
| **T2_SELF_MEASURED** | measured on ONYX's own traffic | the demo calibration (39/39) |
| **SPEC_CONFORMANCE** | ONYX's verdicts match crAPI's OWN spec-documented behavior, offline, with a negative control | `make conformance` / `make selftest` |
| **T1_INDEPENDENT** | recall/precision on a live third-party target, in a proof-carrying bundle anyone can verify | `make prove` against live crAPI, then `make verify` |

SPEC_CONFORMANCE is genuinely above T2 (the response shapes and labels are crAPI's,
not ONYX's, and a reviewer can diff them against the retrieved OpenAPI spec) but
strictly below live-T1 (no live server was queried). The code never lets a result
claim a tier it did not earn.

## What is proven offline (no network)
- ONYX's read-leak BOLA detection conforms to crAPI's official spec behavior:
  recall 1.0 / precision 1.0 on the harness-faithful axis, with the negative control
  passing (ONYX fires on the real vulnerable shape and goes silent the moment the
  ownership check is added). BFLA/mass-assign are reported transparently, never
  scored as misses.
- The full prove -> verify pipeline: `make selftest` builds a Proof-Carrying
  Measurement bundle and a trust-no-one verifier reproduces every finding by
  replaying the raw transcript through ONYX itself. Tampering with the transcript or
  lying about the findings is caught.

## What the operator runs for T1 (one network-bound step)
    make -C p0 seal           # pre-register the ground truth (hash seal)
    # bring up crAPI (deploy/docker compose), then:
    make -C p0 prove BASE=http://localhost:8888   # live run -> bundle.json (self-verified)
    make -C p0 verify                              # anyone re-verifies, trusting no one
    make -C p0 score                               # recall/precision + the T1 tier gate

The live run differs from the offline self-test in exactly one way: the transcript
comes from the live crAPI instead of the spec-shaped replay target. The integrity
core — sealed oracle, hash chain, trust-no-one verifier — is identical and is proven
offline. That is what makes the eventual T1 result unforgeable: it is a property of
the evidence, not of whoever pressed the button.

## Corpus provenance
`corpus/` holds crAPI's own published artifacts (OpenAPI spec) with their retrieval
URLs in `corpus/PROVENANCE.md`. The ground truth in `corpus/spec_derived_ground_truth.json`
is derived from those — each label traceable to a spec fact (a 403 response means an
ownership check exists; cross-user example data means a leak).
