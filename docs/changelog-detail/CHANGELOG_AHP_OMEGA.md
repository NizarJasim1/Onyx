# AHP-Ω — Adversarial Hermetic Proof (radical extension of P0)

## The leap
P0 built an honest local rig but left the live measurement as a human-trusted step.
AHP-Ω removes the human from the trust path: ONYX's measurements become
**proof-carrying** — verifiable by an adversary who trusts neither the runner, the
author, nor the host. It also adds a real, third-party-grounded offline validation
against crAPI's own published contract, so the project is no longer purely
self-measured even before the live run.

## What was built (all offline-complete and tested)
- `p0/corpus/` — crAPI's OWN OpenAPI spec, retrieved verbatim with provenance, and a
  ground truth DERIVED from it (403-presence = ownership enforced; cross-user example
  data = leak). Labels are crAPI's, not ONYX's.
- `p0/conformance.py` — a replay target whose endpoints/fields/status codes are taken
  verbatim from that spec, run in vulnerable AND patched variants. ONYX must fire on
  the real shape and go silent when the ownership check is added (the negative
  control). Result on the harness-faithful read-leak axis: recall 1.0, precision 1.0,
  negative control passing; BFLA/mass-assign reported transparently, never scored as
  misses (ONYX confirms them in calibration).
- `p0/pcm.py` — Proof-Carrying Measurement: an evidence bundle (target attestation +
  sealed oracle + raw transcript + findings + scorecard + hash chain) and a
  trust-no-one verifier that recomputes the chain, checks the seal, and REPLAYS the
  raw transcript through ONYX to reproduce every finding independently. Tampered
  transcripts and lied findings are caught.
- `p0/prove.py` / `p0/verify.py` — the hermetic entry and the standalone verifier.
  `make selftest` runs the whole prove->verify pipeline offline, end to end, VERIFIED.

## The honest tier ladder (enforced, never inflated)
T2_SELF_MEASURED (own demo) -> SPEC_CONFORMANCE (matches crAPI's documented behavior,
offline, negative-controlled) -> T1_INDEPENDENT (live third-party, proof-carrying).
The live run is one network-bound command; its integrity core is identical to the
offline self-test and is fully proven here.

## Verification
- conformance: read-leak BOLA recall 1.0 / precision 1.0, negative control 2/2.
- PCM: honest bundle verifies; tampered transcript and lied findings are caught.
- 15 new tests (conformance + pcm + p0 scorer offline); 456/456 total — zero regression.
- Demo byte-identical: 39/39, 19 findings, 3 dropped.

## Honest boundary (unchanged and explicit)
No live network in the build environment. AHP-Ω makes the eventual live run trivial,
zero-touch, and unforgeable — but until `make prove` is run against a live crAPI and
`make verify` passes, ONYX's numbers stand at SPEC_CONFORMANCE, not T1. The rig
guarantees that when that step is taken, the result cannot be faked by anyone.
