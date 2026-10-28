# CHANGELOG — G3,G4,G5,G7,G8,G9,G11,G12,G15 (completing the G1–G15 catalog)

## What
Nine new pure-logic modules + one falsification suite (21 tests) closing the last
nine recall gaps from the drift gap-catalog. With this, **all of G1–G15 are built**.

| Gap | Module | Mechanism | Key FP gate |
|-----|--------|-----------|-------------|
| G3  | `convergence.py` | replica-lag / read-your-writes: confirm only at a proven convergence point | vanished-after-convergence ⇒ abstain |
| G7  | `idempotency.py` | idempotency-key replay drift | confirm via attributed read-back, not the replay response |
| G8  | `deep_provenance.py` | stored-ID-abused-later across async gaps (builds on G14) | no causal link without exact nonce; cross-principal still required |
| G12 | `discriminating.py` | learn discriminating vs shared-default values | suppress only a proven shared default, never a discriminating value |
| G9  | `state_inference.py` | producer→consumer + validate-commit seams from OpenAPI | candidates only — never reports; each must pass an independent Δstate confirmer |
| G11 | `ownership_sparse.py` | sparse-target ownership via attested identity | attested match is an ALTERNATIVE to the ≥2-source rule, not a loosening |
| G15 | `drift_chain.py` | register confirmed drift as capability-graph edges | every edge independently Δstate-confirmed; a path reports only if all edges confirmed |
| G5  | `graphql_interleave.py` | aliased/batched-mutation + nested-resolver interleave | confirm via an independent victim read-back, not the batched response |
| G4  | `window_opener.py` | single-packet / deferred-collision window-opener | timing is a probabilistic trigger only — the verdict is solely a persisted Δstate read-back |

## Governing principle (held throughout)
Separate the probabilistic trigger (timing/async) from the deterministic oracle
(persisted read-back). The nonce proves attribution ("my effect landed"); the
cross-principal read-back proves authorization. They are never merged. Every module
either confirms a persisted, attributed, cross-principal Δstate or abstains.

## Network-wall-killer applied (G4/G5/G9)
The gaps that "need network" were split into: (a) pure decision/planning logic — built
and fully tested here with fakes; (b) a thin injected I/O adapter (synchronous
race dispatch for G4, GraphQL send for G5, spec fetch for G9) that carries no logic.
Verification = "proved the determinism," not "ran it live."

## Safety (No-Regression Invariant)
- All nine are additive, standalone modules; nothing existing imports them yet, so
  behavior is byte-identical. Full suite **648 → 669**, 0 failures, 0 import errors.
- Each is reversible (delete the file) and default-OFF by virtue of being unwired.

## Honest scope
These are the LOGIC LAYER for the nine gaps, complete and falsification-tested. The
network-dependent ones (G4 single-packet, G5 GraphQL-live, G9 inference-driven runs)
need their thin I/O adapters + engine wiring to fire on live targets — the confirming
logic they feed is done and tested. The pure-logic gaps (G3, G7, G8, G11, G12, G15)
are ready to wire into the engine's confirmation paths the same way G14/G2/G1 were.
