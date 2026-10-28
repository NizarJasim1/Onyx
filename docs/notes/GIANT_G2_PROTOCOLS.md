# Protocol [21] — Giant-surface targeting, gap G2 (protocol diversity)

Giants are not one REST+JSON API. Their objects hide in carriers ONYX's numeric/uuid
detection misses — and an object ONYX cannot SEE is a BOLA it cannot find. G2 removes that
lock so non-REST giant surfaces are in scope for the SAME deterministic Δstate confirmation.

## The move (`authpath/protocol.py`, flag-gated `giant_protocol`)
- **Opaque / signed ids** — base64url handles, signed cursors, encrypted ids in bodies/
  queries that numeric detection skips (conservative: a plain word or short token is not an
  id, to avoid over-tagging).
- **Batch / aliased operations** — JSON-RPC batch arrays, OData `$batch`, and GraphQL alias
  batching are decomposed so every sub-operation's object becomes independently addressable.
- **gRPC via JSON transcoding** — object ids extracted from the transcoded JSON.

It only EXPANDS what ONYX can address; it never confirms. The Δstate confirmer still decides
truth, so a newly-addressable but safe object yields no finding — zero-FP preserved by
construction (verified on a 403-enforced batched target).

## Proven (`tests/test_giant_protocols.py`, 7/7)
Opaque ids recognised (and plain words rejected); opaque body cursors, batch sub-operations,
GraphQL aliases, and gRPC-transcoded ids all become addressable; a safe target still yields
nothing; and the whole thing is a no-op when `giant_protocol` is off (byte-identical demo,
suite 553 green, lint clean).

## The wall ([19] band 3) — declared
Raw binary protobuf / custom framing with no transcoding is not black-box introspectable.
The operator supplies a decoder, or that surface abstains — declared, not silently missed.

## The [21] card
- **(أ) Structural lock removed:** the "REST + numeric id in path" assumption — ONYX now
  addresses objects across opaque ids, batches, and gRPC, so a giant's non-REST surface is
  testable by the same method.
- **(ب) Differentiation:** generic scanners fuzz payloads and ignore batch/opaque semantics;
  ONYX resolves the actual OBJECT in each sub-operation and confirms cross-principal access
  by Δstate — the deep-authz behaviour they lack on these protocols.
- **(ج) Evidence measured:** 7/7 on a multi-protocol emulation incl. the FP-safety case
  (tier: self-authored anvil, T2; independent measurement remains the operator's).
- **(د) Graduated station reached:** protocol-diversity emulation. Still open: G3 (zero-FP at
  10^6 volume), G4 (differential encoding), G5 (independent giant-property target). Live giant
  run stays the operator's.

## Honest ceiling (unchanged)
This makes non-REST giant surfaces addressable by ONYX's method — it does not guarantee any
specific giant's bug. Reach stays a function of operator + live surface + conditions.
