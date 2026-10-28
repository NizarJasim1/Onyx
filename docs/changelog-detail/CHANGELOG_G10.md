# CHANGELOG — G10: Extended reference-source extraction (headers / JWT / GraphQL vars)

## What
`authpath/nestedref.py` now mines object references from FOUR more sources beyond
body + query: **identity/reference headers**, **JWT claims**, and **GraphQL
operation variables**. New `find_refs(..., headers=, variables=)` params default to
None ⇒ byte-identical to prior behavior. Adds `swap_ref_full(...)` for
location-complete swaps.

## Why
Object references that live in headers (X-Customer-ID, X-Tenant-ID), JWT claims
(user_id, tenant_id, account_id), or GraphQL variables were never extracted, so
cross-principal drift on those surfaces was never probed → lost recall. Same
conservative guards, more surface covered.

## Design (guards preserved, one honest limitation)
- Every new source reuses the EXISTING guards: `_is_ref_name` (+ `_NEVER` block
  list) and `detect_shape` confidence. No guard was loosened.
- **JWT claims are extraction-only** (`swappable=False`): a signed token cannot be
  re-forged with a swapped ref, so proposing a JWT swap would produce a broken
  request. `swap_ref_full` refuses them. They remain valuable for cross-step
  provenance/observation (feeds G8).
- The Authorization header is mined for JWT claims, not double-counted as a plain
  header reference.
- **Known limitation (deliberately out of scope):** camelCase names (`orderId`)
  and the JWT `sub` claim are not matched by the current snake_case name guard.
  Extending the shared `_is_ref_name` regex risks changing body/query behavior
  (regression), so it is left as a separate future micro-gap rather than bundled
  here. G10's scope is SOURCES, not the name matcher.

## FP gate (R-1..R-5)
- R-1 same name + shape guards on all new sources.
- R-2 JWT claims never become swap candidates (not forgeable).
- R-3 header/gql-var swaps go through the same downstream Δstate gate.
- R-4 default-OFF for behavior change (new params default None; `generate_swaps`
  still `enabled=False`).
- R-5 JWT parsing is best-effort and fail-safe (bad token ⇒ no claims, never raises).

## Verification
- New falsification suite: 10/10 (headers extracted, JWT extracted-not-swappable,
  JWT swap refused, gql vars swappable, _NEVER blocks across all sources, malformed
  JWT fail-safe, targeted-only swaps, body/query unchanged).
- Full project suite: **621 → 631**, 0 failures, 0 import errors (no regression).
