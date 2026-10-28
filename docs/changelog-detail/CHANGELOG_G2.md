# CHANGELOG — G2: Conditional-Request Oracle (ETag / If-Match)

## What
New module `authpath/conditional_oracle.py` + falsification suite
`tests/test_conditional_oracle_g2.py` (12 tests). Closes gap **G2**: a
deterministic, server-authoritative instrument that detects an object's
version/binding changed between check and commit — the cleanest signal in the
gap catalog for object-binding drift (TOCTOU-of-authorization).

## Mechanism
Per RFC 7232 §6, a server MUST answer 412 to a false `If-Match`. Capture the
object's strong ETag at CHECK, replay the mutating request with `If-Match:<etag>`
at COMMIT, and read the status: 412 = the re-bind window fired (deterministic, no
heuristic); 2xx = write hit the version we read; else = abstain. One header turns
the server into the oracle.

## Correctness rules (never emit an unreliable signal)
1. **Weak ETag** (`W/"..."`) is refused for If-Match (RFC 7232 §3.1 requires the
   strong comparison) → fall back to an explicit version field or abstain.
2. **Fronting proxy** (AWS ALB/CDN can fake a 412): if a proxy header is present,
   a 412 is INDETERMINATE and must be corroborated by a Δstate read-back.
3. **No wildcard** `If-Match: *` — only the exact captured strong ETag.

## FP gate (E-0..E-5)
- E-0 a strong validator (ETag or explicit version) must exist → else abstain.
- E-1 If-Match carries the exact captured strong ETag; never `*`, never a guess.
- E-2 a 412 is an OBSERVATION, not a finding.
- E-3 proxy suspected ⇒ 412 is INDETERMINATE ⇒ require read-back corroboration.
- E-4 a finding requires VERSION_CHANGED **and** a cross-principal read-back;
  either alone ⇒ abstain (observation ≠ finding).
- E-5 default-OFF ⇒ byte-identical when unused.

## Verification
- New falsification suite: 12/12 pass (incl. weak-etag refusal, proxy-412
  indeterminate, no-validator abstain, version-field fallback, observation≠finding).
- Full project suite: **589 → 601**, 0 failures, 0 import errors (no regression).

## Not yet wired (honest scope)
- The engine does not yet auto-run the oracle during drift probing; wiring
  connects check-response ETag capture → conditional commit → the existing Δstate
  read-back in a later integration pass. The module provides the instrument and
  the gated confirmation logic.
