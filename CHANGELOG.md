# Changelog

Notable changes per release. Detailed design notes for each item are in
[`docs/changelog-detail/`](docs/changelog-detail).

## [3.2.0] - 2026-10

Closing the gaps found in the v3 gap analysis.

### Added
- Oracle registry and a `whoami` identity differential, so every confirmation names
  the oracle it used.
- Cross-tenant detection and a parser-differential check (two parsers disagreeing on
  the same request).
- Field-level authorization for nested and aliased fields. Valueless confirmation is
  now the default when a value can't be read back safely.
- High-recall probe generation, portfolio expected-value ranking, and CVE dedup.
- Transitive ReBAC grants and a consistency-window guard for eventually consistent
  backends.
- Law-driven state driving: the engine walks an object into the state a law needs
  before testing it. Ownership pinning at scale.

## [3.1.0] - 2026-07

Confirmation channels beyond the direct response.

### Added
- Out-of-band channels: confirm effects that show up somewhere other than the
  response (second-order leaks).
- Conditional-request oracle using `ETag` / `If-Match`.
- Async-commit follower for `202 Accepted`, saga and CQRS flows.
- Reference extraction from headers, JWT claims and GraphQL variables.
- Stability voting over volatile fields to keep recall under noisy responses.
- Nonce provenance for cross-channel attribution.
- Wired the above into the declared-vs-actual bridge and the main engine.

### Hardening
- Adversarial hermetic proof suite on top of the independent-measurement rig.

## [3.0.0] - 2026-06

First complete v3 engine.

### Added
- Eight-stage pipeline: scope guard, transport, effect contract, value provenance,
  principal envelopes, invariant law library, Δstate confirmer, report emitter.
- Authority conservation: exercised authority must stay within what a principal
  provably holds, which lets read-side leaks be confirmed without mutating state.
- Evidence tiers on every metric, plus a CI gate that rejects untiered numbers.
- Temporal checks (revoked credentials, regressions between scans), cross-surface
  and combinatorial checks, global invariants.
- Control-center dashboard, HAR import, OpenAPI/GraphQL discovery, CVSS scoring and
  OWASP API / CWE mapping in reports.
- Independent-measurement rig, comparison design against an Autorize-style baseline,
  mutation harnesses and the labeled calibration.
