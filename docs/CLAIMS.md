# ONYX — Headline Claims (every claim carries its evidence tier)

Tiers: T1 independent · T2 self-measured · T3 mechanism-estimate · T4 by-construction.
"Proven" is reserved for T1. No number below is presented as independent proof.

- [T4_BY_CONSTRUCTION] Precision is a construction property: no finding is emitted
  without a Δstate delta (guaranteed by construction, not a measured rate).
- [T4_BY_CONSTRUCTION] Attribution is deterministic and order-free (guaranteed by
  construction, not a measured rate).
- [T4_BY_CONSTRUCTION] The read-leak coordinate is reachable without mutation, a
  position no surveyed mutation verifier holds (a structural argument).
- [T2_SELF_MEASURED] The labeled calibration reproduces byte-identically across
  refactors (measured on a self-authored simulation).
- [T3_MECHANISM_ESTIMATE] Recall and a false-positive rate on an independently
  designed target are not yet measured (estimated from the mechanism, pending P0).
- [T2_SELF_MEASURED] On self-authored labeled traffic, ONYX added no false positive
  where a full-strength Autorize-equivalent heuristic added many — a measured
  precision advantage on a self-built target (the independent re-run is pending P0).
- [T4_BY_CONSTRUCTION] The exact remediation and the standard taxonomy (OWASP API /
  CWE) are derived from the violated invariant — a property of the effect-invariant
  model, not a measured rate.
- [SPEC_CONFORMANCE] On crAPI's official-OpenAPI-documented behavior, ONYX's read-leak
  BOLA verdicts match the ground truth with a passing negative control (fires on the
  vulnerable shape, silent once the ownership check is added) — offline, not yet live.
- [T4_BY_CONSTRUCTION] Each measurement is proof-carrying: a verifier reproduces every
  finding by replaying the raw recorded transcript through ONYX, so a result cannot be
  forged or inflated by whoever ran it.
