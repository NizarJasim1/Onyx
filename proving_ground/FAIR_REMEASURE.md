# FAIR FULL GROUND RE-MEASURE — honest current level

Proving ground upgraded PERMANENTLY to give every detector its designed declaration:
owner_id in doc + account bodies; _links action declarations; a public decoy
(/api/public/info, no owner field); accounts enforce ownership (403 to non-owners) except
the planted BOPLA-strange + AUTHN-gap. All detectors on, ARMED scope (for BFLA). Seed 1337.

## RESULT (raw, GT4)
```
RECALL    = 4/6 = 67%   (up from 0/6 on the first, unfair measurement)
PRECISION = 0 false positives   (perfect — abstained on every clean/decoy/public resource)
```
  CAUGHT: BOPLA familiar (doc:1), BOPLA strange (acct:1, via the nerve), BFLA (doc:4,
          function_escalation, armed), AUTHN-gap (acct:4, anon).
  MISS  : BOLA strange (order:4) — orders emit NO ownership declaration → CORRECT abstain
          (problem #1: ownership-less BOLA is undetectable deterministically, RL1/RL5).
          BOLA familiar (doc:2) — a GENUINE miss to diagnose (served cross-owner with
          owner_id present, yet not flagged). Next CRUCIBLE problem.

## HONEST READING
- Precision is perfect on a fair ground with public + shared + feature-flag + correct-denial
  decoys: the zero-FP discipline holds across all four detectors on real HTTP.
- Recall 4/6 where one miss is a CORRECT abstain (order:4) → effective recall is 4/5 = 80%
  on the deterministically-detectable set, with ONE real miss (doc:2) open.
- A proving-ground bug was found and fixed during this measurement (accounts were
  unintentionally cross-owner readable; the tool CORRECTLY flagged it — measurement
  injustice, not a tool FP; KP1).
- CEILING unchanged: one author built target + tool → high-quality SIMULATION, not a
  substitute for crAPI on a repaired machine.

## NEXT
Diagnose the doc:2 BOLA-familiar miss (CRUCIBLE problem #5): owner_id present, accessor
is a same-role peer, served cross-owner — why did nerve 1 not confirm it? Likely the
ownership-pointer learning or the cross-owner candidate generation interacts with the new
_links/owner_id emission. Triple-diagnose, then fix or prove a correct abstain.

## UPDATE — after CRUCIBLE problem #5 (order-dependent ownership fix)
RECALL improved 4/6 → 5/6 across three seeds (1337/99/7); PRECISION stays 0 FP. The sole
remaining miss is BOLA-strange (order:4, ownership-less) — a CORRECT abstain. Effective
recall on the deterministically-detectable set = 5/5 = 100%, zero false positives.
