# CRUCIBLE — problem #5: the doc:2 BOLA-familiar miss (order-dependent blindness)

## LOOP 1-2 — TRIPLE-DIAGNOSE + KILL (converged on a real, deep defect)
- TD1: doc:2 (bola_idswap, served cross-owner WITH owner_id) not flagged; nerve found doc:1.
- TD2: ownership_pointer LEARNED (owner_id), yet abstained list EMPTY for doc:2 → no
  candidate was ever generated (not an abstain).
- TD3 (the root): the access records showed declared_owner=None for alice→doc:2 (and other
  cross-owner accesses) even though their bodies carry owner_id. CAUSE: record_access
  computes declared_owner ONCE, at record time, using the pointer learned SO FAR. The
  pointer is learned INCREMENTALLY — accesses filed before it stabilises carry
  declared_owner=None FOREVER and are never revisited. An ORDER-DEPENDENT blind spot:
  whether a cross-owner access is caught depends on whether it happened before or after the
  pointer was learned. (This also explains why doc:1 was caught but doc:2 was not, and why
  the same bug is flaky across probe orders.)
- KP: defect (not measurement injustice). The fix must not add FP.

## LOOP 3 — FORGE-HARDEST (DONE) — lazy ownership extraction
authpath/equivalence.py ownership_mismatch_candidates(): declared_owner is now recomputed
LAZILY at candidate-generation time (where the pointer is FINAL) for any record whose
record-time declared_owner is None — applying the SAME learned pointer to every record
consistently. F7 pre-mortem: same pointer ⇒ no new signal ⇒ no new FP; only recall rises
(records that were order-blinded now reconcile). Self-owned and granted accesses still skip.

## LOOP 4 — RE-MEASURE-CRUEL (DONE) — PASSED across THREE seeds
Fair full ground (all detectors, armed), seeds 1337 / 99 / 7:
  RECALL = 5/6 (was 4/6) on every seed; the only MISS is BOLA/strange (order:4) — the
  ownership-LESS BOLA that is a CORRECT abstain (problem #1). PRECISION = 0 false positives.
  → effective recall on the deterministically-detectable set = 5/5 = 100%, zero FP.
Suite 367→369 (2 new order-independence tests); demo byte-identical.

## PROBLEM #5 — RESOLVED
An order-dependent recall bug (cross-owner accesses filed before the ownership pointer
stabilised were permanently blind) is fixed by lazy, consistent ownership extraction. doc:2
is now caught; recall 4/6→5/6 with the sole remaining miss being a proven correct abstain.
Permanent regression: tests/test_ownership_order.py.
