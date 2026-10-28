# GAP #3 — cold-start ownership blindness (closed) — RL21

## The defect (reproduced honestly)
On a flat capture, A and B both read mechanic reports owned by a THIRD party
(admin@/pogba@ — never provisioned as A/B/C). ONYX abstained (0 findings): its
cross-principal ownership set was limited to TRACKED principals, so an object owned
by an untracked identity produced no ownership differential — even though the body
literally declares a foreign owner and multiple non-owners can read it.

Note (intellectual honesty): abstaining on a SINGLE non-owner read of a
foreign-owned object is CORRECT (the reader might be authorised, e.g. a support
agent). The genuine, FP-safe gap is the MULTI-non-owner exposure.

## Root
ONYX resolved ownership only via prior provenance (a tracked principal was observed
holding the object) OR a tracked embedded-owner identity. It could not treat an
UNTRACKED embedded owner-identity as an owner, so a third-party-owned object read by
several non-owners was invisible. Sibling of the envelope/discriminating roots:
*ownership evidence was restricted to tracked principals.*

## The fix — RL21 embedded-owner exposure (additive, flag-gated, default OFF)
`engine._embedded_owner_exposure_pass`: an object whose body declares a
DISCRIMINATING owner-identity held by NO tracked principal, read successfully by
>=2 DISTINCT non-owner principals, is confirmed as a broken-authorization exposure
(BFLA-class: any authenticated user reads any object + its owner's PII).

FP-safety — fires ONLY when every gate holds, else abstains (RL5):
- owner value is DISCRIMINATING (reuses the Gap#2 gate — `owner.id=0` never fires);
- owner is held by NO tracked principal (a genuine third party, not self / known peer
  — the tracked-owner case is already handled by the existing differential);
- the object is read by >=2 distinct principals (a single reader abstains);
- the object is NOT declared shared to a reader (`shared_with`/`acl`/…);
- the object is NOT explicitly public (`visibility: public`, …).

## Result on the REAL crAPI capture
- **BOLA-MECHANIC-REPORT: CONFIRMED** (5 finding instances) — the first
  independently-verifiable recall on the real capture, up from 0.
- Precision unchanged: **zero false positives** across all clean + attack probes.
- **PCM bundle verifies trust-no-one** — the engine config (RL21 + strict-leak) is
  hash-chained into the bundle, so an independent verifier re-derives the identical
  findings.

Honest tier: **T1_PARTIAL — 1/5 oracle vulns confirmed** on this capture. The other
4 still need provisioning (vehicle, video) or a credit read-back (the Gap#1 spec).

## Discipline preserved
- **Default OFF -> byte-identical** calibration (39/39, 19 findings); real runs enable it.
- **Additive isolation (A1)** — a new pass + two structural helpers; no existing
  detection logic changed. Full suite **472/472**; mutations 6/7 + 8/8; RL20
  tier-clean; PCM selftest VERIFIED; conformance recall 1.0 / precision 1.0.
- **Negative controls** (`tests/test_embedded_owner_exposure.py`): self / shared /
  public / single-reader / shared-default-owner all abstain; only the true
  multi-non-owner exposure fires.
