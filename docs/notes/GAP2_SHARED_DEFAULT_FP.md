# GAP #2 — the shared-default false positive (closed)

## The defect (reproduced, then fixed)
A value that is a **shared default/sentinel** — `video_id=0`, `status="pending"`,
`role="ROLE_USER"`, booleans, empty strings — matches **identically** across every
principal. The leak audit counted such a match as "actor reproduced the owner's
private field", so a principal reading **its own** resource could be confirmed as a
cross-principal leak. This directly contradicts the zero-false-positive core — the
tool's entire differentiator.

Reproduced: B reads B's own item; because the body carries `category_id=0` (a
default A's item also had), ONYX confirmed a false `OBJECT_ACCESS` finding — and,
after the first route was closed, a false `CONSERVATION` finding via the sibling
value-presence route.

## Root (via the 7-strata dig)
The engine conflated **"a value the index recorded under one principal"** with **"a
value that discriminates that principal's private object."** It had no measure of a
value's **discriminating power** — a low-entropy shared default was treated exactly
like a high-entropy private id. Sibling of the envelope-precision root: *value
presence ≠ value privacy.*

## The fix (radical, R1–R5)
A leaked value is substantive evidence only if it **discriminates a private
object**. `_value_is_discriminating` / `_substantive_leak_value` (in `confirmer.py`)
apply a purely **structural** test (RL1-safe, no learning, no baseline):
- **kept** (discriminating): OWNER/TOKEN/AMOUNT-class fields, PII-named fields,
  specific numbers, non-empty structures, emails, uuids, addresses, mixed-case
  names, long tokens.
- **filtered** (shared default): `0/1/-1`, booleans, empty, short single-case enum
  words (`pending`, `active`, `ROLE_USER`).

Applied at **both** confirmation routes (the sibling ramification): `audit_leak`
(object-access three-way audit) and `_confirm_conservation` (value-presence
differential).

## Discipline preserved
- **Flag-gated, default-OFF** (`Confirmer.strict_leak`) — the frozen calibration
  stays **byte-identical** (39/39, 19 findings). Real runs (the live-capture bridge)
  enable it.
- **Zero recall loss** — with the gate forced ON across the whole demo, all **19**
  true findings still confirm (they rely on discriminating values). Conformance
  stays recall 1.0 / precision 1.0 / negative-control 2/2.
- **Additive isolation (A1)** — engine detection logic otherwise untouched; full
  suite 466/466; mutations 6/7 + 8/8; RL20 tier-clean.

## Regression lock
`tests/test_shared_default_fp.py`: FP present with the gate OFF, killed with it ON
(proves the gate is load-bearing); the discriminating helper admits every real-leak
value and rejects every sentinel.
