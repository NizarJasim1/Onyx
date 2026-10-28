# GAP #4 — Excessive Data Exposure (EDE), closed — RL22

## The defect (reproduced)
crAPI's community feed (`GET /community/api/v2/community/posts/recent`) returns
every post's `author.email` and `author.vehicleid`. ONYX abstained (0 findings)
even on a synthetic feed that leaks a TRACKED principal B's private email to A.

Root: ONYX's leak detection is triggered by OBJECT ACCESS (a foreign object id in
the request), not by FIELD EXPOSURE (foreign private data in the response). An
endpoint the actor is ALLOWED to call, whose body embeds another principal's private
fields, produced no candidate — invisible to every existing law (RL19 included).

## The fix — RL22 field-exposure (additive, flag-gated, default OFF)
`engine._field_exposure_pass`: scans a successful response body for a DISCRIMINATING
PII field (email-shaped value, or PII-named field, or OWNER/TOKEN class) that
provenance proves is ANOTHER tracked principal's PRIVATE data — that principal saw
it first in their own authenticated self-access (`legitimate_seers`). If exactly one
OTHER principal is the private seer and the object is not shared/public, the response
leaked their field to the actor -> confirmed EDE.

## Honest boundary (the disciplined choice)
RL22 confirms ONLY when the leaked identity is a TRACKED principal, because only then
is its privacy PROVEN (by that principal's own envelope). On the REAL capture the feed
authors (robot001@, pogba006@) are UNTRACKED third parties — black-box replay cannot
prove their fields are private, so RL22 correctly **abstains**. This is a true
boundary of black-box detection, declared rather than faked with an FP-prone
heuristic. Result on the real capture: EDE **not confirmed**, zero false positives
preserved.

## FP-safety (every gate must hold, else abstain)
- value DISCRIMINATING (reuses Gap#2 gate) AND PII/identity-bearing;
- seen privately by exactly ONE other principal (not broadly shared/public);
- object not declared shared (`shared_with`/`acl`) and not `visibility: public`.

## Discipline preserved
- **Default OFF -> byte-identical** (39/39, 19 findings); real runs enable it.
- **Additive isolation (A1)** — a new pass + two helpers; no existing logic changed.
  Full suite **477/477**; mutations 6/7 + 8/8; RL20 tier-clean; PCM selftest VERIFIED;
  conformance recall 1.0 / precision 1.0.
- **Negative controls** (`tests/test_field_exposure.py`): self / broadly-shared /
  untracked-third-party / non-PII all abstain; only a proven tracked-principal leak
  fires.
