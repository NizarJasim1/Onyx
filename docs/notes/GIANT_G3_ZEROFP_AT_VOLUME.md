# Protocol [21] — Giant-surface targeting, gap G3 (zero-FP at 10^6 volume)

This is the sacred constraint under maximum pressure. On a giant surface even a 1e-5 false-
positive rate over 10^6 requests means ~10 false alarms that bury the tool. The crown jewel
must hold not just under chaos but under VOLUME — and the small proving world never triggers
the scale-only vector that threatens it.

## The scale-only FP vector (G3-1)
`owner_of_value` attributes a leaked value to its earliest origin. Across millions of values
the birthday paradox makes coincidental collisions inevitable: two DIFFERENT principals
independently hold the SAME value (a common name, a default avatar, a shared enum, a small
int). A cross-principal read of such a value LOOKS like a leak but is coincidence — a false
positive that only appears at scale. (Proven real: `test_g3_base_resolver_WOULD_misattribute`.)

## The move — collision-proof attribution by construction (`provenance.unambiguous_owner`)
A value is attributed to an owner ONLY if its legitimate origins are a SINGLE distinct
principal. If two or more legitimate principals originated it, it is shared/colliding →
abstain (None). Combined with the existing entropy gate:
- a low-entropy value that could collide → caught here (multi-origin) → abstain;
- a high-entropy value colliding across two distinct principals by chance → ~2^-100 for a
  real token (the honest, quantified bound — not "distinctive enough").

This only ABSTAINS more than the base resolver; it can never attribute where the base did
not, so it cannot lower precision — it purely removes a scale-only FP vector. Flag-gated
`giant_volume`; off → byte-identical.

## Proven at 10^6 scale (`tests/test_giant_volume_zerofp.py`, 3/3)
A 1000-principal population with 10^6 legitimate observations — each principal holding many
COMMON (colliding) values plus one distinctive secret:
- **Zero scale-FP:** every colliding common value abstains (0 misattributions).
- **Recall preserved:** all 1000 distinctive secrets still attribute to their true owner.
- **End-to-end:** with `giant_volume` on, a cross-principal read of a colliding value yields
  no finding.

MSI byte-identical; full suite 556 green; lint clean.

## The [21] card
- **(أ) Structural lock removed:** the crown jewel now holds under VOLUME, not just chaos —
  a coincidental value collision at giant scale can no longer be misattributed as a leak.
- **(ب) Differentiation:** payload/response-diffing scanners have no principled owner model,
  so at scale they drown in coincidental "leaks"; ONYX abstains on ambiguous ownership by
  construction — the zero-FP discipline no competitor matches on the deep axis.
- **(ج) Evidence measured:** 0 scale-FPs over 10^6 observations + full recall on distinctive
  values + a stated 2^-100 collision bound (tier: self-authored anvil, T2).
- **(د) Graduated station reached:** 10^6-volume zero-FP. Still open: G4 (differential
  encoding), G5 (independent giant-property target). Live giant run stays the operator's.

## Wall — none
This is a pure STRENGTHENING of the sacred constraint. Deterministic, no ML, no trade-off.
