# Protocol [21] — Giant-surface targeting, gap G1 (scale triage)

The honest goal ([21] zero rule): NOT "guarantee a Google/Microsoft bug" — that is
ungrantable by any tool and fails the lie test. The goal is to remove the structural locks
that stop ONYX's method from RUNNING at giant scale, proven on a giant-emulating anvil.

G1 is the first and most load-bearing lock: a giant surface has 10^4–10^6 endpoints; a
fixed confirmation budget must be spent on the highest-authorization-risk candidates first,
or the deep bugs are never reached.

## The move — deterministic authz-risk triage (`authpath/triage.py`)
Every candidate endpoint is scored by transparent, deterministic authz-risk signals
(object-addressed, mutating verb, privilege/admin surface, cross-tenant, versioned/legacy,
sensitive noun, secondary-key). Confirmation runs in descending risk order within a budget.
No ML (RL1); the score is an auditable integer with reasons.

**Triage decides ORDER, the Δstate confirmer decides TRUTH.** Triage changes only which
candidates get the budget first — it never confirms. A high-ranked but safe endpoint still
yields no finding. So the zero-FP crown jewel is untouched at scale.

## Proven on a giant-emulating anvil (`tests/test_giant_triage.py`, 4/4)
- On a 10,000-endpoint surface, a budget of ~40 (**0.4%** of the surface) captures **≥90%**
  of the total authorization risk — the deep candidates are reached first.
- Real authz-risk endpoints rank above the noise mass.
- Scoring is deterministic and auditable (same input → same score + reasons).
- **Precision is untouched:** a top-ranked admin-delete endpoint that is properly enforced
  (403) yields no finding — triage cannot fabricate.

MSI byte-identical (triage is opt-in); full suite 546 green; lint clean.

## The [21] card
- **(أ) Structural lock removed:** the volume lock — ONYX can now be pointed at a
  giant-scale surface and spend its confirmation budget where authz risk is highest, instead
  of drowning uniformly.
- **(ب) Differentiation:** the triage is authorization-specific (cross-tenant, BFLA,
  secondary-key signals), not a generic crawler's popularity rank — it prioritises exactly
  the deep-authz axis where ONYX is strongest and generic scanners are weakest.
- **(ج) Evidence measured:** 0.4% budget → ≥90% risk captured on a 10k giant-emulating anvil
  (tier: self-authored anvil, T2 — the independent-target measurement remains the operator's).
- **(د) Graduated station reached:** giant-emulating anvil (volume). Next stations (still
  open, honest): protocol diversity (G2), zero-FP at 10^6 volume (G3), differential encoding
  (G4), independent giant-property target (G5). The live giant run stays the operator's.

## Honest ceiling (unchanged)
This makes ONYX CAPABLE of running its method at giant scale and prioritising the deep-authz
axis — it does not and cannot guarantee a specific giant's bug. Actual reach stays a function
of operator + live surface + conditions.
