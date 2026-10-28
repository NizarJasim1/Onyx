# RL19 — Authority Conservation (P1, complete: six-step arc)

## Position (why this beats the state of the art)
Hadrian (Praetorian, 2026 SOTA) proves WRITE/DELETE by verifying a state change.
A READ changes nothing, so for the DOMINANT BOLA shape (a body over-exposing
another principal's private field) Hadrian falls back to response/template
matching — the very 200-OK heuristic it rightly mocks Autorize for. ONYX reframes
one level up: authority is a CONSERVED quantity; exercised authority must be a
subset of conserved authority at a coordinate (object × property × function ×
SERVICE × time). A read surfacing another principal's private value violates the
invariant — proven by a cross-principal differential, non-invasively (no resource
creation, no mutation). Hadrian's check is the single object/write special case.

The honest boundary: ONYX is architecturally deeper on the confirmation axis
(reads, cross-service, non-invasive, derived-not-templated); Hadrian is ahead on
INDEPENDENT proof (crAPI) and engineering maturity. ONYX's superiority is on the
read-leak/conservation axis and is established only once measured on a third-party
target (the P0 work). No claim here is presented as independent proof.

## How it was built (analysis 3 sessions, execution 3 sessions)
1. Competitor teardown (Hadrian/Vespasian source): 6 structural boundaries.
2. Self-teardown: 13 defects in the first prototype (flat value-equality
   attribution, dead exoneration, order dependence, public-laundering FN,
   feed-confirmation FN, ...).
3. Red-line trial of every fix; locked design.
4. Rebuilt attribution on MEASURED, order-free, laundering-proof relations.
5. Rebuilt confirmation as cross-principal VALUE-PRESENCE differential (works on
   feeds/search); added the SERVICE coordinate (host-scoped ownership).
6. Adversarial hardening: manual mutation testing on the law (6/7 mutants killed;
   the survivor is a documented finding-equivalent noise guard).

## Mechanism (measured, not heuristic)
Ownership = provenance legitimate-phase-only indices: legitimate_holders(V)
(addressed+received as own), legitimate_seers(V) (a sole non-anon seer owns a
secret), legitimate_hold_hosts(V, p) (service coordinate). A value owned by exactly
one OTHER principal, that B neither holds nor was legitimately shown, that no anon
legitimately received, is a violation. Confirmation: V present in owner read-back +
absent for a control peer + present for B. Ambiguity → visible coverage-gap abstain.

## Files
- authpath/conservation.py (NEW), authpath/provenance.py (+3 accessors),
  authpath/confirmer.py (+ value-presence differential), eil.py + engine.py
  (additive isolation, flag-gated, OFF by default), tools/mutate_conservation.py.
- tests: test_conservation.py (12 adversarial), _e2e.py (3), _confirm.py (2).

## Red lines
RL1 every decision a measured fact or fixed lexicon (zero learned threshold).
RL2 order-free set membership → deterministic. RL3 candidate-only; differential
confirmer decides. RL5 abstain on ambiguity.

## Verification
- 17 conservation tests (12 adversarial + 3 e2e + 2 confirmation) green.
- Mutation score 6/7 on the law (1 documented equivalent mutant).
- 401/401 total (384 original + 17) — zero regression.
- Demo byte-identical: 39/39, 19 findings, 3 dropped (RL19 OFF by default).
