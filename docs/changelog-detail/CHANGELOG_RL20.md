# RL20 — Evidence Discipline (P8, complete: six-step arc)

## Position (the move that makes competitors look silly)
ONYX's thesis is "confirm by proof, never by inference" (RL3). The deadliest attack
is self-refutation: a number ABOUT ONYX ("recall 5/5", "zero FP", "beats Hadrian")
that is itself an inference dressed as proof. No surveyed tool — Hadrian, Salt, Akto
— attaches a falsifiable epistemic tier to its own output: Hadrian says "3 BOLA in
crAPI" (true, unstamped); Salt claims "98.9% accuracy" (an unfalsifiable marketing
number). ONYX is the only one that, by construction, refuses to let its own output
out-run its evidence. That self-applied discipline is itself evidence the thesis is
real — and it neutralises the one attack that could end the project.

## How it was built (analysis 3 sessions, execution 3 sessions)
1. Leak map: every surface where a false-strength claim reaches a judge (CLI summary,
   per-finding "confirmed", diagnostics, future scorer) — root cause: zero target-
   provenance notion anywhere.
2. Enforcement design: tiers on TWO axes (kind × independence), not one ladder;
   language bound to tier; the gate is a CI test, not decoration.
3. Red-line trial: tier must be DERIVED from declared facts, default humble, self-
   applied (anti-hypocrisy), and the "zero-FP" claim decomposed into 3 tiers.
4-6. Built evidence.py, integrated additively, mutation-tested the grader (8/8).

## Mechanism
A finding's tier is DERIVED from the target's provenance (declared once on the
scope) + confirmation status — never chosen. The SAME confirmed finding is T2 on a
self-built target and T1 on crAPI, automatically. The "zero false positives" claim
is decomposed: T4 (by construction) + T2 (observed on the demo) + T3 (independent
rate pending). assert_no_bare_metrics fails the build on any untiered metric; the
project's headline claims live in a sealed manifest CI re-grades.

## Files
- authpath/evidence.py (NEW): tiers, pure grader, Claim, fp-decomposition, ledger,
  sealed ClaimManifest, no-bare-metrics gate, strongest-honest-claim.
- authpath/scope_guard.py: ScopeConfig.target_provenance (default 'self', humble).
- authpath/engine.py: engine.evidence_report() (additive, non-mutating, self-applied).
- CLAIMS.md (NEW): judge-facing headline claims, tier-clean, CI-gated.
- tools/mutate_evidence.py; tests/test_evidence.py (12) + test_evidence_integration.py (6).

## Red lines
RL1 tier derived from declared facts, never inferred. RL2 grade() is a pure
function. RL5 unknown provenance → humblest tier (can only under-claim by accident).

## Verification
- 18 evidence tests (12 unit + 6 integration incl. the self-applied demo audit and
  the CLAIMS.md gate) green; mutation score 8/8 on the grader/enforcement.
- 419/419 total (401 from P1 + 18) — zero regression.
- Demo byte-identical: 39/39, 19 findings, 3 dropped. Live self-audit: all 19 demo
  findings stamped T2, FP claim decomposed, zero over-claims. evidence.py is imported
  by nothing in the live path, so the calibration is untouched.

## Honest boundary
P8 guarantees nothing is presented above its true tier and emits the strongest
defensible claim. It does NOT manufacture T1 evidence — that is P0. After P8, the
headline is: precision by construction (T4), calibration self-measured (T2),
independent measurement the declared next step.
