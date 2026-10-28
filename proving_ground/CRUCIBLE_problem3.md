# CRUCIBLE — problem #3: BFLA (broken function-level authz) is invisible

## LOOP 1 — TRIPLE-DIAGNOSE (converged)
- TD1: planted bfla_method_escalation at doc:4 — a non-owner member DELETE returns 200.
- TD3 principle: the conserved law is broadcast-vs-act on the ACTION channel — the
  declaration gates the action to the owner (clean doc:3 non-owner DELETE → 403), but the
  act executes it (doc:4 non-owner DELETE → 200). Clean contradiction.
- TD2: nerve 1 = read-BOLA; bva = read field-leak. NEITHER tests a MUTATION against its
  declaration. BFLA is invisible. Confirmed gap.

## LOOP 2 — KILL-THE-PROBLEM (BFLA = action-channel BvA, partially built; two precise gaps)
- KP2 (one problem or several?): BFLA IS a Broadcast-vs-Act instance on the ACTION channel.
  Partially built already:
    * act_confront.py GENERATES hidden_action confrontations (delete→DELETE) with the
      scope gate (DELETE blocked unless armed). ✓
    * act_bridge.py confirms hidden_FIELD only — NO confirm_action (the mutation half). ✗
    * the proving ground emits NO _links action declaration → nothing to key on. ✗
- KP1/KP3 (the FP trap + a NEW precise finding): when the proving-ground-style response
  DOES declare actions (_links: owner has delete/edit, non-owner has self only), the
  broadcast extractor reads them correctly — BUT broadcast_difference_candidates() returns
  0, because its FP guard requires a ROLE difference (or explicit 403), and here the two
  principals are the SAME role (both member) differing by OWNERSHIP. The guard, tuned for
  FIELD differences (avoid feature-flag FP), is TOO STRICT for ownership-tied ACTION
  differences → it suppresses the valid BFLA candidate before it is ever confronted.
  This is safe to relax for actions because candidates never convict (the act + Δstate
  decide); the relaxation only lets a valid candidate through.

## LOOP 2 VERDICT — the three precise build pieces (loop 3, next session)
1. BROADCAST GUARD REFINEMENT (delicate — must not reintroduce field FP): allow an ACTION
   difference as a candidate when it is OWNERSHIP-tied (one principal is the declared owner
   via owner_id, the other is not), even at the same role. Keep the field-difference guard
   exactly as is (role-difference / explicit-403) to preserve zero field FP. Scope the
   relaxation to actions_only_* deltas, never to fields_only_*.
2. act_bridge.confirm_action(conf, ...): for a hidden_action confrontation, execute the
   mutation ONLY when scope.may_mutate allows (armed); confirm via Δstate (the action
   executed: 2xx + the object's state changed / it is gone on re-read). Abstain when
   scope-blocked (default dry_run) — BFLA confirmation is inherently operator-consented and
   destructive, so default-abstain is correct and safe. Reuse the audited gate; never force.
3. PROVING GROUND: emit _links per object (owner gets delete/edit, non-owner gets self),
   so the action declaration exists to test against. Then wire confirm_action into
   bva_findings, run on the proving ground with an ARMED scope (the proving-ground DELETE is
   a harmless stub), score: BFLA at doc:4 caught, clean docs abstained, zero FP.

## SAFETY NOTE
BFLA confirmation executes a real mutation, so by design it only runs on an AUTHORIZED
target with the operator explicitly arming allow_destructive. Default behavior = abstain.
This is not a limitation to "fix" — it is the zero-harm red line.

## STATUS
Loops 1-2 DONE (by running). Build (loop 3, three pieces above) deferred to protect the
project at 359 green — the guard-refinement touches the FP-sensitive broadcast path and
must be built with a cold mind + field-FP regression, not rushed at session end.

## LOOP 3 — FORGE-HARDEST (DONE) — BFLA detection built, three pieces
1. BROADCAST GUARD REFINEMENT (broadcast.py): added `is_owner` to PrincipalBroadcast
   (a body value == accessor identity) + an ownership-tied ACTION path in
   broadcast_difference_candidates — an action difference between the declared owner and a
   non-owner is a candidate even at the SAME role, but FIELD deltas are zeroed on this path
   so the field FP guard is untouched (verified: same-role field diff still 0 candidates).
2. act_bridge.confirm_action: confirms a hidden_action by executing the mutation through
   the scope-gated path. ZERO-HARM FIX (found by the dry_run test): _read only checks
   host/path, NOT the mutation policy — so confirm_action now calls scope.may_mutate FIRST
   and abstains unless armed. Default dry_run ⇒ no mutation, abstain.
3. engine.bva_findings: wired the action-confrontation path (owner-withheld actions → the
   non-owner attempts them → confirm_action).

## LOOP 4 — RE-MEASURE-CRUEL (DONE) — PASSED
Proving ground with _links action declaration (owner→delete/edit, non-owner→self):
  ARMED scope  : caught the planted BFLA at doc:4 (u-alice non-owner DELETE), and ONLY
                 doc:4 — zero FP on clean docs.
  DRY_RUN scope: 0 findings — the mutation is gated, nothing executed (zero-harm red line).
Suite 359→363 (4 new BFLA tests incl. the dry_run-abstain safety pin); demo byte-identical.

## PROBLEM #3 — RESOLVED
BFLA is now detectable as a Broadcast-vs-Act action-channel instance: declaration =
the action links the target offers the owner but withholds from the non-owner; act = the
non-owner executing it anyway; confirmed by live Δstate ONLY when the operator arms
destructive testing on an authorized target. Permanent regression: tests/test_bfla_action.py.
The zero-harm safety hole (mutation under dry_run) was found by the cruel re-measure and
fixed — exactly what CRUCIBLE exists to do.
