# CRUCIBLE — problem #10 (GT3): mass-assignment WRITE — the first write-side capability

## LOOP 1-2 — DIAGNOSE + KILL
Shape: a member sends PATCH /api/me {is_admin:true} (a privilege-bound field) and it STICKS
on read-back. Every prior detector is READ-side; this is a WRITE bug.
- Declaration (non-inductive): the field is ROLE-TIED — in observed self-bodies its
  privileged value appears ONLY for a privileged role and a different/absent value for
  members. That role↔value correlation is the target's own declaration of privilege-binding.
- FP trap: a member-settable cosmetic field (display_name) sticks but is NOT privilege-bound
  → must abstain; a write that does NOT stick (server ignored) → Δstate shows old value →
  abstain.
- Safety: the write is a MUTATION → scope-gated like BFLA; dry_run ⇒ propose-but-abstain
  (zero-harm). New primitive: write-then-read-back Δstate confirmation.

## LOOP 3 — FORGE-HARDEST (DONE)
- authpath/mass_assign.py role_tied_privileged_fields(self_bodies): selects fields whose
  privileged value is role-tied AND (name hints privilege OR value is clearly-privileged);
  excludes identity/cosmetic fields (display_name 'Admin' is NOT selected — the FP guard).
- act_bridge.confirm_mass_assignment(): PATCH {field:value} as the member (scope.may_mutate
  gate; HALT under dry_run ⇒ abstain), then GET read-back as the member; the value must
  PERSIST (Δstate) to convict. Guards M-1..M-4 (member, gate, IO, did-not-stick).
- engine.massassign_findings(): collects self-bodies per principal, detects role-tied
  fields, confirms each member's write. Separate channel; empty unless bva is on.

## LOOP 4 — RE-MEASURE-CRUEL (DONE) — PASSED
Proving ground: /api/me emits role-tied is_admin + member-settable display_name; PATCH binds
is_admin (bug) and display_name (legitimate); role is server-ignored (control).
  ARMED  : caught is_admin escalation for both members; ZERO FP on display_name (cosmetic)
           and role (did not stick → abstained).
  DRY_RUN: 0 findings — the write is scope-gated (zero-harm).
Suite 379→384 (5 new); demo byte-identical.

## PROBLEM #10 — RESOLVED
ONYX now has its FIRST write-side detector: mass-assignment, confirmed by a live write-then-
read-back Δstate, scope-gated (armed-only), with the role-tie as the non-inductive
declaration and cosmetic/non-sticking writes correctly abstaining. Permanent regression:
tests/test_mass_assignment.py.
