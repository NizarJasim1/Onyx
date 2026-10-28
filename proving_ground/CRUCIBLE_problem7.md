# CRUCIBLE — problem #7 (GT3): verb-tunneling BFLA was invisible

## LOOP 1 — TRIPLE-DIAGNOSE
- TD1: a doc whose PLAIN DELETE is gated (non-owner → 403) but whose POST +
  X-HTTP-Method-Override: DELETE bypasses the gate (→ 200) — a verb-tunneling BFLA.
- TD2: the BFLA detector caught only the plain-DELETE BFLA; the tunnel bypass was MISSED.
- TD3 (root): confirm_action confirmed via the PLAIN verb only — on 403 it abstained
  ("declaration honored") and never tried the tunnel. The detector MEMORIZED the plain
  vector; it did not generalize across the delivery vector.

## LOOP 2 — KILL-THE-PROBLEM (RL1-safe generalization)
The ACTION ('delete') is quoted from the broadcast (owner has the delete link, non-owner
does not). Only the DELIVERY VECTOR varies. Trying the bounded, standard set of verb-tunnel
headers (X-HTTP-Method-Override / X-HTTP-Method / X-Method-Override) delivers the SAME
quoted action — confrontation expansion, not induction. FP/safety: still scope-gated
(armed-only), still requires a 2xx on a declared-withheld action.

## LOOP 3 — FORGE-HARDEST (DONE)
act_bridge.confirm_action: when the plain verb is denied, call _try_verb_tunnels — for each
standard override header, build a POST that smuggles the real method, gate it via
scope.may_mutate (HALT under dry_run ⇒ skip = zero-harm), execute; a 2xx convicts as a
verb-tunneling BFLA. The action is never changed, only the vector.

## LOOP 4 — RE-MEASURE-CRUEL (DONE) — PASSED across two seeds
Proving ground: do_POST honours ownership on the tunnel for every doc EXCEPT the planted
tunnel_bfla doc (gate bypass there only).
  seed 1337: plain-BFLA doc:4 CAUGHT + tunnel-BFLA doc:3 CAUGHT, zero FP on clean docs.
  seed 99  : plain-BFLA doc:2 CAUGHT + tunnel-BFLA doc:4 CAUGHT, zero FP.
  DRY_RUN  : 0 findings (the tunnel mutation is scope-gated — zero-harm).
Suite 375→378 (3 new tunnel tests); demo byte-identical.

## PROBLEM #7 — RESOLVED
The BFLA detector now GENERALIZES across the verb-tunneling vector, catching the gate-bypass
form with zero FP on docs whose tunnel correctly enforces ownership, and abstaining under
dry_run. Permanent regression: tests/test_bfla_action.py (verb-tunnel cases).
