# CHANGELOG — INTEGRATION #1: G14 nonce attribution wired into act_bridge (mass-assignment)

## What
`authpath/act_bridge.py` now accepts an optional `nonce_authority` + `seeker`
(default `None` → legacy behavior byte-identical) and gains a new method
`confirm_mass_assignment_attributed(...)`. This is the FIRST real wiring of a
built gap-module (G14) into a live conviction path — moving it from shelf code
to actual detection value.

## Why this matters (Anti-Patch: don't accumulate dead modules)
G14/G1/G2 were built and tested in isolation but default-OFF, so recall had not
actually risen. This integration makes G14 do real work: it strengthens the
mass-assignment (write-side BOPLA) proof with cryptographic attribution.

## The concrete win: a real false-positive class is killed
The legacy M-4 check confirms when `readback[field] == privileged_value` (e.g.
"admin"). That cannot distinguish OUR successful write from a PRE-EXISTING "admin",
a shared default, or another tester's write. The attributed path stamps a unique
nonce into a free-text companion field in the SAME write and requires BOTH:
  * the privileged value stuck (write-side BOPLA), AND
  * our exact nonce present on read-back (proves THIS test's write landed).
Test `test_preexisting_admin_is_NOT_a_false_positive` proves it: a server that
already shows `role=admin` but IGNORES our write yields NO nonce → abstain, where
the old check could have false-positived.

## Safety (No-Regression Invariant — all four clauses)
- Zero-FP strengthened, not relaxed: the attributed path is STRICTER (nonce required).
- No regression: additive only (optional ctor args + new method); the existing
  `confirm_mass_assignment` is untouched. Full suite **601 → 605**, 0 failures.
- No hidden debt: opt-in; with no authority wired the new method abstains explicitly
  and all legacy callers are byte-identical.
- Reversible: remove the two ctor args + the new method; nothing else depends on them.

## Guards in the attributed path
- A-0 no authority/seeker wired → abstain (never silently downgrade).
- C-1 companion must be a genuine free-text field (choose_strategy) → else abstain
  (never plant a nonce into a constrained/enum field and break the write).
- M-1..M-4 provisioning / scope-gate / write-read / attributed-stick, each abstaining.

## Verification
- Integration suite: 4/4 (confirm, FP-kill, no-authority abstain, constrained-companion refuse).
- Full project suite: **601 → 605**, 0 failures, 0 import errors.

## Still shelf (honest scope)
- G1 (OOB channels) and G2 (ETag oracle) remain built-but-unwired; their
  integrations are the next passes (engine must plant OOB nonces during drift
  probing for G1; capture check-response ETags for G2).
- The engine's top-level driver does not yet construct ActBridge WITH an authority
  by default — a caller opts in by passing one. Making the engine wire it under a
  run-flag is a small follow-up.
