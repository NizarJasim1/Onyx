# CHANGELOG — GAP-8 (law<->state driving) + GAP L1-8 (ownership pinning at scale)

One seam: **reaching AND pinning the state a law needs to fire.** GAP-8 drives the target
TO a required state; GAP L1-8 pins ownership in time so a multi-step drive cannot confirm
against a boundary that drifted under it.

## GAP-8 — `authpath/state_driver.py` (`LawStatePlanner`, `Primitive`, `DrivePlan`)
Closes the one part `completeness.py` names as genuinely open ("can we drive the system
into every violating state?") and that `composite_sequences` leaves as a non-executable
`requires_writes=True` worklist.
- Binds a law L to the state S it requires and composes **consent-gated** primitives into
  an EXECUTABLE ordered reach plan (deterministic forward chaining): e.g.
  create_order → pay_partial → open_refund → now the context-dependent BAC is reachable.
- **RL5:** only consent-gated primitives are usable; a non-consented one is refused and
  named, never silently included.
- **Honest unreachability:** if S can't be reached, the planner says so and NAMES the
  missing facts — a bounded, stated residual, not a false "covered".
- `required_facts_from_prior_state` adapts `state_machine.prior_state_requirements` so the
  driver consumes what the existing layer-E machine already emits.
- The plan is a LEAD; the law still fires through the deterministic Δstate confirmation (RL3).

## GAP L1-8 — `authpath/state_pin.py` (`OwnershipLedger`, `Pin`, `DriveStabilityGuard`)
- Pins `(object_ref → owner, logical token)` when ownership is established (e.g. at object
  creation during a drive), zookie/snapshot style, so confirmations ride a STABLE snapshot
  on a giant with thousands of churning objects.
- A confirmation on a dynamic object is sound only if the live owner still matches the pin;
  any drift ⇒ UNSTABLE ⇒ ABSTAIN. Kills the named FP source (consistency drift under a
  multi-step plan) — precision first.

## Verification (external oracles — AMP)
- `tests/run_all.py`: **789/789 PASSED, 0 FAILED, 0 IMPORT_ERRORS** (was 782; +7 new).
- `demo_live.py`: **precision 1.000, 0 false positives at every chaos level** — unchanged.
- Off the detection decision path (generation/sequencing + a fail-safe stability gate);
  no `EffectClass`/oracle/remediation change. Red lines held.

## Honest scope
Planner and pin proven on self-authored multi-step scenarios (Tier-2 / AMP E2). Executing
a real drive against a live authorized target is the operator's run (T1).
