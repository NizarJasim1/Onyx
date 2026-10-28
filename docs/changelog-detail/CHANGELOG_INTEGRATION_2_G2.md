# CHANGELOG — INTEGRATION #2: G2 ETag/If-Match oracle wired into act_bridge (drift)

## What
`authpath/act_bridge.py` gains `confirm_action_conditional(...)` — a live
object-binding-drift (TOCTOU-of-authorization) confirmer that uses the G2
ETag/If-Match oracle as a deterministic instrument. Second built gap-module now
does real work on a conviction path.

## Flow
1. read the resource AS THE ATTACKER → capture a STRONG ETag (E-0).
2. issue the mutation with `If-Match:<etag>` (E-1), zero-harm scope-gated.
3. interpret the status (proxy-aware): 412 ⇒ VERSION_CHANGED = re-bind window
   FIRED; anything else ⇒ abstain (E-2/E-3).
4. read the resource AS THE OWNER; a finding requires the attacker's write
   (`drift_marker`) to be present in the OWNER's view — the effect drifted onto
   the victim's object (E-4). Otherwise abstain (observation ≠ finding).

## Correctness preserved
- Weak ETag ⇒ abstain (no unreliable If-Match).
- 412 behind a fronting proxy ⇒ indeterminate ⇒ abstain (never confirm on a
  possibly-spurious ALB/CDN 412).
- Zero-harm mutation gate (`scope.may_mutate`) enforced before any write.

## Safety (No-Regression Invariant)
- Additive only: new method; legacy `confirm_action` untouched.
- Full suite **605 → 610**, 0 failures, 0 import errors.
- Reversible: delete the method; nothing else depends on it.

## Verification
- Integration suite: 5/5 — confirm on window+landing; abstain on 2xx (no window),
  on window-without-cross-principal-landing, on weak ETag, and on proxy-412.
- Observation ≠ finding is enforced by two independent abstain paths.

## Progress state
- LIVE now: G14 (attribution, integration #1) + G2 (drift oracle, integration #2).
- Still shelf: G1 (OOB channels) — needs the engine to plant OOB nonces during
  drift probing and poll real channels.
- The engine's top-level driver still opts in by calling these methods with the
  right args; wiring them into the default run path under a flag is a follow-up.
