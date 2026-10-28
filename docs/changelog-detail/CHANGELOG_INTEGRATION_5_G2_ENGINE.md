# CHANGELOG — INTEGRATION #5: engine drives the G2 object-binding-drift oracle

## What
`authpath/engine.py` gains `_bva_drift_probe(...)`, called from the BvA
owner-withheld-action loop. When `stateful_attribution` is on and an owner is
known, the engine stamps a unique marker into a conditional write and delegates to
the tested `confirm_action_conditional` (G2 ETag/If-Match oracle). This wires G2
into a live engine path, mirroring INTEGRATION #4 for G14.

## Design
- Extracted into a directly-testable method (falsifiable, per the Anti-Patch Gate)
  rather than an inline block.
- Additive + flag-gated: no-op unless a nonce authority is wired AND an owner is
  known → byte-identical when off.
- Zero-harm: the conditional write is scope-gated inside `confirm_action_conditional`
  (dry_run ⇒ abstain).

## Safety (No-Regression Invariant)
- Flag OFF ⇒ byte-identical: full suite **617 → 621**, 0 failures (the +4 are the
  new wiring tests; the pre-existing 617 unchanged).
- Reversible: remove the method + its one call site.

## Verification
- Engine-wiring suite: 4/4 — confirm (window+drift), abstain (no window), no-op
  (no authority), no-op (no owner) — all through the engine's own authority against
  a fake ETag+drift target.
- Full suite: **617 → 621**, 0 failures, 0 import errors.

## Honest boundary (the network wall)
- G2 is now ENGINE-WIRED and validated offline against a fake ETag+drift target.
- LIVE activation additionally requires: (a) an ARMED scope (not dry_run) on an
  authorized target, and (b) real ETags + a genuine re-bind window — which needs
  network and a target that exhibits the TOCTOU. Those cannot be validated in this
  sandbox (no egress); the confirmation + wiring logic is complete and tested.

## Series status (recall-gap modules)
- G14 — built, integrated (#1), engine-driven (#4). Fully live with the flag.
- G2  — built, integrated (#2), engine-driven (#5). Engine-wired; live needs network.
- G1  — built, integrated (#3). Needs real OOB I/O adapters (HTTP/OAST/IMAP) to go
  live; confirmation logic complete and tested.
