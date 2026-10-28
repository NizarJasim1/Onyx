# CHANGELOG — INTEGRATION #4: engine wires the nonce authority (run-flag)

## What
`authpath/engine.py` now, when `stateful_attribution` is enabled, builds the BvA
ActBridge WITH a ledger-tied `NonceAuthority` + `NonceSeeker`, and routes the
mass-assignment confirmation to the G14-attributed variant when the object carries
a free-text companion field. Flag OFF (default) ⇒ byte-identical to before.

This moves G14 from "opt-in method a caller must invoke" to "exercised by a normal
engine run" (with the flag), closing the last gap between built capability and
active capability for the mass-assignment path.

## Changes
1. `__init__`: new `self.stateful_attribution = False` flag + lazy
   `_nonce_authority` / `_nonce_seeker` holders (one authority per engine, tied to
   the tamper-evident ledger).
2. `_bva_channel()`: builds `ActBridge(..., nonce_authority, seeker)` when the flag
   is on; otherwise the exact legacy `ActBridge(confirmer, by_identity)` call.
3. mass-assignment call site: when a free-text companion field is present, use
   `confirm_mass_assignment_attributed`; **never fall back to the semantic-only
   check once the attributed path ran** (that would re-introduce the
   pre-existing-value false positive the attributed path exists to kill).

## Safety (No-Regression Invariant)
- Flag OFF ⇒ byte-identical: full suite **614 → 617**, 0 failures (the +3 are the
  new wiring tests; the pre-existing 614 are unchanged).
- The FP-safety subtlety was caught and fixed: no legacy fallback after the
  attributed path runs.
- Reversible: remove the flag + the two conditional blocks.

## Verification
- Wiring suite: 3/3 — flag OFF ⇒ no authority; flag ON ⇒ ledger-tied authority,
  minting unique + recognised; authority is a per-engine singleton.
- Full suite: **614 → 617**, 0 failures, 0 import errors.

## Honest remaining scope
- **Fully end-to-end now (with the flag):** G14 mass-assignment attribution — a
  normal engine run exercises the attributed path and its FP-kill.
- **Reachable but not yet auto-driven:** G2 drift (`confirm_action_conditional`)
  and G1 OOB (`confirm_field_leak_oob`) are constructible (the bridge has the
  authority) but the engine does not yet feed them `drift_marker` / `channel` /
  `trigger`. Driving them from the pipeline needs: (a) capturing a drift marker
  from the mutating request for G2, and (b) real OOB I/O adapters (HTTP export
  fetch, OAST client, IMAP) for G1. Their confirmation logic is complete and
  tested; only the pipeline feed + live I/O remain.
