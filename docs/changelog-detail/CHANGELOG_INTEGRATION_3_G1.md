# CHANGELOG — INTEGRATION #3: G1 out-of-band channels wired into act_bridge (2nd-order leak)

## What
`authpath/act_bridge.py` gains `confirm_field_leak_oob(...)` — a live second-order
out-of-band leak confirmer. This is the THIRD and final built gap-module wired to
a conviction path. **All of G14, G2, G1 are now live** (no more shelf modules).

## The bug it catches
A leak that surfaces NOT in the direct response but in an out-of-band artifact the
attacker triggers: an exported file, a webhook callback, an email, or an audit feed
that leaks the OWNER's private field. This is the class `authz_drift` wall #4
declared out of scope and ONYX previously scored zero recall on.

## How three modules chain
- **G14 (nonce)**: mint a unique token, embed it in the triggering action; any
  artifact carrying it is provably THIS test's.
- **G1 (channel)**: poll the OOB sink over a settling window.
- **cross-principal**: the OWNER's real datum for the hidden field must appear in
  that same attributed artifact → a genuine cross-principal leak.
A finding requires BOTH the nonce AND the owner's datum in one payload.

## FP gate
- A-0 no authority/seeker wired → abstain.
- owner datum captured via the audited `_read`; empty → abstain (no discriminator).
- nonce present but owner datum absent → abstain (attribution ≠ leak).
- owner datum present but nonce absent → abstain (un-attributable; could be
  background data).
- bounded settling poll; timeout → abstain.

## Safety (No-Regression Invariant)
- Additive only: new method; `confirm_field_leak` untouched.
- Full suite **610 → 614**, 0 failures, 0 import errors.
- Reversible.

## Verification
- Integration suite: 4/4 — confirm on nonce+owner-datum; abstain on owner-datum-
  without-nonce, nonce-without-owner-datum, and no-authority.

## Milestone
All three gap-modules built in this series are now integrated into live conviction
paths:
  * INTEGRATION #1 — G14 → mass-assignment attribution (kills pre-existing-value FP)
  * INTEGRATION #2 — G2  → object-binding-drift oracle (deterministic 412 window)
  * INTEGRATION #3 — G1  → second-order OOB leak (export/webhook/email/audit)
Test count 570 → 614 across the series, 0 failures throughout, zero-FP preserved.

## Honest remaining scope
- These are opt-in methods: a caller wires an authority/channel and calls them.
  Making the top-level engine construct ActBridge WITH an authority and drive
  these paths under a run-flag (so a normal run exercises them) is the next
  meaningful step.
- Real I/O adapters (HTTP export fetch, OAST provider client, IMAP reader) still
  need to back the OOB channels for live targets; the confirmation logic they feed
  is complete and tested.
