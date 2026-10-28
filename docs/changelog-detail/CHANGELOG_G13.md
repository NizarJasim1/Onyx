# CHANGELOG — G13: Volatile-projected stability voting (recall under chaos)

## What
`authpath/confirmer.py` gains an optional `stability_strip_volatile` flag and a
`_quorum_key` projection. When stability voting (`stability_k>1`), well-known
volatile scaffolding fields are projected OUT before the quorum key is computed, so
transport noise cannot break an otherwise-stable security verdict and cost recall.

## Why
The RL24 stability vote keyed on `(status, FULL body)`. Under chaos, bodies carry
volatile fields (timestamps, trace ids, etags, counters) that differ on every read
even when the security-critical value is perfectly stable — so the vote never
reached the 80% quorum and ONYX abstained. That is the recall cliff (~0.94 → ~0.80
under heavy chaos). G13 votes on the security-relevant projection instead.

## Mechanism (attack the cause)
`_quorum_key(r)` computes the vote key. Under the flag, `_strip_volatile` removes a
CONSERVATIVE, fixed allowlist of universally-volatile field NAMES (created_at,
updated_at, timestamp, trace_id, etag, nonce, iat/exp, rate-limit counters, …)
recursively, then keys on `(status, projected-body)`. Security-relevant fields
(id/owner/role/amount/email/tenant/…) are NEVER in the allowlist, so they are always
voted on.

## FP gate (S-1..S-5) — zero-FP preserved
- S-1 the volatile allowlist is conservative and fixed; nothing security-relevant
  is ever stripped.
- S-2 the ≥80% strong-quorum threshold is UNCHANGED — G13 changes WHAT is voted on,
  not HOW strict.
- S-3 `status` is always part of the key — a status flip is never masked.
- S-4 default-OFF (`stability_strip_volatile=False`) ⇒ `_quorum_key` is byte-
  identical to the previous inline `(status, full body)` key.
- S-5 if stripping would empty a non-empty body, fall back to full-body voting —
  never vote on an empty (always-agreeing) key.

## Verification
- New falsification suite: 7/7 — proves the baseline recall loss exists; proves G13
  recovers the stable security verdict; proves a real security-field flap STILL
  abstains; proves a status flip STILL abstains; proves the S-5 empty-body fallback;
  proves default-OFF is byte-identical.
- Full project suite: **631 → 638**, 0 failures, 0 import errors — the confirmer
  core was modified and every existing test stayed green.

## Effect
Recovers recall lost to transport/volatile noise under chaotic targets (the ~0.14
gap the gap-catalog flagged for G13) without touching precision: real instability
and status changes still correctly abstain.
