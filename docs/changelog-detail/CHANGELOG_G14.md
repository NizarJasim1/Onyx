# CHANGELOG — G14: Nonce Provenance (cross-channel attribution)

## What
New module `authpath/nonce_provenance.py` + falsification suite
`tests/test_nonce_provenance_g14.py` (10 tests). Closes gap **G14** from the
stateful-authorization-drift gap catalog: deterministic, cross-channel
attribution of a planted effect to *this* test.

## Why
The prior "did my effect land?" check (`act_bridge` M-4) compares a read-back
value against a SEMANTIC constant (`got == "admin"`). That is ambiguous as
attribution — a pre-existing value, a shared default, or a second test can all
satisfy it — and it cannot survive an async / out-of-band boundary (an effect
surfacing in a CSV export or webhook later). G14 replaces heuristic attribution
with a minted, high-entropy (122-bit uuid4), self-identifying nonce whose later
appearance ANYWHERE is proof-by-construction that this test caused it.

This is the FOUNDATION for G1 (OOB channels), G7 (idempotency replay) and G8
(deep second-order), none of which can be built soundly without bullet-proof
attribution. The `NonceSeeker.seek(payload, channel)` interface is channel-
agnostic by design so those gaps plug straight in.

## Design guarantees (Anti-Patch Gate + No-Regression Invariant)
- **Field-type aware planting** (`choose_strategy`): PURE_TEXT for free-text
  fields, HYBRID_COMPANION for constrained/enum fields (write the semantic value
  AND stamp a nonce into a free-text sibling), ISOLATION as last resort, else
  ABSTAIN. This prevents the regression of writing `role="ONYX-…"` (invalid enum
  → failed write → false negative).
- **Attribution ≠ authorization**: the nonce proves the effect landed; the
  cross-principal read-back stays an INDEPENDENT requirement
  (`attributed_stick_check` abstains when cross-principal is unproven).
- **FP gate (P-0..P-4)**: pre-plant absence check; exact full-entropy match only
  (no prefix/substring); only self-minted tokens attributable; attribution alone
  is never a finding.
- **Default-OFF / reversible**: nothing calls it yet, so behavior is byte-
  identical to before; the legacy M-4 path is untouched.

## Verification
- New falsification suite: 10/10 pass.
- Full project suite: **570 → 580**, 0 failures, 0 import errors (the pre-existing
  570 are unchanged — no regression).

## Not yet wired (honest scope)
- `act_bridge` M-4 is NOT yet switched to `attributed_stick_check` (integration
  step deferred to avoid touching a tested path here).
- ISOLATION strategy exposes its interface but needs a fresh-victim-object
  provider (arrives with G8).
- Real OOB listeners (file/webhook/email) are G1; G14 provides their foundation
  and the exact-match oracle they will call.
