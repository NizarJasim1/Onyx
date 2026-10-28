# CHANGELOG — G1: Out-of-Band Channels (confirm effects outside the direct response)

## What
New module `authpath/oob_channels.py` + falsification suite
`tests/test_oob_channels_g1.py` (9 tests). Closes gap **G1**: confirming
second-order authorization leaks that surface in an EXPORTED FILE, a WEBHOOK,
an EMAIL/notification, or an AUDIT-LOG feed — never in the direct response.

## Why
All prior confirmation reads the direct response to the mutating request. The
OOB second-order class (`authz_drift` wall #4) never appears there, so ONYX
abstained and the class scored zero recall. This is the single largest recall
gain in the gap catalog.

## Mechanism (built on G14)
The class collapses to one abstraction — a **Channel** you poll over a settling
window that yields payloads to seek nonces in. Direct read-back is the degenerate
synchronous case; export/webhook/email/audit are the same shape. Attribution is
G14's exact-match nonce, reused verbatim (`NonceSeeker.seek`), which is what makes
OOB safe: an artifact is attributable only if it carries the exact minted token.

Concrete channels (`ExportFileChannel`, `OASTChannel`, `MailboxChannel`,
`AuditFeedChannel`) each wrap an INJECTED I/O callable — the engine wires real I/O
(HTTP GET the export, poll interactsh/Collaborator, IMAP the mailbox); tests inject
fakes. No network in the module, stdlib-only, deterministic.

## FP gate (Q-0..Q-4)
- Q-0 bounded poll; settling-window timeout → abstain (never infer from absence).
- Q-1 exact full-entropy nonce match (inherited G14 P-1).
- Q-2 a finding requires nonce AND a distinct victim-owned datum in the SAME
  payload; either alone → abstain.
- Q-3 victim datum must be discriminating and not the nonce itself.
- Q-4 default-OFF; unused ⇒ byte-identical behavior.

**Attribution ≠ authorization**: the nonce proves the artifact is ours; the
cross-principal leak requires the victim's discriminating datum in that same
artifact. Both are required.

## Verification
- New falsification suite: 9/9 pass (incl. late-arrival within window, foreign
  nonce never attributes, nonce-without-leak abstains, leak-without-nonce abstains).
- Full project suite: **580 → 589**, 0 failures, 0 import errors (no regression).

## Not yet wired (honest scope)
- Real I/O adapters (HTTP export fetch, OAST provider client, IMAP reader) are
  engine-integration steps; this module provides the channels and the confirmation
  logic they feed.
- The engine does not yet auto-plant OOB nonces during drift probing; that wiring
  connects G14 planting → G1 channels in a later integration pass.
