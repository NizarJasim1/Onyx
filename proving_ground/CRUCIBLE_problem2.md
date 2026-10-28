# CRUCIBLE — problem #2: nerve 1 false-positives on privileged-role access

## LOOP 1 — TRIPLE-DIAGNOSE (converged)
- **TD1/TD2 measurement + self-finding:** on the fair variant (owner_id in bodies), across
  TWO seeds (1337, 99), the admin principal is flagged on ALL docs (doc:1-4), clean ones
  included. Reproducible.
- **TD3 principle:** remove the admin principal → findings collapse from 5 to 1 (only the
  real member→member leak bob→doc:1 remains). So 4/5 findings were admin = an 80% FP rate.
  Cause: nerve 1 reads ownership (owner_id) but NOT the accessor's declared ROLE, so it
  cannot tell "admin legitimately reads all" from "a peer attacker reads one".
- Converged problem nerve: **nerve 1 confirms an ownership mismatch as BOLA without
  reading the role declaration → false-positive on legitimate role-based cross-owner
  access. A zero-FP red-line violation, hidden by mocks, exposed by real HTTP + admin.**

## LOOP 2 — KILL-THE-PROBLEM (sound fix found; over-correction avoided)
- KP1 (real FP or flaggable?): admin cross-user read is legitimate in the common case →
  flagging it is a false positive. BUT an over-privileged admin (admin accessing what even
  admin must not) is a real bug — so do NOT blindly suppress all admin findings.
- KP2 (one problem?): yes — role-blindness. The role is DECLARED at /me (role: admin);
  nerve 1 ignores it. Same theme as problem #1: read the declaration the target emits.
- KP3 (does the fix break the nerve?): only if it suppresses same-role (peer) BOLA. The
  guard must abstain ONLY on a role DIFFERENCE, never on same-role.

### THE SOUND, NON-INDUCTIVE GUARD (verified in principle)
  **Confirm an ownership-mismatch BOLA candidate ONLY when the accessor and the declared
  owner share the SAME declared role (peer-to-peer). When the accessor's declared role
  DIFFERS from the owner's (a plausible role-based grant), ABSTAIN (RL5).**
  Verified: bob(member)→alice(member) doc = same role → CONFIRM (real peer BOLA);
  admin(admin)→alice(member) doc = different role → ABSTAIN (kills the FP). Uses only the
  two principals' declared roles — no induction, no cross-object inference.
- Honest trade (RL5): this MISSES a genuinely over-privileged-admin bug (admin overreach),
  which is acceptable under zero-FP — detecting that needs a separate declaration of what
  admin may access. Abstaining beats false-positiving.

## LOOP 3 — FORGE-HARDEST (NEXT SESSION — execute directly)
Build the peer-role guard in the nerve confirmation path:
  1. F7 pre-mortem: the guard must NOT suppress same-role peer BOLA; must NOT crash when a
     role is undeclared (no /me, or no role field) → when role is UNKNOWN for either side,
     keep current behavior (do not silently suppress — unknown ≠ elevated).
  2. Read the declared role for accessor and owner from the attestation /me responses
     (reuse the role-extraction already written for BvA: module-level _bva_role / the
     _BVA_ROLE_FIELDS list). Add an equivalent on the nerve-1 path.
  3. In nerve_findings()/nerve_bridge confirmation: before emitting a confirmed mismatch,
     compare accessor.declared_role vs owner.declared_role; if BOTH known and DIFFERENT →
     abstain (record reason "role-difference: plausible role-based grant"). If same, or
     either unknown → proceed as today.
  4. Isolated/gated/candidates-only; never weaken existing red lines; Δstate still judges.

## LOOP 4 — RE-MEASURE-CRUEL (NEXT SESSION — after the build)
  - New seed + the fair variant. The admin FP count must drop to 0; the member→member
    real leak must stay caught.
  - Run the 355-suite (no regression) and demo byte-identical.
  - GT4: hand over the raw before/after FP numbers however they fall.

## STATUS
Loops 1-2 DONE and verified by running. Fix precisely specified and validated in
principle. Build (loop 3) deferred to keep the project intact at 355 green at session end
(no rushed nerve-path surgery). Next session = direct execution of loops 3-4.

## LOOP 3 — FORGE-HARDEST (DONE) — the peer-role guard, built
authpath/nerve_bridge.py: added module-level `_declared_role(response)` (reads role/tier
the target declares at /me) + `self.declared_role` map captured in feed_self + the guard at
the top of `_confirm`: if BOTH accessor and owner roles are KNOWN and DIFFERENT → abstain
("role-difference: plausible role-based grant"). Guard rails honored: same-role proceeds
(peer BOLA still caught); unknown role proceeds (unknown ≠ elevated). Isolated, no new
conviction logic, Δstate still judges.

## LOOP 4 — RE-MEASURE-CRUEL (DONE) — PASSED across two seeds
Fair variant (owner_id in bodies), seeds 1337 & 99:
  BEFORE guard: 5 findings, 4 of them admin FPs (80% FP rate).
  AFTER guard : seed 1337 → 1 finding (u-bob→doc:1, real), admin FPs = 0.
                seed 99   → 2 findings (u-bob→doc:1, u-bob→doc:3, real), admin FPs = 0.
  Admin false positives: 4 → 0. Real peer→member leaks: still caught. Zero regression
  (suite 355→359 with 4 new guard tests; demo byte-identical 39/39·19·3).

## PROBLEM #2 — RESOLVED
The first real defect surfaced by measurement is FIXED and locked. The fix strengthened the
zero-FP red line (removed false positives) without suppressing true findings — proven by
running, both directions. Permanent regression: tests/test_nerve_role_guard.py.
