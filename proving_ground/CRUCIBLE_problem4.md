# CRUCIBLE — problem #4: AUTHN-gap (anonymous receives private data) is invisible

## LOOP 1 — TRIPLE-DIAGNOSE (converged)
- TD1: planted authn_anon_read at acct:4 — readable with NO token (anon GET → 200 + body).
- TD3 principle: the conserved law is "private ⇒ authenticated". anon GET acct:4 → 200
  with balance; a CLEAN account (acct:1) → 401 to anon. The act (anon 200 on a private
  resource) contradicts the declaration that accounts require auth.
- TD2: nerve1 (owner-field BOLA), bva-field (role/owner field leak), bva-action (BFLA) —
  NONE keys on the ANONYMOUS principal receiving private data. AUTHN gap invisible. Confirmed.

## LOOP 2 — KILL-THE-PROBLEM (sound, non-inductive signal found)
- KP1 FP trap: genuinely PUBLIC endpoints (anon 200 is correct — public profile, health,
  catalog). Flagging those = FP.
- KP2/KP3 the distinguisher: a per-resource PRIVATE declaration. VERIFIED sound signal:
  when the anonymous principal (no token) receives a 200 body that CARRIES AN OWNERSHIP
  FIELD (owner_id tying the resource to a real identity), the resource declares itself
  private — and anon is provably not that owner → AUTHN gap. Non-inductive (uses only the
  resource's own declaration, no cross-resource inference). ABSTAIN when the anon body has
  NO ownership declaration (could legitimately be public) — RL5.
  Empirically confirmed: with owner_id emitted in account bodies, anon GET acct:4 returns
  {id, balance, owner_id: u-bob} — the private declaration is right there in the anon view.

## LOOP 3 — FORGE-HARDEST (NEXT SESSION — execute directly)
1. PROVING GROUND: emit owner_id in account bodies (the private declaration). authn_anon_read
   is already planted (acct:4 anon-readable). Keep a PUBLIC decoy (an endpoint anon may read
   that carries NO owner_id) to prove precision.
2. DETECTOR (a new candidate path, own flag or folded into the bva channel): a candidate
   when an ANONYMOUS / unauthenticated principal receives a 200 body carrying an ownership
   field whose value is a real identity. The accessor is anon (no attested identity), so the
   existing nerve-1 attestation path skips it — this needs an explicit anon-accessor path.
3. CONFIRM by Δstate: read the same resource AS the declared owner; the anon body must carry
   the owner's real private datum (value match), proving anon received owner-scoped private
   data — not a coincidental public field. Abstain on mismatch or missing owner readback.
4. FP guard: abstain when the anon body has no ownership field (possibly public); abstain
   when the resource returns 401/403 to anon elsewhere is NOT required (per-resource decl is
   enough). Strange form: auth required on GET but a HEAD/OPTIONS/cached variant leaks it.
5. RE-MEASURE-CRUEL: new seed + sealed oracle; catch authn_anon_read (acct:4), abstain on
   the public decoy; suite stays green; demo byte-identical.

## STATUS
Loops 1-2 DONE (by running). Sound signal verified. Build (loop 3) deferred to keep the
project intact at 363 green after two fixes already built this session (problems #2, #3) —
no third build rushed at session end. Next session = direct execution of loops 3-4.

## LOOP 3 — FORGE-HARDEST (DONE) — AUTHN-gap detection built
- broadcast.py: added is_anonymous + owner_ref to PrincipalBroadcast (+ _OWNER_FIELDS);
  record() now captures whether the accessor was anonymous and the ownership field value
  the body declares.
- engine.bva_findings: added the AUTHN-gap path — for any resource where an ANONYMOUS
  principal got a 200 body whose owner_ref is a real attested identity (and not the anon
  itself), build a candidate and confirm.
- act_bridge.confirm_authn_gap: confirms by reading AS the declared owner; the owner view
  must itself carry owner_ref (proving real ownership) → finding kind="authn_gap".
  Abstains when the body declares no owner (public) or the owner view does not confirm.

## LOOP 4 — RE-MEASURE-CRUEL (DONE) — PASSED across two seeds
Proving ground: accounts emit owner_id; a PUBLIC decoy (/api/public/info, no owner field).
  seed 1337: caught the gap at acct:4 (anon), zero FP (public decoy + clean accounts clean).
  seed 99  : caught the gap at acct:3 (anon), zero FP.
Suite 363→367 (4 new AUTHN-gap tests); demo byte-identical.

## PROBLEM #4 — RESOLVED
AUTHN-gap is detectable: an anonymous principal receiving a body that declares an owner is
receiving private data with no credential, confirmed by reading as that owner. Precision
held by abstaining when the anon body declares no owner (possibly public). Permanent
regression: tests/test_authn_gap.py.
