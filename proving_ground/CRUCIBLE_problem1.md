# CRUCIBLE — problem #1: "nerve 1 is blind without a declared owner field"

## LOOP 1 — TRIPLE-DIAGNOSE (converged on one problem nerve)
- **TD1 measurement:** recall 0/2 on planted BOLA bugs.
- **TD2 self-diagnosis:** ownership_pointer_learned=False; owner_declared_ratio=0%;
  accesses_with_declared_owner=0 (identities WERE attested: 3).
- **TD3 principle:** nerve 1 learns ownership by finding a body field whose VALUE equals
  the accessor's attested identity. The doc body `{id,title}` shares no field with the
  /me identity `{id,role,email}` → ownership is unlearnable from the broadcast.
- **Converged problem nerve:** nerve 1 detects BOLA only when the object body declares
  ownership in a form it reads (a field whose value == an attested identity). With no such
  declaration, it is structurally blind.

## LOOP 2 — KILL-THE-PROBLEM (attack the problem itself; multi-angle)

### KP1 — tool defect, or measurement injustice? → BOTH, but the deep part is real.
Real APIs (and crAPI) often DO broadcast ownership (owner_id) — so the proving ground was
partly unfair (it denied nerve 1 its designed input). BUT "ownership-less" objects are
real: many endpoints return an object by id with NO owner reference in the body.

### KP2 — one problem, or several? → it splits, and the core one is profound.
Attacking "just detect ownership-less BOLA" with rigor exposes a deeper truth:

  **Without ANY readable declaration of ownership/exclusivity, BOLA is OBSERVATIONALLY
  INDISTINGUISHABLE from a legitimately SHARED resource.**

  Proof sketch: object X is access-controlled (anon → 401). It is served (200, private
  body) to principal A and also to principal B. Two cases produce the IDENTICAL external
  observation: (i) X belongs to B and A is a BOLA attacker; (ii) X is legitimately shared
  between A and B. To tell them apart you need a signal that ties X to a specific owner —
  i.e. a DECLARATION. The only non-inductive ways to get one:
    (a) an owner field in the body (nerve 1 already reads a value-match form of this);
    (b) the body contains another principal's identity value (provably theirs);
    (c) an access-control PATTERN that ties X to one principal (owner→200, others→403).
  Distinguishing by "other objects of this type are exclusive, so X should be" is
  INDUCTION → forbidden by RL1.

### KP3 — does a fix break the founding nerve? → the shared-resource FP is the killer.
Any detector that flags "two principals received X" WITHOUT a declaration will false-
positive on every shared resource (team docs, public-ish records, org-scoped data). That
violates the zero-FP red line. So on a truly declaration-less object, ABSTAINING IS
CORRECT (RL5) — ONYX's 0% there was the discipline working, not a defect.

## LOOP-2 VERDICT (honest, reframes the whole problem)
The problem is NOT "nerve 1 can't detect BOLA without an owner field" (that abstention is
correct). The REAL, addressable problem is narrower and sharper:

  **nerve 1 reads only ONE form of the ownership declaration — a body field whose value
  equals the accessor identity. It ignores OTHER readable declarations the target emits,
  chiefly (c) the access-control pattern (owner→2xx, others→403/401) and (b) a body value
  matching ANOTHER principal's identity. Broadening the declaration-readers is the fix;
  inventing ownership where the target declares none is impossible and forbidden.**

## OPEN QUESTION FOR LOOP 3 (the decisive attack, next)
Is form (c) — the access-control pattern — a SOUND, non-inductive ownership declaration?
Specifically: if X is served to A and denied (403) to a third principal C, does that
declare "X is A's"? Risk: it declares "X is not C's", not "X is A's" — and on a BOLA leak,
the victim's object is served to the attacker (200) too, so the pattern is exactly the one
that's ambiguous. Loop 3 must KILL or CONFIRM form (c) as a declaration before building on
it. If (c) survives → build a broadened ownership-declaration reader (FORGE-HARDEST, prove
on the strange form with zero FP on shared-resource decoys). If (c) dies → the honest
finding is that this BOLA class is undetectable deterministically, and the frontier moves
to the classes that DO emit a declaration (BFLA via action links, AUTHN via anon-2xx).

## LOOP 3 — KILL/CONFIRM (cold mind, by running)
- **Form (c) — access-control pattern — KILLED.** On the BOLA leak doc the pattern is
  (owner→200, attacker→200, anon→401), BYTE-IDENTICAL to a legitimately shared doc. It
  cannot distinguish BOLA from shared on exactly the leak case. (c) dies as a standalone
  ownership declaration.
- **Form (b) — body carries owner identity — CONFIRMED.** Fair variant: inject
  `owner_id` into bodies. nerve 1 immediately learned the pointer (`owner_id`, ratio
  66.7%) and went from 0 → 5 findings. **PROVES the original 0% was CORRECT ABSTENTION
  (no declaration present), not a defect.** nerve 1 already reads form (b)/(a). The
  proving ground was unfair to nerve 1; loops 1-2 reasoning is empirically confirmed.

## LOOP 4 — RE-MEASURE-CRUEL → exposed PROBLEM #2 (a real zero-FP violation)
Classifying the 5 fair-variant findings:
  doc:1/u-bob = REAL leak. doc:1/u-admin, doc:2/u-admin = (admin on actually-leaked docs).
  **doc:3/u-admin and doc:4/u-admin = FALSE POSITIVES** — clean docs, admin reading by
  ROLE. nerve 1 flags any accessor whose identity != owner_id and got 200, so it brands
  legitimate privileged-role access as BOLA. Hidden by the mocks (no admin-cross-owner
  case); exposed by real HTTP + an admin principal.

### This is the SAME deep theme: read the declaration.
The target DECLARES the elevated role at /api/me (`role: admin`). nerve 1 ignores it, so
it cannot tell "admin legitimately reads all" from "attacker illegitimately reads one" —
the same indistinguishability as the shared-resource trap, resolved the same way: by
reading the role declaration the target emits.

## CRUCIBLE problem #1 — VERDICT
- ownership-LESS BOLA is correctly an ABSTAIN (undetectable deterministically; RL5/RL1).
- nerve 1 WORKS on declared-ownership BOLA (form a/b) — confirmed 0→5.
- but nerve 1 has a REAL PRECISION DEFECT (problem #2): it false-positives on
  privileged-role cross-owner access because it does not read the declared role.

## PROMOTED: PROBLEM #2 (jumps the queue — zero-FP is the foundation)
nerve 1 must read the accessor's declared role (from the attestation /me) and, when the
accessor holds an elevated role that plausibly grants cross-owner access, the ownership
mismatch is NOT a violation → abstain (RL5). Fix theme identical to all of CRUCIBLE: read
more of what the target declares. Next session: CRUCIBLE on problem #2 — triple-diagnose
(confirm the FP across seeds), kill-the-problem (is admin-access always legitimate? what
about an admin-SHOULD-NOT case?), FORGE-HARDEST the role-aware guard (abstain on declared
elevated role; still catch peer-to-peer BOLA), re-measure-cruel (FP must drop to 0, real
leaks must remain caught).
