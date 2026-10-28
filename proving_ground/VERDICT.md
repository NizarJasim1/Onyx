# GROUND — GATE 5 — THE HONEST VERDICT

First real measurement of ONYX over REAL HTTP, against a sealed oracle, without Kali or
internet. Raw result handed over as-is (GT4).

## THE NUMBERS (run.json vs sealed oracle.json, seed 1337)

```
planted authz bugs : 6   (BOLA×2, BOPLA×2, BFLA×1, AUTHN-gap×1; 2 are strange-form)
ONYX findings      : 0
RECALL             : 0 / 6  = 0%
PRECISION          : 0 false positives on 3 decoys  (perfect — it abstained on everything)
raw exchanges      : 72 over real HTTP (HTTPTarget, not mocks)
```

The tool found NOTHING, and falsely flagged NOTHING. It abstained across the board.

## WHY — from the tool's own self-diagnosis (this is the gold)

**Nerve 1 (identity⇄ownership):** `ownership_pointer_learned = false`,
`owner_declared_ratio = 0%`. It attested all 3 identities correctly, but it never found an
ownership field to key on — because the proving-ground responses do not broadcast an owner
reference (a doc body is `{id, title, salary?}`, no `owner_id`). With nothing declaring
ownership, this nerve has no signal and abstains. → **Blind to BOLA whose response does
not name the owner.**

**Nerve 2 (Broadcast-vs-Act):** raised **32 broadcast candidates** but **confirmed 0**
(144 abstentions: 84 accessor-read-failed, 60 field-not-exposed). The planted field leaks
are UNIFORM (the field is over-exposed to everyone), which is not a broadcast≠act
*contradiction*; and the one inconsistent-projection bug leaks via a *different* vector
(`?expand=full`) than the stored read used to confirm — and the bridge re-reads only one
stored request per resource. → **Blind to uniform over-exposure, and to inconsistent
projection when the leak vector differs from the observed one.**

**Both nerves:** there is no detector at all for **BFLA** (non-owner DELETE succeeded),
**AUTHN-gap** (anonymous read succeeded), or **secondary-key BOLA** (`?invoice=`). These
real OWASP classes are simply outside the two nerves' signals.

## HONEST FAIRNESS CAVEAT (T3 — both directions)

This 0% is partly a real limitation and partly an **unfair proving ground**:
- UNFAIR to the tool: real APIs (and crAPI) usually DO broadcast an owner reference in
  object bodies — exactly the signal nerve 1 was built for. By omitting owner fields, the
  proving ground denied the tool its designed input. On an ownership-broadcasting API the
  first nerve would very likely score far above 0. So this run UNDER-measures the common
  case.
- REAL, regardless: even granting that, the tool covers a NARROW band of the OWASP authz
  spectrum. BFLA, AUTHN-gap, secondary-key BOLA, and uniform BOPLA are real, common, and
  currently invisible to it. A tool aiming at giant surfaces cannot be blind to these.

## WHAT THIS PROVES (the honest level)

- The plumbing WORKS over real HTTP: 72 real exchanges, identities attested, 32 candidates
  raised, redacted export produced. The machine runs end-to-end on real traffic — that was
  never proven before today.
- PRECISION is excellent: zero false positives, even with 32 candidates and 3 decoys. The
  abstain-by-default discipline holds on real traffic.
- RECALL is the weakness: the two nerves are NARROW and signal-dependent. The tool is not
  yet a general authz scanner; it is a precise detector of two specific contradictions.

## NEXT CYCLE (measured material, not guesses)

1. FAIR RE-MEASURE: add owner-broadcasting responses (owner_id in bodies) so nerve 1 is
   tested where it works; add an inconsistent-projection bug that shares resource identity
   so BvA is tested where it works. Re-run → a fair recall number.
2. THEN, the development frontier (DEEP from CROSS) is breadth: detectors for the classes
   currently invisible — BFLA (action gated by declaration, executed by act), AUTHN-gap
   (anonymous receiving private data), ownership-less BOLA (cross-principal identical
   private object without an owner field), uniform BOPLA. Each is a candidate nerve to run
   through DEEP → FORGE.
3. The honest destination remains an independent target (crAPI on a repaired machine),
   where the ground truth is not designed by the tool's author.
```
