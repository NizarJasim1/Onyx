# RL18 — Global Invariant Engine (The 4th Dimension) · Build Report

> Derived and built under **AEGIS** (4 gates: Absolute Preservation, Invariant
> Soundness, Guarded Execution, Proof & Discrimination + the Zero-Sum Veto). This is
> the engine PROMETHEUS singled out as the one capability that lets ONYX find what no
> commercial tool publishes — the emergent, sequence-level authorization break.

---

## 1. The nerve

> **RL15/16/17 all ask "is THIS state broken?" The surviving class on a hyperscale
> target is EMERGENT: a sequence of individually-permitted operations that
> accumulates into a state no single operation would ever have granted. Every step
> keeps its local rule; the SEQUENCE breaks a global invariant no step owns.**

Canonical case (parent/child ownership): a principal owns folder F and reads doc D
inside it (permitted); F is transferred away (permitted); D should have followed F.
If the principal can still read D while F is now forbidden, the authority transfer
did not propagate. No single operation broke a rule — the composition did. A
per-request scanner and an atomically-thinking researcher are both structurally
blind to it. This is the 4th dimension above boundary (RL15), time (RL16), family
(RL17): the **sequence**.

## 2. What was built (additive, flag-gated, byte-identical when off)

| Component | File | Role |
|---|---|---|
| `InvariantLedger` + break detector | `global_invariants.py` (new) | record per-principal access outcomes over the sequence; detect child-accessible ∧ declared-parent-forbidden |
| `GlobalInvariantLaw` | `eil.py` | candidate when the observed sequence broke "a child's authority follows its parent's" |
| `_confirm_global_invariant` | `confirmer.py` | **read-only** read-backs of child + parent; abstain on independent grants (RL3, AEGIS gate 3) |
| `EMERGENT_BREAK` effect + `_global_invariant_pass` | `models.py`, `engine.py` | flag-gated additive pass |
| planted hierarchy + two decoys | `transport.py` | f1 transferred → d1 break; d2 (no loss) and d3 (independent grant) cleared |
| 7 guarantees | `tests/test_global_invariant_rl18.py` | locks every AEGIS gate |

Calibration moved **35→39 probes, 18→19 findings** (the emergent break on d1, with
the transfer, no-parent-loss, and independent-grant cases all asserted). Test suite
**249→256**. Flag default **off** ⇒ ledger never seeded, pass never runs ⇒ identical.

## 3. AEGIS gates, satisfied

- **Gate 1 — Absolute Preservation (A1–A3):** new module, non-routed law, additive
  confirmer strategy, flag default off. The 256 tests + the demo pass byte-identical
  with the flag off. The GIE only READS from ResourceIdentity / hierarchy / the
  confirmer — it modifies none of them.
- **Gate 2 — Invariant Soundness (B1–B3):** the parent→child link is **DECLARED**
  (`resource_parents`), never inferred. Locked by `test_ledger_requires_declared_parent`
  (no declared link ⇒ no break). The invariant is tested only after the parent is
  **observed** forbidden (B3) — `test_ledger_requires_parent_forbidden_observation`.
- **Gate 3 — Guarded Execution (G1–G4):** the engine runs at **execution level 1
  (read-only)**. It OBSERVES the transfer sequence in legitimate traffic — it never
  generates the transfer — and confirms with GETs only. **No write is ever issued, so
  no server state can be damaged.** Mechanised by `test_proof_is_read_only`, which
  spies every request during confirmation and asserts all are GET/HEAD.
- **Gate 4 — Proof & Discrimination (P1–P4):** a break is a finding only with a live
  read-only Δstate (child accessible ∧ parent forbidden). The double null hypothesis
  is defused: a child legitimately **shared independently** of its parent declares a
  grant the confirmer reads and abstains on (`test_independent_grant_abstains`); a
  child whose parent was never lost never fires (`test_no_parent_loss_no_break`).

## 4. Zero-Sum Veto — the final gate

The GIE buys a new dimension (sequence/emergent) at **zero** cost to existing power:
it is additive, flag-gated, byte-identical off, read-only, and reuses the single-Δstate
confirmer. No existing verdict, no red line, no zero-FP property, and no server state
is touched. The veto passes.

## 5. Red lines preserved

- **RL1 (no induction):** the invariant is declared; the break is a structural fact
  (accessible ∧ forbidden ∧ declared link). No similarity, no statistics.
- **RL3 (Δstate):** confirmed only by a live read-only read-back of both child and parent.
- **RL5 (fail-safe):** no declared parent, no observed parent-loss, an independent
  grant, or any unreadable side ⇒ abstain.
- **New (AEGIS) red line — execution ladder:** the engine never exceeds level 1
  (read-only). Levels 2 (reversible writes) and 3 (irreversible) are **not built**.

---

## 6. RESIDUE — what survives even this build

### Residue A — generated-sequence testing *(type γ — deliberately NOT built)*
This build is **passive + read-only**: it detects breaks whose sequence appears in
OBSERVED traffic. Actively GENERATING a candidate sequence (own → transfer → re-read)
to provoke a latent break would need execution level 2 (reversible writes), which
AEGIS gate 3 permits only with explicit opt-in, a recorded rollback plan, and a
hardened scope guard. It is intentionally left unbuilt — the safe, high-value core is
the passive detector. This is the single biggest capability still on the table, and
also the single most dangerous; it must go through AEGIS gate 3 before any code.

### Residue B — invariant breadth *(type β — the moat / cold-start)*
Only one invariant is modelled today (parent/child ownership, the most seed-backed via
`hierarchy.py`). Others — "a deleted id is never readable", "a state reachable only via
Y", "a recycled id carries no prior authority" — are declared-extractable from
`lifecycle`/`temporal` seeds but not yet wired. Like every prior engine, breadth
compounds with use (more declared structure observed ⇒ more invariants testable).

### Residue C — independent-grant completeness *(type α — managed)*
The independent-grant refutation reads a closed vocabulary of grant fields
(`shared_with`, `acl`, …). A grant expressed in a shape outside that vocabulary could,
in principle, be missed — but the failure direction is **fail-safe**: an unrecognised
grant means the engine does not see the legitimacy and may abstain conservatively, or
(worst case) flags a share for human review. It never silently mislabels in the
unsafe direction because the conviction still requires parent-forbidden ∧ child-accessible.

---

## 7. Epistemic honesty

A design that survived AEGIS — the strictest protocol in the project, built because
the GIE is the only engine whose subject is multi-operation — with every gate
mechanised as a test, including a spy that proves the proof path issues no writes.
**Not** a demonstrated hyperscale finding. The strongest true claim: RL18 detects a
class (emergent, sequence-level authorization breaks) that no per-request commercial
tool models, at **zero cost** to the project's existing precision, entirely read-only.
The honest caveat: the **active** version (generating sequences) — the most powerful
form — is deliberately unbuilt because it requires write execution, and that crosses
the one line AEGIS was written to guard.

---

## 8. The complete arc

ONYX now reasons across four dimensions, one spine:

  * **RL15 — boundary:** one resource, many doors → which door betrays the canonical?
  * **RL16 — time:** one resource over deploys → did a filter regress?
  * **RL17 — family:** one proof → which siblings repeat it? (orchestration)
  * **RL18 — sequence:** many permitted operations → did the composition break a
    global invariant no step owns?

Each is additive, flag-gated, byte-identical when off, proven by the same single
Δstate confirmer, and bound by the same red lines. Together they move ONYX from "what
did I observe in this state" to "what is true across doors, across time, across the
family, and across the sequence" — without ever relaxing zero-false-positive discipline.
