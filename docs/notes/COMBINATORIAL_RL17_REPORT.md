# RL17 — Combinatorial Orchestration · Build Report

> Derived under **CRUCIBLE v2** (the original 18 laws + a new **Layer Zero: the
> Clustering Crucible**, C1–C6). Records the design honestly: what it does, the
> guarantees, and the residue.

---

## 1. The nerve (CRUCIBLE law 2)

> **ONYX detected a leak WHERE it observed one; on a hyperscale target the leak
> lives WHERE it did not look — cell #743,219 of a million-cell (resource × door ×
> role) matrix, not hidden, just never reached. The gap is not a missing detector;
> it is a missing ORCHESTRATOR: the ability to take one proof and infer where it
> repeats, then check only there.**

## 2. The reframing that Layer Zero forced

The original Problem #1 ("hunt the outlier in a family of similar endpoints") **fails
the clustering crucible**: grouping by *similarity* is induction (violates RL1). Under
C1 (reverse burden) and C2 (declared equivalence source), the only legitimate family
is "same ResourceIdentity TYPE reached by the same door." So RL17 is **not a new
detector** — it is an orchestrator that reuses RL15's proof entirely:

> A CONFIRMED cross-surface leak generalises into a **structural rule**
> `(door D, sensitive field F, resource-type T) → leaks`. The rule TARGETS sibling
> cells of the same type/door; each target is convicted ONLY by its own per-cell
> Δstate via the existing RL15 confirmer. **The family discovers; the single Δstate
> convicts (C6).** The combinatorial layer adds targeting, never a new proof path,
> hence no new false-positive surface.

## 3. What was built (additive, flag-gated, byte-identical when off)

| Component | File | Role |
|---|---|---|
| `HypothesisEngine` + `StructuralRule` | `hypothesis.py` (new) | learn a rule from a confirmed leak; propose sibling cells; scale-scaled rigor |
| rule-learning hook | `engine.py` (`_cross_surface_pass`) | a confirmed RL15 finding earns a rule (witness-1) |
| `_combinatorial_pass` | `engine.py` | target rule-matching siblings; convict each by the existing RL15 confirmer |
| `combinatorial` flag + `_derived_count` | `engine.py` | gate + count of orchestrated findings |
| planted family + public decoy | `transport.py` | `payouts` 600–602 vulnerable, 603 public (refuted) |
| 7 guarantees | `tests/test_combinatorial_rl17.py` | locks every Layer-Zero constraint |

Calibration moved **34→35 probes, 15→18 findings** — the +1 probe (`/api/payouts`)
yields **3** findings: 600 observed directly, **601 & 602 discovered by orchestration
(never read canonically in the baseline)**, while the public **603 is cleared**. Test
suite **242→249**. Flag default **off** ⇒ no rule learned/applied ⇒ byte-identical.

## 4. The Clustering Crucible, satisfied (CRUCIBLE v2 Layer Zero)

- **C1 reverse burden / C2 declared source:** the family is ONLY "same resource-type,
  same door" (`_list_resource_type` + `ResourceIdentity`). No similarity, no shape
  clustering — that would be induction.
- **C4 cross-witness:** every derived conviction has TWO independent witnesses —
  *witness-1*, the rule, already proven by a real Δstate finding on an exemplar; and
  *witness-2*, this sibling's own canonical read-back contradicting its door. Two
  independent proofs do not coincide by accident → zero FP. Locked by
  `test_public_sibling_is_refuted_zero_fp` (603 matches the rule but its canonical
  legitimately exposes the field → refuted per-cell).
- **C5 rigor ∝ scale:** a rule must be earned by a confirmed exemplar before it
  generalises, and the independent-confirmation bar grows with family size
  (≤8 → 1, ≤64 → 2, larger → 3). Locked by `test_rigor_scales_with_family_size`.
- **C6 isolatability:** the family is a cheap DISCOVERY device; every conviction is
  one isolated resource proven by the SAME single Δstate confirmer. The combinatorial
  layer contributes no new proof path. Locked by `test_orchestration_discovers_*`
  and `test_public_sibling_is_refuted_zero_fp`.

## 5. Red lines preserved (CRUCIBLE law 4)

- **RL1 (no induction):** a rule is a structural triple proven by Δstate, never
  similarity. Targeting only chooses WHERE to read; it never asserts a verdict.
- **RL3 (Δstate):** every derived finding is proven by a live per-cell canonical
  read-back (the existing RL15 confirmer).
- **RL5 (fail-safe):** an unproven rule targets nothing; a refuted per-cell read-back
  clears the cell; a wrong proposal costs a wasted read, never a false finding.

---

## 6. RESIDUE — what survives even this build (CRUCIBLE laws 15/16)

### Residue A — multi-principal / role provisioning *(type γ — external, declared)*
The full (resource × door × **role**) matrix needs accounts provisioned at multiple
roles, which bug-bounty programs constrain. RL17 as built generalises across the
**resource × door** plane intra-principal (no role swapping); the role plane is
available through the existing N-principal matrix (`matrix.py`) when the operator
provisions roles, but that is an operational input, not a code capability — declared
honestly, never silently assumed. This is the single biggest practical caveat: unlike
RL15/RL16, the *full* power of RL17 is heavier to operate.

### Residue B — over-generalisation from a thin exemplar *(type α — managed)*
A rule earned on one resource could, in principle, mis-target. Managed by C5 (rigor ∝
scale: a thinly-proven rule may not be extrapolated across a large family) and by C6
(every target is still independently proven, so a mis-target is a wasted read, not a
false finding). The residue is *cost* (wasted reads), never *correctness*.

### Residue C — the first-of-its-kind cell *(type β — the moat)*
A vulnerability pattern never proven on any exemplar cannot be generalised — there is
no rule yet. Like RL16's first blind window, this inverts into the advantage
(CRUCIBLE L17 / Scale-Aikido): every confirmed finding makes the next cheaper to find,
and a larger family supplies MORE cross-witnesses, so conviction gets *stronger* with
scale, not weaker. The constraint (needs a first proof) is the moat (a campaign that
compounds).

---

## 7. Epistemic honesty (CRUCIBLE law 12)

A design that survived CRUCIBLE v2 — including a Layer Zero built specifically because
the combinatorial dimension is the most dangerous for false positives — with every
Layer-Zero guarantee mechanised as a test. **Not** a demonstrated hyperscale finding.
The strongest true claim: RL17 turns ONYX from a per-observation detector into an
orchestrator that converts one proof into a family-wide campaign across the
resource×door matrix, **without weakening the single-Δstate precision the whole
project rests on** (C6: the family only discovers; the Δstate convicts). The honest
caveats: the full role-plane power needs multi-role provisioning (Residue A), and the
engine only generalises patterns it has already proven once (Residue C — a moat, but
also a cold-start).

---

## 8. The arc, complete

Problem #2 (boundary), #3 (temporal), #1 (combinatorial) now share one spine — the
`ResourceIdentity` and the single-Δstate confirmer — and compose: RL15 proves a leak,
RL16 catches it drifting over time, and RL17 propagates the proof across the family.
Each is additive, flag-gated, and byte-identical when off; together they move ONYX
from "what did I happen to observe" to "what does one proof imply across the whole
matrix, over time" — while never once relaxing zero-false-positive Δstate discipline.
