# Deficiency #8 (law-space search / generative grammar) — SOLVED under [18]+[19]+[20]

All ~25 detection laws were hand-written POINTS in a shared space, so ONYX could never
detect a violation class no human wrote — innovation was capped at the author's imagination.

## The root move ([4].R5 / [12]) — abstract the laws into a grammar, then generate
Every law is a tuple in `actor_relation × verb × object_selector × confirm_channel`. The
grammar (`authpath/grammar.py`) enumerates that product; any tuple absent from the
hand-written `KNOWN_LAWS` set is a NOVEL law ONYX generated itself.

**The FP-safety split (why this is safe):** generation expands only WHICH pattern ONYX
looks for. CONFIRMATION stays the exact same proven Δstate machinery. A generated law that
matches a pattern but cannot confirm a real Δstate emits NOTHING — so generation can raise
recall but can never manufacture a false positive. GP5 is preserved by construction, not by
audit. Every generated finding is tagged `AUTO-GENERATED / UNREVIEWED`.

## Gap inventory ([19] band 1) and closure

| Gap | Closure |
|-----|---------|
| **1 abstraction** | The hand-written laws are encoded as tuples (`KNOWN_LAWS`) in the four-dimension space. |
| **2 generation** | `LawGrammar.novel_laws()` enumerates the product and returns tuples outside the known set — laws no human wrote. |
| **3 executable** | `GeneratedLaw.evaluate()` matches its pattern on an exchange, resolves object+owner by its selector, and confirms via its channel. |
| **4 novelty proven, not claimed** | A novel law `(cross_principal, read, secondary_key, direct_readback)` — a secondary-key BOLA no hand-written law addresses — confirms a seeded violation, tagged AUTO-GENERATED, actor/owner correct. |
| **5 FP-safety** | The same novel law on a safe target (403-enforced) emits nothing; same-principal access is not flagged. Confirmation stays Δstate. |

Tests: `tests/test_law_grammar.py` (5 cases). MSI byte-identical (grammar is opt-in, not in
the default path); full suite 532 green; dedup lint clean.

## The wall ([19] band 3) — bounded novelty, declared
ONYX composes new COMBINATIONS within the four dimensions; it cannot invent a genuinely new
DIMENSION (a violation type outside the space). Adding a dimension is a human act. Novelty
here is combinatorial within the grammar, not unbounded invention — declared, not implied.

## The [18] card
- **(أ) Structural constraint removed:** detection is no longer limited to hand-written
  laws; ONYX generates and runs novel violation classes from a grammar — reaching bug
  classes the author never enumerated, which is exactly what a mature target's unusual
  surface needs.
- **(ب) Hypothesis the solution requires:** the grammar's dimensions and the `KNOWN_LAWS`
  encoding are the declared basis; a generated finding is surfaced as UNREVIEWED for a human
  to confirm before it is trusted as a curated law.
- **(ج) Weakest remaining link:** bounded novelty — new combinations, not new dimensions;
  and a generated law still depends on the same confirmation channels (#4) and surface (#2).

## Graduation
Proven on a seeded secondary-key BOLA (a novel tuple) + FP-safety on a safe target. Next
honest station: run the generated novel laws across a real app's traffic and have a human
review the AUTO-GENERATED findings — not a Google/Microsoft claim.
