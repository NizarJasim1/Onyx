# Protocol [22] — "Pioneered" class (defensive sense only): Object-Binding Authorization Drift

> ⚠️ **PRIOR-ART CAVEAT (read before any public use of "pioneered" / "novel class").**
> "Pioneered" here means only the narrow, defensible sense: ONYX DEFINES a formal detector
> and CONFIRMS this pattern by Δstate. It is **NOT** a claim of world-first novelty. No
> literature review was performed, and closely related ideas are known — TOCTOU of
> authorization, confused-deputy via a mutable reference, IDOR-via-rebinding. Before any
> public presentation or competition submission, do a **real prior-art review**; a reviewer
> who knows the literature could otherwise surface precedent. This is the single most likely
> place to be caught. Prefer wording like "a formally-defined, Δstate-confirmed detector for
> an object-rebinding authorization-drift pattern" over "new class".

## Honest framing first ([16].1)
ONYX already has a TEMPORAL axis — `temporal.py` detects CREDENTIAL-lifecycle drift (a stale
credential still working after a revocation event). This class does NOT re-claim that axis.
Its contribution is a DISTINCT class on the interaction of **temporal × object-reference
resolution** that neither the credential-lifecycle detector nor any point-in-time law covers.

## The class
An authorization is granted while a reference REF resolves to the actor's own object O1
(authorized). REF is then re-pointed to a victim's object O2 (a mutation the actor may make on
REF). The privileged operation COMMITS against REF, now resolving to O2 — so the effect lands
on the victim's object under an authorization that only ever saw the actor's own. A
TOCTOU-of-authorization by object re-binding.

## The six-part [22] card
- **(أ) The new axis:** `binding_state ∈ {stable, rebound_between_check_and_use}` — the object
  bound to an authorization can drift across an ordered sequence. Point-in-time laws and the
  credential-lifecycle detector do not model it.
- **(ب) Competitor structural blindness (measured):** on the 3-step sequence, response-diff
  and single-exchange oracles score **recall 0.0** (each step is individually authorized);
  ONYX's cross-step detector scores **1.0**. (`test_g22_competitor_structural_blindness_measured`.)
- **(ج) Δstate zero-FP:** confirmed only when a check resolved REF to an actor-owned object,
  an observed mutate changed REF's resolution, and a committed use landed on a different
  principal's object. An atomic / re-checked target yields nothing; an uncommitted use yields
  nothing. Deterministic, no ML.
- **(د) Real mechanism:** sagas, eventual consistency, CQRS, async "validate-then-commit"
  flows where the validated reference can change before the commit — a real modern-systems
  pattern, not fiction.
- **(هـ) Reproducible PoC:** every finding carries the ordered CHECK → MUTATE → USE sequence;
  proven on a seeded target, clean on an atomic one. (`tests/test_authz_drift_class.py`, 5/5.)
- **(و) Honest ceiling:** ONYX DEFINES and DETECTS this class by this mechanism, proven on a
  seeded target. Its prevalence in the wild is an OPEN empirical question — no "first ever"
  and no "present in Google/Microsoft" claim. The mechanism is the pioneering contribution;
  prevalence is what an operator's live run would measure.

## Wall (declared, = #4)
ONYX must OBSERVE the ordered steps. A mutation entirely internal to the server that never
surfaces is out of scope (invisible Δstate).

MSI byte-identical (opt-in module); full suite 570 green; lint clean.
