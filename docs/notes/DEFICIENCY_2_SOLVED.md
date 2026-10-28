# Deficiency #2 (spec-consumer → surface-discoverer) — SOLVED under [18]+[19]+[20]

ONYX tested only the documented/observed surface, capping it at the operator's recon and
locking it away from the hidden endpoints where mature-target authz bugs live. The commodity
fix — blind dictionary fuzzing — is the wrong move here: it is noise (trips #6), risks scope
violations (#9), and bolts a probabilistic "does this exist?" layer onto a deterministic
zero-FP engine.

## The root move ([4].R5 / [12]) — harvest, don't fuzz
Every endpoint ONYX adds is grounded in a reference the TARGET ITSELF emitted. That keeps
discovery deterministic (RL1), quiet (no wordlist), and FP-safe: discovery only FEEDS the
detection pipeline, and the confirmer still requires a proven Δstate, so a discovered
endpoint that is not vulnerable yields no finding. **Discovery cannot add a false positive.**

## Gap inventory ([19] band 1) and closure

| Gap | Closure (`authpath/expander.py`) |
|-----|----------------------------------|
| **1 reference harvesting** | From response bodies: absolute/relative URLs, HATEOAS `_links`, and nested id fields (`invoice_id` → `/invoices/{id}`). Endpoints the server disclosed — zero guessing. |
| **2 version/lineage** | Deterministic downgrade siblings of a REAL path: `/api/v2/x` → `/api/v1/x`, `/v0/x`, `/internal/x`, `/legacy/x` — a classic IDOR/BFLA vector. |
| **3 JS-bundle extraction** | API path literals in served JavaScript — real endpoints the frontend calls, often undocumented. |
| **4 param mining** | Field names harvested from bodies → undocumented mass-assign / EDE candidates the spec omits. |
| **5 unified ingest + tiers + precision** | One channel into the existing discovery pipeline, TIER-TAGGED (observed < spec < referenced < lineage < js), only-new returned. **Precision stays 1.0** — a discovered-but-safe endpoint yields no finding (verified). |

Tests: `tests/test_surface_expander.py` (6 cases incl. the no-FP guarantee). MSI byte-identical
(expander is opt-in, not in the default path); full suite 519 green; dedup lint clean.

## The boundary ([19] band 3) — declared by design, not laziness
An endpoint the target references NOWHERE and ships in no spec/JS is findable only by blind
fuzzing. That is rejected on purpose: fuzzing is noise (breaks #6), it risks unauthorized
scope (#9), and "guess a path and see if it exists" is a probabilistic layer alien to a
deterministic zero-FP tool. ONYX discovers the REFERENCED + DERIVABLE fraction — which, on a
mature target, is large, because the target's own bodies, JS, and version lineage leak most
of its real surface.

## The [18] card
- **(أ) Structural constraint removed:** ONYX is no longer capped at the operator's
  documented surface — it expands to the endpoints the target itself discloses, reaching the
  hidden surface where real bugs hide, while staying deterministic and quiet.
- **(ب) Hypothesis the solution requires:** ONYX must be given the target's own emissions
  (bodies it already reads; optionally served JS) — no external hypothesis beyond what a
  normal client sees.
- **(ج) Weakest remaining link:** endpoints never referenced anywhere (need blind fuzzing) —
  out of scope by design; and reaching a discovered endpoint still depends on #3 (live auth)
  and is governed by #9 (ROE).

## Graduation
Proven on synthetic bodies/JS/lineage + the no-FP guarantee. Next honest station: feed a real
app's bodies and JS bundle and measure the hidden-surface fraction recovered — not a
Google/Microsoft claim.
