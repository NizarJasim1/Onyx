# SAIE — Build Report (Structural Authorization Interrogation Engine)

Built into the ONYX / `authpath` engine per `SAIE_HANDOFF.md`, Part F (test-gated,
incremental). Every step held `python -m authpath demo` green. Final state:

```
17/17 probes matched · 9 findings · 2 candidates dropped by Δstate · 0 false positives
authpath/structural.py self-tests: 15/15
```

## What SAIE detects
A JSON response is a 2-D shadow of a multi-dimensional backend object. SAIE measures
the *shape* of that shadow. When an under-privileged principal's response shares the
structural fingerprint of a privileged principal's response — same paths present, same
topology — while the sensitive values are filtered to `null`, the server provably ran
the attacker through the privileged serialization/authorization code path. Output
filtering was the only barrier. Content-diffing tools (including ONYX's own IDOR
confirmer) see nothing, because no value leaked. SAIE sees the path.

Decisive signal: `PRESENT_NULL` (branch executed, then emptied) vs `ABSENT` (branch
never ran for this principal).

## Architecture as built
- **Layer 0 — StabilityGate** (`structural.py`): the 0-FP gate. Observes ≥2 repeats of
  an identical request, compares *value-blind fingerprints*, and classifies each node
  `STRUCT_LIKE` / `MAP_LIKE` (order varies → order signal disabled) / `VOLATILE`
  (topology varies → node excluded). Anything not proven stable is excluded from every
  decision (RL5). Because comparison is value-blind, a field whose *value* changes
  across repeats stays stable; only presence/type/topology changes degrade trust.
- **Layer 1 — fingerprint** (`structural.py`): value-blind. `absence_map`
  (path→`PRESENT_POPULATED`/`PRESENT_NULL`/`PRESENT_EMPTY`), `types`, `order`,
  `array_counts`, derived `quantities`. `ABSENT` is comparison-relative, never stored.
- **Layer 2 — CoherenceModel** (`structural.py`): per (principal, family) grammar.
  `fits()` is presence-level (paths + shape kind + trusted order), **state-blind** — so
  a value-filtered response *fits* the privileged grammar it was filtered from.
  `privilege_rank()` counts admissible, state-trusted `PRESENT_POPULATED` paths.
- **Three-gate confirmation** (RL3):
  - **Gate 1** — `StructuralDivergenceLaw.evaluate` (`eil.py`): coherence breach — the
    fingerprint fits a *strictly higher-privilege* grammar but not the acting
    principal's own.
  - **Gate 2** — `Confirmer._confirm_structural_divergence`: a genuinely lower-priv
    control must NOT receive this shape. No clean control ⇒ object-driven / by-design
    richness ⇒ **abstain** (not a finding).
  - **Gate 3** — functional anchor: ≥1 privileged-only path that is `PRESENT_POPULATED`
    in the owner's grammar must be present in the attacker's response. Optional
    escalation: a live, scope-guarded owner read-back + leak audit raises severity from
    High to (CVSS) C:H only when a real sensitive *value* crossed.
  Any indeterminate gate ⇒ no finding.

## Key decisions & deviations (flagged, then executed)
1. **SAIE runs as an independent additive pass, NOT inside `EIL.evaluate`.** The handoff
   suggested mirroring the temporal law inside `evaluate`. But `evaluate` returns one
   verdict and short-circuits; injecting SAIE there risked perturbing the existing 12
   verdicts. Instead SAIE is reached only via `EIL.evaluate_structural()` from
   `engine._structural_pass`, invoked through a single `_finish()` tail after the main
   verdict. It can only *add* a finding, never alter the main verdict. This makes
   additive isolation a structural guarantee — see DoD #4 below.
2. **`divergence()` vs `fits()` are deliberately separate.** `divergence()` is the
   fine-grained diff and reports absence-STATE differences (populated↔null↔empty),
   satisfying the Step-1 self-test "privileged vs filtered diverges on absence_map".
   `fits()` (Layer 2) ignores state and compares presence + shape kind, so the filtered
   attacker response matches the privileged grammar. Conflating them would have stopped
   Gate 1 from ever firing.
3. **`shape_kind` collapses `{scalar,null,bool}` → `leaf`.** Nulling a value flips the
   raw type scalar→null; treating that as a topology change would break both the
   stability gate and `fits`. Nulling is an absence-STATE fact, not a shape change.
4. **Demo fixture built to the prose, not the literal Part-B JSON.** The literal example
   shared a substantive top-level scalar between attacker and owner, which the existing
   IDOR confirmer would (correctly) fire on, masking SAIE. The widget fixture shares no
   substantive value: the attacker's privileged-shape response is fully value-filtered,
   so the IDOR confirmer correctly abstains and SAIE fires alone.
5. **New control principal `C` is scoped out of the orders subsystem** (`MockTarget`),
   so adding it does not change the original IDOR/BFLA confirmations. Verified
   byte-identical (DoD #4).

## Validation against Definition of Done (Part J)
1. **≥13/13 with 0 FP** → **17/17, 0 FP.** (12 original + 1 SAIE positive + 4 negatives.)
2. **Exactly ONE `STRUCTURAL_DIVERGENCE` finding; control fires nothing** → confirmed
   (1 structural finding on widget 50; control C clean).
3. **All negatives clean** → value-only diff, map-like reorder, object-driven richness
   (Gate-2 suppressed), volatile topology (Layer-0 excluded) — all clean.
4. **Deleting SAIE restores byte-identical behavior on the original 12** → proven: with
   the SAIE pass + seed disabled, the original probes' findings AND traces are
   byte-identical (ids scrubbed). 8 original findings preserved.
5. **No timing in verdicts** → no latency/elapsed/duration anywhere in the decision
   path; Layer 5 (timing-as-compass) deliberately not implemented.
6. **Every finding has causal path + structural StateProof (before≠after) + CVSS +
   markdown** → confirmed; the causal path enumerates the three gates explicitly, the
   StateProof contrasts the ABSENT privileged paths (before) with the received
   privileged shape (after), CVSS `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (C:H on real
   sensitive leak), full markdown renders.

## Files
- **new:** `authpath/structural.py`, `tests/test_structural.py`
- **modified:** `models.py` (EffectClass/ImpactClass), `eil.py` (LawContext fields,
  `StructuralDivergenceLaw`, `evaluate_structural`), `engine.py` (gate/coherence,
  `_saie_seed`, `_finish`, `_structural_pass`), `confirmer.py`
  (`_confirm_structural_divergence`), `poc.py` (title/severity/causal-path),
  `cvss.py` (vector), `transport.py` (widget/report/config/feed routes + order scoping),
  `fixtures/demo_scenario.py` (principal C, contract, SAIE seeds + probes)

## Deliberately deferred (honest scope boundary)
The CORE (L0+L1+L2 + three gates) is complete and proven at 0-FP. L4 (temporal
structural drift — a principal's own grammar gaining privileged paths after a
revocation/role event) and L5 (timing-as-compass) are NOT built. Rationale: each is a
detection angle that must arrive with its own negative fixtures proving it does not
erode the 0-FP guarantee that is the entire value of this engine. Bolting them on
unvalidated would weaken, not strengthen, the deliverable. L4 is the recommended next
increment; L5 should remain guidance-only and never touch a verdict. L3 (structural
derivative) is already present in spirit as `DivergenceReport.magnitude`, used only for
ranking, never for a decision.

---

# Phase 2 — ISI (Intrinsic Structural Interrogation): reference-free coverage

## The problem this solves
The structural engine (Phase 1) is RELATIONAL — it proves a finding by comparing an
under-privileged response to a higher-privilege grammar. That costs a reference
principal + repeated identical observations, and goes silent whenever they are missing
(the common case on a real target: one account, single-shot, non-deterministic
endpoints). Root cause: detection was *relational*, never *intrinsic*.

## The solution (genius-but-practical, zero strength lost)
Separate DISCOVERY from CONFIRMATION:
- **ISI** (`intrinsic.py`) mines a SINGLE response — no reference, no repeat — for
  self-contained structural evidence, and emits ranked **LEADS**.
- The existing gated machinery still owns **FINDINGS** (0-FP untouched).
A lead is not a finding, so the 0-FP guarantee for findings is mathematically
unaffected (proven below). Coverage explodes because every response is now mined at the
cost of one operation.

## Signals (chosen for maximum signal / minimum information)
- **SIBLING_ASYMMETRY** — within ONE collection response, peer elements share a common
  base schema but a MINORITY carry a sensitively-named privileged overlay the majority
  lack. The peers are each other's control → a reference-FREE differential. This is the
  crown jewel: a built-in baseline inside a single response. Demo: `GET /api/directory`
  — the finding-pipeline passes it as clean, ISI flags the leaked `internal`/`salary`
  overlay on 1/4 rows as a STRONG_LEAD, with the exact one-read-back probe to confirm.
- **GHOST_FIELD** — a sensitively/privileged-named path PRESENT but NULL / EMPTY /
  MASKED: the serialization branch executed while output filtering emptied the value.
  MASKED (`***-**-1111`, `[REDACTED]`) is a STRONG_LEAD — the server fetched the real
  value then redacted it, so the field provably exists. Demo: the SAIE-suppressed
  `reports/80` case still yields three ranked ghost-field leads — coverage even where a
  finding is correctly withheld.

A closed, weighted sensitivity lexicon (secrets 10, internal 8, authz 7, PII 5) ranks
leads; the value-AWARE masking probe is confined to the leads channel and never touches
a verdict (RL discipline preserved).

## Validation
- `tests/test_intrinsic.py`: 8/8. `tests/test_structural.py`: 15/15.
- `python -m authpath demo`: **18/18, 0 FP**, 9 findings, **6 leads** surfaced.
- **Byte-identical (proven):** with the ISI pass (and the SAIE pass) disabled, the
  original 12 probes' findings AND traces are byte-for-byte identical to on. ISI is a
  pure additive lead channel: `engine.leads` + `snapshot()["leads"]`, never `findings`
  or `traces`.

## What this buys, honestly
- Detection without a reference principal or repeats → works on one-account, single-shot
  targets where Phase 1 is silent.
- Minimum operations: leads from a single response; the strongest (sibling-asymmetry)
  carries a built-in control, and its `suggested_probe` is a single read-back to confirm.
- No strength lost: findings remain gated and 0-FP; leads are strictly additive.

## Deliberately deferred (next increments, each gated on its own 0-FP proof)
1. **Lead → finding auto-elevation**: when the engine holds access, issue the single
   `suggested_probe` read-back to confirm a sibling-asymmetry / ghost-field lead and
   graduate it to a gated finding (one operation).
2. **Graduated stability tiers** (`PROVISIONAL`/`CONFIRMED`): let a single-observation
   endpoint feed leads (never findings) — removes the hard ≥2-repeat silence.
3. **AUTHZ_ORACLE signal**: structured error bodies (`required_role`, `missing_scopes`)
   that leak the authorization model — pure reference-free mapping leads.
4. **Cross-session grammar memory**: persist confirmed grammars so the stability bar is
   met across visits, not just within one run.

---

# Phase 3 — Lead elevation + intrinsic recon signals

Two of the four planned increments, each gated on its own 0-FP proof and leaving the
original probes byte-identical (verified with all SAIE+ISI+elevation passes disabled).

## 3a — Lead → finding elevation (FIELD_PROJECTION)
The intrinsic SIBLING_ASYMMETRY lead now graduates into a gated FINDING via a SINGLE
Δstate read-back (RL3): fetch the carrier element through its canonical detail endpoint
AS THE SAME principal. If the list view exposed a populated privileged field that the
detail view FILTERS for that very principal, the list serializer over-projects — a
concrete behavioural contradiction, not a heuristic. New `EffectClass.FIELD_PROJECTION`
+ `Confirmer._confirm_field_projection` + poc/cvss branches. If the detail view also
exposes it (consistent) or cannot be read, we abstain and the lead stays a lead.
Demo: `GET /api/directory` — finding-pipeline passes it clean; ISI flags the leaked
`internal`/`salary` overlay on 1/4 rows; one read-back of `/api/directory/{id}` confirms
the detail view filters it → a real finding (High, CVSS 6.5). This is detection from a
single response + one confirming operation — the "minimum information" thesis realised.

## 3b — Intrinsic recon signals (AUTHZ_ORACLE, TYPE_ASYMMETRY)
Pure additive ISI signals (leads channel only, zero verdict risk):
- **AUTHZ_ORACLE** — a denial body that discloses the authorization model
  (`required_role`, `missing_scopes`, `allowed_roles`, …). Reference-free recon that
  hands the hunter the exact gate to attack, even on 4xx (the intrinsic pass now mines
  any structural body; signals self-gate). Demo: `GET /api/admin/billing` 403 →
  STRONG_LEAD naming `required_role=admin`, `missing_scopes=[billing:read]`.
- **TYPE_ASYMMETRY** — a sensitive shared field served as an expanded object/array to a
  minority of peers but flattened to a scalar for the rest (an over-expanded projection).

## Validation
- `tests/test_intrinsic.py`: 12/12. `tests/test_structural.py`: 15/15.
- `python -m authpath demo`: **19/19, 0 FP**, 10 findings, 7 leads across 3 kinds.
- Byte-identical: original 12 findings AND traces unchanged with all SAIE+ISI+elevation
  passes disabled.

## Remaining (next increments, same discipline)
- **Graduated trust tiers** (PROVISIONAL/CONFIRMED): let the RELATIONAL engine emit
  structural LEADS on single-observation grammars (breaking the hard >=2-repeat silence)
  while findings stay CONFIRMED-only.
- **Real-traffic bridge** (HAR / proxy capture → Exchange stream): turn the proven
  engine from an offline harness into a field tool.

---

# Phase 4 — Graduated trust + offline field bridge (the final two increments)

All four planned increments are now complete, each gated on its own 0-FP proof and
leaving the original probes byte-identical (verified with EVERY SAIE/ISI/elevation/
provisional pass disabled → original-12 findings AND traces unchanged).

## 4a — Graduated trust (PROVISIONAL leads): breaking the >=2-repeat silence
The relational engine was silent on single-observation endpoints (the common field
case). The CONFIRMED tier is untouched; a parallel PROVISIONAL tier on the
CoherenceModel reasons over single-observation grammars and emits a LOWEST-tier,
LEAD-ONLY relational hint when an acting principal's shape fits a higher-privilege
unstable grammar but not its own — gated on the diverging paths being privileged-named
to stay high-signal. It can NEVER feed a finding (an unproven shape is not finding-
grade), and it is opt-in (`engine.provisional_leads`, default off) so the gated engine
stays byte-identical. Demo: `GET /api/vault/200` read once by each principal yields a
PROVISIONAL_LEAD naming `internal.*`/`audit.*`, with the exact repeats needed to promote
it to a confirmed structural-divergence finding.

## 4b — Offline field bridge: HAR → confirmed findings with ZERO live access
`harimport.parse_har_exchanges` reconstructs Exchanges (request + captured RESPONSE +
fingerprinted principal) from a HAR; `transport.ReplayTarget` serves captured responses
for the confirmer's read-backs and fails safe (non-2xx) on anything not captured;
`harimport.ingest_har` drives a fresh engine in two passes (build SAIE grammars across
the whole capture, then analyse every request as a probe). New CLI: `authpath ingest
capture.har --scope host`. Findings appear where the capture itself corroborates them
(Δstate via a captured read-back) or where a reference-free signal fires; everything
else is a ranked lead — all with no network and full determinism.
Proven end-to-end (`tests/test_har_ingest.py`): a capture of a list response + one
detail read elevates the reference-free sibling-asymmetry lead into a confirmed
FIELD_PROJECTION finding (High) using only the captured traffic.

## Final validation (whole system)
- Unit: `test_structural` 16/16 · `test_intrinsic` 12/12 · `test_har_ingest` 2/2.
- `python -m authpath demo`: **20/20, 0 FP**, 10 findings, 14 leads across 4 kinds.
- Offline CLI: `authpath ingest` yields a confirmed finding + ranked leads from a HAR
  with zero live access.
- Byte-identical: original 12 findings AND traces unchanged with every SAIE/ISI/
  elevation/provisional pass disabled.

## The arc, end to end
ONYX now spans the full spectrum from maximum-rigour to maximum-reach, without trading
one for the other: a RELATIONAL value-blind engine that proves authorization-path
divergence at 0-FP; an INTRINSIC engine that mines a single response for reference-free
leads (ghost fields, sibling asymmetry, authz oracles, type asymmetry); a CONFIRMATION
bridge that elevates the strongest leads to findings in one read-back; a GRADUATED-trust
tier that keeps the engine useful on single-shot endpoints; and an OFFLINE field bridge
that turns a HAR capture into findings with no live access. Findings stay gated and
0-FP; leads widen coverage at minimum information cost; the original engine is preserved
byte-for-byte.

---

# Phase 5 — Structural Normalisation (production-robustness, idea #1 of 6)

Built after a six-angle adversarial critique. The danger: any loosening of Layer 0
threatens 0-FP. Resolution — normalise ONLY along the VALUE axis; a flicker along the
PRESENCE/TOPOLOGY axis is never "noise" but a SIGNAL; and normalised/intermittent nodes
feed LEADS only, never findings.

## What it adds
- `StructuralFingerprint` was already value-blind, so value-entropy (a field whose
  VALUE churns but presence/type are stable) is already tolerated by the CONFIRMED path.
- New `StabilityGate.normalize(family)` builds, per node, a cumulative `NodeProfile`
  (`seen`/`present`/`state_distinct`/`topo_stable`) PER identical-request series, so
  "intermittent" means a flicker under IDENTICAL input — not legitimate per-object
  variation. O(distinct paths), three counters, no stored fingerprints.
- New signal **INTERMITTENT_PRESENCE**: a privileged-named field present in only some
  identical-request repeats. A sensitive field the server emits conditionally is an
  authorization-conditional leak that current tools read as mere inconsistent noise.
  Demo: `GET /api/session` emits `internal_token` in 2/3 identical reads → STRONG_LEAD.

## Discipline preserved (the critique's resolutions, in code)
- Normalisation/intermittent nodes are LEAD-ONLY; the CONFIRMED `trust_mask` is
  untouched (an intermittent node stays VOLATILE there → excluded from every finding),
  so poisoning the "entropy" region can never exceed a lead.
- Flag-gated (`provisional_leads`, default off) and deduped per (family,path) =>
  byte-identical when off, and verified byte-identical (findings AND traces) even when
  on, across the original 12 probes.

## Validation
- `test_structural` 17/17 (incl. presence-axis-only normalisation), `test_intrinsic`
  12/12, `test_har_ingest` 2/2. Demo: 21/21, 0 FP, 15 leads across 5 kinds.

## Remaining ideas (in order, each with its own critique + 0-FP proof)
3. **Inconsistent-ABSENT ("missing shadow")** — the signature that survives in mature
   systems that authorise BEFORE serialisation (no PRESENT_NULL): flag a branch that is
   selectively ABSENT where the principal's own grammar expects it.
2. **GraphQL/BFF demultiplexer** — define the family by query SHAPE, not path; project
   response structure onto the request's field selection.
4. **Disciplined active probe ("one question")** — execute a lead's suggested_probe
   behind Scope-Guard to elevate it in a single request.
5. **Cross-step value provenance** — track a value's origin across a request chain and
   flag consumption without re-authorisation.
6. **Temporal structural drift (L4)** — a grammar gaining privileged branches after a
   revocation/role event.

---

# Phase 6 — Missing Shadow / Inconsistent ABSENT (idea #3 of 6)

Built after a seven-angle adversarial critique. The hard truth surfaced by the critique:
deciding WHICH side of an absence differential is the violation needs a privilege-tier
signal ONYX does not reliably hold — so making the inversion a FINDING would break 0-FP.
The disciplined outcome: idea #3 ships a 0-FP RECON LEAD (the field-level authorization
map no passive tool builds), and the inversion-as-finding is explicitly deferred until a
trustworthy tier input exists.

## What it adds
- `CoherenceModel.object_presence(family, objsig)` → per principal who observed the
  SAME object: (present_paths, populated_paths).
- `engine._missing_shadow` pass (flag-gated, leads-only, deduped per (family,objsig,
  branch)): on a record observed by >=2 principals sharing a common base schema, a
  privileged-named branch PRESENT_POPULATED for some principals yet ABSENT for others
  yields an **ABSENCE_MAP** lead. This is the residual signature in mature systems that
  authorise BEFORE serialisation (no PRESENT_NULL residue to detect).
- Demo: `GET /api/cases/300` read by senior A (no internal) and junior C (with
  `internal.notes`) on the SAME record → two ABSENCE_MAP leads mapping the field-level
  ACL differential.

## Discipline preserved (the critique's resolutions, in code)
- Expectation anchored on the principal's own normalised grammar; INTERMITTENT nodes
  (idea #1) are excluded so a naturally-flickering field is never read as "inconsistent
  absence".
- Shared-base requirement (>=2 common paths) rules out absence explained by a different
  object type, not authorization.
- Anchored on cross-principal object pairs (the hot spots harimport already detects),
  not a full O(principals x objects x fields) scan.
- LEAD-ONLY, flag-gated, deduped => byte-identical (findings AND traces) on the original
  12 probes, verified with `_missing_shadow` in the disabled-passes set.

## Validation
- `test_structural` 18/18 (incl. object_presence differential), `test_intrinsic` 12/12,
  `test_har_ingest` 2/2. Demo: 22/22, 0 FP, 17 leads across 6 kinds.

## Remaining ideas (in order): #2 GraphQL/BFF demultiplexer · #4 disciplined active
## probe · #5 cross-step value provenance · #6 temporal structural drift (L4).

---

# Phase 7 — GraphQL/BFF demultiplexer + field-level lens (idea #2 of 6)

Built after a seven-angle critique. The GraphQL-specific FP trap (a field is "absent"
because the client did not request it, not because of authz) is resolved by projecting
the REQUEST<->RESPONSE: a field counts as authz-denied only when the server itself
returns an authz-class error for it.

## What it adds
- `graphql.response_data(body)` projects the `data` object graph; `engine._struct_body`
  feeds that graph (not the {data,errors} envelope) to EVERY structural engine — SAIE,
  sibling, missing-shadow, normalisation — so GraphQL plugs into all detectors at once.
  Gated on is_graphql => REST byte-identical.
- `graphql.authz_denied_paths(body)` reads `errors[].path` + `extensions.code`
  (FORBIDDEN/UNAUTHORIZED/...) — the field-level boundary the backend discloses itself
  (0-FP measured fact). Non-authz errors (validation/timeout/not-found) are ignored.
- `engine._graphql_pass` (leads-only): a **GRAPHQL_FIELD_AUTHZ** recon lead per denied
  field, plus a cross-principal index that emits **GRAPHQL_FIELD_BOLA** when the SAME
  field on the SAME object is POPULATED for one principal yet authz-DENIED for another —
  field-level BOLA/BFLA invisible to path-based tools.
- Demo: one `POST /graphql`; C and B issue the identical `order(id:101){...internal}`
  selection — C receives `internal`, B gets it denied with FORBIDDEN → both leads fire.

## Discipline preserved
- Family = the GraphQL operation; object = id-like variables (unifying GraphQL with the
  REST (family,objsig) abstraction). Leads-only, deduped, is_graphql-gated => byte-identical
  (findings AND traces) on the original 12 REST probes, verified with `_graphql_pass` and
  `_struct_body` projection active.

## Validation
- `test_structural` 18/18, `test_intrinsic` 12/12, `test_har_ingest` 2/2,
  `test_graphql_fieldauthz` 3/3. Demo: 24/24, 0 FP, 20 leads across 8 kinds.

## Remaining: #4 disciplined active probe · #5 cross-step value provenance · #6 temporal
## structural drift (L4).

---

# Phase 8 — Disciplined active probe ("one question", idea #4 of 6)

Built after a seven-angle critique. The danger: any active request risks state change
and could feed a false finding. Resolutions, in code: READ-ONLY only; behind Scope-Guard;
no new confirmation path (reuses Δstate + the emitter, RL3); opt-in flag (default off =>
byte-identical); strict per-run budget; deterministic request built from `evidence`, not
from the human probe text.

## What it adds
- `engine._active_field_probe` (flag `active_probing`, default off): for a
  GRAPHQL_FIELD_BOLA hypothesis (a field populated for one principal, authz-denied for
  another on the SAME object), it reproduces the differential NOW — replaying the
  identical read-only operation as each principal through Scope-Guard. If the field is
  freshly populated for one and absent for the other, the passive correlation becomes a
  confirmed Δstate finding; otherwise it abstains (stays a lead). This converts a
  possibly-coincidental passive observation into a controlled, reproducible proof.
- `scope_guard`: a GraphQL QUERY (read) is exempted from the dry-run non-idempotent
  block (only mutations are state-changing) — also repairs GraphQL read-back confirmation
  under dry-run, which POST-blocking previously suppressed.
- Demo: Bob's denied `order(id:101){internal}` is confirmed into a High field-level BOLA
  finding by one controlled read-only cycle.

## Discipline preserved
- Never mutates (read-only op + Scope-Guard); abstains on scope HALT or non-reproduction;
  budget-bounded and deduped per (family,object,field); flag-gated => byte-identical
  (findings AND traces) on the original 12, verified with `_active_field_probe` in the
  disabled-passes set across all 9 additive layers.

## Validation
- `test_graphql_fieldauthz` 5/5 (incl. active-probe confirmation), all other suites green.
  Demo: 24/24, 11 findings (the new active-confirmed BOLA), 0 FP.

## Remaining: #5 cross-step value provenance · #6 temporal structural drift (L4).

---

# Phase 9 — Cross-step value provenance (chain memory, idea #5 of 6)

Built after a seven-angle critique. The chief danger is noise: common scalars recur by
coincidence. Resolutions, in code: track only DISTINCTIVE values (token/uuid/long-id
shaped); the origin must be ANOTHER principal's response at a SENSITIVELY-NAMED field (a
private context, not a public catalog id); the claim is a documented temporal ordering +
value rarity, never an assertion about server internals; leads-only, flag-gated.

## What it adds
- `engine._chain_provenance` (flag `chain_provenance`, default off): extracts the
  distinctive values consumed in a request (body/query/path), and for each, queries the
  existing Axis-1 provenance table. If the value first surfaced in a DIFFERENT principal's
  response at a sensitive field (or is token-shaped), it emits a **CHAIN_PROVENANCE**
  lead — a cross-principal value migration spanning the request chain that no
  single-exchange payload tool can see.
- Reuses `ProvenanceStore.first_seen_for_other_principal`, so same-principal reuse and
  public-origin values never fire (verified).
- Demo: a `transfer_token` from Alice's private `/api/handoff` response is consumed in
  Bob's `/api/claim` request → CHAIN_PROVENANCE lead.

## Discipline preserved
- Distinctiveness gate (token/uuid/long-id) + private-origin gate (sensitive field name
  or token shape) keep it high-signal; deduped per (value,principal); leads-only and
  flag-gated => byte-identical (findings AND traces) on the original 12, verified with
  `_chain_provenance` in the disabled set across all 10 additive layers.

## Validation
- `test_chain_provenance` 3/3 (distinctiveness gate, cross-principal fire, public-origin
  suppression), all other suites green. Demo: 25/25, 11 findings, 0 FP, 21 leads / 9 kinds.

## Remaining: #6 temporal structural drift (L4).

---

# Phase 10 — Temporal structural drift (L4, idea #6 of 6) — FINAL

Built after a seven-angle critique. The decisive finding from the critique: the existing
value-based TemporalDriftLaw already owns the REVOKED-credential case (and fires on any
non-empty response), so a structural angle there is redundant. The genuine, non-overlapping
gap is privilege NARROWING (role downgrade / plan change) where the credential stays VALID —
the revocation law passes, and only structure betrays that the privileged code path survived
the downgrade.

## What it adds
- Contract `role_change_events` (endpoint + affected principals + kind): privilege-narrowing
  events that do NOT invalidate the credential. The engine records, per principal, the seq of
  the first such event.
- `engine._temporal_drift_pass` (flag `temporal_drift`, default off): if the credential was
  NOT revoked (so TemporalDriftLaw passes) but the principal underwent a prior narrowing event,
  and its later response still carries a privileged-named branch structurally, it emits a
  **TEMPORAL_STRUCTURAL_DRIFT** lead. Applies the SAIE thesis (structure as the leak channel)
  to the temporal axis.
- Demo: Carol is role-downgraded (credential valid), yet her later `/api/dossier` response
  still carries the privileged `internal` branch → drift lead. Strictly disjoint from Alice's
  revoked-token case, which remains a value-based finding.

## Discipline preserved
- Explicitly disjoint from the revocation law (returns early if the credential was revoked);
  anchored on a declared narrowing event with strict seq ordering; leads-only, flag-gated,
  deduped => byte-identical (findings AND traces) on the original 12, verified with
  `_temporal_drift_pass` in the disabled set across all 11 additive layers.

## Validation
- `test_temporal_drift` 2/2 (drift fires on downgrade; disjoint from revocation), all other
  suites green. Demo: 27/27, 11 findings, 0 FP, 24 leads across 10 kinds.

## ALL SIX IDEAS COMPLETE
#1 structural normalisation · #3 missing shadow · #2 GraphQL/BFF demux · #4 disciplined active
probe · #5 cross-step value provenance · #6 temporal structural drift. Each shipped behind its
own opt-in flag, leads-only where 0-FP could not be guaranteed, findings only where Δstate
proves them — with the original engine preserved byte-for-byte throughout.
