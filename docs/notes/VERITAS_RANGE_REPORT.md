# VERITAS — Blind Real-World Range · Report

> A faithful INTERNAL predictor of a real engagement, built under the VERITAS protocol
> because the calibration demo cannot predict the real world: its bugs are flags whose
> location the author knows, so ONYX finds them trivially. This range is different — its
> authorization bugs EMERGE from a realistic authz engine, ONYX receives no oracle leak,
> and a hidden ground truth scores the run, so the verdict predicts a real target
> **including ONYX's honest blind spots**.

---

## 1. The governing law

> **An internal test predicts the real world only if BOTH hold: (1) the bugs EMERGE
> from a realistic authorization architecture — they are not planted flags; (2) ONYX
> receives only what a real engagement gives it — no hint of where the bugs are.
> Break either and the test produces false confidence, which is more dangerous than no
> test.**

## 2. The range is research-grounded (every bug maps to a documented real mechanism)

Built after deep reading of real disclosures and the OWASP API Top-10 (2023):

| Bug | Emergent mechanism (as it happens in reality) | Grounding |
|---|---|---|
| **B1** | a different DOOR to the same org exposes the `webhook_secret` the GraphQL canonical FORBIDS — per-door field-level inconsistency | HackerOne **$1,500** GraphQL field-level leak (secondary op returns what the primary withholds) |
| **B2** | the projects LIST over-projects `tax_id` the canonical detail withholds | **BOPLA / API3:2023** (Excessive Data Exposure merged with Mass Assignment) |
| **B3** | a resource's project was re-homed to another org, but its access still follows the OLD org — the child's authority did not follow the parent | **ownership anomaly from a schema change** (transitive ownership; USPTO doc 24: "if A owns B and B owns C, A owns C") |
| **B4** | a serializer regressed across a deploy and a later read exposes `ssn` an earlier read filtered | BOPLA over time / authorization-shape regression |

The authz engine is real: a transitive ownership tree (orgs→projects→resources), RBAC
roles per org, and several doors (REST detail, REST list, GraphQL primary, GraphQL
secondary) to the same backing objects. **No bug is a flag** — each is the consequence
of one realistic mistake in that engine. Decoys (a lean list, a public token) look
bug-shaped but are legitimate by design and must stay clean.

## 3. No oracle leak (VERITAS V2)

ONYX is handed only a contract a real tester reconstructs from observed traffic —
endpoint effect classes and the ownership link the resource body itself advertises
(`resource:r3 → project:p9`). It is given **no** bug locations and **no** sensitivity
hints. The hidden `ORACLE` lives beside the scorer and is never passed to the engine.

## 4. The honest scorecard

```
TRUE POSITIVES (reachable emergent bugs caught): 5/5
  ✓ B1 org:o1       [CROSS_SURFACE]    per-door field-level inconsistency
  ✓ B2 project:p1   [CROSS_SURFACE]    list over-projection
  ✓ B2 project:p2   [CROSS_SURFACE]    sibling, caught by RL17 orchestration
  ✓ B3 resource:r3  [EMERGENT_BREAK]   ownership anomaly (RL18)
  ✓ B4 resource:r1  [AUTH_REGRESSION]  deploy drift (RL16)
FALSE POSITIVES: 0          decoys (cards, status): clean
```

The scorer is **mechanism-aware**: a finding of the wrong class on the right resource
does NOT count (it caught an early self-deception where a coincidental `ssn` leak on r3
was masquerading as the RL18 ownership break — fixed by isolating the deploy drift to
r1, after which RL18 fired on its own merits).

## 5. DECLARED BLIND SPOTS — what a 5/5 does NOT mean (VERITAS V5/V6)

A clean sweep with no declared limits would be exactly the false confidence VERITAS
exists to prevent. Two real classes are structurally out of reach today, and the harness
**probes U1 to prove the miss rather than assume it**:

- **U1 — cross-OPERATION leak.** The literal $1,500 case: a differently-named operation
  (`orgWebhooks`) returns the same data the primary withholds. ONYX unifies identities
  by `(type, id)` from the root field, so `orgWebhooks` is not unified with `org`. The
  range serves this leak and the harness confirms ONYX **misses it** (empirically True).
  Capability needed: an operation-equivalence declaration ONYX does not synthesise.
- **U2 — BFLA write-privilege escalation.** A member succeeding at an admin-only
  mutation. ONYX is read-only/passive by default (AEGIS gate 2); catching this needs
  active multi-principal provisioning and write execution, deliberately not built.

## 6. The range earned its keep — it found a REAL ONYX bug

While debugging why RL18 would not fire on B3, the range surfaced a genuine defect in
ONYX's identity normalisation: `_singular` over-stripped `-es`, turning **`resources` →
`resourc`**, **`devices` → `devic`**, **`services` → `servic`**, **`invoices` →
`invoice`** (wrong). On a real target this silently breaks identity unification — and
therefore cross-surface (RL15) AND ownership (RL18) detection — on a huge class of
common REST collection names. **Fixed**: `-es` is now stripped only for genuine
sibilant plurals (classes→class, boxes→box), while `resources→resource`,
`devices→device`, `houses→house` normalise correctly. This is the highest-value outcome
of the whole exercise: a faithful range catches the silent failures a hand-planted demo
never could.

## 7. What changed

New: `fixtures/realworld_range.py` (faithful black-box target + hidden oracle + declared
blind spots), `fixtures/run_blind_range.py` (blind harness + mechanism-aware scorer),
`tests/test_veritas_range.py` (7 guarantees). Fixed: `authpath/surface_map._singular`.
Suite **264 → 271**. Demo **39/39 · 19 findings** unchanged; the `_singular` fix is
additive and regression-clean.

---

## 8. Epistemic honesty — what this predicts, and what it does not

**Predicts (with grounding):** on a real target whose bugs match the four documented
mechanisms above, and whose traffic ONYX has actually observed, ONYX catches them by the
correct mechanism at zero false positives, and abstains on by-design decoys.

**Does NOT predict / cannot promise:** completeness. A real target differs in three ways
this range cannot fully reproduce — (a) bug classes outside the modelled four (e.g. U1/U2
above, SSRF, business-flow abuse); (b) coverage of traffic ONYX never observed (it only
reasons about what it saw); (c) target-specific vocabulary the operator must declare.
The range is the closest faithful proxy, not a guarantee — and its central value is that
it makes ONYX **fail honestly and visibly** where a real target would defeat it, rather
than report a falsely clean sweep. The user's premise stands: nothing replaces a real
engagement; this is the most truthful internal rehearsal of one.
