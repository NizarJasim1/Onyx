# ONYX / AuthPath — Architecture Map

A deterministic, black-box HTTP **authorization** engine. One rule governs the whole
system: **a finding is emitted only when a Δstate (state-change) differential proves
it — never from a status code, a length diff, or any learned signal** (RL3).

This map exists so a reviewer can navigate ~50 modules in minutes. Read it top to
bottom: the **core pipeline** first, then the **two measurement axes**, then the
**law library**, then the **extension layers**, then a flat **glossary**.

---

## 1. The core pipeline (a request's life)

A captured exchange flows through eight numbered stages. The circled number in each
module's docstring marks its stage:

| # | module | role |
|---|--------|------|
| ⓪ | `scope_guard` | authorisation/safety gate — RL5 fail-safe; declares `target_provenance` (RL20) |
| ① | `transport` | the wire: real `HTTPTarget` (live) + `MockTarget` (calibration fixtures) |
| ② | `contract` | classify each exchange into an **effect class** (OBJECT_ACCESS, PAYMENT, …) |
| ③ | `provenance` | **Axis 1** — value-origin: which principal each value provably came from |
| ④ | `envelope` | **Axis 2** — per-principal HELD vs SEEN authority (measured, order-free) |
| ⑤ | `eil` | **Effect-Invariant Library** — the law catalog; the v3 core |
| ⑥ | `confirmer` | multi-principal **Δstate** differential — turns a candidate into proof (RL3) |
| ⑦ | `poc` | Evidence→PoC emitter — causal path, curl, CVSS, report (RL4) |

`engine` orchestrates the eight stages; `models` holds the shared dataclasses;
`cli` / `serve` are the entry points; `diagnostics` is a read-only self-observer.

---

## 2. The two measurement axes (why attribution is a fact, not a guess)

- **Axis 1 — `provenance`**: every value is tagged with the principal whose response
  first carried it, split into *legitimate* (observe phase) vs *attack* sightings.
  The legitimate-only `legitimate_holders` / `legitimate_seers` / `legitimate_hold_hosts`
  sets are the laundering-proof, order-free ownership signal.
- **Axis 2 — `envelope`**: what each principal **HELD** (addressed + received as its
  own) vs merely **SEEN**. HELD is the strong ownership relation.

Together they let a violation be asserted from **measured facts**, satisfying RL1
(no induction).

---

## 3. The law library (`eil`) and the conservation frame

The EIL catalogs one law per effect class. Each law is *true by the definition of
its effect*, not learned. Detection emits a **candidate**; only `confirmer` convicts.

`conservation` (**RL19**) sits above the per-action laws: authority is a **conserved
quantity**; exercised authority must be ⊆ conserved authority at a coordinate
(object × property × function × **service** × time). The READ-leak coordinate it
proves — another principal's private value surfacing in B's read — is the dominant
BOLA shape that a write-only mutation verifier structurally cannot reach.

`evidence` (**RL20**) applies the same rigor to ONYX's own claims: every metric
carries an evidence tier (T1 independent · T2 self-measured · T3 estimate · T4
by-construction), derived from `target_provenance`, never chosen.

---

## 4. Extension layers (RL6–RL20), grouped by what they add

- **Surface & wire**: `surface`, `surface_map`, `surface_intel`, `codec` (RL7 wire
  format), `economy` (RL6 spend bound), `errnorm` (error-semantics), `idformat`,
  `nestedref` (id intelligence).
- **Acquisition & discovery**: `discovery`, `acquisition` (RL12 spec), `harimport`
  (HAR→spec), `graphql`, `pipeline`, `matrix` (N-principal probe matrix).
- **Authority graph & hierarchy**: `iam` (RL13 graph), `hierarchy` (RL14),
  `ownership_pointer`, `attestation`, `broadcast` + `act_*` (declared-vs-actual).
- **Temporal & cross-session**: `persistence` (RL11 sealed memory), `temporal`,
  `temporal_shape` (RL16 time-series).
- **Structural / combinatorial nerve**: `structural` + `intrinsic` (SAIE),
  `hypothesis` (RL17), `global_invariants` (RL18), `equivalence`,
  `nerve_unification` / `bva_unification` (the unifying laws).
- **Action / write side**: `action_matrix`, `mass_assign`, `chains` (multi-step).
- **Reporting**: `poc`, `cvss`, `diag_export`.

---

## 5. Flat glossary (the less-obvious names)

`harimport` HAR capture → ONYX spec · `errnorm` normalise error semantics ·
`idformat` id-shape intelligence · `nestedref` nested id extraction/swap ·
`surface_intel` strategic read-only surface recon · `surface_map` resource-identity
unification + cross-surface ledger · `bva_unification` / `nerve_unification` the
single laws under which the RL15–18 detectors are special cases · `broadcast` the
target's *declared* decision · `act_bridge` / `act_confront` confront declared vs
actual via Δstate · `attestation` the target's own testimony about who holds a
credential · `economy` bounded-spend model · `codec` wire-format normalisation.

---

## 6. Tests, gates, and how to run

- `tests/run_all.py` — the canonical, **stdlib-only** gate (matches `pytest`).
- `python -m authpath demo` — the labeled calibration; its byte-identical result is
  the regression guarantee.
- `tools/mutate_conservation.py` / `tools/mutate_evidence.py` — mutation harnesses
  with score floors (fail CI below them).
- `tools/check_claims.py` — the RL20 no-bare-metrics gate over `docs/CLAIMS.md`, `README.md` and `docs/overview.md`.
- `make ci` runs all of the above; `.github/workflows/ci.yml` runs it on every push.

**A deliberate non-refactor:** `engine` (~2k LOC) and `confirmer` (~1.4k LOC) are
large but cohesive (one pipeline, one differential). They are intentionally left
intact — the frozen byte-identical calibration plus the full suite are the
maintainability guarantee; splitting cohesive, frozen-behaviour modules would risk
that guarantee for an aesthetic gain a reviewer does not reward.
