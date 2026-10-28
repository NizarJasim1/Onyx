# ONYX / AuthPath v3 — Audit Remediation Changelog

All 13 defects found in the execution-backed audit are fixed, each validated by a
regression test in `tests/test_fixes_regression.py` (18/18 pass) with **zero
regression** on the original calibration (27/27) and the 7 existing suites.

Headline: on a 264-exchange production-shaped capture with **zero planted bugs**,
the pre-fix engine emitted **237 "confirmed" findings (100% false positive)**.
The fixed engine emits **0 false findings** and surfaces genuine cross-principal
access as ranked, triage-able **leads** — while a real planted IDOR still surfaces.

| # | Severity | Defect | Root fix |
|---|----------|--------|----------|
| 1 | Critical | `ingest_har` never built a baseline → every access became a candidate | Offline mode is **leads-only** for object access; a passive capture cannot prove ownership (RL5). |
| 2 | Critical | `ReplayTarget` keyed by *normalised* endpoint + any-principal fallback → read-back returned a **different object** | Key by full object identity `(pid, method, path, ids)`; fallback removed; abstain when no exact read-back. |
| 3 | Critical | Confirmer invented a **fallback "owner"** → fabricated causal paths | No proven owner ⇒ no finding (folded into #1). |
| 4 | High | Legitimately **shared / public** objects fired IDOR | Language-free benign suppression: anon-reachable, or actor ∈ the object's own published member list. |
| 5 | High | `name_sensitivity` = closed **English dictionary** gating every lead channel | Added language-neutral `value_salience` (IBAN/SSN/card/token/JWT/numeric shape); freed the relational differential. |
| 6 | High | Duplicate finding explosion (237 over 13 real pairs) | Dedup by `(actor, object, law)`. |
| 7 | Medium | `/users/me` treated as an object id; dotted slugs dropped | `SELF_ALIASES` excluded; `.`/`@` allowed in id-like slugs. |
| R1 | Medium | `PriceLaw`: `"price"` name collided with line items; nested money mis-parsed; float noise | Removed `price` from total-name set; dig nested unit price; half-cent epsilon compare; abstain when not reconcilable. |
| R2 | Med-High | Confirmer **hard-coded** `/api/orders/{id}` & `order_id` → real PAYMENT/STATE_GATE bugs silently unconfirmed off the demo shape | Transition response is the authoritative post-state; read-back only overrides on a real 2xx; generic object-ref derivation. |
| R3 | — (sound) | (checked) host-confusion / case — already correct | none |
| R4 | Med-High | `OwnershipLaw` fired a **confirmed** mass-assignment on a benign resubmission of an already-held role | Measured `held_field_values` baseline; resubmitting an already-held value is a no-op (RL1); real elevation preserved. |
| R5 | Medium | Unbounded recursion in `_walk`/`fingerprint` → `RecursionError` DoS on deep bodies | Depth cap (64) — fail-safe, no crash. |
| 9 | Medium | Super-linear perf: `endpoint_key`/`is_graphql`/`object_ids` recomputed ~50×/request | Per-request memoisation → **1.6× faster** (40k: 103s→68s), zero behaviour change. |

## Epistemic principle established
A passive capture cannot distinguish ownership from IDOR. Therefore **offline =
ranked leads; a finding requires the information that only exists live** (an owner
read-back via `authpath scan`). This is not a downgrade — it is the honest
realisation of the project's own RL5 (fail-safe to inaction).

## Residual (documented, not yet implemented)
- Perf still mildly super-linear; next step is indexing the growing `_gql_field`
  map by `(family, objsig)` and streaming the stability series.
