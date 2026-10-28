# NERVE BUILD REPORT — identity⇄ownership reconciliation as the general law

## 1. What this build added

A deterministic, zero-false-positive detector for **owner-field BOLA** (Broken Object
Level Authorization, API1:2023) built on a single conserved quantity that also unifies
the four existing engines (RL15–RL18):

> **Decision consistency.** For a fixed `(declared-authority, object, permission)`, the
> target's authorization decision must be invariant under the *path* taken to it. A
> vulnerability is the target contradicting that decision across a path-transformation,
> confirmed by Δstate. ONYX never reconstructs the policy (that is policy-mining =
> induction = false positives = an RL1 violation); it holds the target to the decisions
> and declarations it makes about *itself*.

The build was produced under the **FORGE** protocol: F7 false-positive pre-mortem
*before* any code, each step proven by running break-cases, additive / flag-gated /
byte-identical-when-off, candidates-only until live Δstate confirms.

## 2. The five components (all new, all additive)

| Module | Role | Guarantee |
|---|---|---|
| `authpath/attestation.py` | binds a credential fingerprint to the identity the **target** declares at a self endpoint (`/me`, `/userinfo`, `viewer`) | no token parsing (opaque-safe, RFC 9068); abstains without testimony |
| `authpath/ownership_pointer.py` | discovers *which* response field denotes ownership by correlating its value with the attested identity across ≥2 of a principal's own resources | five FP guards (coincidence, shared-constant, legit-share, policy-grant, reflected-input); candidates only |
| `authpath/equivalence.py` | the nerve signal: "target served Y an object its own data declares belongs to X, with no grant to Y" | six FP guards; no verdict path |
| `authpath/nerve_bridge.py` | confirms each candidate by a **live read-back as the declared owner**, reusing the audited `_read` primitive | four abstain guards (owner-not-provisioned, public, no-substantive-leak, read-fail) |
| `authpath/nerve_unification.py` | descriptive registry: RL15–18 as special cases of the one law | inert; imported by nothing live |

## 3. Engine integration — a strictly separate channel

The nerve is wired into the live engine as an **opt-in separate channel**, never the
existing findings path:

* `observe()` feeds the three ledgers only behind `getattr(self, "nerve", False)` —
  a no-op when off, so `observe()` is byte-identical.
* `engine.nerve_findings()` runs the live confirmation and returns its findings. It
  **never** writes `engine.findings`, so even with the flag **on** it cannot perturb
  any existing verdict or output.
* Default **off**. Nothing in shipping code sets it true; the demo/CLI never enable it.

## 4. Verification (run, not asserted)

* **Flag off ⇒ byte-identical.** Full suite 315 passing; `demo` unchanged at
  `39/39 probes · 19 findings · 3 Δstate-dropped`.
* **Flag on ⇒ catches real bugs, zero FP.** A dedicated VERITAS blind range
  (`fixtures/nerve_blind_range.py`) plants owner-field BOLAs alongside adversarial
  legitimate decoys (a shared resource, a public object, a redacted view). Driven blind
  through `engine.observe`, the nerve scores **TP 2/2, FN 0, FP 0**, each decoy
  suppressed at its correct guard (grant → candidate stage; public → X-2; redacted → X-3).
* **Unification is empirical, not prose.** The nerve's own `decision_conflict_pairs()`,
  using the same audited `surface_map.identify` the engines use, surfaces the RL15
  (representation) and RL16 (time) inconsistencies as candidates.
* **Three-layer isolation proof.** Every engine touch-point is gated; the nerve channel
  never appends to `self.findings`; the new modules are imported by zero pipeline files.

## 5. Three real defects the discipline caught before they shipped

1. **Principal-splitting** — the first attestation design picked a volatile `session`
   field as the self-pointer, splitting one multi-device principal into two. Fixed by
   restricting the pointer to a declared identity-name vocabulary.
2. **A blind test that tested nothing** — the first blind range routed its decoys
   through paths `surface_map.identify` did not recognise, so they were dropped before
   reaching the X-2/X-3 guards. Renamed to recognised collections so the guards fire
   in-situ.
3. **Ownership metadata mistaken for a leak** — reproducing the `owner_id` field is
   trivial in any BOLA and is not independent evidence; it is now excluded from the
   leaked set, so a confirmed leak requires a *substantive* private field.

## 6. Honest residue (fails safe — abstain, never a false positive)

* Detects **owner-field** BOLA (the response declares an owner). Where the target
  declares no owner, the nerve abstains rather than guess.
* Requires the **declared owner's credential to be provisioned** for the live read-back;
  otherwise it abstains (X-1).
* Purely contextual/stateful ABAC conditions (separation-of-duties, "only if not
  published") the target never declares → abstain. The cost is reduced recall, never a
  false positive.
* Demonstrated on a controlled blind range, **not** on a real hyperscale target. That
  is a stated limit of this build, not a claim withheld.

## 7. Tally

`271 → 315` tests. `+5` modules, `+5` test suites, `0` regressions, `0` weakening of any
existing capability — proven byte-identical with the flag off.
