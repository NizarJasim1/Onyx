# RL16 — Temporal Authorization-Shape Regression · Build Report

> Derived under **CRUCIBLE** (18 laws, 4 phases). Records the design honestly: what
> it does, the guarantees it earns, and the residue that survives even a perfect build.

---

## 1. The nerve (CRUCIBLE law 2)

> **ONYX measured the authorization *state* at one moment; the vulnerability lives in
> the *derivative* — the change of the authorization-shape over time. On a
> continuously-deployed target the boundary moves daily: a field filtered yesterday
> is exposed today because a deploy regressed the serializer.**

That window — opened by a 3pm deploy, closed by a 9pm hotfix — is invisible to any
point-in-time scanner and to a human with no snapshot of yesterday to diff. It is
the one class that gets *worse* the faster the target ships (CRUCIBLE L10).

## 2. What was built (additive, flag-gated, byte-identical when off)

| Component | File | Role |
|---|---|---|
| `AuthShapeLedger` + `ShapeSnapshot` | `temporal_shape.py` (new) | per (principal, endpoint, object) value-blind shape time-series + regression detector |
| `AuthShapeRegressionLaw` | `eil.py` | candidate when a **sensitive** path crossed **withheld→populated** with **no declared role change** |
| `_confirm_auth_regression` | `confirmer.py` | **intra-principal** read-back proving the regression is **live** (RL3) |
| `AUTH_REGRESSION` effect + `_auth_regression_pass` + role-epoch tracking | `models.py`, `engine.py` | flag-gated additive pass; advances the series each read |
| planted deploy drift + role-change decoy | `transport.py` | `profile2.ssn` regresses on the 2nd read; `clearance.secret` widens only after a promotion |
| 9 guarantees | `tests/test_temporal_regression_rl16.py` | locks every CRUCIBLE constraint |

Calibration moved **31→34 probes, 14→15 findings**. Test suite **233→242**. Flag
default **off** ⇒ ledger never seeded, pass never runs ⇒ pre-RL16 behaviour identical.

## 3. The law, precisely

For one principal P and one resource R, the sensitive fields P may see are invariant
absent a declared role change. So a sensitive path that was structurally
ABSENT/NULL/EMPTY for P at T1 and is PRESENT_POPULATED at T2 — with P's declared
role-epoch unchanged — is an authorization regression: a deploy widened what P sees.
This is conservation, not anomaly: two **measured** value-blind fingerprints, a
specific path named, never "this looks unusual."

## 4. Why it survived the Crucible (laws 10–14)

- **Omniscient adversary (L10):** the defence is "never regress," but a hyperscale
  org's deploy velocity guarantees a stream of regressions on a surface no internal
  canary diffs against an *external* principal's historical shape. The faster they
  ship, the more this finds — it improves with the target's velocity.
- **Kill-test (L11):** the worst confusion is "the object itself gained the value"
  (user filled in their phone) vs "authz broke." Defused by comparing the
  **value-blind** absence-state (ABSENT/NULL vs POPULATED), never the value. Locked
  by `test_ledger_same_populated_value_no_regression`.
- **Sacred false-positive (L12):** the single worst FP is a **legitimate role
  promotion** widening P's view. Defused by the **role-epoch guard** — snapshots
  taken under different declared role-epochs are never compared. Plus sensitive-only,
  plus a **live** read-back so a transient blip cannot confirm. Locked by
  `test_legitimate_promotion_is_not_a_regression`, `test_nonsensitive_regression_is_silent`,
  `test_transient_blip_not_confirmed`.
- **Observability (L13):** value-blind fingerprints, timestamps, declared role events
  — all from the HTTP layer. No internal visibility.
- **Operational viability (L14):** intra-principal read-back (no role swapping). Cost
  is one re-read per candidate. The real cost is **time** — see residue.

## 5. Red lines preserved (CRUCIBLE law 4)

- **RL1 (no induction):** a diff of two measured value-blind fingerprints; the
  role-epoch comes from declared events, never inferred.
- **RL3 (Δstate):** confirmed only when a live read-back still populates the field.
- **RL5 (fail-safe):** no prior snapshot, a role-epoch change, a non-sensitive change,
  or a non-reproducing blip ⇒ abstain.

---

## 6. RESIDUE — what survives even this build (CRUCIBLE laws 15/16)

### Residue A — the first blind window *(type β — managed, turned into the moat)*
The first observation of a (principal, endpoint, object) has no prior to diff, so the
very first regression in a fresh deployment is missed until history accrues. This does
not get "fixed" — it gets **inverted into the advantage** (CRUCIBLE L17): ONYX grows
stronger the longer it runs, while every stateless scanner restarts from zero. The
constraint (needs a past) is the moat (a temporal history a new competitor cannot
clone). Locked as expected behaviour by `test_first_observation_is_blind_silent`.

### Residue B — undeclared role changes *(type α — open)*
The role-epoch guard relies on the role change being **declared** (a `role_change_event`).
A silent promotion (no declared event) could still produce a false positive. Closing
this means detecting a role change from the shape itself — which flirts with induction
and must go through CRUCIBLE before any code. **This is the real open gap.**

### Residue C — deploy attribution *(type β — managed, context not verdict)*
ONYX can correlate a shape jump with a build-id/`X-Served-By` change, but correlation
is not causation. So deploy attribution is offered as **report context**, never as the
verdict — the verdict remains the live-proven leak itself.

### Residue D — cross-session durability *(type γ — operator-wired)*
Within a run the series lives in memory (T1 then T2). True deploy-drift spans sessions;
because every snapshot is **value-blind** (paths + states + timestamps, no values), it
is inherently sealed and safe to persist via the existing `SealedStore`. Wiring that
durability is an operator/deployment choice, declared honestly, not silently assumed.

---

## 7. Epistemic honesty (CRUCIBLE law 12)

A design that survived a brutal protocol against ONYX's own mock, every guarantee
mechanised as a test — **not** a demonstrated hyperscale finding. The strongest true
claim: RL16 opens a *temporal* detection angle structurally unavailable to
point-in-time tools and to humans without a historical snapshot, it is intra-principal
(operationally viable), and it preserves every red line. The honest caveats: it needs
**time** (weeks of snapshots) before it pays off, and **undeclared role changes**
(Residue B) remain the open false-positive gap.
