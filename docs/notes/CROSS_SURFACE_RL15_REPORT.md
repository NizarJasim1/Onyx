# RL15 — Cross-Surface Consistency (Boundary Law) · Build Report

> Derived under the **CRUCIBLE** protocol (18 laws, 4 phases). This report records
> the derivation honestly: what the solution does, the guarantees it earns, and —
> per CRUCIBLE laws 15/16 — **the residue that survives even a perfect build.**

---

## 1. The nerve (CRUCIBLE law 2)

> **ONYX assumed identity = the endpoint. Reality: identity = the resource, and the
> endpoint is just one of several doors to it — and the vulnerability lives in the
> disagreement between doors, never in one door.**

Per-endpoint scanners and human testers cannot see this class: the two sides of the
boundary are produced by different code paths (written by different teams, at
different times), so the contradiction only surfaces when something compares them
*simultaneously and deterministically*. On hyperscale this is precisely the unmet
gap — the surface that grows with the org, the inconsistency at cell #743,219 of a
million-cell matrix that no human counted to.

## 2. What was built (all additive, flag-gated, byte-identical when off)

| Component | File | Role |
|---|---|---|
| `ResourceIdentity` + `SurfaceLedger` + door classifier | `surface_map.py` (new) | unify a resource across doors; record the **canonical** door's exposures |
| `CrossSurfaceConsistencyLaw` | `eil.py` | emit a candidate when a **non-canonical** door exposes a **sensitive** field the **canonical** view withholds from the **same principal** |
| `_confirm_cross_surface` | `confirmer.py` | **intra-principal** canonical read-back proving the divergence is live (RL3) |
| `CROSS_SURFACE` effect + `_cross_surface_pass` | `models.py`, `engine.py` | a flag-gated additive pass that can only ADD a finding |
| planted bug + directional decoy | `transport.py` | `accounts` list over-projects `iban`; `cards` detail-richer-than-list decoy |
| 10 guarantees | `tests/test_cross_surface_rl15.py` | locks every CRUCIBLE constraint |

Calibration moved **27→29 probes, 11→12 findings, 3 dropped** (the +1 finding is the
cross-surface leak; the +1 clean is the directional decoy). Test suite **211→221**.
Flag default **off** ⇒ ledger never seeded, pass never runs ⇒ pre-RL15 behaviour
is byte-identical.

## 3. The law, precisely

For one principal **P** and one resource **R**, the set of sensitive fields P may
see of R is a property of **(P, R)** — *not of the door*. So no non-canonical door
may expose a sensitive field for (P, R) that the **canonical** authoritative view
withholds from that same principal. This is conservation, not anomaly: it never
says "unusual" — it says **the server contradicts itself**, and the only barrier
left (the list/graphql serializer) failed.

## 4. Why it survived the Crucible (laws 10–14)

- **Omniscient adversary (L10):** the only defence is making every door share one
  serializer — i.e. rewriting the backend across teams. The org's structural
  complexity *is* the undefendable surface. The bug gets worse as they grow.
- **Kill-test (L11):** the naive "all doors agree" rule false-positives on the
  universal list/detail asymmetry. Fixed by making the law **directional** — only a
  non-canonical door exposing what the canonical door *hides* fires. Locked by
  `test_directional_detail_richer_than_list_is_silent`.
- **Sacred false-positive (L12):** fires only on **sensitive** fields (the existing
  closed vocabulary), after ephemeral-field exclusion, with a **live synchronous**
  canonical read-back so a stale baseline cannot mislead. Three guards, every one
  with a pre-existing seed in the code (no invented mechanism). Locked by
  `test_non_sensitive_divergence_is_silent` + `test_surfaces_agree_confirmer_refutes`.
- **Observability (L13):** uses only HTTP request/response. No internal visibility.
- **Operational viability (L14):** the confirmation is **intra-principal** — P reads
  its own canonical view. **No multi-principal replay**, sidestepping the single
  biggest legal/operational constraint on automated authz testing.

## 5. Red lines preserved (CRUCIBLE law 4)

- **RL1 (no induction):** unification is a structural parse (`resource_name` + the
  deterministic `idformat` decoder). No fuzzy/similarity matching; ambiguous names
  simply fail to unify (fail-safe). Sensitivity is the existing closed vocabulary.
- **RL3 (Δstate):** a candidate becomes a finding only when a live canonical
  read-back proves the field is still withheld there while the door served it.
- **RL5 (fail-safe):** no canonical reference, unreadable canonical, or agreeing
  surfaces all ⇒ abstain, never fire.

---

## 6. RESIDUE — what survives even this build (CRUCIBLE laws 15/16)

Honesty demands these be named, not buried. **A "solved" problem with hidden residue
is the most dangerous kind.**

### Residue A — "What is the canonical door?" on non-REST APIs *(type α — NOW CLOSED for GraphQL)*

**Closed via the intent-declared canonical.** On GraphQL/RPC there is no REST detail
view to use as the authoritative reference — but the server *declares its own answer
explicitly*: a field returned as an authorization-class error (`FORBIDDEN`,
`UNAUTHORIZED`, …) is the server saying, in its own words, "this principal may not
see this field." That explicit denial IS the canonical "withhold" — and unlike the
REST case it is **stronger**, because it is the server's stated intent rather than an
inferred absence.

Implementation (all additive, same flag):
  * `identify_graphql` binds a GraphQL op to the same `(type, id)` identity a REST
    door produces (type = root field, id = id-shaped variable), so a GraphQL denial
    and a REST list leak for the same resource unify.
  * `SurfaceLedger.record_denials` stores the sensitive fields the server returned as
    authz-denied (via the existing 0-FP `graphql.authz_denied_paths`), plus the
    request, so the denial can be re-proven live.
  * `CrossSurfaceConsistencyLaw` gains an **intent-declared trigger** that fires when
    a door exposes a sensitive field the ledger recorded as explicitly FORBIDDEN for
    that (resource, principal) — and it works **even when there is no REST canonical
    at all** (the GraphQL-only case).
  * `_confirm_cross_surface` gains a branch that **replays the GraphQL operation** as
    the same principal and confirms the field is STILL forbidden while another door
    served it — an intra-principal Δstate proof with no REST detail required.

Calibration moved **29→30 probes, 12→13 findings** (the +1 finding is a GraphQL-only
`vault.secret` the REST list over-projects — catchable by the intent path and by
nothing in RL15's exposed-reference path). Tests **221→227** (+6 GraphQL guards,
including the `null`-is-not-a-denial kill-test). Flag still default-off ⇒ inert.

**Kill-test held (CRUCIBLE L11):** a field returned `null` is never a denial — only an
authz-class error is. `test_null_is_not_a_denial_killtest` locks this; it is the guard
against the absence/forbidden confusion that killed this idea for everyone before.

**Why this is the hyperscale-relevant half:** GraphQL/RPC is the bulk of Google's and
Microsoft's external surface, and field-level authz there is written resolver-by-
resolver across thousands of resolvers — the structural complexity that makes a
uniform field-filter undefendable (CRUCIBLE L10). The intent-declared canonical reads
the server's own per-resolver denials and catches the door that contradicts them.

**Residue that remains even after this closure:**
  * **Persisted/APQ queries** *(type α — NOW CLOSED, see below)*.
  * **gRPC/RPC field naming** *(type α — NOW CLOSED via the existing SchemaRegistry,
    see below)*.
  * **Two legitimate observations needed** *(type β — managed, turned into the
    feature)*: the GraphQL path needs both the FORBIDDEN observation and the leaking
    door. That cross-observation requirement is not a weakness — it *is* the detection
    (field-level BOLA is, by definition, "a field served to whom it was denied").

---

### Residue A-1 — Persisted / APQ queries *(type α — CLOSED, #2-a)*

Hyperscale GraphQL sends a **sha256 hash** instead of the query text. To a
per-request tool the intent is opaque — but the hash is a *reference to a text the
engine can observe once at registration*. We learn `hash → operation` from that one
observation (RL1: measured, never guessed) via a `PersistedQueryRegistry`, and
resolve every later hash-only request from the learned map. When the text was never
observed, the hash itself is a **stable identity key** (same query ⇒ same hash for
every principal), so a hash-keyed cross-principal differential still works — with a
synthetic `persisted:<hash>` type rather than a real root field.

Implementation (entirely inside the flag-gated path — `looks_like_graphql` is
**unchanged**, so global GraphQL detection is byte-identical):
  * `graphql.persisted_query_hash` / `PersistedQueryRegistry` — learn + resolve.
  * `surface_map.identify` / `identify_graphql` accept the registry and resolve a
    hash-only request to its `(type, id)`.
  * `SurfaceLedger.observe_persisted` / `record_denials` handle hash-only requests.
  * the confirmer replays the (hash-only) operation to re-prove the denial.

Calibration: a `wallet.private_key` denial learned from a **HASH-ONLY** request
(intent recovered from a registration seen earlier, from a *different* principal)
catches a REST list leak → confirmed. Tests add the registration→hash-only→leak
end-to-end, the unknown-hash synthetic-identity case, and the flag-off guard.

### Residue A-2 — gRPC / protobuf field naming *(type α — CLOSED for free, #2-b)*

gRPC sends positional protobuf (`f1`, `f2`, …) with no field names, and sensitivity
is name-based. **This dissolves into cross-surface with NO new detection code**: the
engine already runs every body through `codec.normalize_body`, and a registered
protobuf schema (`SchemaRegistry` + `apply_schema`) renames the positional keys to
their semantic names *before* any law runs. Once named, a gRPC body is
indistinguishable from JSON to the cross-surface law.

Proven end-to-end with **real protobuf bytes**: a gRPC `wallets` list
(`0a0337303012…`) is decoded, schema-named to `{id, private_key}`, and produces a
confirmed cross-surface finding against a GraphQL-declared denial — through the
existing decode path. The only operator input is the schema (the same input gRPC
analysis already requires); without it, the field names are genuinely unavailable
(type γ — an external input, honestly declared, never guessed).

---

### Residue that *still* remains (CRUCIBLE honesty)
  * **APQ before observation** *(type α)*: a session whose registration predates the
    capture resolves only to the synthetic hash-keyed identity (cross-principal
    differential still works; cross-door REST↔GraphQL unification needs the text).
  * **gRPC resource identity on non-REST paths** *(type γ)*: the schema names the
    *fields*; binding a `/Service/Method` path to a resource `(type,id)` is the same
    open item as any non-REST surface, mitigated where the id rides in the message.

### Residue B — semantic absence under sparse coverage *(type α — solvable, mitigated)*
"A field is absent because it is withheld" vs "absent because empty for this
instance." Mitigated here by the live synchronous read-back + sensitive-only +
canonical-reference triple, but a field that is structurally empty for one instance
across *all* doors could still mislead a future generalisation. Bounded today; watch
it when Residue A is addressed.

### Residue C — coverage dependence *(type γ — external, declared)*
The law needs the canonical door to have been **observed** for (resource, principal)
in the baseline. Incomplete baseline ⇒ missed findings (a false-negative, never a
false-positive — the fail-safe direction). This is a coverage property of the
engagement, not a code defect.

### Residue D — program policy *(type γ — external, declared)*
Even though confirmation is intra-principal (a major win), large programs still cap
automated traffic. The pass is cheap (two reads per candidate, budgeted via the
existing ledger), but viability is ultimately the operator's call, declared honestly
via Scope-Guard — never silently assumed.

---

## 7. Epistemic honesty (CRUCIBLE law 12)

This is a **design that survived a deliberately brutal protocol against ONYX's own
mock**, with every guarantee mechanised as a test. It is **not** a demonstrated
finding on a real hyperscale target. The strongest claim that is true: RL15 opens a
detection angle that is *structurally* unavailable to per-endpoint tools and human
session-by-session testing, it is intra-principal (operationally viable), and it
preserves every red line. The honest caveat: **Residue A (non-REST canonical) is the
gate between this and Google/Microsoft's GraphQL/RPC surfaces, and it is not yet
closed.**
