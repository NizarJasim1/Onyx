> ⚠️ **Historical deep spec.** This file uses the project's earlier framing (it predates the competition and still refers to the tool by its old name, "DPT"). It is kept for depth and provenance. For the **current** navigable module map see [`../ARCHITECTURE.md`](../architecture.md); for the judge-facing story see [`../PITCH.md`](../overview.md).

---

# AuthPath — **v3** — Architecture & Build Handoff
### (formerly "DPT" — Decision Provenance Tracer; renamed to reflect its true center: **Authority-Provenance for web/API authorization & business-logic bug hunting**)

> **What this file is:** The complete, self-contained architecture for **AuthPath v3**, a precision bug-bounty engine that proves *where the authority for each privileged action came from* and flags any action whose effect exceeds the authority the acting principal actually holds. It is written to be read cold by any capable AI or engineer and used to build, harden, and evaluate the tool. Read top to bottom before proposing changes.
>
> **What changed from v2:** v2 governed an **AI agent's MCP trajectory**. Deep analysis established that v2's authority-provenance model *is itself* the classic web-app authorization mindset (IDOR / mass-assignment / business-logic / confused-deputy) lifted to the agent layer. v3 **lowers the lift**: it runs the same two-axis authority-provenance engine one layer down, at **HTTP/API traffic**, where (a) the values are structured and stable so causality is *genuinely* deterministic (no LLM in the value path — v2's single deepest crack disappears), and (b) the money is. The MCP-proxy becomes one *transport adapter* of a more general engine, so no v2 work is lost. v3 also **removes** v2's most fragile research piece — the *learned* Plan/state-machine for business logic — and replaces it with a **derived** invariant library that cannot be laundered by induction. See **§15** for the full v2→v3 comparison.
>
> **Owner context (shapes every recommendation):** Based in Iraq, below-average hardware, no capital. Runs on a single laptop, free/permissionless tooling (mitmproxy / Burp community extension class), no paid infra. Hot path stays cheap; expensive/stateful work runs off the critical path. The deliverable must convert to **paid HackerOne/Bugcrowd findings**, so report-quality output is a first-class requirement, not an afterthought.
>
> **How an AI assistant should use this file:** Help with implementation, hardening, evaluation, incremental delivery. Respect the rejected-complexity list (§12) and the design rules (§13). Every addition must name the specific vulnerability class or failure it eliminates and confirm it preserves the five core properties (§13.2). Treat external/empirical claims (§11) as flagged-for-verification, not established.

---

## 0. One-paragraph summary

AuthPath v3 is a **deterministic authorization & business-logic provenance engine** that sits in the HTTP/API path of a target the owner is authorized to test. It does not ask *"is this request anomalous?"* (statistics) nor *"did this status code differ across users?"* (the false-positive engine of existing authz tools). It asks: **"does this successful privileged action draw its authority from the acting principal's own session-envelope, or did a value (object-id, hidden field, amount, state token) grant itself authority it was never given?"** It tracks **two orthogonal provenance axes** carried over from v2 — *value-origin* (which response a value provably came from) and *authority* (the **principal envelope**: what the legitimately-authenticated user actually did and may do) — and adds the v3 core: an **Effect-Invariant Library (EIL)**, a small reusable catalog of conservation/consistency laws that are **true by the definition of an effect-class** (e.g. PAYMENT ⇒ `amount_paid ≥ amount_due`; PRIVILEGE_GRANT ⇒ `granted ⊆ granter`; OBJECT_ACCESS ⇒ `object_id ∈ self_envelope`). A **multi-principal differential engine** replays each request under N identities and confirms a finding *only by proven state-change*, never by raw status-code diffing. Causality is **proven, not inferred**, because HTTP values are structured and pass through no model that paraphrases them. The unifying invariant: **authority cannot be laundered, and a privileged action cannot violate the conservation law of its own effect-class.** Every finding emits a human-readable causal path **plus an auto-generated, reproducible PoC and impact narrative** — because the violated law names its own impact. No anomaly model, no learned baseline, deterministic on the hot path.

---

## 1. The one idea that organizes everything (read this first)

v2 made one jump: stop **inferring** data causality (fragile string-matching) and start **proving** it (referent value-flow). v3 makes the *same jump one level up*, and states the meta-principle that now governs every layer of the tool:

> **Do not *learn* what you can *derive*. Do not *infer* what you can *prove*. Anchor every judgment either to something *declared by a trusted party* or *true by the definition of the effect-class*. Induction/anomaly is forbidden in every layer — because an attacker controls the very traffic you would induce from.**

v2's deepest residual weakness — the *learned* business-logic Plan — was the one place induction sneaked back in: a rule learned from "legitimate traffic" cannot tell *"this never happened because it is forbidden"* from *"it never happened because nobody tried."* v3 removes that crack at the root. Business-logic correctness is no longer **learned** from traffic shape; it is **derived** from three deterministic sources of truth:

1. **The application's own declared contract** — OpenAPI / GraphQL introspection / response schemas. The app *declares* what its fields mean. (The trusted-input analogue of v2's Mandate derivation.)
2. **Conservation / consistency laws bound to the effect-class, true by definition** — encoded **once** into the EIL, reused across every target forever.
3. **The principal's own observed envelope** — what the authenticated user legitimately did this session (a *measured fact*, not an induced rule).

And every vulnerability class collapses into one engine: a successful action is a finding **iff** its proven effect exceeds the acting principal's envelope **or** violates the conservation law of its effect-class.

| Vulnerability class | What "laundering" looks like here | EIL law that catches it |
|---|---|---|
| **IDOR / BOLA** | object-id from another session grants itself access | `OBJECT_ACCESS: object_id ∈ self_envelope` |
| **Mass assignment / BOPLA** | client-supplied privileged field grants itself ownership/role | `OWNERSHIP: privileged_field immutable by non-owner` |
| **Business logic** | state/value transition skips a gate or breaks conservation | `PAYMENT/STATE_GATE/INVENTORY/COUPON` laws |
| **Confused deputy / SSRF-as-authority** | server's broad authority used on attacker's behalf | `AUTHORITY: action_effect ⊆ principal_envelope` |

**The whole tool is one principle (`effect ⊆ authority ∧ effect respects its conservation law`) applied through one reusable law library.** This coherence is the design-quality signal: v3 is not four detectors, it is one engine + one growing catalog.

---

## 2. Problem statement (refined from v2 §2)

The bug-bounty automation stack has mature coverage of **injection-shaped** vulns (SQLi/XSS/SSRF/template — handled well by nuclei/Burp/sqlmap) and **shallow authz diffing** (Autorize/AuthMatrix), but a persistent **unsolved frontier**: **authorization-flow and business-logic correctness**, which are (a) where the largest bounties live, and (b) where automation is weakest because the bug is *semantic*, not pattern-based.

Existing authz tools diff status codes/response lengths across users. This is the source of their crippling false-positive rate: a `200` for user B on user A's object can be a vuln, a redirect, a soft-deny, a cached page, or an empty-but-authorized read. They detect *difference*, not *authority violation*. AuthPath's contribution is to replace **difference-detection** with **authority-provenance + effect-conservation proof**, making the signal a *property violation with a causal path*, not a *statistical diff*.

Why this framing is right: it is the exact authorization mindset that defines IDOR/business-logic/confused-deputy — *"the system acted with authority it should not have had, on behalf of input it should not have trusted"* — now expressed as a checkable invariant over proven value-origin and a derived law library, rather than a heuristic diff.

---

## 3. Threat model & operating model (v3)

**In scope (vulnerability classes the engine claims):**
- **IDOR / BOLA** (broken object-level authorization).
- **Mass assignment / BOPLA** (broken object-property-level authorization).
- **Business-logic flaws**: payment/price tampering, state-gate skipping (e.g. fulfillment without settled payment), quantity/inventory abuse (negative/oversize), coupon/discount reuse, replay of single-use operations, workflow-order violations.
- **Confused-deputy / function-level authz (BFLA)**: server acts with its own privilege rather than the requester's.
- **Authority laundering** (the unifying class): a value acquiring authority it was not granted, via any channel (cross-object, cross-principal, cross-session, hidden-field).

**Out of scope (explicit — left to other tools, declared not silently assumed):**
- **Injection-shaped vulns** (SQLi/XSS/SSRF-as-RCE/template/command). AuthPath does not compete with nuclei/sqlmap/Burp scanner here; it composes with them. (SSRF is in scope *only* as a confused-deputy/authority case, not as a payload-injection case.)
- Memory-corruption, crypto, DoS, network/OS-layer.
- Targets where the owner is **not authorized to test** — hard-blocked by Scope-Guard (§7.5), non-negotiable.

**Operating model:**
- The engine sits in the HTTP path of a target the owner is authorized to test (proxy / browser-driven / replay), under explicit program scope.
- The app's contract (OpenAPI/GraphQL/inferred) and the engine's EIL are the **trusted sources of truth**; all traffic values are **untrusted by default**.
- Multiple authenticated principals (≥2 low-priv accounts + 1 anonymous) are provisioned by the tester; the engine never fabricates credentials.

---

## 4. Architecture (engine + adapters + law library)

AuthPath v3 = **transport adapters** + **deterministic provenance engine** + **Effect-Invariant Library** + **multi-principal differential confirmer** + **evidence→PoC emitter**. No anomaly model. No learned baseline. No LLM on the hot path.

```
                          ┌───────────────────────────────────────────────────────────┐
  Authorized target ◀────▶│  AuthPath v3 ENGINE                                          │
   (in-scope only)        │                                                              │
  Principals: A, B, anon  │  ⓪ Scope-Guard (first-class, fail-safe to "do nothing")      │
                          │  ① Transport Adapter  (HTTP-proxy │ browser │ MCP-shim)      │
                          │  ② Contract Resolver  (OpenAPI/GraphQL/inferred → effects)   │
                          │  ③ Value-Origin Provenance (axis 1 — proven, deterministic)  │
                          │  ④ Principal-Envelope Engine (axis 2 — measured authority)    │
                          │  ⑤ Effect-Invariant Library (EIL — derived laws, reusable)    │
                          │  ⑥ Multi-Principal Differential Confirmer (proof by Δstate)    │
                          │  ⑦ Evidence→PoC Emitter (causal path + reproducible PoC)       │
                          │                                                              │
                          │  side stores (off hot path, hashes/levels/contracts only):   │
                          │    [Principal Envelopes]  [Contract Cache]  [EIL catalog]    │
                          └───────────────────────────────────────────────────────────┘
                                              │
                                              ▼
            CONFIRMED-FINDING / CANDIDATE(needs-confirm) / CLEAN  +  causal path + auto-PoC + impact class
```

### 4.1 Axis 1 — Value-Origin Provenance (kept from v2's referent idea, now *genuinely* deterministic)
Every structurally-significant value in a response (object ids, owner ids, tokens, amounts, prices, state flags, quantities, coupon codes, URLs) is tagged with its **origin**: `{response_id, principal, endpoint, field_path, session_id, observed_at}`. Because HTTP payloads are structured (JSON/form/query/GraphQL) and **no model paraphrases them in the value path**, origin tracking is parsing + table lookup — **proven, not inferred**. This is the v2 referent idea with its single deepest crack (LLM may rewrite a value, breaking the link) **structurally removed**: there is no LLM between observe and use.

### 4.2 Axis 2 — Principal Envelope (the measured-authority axis)
For each authenticated principal, the engine maintains the **envelope**: the set of `(effect_type, scope, object-ids, value-ranges)` the principal **legitimately exercised or was granted** this session — a *measured fact*, not an induced rule. `self_envelope` is what makes `OBJECT_ACCESS: object_id ∈ self_envelope` checkable. The envelope is grown only by the principal's own authenticated actions (the trust-raising analogue of v2's elicitation).

### 4.3 ② Contract Resolver
Resolves the target's declared contract (OpenAPI, GraphQL introspection, response-schema inference) into a per-endpoint **effect classification** `(effect_type, scope, security-critical parameters)`. Where a contract is missing, falls back to **dynamic effect inference** (v2 §7.2 — declared-vs-observed behavior) **under higher caution**. Critically: the contract is used to **classify the effect-class**, *never* to learn *what is forbidden* — forbiddenness comes only from the EIL. So a partial/absent contract weakens classification (fail-safe) and never compromises law soundness.

### 4.4 ⑤ Effect-Invariant Library (EIL) — the v3 core
A small, hand-authored, **reusable** catalog. Each entry: `(effect_class, invariant_predicate, impact_class)`. The predicates are **true by definition of the effect**, not learned:

```
OBJECT_ACCESS   : accessed.object_id ∈ acting_principal.self_envelope
OWNERSHIP/BOPLA : privileged_field(role|isAdmin|owner_id|verified|balance) is server-authoritative,
                  immutable via client-supplied value by a non-owner principal
AUTHORITY/BFLA  : action.effect ⊆ acting_principal.envelope            (confused-deputy)
PAYMENT         : amount_paid ≥ amount_due  ∧  value conserved  ∧  paid-state monotonic & terminal
PRICE/AMOUNT    : server-side amount == Σ(server-side line items)      (client amount is advisory only)
STATE_GATE      : terminal/privileged state reachable only via its declared predecessor gate,
                  bound to the SAME object (fulfillment ⇐ settled-payment(order_id))
INVENTORY/QTY   : 0 ≤ requested_qty ≤ available  ∧  stock decremented == purchased
COUPON/SINGLE-USE: redemptions(token) ≤ declared_limit  ∧  idempotent replay has no extra effect
```

The catalog is **the moat and the compounding asset**: every new bug found anywhere (by anyone) becomes a new reusable invariant entry. Coverage *grows with use*; it is not capped by the quality of a learned dataset.

### 4.5 ⑥ Multi-Principal Differential Confirmer (kills the false-positive engine)
For each candidate, the engine replays the action under N principals (A, B, anon) and **confirms only by proven Δstate**, never by raw status diff: an authenticated read-back (as the *owner*) must show the security-critical property actually changed/leaked. This is the precision mechanism — the difference between "B got a 200" (noise) and "B mutated A's `owner_id` and a confirming read proves it" (a real, reportable finding).

### 4.6 ⑦ Evidence→PoC Emitter (report-quality is first-class)
Every CONFIRMED-FINDING emits: (a) the **causal path** (which value, from which principal's response, granted itself which authority), (b) a **reproducible PoC** (the minimal request sequence that produced the violation), and (c) an **impact narrative pulled from the violated law's `impact_class`** (PAYMENT→financial, PRIVILEGE→privesc, OBJECT_ACCESS→data exposure). *The violated invariant writes its own report.* An anomaly score cannot do this — it does not know *why* its deviation matters. This is what converts detection into a paid bounty.

---

## 5. The pillars (each names the class it kills)

| # | Pillar | Closes | Hot path? |
|---|---|---|---|
| p1 | Value-origin provenance, structured & LLM-free | paraphrase laundering / false coincidental links (v2's deepest crack) | yes (deterministic) |
| p2 | Principal envelope (measured authority) | IDOR/BOLA, confused-deputy | yes |
| p3 | Effect-Invariant Library (derived laws, not learned) | business-logic, mass-assignment, the v2 learned-Plan crack | yes (predicate eval) |
| p4 | Contract resolver → effect classification | endpoint mislabeling, scope confusion | yes (lookup) |
| p5 | Multi-principal differential, confirm-by-Δstate | the false-positive engine of existing authz tools | yes |
| p6 | Evidence→PoC + law-named impact | unreportable findings (rejected bounties) | off-path emit |
| p7 | Scope-Guard, fail-safe to inaction | program-scope violation = ban = zero income | yes (gate) |
| p8 | Cross-session sealed envelopes (from v2) | replay/single-use abuse across sessions | no (side store) |

---

## 6. The EIL: authoring and growth (v3's load-bearing piece)

The EIL is where the v2 *learned-Plan* problem is solved by **derivation, not induction**.

**Mechanism 1 — Effect classification.** Resolve each operation to an effect-class via contract (preferred) or dynamic inference (fallback, higher caution). This is the only probabilistic step, and it is **fail-safe**: a misclassification errs toward *more* scrutiny / a candidate flagged for confirmation, never toward silently passing a violation.

**Mechanism 2 — Law derivation (not learning).** The invariant predicate is taken from the EIL entry for that effect-class — a law true by the definition of the effect. Nothing is induced from traffic frequency. "This transition never appeared in legitimate traffic" is **not** evidence of anything; only "this transition violates the effect's conservation law" is.

**Mechanism 3 — Envelope binding.** Security-critical parameters are checked against the acting principal's measured envelope using **value-origin proof** (axis 1): e.g. `accessed.object_id` must trace to a response the acting principal legitimately received.

**Mechanism 4 — Δstate confirmation.** A candidate becomes a CONFIRMED-FINDING only after an authenticated read-back proves the security-critical state actually changed/leaked (§4.5).

**Mechanism 5 — Offline calibration (the scientific contribution).** The only thing to validate is now **(a) EIL law correctness** and **(b) effect-classifier accuracy** — both testable on *labeled* targets (Juice Shop, crAPI, VAmPI, PortSwigger labs): does each law fire on the known bug and stay silent on the benign path. Metrics: **detection rate per class** (target high) and **false-positive rate** (target near-zero, structurally enforced by confirm-by-Δstate). Crucially, **precision is individually verifiable** — every finding ships with a proof a human can check — so the numbers are a reviewable chain of evidence, not a black-box claim.

**Why this survives the one remaining probabilistic step:** effect-classification runs (a) off the critical decision (it only *routes* to a law), (b) is contract-anchored where possible, (c) is fail-safe (errs toward confirmation, never toward pass). Non-determinism is confined to a fail-safe position — the same property that made v2 sound, preserved.

---

## 7. Hardening & graduated response

### 7.1 Confirm-by-Δstate over status-diff (precision core)
Never report on a status-code or length difference alone. A candidate is promoted only when an authenticated read proves the critical property changed/leaked. This single rule eliminates the dominant false-positive source of Autorize/AuthMatrix-class tools.

### 7.2 Dynamic effect classification (kept from v2 §7.2)
Where no contract exists, infer effect from declared-vs-observed behavior; a declared-READ endpoint whose params carry mutation/external-destination values → contradiction → higher caution + candidate.

### 7.3 Conservation laws need both sides — graded coverage (honest)
Some laws (value-conservation across a transfer) need both endpoints of a transaction. The multi-principal engine observes the counterparty *by being the other principal*. Where only one side is visible, the engine asserts the weaker single-sided laws that still hold (monotonicity, bounds, idempotency) and **declares** the coverage limit rather than over-claiming.

### 7.4 Over-approximate then prune (kept from v2 §7.4)
When influence is plausible but unproven, record a candidate and prune infeasible ones; the burden here is small because envelope-binding + EIL resolve most cases deterministically.

### 7.5 Scope-Guard (NEW, first-class, fail-safe-to-inaction)
Operates only on hosts inside the loaded program scope; honors rate-limits; **dry-run by default**; no destructive/irreversible action (PAYMENT/DELETE confirmation flows) without explicit operator approval. This is the v2 fail-safe principle aimed at the *target*: out-of-scope = program ban = zero income. An error here must **do nothing**, never act.

---

## 8. Cross-session layer (kept & re-aimed from v2 §8)

The unifying insight survives unchanged: **do not build a persistent cross-session graph; carry only the sealed level/envelope with the value.**
- **Sealed principal envelopes:** a principal's authority and the object-ids it legitimately holds are sealed per session; a single-use token or settled-order state cannot "wake up" reusable in a later session — defeats cross-session replay / coupon-reuse / payment-replay.
- **Contract cache + behavioral fingerprint (from v2 r7):** detects an endpoint changing its declared/observed effect between sessions (a target-side behavior change), under impact-graded re-attestation.
- Storage: contracts + hashes + levels only, **zero raw sensitive payload** — within modest-hardware budget (grows with #endpoints, not #requests).

---

## 9. Offline harness & calibration (no hot-path cost)

Two ranges, both **labeled** (this is why v2's benchmark crisis is gone):
- **Functional/labeled range:** OWASP Juice Shop, crAPI, VAmPI, PortSwigger Web Security Academy labs — each contains *known* IDOR/BOLA/mass-assignment/logic bugs. The harness verifies each EIL law fires on the planted bug and stays silent on the benign path. *(Verify exact lab/bug inventory against current releases.)*
- **Counterfactual replay range:** vary one input, observe which downstream values/states change, to validate value-origin completeness and law triggering — off the hot path.

Calibrates four things: (1) **value-origin extraction completeness** per value class; (2) **effect-classifier accuracy** (contract-anchored vs inferred); (3) **EIL law correctness** (fires on bug, silent on benign); (4) **false-positive rate** (target near-zero via confirm-by-Δstate). All four are checkable against ground truth — no learned "normal" distribution required.

---

## 10. Build roadmap (v3; each milestone independently useful & demoable)

- **M0 — Transport adapter + multi-principal replay.** Proxy in path; replay each request under A/B/anon; log everything. *See cross-principal behavior.*
- **M1 — Value-origin provenance + principal envelopes.** Track ids/tokens/amounts; build `self_envelope`. *Proven authority labels.*
- **M2 — IDOR/BOLA via `OBJECT_ACCESS` law + confirm-by-Δstate + Scope-Guard.** *First confirmed, reportable, paid-class finding.*
- **M3 — Mass-assignment via `OWNERSHIP` law (confirm by authenticated read-back).** *Second class; effect-typed field injection.*
- **M4 — EIL business-logic laws (PAYMENT, PRICE, STATE_GATE, INVENTORY, COUPON) + Contract Resolver.** *Highest-bounty class; the core differentiator.*
- **M5 — Evidence→PoC emitter (causal path + reproducible PoC + law-named impact).** *Detection → submittable report.*
- **M6 — Calibration on labeled targets (§9): per-class detection rate, near-zero FP.** *Defensible numbers.*
- **M7 — MCP transport adapter.** Revives v2 as a special case of the same engine (no work lost).

---

## 11. Evaluation & success criteria — with honesty flags

- **Per-class detection rate** on labeled targets (IDOR/BOLA, BOPLA, business-logic, BFLA).
- **False-positive rate** on benign workflows (target near-zero; structurally enforced by confirm-by-Δstate — the headline advantage over existing authz tools).
- **Report-acceptance proxy:** % of confirmed findings that emit a complete causal path + reproducible PoC + impact narrative.
- **Latency budget** low enough for modest hardware; cross-session work off the hot path.

> **⚠ Unverified — verify before any writeup or real engagement.** (1) Exact bug inventory/versions of Juice Shop / crAPI / VAmPI / PortSwigger labs. (2) That no existing tool already combines multi-principal + deterministic provenance + derived business-logic laws + auto-PoC (positioning claim — verify against current Autorize/AuthMatrix/Akto/StackHawk feature sets). (3) Any bounty-value or market figures. (4) That target programs permit automated multi-principal replay (some forbid automation — read each program's rules; Scope-Guard enforces, but the tester must verify policy). Treat all as TODO-verify, not fact.

---

## 12. Rejected complexity (DO NOT re-add without a NEW, concrete justification)

Carried from v2 and extended:
- **Anomaly / learned baseline of "normal" traffic.** The original sin v2 rejected and v3 finishes removing (the learned-Plan). Induction over attacker-influenced traffic cannot distinguish forbidden from untried. Rejected at every layer.
- **Detection-time LLM / model internals.** Doubles cost+latency; destroys determinism and the proof advantage.
- **Trained ML classifier for vuln detection.** Needs labels the owner lacks; converts an explainable engine into a black box.
- **Injection-vuln scanning (SQLi/XSS/etc.).** Out of scope; composes with nuclei/Burp instead of duplicating them.
- **Persistent cross-session provenance graph.** Storage/privacy-expensive; sealing levels onto values (§8) is sufficient.
- **Trusting the target's self-reported authorization.** Trusting the tested party to secure itself is an authority-laundering vector by design.

> Any future addition must show: (1) the specific class it newly catches, (2) no lighter mechanism already covers it, (3) it does not degrade explainability, latency, the no-anomaly/no-detection-LLM core, the fail-safe property, or Scope-Guard.

---

## 13. Design rules for anyone (human or AI) extending AuthPath v3

1. **Name the class first.** No feature without a specific vulnerability class or failure it eliminates.
2. **Protect the five core properties:** *deterministic on the hot path · no anomaly/learned baseline · no detection-time LLM · explainable causal-path + reproducible PoC output · Scope-Guard fail-safe-to-inaction.* An addition eroding any is rejected by default.
3. **Derive or measure; never induce.** Every rule must trace to a declared contract, an effect-class conservation law, or a measured principal action — never to "what legitimate traffic looked like."
4. **Confirm by Δstate, never by status-diff.** Precision is non-negotiable; false positives kill the tool's economic value.
5. **Keep the hot path cheap.** Expensive/stateful work (replay, calibration, cross-session) runs off the critical path.
6. **Conservatism over silence, but inaction over scope-violation.** When influence is plausible but unprovable, over-approximate then prune; when scope is uncertain, do nothing.
7. **Push non-determinism (effect-classification) to a fail-safe position** — it routes to a law, errs toward confirmation, never toward pass.
8. **Every finding must be reportable.** A detection that cannot emit a causal path + PoC + impact is not done.

---

## 14. Open problems (state honestly to any collaborator)

- **EIL coverage is bounded by the catalog.** A logic bug outside the authored laws is missed — but this is an *honest, growing* bound, strictly better than the learned-Plan (which missed the same bugs *and* added false positives), and the catalog compounds with every bug found.
- **Effect-classification remains probabilistic** where no contract exists. Confined, contract-anchored, fail-safe — measured, not eliminated.
- **Two-sided conservation laws need both transaction sides.** Mitigated by multi-principal observation; single-sided cases assert weaker laws and declare the limit.
- **Some programs forbid automated replay.** Scope-Guard enforces technical scope, but legal/policy scope is the tester's responsibility — declared, not assumed.
- **Value-origin completeness depends on the extractor** recognizing all critical value classes; calibrated on the harness, but novel encodings must be added.
- **The scientific value is per-class precision/recall on labeled targets**, not a complete solution. Stay skeptical of "complete" claims — including these.

---

## 15. v2 → v3 comparison (what actually changed and why)

### 15.1 The single biggest change
**v2 governed an AI agent's MCP trajectory by authority-provenance; v3 runs that same authority-provenance engine at the HTTP/API layer, where causality is genuinely deterministic and the bounties are — and replaces v2's *learned* business-logic Plan with a *derived* Effect-Invariant Library.** v2's deepest crack was that "proven causality" depended on an LLM honoring opaque referents (and exposing values for utility broke the proof). At the HTTP layer there is **no LLM in the value path**, so causality is proven by construction. v2's most fragile research piece (the learned Plan) is removed at the root by the meta-principle *derive, don't induce*.

### 15.2 Side-by-side

| Dimension | v2 (DPT) | v3 (AuthPath) |
|---|---|---|
| **Operating layer** | AI-agent ↔ MCP servers | HTTP/API of an authorized target |
| **Core question** | Did untrusted content launder authority to an agent action? | Does a successful action exceed the principal's authority **or** violate its effect-class law? |
| **Causality** | Proven via referents — but depends on LLM honoring opaque placeholders (deepest crack) | Proven by structured value-origin; **no LLM in the value path** (crack removed) |
| **Business logic** | **Learned** Plan/state-machine (induction — the v2 research crack) | **Derived** Effect-Invariant Library (laws true by effect-class) |
| **False-positive control** | Structural (escalate once per new effect-class) | Structural (**confirm-by-Δstate**, not status-diff) — beats existing authz tools |
| **Detector count** | 4 separate detectors | **1 engine + 1 reusable law library** (the four classes are EIL entries) |
| **Benchmark** | No accepted public agent/MCP benchmark (v2's eval crisis) | **Labeled targets exist** (Juice Shop/crAPI/VAmPI/PortSwigger) — real precision/recall |
| **Probabilistic step** | Mandate derivation (once, fail-safe) | Effect-classification (contract-anchored, fail-safe) |
| **Output** | Causal path (proof) | Causal path **+ reproducible PoC + law-named impact** (a submittable bounty report) |
| **Economic outcome** | Defensive / research | **Paid findings** — the owner's actual goal |
| **Scope safety** | Implicit | **Scope-Guard, first-class, fail-safe-to-inaction** |
| **Unifying principle** | "Authority cannot be laundered" | "Authority cannot be laundered **∧** an action cannot violate its effect-class conservation law — derive, don't induce, in every layer" |

### 15.3 What v3 kept from v2 (deliberately, unchanged or strengthened)
The two-axis provenance model (value-origin + authority); referent-style value tracking (now LLM-free → genuinely proven); dynamic effect-based classification (§7.2); over-approximate-then-prune (§7.4); sealed levels traveling through time (§8); the explainability-as-proof moat (now extended to auto-PoC); the rejected-complexity discipline and design rules (§12–13); fail-safe positioning of the one probabilistic step. v3 is a **re-aiming and simplification**, not a rewrite — v2's engine is intact, pointed at a layer where its assumptions actually hold.

### 15.4 Honest net assessment
v3 is strictly stronger where it counts for the owner's goal: causality is deterministic by construction (not contingent on an LLM), business logic is derived not induced (the v2 research crack is gone), false positives are crushed by confirm-by-Δstate, the benchmark crisis is solved by labeled targets, and output is a submittable PoC, not a defensive log. It is **not** a complete vulnerability scanner — it deliberately cedes injection classes (§3) and is bounded by EIL coverage (§14, honest and growing). The cost is the need to author the initial law library — a finite, compounding, individually-verifiable effort, not an open-ended induction problem. Net: v3 trades v2's broad-but-fragile agent ambition for a **narrow, deep, deterministic, and monetizable** authorization/business-logic engine.

---

## 16. Glossary

- **Principal / envelope:** an authenticated identity; its envelope is the measured set of authorities/object-ids it legitimately exercised this session.
- **Value-origin provenance:** proven record of which response a value came from (structured, LLM-free).
- **Effect-class:** the kind of effect an action has (OBJECT_ACCESS, OWNERSHIP, PAYMENT, STATE_GATE, INVENTORY, COUPON, AUTHORITY…), classified by contract or behavior.
- **Effect-Invariant Library (EIL):** reusable catalog of conservation/consistency laws true by the definition of each effect-class.
- **Confirm-by-Δstate:** promoting a candidate to a finding only when an authenticated read-back proves the critical property actually changed/leaked (not a status-code diff).
- **Authority laundering:** a value acquiring authority it was never granted (cross-object/principal/session/hidden-field) — the unifying class.
- **Confused deputy / BFLA:** a server acting with its own broad privilege rather than the requester's authority.
- **IDOR/BOLA · BOPLA:** broken object-level / object-property-level authorization.
- **Scope-Guard:** the first-class gate restricting all activity to authorized scope, fail-safe to inaction.
- **Evidence→PoC:** the emitter turning a confirmed finding into a causal path + reproducible proof-of-concept + impact narrative (a submittable report).
