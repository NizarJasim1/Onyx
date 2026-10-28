# Design rationale, decision log and red lines
### Companion to [`../ARCHITECTURE.md`](architecture.md) (the current module map) and [`../PITCH.md`](overview.md). Read **this file first.**

> **TO THE AI OR ENGINEER RECEIVING THIS:** The architecture file tells you *what* AuthPath is and *how* it works. This file tells you *why every decision was made* and *what you must never break*. The architecture is a set of conclusions; this is the reasoning that produced them and the adversarial pressure each conclusion survived. **Do not propose any change before reading this file in full.** Many "reasonable-looking" improvements (add a small ML classifier, learn a traffic baseline, relax the confirmation step for speed) re-introduce a root cause we deliberately removed. If you cannot see *why* a thing was rejected, you cannot safely re-add it. Your job is to implement **with judgment**, not just faithfully.

---

## 0. How to use this file

1. Read §1 (the lineage) — it explains the tool as a *chain of resolved tensions*, not a static spec. If you understand the chain, you understand the tool.
2. Read §4 (Red Lines) before touching anything. These are the load-bearing properties; breaking one silently destroys the tool's value even if the code still runs.
3. When you want to change something, apply the **§5 three-point test**. If a change touches a Red Line, it needs an explicit written justification or it is rejected by default.
4. Use §3 (Decision Log) as the lookup: "why is it done this way and not the obvious other way?"
5. Use §6 (Honesty Map) so you never present an estimate as a measured fact.

---

## 1. The lineage — read the tool as a chain of resolved tensions

AuthPath is **not** a design that appeared whole. It is the third point on a line, and each step was forced by a *specific tension that killed the previous version*. If you only read the architecture, you see three designs; if you read the tensions, you see one idea sharpening.

**v1 (data provenance):** "Did untrusted *data* reach a sink?"
→ **Killed by:** the legitimate use of an agent *is* untrusted-data-influencing-a-sink ("read this email and book what it asks"). A data-provenance gate must either block legitimate work or wave through attacks. There is no threshold that separates them, because the data and the chain shape are identical in the benign and malicious case.

**v2 (authority provenance):** the thing that differs is not the data but the *origin of the authority to act*. Added a second axis (the Mandate) and proved causality with **referents** (opaque tokens replacing untrusted values), so causality is proven not string-matched.
→ **Killed (as a top-tier tool) by two cracks found under deep analysis:**
- **Crack A — the referent ↔ utility contradiction.** Referents prove causality *only if the model never reconstructs the value*. But the model must reason about values (sum, convert, reformat), so v2 had to *expose* values (`val=1500`) for utility — which lets the model emit the raw value and silently break the proof. Every exposure for utility is a hole in the proof. This is not a tunable knob; it is a structural contradiction baked into putting an LLM in the value path.
- **Crack B — the learned Plan.** v2's business-logic detector *learned* a state-machine from "legitimate traffic." This re-introduced the exact thing v1→v2 rejected (anomaly/induction) in the one place v2 called "the hardest research piece." Induction over attacker-influenced, sparse traffic **cannot distinguish "forbidden" from "never tried."**

**v3 (this design):** make v2's *same* jump (infer→prove) one layer up.
- **Resolves Crack A** by moving the engine to the **HTTP/API layer**, where values are structured and **no LLM sits in the value path** — so causality is proven *by construction*, not contingent on a model honoring placeholders. The contradiction doesn't get mitigated; it ceases to exist.
- **Resolves Crack B** by replacing the *learned* Plan with the **Effect-Invariant Library (EIL)**: business-logic correctness is **derived** from laws true by the definition of an effect-class (PAYMENT ⇒ `amount_paid ≥ amount_due`), not induced from traffic. The meta-principle that falls out: **derive, don't induce — in every layer.**
- **Bonus it unlocked:** at the HTTP layer the bounties are real, labeled benchmarks exist (Juice Shop/crAPI/VAmPI/PortSwigger), and output can be a submittable PoC. The pivot wasn't a lateral move; it was the resolution of v2's cracks that *happened to* land on the owner's actual money-making goal.

**The one sentence that holds it all:** *Every version removed one more place where a judgment was based on a guess instead of a proof or a definition. v3 is the version where no security judgment rests on induction or on an LLM honoring a contract.*

---

## 2. The meta-principle (the thing to protect above all)

> **Do not learn what you can derive. Do not infer what you can prove. Anchor every judgment to either (a) something declared by a trusted party, or (b) something true by the definition of the effect-class, or (c) a measured fact about the principal. Induction/anomaly is forbidden in every layer.**

Every Red Line in §4 is a *consequence* of this principle. If you ever find yourself reasoning "this is probably fine because it's how normal traffic behaves," you have violated the principle and you are rebuilding v1's failure.

---

## 3. Decision log (decision · tension it resolved · rejected alternative · why rejected)

**D1 — Operate at HTTP/API layer, not the MCP/agent layer.**
- *Resolves:* Crack A (referent↔utility). No LLM in the value path ⇒ causality proven by construction.
- *Rejected alt:* stay at the agent layer and "improve referent compliance." *Why:* you cannot fix a structural contradiction with calibration; exposing any value for utility re-opens the hole. The MCP path is preserved as a *transport adapter* (M7), so nothing is lost.

**D2 — Effect-Invariant Library (derived laws), not a learned Plan/state-machine.**
- *Resolves:* Crack B (induction). Laws are true by effect-class definition; reusable across all targets; the catalog compounds with every bug found.
- *Rejected alt:* learn the workflow from traffic / "just add a small ML model for logic." *Why:* induction over attacker-influenced sparse data cannot tell forbidden from untried; it produces false negatives *and* false positives simultaneously, and it can't explain *why* a deviation matters (so it can't write a report). This is the single most important rejection in the whole project. **If a future suggestion re-adds learning here, it is reviving the dead.**

**D3 — Confirm-by-Δstate, never by status-code/length diff.**
- *Resolves:* the false-positive engine that cripples Autorize/AuthMatrix-class tools. A finding requires an authenticated read-back proving the critical property actually changed/leaked.
- *Rejected alt:* report on status/length differences (faster, simpler). *Why:* a `200` for the wrong user can be a vuln, a redirect, a soft-deny, a cached page, or an authorized-but-empty read. Difference ≠ violation. Reporting on difference is exactly why existing tools drown in noise and why their findings get rejected. **Precision is the economic engine; this is non-negotiable.**

**D4 — Contract resolves *effect-class only*, never *forbiddenness*.**
- *Resolves:* the temptation to trust the target's declared contract as a security policy.
- *Rejected alt:* use the OpenAPI/contract to decide what's allowed. *Why:* the target is untrusted; its contract tells you *what an endpoint does* (classification), not *what is safe* (that comes only from the EIL). A missing/partial contract therefore only weakens classification (fail-safe) and never compromises a law.

**D5 — Effect-classification is the only probabilistic step, and it is fail-safe.**
- *Resolves:* the need to keep determinism while still handling unknown endpoints.
- *Rejected alt:* make detection itself probabilistic. *Why:* this design confines all uncertainty to *routing* (which law applies), where an error errs toward *more scrutiny / flag a candidate*, never toward passing a violation. Same fail-safe property that made v2 sound, preserved.

**D6 — Multi-principal replay (A/B/anon) provisioned by the tester, never fabricated.**
- *Resolves:* how to *measure* authority (the envelope) rather than guess it.
- *Rejected alt:* infer authorization from a single session. *Why:* you cannot prove "B should not access A's object" without actually being B. Fabricating credentials is both unsound and out of scope (auth is the identity layer's job).

**D7 — Scope-Guard as a first-class component, fail-safe to inaction.**
- *Resolves:* the existential business risk — an out-of-scope action gets the tester banned and earns zero.
- *Rejected alt:* treat scope as a config detail / the operator's manual responsibility. *Why:* for a money-making tool run on real programs, scope violation is the highest-cost failure mode. It deserves the same fail-safe treatment as v2 gave its probabilistic steps: an error here must **do nothing**.

**D8 — Cede injection classes (SQLi/XSS/SSRF-as-RCE) entirely.**
- *Resolves:* scope creep that would dilute a deep, precise authz/logic engine into a mediocre general scanner.
- *Rejected alt:* "also add injection scanning to be a complete tool." *Why:* injection is well-served by nuclei/Burp/sqlmap; duplicating them adds complexity with no edge. AuthPath's moat is the class *no one automates well* (authz/logic). Compose, don't duplicate. (SSRF stays in scope *only* as a confused-deputy/authority case.)

**D9 — Evidence→PoC emitter is part of "done," not a nice-to-have.**
- *Resolves:* the real bottleneck in bounty hunting — a correct detection with a weak report is a rejected bounty.
- *Rejected alt:* output findings as logs/scores and write reports manually. *Why:* the violated EIL law already names its own impact-class, so the report writes itself. A detection that cannot emit causal-path + reproducible PoC + impact is **not finished**.

**D10 — Carry sealed levels/envelopes across sessions; do NOT build a persistent cross-session graph.**
- *Resolves:* cross-session replay / single-use-token / coupon-reuse without a storage/privacy lake.
- *Rejected alt:* persist a full cross-session provenance graph. *Why:* storage/privacy-expensive and a sensitive-data lake; sealing the level onto the value is sufficient and cheap (grows with #endpoints, not #requests).

---

## 4. RED LINES — break any of these and the tool is dead even if it compiles

These are the five core properties (architecture §13.2) plus their rationale. **Touching any one requires the §5 written justification.**

**RL1 — No induction / no learned baseline / no anomaly model. Anywhere.**
This is the original sin every version was built to remove. The moment a judgment rests on "this is how normal traffic looks," you have rebuilt v1's unsolvable gate. *Symptom to watch for in proposals:* "learn", "baseline", "train", "typical", "anomaly score", "it usually doesn't…".

**RL2 — No LLM in the value/decision path; the hot path stays deterministic.**
An LLM in the value path resurrects Crack A (it can reconstruct/reformat values and break proof). A model may be used **off the hot path** for non-security-critical assist (e.g. drafting human-readable report prose from an already-proven finding), never to *make* a security decision. *Symptom:* "let the model decide if this is a vuln", "ask the LLM whether this looks exploitable".

**RL3 — Confirm-by-Δstate, never by status/length diff.**
This is the precision engine and therefore the economic engine. Relaxing it for speed brings back the false-positive flood that makes findings unreportable. *Symptom:* "we can skip the read-back to go faster", "a 200 difference is enough".

**RL4 — Every finding emits causal-path + reproducible PoC + law-named impact.**
A detection that can't be reported isn't done. This is what separates AuthPath from a scanner that produces a noisy list. *Symptom:* "output the findings as a list/score and report later".

**RL5 — Scope-Guard, fail-safe to inaction; uncertainty ⇒ do nothing.**
Out-of-scope = ban = zero income, plus ethical/legal exposure. An error in scope resolution must halt, never act. *Symptom:* "run broadly and filter later", "scope is the user's problem".

**Two derived rules that protect the Red Lines:**
- **Derive or measure; never induce** (RL1 in active form).
- **The EIL is the only source of "forbidden"; the contract is only a source of "what this endpoint is"** (protects RL1/RL3 from D4 erosion).

---

## 5. The three-point test for any proposed change

Before adding or altering anything, answer all three in writing:
1. **What specific vulnerability class or failure does this newly catch or fix** that the current design misses? (No feature without a named target.)
2. **Does it touch a Red Line (§4)?** If yes — does it preserve determinism, no-induction, no-detection-LLM, confirm-by-Δstate, reportability, and Scope-Guard? Show how. If it erodes any, it is rejected by default.
3. **Is there a lighter mechanism that already covers it?** If yes, prefer the lighter one. Complexity must pay rent.

If a proposal cannot pass all three, do not implement it — flag it to the owner with the failing point named.

---

## 6. Honesty map (never present an estimate as a measured fact)

- **All per-class detection numbers (e.g. "~90% IDOR recall") are engineering estimates from the mechanism, NOT measurements.** Real numbers exist only after calibration on labeled targets (§9). Always say "estimated, pending calibration."
- **The "<5% false positive" claim is a design *target* enforced structurally by confirm-by-Δstate, not a measured rate.** It is the most defensible estimate (because the mechanism, not a model, enforces it) but it is still unmeasured.
- **The positioning claim "no existing tool combines all four properties" is unverified** — re-check current Autorize/AuthMatrix/Akto/StackHawk feature sets before stating it in any writeup.
- **The labeled-target inventory (Juice Shop/crAPI/VAmPI/PortSwigger bug lists/versions) must be verified** against current releases before relying on it.
- **Program automation policy varies** — some bounty programs forbid automated multi-principal replay. Scope-Guard enforces technical scope; legal/policy scope is the tester's responsibility. Verify per program.
- **Where fail-safe actually protects you:** effect-classification errors (route to more scrutiny, not a pass) and scope errors (halt, not act). Where it does NOT protect you: EIL coverage gaps — a logic bug *outside* the authored laws is simply missed (an honest, growing bound, not a fail-safe).

---

## 7. What is genuinely still open (so the second AI doesn't "solve" non-problems or hide real ones)

- **Authoring the initial EIL** for the highest-impact effect-classes (PAYMENT, PRICE/AMOUNT, STATE_GATE, OBJECT_ACCESS, OWNERSHIP, INVENTORY/QTY, COUPON/single-use, AUTHORITY/BFLA) is a finite, compounding, individually-verifiable logic-authoring effort — **the real first work item.** It is not an induction problem; treat it as writing checkable predicates, each validated against a labeled bug.
- **Two-sided conservation laws** (value conserved across a transfer) need both transaction sides; mitigated by multi-principal observation, single-sided cases assert weaker laws and must *declare* the limit.
- **Value-origin extraction completeness** for novel encodings (a value the extractor doesn't recognize flows as free text) — calibrate on the harness, extend the extractor as new value classes appear. This is the residual of v2's old extraction fragility; smaller here (HTTP is structured) but not zero.
- **Effect-classification without a contract** stays probabilistic; keep it contract-anchored and fail-safe.

Do not let any of these be quietly "resolved" by adding induction (RL1). If one of them tempts you toward a learned model, that is the signal to stop and flag it, not to proceed.

---

## 8. One closing instruction to the receiving AI

You are inheriting a design whose entire value is **discipline**: it is strong precisely because of what it refuses to do. The easiest way to ruin it is to make it "smarter" by adding learning, or "faster" by skipping confirmation, or "more complete" by adding injection scanning. Each of those undoes a specific, hard-won resolution documented above. Build it deep and narrow, prove every judgment, confirm every finding, stay in scope, and make every detection reportable. That is how this becomes the best tool it can be — not by adding, but by holding the line.

---

## 9. AHP-12 hardening pass — confirmer soundness (decision log)

> Added after an execution-backed adversarial audit found the Δstate confirmer —
> the load-bearing RL3 mechanism — was the least-tested surface. Each fix below
> *strengthens* under the Monotonic-Strengthening Invariant (FP↓ or FP=, FN=,
> capability⊇), is byte-identical on the frozen 27-probe demo, and is locked by
> `tests/test_ahp_hardening.py` (every test fails on the pre-fix code).

**AHP-1 — STATE_GATE predecessor re-evaluated on the read-back, not string-matched.**
- *Defect:* improvement #4 turned `evidence["missing_gate"]` into a predicate
  *description* ("paid equals True") while `_confirm_state_gate` still compared it
  to the raw field name `"paid"` — silently disabling the "predecessor unsatisfied"
  half of the proof. A legitimately settled-then-fulfilled order was mis-confirmed
  (FALSE POSITIVE). *Fix:* the law now emits `unmet_predicate_specs` (the predicate
  dicts); the confirmer re-evaluates them against the authoritative post-state via
  the same `_predicate_holds`. No machine-usable spec ⇒ fail-safe abstain.
- *Rejected:* keep comparing the description string. *Why:* a display string is not
  a verifiable predicate; coupling the proof to report prose is the root cause.

**AHP-2 — INVENTORY requires proof of persistence (no rubber stamp).**
- *Defect:* `_confirm_inventory` returned confirmed on `requested_qty present AND
  body truthy` — a pure 2xx/existence stamp, the exact "a 200 is enough" breach the
  red lines forbid. *Fix:* an authenticated read-back must show the out-of-bounds
  qty recorded in server state (or stock/available gone negative); a clamped/absent
  qty refutes; no positive evidence ⇒ abstain.
- *Rejected:* trust the transition response's success. *Why:* success ≠ acceptance
  into state; that is a status diff by another name.

**AHP-3 — read-back REFUTATION for PAYMENT/PRICE/OWNERSHIP.**
- *Defect:* these confirmed on the captured/echoed response and could only *upgrade*
  on a read-back, never be *refuted* by one — so a server that optimistically echoes
  a client value (PRICE especially) but recomputes correctly downstream produced a
  false positive. *Fix:* when an authenticated read-back is available it is
  AUTHORITATIVE — it confirms (value persisted) or refutes (value not persisted /
  corrected). The single-sided post-state fallback is kept ONLY when no read-back
  exists, so FN is unchanged while FP drops.
- *Rejected:* force abstain when no read-back exists. *Why:* a mutation response IS
  the server's own post-state assertion; abstaining there would raise FN (MSI breach).

**AHP-4 — `within_seconds` predicate is deterministic.**
- *Defect:* it read wall-clock `time.time()`, making a temporal STATE_GATE verdict
  depend on scan time (determinism breach). *Fix:* `_predicate_holds(now=…)` is
  threaded the exchange's `observed_at`, so the verdict is a pure function of the
  capture; wall-clock is used only when no reference is supplied.

**AHP-5 — additive findings routed through `_emit_finding` dedup.**
- *Defect:* `_elevate_leads` / `_structural_pass` / `_active_field_probe` appended
  findings directly, bypassing the (actor, target, law) dedup. *Fix:* all emission
  goes through `_emit_finding`; trace outcome is set only on a newly-emitted finding.

**AHP-6 — read-back block/expiry detection failure fails safe.**
- *Defect:* an exception inside `detect_block`/`detect_auth_expiry` was swallowed and
  the raw response returned — risking a WAF interstitial being compared as the owner
  view (silent corruption). *Fix:* on detection exception, abstain (return None).

---

## 10. RL6 — Bounded Economic Spending (the cost model)

> Added after a giant-surface analysis proved ONYX was not "weak" at hyperscale
> targets but *non-runnable*: spend was O(endpoints × principals × candidates),
> unbounded, locally issued, with no global accounting — months of scanning, or a
> reputation/IP ban long before completion (measured: a 1M-object surface floors
> at ~8M read-backs ≈ 92 days at 1 req/s). The root was architectural: ONYX
> modelled *correctness* (is this a finding?) but never *cost* (what does proving
> it spend?). Requests were an unpriced resource.

**The fix is a peer layer to the correctness model, not a throttle.** `economy.py`
adds a cost model and `engine.drain_deferred()` adds a value-ordered allocator.

```
RL6 — BOUNDED ECONOMIC SPENDING (red line):
  Every network request is drawn from a global + per-host budget and allocated
  in value-descending order. No request is spent on a candidate while a
  higher-value candidate is unspent. On exhaustion, unconfirmed candidates
  degrade to honest LEADS (never silent drops, never status-only confirmations).
  Reputation degradation (429/503/WAF/auth-expiry strikes) only ever TIGHTENS
  the budget and can FREEZE a host; it never loosens spending.
```

Three slices, each independently usable:
- **BudgetLedger** — the single authority every `confirmer._read` acquires from;
  exhaustion/freeze ⇒ the read fails safe (abstain), identical to a failed
  read-back. A closed-loop reputation governor turns block/rate-limit signals
  back into budget pressure (and a host freeze), so ONYX stops probing a hostile
  host after `strike_freeze` strikes instead of hammering into a ban.
- **yield_score** — a passive, zero-network valuation of each candidate (effect
  value × confirm-likelihood prior, field sensitivity, provenance laundering,
  authority gap, structural divergence). Ranks thousands of candidates before a
  single request is spent.
- **drain_deferred (allocator)** — confirms buffered candidates in yield order
  under the ledger; the rest become budget-deferred leads.

**Why it does not weaken the tool (MSI / X4):** the ledger defaults to UNBOUNDED,
which is a strict no-op — `analyze()` with `defer=False` is byte-identical to the
pre-economy engine (calibration unchanged, 92 tests green). On a small target the
budget never binds, so a budgeted run yields the same findings as streaming. The
layer ENGAGES only on a giant surface, where the prior behaviour was *no result
at all* (unrunnable) — so it is strictly more capability, never less. Locked by
`tests/test_economy_rl6.py` (bounded / value-ordered / honest-deferral / governed).

**Measured (proof harnesses):** on a 205-candidate surface with a 30-read-back
budget, spend was capped at exactly 30, all 5 sensitive IDORs were confirmed
first, and the remaining 190 became honest leads. Under a host that challenged
every read-back, ONYX froze the host after 3 strikes (≈3 hostile requests sent,
not 200+) and deferred the rest — ban avoided.

> Still open (documented, not yet built — these are the *other* hyperscale
> blockers from the same analysis, in dependency order): a decoding layer
> (protobuf/gRPC/multipart/ndjson), a discovery engine (crawl + introspection),
> a cross-host authority model, an eventual-consistency window for the confirmer,
> cross-session persistence, a chaining/planning engine, and EIL expansion for
> cloud effect-classes (IAM/quota/billing/ML). RL6 unblocks the others by making
> any run bounded in the first place.

---

## 11. RL7 — Wire-Format Normalization (the wire-format model)

> Added after a hyperscale-readiness analysis proved ONYX was not "weak" on
> Google/Apple/MS traffic but BLIND to it. `extract_values` — the single entry of
> every law, SAIE, provenance and the leak-audit — assumed the body was already a
> decoded JSON dict/list. Measured against real hyperscale wire shapes it returned
> ZERO values on protobuf, gRPC-Web frames, multipart and ndjson — i.e. it
> silently reported "clean" on traffic it literally could not read. A confident
> false-negative is the most dangerous output a scanner can produce.

**Root (parallel to RL6's "correctness without cost"):** ONYX modelled semantic
*structure* but had no *wire-format* model — no decode boundary between bytes on
the wire and the canonical `{dict/list}` the laws consume. It privileged one
format (JSON) that is not the hyperscale default.

```
RL7 — WIRE-FORMAT NORMALIZATION (red line):
  Every exchange is normalized into the canonical structured form BEFORE any law
  runs. Decoding is schema-free and VALUE-BLIND: it recovers STRUCTURE (fields,
  paths, wire-types, repetition) without interpreting meaning (RL1 preserved). It
  NEVER fabricates structure (a field absent on the wire is absent in the
  canonical form). A body that cannot be decoded becomes an explicit OPAQUE
  marker and an "opaque-unanalyzed" outcome — NEVER silently treated as clean.
```

`codec.py` adds the boundary; six slices, each independently useful:
- **codec registry** — content-type/sniff → decoder, with full fallback.
- **schema-free protobuf** — wire parser → `{f<N>: value}` with wire-type-derived
  SHAPE (varint→int, length-delimited→nested/string/bytes). Field NUMBERS become
  positional keys; we never assert "f1 is a user id" (RL1).
- **gRPC-Web framing** — strips the flag+length frame(s), skips trailers, decodes.
- **multipart / ndjson** — structural splitters → field map / list.
- **resource-name model** — `HTTPRequest.resource_name()` parses an AIP-122
  composite path into (primary_object_id, parent_chain, all_ids), so laundering
  gets the addressed object + hierarchy instead of object_ids()'s flat ambiguous
  list. Additive — object_ids() is unchanged.
- **opaque honesty** — the engine emits an explicit "opaque body — not analyzed"
  trace + lead, so an unreadable endpoint is never certified safe.

**Why it does not weaken the tool (MSI / X4):** `normalize_body` returns a dict/
list UNCHANGED (identity) — the entire JSON world, and the whole calibration, is
byte-identical (119 tests green, demo 27/27 unchanged). The decoder ENGAGES only
on non-JSON bodies, where the prior behaviour was a silent false-clean — so it is
strictly more capability and strictly more honest, never less. Locked by
`tests/test_codec_rl7.py` (decoded / value-blind / never-fabricate / fail-safe /
honest-opacity / resource-name).

**Measured:** a gRPC-Web/protobuf IDOR body `{f1:101, f2:"B", f3:"SSN-X"}` is now
fully recovered (was 0 values); ndjson yields all rows (was 0); a truly
undecodable blob produces an honest "opaque-unanalyzed" outcome (was a false
"clean").

> Honest residual (documented, not yet built): schema-free protobuf recovers
> STRUCTURE but not field NAMES, so a protobuf id under "f1" is not yet
> name-classified as an id (it is still tracked by value/shape, and SAIE
> fingerprints it structurally). Closing this fully needs optional .proto/schema
> ingestion — the next layer. The remaining hyperscale blockers from §10 stand in
> the same dependency order: discovery, cross-host authority, consistency window,
> persistence, chaining, EIL expansion.

### 11.1 RL7.2 — Schema-aware semantics (closing the protobuf residual)

> §11 left an honest residual: schema-free decode recovered STRUCTURE but not field
> NAMES, so on protobuf every field landed in OTHER — id/owner/sensitivity
> classification (all name-based) was dead, degrading laundering-IDOR and
> field-projection on gRPC even after the body was legible. Measured: the same data
> as JSON classified id→ID, owner_id→OWNER, ssn→sensitive; as protobuf all three
> were OTHER and ssn's sensitivity was invisible under key "f3".

Root: ONYX binds semantics to field NAMES (present in JSON), but protobuf encodes
them as field NUMBERS resolved by a schema. The missing layer was a semantic map.

```
RL7.2 — SCHEMA-AWARE SEMANTICS:
  When a wire schema (field-number → name map) is registered for an endpoint, the
  codec renames positional keys to SEMANTIC names so name-based classification
  works identically to JSON. The schema supplies NAMES only — never value meaning
  (RL1). Without a schema, the decoder falls back to value-SHAPE classification
  (uuid/jwt/prefixed-id), which fires ONLY on positional keys so named JSON fields
  are untouched (byte-identical). It NEVER fabricates a name it was not given.
```

Three slices: a `SchemaRegistry` (endpoint → field-map, recursive for sub-messages);
`apply_schema` (renames f<N> during decode); and a value-blind shape classifier
gated on positional keys. Engine holds an (empty by default) registry; a decoded
non-JSON body replaces the exchange body so the whole pipeline runs on named fields.

**Proven:** with a schema, protobuf `{f1,f2,f3}` → `{id:101, owner_id:'B', ssn:'SSN-X'}`
classifying id→ID, owner_id→OWNER, ssn→SENSITIVE — full parity with JSON. Without a
schema, a uuid under "f1" → ID, a JWT → TOKEN, plain text → OTHER (not fabricated).
End-to-end, the OBJECT_ACCESS law now FIRES on a schema-decoded gRPC IDOR (was a
silent EIL "pass"); the confirmer then applies the identical Δstate rigor as JSON
(it is format-blind once the body is decoded — covered by the existing 119 tests).
Locked by `tests/test_codec_schema_rl72.py`. Default registry is empty ⇒ JSON path
byte-identical; demo 27/27 and full suite unchanged.

**RL7 is now complete:** structure (RL7) + semantics (RL7.2) + honesty (opaque) +
resource-name model. The only remaining protobuf nuance — auto-deriving a schema
when none is supplied — is out of scope by design: a schema is operator-provided
data, not something to guess (guessing names would violate "never fabricate").

---

## 12. RL8 — Surface Enumeration (the surface model)

> Added after the hyperscale analysis showed ONYX could only find a vulnerability
> in an endpoint a human had already walked: the testable surface == the captured
> traffic (plus a spec doc you happened to hand it). On a target with millions of
> endpoints and a 200-request capture, that is blindness to ~everything. The
> existing `discovery.py` was a passive parser (it parses an OpenAPI/GraphQL doc
> you supply and issues zero requests), not a surface builder.

Root (parallel to RL6/RL7): ONYX had an *analysis* model but no *surface* model —
it treated "the surface to test" as an input, never as something to be DERIVED.

```
RL8 — SURFACE ENUMERATION (red line):
  The surface ONYX tests is DERIVED, not merely the captured traffic. From observed
  exchanges it enumerates sibling/collection/parent/method endpoints (deterministic,
  value-blind, NETWORK-FREE), harvests ids from list bodies for the item template,
  records each endpoint with its source + confidence in a surface graph, and
  synthesises READ-ONLY cross-principal probes. Every probe is (a) GET/read-only by
  default (RL5), (b) drawn from the RL6 budget and allocated by value, (c) subject
  to the SAME Δstate confirmation as any candidate — discovery NEVER promotes a
  finding by itself; a derived endpoint that 404s is "absent", never a finding,
  (d) honest about provenance. Derivation NEVER fabricates an endpoint as
  vulnerable or an id it did not observe; it only proposes WHERE to look.
```

`surface.py`: a `SurfaceGraph` (dedup registry, confidence by source) + `generalize`
(item↔collection, full parent chain via the RL7.2 resource-name model, REST verb
family) + `observed_ids_by_template` (path ids + ids harvested from list bodies) +
`synth_probes` (GET-only IDOR + collection-enumeration probes, generic roots
filtered). Driven through the engine's `analyze(defer=True)` + the RL6 allocator.

**Why it does not weaken the tool (MSI / X4):** the surface layer is a separate
entry point invoked only by a budgeted discovery run; the streaming engine and the
calibration are untouched (demo 27/27, full suite 142 green, byte-identical). On a
giant surface the prior behaviour was "blind to everything unwalked", so this is
strictly more capability. Soundness is preserved because discovery only proposes
probes — the Δstate confirmer still proves every finding. Locked by
`tests/test_surface_rl8.py`.

**Measured:** from 2 walked endpoints, ONYX derived 22 endpoints (20 new). From two
SEPARATE single-principal captures (A read A's order, B read B's order), it
SYNTHESISED the cross-principal attack A→101 that no human performed and confirmed
it as a Critical IDOR — bounded (1/50 budget) and sound (the absent derived
collection produced no false finding).

### 12.1 Discovered sibling-root (precisely characterised, deferred by A1)

While testing the flagship "list → item PII pivot" (harvest ids from a collection,
fetch each item) the surface layer worked — it derived the item endpoint, harvested
the ids and synthesised the probes — but the IDOR was NOT confirmed. Traced to the
nerve: the OBJECT_ACCESS law skips when `seen_by_principal(oid)` is true, and the
provenance store records an id GLIMPSED in a list response as "seen". So the
envelope conflates *knowing an id* with *being authorised for the object*, which
suppresses any attack that pivots from a listing.

This is a genuinely SEPARATE root — **envelope precision (id-knowledge ≠
object-authorisation)** — living in the provenance/envelope layer, not the surface
layer. The `seen_self` guard it depends on is exactly what prevents false positives
elsewhere and is relied on by the calibration; changing it inside this pass would
risk the byte-identical guarantee and reintroduce FPs. Per AHP-12 A1 (atomic
isolation) it is deferred to its own pass rather than half-fixed here. The surface
ENUMERATION obstacle (only-finds-what-was-walked) is solved; the envelope-precision
root is the precisely-scoped next obstacle that determines how much of the newly
visible surface becomes confirmable.

> Remaining hyperscale layers from §10, updated: envelope-precision (newly
> surfaced, next), spec acquisition (active fetch of OpenAPI/introspection — the
> live-network slice of RL8), cross-host authority, eventual-consistency window,
> cross-session persistence, chaining, EIL expansion.

### 12.2 Envelope precision — RESOLVED (its own atomic pass)

The §12.1 sibling-root was then closed as its own pass (A1: one root, isolated).
Root: "the actor SAW an id" was conflated with "the actor is AUTHORISED for the
object", at TWO sites:
  * provenance `_seen_by` recorded any id present in a received response; and
  * `EnvelopeEngine.observe` absorbed every response-body ID/OWNER value into the
    envelope's object_ids — including list-element and nested ids.
Either was enough to make `holds_object`/`seen_self` true for an id merely glimpsed
in a listing, so the OBJECT_ACCESS law short-circuited to clean.

Fix (derived from the distinction, not invented):
  * provenance adds a `_held_by` index — an authoritative HOLD = the actor
    EXPLICITLY ADDRESSED the id (∈ request.object_ids) and received it. Strict
    subset of "seen". New accessor `held_object_by_principal`.
  * the envelope absorbs a response id only when its field_path is TOP-LEVEL
    (no array index, no nesting) — the addressed object's own identity — never a
    list element ("orders[0].id") or a nested related id ("items[0].pid").
  * the law suppresses on HELD; mere incidental SEEN suppresses only when the id
    is NOT cross-principal laundered. The Δstate confirmer remains the final
    filter, so candidates widen without precision loss (a non-leak fails to
    confirm — public/shared data is ruled out by the differential read-back).

The ONLY behavioural delta vs before: an id that was seen incidentally (not held)
AND is laundered from another principal now fires a candidate (was silently
cleared). Everything else is unchanged — demo byte-identical, full suite green.

**Result:** the flagship list→item PII pivot now lands end-to-end — from a capture
where the human only read a collection (ids visible, no PII) and another principal
read its own items, ONYX derives the item endpoint, harvests the ids, synthesises
the cross-principal fetches, and CONFIRMS the IDOR on items no human ever opened
(measured: 2 confirmed, bounded 2/50). No new false-positive class: an
authoritative self-hold and an incidental-but-not-laundered id remain clean.
Locked by `tests/test_envelope_precision.py`. RL8 (surface enumeration) is now
complete AND fully actionable.

---

## 13. RL9 — Host-Scoped Authority (the cross-service authority model)

> Added after the hyperscale analysis flagged the highest-value giant-target class
> — authority that crosses services — as unrepresented. Measured: provenance is
> value-keyed so a token laundered across hosts to read another principal's data
> already fired; but the INVERSE was a silent miss — an object legitimately held on
> service X made the envelope believe the principal held that id EVERYWHERE, so
> reading a DIFFERENT principal's same-numbered object on service Y was cleared as
> "self". Authority was host-blind.

Root (parallel to RL6/7/8): ONYX modelled *whether* a principal holds an id, but
not *on which service*. Authority is host-scoped; the model was not.

```
RL9 — HOST-SCOPED AUTHORITY (red line):
  Authority (held objects, seen ids, granted functions) is scoped to the
  (principal, service/host) it was MEASURED on. A hold proven on service X does
  NOT authorise the same id on service Y — cross-service access fires a candidate
  and is decided by Δstate, never silently cleared. Cross-service token reuse
  outside a token's declared audience is surfaced as a provisional lead. Host
  scoping only ever WIDENS candidates (FN↓); the Δstate confirmer remains the
  precision filter, so a legitimate shared-namespace self-access fails to confirm
  rather than producing a false positive.
```

Implementation (minimal, blast-radius = the IDOR law's three suppression checks):
- `Envelope.object_ids_by_host` + `holds_object_on_host`; `EnvelopeEngine` records
  every legitimate hold per host.
- `ProvenanceStore` gains per-host seen/held indices + host-aware
  `seen_by_principal(…, host)` / `held_object_by_principal(…, host)` (global
  behaviour preserved when host omitted).
- the OBJECT_ACCESS law consults the per-host views; laundering stays
  host-agnostic (a value owned by another principal on ANY service is a launder
  signal).
- companion `_audience_check`: a successful request bearing a JWT whose HOST-LIKE
  `aud` claim does not cover the request host emits a `TOKEN_AUDIENCE_CONFUSION`
  provisional lead. Conservative by design — opaque/identifier auds are skipped,
  so it is low-noise and never a finding (token validity has no Δstate proof).

**Why it does not weaken the tool (MSI / X4):** a single-host capture has one host,
so the per-host checks equal the old global checks — demo byte-identical (27/27),
full suite green. The change only WIDENS candidates for cross-service access (FN↓),
and the confirmer filters them (FP=0: a legitimate cross-service self-access fails
to confirm). Locked by `tests/test_crosshost_rl9.py`.

**Measured:** the cross-service IDOR (A holds object 500 on api.svc, reads
B-owned 500 on internal.svc) is now CAUGHT (was a silent miss); same-service
self-read stays clean; audience confusion flags a host-like aud mismatch and stays
silent on a matching or opaque audience.

> Remaining hyperscale layers: spec acquisition (active OpenAPI/introspection
> fetch — the live-network slice of RL8), eventual-consistency window for the
> confirmer, cross-session persistence, chaining/planning, EIL expansion for cloud
> effect-classes. The internal server-to-server confused-deputy (an SSRF where one
> service trusts another's identity) remains out of reach by construction — it
> lives in traffic ONYX never sees — and is honestly out of scope until a
> server-side vantage is provided.

---

## 14. RL10 — Read Consistency (the distributed-target / time model)

> Added after proving a SELF-INFLICTED regression: AHP-3's read-back refutation
> assumed the read-back was instantaneously consistent. On an eventually-consistent
> store the owner read-back issued just after the attacker's read can hit a LAGGING
> replica and return a stale value — so refutation would drop a REAL leak (a false
> negative). Measured: a genuine underpayment refuted because the first read-back
> showed a stale corrected-looking state.

Root (parallel to the earlier roots): the confirmer modelled state as
INSTANTANEOUSLY CONSISTENT — one read-back == ground truth. It had no time/
consistency model: no notion that a read may be stale, that state converges, or
that a verdict must be STABLE before it is trusted.

```
RL10 — READ CONSISTENCY (red line):
  No confirmer acts on a read-back — to CONFIRM or to REFUTE — until the
  observation is STABLE across a bounded re-read window. The converged verdict
  (the last `consistency_quorum` passes agree) is the truth. A verdict that
  flickers mid-convergence ⇒ abstain + an honest instability lead (RL5), never a
  coin-flip. The window is bounded by the RL6 budget; on a synchronous target it
  converges on the first re-read (byte-identical).
```

The soundness symmetry is the point: requiring stability for CONFIRMATION keeps a
transient stale-leak from becoming a false positive, while requiring stability for
REFUTATION keeps a stale corrected-looking read from dropping a real leak. Both
directions fail safe to abstain when state has not converged.

Implementation (confirmer-agnostic, minimal): `Confirmer.confirm` is a wrapper —
with `consistency_reads=1` (default) it is the old single pass (byte-identical);
with N>1 it re-runs `_confirm_once` until `consistency_quorum` consecutive verdicts
agree, then acts on that converged verdict, else logs instability and abstains. The
engine surfaces a `CONSISTENCY_UNSTABLE` provisional lead via `_drain_instability`.
A new `consistency_reads` knob threads from the engine for distributed scans.

**Why it does not weaken the tool (MSI / X4):** the default is single-shot, so the
demo is byte-identical (27/27) and the full suite is green. The window only ENGAGES
when an operator opts in for a distributed target, where it strictly reduces the
AHP-3 false negative (FN↓) while keeping zero false positives (a non-stable leak is
never confirmed). Re-reads are budget-bounded (RL6). Locked by
`tests/test_consistency_rl10.py`.

**Measured:** stale-first-then-converges → CONFIRM (FN fixed); transient-leak-then-
fixed → abstain (no FP); flapping backend → abstain + instability lead; a genuinely
stable leak still confirms under a 4-read window.

> Remaining hyperscale layers: spec acquisition (live OpenAPI/introspection fetch),
> cross-session persistence, chaining/planning, EIL expansion for cloud
> effect-classes. The server-to-server confused-deputy remains out of scope by
> construction (invisible from the client vantage).

---

## 15. RL11 — Sealed Cross-Session Memory (resolving D10 properly)

> D10 forbade a persistent cross-session provenance GRAPH — correctly, because it
> would be a raw-payload/PII lake. But D10 also left ONYX with NO memory across
> process runs, so temporal vulnerabilities that only manifest over time were
> undetectable: a token still honoured days after revocation, a single-use artifact
> replayed in a later session, authority that should have shrunk. Every run started
> blind.

Root: D10 conflated "persistent cross-session MEMORY" with "raw-payload LAKE." It
rejected the lake (right) but discarded memory entirely (wrong). ONYX had no
temporal model spanning process boundaries.

```
RL11 — SEALED CROSS-SESSION MEMORY (red line):
  ONYX may persist DERIVED, FINGERPRINTED facts across sessions — credential
  lifecycle (hash → first/last seen, denial/allow history, endpoints), single-use
  artifact redemption counts, sealed authority levels — and NOTHING ELSE. It NEVER
  persists raw payloads, raw tokens, PII, or a request graph (D10's lake stays
  rejected). The store grows with #credentials/#endpoints, not #requests. It is
  opt-in, fail-safe (absent/corrupt ⇒ a fresh run = byte-identical), privacy
  self-audited, and NEVER promotes a finding by itself — the Δstate confirmer still
  proves it.
```

`persistence.py` — a `SealedStore` of fingerprinted records. `fingerprint()` is a
salted SHA-256 prefix (one-way). Two flagship cross-session signals are wired:
- **credential resurrection** — a credential DENIED (401/403) in a prior session,
  now ALLOWED (2xx), emits a `CREDENTIAL_RESURRECTION` provisional lead (revocation
  reversed / replayable credential) — a contradiction no single run could observe.
- **single-use replay** — a successful coupon/one-time TOKEN redemption is recorded
  (two-layer count: prior-session vs this-session, so no double-count); the existing
  `CouponLaw` augments its in-session redemption count with prior-session
  redemptions, so cross-session replay exceeds the declared limit and is CONFIRMED.
A `_assert_sealed` privacy audit refuses to write anything that is not a
fingerprint/count/timestamp/endpoint-key/authority enum.

**Why it does not weaken the tool (MSI / X4):** with no store path the store is
disabled — every method is a no-op, so the engine is byte-identical (demo 27/27,
full suite green). Persistence only ENGAGES when an operator opts in with a path,
where it strictly adds cross-session detection (FN↓) with zero new FP (the confirmer
still decides; the resurrection signal is a provisional lead). Locked by
`tests/test_persistence_rl11.py` (disabled-noop / privacy / fail-safe / resurrection
/ cross-session replay / no-double-count).

**Measured:** across two SEPARATE processes — session 1 a token is DENIED, session 2
the same token is ALLOWED → resurrection lead; a coupon redeemed once per session
across two sessions → confirmed single-use replay. The raw token/coupon never
reaches disk (only `fp_…` fingerprints).

> Remaining hyperscale layers: spec acquisition (live OpenAPI/introspection fetch),
> a chaining/planning engine, EIL expansion for cloud effect-classes
> (IAM/quota/billing/ML). The server-to-server confused-deputy remains out of reach
> by construction (invisible from the client vantage).

---

## 16. RL12 — Spec Acquisition (the live-network slice of RL8)

> RL8 derives the surface AROUND observed traffic but cannot reach a subsystem the
> capture never touched. The authoritative spec can: an OpenAPI document lists every
> declared endpoint; a GraphQL schema (via introspection) lists every operation.
> `discovery` could PARSE a spec it was handed but had no way to GO GET one — a
> spec-parsing model with no spec-acquisition model.

Root: ONYX treated the spec as an INPUT, never as something to be ACTIVELY ACQUIRED
from the live target. This is ONYX's first ACTIVE-network capability, so its safety
envelope is stated sharply.

```
RL12 — SPEC ACQUISITION (red line):
  ONYX may ACTIVELY acquire an authoritative API spec from the target — fetching
  OpenAPI/Swagger from conventional well-known paths (GET, read-only) and sending
  the standard GraphQL introspection query (a read) — to expand the testable
  surface beyond captured traffic. Acquisition is opt-in, SCOPE-GUARDED, drawn from
  the RL6 budget, and FAIL-SAFE (a non-spec / 404 / corrupt / hostile response is
  ignored, never treated as a spec, never a crash). It issues ONLY read-only
  requests (RL5). Acquired endpoints are PROBES tagged source='acquired-spec', never
  findings — the Δstate confirmer still proves every finding.
```

`acquisition.py` — a `SpecAcquirer(target, scope_guard, ledger)` with one safe,
bounded, scope-guarded `_read`; `acquire_openapi` (GET a fixed list of ~10
well-known paths; first valid OpenAPI/Swagger doc → `parse_openapi`); `acquire_graphql`
(POST the introspection query to conventional GraphQL paths; first `__schema` →
`parse_graphql_introspection`); and `acquire` (both → a `SurfaceGraph` tagged
'acquired-spec', feeding RL8's `synth_probes` → RL6 allocator → confirmer). Spec
validation is strict (OpenAPI needs a version key + a `paths` object; introspection
needs a `__schema`), so garbage is never mistaken for a spec.

**Why it does not weaken the tool (MSI / X4):** acquisition is a separate module,
never auto-invoked by the streaming engine — demo byte-identical (27/27), full suite
green. It only ADDS reach (endpoints the capture never saw), and every acquired
endpoint still flows through the Δstate confirmer, so reach grows with no precision
loss. Locked by `tests/test_acquisition_rl12.py` (openapi / graphql / read-only /
scope / budget / fail-safe×4 / end-to-end).

**Measured:** from a target serving `/openapi.json`, ONYX acquired the declared
endpoints (incl. a server-base-prefixed path), issued only read-only requests, and
— end to end — CONFIRMED an IDOR on `/records/{id}`, an endpoint NO human walked and
NO traffic captured. Garbage/404/hostile targets yield nothing and never crash;
out-of-scope hosts are never touched; fetches honour the budget.

> Environment note: this build/test runs with the network DISABLED, so acquisition
> is exercised against the Target interface with mock spec servers. Live fetching in
> production uses the SAME Target abstraction against a real HTTP target — no code
> change, only a real transport.
>
> Remaining hyperscale layers: a chaining/planning engine (compose single findings
> into multi-step attack chains) and EIL expansion for cloud effect-classes
> (IAM/quota/billing/ML). The server-to-server confused-deputy remains out of reach
> by construction (invisible from the client vantage).

---

## 17. RL13 — Authority-Grant Conservation (the IAM cloud effect-class)

> First step of the cloud-effect-class expansion toward Google coverage. Proven gap:
> an actor calling setIamPolicy to grant ITSELF roles/owner produced — at best — an
> unconfirmable OwnershipLaw candidate. ONYX had no law that UNDERSTANDS an IAM
> grant, so the canonical "viewer makes itself owner" escalation was missed.

Root: ONYX modelled authority as a fixed ENVELOPE the actor operates WITHIN. It had
no model of authority as a MUTABLE GRAPH the actor can EDIT. IAM escalation is a
write to that graph (grant role R to member M on resource X) — an effect-class with
no law and no notion of role rank.

```
RL13 — AUTHORITY-GRANT CONSERVATION (red line):
  Authority is a MUTABLE GRAPH, not only a fixed envelope. A request that edits the
  graph (grant/bind a role or permission — setIamPolicy, addBinding, role
  assignment, ACL write) is an AUTHORITY_GRANT effect. The conservation law: an
  actor must not grant authority above what it itself holds, nor raise its own
  effective authority. Escalation is confirmed ONLY by Δstate — a read-back of the
  authority graph proving the binding PERSISTED — never by status. Role RANK is a
  DECLARED, reviewed partial order (RL1: no induction).
```

Pieces:
- `models.py` — `EffectClass.AUTHORITY_GRANT` + `ImpactClass.IAM_ESCALATION`.
- `iam.py` — a declared `RoleModel` (a coarse rank ladder with sensible cloud
  defaults, overridable per deployment; unknown roles get a conservative mid rank),
  `is_authority_grant` (operation markers + binding-bearing mutating bodies), and
  `extract_bindings` tolerant of GCP / flat / AWS / Azure shapes.
- `contract.py` — AUTHORITY_GRANT is classified FIRST (most security-critical write,
  never shadowed by the generic OWNERSHIP/AUTHORITY routes).
- `eil.py` — `AuthorityGrantLaw`: fires when the actor grants a rank above its
  declared/measured held rank (to anyone), or self-grants a privileged role
  (owner/admin/iam/billing) with its rank unknown.
- `confirmer.py` — `_confirm_authority_grant`: derives the getIamPolicy sibling of
  the grant path, reads the policy back as a non-actor principal, and confirms ONLY
  if the granted binding PERSISTED in the graph (else abstains — the optimistic-echo
  trap is closed for IAM too).

**Why it does not weaken the tool (MSI / X4):** AUTHORITY_GRANT is a new effect
route that fires only on authority-graph edits; non-IAM traffic never reaches the
law, so the demo is byte-identical (27/27) and the full suite is green. It strictly
ADDS a previously-blind vulnerability class (FN↓) with no new FP: a self-grant of a
non-privileged role is clean, a grant within the actor's held rank is clean, and a
grant that does not persist in the read-back abstains. Locked by
`tests/test_iam_rl13.py` (role model / bindings×4 shapes / detection / self-esc /
lateral / two no-FP cases / no-persist abstain / byte-identical guard).

**Measured:** A calls `:setIamPolicy` granting itself roles/owner → CONFIRMED IAM
escalation via a getIamPolicy read-back showing the binding persisted; a viewer
granting editor to a victim (declared actor rank = viewer) → confirmed lateral
escalation; self-grant of viewer, grant within an owner's rank, and a non-persisting
grant → all clean/abstained.

> This is the FIRST of the cloud effect-classes. Remaining for fuller Google reach:
> resource-hierarchy authorization (org→folder→project inheritance), service-account
> impersonation, OAuth-scope confusion, quota/billing abuse — each a further
> AUTHORITY-class law on the same authority-graph model. Structural limits unchanged
> (token binding/attestation; server-to-server confused-deputy).

---

## 18. RL14 — Hierarchical Authority (resource ancestry)

> Built directly on RL13's authority-graph model. Proven gap: ONYX's authority model
> was FLAT — (principal, object) with no ancestry. Real cloud authority inherits down
> a hierarchy (organization ⊐ folder ⊐ project ⊐ resource); a role bound at an
> ancestor covers every descendant. A flat model both (a) risks FALSE POSITIVES
> (reporting legitimate inherited access/grants as escalation) and (b) MISSES SCOPE
> (a grant at an organization escalates over everything beneath it, not one object).

Root: ONYX had no notion of resource ancestry, so it could not compute a principal's
EFFECTIVE authority at a node (which inherits from ancestors).

```
RL14 — HIERARCHICAL AUTHORITY (red line):
  A principal's authority over a resource is the authority it holds on that resource
  OR on ANY ancestor in the declared hierarchy (organization ⊐ folder ⊐ project ⊐
  resource). Ancestry is derived structurally from the resource NAME (name-encoded
  nesting) plus DECLARED parent links for relationships not in the name (org→project)
  — RL1: structural/declared, never induced. This (a) SUPPRESSES false positives —
  inherited authority is legitimate and must not be reported; and (b) SCOPES
  escalation — a grant at an ancestor confers authority over the whole subtree.
```

`hierarchy.py` — `parse_resource_name` (strip version + GCP verb suffix + host),
`ancestry` (name-encoded prefixes + declared parent links), `is_ancestor`,
`effective_rank_at` (max rank over the node and its ancestors, plus a global binding
for RL13 back-compat), and `subtree_scope` (evidence label for the breadth a grant
confers). The RL13 `AuthorityGrantLaw` now resolves the actor's rank with
`effective_rank_at` over the ancestry, and reports the subtree scope in evidence.
Declared `actor_roles` may be the flat list form (global, RL13) or the scoped dict
form `{resource: [roles]}` (RL14); an optional `resource_parents` map supplies
non-name-encoded links.

**Why it does not weaken the tool (MSI / X4):** hierarchy resolution only refines the
existing RL13 path. With no IAM traffic and no declared roles nothing changes — demo
byte-identical (27/27), full suite green, and ALL RL13 tests still pass (the flat
declaration form is preserved). It strictly reduces false positives (an ancestor-admin
granting at a descendant — including an org-owner self-granting at a child project —
is now correctly CLEAN) and sharpens true findings with subtree scope. Locked by
`tests/test_hierarchy_rl14.py`.

**Measured:** owner at projects/P1 granting editor at projects/P1/datasets/D1 → clean
(name-encoded inheritance); org-owner self-granting owner at a child project (declared
parent link) → clean (the dangerous FP, suppressed); project-viewer granting owner at
the ORGANIZATION → finding (escalation over the whole org); project-viewer self-granting
owner at the project → finding.

> Remaining cloud effect-classes toward fuller Google reach: service-account
> impersonation, OAuth-scope confusion, quota/billing abuse — each a further law on
> the same authority-graph + hierarchy model. Structural limits unchanged (token
> binding/attestation; server-to-server confused-deputy).
