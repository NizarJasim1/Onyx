# ONYX vs the field — an honest differential

ONYX is not a broad DAST platform and does not try to be. It occupies one deep niche:
**deterministic, black-box, zero-false-positive, Δstate-confirmed authorization
detection.** This page states, grounded in each tool's own documentation, exactly what
ONYX's method catches that theirs structurally cannot guarantee — and, just as plainly,
what they do that ONYX does not.

> Competitor capabilities below are a snapshot from their public docs as of mid-2026
> (e.g. StackHawk Business Logic Testing, Dec 2025; Escape agentic pentest, 2026). These
> tools evolve — verify against current docs before quoting. Where a tool added a
> capability, this page credits it (StackHawk *does* multi-user testing); the durable
> differentiator is the **confirmation method**, not who tests multiple users.

## How each tool decides "this is a vulnerability"

| Tool | Core method | How a finding is *confirmed* | Decision engine |
|------|-------------|------------------------------|-----------------|
| **Autorize** (Burp) | Replay a high-priv request as low-priv/unauth, compare the two responses | **Response comparison** — status / length / body-string heuristics & fingerprints; its own docs note false positives/negatives are possible and complex logic needs manual detector tuning | Heuristic |
| **Akto** | 1000+ test templates over discovered traffic; BOLA = swap auth token & replay, BFLA = change HTTP method | **Response/template match** on the replayed request | Rule templates |
| **StackHawk BLT** | Spec-driven multi-user crawl in **staging with seeded data**; tests create/update/delete + privilege escalation | Runtime request/response evidence; its published BOLA example flags when the API "returns User A's data *instead of 403 Forbidden*" (status/response-based); cannot safely test destructive ops in production | Deterministic crawl + AI-generated specs |
| **Escape** | AI reads OpenAPI/GraphQL spec, generates attack payloads; business-logic engine; AI scores findings | AI-generated payloads + AI/contextual risk scoring | AI / LLM-assisted |
| **Snyk API** | LLM classifies content ownership (public vs private, is the caller the owner) | LLM reasoning over request/response | LLM |
| **ONYX** | Provision principals, observe legitimately, attack, **confirm by Δstate** | **State change only (RL3)**: write-then-read-back persistence, cross-principal effect, foreign-object destruction verified by the owner's own re-read — a differing status or body is never sufficient | Deterministic, **no ML/LLM in the decision path (RL1/RL2)** |

## The confirmation-semantics difference (where "did it differ / is it not a 403" is unsound)

To be precise and fair: the strongest competitors (StackHawk BLT, Escape) *do* test
mutations, deletes, and privilege escalation across multiple users. The durable
difference is **how a finding is confirmed** — and on each case below, a response/status
signal can be wrong where an actual state-change check cannot:

1. **Mass-assignment / write-effect abuse.** The attacker flips an order to `returned`.
   A tool that inspects the *write's* response sees `{status: ok}` and must infer intent;
   the persisted effect (a credit refund) lives in *other* state. ONYX reads that state
   back and confirms the mutation **persisted** (RL23) — the effect, not the ack.
2. **Cross-principal destruction (admin-delete BFLA).** A delete returns `{deleted}` with
   no owner in the body. Confirming on "the delete wasn't a 403" is a status inference;
   ONYX confirms the owner's own object is **gone on the owner's re-read** (RL25) — the
   harm itself. (This is also why ONYX doesn't need a seeded staging environment to make
   the call: the Δstate is the proof.)
3. **Field-level exposure / EDE with no foreign ID in the request.** A feed leaks another
   user's email though the request carried no foreign object id. ID-swapping and
   method-changing templates never trigger; ONYX flags the leaked private field by
   provenance (RL22).
4. **Shared-cache / stale-read false alarms.** A shared cache serving User A's body to
   User B looks *exactly* like a cross-user leak to any response-comparison — a false
   positive. ONYX re-establishes every trigger on a cache-busted, quorum-voted re-read
   and abstains when it will not reproduce (RL24), so transport noise never becomes a
   finding. This is the case none of the response/status methods can rule out.

## The evidentiary edge (this is the part that is hard to argue with)

- **Zero false positives, quantified and reproducible.** ONYX is measured over a
  *distribution* of randomly-seeded, hash-sealed vulnerable worlds it has never seen,
  with an AST guard proving the target shares no code with the detector. Precision is
  **1.000 at every level**, including under an anvil that injects production chaos
  (stale reads, cache bleed, retries, async, rate-limits) *harder than reality*. We are
  not aware of a competitor publishing a *chaos-hardened* zero-FP figure; Autorize's own
  docs state false positives are possible, and AI-scored tools quote "<5% false
  positives," not zero.
- **Determinism = auditability.** Because there is no ML/LLM in the decision path,
  every finding ships a replayable proof and a hash-chained measurement bundle a third
  party can re-derive. AI-assisted tools cannot offer a by-construction guarantee;
  their output is probabilistic by design.

## What the others do that ONYX does not (stated plainly)

ONYX is a specialist, not a replacement. Honestly:
- **Breadth.** Escape/Akto/StackHawk cover SQLi, XSS, SSRF, XXE, injection, secrets,
  and more; StackHawk BLT also tests create/update/delete authorization and privilege
  escalation across users, over REST, GraphQL, SOAP and gRPC. ONYX detects
  *authorization* effects only, on bearer-token/cookie HTTP surfaces.
- **Discovery & CI-native flow.** Akto/StackHawk auto-discover endpoints (StackHawk even
  from source repos) and gate pull requests; Escape crawls from a schema and does shadow-
  API discovery. ONYX assumes you bring the surface.
- **Remediation UX & GraphQL depth.** Escape/StackHawk ship framework-specific fix code,
  mature GraphQL support, and dashboards. ONYX outputs findings + proofs, not fixes.
- **Hardware-bound auth.** Per-request attestation (TPM/PoP, JS PoW) is a genuine
  structural limit for any black-box replay tool, ONYX included.

The one thing to hold onto: on the *confirmation* of an authorization break — proving
the boundary was actually crossed, deterministically, with zero false positives even on
a hostile network — ONYX's method is sound by construction where the field's is
response/status-based or AI-scored. That is the axis ONYX wins; elsewhere the field is
broader.

## One-line positioning
Where it matters most and is hardest — proving an authorization boundary was *actually*
crossed, deterministically, with zero false positives even on a hostile network —
ONYX's method is sound by construction where the field's is heuristic, status-based, or
probabilistic. Everywhere else, the field is broader. Pick the tool for the axis.
