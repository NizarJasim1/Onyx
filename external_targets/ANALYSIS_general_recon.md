# ONYX Recon — a general, authorized "use the whole app + hunt" engine

## Goal
Point ONYX at **any authorized target** (not just crAPI) and have it exercise the app's
surface comprehensively, discover object identifiers across multiple accounts, and hunt
authorization + business-logic vulnerabilities — automatically, the way a careful human
tester would, but faster.

## Non-negotiable guardrails (what keeps this legitimate)
This is authorized-testing tooling. The engine refuses to act outside these lines:
- **Authorization affirmation required.** No run without an explicit "I am authorized to
  test these hosts and every id is in scope" flag.
- **Scope-Guard on every request.** Only hosts on the allow-list are ever contacted
  (reuses ONYX `ScopeConfig`); any off-scope URL discovered during ingestion is dropped.
- **Honest attribution.** An identifiable `User-Agent` carries the researcher handle. The
  engine never disguises itself or tries to defeat anti-automation / WAF controls.
- **Polite by default.** Concurrency caps + optional jitter; read-biased discovery;
  mutating probes stay dry-run unless `--confirm`, and only against ids the operator owns.
- **Proof, not guesses.** Findings are confirmed by ONYX's Δstate read-back — not by a
  200-vs-403 heuristic — which is what keeps the false-positive rate near zero.

## Why this mechanism (grounded in current practice)
Modern API security tooling (ZAP, Burp, 42Crunch, Invicti, Schemathesis, academic BOLA
scanners) converges on the same findings:
1. **Spec-first beats crawling.** An OpenAPI/Swagger spec gives every endpoint, method,
   parameter, and security scheme up front. Pure crawlers miss endpoints and can't build
   authenticated requests. So ingestion is prioritized: **OpenAPI → HAR/Postman → light
   authenticated crawl** (fallback).
2. **BOLA/BFLA is inherently multi-principal.** The whole class is "what can user A reach
   that belongs to user B." You need ≥2 authenticated identities and a way to know which
   ids belong to whom (**provenance**). ONYX already models this.
3. **Business logic needs effect semantics.** Knowing an endpoint touches *payment* vs
   *price* vs *ownership* is what turns a request into a law. We infer effects from
   path/param/field names (an "annotated-spec" style, but automatic).

## Architecture
```
 sources ─┐
 OpenAPI  │   ┌────────────┐   ┌──────────────┐   ┌───────────────┐   ┌──────────┐
 HAR      ├──▶│  ingest    │──▶│   harvest    │──▶│  plan (effect │──▶│  ONYX    │──▶ reports
 crawl    │   │ (surface)  │   │ (ids + prov.)│   │  -aware, xprin)│   │  engine  │   (vuln + perf/coverage)
 preset   ─┘   └────────────┘   └──────────────┘   └───────────────┘   └──────────┘
                    │                 │                                     ▲
                 Scope-Guard      2+ principals                       Δstate proof
```

### 1. Ingest → normalized surface
Each source yields endpoints: `{method, path_template, path_params[], query, body_example}`.
- **OpenAPI:** walk `paths`; `{param}` → the object-id slot; synthesize a minimal body from
  the request schema/example.
- **HAR/Postman:** replay observed requests; templatize the last numeric/uuid path segment.
- **Crawl (fallback):** seed URLs → extract links/forms + regex API paths from JS bundles.
All templates are normalized so `/users/{id}/orders` is one pattern, not N URLs.

### 2. Harvest → owned ids with provenance
As **each** principal, call the safe collection/read endpoints and collect id-like values,
tagging *which principal saw which id*. That provenance is what lets ONYX prove that
A reading B's id is cross-account access, not a public read.

### 3. Plan → effect-aware, cross-principal
For every `{id}` read endpoint, build the BOLA probe (each principal tries the others'
ids). For mutating endpoints, infer the effect from names and attach a tampered body:
| signal (path / param / field) | effect | law |
|---|---|---|
| pay, amount_paid, checkout, refund, wallet, balance | PAYMENT | underpay / settlement |
| price, total, cost, discount, cart | PRICE | price tamper |
| coupon, promo, voucher | COUPON | reuse / stacking |
| role, is_admin, admin, owner, grant | OWNERSHIP | mass-assignment |
| status, state, approve, publish, cancel | STATE_GATE | skip the gate |
| /admin, /internal, /mechanic (function scope) | AUTHORITY | BFLA |
| default `GET /x/{id}` | OBJECT_ACCESS | IDOR/BOLA |

### 4. Confirm + report
ONYX runs the plan, confirms by Δstate read-back, and emits the **vulnerability report**
(submission-ready) plus the **coverage/performance report** (surface size, ids harvested,
probes, latency, confirmed vs dropped, and an OWASP-API coverage map).

## Honest limits
- Auth flows vary; the engine supports tokens directly and a simple login, and leaves a
  clean hook for custom auth.
- No spec + no HAR = shallow crawl only; coverage is best with a spec.
- Injection, SSRF, brute-force, JWT-crypto are **out of ONYX's model** by design — the
  coverage report says so and points you to complementary tools.
