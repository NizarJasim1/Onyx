# THE BROADCAST-vs-ACT NERVE
### Discovered under the DEEP critical protocol across two cold-minded sessions

---

## 0. What this is

A candidate detection principle for finding authorization vulnerabilities on the
**picked-over surface** of giant targets — bugs the thousands of researchers and every
existing tool miss, not because the bugs are deeper, but because everyone looks through
the same lens. This document freezes the nerve after it survived the full DEEP protocol
(DIG → KILL → CROSS, plus a cold-minded K-final in a separate session). It is the spine
for the FORGE build that follows. It is written to be **attacked**, not admired.

---

## 1. The conserved law (the nerve, stated once)

> **Every target broadcasts its authorization decision twice, on two independent
> channels: as a DECLARATION (what it shows vs. hides — present/absent fields,
> `_links`, explicit 403 reasons, GraphQL schema, the actions its own UI exposes) and
> as an ACT (what it actually executes when you try). The conserved quantity is that
> the two channels must agree. A vulnerability is where they contradict:**
>
> - broadcasts "forbidden" (no link / field hidden / 403) yet the act **executes** → **BFLA / hidden-action**
> - broadcasts "allowed" yet the object is not yours and the act **returns it** → **BOLA**
> - shows a field its own declaration says you should not see → **excessive exposure**
>
> **ONYX quotes the pairs to test from the target's OWN broadcast — it never induces
> them — and tests only where the broadcast disagrees with the act, confirmed by
> Δstate.**

---

## 2. Why this enters the picked-over surface (the creative core)

The whole world tests the **ACT**: swap IDs, replay as another user, try the action,
diff the response. Every tool (Autorize, AuthMatrix, RESTler, the fuzzers) and every
researcher lives on this one channel. The low-hanging fruit on that channel is gone.

**Nobody reads the BROADCAST channel and confronts it with the act.** They treat
`_links` as "UI navigation", absent fields as "just design", 403 text as "an error
message". They are, in fact, the target **declaring its own authorization decision** —
and a declaration can be held against the act that contradicts it.

This is the lens no one else uses. It is reachable from outside (the broadcast is on the
wire), and it convicts with zero false positives (Δstate, never the broadcast alone).

---

## 3. The DEEP journey — what was killed, and why (the evidence of rigor)

### Candidate A — "Identity non-conservation across internal boundaries"  → KILLED (K1)
The giant decides identity once at the gateway and consumes it via trusted headers /
token-exchange across deep services (evidence: CVE-2026-29000 cross-service trust
failure; RFC 8693 token exchange erasing the original authorization chain; "never trust
forwarded `X-User-Id`"). **Killed by K1 (reach):** the gap between identity readers is
*internal*; its only externally-visible trace is decision inconsistency across doors —
which the existing ONYX engines already catch. The reachable part is not new; the new
part is not reachable.

### Candidate B — "Selection under combinatorial explosion"  → SURVIVED K1-K3, deepened
K1 kill of A exposed the real blind spot: not *detecting* contradiction (solved by
Δstate) but *choosing which pair to test* from an explosion. Evidence (K2): the entire
field splits into exactly two families — brute coverage ("try millions fast" — fuzzers,
RESTler breadth-first) and human risk-lists ("focus on auth/payments" — StackHawk,
Acunetix). **Nobody makes the target itself declare which pairs are worth testing.**
K3: selection never convicts (Δstate does), so a wrong choice costs a wasted request,
never a false positive — it touches recall, not precision.

### K-final (cold session) — "Does the giant actually broadcast its decision, reachably?"
Evidence that broadcast is real and external (D1, indisputable):
- David Biesack (API Design Matters): a `_links` "edit" present means the user may edit;
  **its absence means the user may not** — the link set is the server declaring, per
  user and state, what their roles/permissions allow.
- Yapeal (bank) drives UI button visibility purely off "is the HATEOAS link present?",
  to avoid duplicating the business logic already in the service → the **service
  broadcasts the authorization decision in the response**.
- PayPal ships it in production (not theoretical).

The wound that remained: explicit `_links` is rare ("most REST APIs are not
HATEOAS-compliant"). **Healed by T4 (running the code, not the web):** ONYX's own
`action_matrix.py` derives pairs from *observed* actions and *path-shape guessing* —
proving that even our best engine does **not** read the broadcast. And the broadcast is
far wider than formal `_links`: **present/absent fields in every JSON response**,
explicit 403 reasons, GraphQL `__schema` and authorization-nulled fields, `Allow`
headers, UI action maps in JS. Every target, rich or poor in HATEOAS, **must decide what
to show and what to hide, and that decision is visible on the edge.** Surface is wide,
not narrow. Wound closed.

---

## 4. Relationship to the first nerve (the unification — creative payoff)

The first nerve (identity⇄ownership) is a **special case** of this one. "The response's
`owner` field declares the object belongs to X" is one form of broadcast (a declaration
in a present field); serving it to Y is the act contradicting that declaration. So:

> Broadcast-vs-Act is the **general law**; identity⇄ownership is the declaration-channel
> instance keyed on the `owner` field. The four existing engines (door/time/sibling/
> hierarchy) are act-channel consistency. This nerve adds the **declaration channel**
> and the law that unifies both: *the target must not contradict its own broadcast.*

---

## 5. Honest residue (fails safe — abstain, never false-positive)

- A target that broadcasts **nothing** distinguishable (identical responses, no field
  variation, no `_links`, opaque 403) → ONYX abstains. Reduced recall, never an FP.
- The hardest case: a broadcast difference that is a **legitimate** conditional (feature
  flag, A/B, plan tier) not an authorization decision. Guard (must be built in FORGE):
  only treat a broadcast difference as an authorization claim when it correlates with a
  declared identity/role/ownership signal; otherwise abstain. This is the central FP
  risk and the FORGE pre-mortem must center on it.
- Selection chooses *what to test*; it never convicts. Conviction stays Δstate-only.

---

## 6. Status

Candidate nerve, **survived the full DEEP protocol across two cold sessions** (DIG, K1,
K2, K3, K-final, all passed; wound closed by running the code). Newer than the published
field shows (T3 — not claimed as absolute novelty). **Not yet proven by a build** — the
ultimate test, per T4, is FORGE on a ruler with real broadcast.

Next: FORGE. First component — the **broadcast extractor**: read the target's declared
decision from responses (present/absent fields across principals, `_links`, 403 reasons,
schema), emitting candidates only, convicting nothing until Δstate. The FP pre-mortem
(§5, the legitimate-conditional trap) is written before any code.
```
