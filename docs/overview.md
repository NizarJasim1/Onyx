# ONYX overview

> Every claim below carries its evidence tier. **T1** independent · **T2**
> self-measured · **T3** mechanism-estimate · **T4** true by construction.
> "Proven" is reserved for T1. Nothing here is presented as independent proof.

---

## 1. The problem

Every authorization scanner in wide use — Autorize, and the BFLA/BOLA checks bolted
onto larger suites — decides whether access was blocked by **inferring** it from the
response: the status code, the body length, a fingerprint string. That inference is
wrong often enough that the tools say so themselves: Autorize warns that a
"Bypassed!" result does not mean a real vulnerability and that, without a hand-tuned
detector, you will see false positives. A benign `200` and a real leak can look
identical to a length/status heuristic — so these tools either drown a triager in
false positives or miss the leak entirely.

## 2. The insight

Authority is a **conserved quantity**. A principal can only exercise authority it was
actually granted; any effect that exceeds the authority it provably holds is a
violation. ONYX never asks "did this look blocked?" It asks "did the world change in
a way only an over-authorized actor could cause?" — and answers only from a measured
**Δstate differential** across principals, never from a status code or a length diff.
One rule (RL3) governs the entire engine: no Δstate, no finding.

## 3. The proof (assembled, each line at its true tier)

- **[T2_SELF_MEASURED]** On the same labeled traffic, against a full-strength
  reimplementation of Autorize's documented algorithm, ONYX produced no false
  positives while the heuristic baseline produced many — a measured precision gap on
  a self-authored target. (The independent re-run is §5.)
- **[T4_BY_CONSTRUCTION]** ONYX confirms **read** leaks — the most common BOLA shape —
  by a cross-principal value-presence differential. A write-only mutation verifier
  structurally cannot reach that coordinate; ONYX reaches it without mutating state.
- **[T4_BY_CONSTRUCTION]** Because each finding is tied to the specific conservation
  law it violates, ONYX derives the exact missing control (the remediation) and the
  standard taxonomy (OWASP API / CWE) from *which* invariant broke — something a
  template- or signature-driven tool has no model to do.
- **[T4_BY_CONSTRUCTION]** ONYX applies "prove, don't claim" to **itself**: every
  metric it emits is stamped with the evidence tier it is entitled to, derived from
  the target's provenance, never chosen. It is the only tool here that refuses, by
  construction, to over-claim about its own results.
- **[T2_SELF_MEASURED]** The whole engine is held to a byte-identical labeled
  calibration, a mutation-hardened test suite, and a stdlib-only CI gate — so the
  qualities above are demonstrated on every change, not asserted.

## 4. Why this is hard to copy

The flagship sentence: **Hadrian proves what *changed*; ONYX proves what *leaked* —
and reads are the most common BOLA, exactly where write-verifiers fall back to the
heuristic they set out to replace.** That is a structural position, not a feature: it
follows from modelling authority as a conserved quantity with measured provenance,
which is the part a competitor cannot bolt on after the fact.

## 5. Scope — what ONYX covers, and what it deliberately does not

ONYX is a **depth instrument on one axis: authorization.** That narrowness is the
source of its precision, not a gap in it.

**In scope (the authorization surface, in depth):**
- Object level — IDOR / BOLA (`OBJECT_ACCESS`), and read-leak field exposure
  (`FIELD_PROJECTION`).
- Property level — mass-assignment / BOPLA (`OWNERSHIP`).
- Function level — BFLA and privilege-grant escalation (`AUTHORITY`,
  `AUTHORITY_GRANT`).
- Business logic — payment, price, state-gate, inventory, coupon abuse.
- Temporal — stale-authorization drift and authorization regression
  (`TEMPORAL_DRIFT`, `AUTH_REGRESSION`).
- Structural — cross-surface and divergent-path authorization, and emergent
  multi-step breaks (`CROSS_SURFACE`, `STRUCTURAL_DIVERGENCE`, `EMERGENT_BREAK`).

**Out of scope (deliberately ceded):** injection (SQLi, command, XSS), SSRF, JWT
signature/crypto attacks, credential theft and brute force, rate-limiting and DoS,
and anything that is not an authorization decision. A generalist scanner chases this
breadth; ONYX does not, because confirm-by-Δstate is only possible when the question
is narrow enough to have a measurable answer.

**Honest limits within scope:** ONYX is black-box (it reads no source); it needs a
legitimate-traffic phase to learn provenance; it needs at least two principals to
form a differential; and where it cannot observe enough to be certain, it abstains
and reports a coverage gap rather than guess. Abstention is a designed behavior — and
it is also a real boundary.

## 6. The honest bottom line

What is established today is **T2 / T4**: precision by construction, a measured
advantage over the heuristic on a self-authored target, read-leak and remediation
positions that follow from the architecture. What is **not** yet established is the
**T1** claim — independent recall and false-positive rates measured by a third party
on a target ONYX's authors did not design (e.g. OWASP crAPI). That measurement is the
single declared next step, and until it is run, ONYX does not claim it.
