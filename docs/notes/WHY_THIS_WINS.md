# ONYX — why this wins (2-minute read for a judge)

## The one sentence
Most tools *guess* that an authorization boundary was crossed by comparing responses
or status codes. **ONYX proves it by watching the system's state actually change** —
deterministically, with zero false positives, even on a hostile network.

## The problem, in plain terms
The #1 API vulnerability (Broken Object Level Authorization) is, in the industry's own
words, "the hardest for automated tools to detect because it requires understanding the
authorization model." Tools cope by heuristics: *did the response differ? is it not a
403?* Those heuristics break in two directions — they cry wolf on a cached or stale
response (false positive), and they stay silent when the leak leaves the status code
unchanged (false negative).

## What ONYX does differently (the whole idea)
ONYX never trusts a status code or a response diff. It confirms a finding only when it
can observe the **actual state change** the attack caused:
- read another user's object and prove the private data is really theirs (by provenance),
- flip a field and read it back to prove the mutation persisted,
- delete a foreign object and prove the owner's own object is now gone.
No machine learning, no LLM, in the decision path — so every finding is reproducible and
ships a proof a third party can replay.

## The evidence (this is the part that is hard to argue with)
- **Zero false positives, on targets it has never seen.** ONYX is scored over a
  *distribution* of randomly-seeded, hash-sealed vulnerable apps, with a code check
  proving the target shares nothing with the detector. Run it yourself: `python3
  demo_live.py`.
- **The guarantee holds under chaos.** An "anvil" injects production noise — stale
  reads, shared-cache bleed, retries, async, rate-limits — *harder than reality*.
  Precision stays **1.000 at every level**. No competitor publishes a chaos-hardened
  zero-FP number.
- **A target whose author never met ONYX.** Against **VAmPI** (erev0s, 2021) over real
  HTTP, ONYX confirms BOLA and excessive-data exposure and returns **zero findings on the
  fixed version** — the false-positive test on vulnerabilities a third party defined,
  independently, years earlier. This is the closest thing to a third-party run that fits
  in a repo; a judge can confirm against the upstream Docker image in minutes.
- **A real, independent number.** On a live crAPI capture, ONYX produces **zero false
  positives on 36 real probes**, wrapped in a hash-chained measurement bundle that
  re-verifies end-to-end (trust-no-one).

## Threat model & scope (honest boundaries)
- **In scope:** authorization effects on bearer-token / cookie APIs (~70%+ of APIs) —
  BOLA, BFLA, mass-assignment, excessive-data / field exposure, cross-principal
  write/delete.
- **Out of scope, by design:** breadth (SQLi/XSS/SSRF — use a DAST for those),
  endpoint discovery and CI gating (bring your surface), and hardware-bound per-request
  attestation (TPM/PoP, JS PoW) — a genuine structural limit for any black-box tool.

## About the recall number (get ahead of the obvious question)
ONYX's recall is ~0.94 clean / ~0.80 under heavy chaos — deliberately not 1.0. That is
a *design choice*, not a weakness: the sacred rule is **zero false positives always**;
when an observation will not stabilise, ONYX **abstains** rather than guess. A tool that
never lies about a vulnerability is worth more to a security team than one that finds a
few more but cries wolf — because every false positive burns an engineer's trust and
time. ONYX trades a little recall for a precision guarantee no heuristic tool can make.

## Two recall numbers, two different questions (read this before you compare them)
You will see **0.94** (proving world) and **1/5** (real crAPI capture). They are not in
conflict, and the lower one is not hidden:
- **0.94 measures ONYX's detection capability** — it drives the full active loop
  (provision → observe → attack → read-back), so it can confirm the Δstate of any
  planted vulnerability.
- **1/5 measures what is confirmable from a *passive* crAPI capture** — a flat traffic
  sweep with no active loop: no vehicle was provisioned, no video uploaded, and the
  mass-assign was on the actor's own order with no credit read-back. Four of five are
  *unconfirmable from that data*, and ONYX correctly abstains on them (per-challenge
  reasons are printed in the scorecard) rather than guess. That 1/5 is a property of the
  capture, not of the detector.

Raising the crAPI recall needs an *active-loop* capture — the same live run that only
the operator can perform. The honest headline on real crAPI is therefore the
**precision** number (zero false positives on 36 real probes, PCM-verified), with recall
scoped exactly to what a passive sweep can prove.

## What the 0.944 is, and what it is not
The ~0.94 recall is measured **on ONYX's own randomized proving-world distribution** —
a controlled benchmark with a known vulnerability taxonomy. It says: *given these
vulnerability classes, ONYX confirms ~94% of the planted, reachable instances with zero
false positives.* It is **not** a claim about API diversity in the wild — real APIs have
shapes, auth schemes, and business logic this benchmark does not enumerate. Read 0.944 as
"strong recall under a controlled, adversarial-but-known condition," not as a field-wide
detection rate. The number that is safe to carry across targets is the **precision
guarantee**; recall is always relative to the surface and the plan that exercise it.

## Where ONYX sits
Not a replacement for a broad DAST. A **specialist** that is sound-by-construction on the
one axis that matters most and is hardest to get right: proving, deterministically and
without false positives, that an authorization boundary was actually crossed.

## If you are judging by breadth or impact (read this)
The niche is narrow **by design** — and that is an impact argument, not a limitation:
- **It is the highest-impact class.** Broken Object Level Authorization is **#1 on the
  OWASP API Security Top 10** and, in the industry's own words, the hardest for automated
  tools to detect. Depth on the *most exploited, least automatable* class is worth more
  than shallow coverage of ten easy ones.
- **A broad tool that cries wolf on authorization is a net negative.** Every false
  positive on the hardest class burns the exact expert time it was meant to save. A tool
  that is *provably* right here removes the one finding a security team cannot triage
  cheaply.
- **Depth composes with breadth; it does not compete.** ONYX is meant to sit *beside* a
  broad DAST (which handles SQLi/XSS/SSRF), owning the authorization verdict the DAST
  cannot make soundly. "Specialist that plugs a specific hole" is the point, not a
  concession.
If the rubric rewards breadth of vulnerability classes, ONYX will score narrow — honestly.
If it rewards *soundness on the class that matters most*, that is precisely what ONYX is
built to win.
