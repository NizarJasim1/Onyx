# ONYX — Honest status and the one binding constraint

## The strategic truth (owed plainly)
Across the recent sessions a pattern set in: capabilities, classes, and machines were added —
all real, honest, and verified on controlled targets — while the two things that would
actually change the project's status were not touched. This document states them plainly so
no future "keep going" quietly adds coordinate N+1 instead of facing the constraint.

## #7 (tenant isolation) is DONE — it is #1
Deficiency #7's own solved-criterion (deficiencies file, lines 84–85) is, verbatim, what the
#1 policy-hypothesis work already proves: a multi-tenant target mixing legitimate sharing with
a real breach, distinguished at precision 1.0, breach emitted relative to an explicit isolation
hypothesis, honest abstention when absent. Tenant domains = principal domains; RBAC/delegation =
the transitive grant graph; server-side membership = resource-domain established from the
observe walk. `tests/test_policy_hypothesis.py` (7/7) is the #7 proof. There is no separate #7
to build; claiming otherwise would be fabricated work.

## The one binding constraint: a live T1 run
Everything built is Tier-2 — proven on targets authored or controlled by us. The single thing
that converts the whole project from "verifiable" to "proven" is ONE live run against a real,
independently-authored, authorized target (crAPI on a laptop, a VDP scope, a real multi-tenant
app). This sandbox has NO network egress, so it cannot be done here. This is not a code gap —
no new detector, class, or coordinate relieves it. One live run does; more classes do not.

## What is ready for that run
`external_targets/live_run_template.py` — fill four blanks (base URL, test-principal tokens,
tenant domains, engagement paths), add a ~30-line HTTP adapter, and run against a target you
are authorized to test. It wires every capability and emits a sealed scorecard, stamped **T1
only** if you truthfully assert independent authorship + live network. The scorecard is
hash-chained and tier-honest by construction.

## Honest caveats on the latest additions (so they are not oversold)
- The "pioneered" authorization-drift class is pioneered ONLY in the narrow sense (a formally
  defined, Δstate-confirmed detector). It is NOT a claimed world-first; related ideas exist
  (TOCTOU authorization, confused-deputy via mutable reference, IDOR-via-rebinding). Do a real
  prior-art review before any public use of "novel/pioneered".
- Every competitor "0.0 vs 1.0" number is a self-authored structural model on our own scenario,
  a sound illustrative argument — not a benchmark of the real closed-source tools.
- All giant-scale results (G1–G5) are on giant-EMULATING anvils (T2). They prove capability and
  differential structure; they are not field measurements.

## The honest recommendation
Put the next unit of effort into the live run, not coordinate 27. That is the moment the build
becomes a proof.
