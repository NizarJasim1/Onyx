# P6 — Reportability (complete: six-step arc)

## The leap competitors cannot copy
Every other scanner stops at "found an IDOR". ONYX goes further BECAUSE its findings
are tied to a conservation law of a specific effect class: the exact missing control
is a function of WHICH invariant broke. So ONYX emits, per finding, a remediation
DERIVED from the violated invariant — a capability a template-driven or signature
tool structurally cannot match, because it has no effect-invariant model to derive
from. The report already proved WHAT (Δstate) and HOW TO REPRODUCE (curl); P6 adds
WHAT TO FIX and WHERE IT FILES.

## What the report gained
- **TL;DR** — a one-line, plain-language summary for a triager skimming a queue.
- **Standard classification** — OWASP API Top-10 (2023) category + CWE id/name, the
  taxonomy a triager files under (e.g. OBJECT_ACCESS → API1 BOLA / CWE-639;
  AUTHORITY → API5 BFLA / CWE-862; PAYMENT → API6 / CWE-840).
- **Remediation (derived from the violated invariant)** — the precise server-side
  control whose absence the law detected, specific per effect family (ownership
  check; server-side amount; single-use atomic claim; grant ⊆ granter; …).
- **Evidence tier stamp** (P6×P8) — the Summary's "confirmed" now carries its tier
  (self target → T2, third-party → T1), closing the circularity leak in the report
  surface. A judge can no longer read a self-target finding as independent proof.

## Files
- NEW authpath/remediation.py — EFFECT_TAXONOMY (15 effect classes → OWASP+CWE+fix+
  TL;DR), classify(), remediation_block(), triager_tldr(), safe CWE-285 fallback.
- authpath/poc.py — PoCEmitter(target_provenance="self"); _markdown adds TL;DR +
  classification + remediation + tier stamp.
- authpath/engine.py — passes scope.target_provenance to the emitter.
- NEW tests/test_remediation.py (8, incl. report integration self→T2 / third→T1).

## Red lines
RL1 the taxonomy is a FIXED table, true by each effect class's definition — never
learned. RL2 deterministic lookup. No detection/confirmation logic changed: pure
presentation at report time, zero false positives added, nothing weakened. The
existing CVSS 3.1 vectors were verified well-formed (14/14 valid) and left intact.

## Verification
- 8/8 remediation tests green; the taxonomy has teeth (removing a row or emptying a
  field fails a test).
- Live-path diff vs pre-P6: only poc.py + engine.py changed (intended).
- 427/427 total (419 from P4 + 8) — zero regression.
- Demo byte-identical: 39/39, 19 findings, 3 dropped.

## Honest boundary
P6 makes the report world-class in COMMUNICATION (what to fix, how it files, its
evidence tier). It does not change the finding's truth, which still depends on the
target: a beautiful report of a T2 finding is still T2 — and now says so.
