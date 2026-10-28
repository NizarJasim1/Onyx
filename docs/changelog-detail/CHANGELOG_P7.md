# P7 — Narrative & Scope (complete: six-step arc; P3 folded in)

## The non-obvious decision
The temptation in a "pitch" is to maximise claims. Under the project's own evidence
discipline (P8) that would be self-defeating: a judge who has seen many over-claiming
student projects is moved by the one that states exactly what it proves, exactly what
it cedes, and the one thing only it can do. So P7's narrative is the HONEST one, and
the scope card is placed prominently as a credibility instrument — not buried as a
disclaimer.

## What changed (documentation only — proved)
A diff of `authpath/` against pre-P7 shows ZERO code change; the sole non-doc edit is
one line in `tools/check_claims.py` adding PITCH.md to the honesty gate.

- NEW PITCH.md — the single judge-facing narrative in six beats: the problem (the
  status/length heuristic and its own false-positive warning), the insight (authority
  as a conserved quantity; confirm-by-Δstate, RL3), the assembled proof with every
  line at its true tier (P2 [T2], P1/P6/P8 [T4/by-construction], P4 [T2]), why the
  position is hard to copy, the scope card, and the honest bottom line (T2/T4 today,
  T1 pending P0).
- P3 folded in — §5 of PITCH.md is the scope/coverage card: the authorization surface
  ONYX covers in depth; the classes it deliberately cedes (injection, SSRF, JWT
  crypto, brute force, rate-limiting); and the honest within-scope limits (black-box,
  needs a legitimate phase, needs two principals, abstains on coverage gaps). The
  framing: narrowness is the source of the precision, not a gap in it.
- CLAIMS.md — added the P2 measured precision advantage [T2] and the P6 derived
  remediation [T4]; still tier-clean.
- check_claims.py — PITCH.md added to the no-bare-metrics gate (P7×P8): the narrative
  itself fails the build if it ever carries an untiered metric.

## Documentation reconciliation
- docs/ARCHITECTURE.md (the older, "DPT"-era deep spec) got a historical banner
  pointing to the current ARCHITECTURE.md and PITCH.md — content preserved, confusion
  removed, README link intact.
- docs/WHY.md — fixed a dead cross-reference to a renamed file; it now points to the
  current map and the pitch.
- README.md — a prominent "start with PITCH.md" entry point at the top.

## Red lines
No detection or confirmation code touched; deterministic; no over-claim — nothing is
promoted to T1, and the P2 result stays T2. All internal links verified live.

## Verification
- PITCH.md, CLAIMS.md, README.md all pass the no-bare-metrics gate.
- Diff vs pre-P7: zero change under authpath/; only check_claims.py FILES extended.
- 439/439 total — zero regression. Demo byte-identical: 39/39, 19 findings, 3 dropped.

## Honest boundary
P7 adds no detection capability. It makes the existing, tier-stamped work legible and
credible to a judge in minutes, and states the scope honestly. The independent proof
(T1) remains P0.
