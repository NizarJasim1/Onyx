# Deficiency #10 (the independent T1 number) — the honest maximum, under [16]+[17]+[19]

This is the ONE deficiency that is **execution, not code**. A genuine T1 number needs a
live, independently-authored, network-reachable authorized target. This sandbox has no
egress and no live target, so an honest T1 number **cannot be produced here** — and [16]
forbids claiming one, because that is the exact overclaim the deficiency file warns against.

So the resolution is [17] (radical alternative path): build the turnkey machinery that makes
the operator's real T1 run a single command and its result tamper-evident and tier-honest —
removing every obstacle except the one no code can remove.

## What was built (GAP-2..5 — solved + tested)
`external_targets/byo_runner.py`:
- **`run_target(cfg)`** wires EVERY deficiency solution — policy hypothesis (#1), surface
  expander (#2), liveness gate (#3), consequence oracle (#4), capability chaining (#5),
  stealth profile (#6), generative grammar (#8), ROE contract (#9) — points ONYX at a
  caller-supplied client, and drives the observe/analyze plan end-to-end.
- **`SealedScorecard`** emits a hash-chained record (the #9 tamper-evident audit) of target,
  principals, every finding, and the run tier — third-party-verifiable, un-fudgeable.
- **Tier honesty is enforced by construction:** a run is labelled **T1** only if the operator
  asserts the target is BOTH independently authored AND live-networked; an in-process or
  self-authored replica is labelled **T2** and literally cannot be stamped T1 by this code.

Proven in-box against a faithful in-process replica (loopback): the harness confirms the
seeded cross-principal leak, the scorecard is tamper-evident (a single edited byte breaks the
chain), the replica is correctly labelled **T2 — not a live T1**, and recall-vs-declared-
ground-truth is reported. Tests: `tests/test_byo_runner_scorecard.py` (5 cases). Full suite
542 green; MSI byte-identical.

> Note: fixing this deficiency's tamper-evidence surfaced and fixed a real bug in the #9
> audit (verify() had hard-coded the genesis seed) — [16]'s wall-test doing its job.

## The wall ([19] band 1/3) — proven, not assumed
GAP-1 is a genuine wall: a live authorized run needs egress + a target ONYX did not author.
No code removes it inside a no-egress sandbox. The work-around (turnkey harness + sealed,
tier-honest scorecard) is applied and declared. **The first honest T1 number remains the
operator's to run**, against a target they are authorized to test — one command, with a
sealed scorecard as the result.

## The [18] card
- **(أ) Structural constraint removed:** every obstacle to an independent run EXCEPT live
  egress — the wiring, the tier-honesty, the tamper-evident proof — is removed; the operator
  points `run_target` at a live authorized target and gets a sealed T1 scorecard.
- **(ب) Hypothesis the solution requires:** the operator supplies the live client, the
  principals, the engagement contract, and the honest tier assertions.
- **(ج) Weakest remaining link (the honest ceiling for the whole project):** ONYX cannot
  conjure a live authorized target or a network; the T1 number is a function of the operator
  running it. That is the true, declared frontier — exactly as the file states.
