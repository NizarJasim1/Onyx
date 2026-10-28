# P0 — Independent Measurement Rig (complete: six-step arc; operator-run live step)

## What P0 is for
Every ONYX precision/recall number from P1–P7 is self-measured (T2): true, but on
ONYX's own traffic. P0 is the rig that converts those into independent (T1) evidence
by measuring ONYX against a third-party target (OWASP crAPI) under a pre-registered,
hash-sealed ground truth — and it refuses to claim T1 unless the integrity holds.

## The integrity model (game-proof by construction)
A naive run on crAPI would not be T1; it could be gamed by editing the ground truth
after seeing the output, or by cherry-picking. P0 forecloses that:
- The oracle is derived from crAPI's OWN published challenges, restricted to ONYX's
  authorization domain, and **hash-sealed before the run** (pre-registration).
- The scorer awards **T1 only if** the seal still verifies AND the target is
  genuinely third-party; otherwise it downgrades to T2 and states why. This is the
  P0×P8 contract enforced in code, not trust.

## Built (everything except the live run; the sandbox has no network)
- `p0/oracle.json` — ground truth from crAPI's docs: 5 in-domain authz challenges
  (BOLA vehicle/mechanic, BOPLA video/order, BFLA admin-delete) with real endpoints,
  4 known-clean self-access cases (the false-positive traps), and 6 honestly ceded
  classes (SSRF, JWT, injection, chatbot, DoS, brute force).
- `p0/protocol.md` — pre-registered metric definitions, case_id matching rule, and
  the T1 integrity gate.
- `p0/seal.py` — sha256 seal over oracle+protocol; `seal` / `verify`.
- `p0/scorer.py` — recall/precision against the sealed oracle + the T1 gate. Fully
  offline-testable.
- `p0/runner.py` — OPERATOR-RUN: provisions two real crAPI users (never fabricated,
  D6), drives ONYX (observe own resources, then attack cross-principal) through the
  real HTTPTarget, and emits a scorer-ready findings.json. `--check` builds every
  probe from the oracle offline (no network).
- `p0/baseline_runner.py` — the status/length/fingerprint head-to-head on the SAME
  target (in-repo AutorizeBaseline, or a printed real-Autorize/ZAP config).
- `p0/docker-compose.p0.yml`, `p0/Makefile`, `p0/README_P0.md` — the operator runbook.

## Verification (offline proof the rig is correct and game-proof)
`tests/test_p0_scorer.py` (7) proves, without a live run:
- a perfect synthetic run scores recall 1.0 / precision 1.0 and is awarded **T1**;
- a missed challenge lowers recall; a finding on a known-clean case lowers precision;
- a broken seal and a non-third-party target each force a **T2** downgrade with a reason;
- the committed seal verifies; the runner builds a probe for every oracle case.
End-to-end offline dry run (seal → score of a synthetic perfect run) prints a real
T1 scorecard. 446/446 total — zero regression. Demo byte-identical: 39/39.

A modeling bug was caught and fixed during the build: excessive-data-exposure
(FIELD_PROJECTION) is a violation on the actor's OWN resource, so the scorer matches
findings to cases by a runner-supplied case_id rather than inferring cross-principal.

## Honest boundary
The integrity core (oracle, seal, scorer) is complete and tested. The LIVE run is
operator-only — until you run `make -C p0 run && make -C p0 score` against crAPI and
the scorer prints T1_INDEPENDENT, every ONYX number remains T2. P0 makes that final
step a single honest command whose result cannot be faked.
