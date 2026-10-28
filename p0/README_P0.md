# P0 — Independent Measurement Runbook (operator-run)

This rig converts ONYX's self-measured (T2) claims into an independent (T1) result —
**if** it is run honestly. The integrity is enforced by code, not trust: the ground
truth is sealed before the run, and the scorer refuses the T1 tier unless the seal
verifies and the target is genuinely third-party.

## Why this is independent
- Target: **OWASP crAPI**, pulled unmodified (its authors are not ONYX's).
- Ground truth: crAPI's **own** published challenges, restricted to ONYX's domain
  (BOLA/BFLA/BOPLA) and **sealed before** the run. The ceded classes (SSRF, JWT,
  injection, chatbot, DoS, brute force) are declared, not measured.

## Steps
1. **Bring up the target** — see `docker-compose.p0.yml` (uses the upstream crAPI compose).
2. **Seal (pre-register)** — `make seal`. This records `sha256(oracle+protocol)` into
   `oracle.sealed`. Do this **before** running; editing the oracle afterwards breaks
   the seal and forces a T2 downgrade.
3. **Dry check (offline)** — `make check` lists the probes built from the oracle.
4. **Run (live)** — `make run BASE=http://localhost:8888`. Provisions two real crAPI
   users, drives ONYX (observe own resources, then attack cross-principal), and writes
   `findings.json` + `run_manifest.json`. Credentials are real; nothing is fabricated.
5. **Baseline (head-to-head)** — `make baseline` prints the Autorize/ZAP config to run
   the heuristic detector on the same endpoints.
6. **Score** — `make score`. Prints recall/precision and the awarded evidence tier
   with the integrity reasons.

## What a result means
- **T1_INDEPENDENT** is awarded only if the seal verifies AND the target is third-party.
- recall = crAPI authz challenges ONYX confirmed / total in-scope challenges.
- precision = confirmed challenges / (confirmed + findings on legitimate self-access).
- The honest headline after a clean run is the first **independent** evidence for ONYX;
  until then every ONYX precision/recall number remains **T2**.

> Built offline (no network in the build environment). Only steps 1, 4, 5 need the
> live target; the integrity core (oracle, seal, scorer) is fully tested offline.
