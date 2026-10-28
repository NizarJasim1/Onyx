# P0 Protocol — Pre-Registered Independent Measurement

This document is sealed together with `oracle.json` BEFORE any ONYX run. Its hash is
recorded in `oracle.sealed`. The scorer refuses the independent (T1) tier unless this
seal still verifies at scoring time. Nothing below may be changed after a run; doing
so breaks the seal and forces a T2 downgrade.

## 1. Target and independence
- Target: OWASP crAPI, deployed unmodified from the official docker-compose.
- crAPI's authors are not ONYX's authors; its challenges (the ground truth) come from
  crAPI's own published docs. This is what makes a passing measurement independent.

## 2. Ground truth (locked)
- `known_vulns`: the authorization challenges in ONYX's domain (BOLA, BFLA, BOPLA/mass
  assignment). Each is a true positive — crAPI is intentionally vulnerable.
- `known_clean`: legitimate self-access cases on the same endpoints. A finding on any
  of these is a false positive.
- `ceded`: classes ONYX does not target (SSRF, JWT, injection, chatbot, DoS, brute
  force). These are NOT counted for or against ONYX — they are declared, not measured.

## 3. Run procedure (operator)
1. Seal: `python p0/seal.py` (records the hash). Do this BEFORE running.
2. Provision two real crAPI users (signup + login) and capture their JWTs. Credentials
   are real and operator-provided; the rig never fabricates them (D6).
3. Observe phase: each user legitimately accesses ONLY their own resources (this both
   establishes provenance and exercises the `known_clean` cases).
4. Attack phase: each user attempts cross-principal access against the `known_vulns`
   endpoints. ONYX observes and analyzes; confirmation is by Δstate only (RL3).
5. The runner writes `findings.json` and `run_manifest.json` (with target_provenance).
6. Score: `python p0/scorer.py`.

## 4. Metrics (locked definitions)
- The runner tags each finding with the oracle case_id of the probe that produced
  it (one labelled probe is driven at a time, so attribution is exact). A finding
  matches an oracle row by that case_id — no cross-principal inference, which would
  be wrong for excessive-data-exposure cases that occur on the actor's own resource.
- recall    = |known_vulns found| / |known_vulns|.
- precision = |known_vulns found| / (|known_vulns found| + |findings on known_clean|).
- Findings outside the locked oracle are reported separately and never silently
  improve precision.

## 5. Evidence tier (the integrity gate)
The scorer awards **T1 (independent)** only if BOTH hold:
  (a) the oracle/protocol seal verifies, and
  (b) run_manifest.target_provenance == "third_party".
Otherwise the result is **T2** with the reason stated. ONYX cannot claim independence
it did not earn.

## 6. Baseline (head-to-head)
`baseline_runner.py` runs a real status/length/fingerprint detector (Autorize/ZAP, or
the faithful in-repo `AutorizeBaseline`) against the SAME crAPI on the SAME endpoints,
so the precision comparison from P2 is repeated on an independent target.
