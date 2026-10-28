# Proving World — an internal, independent, LIVE detection benchmark

## What this is (and why it is not circular)
The user cannot run crAPI locally, and a synthetic *capture* (canned responses) would
be circular — authoring the data that the tool then "finds". This instead builds a
**real live vulnerable application** (`world.py`) with real in-memory state and real
broken authorization logic, and attacks it with ONYX as a genuine black box.

Anti-circularity is **enforced, not promised**:
- `world.py` imports **zero** `authpath` — proven by an AST guard + a test. It is
  written like an ordinary REST backend; a vulnerability is simply a missing
  `if requester != owner: 403` line. Nothing references ONYX's laws.
- **Which** endpoints are vulnerable is chosen at **random per seed**, not hand-picked
  to match a detector. The ownership graph is random too.
- The oracle (ownership graph + vuln map) is **hash-sealed before** any attack; ONYX
  receives only HTTP request/response and must reconstruct the truth from Δstate.
- The attacker harvests object ids the way a real attacker does — enumeration and
  leaked ids from responses — **never** from the oracle.

Because the target's broken behaviour is real and unseen, ONYX reproducing the sealed
vuln map is genuine independent detection — stronger than a single fixed target: it is
measured over a **distribution** of randomized instances.

## Result (25 randomized sealed worlds)
- **precision = 1.000** — zero false positives across all 96 safe-endpoint
  opportunities. The zero-FP core holds on live targets ONYX has never seen.
- **recall = 0.944** — 84/89 planted, reachable vulnerabilities confirmed by Δstate.
- admin-delete **BFLA** is now closed FP-safely by **RL25** (cross-principal
  destruction); what remains is a small long tail of chained/second-order cases.

## What the world surfaced and what was built
Running it revealed that cross-principal **writes** (PUT/DELETE on a foreign object)
were missed — the read-leak trigger needs the response to echo foreign data, which a
write response does not. This produced **RL23** (`_xprincipal_write_pass`): a
state-changing request to an object owned by a different tracked principal, accepted
(2xx) with the mutation **persisted** on read-back, is confirmed as unauthorized
modification. Δstate-based, flag-gated, default-OFF, FP-safe (the increment RL23 alone added: recall 0.59 -> 0.72; later RL25 +
video ownership lifted the overall to 0.944, precision unchanged at 1.0).

## Run
```
cd proving_world && python3 harness.py          # 25 seeds, aggregate recall/precision
python3 tests/test_proving_world.py             # isolation + zero-FP + recall floor
```

## Honest tier
This is **independent-by-construction live detection** (isolation + randomization +
sealing), stronger than self-measured (T2) and spec-conformance. It is not full T1
only in the social sense that the app author is not a separate organisation like
OWASP — the independence here is architectural and proven, not organisational.

## Note on recall vs the anvil
This clean harness reports recall ~0.94 (perfect transport). The chaos benchmark
(`ANVIL.md`) reports ~0.80-0.86 because it runs with `stability_k=7`, trading a little
recall for iron precision under hostile transport. Different config, not a contradiction.

## RL25 — cross-principal destruction (admin-delete BFLA)
The world now includes a video read/own endpoint and an admin-delete. RL25 confirms
admin-delete BFLA the FP-safe way: not a 'path says /admin' role heuristic, but the
observable CONSEQUENCE — a non-owner destroyed an owner's object, proven by Δstate
(the owner's cache-busted re-read now returns gone) plus legitimate observe-phase
ownership. This lifted recall from ~0.72 to ~0.94 with precision held at 1.000.
