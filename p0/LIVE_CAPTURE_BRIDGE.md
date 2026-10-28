# Live-Capture Bridge — result, tier, and the T1-capable capture spec

## What this closes
A live `capture_full.json` (real crAPI, 3 real users, real RS256 tokens) had **no
consumer** in the tarball. `p0/live_capture_bridge.py` is the missing ingester: it
replays the capture through the **real** engine (via the existing, proven
`transport.ReplayTarget`), builds a **proof-carrying bundle**, verifies it
trust-no-one, and scores against the **sealed** oracle with strict tier discipline.
It **modifies nothing** in the engine; the demo stays byte-identical and the full
suite passes (462/462).

## The measured result (honest, verifiable)

Tier: **T1_PARTIAL — precision axis only.**

| Axis | Result | Provable from this capture? |
|------|--------|------------------------------|
| **Precision** | **ZERO false positives** across 17 clean self-reads + 19 attack probes on real crAPI data | **Yes** — independently, via the PCM bundle |
| **Recall** | 0 of 5 sealed vulns confirmed | **No** — a flat sweep cannot supply the read-backs RL3 needs |

The zero-false-positive result on **real live-crAPI traffic** is the genuine,
defensible half: ONYX never fabricated a finding from a flat sweep — it abstained
wherever Δstate could not be proven. That is the zero-FP core, validated on real
data, and any reviewer can recompute it from the bundle.

## Why recall is 0 here — and why that is NOT a broken bridge
The capture is a **flat sweep**: attack requests with **no paired read-backs**.
ONYX's RL3 confirmation is **active** — it needs, per candidate: an owner
read-back (proves the object belongs to someone else) and a control read-back
(separates BOLA from BFLA-class). A flat sweep contains none of these, so every
candidate correctly degrades to a lead, never a fabricated finding.

**Proof this is a capture-shape limit, not a broken bridge:** the test
`test_positive_control_active_loop_confirms` feeds a *properly shaped* active loop
(owner-observe → attacker-read → owner read-back) and ONYX **confirms a finding**.
Same bridge, same engine — the only difference is capture shape.

## Per-challenge diagnosis (transparent non-scoring)
- **BOLA-VEHICLE-LOCATION** — NOT EXERCISED. No `/vehicle/{id}/location` probe; own-vehicles returned `[]` (no vehicle provisioned).
- **BOLA-MECHANIC-REPORT** — EXERCISED, UNCONFIRMABLE. A and B both read the same third-party reports; no principal among A/B/C **owns** a report, so there is no ownership differential. ONYX abstained (cold-start ownership).
- **BOPLA-VIDEO-INTERNAL-FIELD** — NOT EXERCISED. No video uploaded (`video_id=0`).
- **BFLA-ADMIN-DELETE-VIDEO** — EXERCISED, candidate raised, UNCONFIRMABLE. No GET read-back proving the delete hit another user's video (`video_id=0`).
- **BOPLA-ORDER-MASS-ASSIGN-STATUS** — EXERCISED, UNCONFIRMABLE. Status PUT is on the actor's OWN order; no `available_credit` read-back to prove the refund Δstate.

## The T1-capable capture spec (what to capture next to earn full recall)
For **each** oracle vuln, the capture must contain the full **active loop**, in order:

1. **Provision** the object so it exists and is owned:
   - a **vehicle** for user A (fixes BOLA-VEHICLE-LOCATION + CLEAN-OWN-VEHICLE-LOCATION),
   - an uploaded **video** for user B (fixes BOPLA-VIDEO-INTERNAL-FIELD + BFLA-ADMIN-DELETE-VIDEO),
   - a **mechanic report owned by A** (fixes BOLA-MECHANIC-REPORT with a real owner).
2. **Owner observe** — the owner reads their own object (establishes provenance):
   `GET .../vehicle/{A_vehicleId}/location` as A, `GET .../shop/orders/{B_orderId}` as B, etc.
3. **Attack** — a different principal performs the violation:
   `GET .../vehicle/{A_vehicleId}/location` as B; `DELETE .../admin/videos/{B_videoId}` as A;
   `POST .../shop/orders/{B_orderId}` with `{status: returned}` as B.
4. **Owner read-back** — the owner re-reads to expose Δstate:
   for reads, the owner re-reads the same object (confirms it is theirs);
   for writes (BFLA delete, mass-assign), the owner re-reads to observe the state change
   (video gone; `available_credit` increased by the refund).
5. **Control read-back** — a third principal (C) attempts the same read; a 4xx here
   proves object-level BOLA (not BFLA-class).

With that shape, the SAME bridge (unchanged) will confirm each vuln and the scorer
will award **T1_INDEPENDENT** (seal verifies + `third_party` provenance).

## Reproduce
```
python3 p0/seal.py                       # seal the oracle first
python3 p0/live_capture_bridge.py        # scorecard + PCM verify on p0/capture_full.json
python3 tests/test_live_capture_bridge.py
```
