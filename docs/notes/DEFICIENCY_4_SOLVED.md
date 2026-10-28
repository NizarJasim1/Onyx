# Deficiency #4 (invisible-Δstate blindness) — SOLVED under Protocols [18]+[19]

The confirmer only ever confirmed an effect it could **read back directly**. A whole class
of high-severity effects has no direct read-back (a changed credential, a raised
capability, an effect visible only to another principal, a delayed/external one), so ONYX
abstained on all of them — the same rule that gives zero-FP also caused this blind spot.

## The root move ([4].R5 / [12]) — a consequence oracle
Generalise confirmation from "read back the EFFECT" to "read back a CONSEQUENCE the effect
**necessarily** entails, through a channel ONYX controls." Necessity, not probability, is
what keeps it FP-safe: if the consequence can only hold when the effect happened, observing
it *proves* the effect. No ML, no inference (RL1/RL2 intact); no oracle -> abstain as before.

## Gap inventory ([19] band 1) and closure

| Gap | What was invisible | Closure |
|-----|--------------------|---------|
| **1 credential takeover** | The file's OWN flagship miss — VAmPI's cross-principal password change, invisible without re-auth | **SOLVED.** RL26 confirms via the re-auth consequence: auth AS the victim with the attacker-chosen credential now succeeds. A random value can't authenticate unless the write took effect. VAmPI recall **2/3 → 3/3**, precision 1.0; the fixed app stays **zero findings**. |
| **2 capability acquisition** | Privilege escalation with no visible data | **SOLVED.** A specific action FLIPS from denied (baseline captured before any attack) to allowed after the write — the Δstate the escalation entails. A no-op write does not fire (FP-safe). |
| **FP-safety** | A consequence that didn't actually happen | **SOLVED.** Confirmation requires the consequence's real Δstate; on the safe VAmPI (takeover blocked) RL26 never fires -> zero-FP. |
| **3 victim-visible-only** | Effect visible only to a principal ONYX doesn't control | **Work-around applied:** ONYX reads back as any controlled principal the operator provides (the auth/capability prober is that channel). Where the observer is genuinely unavailable it is a real wall -> abstain + declared. |
| **4 time-delayed / async** | Effect lands outside the run window | **Bounded** deferred re-verification via the oracle; unbounded delay is a real wall -> abstain + declared. |
| **5 external sinks / pure side-channels** | Email/webhook/payment, write-only logs, timing | **Declared walls.** If the operator wires a channel to the sink, the oracle consumes it; a pure side-channel stays outside the Δstate model by design (RL5 abstain). |

Tests: `tests/test_consequence_confirmation.py` (4 cases) + VAmPI suite. MSI byte-identical
(RL26 default OFF); full suite 504 green; dedup lint clean.

## The walls ([19] band 3) — proven, worked around, declared
- **A pure side-channel or an external sink ONYX has no channel to** cannot be read back by
  anyone — a real information wall. Work-around: an operator-wired channel turns it into a
  consequence; absent that, ONYX abstains (never fabricates). Declared, not silent.
- **Unbounded asynchronous effects** cannot be waited on forever — bounded window + honest
  abstention beyond it.

## The [18] card
- **(أ) Structural constraint removed:** confirmation no longer requires the effect to be
  directly visible — any necessary, controllable consequence suffices. This unlocks the
  invisible-Δstate class that **every** response/Δstate-diffing competitor shares as a blind
  spot (an exclusive class, per the file).
- **(ب) Hypothesis the solution requires:** the operator supplies the consequence probes
  (login flow / capability check) — like the auth headers, never fabricated by ONYX.
- **(ج) Weakest remaining link:** effects observable to NO party through ANY channel
  (pure side-channels, unreachable external sinks, unbounded async) stay out of scope —
  ONYX abstains there. Declared ceiling, not a hidden gap.

## Graduation
Proven on VAmPI (the file's own missed example) and a synthetic escalation target. Next
honest station: a real app where the operator can wire a login/capability prober — not a
Google/Microsoft claim.
