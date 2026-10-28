# Deficiency #3 (static identity vs a live auth protocol) — SOLVED under [18]+[19]+[20]

ONYX modelled a principal as fixed headers valid for the whole run. Real valuable surfaces
use short-lived OAuth/OIDC tokens with refresh rotation and device-bound credentials. The
safety-critical failure: a bare 401 from a **dead** token was indistinguishable from a real
authorization denial, so a dead-token negative masqueraded as "access denied = safe" — a
silent false negative that could also corrupt a Δstate verdict (threatening zero-FP).

## The root move ([4].R5) — a liveness gate, not 401-parsing
A NEGATIVE result (401/403/session-expired) is trusted **only** when an independent
**liveness probe** proves the credential was live at that instant (an authenticated
self-read that must succeed iff live). This makes 401-conflation impossible *by
construction* and is deterministic (a hard pass/fail, no inference), so zero-FP is
strengthened, not risked.

## Gap inventory ([19] band 1) and closure

| Gap | Was | Closure |
|-----|-----|---------|
| **1 401 conflation (safety-critical)** | dead-token 401 read as a real authZ denial → silent FN | **SOLVED.** A live-token 401 is trusted as authZ; a dead-token 401 abstains as `authn_contaminated` — never "safe". Tri-state `ensure_live` distinguishes them without parsing the 401. |
| **2 liveness not verified** | negatives trusted blindly | **SOLVED.** Every trusted negative is gated behind the liveness proof. |
| **3 no session lifecycle** | short token dies mid-run | **SOLVED.** An operator re-auth callback restores liveness; the stale response is marked `revived` → re-issue with fresh creds. |
| **4 N concurrent sessions** | a silently dead principal contaminates its reads | **SOLVED.** Per-principal liveness is tracked; a principal that can't be kept live abstains rather than emitting contaminated negatives. |
| **5 device-bound attestation** | per-request enclave signature (Entra PoP/TPM, JS PoW, mTLS) | **REAL WALL, worked around + declared.** Attestation-closed principals abstain; the work-around is to ride a real client that holds the key (operator-provided). ~30% of surfaces; the declared domain is the ~70% bearer surfaces. |

Tests: `tests/test_liveness_gate.py` (5 cases). MSI byte-identical (gate default OFF);
full suite 509 green; dedup lint clean.

## The walls ([19] band 3) — proven, worked around, declared
- **Device-bound per-request attestation** cannot be forged by any external tool — an
  information/physics wall. Work-around: an operator-provided real client that holds the
  key; absent that, the surface is declared attestation-closed and ONYX abstains. This is
  a declared coverage boundary, not a silent gap — and it is the same ~30% the file states.

## The [18] card
- **(أ) Structural constraint removed:** "identity = static header valid all run" is gone;
  a negative is trusted only when liveness is proven, and sessions are kept live via
  re-auth — unlocking long cross-principal runs against short-token OAuth surfaces.
- **(ب) Hypothesis the solution requires:** the operator supplies a liveness probe and
  (optionally) a re-auth callback — like the auth headers, never fabricated by ONYX.
- **(ج) Weakest remaining link:** device-bound attested surfaces stay uncoverable by an
  external tool (declared ~30%); everything bearer-based is in scope.

## Graduation
Proven on a synthetic short-token target (token dies mid-run) with and without the gate —
the difference is exactly the eliminated authN-contamination. Next honest station: a real
OAuth app with an operator-supplied re-auth callback — not a Google/Microsoft claim.
