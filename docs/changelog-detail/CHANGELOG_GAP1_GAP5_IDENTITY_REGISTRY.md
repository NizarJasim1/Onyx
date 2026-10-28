# CHANGELOG — GAP-5 (Oracle Registry) + GAP-1 (Identity whoami-differential)

Two gaps from `ONYX_GAP_ANALYSIS_v3.md` closed in one seam — the **confirmation
boundary**. GAP-5 defines the boundary contract; GAP-1 is the first new oracle that
crosses it. Seeing the same seam from both sides is what made the pairing precise.

## GAP-5 — Oracle Registry (`authpath/oracle_registry.py`)
Generalises the single `Confirmer` into a registry of per-`EffectClass`, FP-safe
oracles — the root move the gap analysis crowned ("the hook / the soul"), not a patch.
- **Structural zero-FP lock:** every `CONFIRMED` is re-validated against three red-line
  preconditions (proof observed out-of-band · victim value known in advance · boundary
  tester-owned on both sides) and **downgraded to ABSTAIN** if any fails (fail-closed,
  RL5). A new oracle cannot raise a finding without a genuine owned, pre-known,
  out-of-band proof. Precision is preserved *by construction*, not by audit.
- **GAP-12 honesty slot:** an effect with no FP-safe oracle returns
  `UNCONFIRMABLE_BLACKBOX` — declared, **not** "clean". ONYX states where it is blind.
- **Backward compatible:** `DeltaStateOracle` wraps the existing `Confirmer` unchanged;
  `registry.confirm(cand)` returns exactly what `confirmer.confirm(cand)` returned over
  all existing classes (proven in `test_backward_compat_equivalence_over_all_delta_effects`).

## GAP-1 — Identity proof layer (`authpath/identity.py`)
Closes the layer ONYX was blind to: *how the target decides who you are* (OAuth/OIDC/
SAML/JWT/SSO). This is where the top-tier 2025 federation bugs live (nOAuth, actor-token,
SAML roulette, audience injection).
- **whoami-differential oracle:** after the tester (as attacker) sets a trusted claim to
  the victim's known value, an **independent authenticated whoami read** confirms a spoof
  only if the returned identity == the victim identity, both principals tester-owned.
  Identity twin of the Δstate read-back — same FP-safe discipline (RL1/RL2/RL3/RL5).
- **Claim-trust model learned from the wire (RL1):** the identity key and whether it is
  tester-settable are read from authenticated responses, never assumed — same discipline
  as `ownership_pointer` ("the nerve").
- New `EffectClass.IDENTITY_SPOOF` + `ImpactClass` + remediation taxonomy entry
  (CWE-290 Authentication Bypass by Spoofing / API2:2023 Broken Authentication).

## Verification (external oracles — AMP)
- `tests/run_all.py`: **742/742 PASSED, 0 FAILED, 0 IMPORT_ERRORS** (was 728; +14 new).
- `demo_live.py`: **precision 1.000, 0 false positives at every chaos level** — unchanged
  from baseline. The crown jewel is intact.
- Two independent checks agree the core did not regress (the project CI gate AND the
  sealed randomized proving-world live proof — different code paths, different data).

## Honest scope (no overselling)
The identity oracle's correctness is proven on a **self-authored** vulnerable-vs-patched
pair (Tier-2 / AMP E2). A live nOAuth-class authorized target — the operator's run — is
what lifts it to T1. No red line was relaxed; every change is additive and no existing
verdict changed.
