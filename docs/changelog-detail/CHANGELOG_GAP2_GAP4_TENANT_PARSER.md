# CHANGELOG — GAP-2 (Cross-Tenant) + GAP-4 (Parser-Differential)

Two more gaps from `ONYX_GAP_ANALYSIS_v3.md`, on the **identity-assertion seam** opened
by GAP-1/GAP-5. One assertion = *(who, within what boundary)*. GAP-4 attacks the
assertion's integrity (same bytes → two identities); GAP-2 attacks the isolation the
assertion is scoped to (identity valid, wrong tenant). Both register as new oracles in
the Oracle Registry and inherit its structural zero-FP guard.

## GAP-2 — Cross-tenant isolation oracle (`authpath/tenant.py`)
Realises the `(identity, tenant)` principal model at the oracle layer (core `Principal`
untouched — additive, zero blast radius).
- **Confirmation (Δstate across a tenant boundary):** a finding stands only when a
  tenant-A principal OBTAINED the object (observed) AND an **independent authenticated
  read** proves the object is owned by tenant B (pre-known, tester-owned) AND A ≠ B.
- **Negative control:** if the object turns out to belong to the caller's OWN tenant (a
  wildcard that only returned own data), the oracle ABSTAINS — a shared/wildcard endpoint
  is not a breach until a PROVEN owned boundary is crossed. Zero FP.
- `EffectClass.CROSS_TENANT` + ImpactClass + remediation (CWE-639 / API1:2023).

## GAP-4 — Parser-differential oracle (`authpath/parser_differential.py`, "SAML roulette")
- **Lead + proof separation:** a parser disagreement is only a LEAD (flagging on
  disagreement alone would wreck precision). The finding is confirmed with the GAP-1
  out-of-band whoami primitive: stands only when the two parsers extract DIFFERENT
  identities from the same bytes AND an independent whoami proves the target acts as the
  pre-known VICTIM.
- **Two negative controls:** parsers disagree but the target acts as the ATTACKER (signed
  identity wins) → ABSTAIN; parsers AGREE (no differential) → ABSTAIN. Zero FP.
- `EffectClass.PARSER_DIFFERENTIAL` + ImpactClass + remediation (CWE-436 Interpretation
  Conflict / API2:2023).

## Verification (external oracles — AMP)
- `tests/run_all.py`: **754/754 PASSED, 0 FAILED, 0 IMPORT_ERRORS** (was 742; +12 new).
- `demo_live.py`: **precision 1.000, 0 false positives at every chaos level** — unchanged.
- Red lines held (RL1/RL2/RL3/RL5). Additive only; no existing verdict changed; the
  registry's zero-FP guard re-validates every new CONFIRMED.

## Honest scope
Both oracles are proven on self-authored vulnerable-vs-patched pairs (Tier-2 / AMP E2).
Live authorized targets (a real multi-tenant SaaS for GAP-2; a real SAML/JWT stack with
two parsers for GAP-4) are what lift them to T1 — the operator's run.
