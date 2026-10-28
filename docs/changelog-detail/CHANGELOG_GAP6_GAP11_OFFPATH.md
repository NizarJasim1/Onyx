# CHANGELOG — GAP-6 (high-recall generation) + GAP-11 (portfolio EV + CVE dedup)

One seam: **the off-confirmation-path intelligence layer.** Both decide WHERE and in WHAT
ORDER ONYX probes; neither is in the decision path. They are competitive levers (recall,
efficiency) — the gap analysis explicitly separates them from detection capability.

## The red line (RL2) — why these are safe
Every lead these modules emit still goes through the deterministic Δstate / Oracle-
Registry confirmation UNCHANGED. An optional external (even offline-LLM) scorer may
influence probe ORDER; it can never make or confirm a finding. So recall and efficiency
rise while precision is untouched. No `EffectClass`, no oracle, no remediation entry —
these are planning utilities, not detectors.

## GAP-6 — `authpath/recall.py` (`RecallPlanner`, `CandidateLead`)
- Generates cross-principal probe leads from observed references and RANKS them by
  deterministic signals: how grounded the lead is (observed > spec > referenced > lineage
  > js), an effect-class prior, id-bearing / ownership-pointer / cross-principal-swappable
  signals, and prior confirmations in the same family (bugs cluster → probe there sooner).
- Optional `external_scorer` is bounded (×[0.5, 1.5]) so it re-orders but never dominates,
  and any exception from it is ignored (fail-safe). Pure stdlib, deterministic by default.

## GAP-11 — `authpath/portfolio.py` (`PortfolioPlanner`, `Asset`, `DedupIndex`)
- `PortfolioPlanner` allocates a finite budget across the WHOLE portfolio by expected
  value per budget unit (`est_value × p_success / est_cost`, boosted by prior yield) —
  global, where `economy.py` is per-host. Budget is strictly respected.
- `DedupIndex` tags a lead KNOWN (already a published CVE/report class) vs NOVEL via a
  deterministic signature `(effect, id-normalized endpoint, param)`, so no effort is spent
  re-finding a burned class. Corpus is operator-supplied; empty ⇒ everything novel.

## Verification (external oracles — AMP)
- `tests/run_all.py`: **782/782 PASSED, 0 FAILED, 0 IMPORT_ERRORS** (was 773; +9 new).
- `demo_live.py`: **precision 1.000, 0 false positives at every chaos level** — unchanged
  (as it must be: these modules never touch the confirmation path).

## Status & scope
Built and tested as off-path utilities ready for the engine/operator to consume before
spending probe budget; deliberately NOT wired into the engine hot path, to keep zero
regression. The external scorer is a seam for an offline model — none is bundled (ONYX
stays stdlib-only, no network, no ML in the decision path).
