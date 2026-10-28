# CHANGELOG — GAP-7 (ReBAC transitive) + GAP-10 (consistency window)

Two gaps on one seam — **access derived from the relationship graph**. GAP-7 is the
graph's structure (is there a legitimate path?); GAP-10 is the graph in time (a path
removed at T still works until the cache propagates). Both live in `authpath/rebac.py`
over a shared `RelationGraph`, and both register through the Oracle Registry (GAP-5).

## RL1 — observed edges only, never a rebuilt policy
`RelationGraph` is built solely from relationship edges the target DISCLOSED (membership,
ownership, containment — the `ownership_pointer` discipline) and takes the transitive
closure of THOSE edges only. We never reconstruct policy. An observed path => legitimate;
absence of a path, Δstate-confirmed, => the breach.

## GAP-7 — ReBAC transitive-authz oracle (`ReBACOracle`, effect `REBAC_BYPASS`)
- Confirms ONLY when there is NO observed relationship path from principal to object AND
  Δstate proves the object belongs to another principal.
- **FP suppression (the point of the model):** a legitimate derived access
  (member -> group -> folder -> doc, a real path) ABSTAINS. This closes both failure
  directions the gap analysis named: the FN (missed unbacked access) and the FP pressure
  (legitimate transitive access mistaken for a leak).
- Remediation: evaluate the full relationship graph server-side (Zanzibar/Cedar/OPA).

## GAP-10 — consistency-window / "new enemy" oracle (`ConsistencyWindowOracle`, effect `CONSISTENCY_WINDOW`)
- A relationship is revoked (both endpoints tester-owned); an INDEPENDENT post-revocation
  read confirms a stale decision ONLY if access still works within the window.
- **Negative control:** if the revocation is enforced immediately (access denied), ABSTAIN.
  This is the race on the authorization DECISION (zookie/snapshot staleness), distinct from
  `TEMPORAL_DRIFT` (stale credential/authority on the resource).
- Remediation: read-your-writes / snapshot-token consistency on authz decisions.

## Verification (external oracles — AMP)
- `tests/run_all.py`: **765/765 PASSED, 0 FAILED, 0 IMPORT_ERRORS** (was 754; +11 new).
- `demo_live.py`: **precision 1.000, 0 false positives at every chaos level** — unchanged.
- Red lines held (RL1/RL2/RL3/RL5). Additive; no existing verdict changed.

## Honest scope
Both proven on self-authored vulnerable-vs-patched pairs (Tier-2 / AMP E2). A live
ReBAC/Zanzibar-style target with a measurable revocation window lifts them to T1 — the
operator's run.
