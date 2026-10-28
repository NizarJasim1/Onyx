# Deficiency #1 (the oracle problem) — SOLVED completely, under Protocol [19]

Protocol [19] forbids shipping a partial fix. The first pass closed one gap; the full
gap inventory and its closure follow. Every gap is either solved+tested or proven a real
structural wall **with the work-around applied and declared** — nothing "hard, untried".

## The gap inventory (Protocol [19] band 1) and its closure

| Gap | What was open | Closure |
|-----|---------------|---------|
| **A** | Distinguish declared sharing from a real breach, relative to an explicit hypothesis | SOLVED — precision 1.0; the legitimate sharing is suppressed, the breach emitted relative to the named invariant. |
| **B/C/D** | Owner/tenant is bound **server-side** and never appears in any body → owner unresolvable → abstain | SOLVED — the resource's tenant domain is **ESTABLISHED mechanically from the legitimate provisioning walk** (each tenant's own principals read their own resources during observe). Classification no longer needs the owner's identity to appear anywhere. The operator declares only the small principal→domain map; ONYX derives resource→domain. |
| **E** | RBAC / group-nesting / delegation give transitive access a flat model can't express | SOLVED — a declared **grant graph**; an access is permitted iff the actor's domain can reach the resource's domain through declared edges (transitive closure). |
| **FP-safety** | A resource legitimately reached by several domains during the walk could be mislabelled | SOLVED — such a resource is ambiguous → unassigned → never yields a breach (zero-FP preserved). |
| **F** | Do cross-principal writes/deletes (RL23/RL25) obey the policy too? | SOLVED — the gate sits at the single finding choke point (`_emit_finding`), so every law routes through it; verified for writes. |

Tests: `tests/test_policy_hypothesis.py` (7 cases, all gaps). MSI byte-identical
(hypothesis empty by default); full suite 500 green; dedup lint clean.

## The real walls (Protocol [19] band 3) — proven, not assumed, and worked around
Two limits are genuine (physics/logic, not laziness). [19] requires proving them AND
applying a work-around:
- **Designer intent is unmeasurable from outside.** Work-around: ONYX never claims
  absolute truth; every finding is emitted **relative to a declared invariant** — a
  measurable statement. The wall is redefined out of the decision path.
- **A server-side grant that is neither declared nor observable cannot be known.**
  Work-around: the grant graph is a declaration channel; anything undeclared and
  unobserved is **UNCOVERED → abstain**, so an unknown legitimate grant can never become
  a false positive. Coverage is bounded honestly, not silently.

## The [18] card (leap / hypothesis / weakest link)
- **(أ) Structural constraint removed:** ONYX was limited to in-band policy; it now
  consumes an out-of-band explicit policy channel **and** establishes tenant membership
  from observation, unlocking the cross-tenant / sharing-rich class — and substantially
  covering deficiency **#7** (tenant isolation), which the file calls a special case of #1.
- **(ب) Hypothesis the solution requires:** the operator declares principal→domain
  membership, isolation, any legitimate grant edges, and sharing links. ONYX derives the
  rest and emits every finding relative to that declaration.
- **(ج) Weakest remaining link (honest ceiling):** membership that is BOTH server-side
  AND never exercised by a legitimate owner during the walk stays invisible → ONYX
  abstains there (bounded by #2 surface and #4 invisible-Δstate). This is the declared
  wall, not a silent gap.

## Graduation (no overclaim)
Proven on a synthetic multi-tenant target that mixes legitimate sharing with a real
breach. Next honest station: a real two-tenant app the operator controls, via
`byo_target.py` with a declared hypothesis — not a Google/Microsoft claim.
