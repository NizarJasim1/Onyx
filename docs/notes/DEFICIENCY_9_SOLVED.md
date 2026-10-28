# Deficiency #9 (ROE — a governing system, not flags) — SOLVED under [18]+[19]+[20]

Safety was a flat set of flags at host + action level. Real rules-of-engagement are
MULTI-LEVEL and must GOVERN every capability ONYX has (#1–#8): each action must trace to a
clause that authorizes it, anything unauthorized fails CLOSED, and every action lands in a
tamper-evident audit. This is the layer that makes ONYX safe to point at a real authorized
target — governance before capability.

## The root move ([4].R5) — an engagement contract, fail-closed, over one choke point
`authpath/roe.py`: an `EngagementContract` of typed clauses at every level, an
`authorize()` that traces each action to a clause and HALTs on any unauthorized level, a
`TamperEvidentAudit` (hash-chained), and `sanitize()` for PII. Wired at the single `analyze`
choke point after Scope-Guard, so it governs all capabilities. An empty contract is a no-op
(byte-identical); a populated one is the operator's license.

## Gap inventory ([19] band 1) and closure

| Gap | Level | Closure |
|-----|-------|---------|
| **1** | data | Cross-principal/destructive actions HALT unless the actor is a declared **test principal** — never a real user. |
| **2** | scope | Authorization is per-**path** clause, not just host; a path outside the engagement HALTs. |
| **3** | policy | "No automated scanning" is a clause every action checks → HALT when the program forbids it. |
| **4** | fine-destruction | A mutate/delete is allowed ONLY against a declared authorized **test resource** — directly guarding RL23/RL25/RL26 cross-principal writes/deletes. |
| **5** | data-handling | Sensitive fields (email, token, SSN, credential…) are **redacted** in findings and audit. |
| **6** | proof | A **hash-chained, tamper-evident** audit: any later edit breaks the chain; every entry cites its authorizing clause. |
| **7** | governs #1–#8 | The gate sits at the single `analyze` choke point → every capability path is fail-closed and audited. |

Tests: `tests/test_roe_governance.py` (8 cases). MSI byte-identical (empty contract = no-op);
full suite 527 green; dedup lint clean. Governance affects only what ONYX may DO — the zero-FP
finding logic is untouched.

## The wall ([19] band 3) — declared
ONYX cannot verify that a declared test account is truly a test account, nor assume legal
liability — the truthfulness of the operator's declaration and all liability remain the
operator's. ONYX enforces the contract faithfully and fails closed; it cannot validate the
contract's real-world correctness. Declared, not hidden.

## The [18] card
- **(أ) Structural constraint removed:** ROE went from flat host+action flags to a
  multi-level contract where every action traces to an authorizing clause and fails closed —
  the governance that makes the other nine capabilities safe to exercise on a real target.
- **(ب) Hypothesis the solution requires:** the operator supplies a signed engagement
  contract (test principals, engagement paths, authorized test resources, policy).
- **(ج) Weakest remaining link:** ONYX cannot verify the operator's declaration is truthful,
  and legal liability stays with the operator — an inherent boundary, declared.

## Graduation
Proven on synthetic multi-level clauses + engine fail-closed + tamper-evident audit + PII
redaction. Next honest station: a real signed engagement where every ONYX action traces to a
clause in the audit — not a Google/Microsoft claim.
