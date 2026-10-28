# ONYX — GAP_ANALYSIS_v3 closure index

Every gap from `ONYX_GAP_ANALYSIS_v3.md` is now addressed, built one seam (two gaps) per
session, each additive, each verified to preserve the crown jewel: zero false positives.
Baseline at start of this work: 728 tests, precision 1.000. End: **789 tests, precision
1.000, 0 FP at every chaos level.**

| Gap | What it closes | Module(s) | Basis / note |
|----|----------------|-----------|--------------|
| 5  | Oracle Registry (generalise the single confirmer) | `oracle_registry.py` | structural zero-FP guard + declared-unconfirmable slot |
| 1  | Identity proof layer / whoami-differential | `identity.py` | value-match, out-of-band whoami |
| 2  | Cross-tenant isolation `(identity, tenant)` | `tenant.py` | Δstate across a tester-owned tenant boundary |
| 4  | Parser-differential ("SAML roulette") | `parser_differential.py` | lead + out-of-band whoami proof |
| 3  | GraphQL field-level (nested/aliased) | `graphql_fields.py` | full selection parser |
| 9  | Valueless structural confirmation as default | `oracle_registry.py` (2nd basis) | `structural-contract`, no third-party data read |
| 7 (ReBAC) | Transitive relationship authz | `rebac.py` | observed-edge closure (RL1) |
| 10 | Consistency-window / new-enemy | `rebac.py` | revoked edge still grants → stale decision |
| 6  | High-recall generation/ranking | `recall.py` | off-path (RL2); optional offline scorer, bounded |
| 11 | Portfolio EV + known-CVE dedup | `portfolio.py` | off-path; global allocation + dedup index |
| 8  | Law↔state driving (deep state) | `state_driver.py` | consent-gated reach plan (RL5); honest unreachable |
| L1-8 | Scale / dynamic-object ownership pinning | `state_pin.py` | zookie-style snapshot; drift ⇒ abstain |
| 12 | Unconfirmable-black-box declared | `oracle_registry.py` | built into the registry from the start |
| 7 (hidden surface) | Undocumented surface discovery | — | OUT of ONYX by design — IOLITE's job (declared) |

## Invariant held across all of it
Every new capability expands WHAT ONYX looks for or HOW it reaches/orders probes. None
relaxes CONFIRMATION. Every finding still requires a proven Δstate (value-match) or a
backend-contract-anchored structural proof — both re-enforced by the registry's zero-FP
guard. Off-path modules (recall, portfolio, driver) never enter the decision path (RL2).

## The one binding constraint (unchanged, from HONEST_STATUS.md)
All of this is Tier-2 — proven on self-authored / controlled targets (AMP E2). The single
thing that converts the project from "verifiable" to "proven" is ONE live run against a
real, independently-authored, authorized target. No module here relieves that; it is the
operator's run, and it is what lifts any of these classes to T1.
