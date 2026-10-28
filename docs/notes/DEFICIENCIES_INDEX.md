# ONYX — Ten Structural Deficiencies: Closure Index

All ten deficiencies from `ONYX_DEFICIENCIES.md` are closed under the R&D protocol system
(20 protocols), each with a full [19] gap inventory, an [18] qualitative-leap card, a
solved-criterion test, MSI preserved (byte-identical demo), and clean-extract verification.
Final combined state: **suite 542/542, byte-identical, lint clean, 49 solved-criterion
tests green.**

| # | Deficiency | Root move (the leap) | Module | Test | Doc |
|---|------------|----------------------|--------|------|-----|
| 1 | Oracle / policy (+#7 tenant isolation) | Explicit external policy hypothesis; resource-domain established from the legitimate walk; breach RELATIVE to a declared invariant | `policy.py` | 7/7 | `DEFICIENCY_1_SOLVED.md` |
| 2 | Surface discovery | Harvest references the target emitted (bodies/JS/lineage), not blind fuzzing; discovery only feeds detection → cannot add FP | `expander.py` | 6/6 | `DEFICIENCY_2_SOLVED.md` |
| 3 | Static identity vs live auth | Liveness gate — a negative is trusted only when an independent probe proves the credential live; 401-conflation impossible by construction | `session.py` | 5/5 | `DEFICIENCY_3_SOLVED.md` |
| 4 | Invisible-Δstate blindness | Consequence oracle — confirm via a consequence the effect necessarily entails (re-auth / capability flip) | `consequence.py` | 4/4 | `DEFICIENCY_4_SOLVED.md` |
| 5 | Chain synthesis | Capability graph — compose confirmed primitives into escalation paths; every edge Δstate-confirmed | `chain.py` | 5/5 | `DEFICIENCY_5_SOLVED.md` |
| 6 | Defensive adversary / stealth | Decouple the quorum's reproduction evidence from the loud burst; same majority semantics, quiet delivery; precision 1.0 under chaos | `stealth.py` | 4/4 | `DEFICIENCY_6_SOLVED.md` |
| 7 | Tenant isolation | (Special case of #1 — covered by the policy hypothesis) | `policy.py` | — | `DEFICIENCY_1_SOLVED.md` |
| 8 | Law-space search | Generative grammar — compose novel violation classes; confirmation stays Δstate → novelty with zero FP risk | `grammar.py` | 5/5 | `DEFICIENCY_8_SOLVED.md` |
| 9 | ROE governance | Multi-level engagement contract, fail-closed, tamper-evident audit, PII redaction; governs #1–#8 | `roe.py` | 8/8 | `DEFICIENCY_9_SOLVED.md` |
| 10 | Independent T1 number | (Execution, not code) turnkey `run_target` + sealed, tier-honest scorecard; the live run remains the operator's | `byo_runner.py` | 5/5 | `DEFICIENCY_10_SOLVED.md` |

## The honest overarching frame (unchanged, [16]/GP2)
The qualitative leap is NOT "ONYX now detects Google/Microsoft bugs" — that fails the lie
test. It is: the structural constraints locking ONYX to synthetic targets have been removed,
so its unique method — deterministic Δstate confirmation at zero false positives — is now
RUNNABLE on hardened, real production surfaces. Actual reach against any specific hardened
target remains a function of operator + surface + conditions. Every solution declares its
weakest remaining link and its proven walls (worked around where possible). The first honest
T1 number remains the operator's to run.

## Shared FP-safety principle across the new capabilities
Discovery (#2), consequence (#4), chaining (#5), stealth (#6), and generation (#8) all expand
WHAT ONYX looks for or HOW it delivers reads — none relaxes CONFIRMATION. Every finding still
requires a proven Δstate. So recall and reach rise while the zero-FP crown jewel is preserved
by construction, not by audit.
