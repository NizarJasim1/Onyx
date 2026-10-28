# Protocol [21] — Giant-surface targeting, gap G4 (the differential, MEASURED)

"Stronger than the giants on the deep-authz axis" must be a NUMBER, not prose. G4 encodes
the structural advantage and measures it on a scenario suite ([21].2, the real-peer test).

## Fair competitor model (not a strawman)
The strongest reasonable authz-diffing tool (Autorize / AuthMatrix class) compares RESPONSES
across principals — status code, content length, body similarity. Its structural limit: it
has NO OWNERSHIP MODEL. It can only ask "did the response differ?" — never "whose data is
this?". ONYX establishes ownership during the observe walk and confirms by Δstate.

## The measured result (`authpath/differential.py`, `tests/test_differential_measured.py`)
On a 6-scenario suite spanning the cases that separate the two methods:

| oracle | precision | recall | FP | FN |
|--------|-----------|--------|----|----|
| response-diff (competitor class) | **0.333** | **0.5** | 2 | 1 |
| ONYX (ownership + Δstate) | **1.000** | **1.000** | 0 | 0 |

The two decisive cases:
- **diff FALSE POSITIVE:** a benign extra public field makes the response differ across
  principals → the diff class flags a non-existent leak; ONYX sees no foreign value → clean.
- **diff FALSE NEGATIVE:** a cross-principal WRITE returns a generic `{"success":true}` for
  everyone → the diff class sees an identical response and misses it; ONYX confirms the
  victim-resource Δstate → caught.

MSI byte-identical; full suite 561 green; lint clean.

## The [21] card
- **(أ) Structural advantage encoded:** the differential is now an executable, measured
  artifact — ownership+Δstate vs response-diff — not a prose claim.
- **(ب) Differentiation (measured):** on this suite the competitor class scores precision
  0.333 / recall 0.5; ONYX scores 1.0 / 1.0. The gap is exactly the ownership model the
  diffing class structurally lacks — the deep-authz axis where ONYX is strongest.
- **(ج) Evidence measured:** the numbers above (tier: self-authored anvil, T2; it models the
  competitor's DOCUMENTED method, since the closed-source tools can't be run in-box — declared).
- **(د) Graduated station reached:** measured differential on a scenario suite. Still open:
  G5 (independent giant-property target). Live giant run stays the operator's.

## Honest scope ([21].7)
This proves the structural advantage on THIS suite against a faithful model of the diffing
class. It does not claim to beat every tool on every input, nor to have run the real
closed-source products. It encodes and measures the specific edge — the ownership model — and
that edge is real and load-bearing on the deep-authz axis.
