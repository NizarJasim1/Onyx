# CRUCIBLE — problem #9 (GT3): AUTHN method-only gap — detector ALREADY generalizes

## SHAPE
GET /private requires a token (anon → 401), but a non-GET method (OPTIONS/HEAD) leaks the
same private body unauthenticated.

## KILL/DIAGNOSE (CT1, RL1)
Testing a non-GET method on the SAME resource with the SAME (no) credential varies only the
VERB-VECTOR — the action is quoted from the GET we already observe. RL1-safe confrontation
expansion (like verb-tunneling #7), not induction. Caveat: HEAD returns no body (confirmable
only via headers/length, not a body Δstate); OPTIONS rarely returns private data — so the
*confirmable* method-only gap is narrow: a non-GET method returning a PRIVATE BODY to anon.

## VERDICT — RESOLVED (no detector change needed); confirmed BY RUNNING
The AUTHN-gap detector keys on (anonymous principal + 200 + owner-declaring body),
INDEPENDENT of the HTTP method. Proven on the proving ground: an OPTIONS handler that leaks
an owner-declaring account body to anon on a CLEAN account (acct:1) was CAUGHT
(authn_gap, anon) — exactly as a GET leak would be. The detector already GENERALIZES across
method. Permanent regression: tests/test_authn_gap.py::test_authn_gap_is_method_independent.

The only residual is scan-POLICY: whether the probe matrix issues non-GET methods. That is a
run_gate3 / runner choice, NOT a detector defect. (Optional: add OPTIONS probes to the
matrix to exercise it in the fair measurement.) No build to the decision path.
