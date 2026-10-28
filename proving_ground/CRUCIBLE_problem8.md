# CRUCIBLE — problem #8 (GT3): shadow-admin endpoint — KILLED → CORRECT ABSTAIN

## LOOP 1-2 — KILL-THE-PROBLEM FIRST (CT1, RL1) — the problem does not survive
The vuln: an UNLINKED admin path (e.g. /internal/users/{id}/role) reachable + executable by
a non-admin. By definition it is declared in NO broadcast — no _links, no response field, no
observed exchange names it.

For a quote-not-induce tool to test it, ONYX must first KNOW it exists. The only ways to
learn an undeclared path are:
  (a) GUESS / enumerate (wordlists) → INDUCTION (RL1 violation) + active fuzzing of
      unrequested endpoints (violates quiet-by-default; manufactures FPs on 404/odd paths).
  (b) Observe it DECLARED somewhere ONYX reads (a link, a JS bundle, an ingested OpenAPI/
      GraphQL spec). But if it is declared there, it is NO LONGER shadow → it is an ordinary
      BFLA on a KNOWN action, already covered by problems #3 (plain) and #7 (verb-tunnel).

## VERDICT — do NOT build
A TRULY shadow (undeclared) endpoint is, for a quote-not-induce tool, observationally
non-existent; reaching it REQUIRES guessing = forbidden (RL1). Detecting it is therefore a
CORRECT ABSTAIN (the red line working), not a capability gap. Building a guesser/fuzzer
would betray RL1 and add false positives. The honest, already-correct scope:
  - path declared ANYWHERE ONYX reads (traffic / links / ingested spec) → known action →
    the existing BFLA detectors (#3, #7) handle it;
  - path declared NOWHERE → abstain (correct).

This sits beside problem #1 (ownership-less BOLA) and uniform-BOPLA: a measured-correct
abstain that must NOT be "fixed". Recognizing when NOT to build is a CRUCIBLE outcome.
