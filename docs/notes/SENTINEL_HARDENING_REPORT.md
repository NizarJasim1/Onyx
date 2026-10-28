# SENTINEL — Real-World Hardening Audit · Report

> A final cleanup pass under the SENTINEL protocol: close the gap between "passes the
> mock" and "matches the described power on a messy REAL target." The enemy here is
> not a missing vulnerability — it is the **silent failure** that turns described
> power into zero without making a sound. Four categories, ordered by how badly each
> threatens the described power; every claim below was checked against the running
> code, not asserted.

---

## S1 — Silent failure / crash isolation  *(FIXED)*

**What was found (real, severe).** The three real driver loops —
`cli.py`, `harimport.py` (HAR ingest), `chains.py` — called `engine.analyze(ex)`
**with no per-exchange guard**, and the additive passes inside `_finish` were
unguarded too. On a real target, the FIRST exchange that raised on a malformed
response would **crash the entire run** — every later exchange never analysed. The
described "analyses the whole capture" silently became "dies on exchange #K."

**Fix.** A `_guard` wrapper runs every additive pass (SAIE, RL15, RL17, RL16, RL18,
intrinsic) in isolation; an unexpected exception becomes a **visible** `errored`
diagnostic on the trace plus a `_pass_errors` counter — never a silent false
`clean`, never a crash. The three drivers now isolate per-exchange failures and
record them. The CLI summary **reports coverage gaps** (`⚠ coverage gaps: N pass
error(s)`) so the operator never mistakes incomplete coverage for a clean result.

**Verified.** `test_additive_pass_exception_is_contained_and_visible` forces a pass
to raise and asserts: analyse does not throw, the error is counted, the diagnostic is
visible, the outcome stays valid. Byte-identical on clean data (no pass raises ⇒
guard inert) — the 264 tests and the demo (39/39) are unchanged.

## S2 — Soundness leak / false positives on real data  *(FIXED)*

**What was found (real).** Sensitivity classification used naive substring matching,
so SHORT tokens false-positived on innocent field names: `pan` ⊂ **company**, `pan` ⊂
**japan**, `pin` ⊂ **shipping**. A benign field could be mislabelled sensitive,
risking a false positive in the cross-surface / temporal laws on a real target.

**Fix.** `_is_sensitive_key` is now **token-aware**: it splits a field name across
snake_case, kebab-case, dotted paths AND camelCase, and matches SHORT vocabulary
entries (≤4 chars) **only as a whole token** — longer entries may still substring-
match safely. `company`, `japan`, `shipping`, `public`, `campaign` are now correctly
non-sensitive, while `userSSN`, `iban_number`, `card_number` still match.

**Other soundness checks that PASSED (no fix needed).** The `_owner_of` resolution is
provenance-based (`laundered_from`), not a guess — it returns None when origin is
absent. The scope guard correctly HALTs out-of-scope hosts, **suffix-spoofs**
(`target.com.evil.com`), prefix-spoofs (`xtarget.com`), and an empty allow-list
(nothing in scope by default). `_read` fails safe (abstain) on scope/budget/WAF.

## S3 — Crash on real input  *(VERIFIED ROBUST)*

Fuzzed `analyze()` (all four engines on) with genuinely messy bodies — raw bytes,
plain strings, scalars, `NaN`, `None`, deeply-nested graphs, `{data:null,errors}` —
across REST and GraphQL paths: **zero uncontained crashes and zero swallowed
errors**. The existing `isinstance(body, (dict, list))` guards skip non-structural
bodies cleanly; the new `_guard` is the safety net for the unbounded tail of real-
world inputs that can't be enumerated. Locked by `test_messy_real_bodies_never_crash`.

## S4 — Coverage honesty  *(FIXED)*

**What was found (real).** The sensitivity vocabulary was English/US-centric: it
caught `ssn`/`iban`/`national_id` but **missed** `personnummer` (SE), `aadhaar` (IN),
`cpf`/`cnpj` (BR), `steuer_id` (DE), `codice_fiscale` (IT), `emirates_id` (AE), … On a
non-US target these are silent false negatives — the described "detects sensitive
field exposure" simply did not hold.

**Fix.** The vocabulary was broadened with international PII / national-identifier
names and a `register_sensitive_fields()` operator hook so a specific engagement can
declare the target's own field names (deterministic, RL1 — declared, never inferred).
Coverage gaps from S1 are now surfaced, so partial coverage is **reported**, not
hidden. Locked by `test_international_pii_covered` and
`test_operator_can_extend_vocabulary`.

---

## What this pass changed

| Area | Before | After |
|---|---|---|
| One bad real response | crashes the whole scan | contained + visible coverage gap |
| Additive pass exception | crash / would silently mislead | counted + diagnostic, run continues |
| `pan`/`pin` tokens | flag `company`/`shipping` (FP) | whole-token only (no FP) |
| International PII | missed (silent FN) | covered + operator-extensible |
| Coverage gaps | invisible | reported in the CLI summary |

Tests **256 → 264** (+8 SENTINEL). Demo **39/39 · 19 findings** unchanged. All four
engines (RL15–RL18) and the original pipeline are byte-identical on clean data.

---

## Residue — declared limitations (honest, not silently assumed)

These are inherent to a deterministic (non-ML, RL1) design and are now **declared**
rather than hidden:

1. **Sensitivity is vocabulary-based, never inferred.** It can be widened
   (`register_sensitive_fields`) but can never be complete — a field with a bespoke,
   unseen name needs operator declaration. This is a *coverage* bound (false
   negatives), never a *soundness* one (it cannot cause false positives).
2. **Subdomains are not auto-in-scope.** `sub.target.com` HALTs unless the operator
   allow-lists `*.target.com`. Conservative by design (legal safety first).
3. **Zero-FP remains conditional on baseline coverage and correct scoping**, exactly
   as documented for RL15–RL18: the engines confirm by live Δstate, so an incomplete
   baseline reduces *coverage*, never *precision*.
4. **Coverage gaps depend on the operator reading the report.** They are now surfaced
   prominently, but the tool cannot force attention — it can only refuse to call an
   un-analysed exchange "clean," which it now does.

## Epistemic honesty

This pass did not add power; it ensured the **existing** described power survives
contact with a real, messy target — by converting the worst failure mode (a silent
crash that hides as "clean") into a loud, counted, reported coverage gap, and by
fixing a genuine false-positive source and a genuine international-coverage gap. The
strongest true claim: ONYX now **fails honestly** — it never mistakes "I crashed" or
"I don't know that field" for "this is clean." The honest caveat: deterministic
sensitivity and scoping are bounds the operator must own, and are now declared in the
output rather than assumed.
