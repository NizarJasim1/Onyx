# P2 — Comparison Design (complete: six-step arc)

## The claim, made falsifiable
ONYX's thesis is that confirm-by-Δstate beats the status/length/fingerprint heuristic
every authorization scanner uses. P2 turns that thesis into a measured, reproducible
experiment instead of a slogan: it runs ONYX and a full-strength Autorize-equivalent
baseline over the SAME labeled traffic and reports precision/recall/F1 for both.

## Anti-strawman discipline (the integrity of the whole comparison)
A rigged baseline would make the result propaganda. Guards:
- `baseline.py` implements Autorize's DOCUMENTED algorithm verbatim — enforcement by
  status code, body fingerprint, and content-length vs the owner's original.
- It is given FULL strength: a realistic pre-configured fingerprint set AND, for
  every probe, the largest 2xx response any principal receives for that request as
  the high-privilege length reference.
- A dedicated test asserts the baseline's recall is high (>0.8) BEFORE any precision
  number is read — so a low precision can never be an artefact of a crippled baseline.

## The measured result (T2 — self-measured, stated honestly)
On the demo's labeled probes:
  - ONYX     precision 1.0   recall 1.0    F1 1.0    (fp 0)
  - baseline precision 0.471 recall 0.941  F1 0.627  (fp 18, fn 1)
The baseline is a real, working detector (recall 0.941 — it catches genuine BOLA).
Its 18 false positives are all benign cases — self-access, by-design rich shapes,
legitimate grants — where a status/length heuristic flags any 2xx and ONYX abstains
via Δstate/provenance. It also missed one finding by trusting a 403 that ONYX's
active probe proved was a field-level BOLA.

## Honest boundary (the part most tools would hide)
ONYX's 1.0/1.0 is measured on its OWN calibration set, so it is somewhat circular and
is stamped **T2**, never independent proof. The VALUE here is the structural
demonstration — a full-strength heuristic still produces 18 benign false positives
where confirm-by-Δstate produces none — not the exact perfect score. The independent
head-to-head (the real Autorize/ZAP against a third-party target such as crAPI) is
P0, and the harness says so in its own output.

## Files (100% additive — proved by diff)
- NEW authpath/baseline.py — AutorizeBaseline (faithful, full-strength; never in
  ONYX's detection path).
- NEW authpath/comparison.py — Metrics, owner-reference derivation, run_comparison,
  format_report; T2-stamped.
- NEW tests/test_baseline.py (7, fairness) + tests/test_comparison.py (5, structural
  result + tier honesty).

## Red lines
RL1 unchanged (ONYX's detection untouched; baseline is comparison-only). The two new
modules are imported by no live detection path. Deterministic, reproducible numbers.

## Verification
- 12 new tests green; baseline proven non-strawman before precision is compared.
- Live-path diff vs pre-P2: only baseline.py + comparison.py added — zero live-code change.
- 439/439 total (427 from P6 + 12) — zero regression.
- Demo byte-identical: 39/39, 19 findings, 3 dropped.
