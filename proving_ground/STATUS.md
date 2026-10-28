# PROVING GROUND — status & handoff (GROUND protocol)

A real-HTTP measurement instrument with sealed ground truth, built to test ONYX without
Kali/internet. Goal: the strongest possible measurement under the constraint, honestly
bounded (it measures whether the tool works and where it is blind on real HTTP — NOT giant
behaviour like WAF/rate/scale).

## DONE — gates 1 & 2 (built BLIND of detection logic; see _catalog_started_at.txt)

- **Gate 1 — catalog.json**: authz vulnerability classes from OWASP API Top 10 (BOLA,
  BFLA, BOPLA, AUTHN gap), each with the attacker-side observable, plus FAMILIAR and
  STRANGE forms (7 strange) to test generalization not memorization, plus 5 legitimate
  decoys (feature-flag, null-not-forbidden, plan-tier, 404-vs-403, correct-denial) that
  MUST be abstained on (precision).
- **Gate 2 — proving_server.py + oracle.json**: a real stdlib HTTP server on loopback
  with tokens, /api/me attestation, and the catalog's bugs planted at SEEDED-RANDOM
  locations (seed I do not hand-tune). The exact ground truth is sealed in oracle.json +
  oracle.json.sha256 BEFORE any detector runs. VALIDATED over real HTTP: all 6 planted
  bugs behave exactly as the oracle claims, including the strange forms (iban leaks only
  via ?expand=full; ownership via ?invoice= secondary key; anon account read; non-owner
  DELETE). Run it in-process (threaded) — bash backgrounding is unreliable here.

## REFINEMENT NEEDED before gate 3 (found by running)
With only 6 objects and 6 planted bugs, almost every object is vulnerable, leaving too
little CLEAN surface to measure precision. Before gate 3: widen the world — add ~6 clean
objects and wire the explicit decoys (feature-flag field on a same-role pair; a plain
404; a correct 403 non-owner denial; a plan-tier field) so precision has something to be
right about. Keep the seed-random planting; just enlarge the pool.

## NEXT — gate 3 (THE UNBLINDING) and gates 4–5

**Gate 3 — run ONYX through real HTTP.** This is where the blindness ends: only now may
the detection logic be used. Build a small runner that:
  - starts proving_server in-process (threaded) on loopback;
  - drives ONYX via the REAL HTTPTarget (the same path used against any external host) —
    NOT mocks — with a spec whose principals carry the proving-ground tokens
    (tok-alice / tok-bob / tok-admin / anon) and seed GETs to /api/me + each object;
  - enables BOTH nerves (engine.nerve = True; engine.bva = True) + capture;
  - writes run.json via the export path.
  GT3 lock: do NOT edit any detection file after seeing results to improve the number;
  any such edit voids the round and restarts from gate 2 with a fresh oracle.

**Gate 4 — score run.json vs oracle.json automatically.** Recall (planted caught/missed),
Precision (any decoy flagged = FP), and per-FORM breakdown — the strange-form misses are
the real blindness (memorization vs generalization). Output a raw table, no cosmetics
(GT4: the raw result is sacred, handed over however embarrassing).

**Gate 5 — honest verdict (T3).** The tool's real level on HTTP and exactly where it is
blind, by the numbers; explicit that this does not measure giant-scale behaviour; the
measured gaps feed the next DEEP development cycle.

## HONEST CEILING (told to the user, kept here)
Because one mind designed both the target and the tool, this is a high-quality SIMULATION
of independent testing, not a substitute for it. It cannot exceed hands-on testing on an
independent target (crAPI) or surface a vulnerability outside the designer's imagination.
The real independence is regained by fixing the computer (Kali repair / bootable USB /
Docker-on-Windows) — that path stays the true goal; this is the strongest bridge under the
no-Kali, no-internet constraint.
