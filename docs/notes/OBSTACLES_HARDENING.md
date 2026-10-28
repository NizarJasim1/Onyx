# ONYX — Real-World Hardening (Obstacles 1–3)

These additions let ONYX operate against modern, well-defended targets **without
weakening its core**. Every one is OPT-IN, defaults to original behaviour, is
verdict-neutral, and was added under adversarial self-critique + regression tests
(`tests/test_fixes_regression.py`, 35/35).

## Obstacle 1 — Coherent header profile
- **Root:** replay sent only `Authorization`; every browser-coherence header was
  dropped → a bare token = classic tool signature; and a frozen profile reused
  per-request Sec-Fetch/Referer (incoherent), while the whole Cookie was redacted
  wholesale (broke coherence cookies + CSRF).
- **Fix:** capture the real, coherent header set per identity; split STABLE
  (UA/Accept/sec-ch-ua → `Principal.profile_headers`) from CONTEXTUAL
  (Sec-Fetch/Referer/Origin → carried per request); per-cookie redaction keeps
  coherence cookies + cookie shape, redacts only secret values; transport-managed
  headers (Host/Content-Length/Accept-Encoding) are stripped.
- **Honest boundary:** on-wire header ORDER and client-injected headers are a
  transport-stack fingerprint → that is obstacle 6 (a curl_cffi-class transport),
  not claimed here.

## Obstacle 2 — Source legitimacy & rate (not evasion)
- **Root reframed:** in authorised bug bounty, legitimacy comes from *declaration*,
  not hiding. Rotating residential IPs both **break determinism** (IP becomes a
  confound) and risk **voiding Safe Harbor** — rejected.
- **Fix:** (a) researcher **attribution** header (+ optional UA suffix) so the IP is
  allow-listable; (b) a **deterministic, seeded rate governor**, global per egress;
  (c) IP-stability invariant — ONE shared egress for all identities so any response
  delta is attributable to AUTHZ, not IP; (d) a **WAF block/challenge detector** so
  the confirmer ABSTAINS instead of comparing against a challenge page (a
  correctness guard, RL5).

## Obstacle 3 — Behavioural access pattern
- **Root:** multi-identity access of the same object is **intrinsic to the test**
  (cannot/should not be hidden). The *artifacts* are: cold isolated hits, metronomic
  timing, unnecessary clustering.
- **Fix:** **session-contextual warm-up** — before a probe, replay a few of the SAME
  principal's own captured benign GETs (responses discarded, **zero engine state
  change**), so the probe lands inside a plausible session. Governed, GET-only,
  aborts on challenge, deterministic, opt-in.
- **Honest boundary:** one IP acting as N identities on one object is NOT hidden —
  it is *sanctioned* in authorised testing and declared via attribution. Building
  evasion for it would be ineffective and push toward illegality.

## Invariants preserved (verified)
No LLM/anomaly in the decision path · confirm-by-Δstate only · Scope-Guard fails
safe to inaction · deterministic · additive & flag-gated (all defaults reproduce
original behaviour) · 27/27 calibration + 8 suites + 35 regression all green.

## Obstacle 4 — Session-state explosion
- **Root:** the confirmer replayed requests VERBATIM, with no notion of session-
  derived freshness → a stale CSRF/nonce/short-lived JWT → 403/401 → silent FALSE
  NEGATIVE on a real bug.
- **Fix (4a):** declarative `session_refresh` recipes — before a matching WRITE,
  fetch a FRESH token from a GET source and inject it (header/body/cookie). EXPLICIT
  only (never auto-applied); source is GET-only (no recursion); the verdict depends
  on Δstate, not token bytes (determinism preserved).
- **Fix (4b):** `detect_auth_expiry` — an explicit expiry (markers / 419 / 440) on an
  owner/control read-back makes the confirmer ABSTAIN with a clear "re-capture" note,
  never a silent "clean". A bare 401 is NOT mislabeled (avoids a misleading note).
- **Honest boundary:** cryptographic sender-constraint (DPoP / mTLS) signs each
  request with a private key — replay cannot forge it. Out of scope, stated.

## Obstacle 5 — Multi-step business logic
- **Root:** the engine's unit is a single Exchange; business-logic vulns are STATE
  MACHINES (ordered steps, live data dependencies, per-step actor, final invariant).
- **Fix:** `ChainRunner` — a declarative `chains` block. It threads data ({{var}}
  from earlier steps' saved fields), sends each step through the existing transport
  (so obstacles 1-4 apply) and feeds it to the ENGINE (every existing detector fires
  on live-minted values). The chain verdict is a DECLARATIVE invariant CONFIRMED by
  an owner-side read-back — so a chain finding needs a real breach, never "the
  requests worked". Findings carry the full ordered causal path + a real CVSS.
- **Safety:** every step clears scope-guard; mutating steps need may_mutate
  (dry_run aborts the chain). Deterministic despite live ids. Opt-in.
- **Honest boundary:** ONYX does not INVENT business rules; the user declares the
  invariant, ONYX confirms it by Δstate.

## Obstacle 6 — TLS / HTTP-2 fingerprint (the access gate)
- **Root:** `requests`/urllib3 has a static, catalogued JA3/JA4 + HTTP/1.1 + wrong
  header order. On Akamai/Cloudflare/DataDome the request is blocked at the TLS layer
  BEFORE the application — so ONYX's authorization genius never runs.
- **Fix:** a pluggable transport BACKEND. Default = `requests` (unchanged, zero new
  dependency). Opt-in `tls_impersonate` selects a curl_cffi backend with a real
  Chrome JA3/JA4 + HTTP-2 fingerprint; "auto" derives the profile from the captured
  UA so TLS + UA + headers all cohere (no cross-layer drift); a persistent Session
  keeps the HTTP-2 fingerprint stable (no mid-session drift). A missing curl_cffi
  RAISES (never a silent fallback to a blocked fingerprint). An explicit profile that
  contradicts the UA family warns.
- **Layered-boundary (no over-claiming):** impersonation fixes TLS/HTTP-2 + header
  order ONLY. It does NOT solve JS challenges (canvas/WebGL/Turnstile), behavioural
  signals, or IP reputation. On those, the obstacle-2 block detector makes ONYX
  ABSTAIN rather than mis-judge. Real on-wire JA4 effectiveness must be validated by
  the operator against a live authorised target (the dev sandbox has no network).

## Problem 1+2 — Discovery & N-principal matrix (integrated pipeline)
- **Root:** ONYX had the detection (Δstate) but not the COVERAGE — it only tested
  endpoints seen in the capture, with one identity per object. The two new modules
  were initially isolated; this integration wires them into one pipeline.
- **Bridge (`pipeline.py`):** extracts legitimate GET object-accesses from the
  capture (owner_pid, endpoint template, object_id) by matching concrete seed paths
  against contract templates — the input both expansions needed.
- **Problem 1 (`discovery.py`):** `scan --discover <openapi|introspection>` expands
  the contract from authoritative read-only docs; user-declared effects always win;
  auto-probes restricted to single-param object templates (no wrong multi-fill).
- **Problem 2 (`matrix.py`):** `scope.auto_matrix` builds the N-principal probe
  matrix (horizontal peers + vertical/anon) from observed accesses; owner-excluded;
  GET-only; bounded (`matrix_max_pairs`); deterministic.
- **Pipeline:** discover (expand contract) -> observe seed -> matrix (expand probes)
  -> existing engine confirms each by Δstate. Verified end-to-end: from an EMPTY
  contract+probe spec, the pipeline discovered the endpoint, generated the matrix,
  and confirmed the leak on a vulnerable target — and produced ZERO findings on a
  secure target (no false positive introduced anywhere in the integration).
- **Invariants:** both expansions opt-in (defaults off); Δstate gates every verdict
  (structurally cannot add an FP); deterministic; GET-only (no multiplied mutations);
  no LLM in the decision path.
- **Honest boundary:** discovery finds DECLARED endpoints only (hidden ones need
  JS/source-map mining + fuzzing); the matrix increases coverage, not cleverness —
  it cannot find a bug the confirmer would not confirm.

## Problem 3 — Error-semantics normalisation (`errnorm.py`)
- **Root:** ONYX judged a read-back "successful" on any 2xx and read denials by raw
  status, but large targets DECOUPLE status from meaning: 200-with-error-body (a
  false-positive trap), 404-as-403 to hide existence (a false-negative trap), and
  opaque gateway strings ("Missing Authentication Token").
- **Fix:** `classify_outcome(status, body, headers)` -> a canonical Outcome
  {AUTHORIZED, DENIED_AUTHZ, NOT_FOUND, NOT_AUTHENTICATED, CHALLENGE, ERROR}, reusing
  detect_block / detect_auth_expiry as one source of truth. Wired into the
  confirmer's `_resp_ok` so a REST 200 carrying an error envelope is NOT a successful
  object read. `disambiguate_attacker_404` relabels a masked deny using the owner's
  outcome (better lead signal, never a new finding).
- **Cardinal guard:** any explicit error signal (error/errors field, ok:false,
  success:false) can NEVER be AUTHORIZED — uncertainty always collapses toward
  DENIED/ERROR (RL5). snake_case/kebab-case error codes are normalised so markers
  match uniformly. Structural envelope test (not naive substring) so a data field
  literally named/containing "error" is not misread.
- **Verified:** kills the 200-with-error-body false positive in real detection while
  a genuine leak still fires; deterministic; Δstate still gates every verdict.
- **Honest boundary:** decodes common shapes (REST/GraphQL/Slack/AWS-gateway) via an
  extensible marker table + structural rules; truly novel error shapes fall to the
  conservative ERROR default — never to AUTHORIZED.

## Deep-semantic engine (gaps 1-3) + strategic classifier (track 1)
Grounded in a 107-report field BOLA taxonomy and 5 first-principles deep-dive sessions.

- **Gap 1 — id-format intelligence (`idformat.py`):** detects encoded id structure
  (int/padded/prefixed/base64-global-id/UUID/hex) and generates structure-preserving
  neighbour candidates (decode->increment->re-encode), preserving the observed
  encoding style (url-safe base64, no padding — matching real GraphQL global ids).
  39.2% of field BOLA uses encoded ids. Flag-gated; Δstate still gates every probe.
- **Gap 3 — action-level BOLA matrix (`action_matrix.py`):** the largest field family
  (41.7%). Generates state-change probes for non-owners, confirmed by an OWNER
  read-back (Δstate); rendered as one-step chains so the existing ChainRunner judges
  them. Irreversible actions excluded by default; every action gated by may_mutate
  (dry_run blocks). Zero-FP: "200" is never a finding without an owner-confirmed change.
- **Gap 2 — nested object references (`nestedref.py`):** finds object-reference fields
  in request BODIES, nested JSON, and query strings (conservative name+value match
  reusing idformat) and generates structure-preserving swaps. Exact rebuild; non-ref
  fields never swapped. (A real bug was caught in critique: "account" was wrongly
  blocked by the "count" substring; fixed by anchoring the blocklist.)
- **Track 1 — strategic surface classifier (`surface_intel.py`, READ-ONLY):** classifies
  a target as ARENA (unbound bearer API — ONYX's strong ground) / PARTIAL (browser/
  behavioural) / OUT_OF_REACH (DPoP/mTLS/attested — names the exact binding, states
  the honest replay limit). Conservative: only a positive binding signal flips a
  surface to bound; ambiguous defaults to ARENA (the 70%+ bearer prior). ARENA means
  the semantic layer is REACHABLE — it explicitly does NOT claim a vulnerability exists.
  A `classify` CLI command emits the verdict. Imported nowhere in the decision path.

DURABLE PRINCIPLE (from the deep dives): cryptographic protections (DPoP/mTLS/attestation)
secure AUTHENTICATION; they are blind to the AUTHORIZATION-semantics layer ONYX hunts.
So unbound bearer surfaces (the majority of the web) are reachable arenas; per-request
hardware-attested cores remain an honest structural limit.
