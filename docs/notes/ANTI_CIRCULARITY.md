# Anti-circularity — the honest threat model

A skeptic's sharpest objection to any self-run benchmark is: *"you wrote the target, so
of course your tool finds its bugs."* This page states, without spin, exactly how far
that objection is closed and where it is not.

## The three layers of independence, and which we have

| Layer | What it defeats | Status here |
|-------|-----------------|-------------|
| **Code isolation** | Detector and target sharing logic / leaking answers | **Closed.** `world.py` imports zero `authpath`; an AST guard + a test enforce it. The target computes responses from its own state; ONYX sees only HTTP. |
| **Answer isolation** | The author hand-picking which endpoints are vulnerable to match the detector | **Closed.** The vulnerability map is drawn from a per-seed RNG and **hash-sealed before any attack**; the run is scored against that seal. Across 25 seeds the vulnerable subset is different each time and ONYX has never seen it. |
| **Author isolation** | The author (even with the above) unconsciously shaping the target's *structure* to suit the detector | **Closed for a real third-party target (VAmPI), in CI; not for the self-authored proving world.** See below. |

The first two are real and mechanical, not rhetorical. The third is closed the only way
it honestly can be — by a target whose vulnerabilities someone else authored.

## Author isolation, closed against VAmPI (erev0s)
VAmPI (github.com/erev0s/VAmPI, 2021) is an intentionally-vulnerable API built by a third
party **to evaluate vulnerability-detection tools** — years before, and independently of,
ONYX. It ships a vuln ON/OFF switch that defines ground truth. ONYX runs against it here:

- **`external_targets/vampi_faithful.py`** carries VAmPI's authorization logic transcribed
  **verbatim** from its source (the exact `if vuln:` branches), attributed inline and
  diff-able against the upstream repo. The plumbing (Flask/sqlite) is ours and makes no
  authorization decision. We did not choose or shape these vulnerabilities — erev0s did.
- **`external_targets/run_vampi.py`** drives ONYX against it over **real loopback HTTP**.
- Result (in CI, `tests/test_vampi_external.py`): on erev0s's **SAFE** app ONYX produces
  **zero findings** (the external false-positive test — the crown jewel on a target we did
  not design); on the **vulnerable** app it confirms erev0s's **BOLA and excessive-data
  exposure** (recall 2/3, precision 1.000, zero FP).
- Honest limits: (1) it is a *faithful port run locally*, not the upstream Docker image —
  a judge can run `erev0s/vampi` in Docker + `byo_target.py` to confirm identical results;
  (2) n is small (3 authorization vulns); (3) the one miss (a cross-principal password
  change) is a *Δstate-observability* limit — a changed password is invisible without
  re-authentication, so ONYX abstains rather than guess. That is the design, not a bug.

The proving world still carries the honest residue (same author); VAmPI removes it for a
real target. The two are complementary: the proving world gives statistical power over a
*distribution*; VAmPI gives *author independence* on a fixed, externally-defined target.

## What we claim, precisely
- **On the self-authored proving world:** ONYX's zero-FP behaviour is real under code and
  answer isolation, over a distribution of unseen sealed worlds and under injected chaos.
  This measures the *method*, honestly caveated as author-not-isolated.
- **On VAmPI (author-isolated, in CI):** zero findings on erev0s's SAFE app; BOLA + EDE
  confirmed on the vulnerable app; precision 1.000. The vulnerabilities are erev0s's, not
  ours.
- **On real crAPI (author-isolated data):** zero false positives on 36 real probes,
  PCM-verified.
- **Full closure on any target you choose** is a third party running the shipped
  `byo_target.py` against a live crAPI or their own app. If a judge runs it and sees a
  false positive, that is a real defect on a target we never saw. We invite exactly that.

## The one sentence
Code and answer isolation are closed mechanically in-repo; author isolation is closed
in-repo against VAmPI (a third party's vulnerabilities, in CI) and against real crAPI data,
and is closeable on any target via the shipped `byo_target.py` — so the independence
argument now rests on runnable artifacts, not on trusting the author.
