# ONYX

[![ci](https://github.com/NizarJasim1/onyx/actions/workflows/ci.yml/badge.svg)](https://github.com/NizarJasim1/onyx/actions/workflows/ci.yml) ![python](https://img.shields.io/static/v1?label=python&message=3.10+to+3.12&color=3776AB) ![deps](https://img.shields.io/badge/runtime%20deps-none-success) ![license](https://img.shields.io/badge/license-MIT-blue)

ONYX is a black-box engine for finding **authorization bugs** in web APIs: IDOR/BOLA,
mass assignment (BOPLA), broken function-level authorization, and the business-logic
cousins of those bugs (price and payment tampering, skipped workflow states, coupon
replay).

What makes it different is how it decides something is a bug. Most authorization
scanners compare responses between two users and guess from the status code or the
body length. ONYX only reports a finding when it can **read the state back and show
that something actually changed or leaked** across principals. No state change, no
finding.

The Python package is called `authpath`. It runs on the standard library alone.

```
$ python -m authpath demo        # self-authored calibration target
...
  39/39 probes matched · 19 findings · 3 candidate(s) dropped by Δstate
  all assertions passed ✓
```
<sub>Output of the built-in calibration run. The target is a self-authored simulation
with planted bugs and benign decoys, so this is a regression check, not an
independent benchmark.</sub>

---

## Why I built it

Tools like Autorize are useful but noisy. A `200 OK` with an error message inside,
a shared public object, or a response that only *looks* similar will all produce
"bypassed" results that someone has to triage by hand. The opposite also happens:
a real leak hidden inside a response that has the same length as a denial.

I wanted a tool whose output I could paste into a report without re-checking it.
That meant moving the decision away from "does this response look blocked?" to
"did user B just read or change something that only user A was allowed to touch?",
and answering that with measurements instead of heuristics.

## How it works

Each captured request goes through the same pipeline:

```
            ┌─ 0  Scope guard      anything uncertain → do nothing (dry-run by default)
            │  1  Transport        live HTTP, HAR replay, or an in-process mock target
request  ───┤  2  Contract         classify the effect: object access, payment, grant, ...
            │  3  Provenance       which principal each value really came from
            │  4  Envelope         what each principal held vs. merely saw
            │  5  Invariant laws   effect-specific rules → PASS or CANDIDATE
            │  6  Confirmer        multi-principal Δstate read-back → FINDING or DROP
            └─ 7  Report           causal path, curl PoC, CVSS, OWASP/CWE mapping
```

A few rules hold everywhere in the code:

- **No learned baselines.** Every judgment traces back to a declared contract, a law
  that is true by definition of the effect (e.g. "a refund can't exceed the original
  charge"), or something a principal was measured doing.
- **No model in the decision path.** Parsing, table lookups and predicates only.
- **Confirm by state change.** A law can only raise a *candidate*. It becomes a
  finding only after an authenticated read-back proves the property changed or leaked.
- **Fail safe.** Scope violations, ambiguous ownership, or irreversible actions in
  dry-run mode all resolve to doing nothing.

The details, module by module, are in [`docs/architecture.md`](docs/architecture.md).
The reasoning behind each rule is in [`docs/design-rationale.md`](docs/design-rationale.md).

## Quick start

No install needed for the offline parts.

```bash
git clone https://github.com/NizarJasim1/onyx.git && cd onyx

python -m authpath demo        # calibration run in the console
python -m authpath serve       # local dashboard at http://127.0.0.1:8787
```

The dashboard drives the real engine. You can watch requests move through each
stage, see every probe's verdict (`FINDING`, `Δ-DROPPED`, `CLEAN`, `HALTED`), and open
a finding to get its before/after state and a ready-to-run PoC.

### Scanning a real target

Only scan systems you own or are explicitly authorized to test.

```bash
pip install -e ".[live]"                        # adds `requests`

# turn a Burp / DevTools capture into a spec
python -m authpath import-har capture.har --scope api.example.test --out spec.json

# run it (optionally widen the surface from an OpenAPI doc)
python -m authpath scan spec.json --discover openapi.json --out reports/
```

`import-har` redacts live credentials by default, so fill in the tokens for your own
test accounts before scanning. `spec.json` describes the base URL and scope, the test accounts you control, an
optional effect contract, and the legitimate (`seed`) and test (`probe`) request
sequences. Other commands:

| command | what it does |
|---|---|
| `ingest` | analyze a HAR file fully offline, no live traffic |
| `discover` | expand the test surface from an OpenAPI/Swagger or GraphQL introspection doc |
| `classify` | read-only check of whether an endpoint is in ONYX's reach |
| `diagnostics` | read-only statistics report for sharing |

Example reports produced by the engine are in [`sample_reports/`](sample_reports).

## What it covers

| area | effect classes |
|---|---|
| Object level | IDOR/BOLA, read-side field leaks |
| Property level | mass assignment / BOPLA |
| Function level | BFLA, privilege-grant escalation |
| Business logic | payment, price, state gates, inventory, coupons |
| Time | revoked credentials that still work, authorization regressions between scans |
| Structure | two routes to the same resource with different checks, multi-step chains |

It also handles GraphQL (including field-level and aliased access), multi-tenant and
relationship-based (ReBAC) setups, async `202`/saga flows, and ETag/If-Match based
confirmation.

**Deliberately out of scope:** injection, XSS, SSRF, JWT crypto, brute force, rate
limiting, DoS. ONYX goes deep on one question. Narrowing the question is what makes
a measured answer possible.

**Known limits:** it is black-box only, it needs a phase of legitimate traffic to learn
who owns what, it needs at least two principals, and when it can't observe enough it
abstains and reports a coverage gap instead of guessing.

## Status

I keep claims about ONYX graded by how they were obtained (see
[`docs/CLAIMS.md`](docs/CLAIMS.md)): `T1` independent, `T2` self-measured, `T3` estimate,
`T4` true by construction. A CI gate rejects any metric in the docs that has no tier.

- Precision is a construction property (`T4`): nothing is emitted without a Δstate delta.
- On self-authored labeled traffic, ONYX produced no false positives where a
  reimplementation of the Autorize heuristic produced many (`T2`).
- crAPI read-leak verdicts match its documented behavior offline, with a passing
  negative control (spec conformance, not yet a live `T1` run).
- An independent live measurement on a third-party target is the next milestone.
  [`docs/status.md`](docs/status.md) explains what that run needs.

## Repository layout

```
authpath/          the engine (stdlib only)
dashboard/         control-center UI served by `authpath serve`
tests/             test suite, entry point tests/run_all.py
tools/             mutation harnesses and the claims gate
fixtures/          labeled calibration scenarios
external_targets/  recon, crawling, GraphQL/WebSocket ingestion, race and token probes
proving_ground/    sealed-oracle range for blind end-to-end runs
proving_world/     larger multi-tenant ranges
p0/                independent-measurement rig
scripts/           one-command runners for a local OWASP crAPI lab
docs/              architecture, rationale, claims, status, research notes
```

## Development

```bash
make test       # full suite, stdlib only
make demo       # calibration must stay byte-identical
make mutation   # mutation harnesses with minimum kill scores
make gate       # every metric in the docs must carry an evidence tier
make ci         # all of the above
```

`pytest` also works if you prefer it. CI runs the same targets on Python 3.10–3.12.

Adding a new bug class means adding a law:

```python
from authpath.eil import Law, LawContext
from authpath.models import EffectClass, ImpactClass

class RefundCap(Law):
    effect = EffectClass.PAYMENT
    name   = "PAYMENT: refund <= original charge"
    impact = ImpactClass.FINANCIAL

    def evaluate(self, ctx: LawContext):
        ...  # deterministic predicate over measured facts → PASS or self._candidate(...)

engine.eil.register(RefundCap())
```

The law only raises candidates. The confirmer still has to prove the state change.

## Responsible use

ONYX sends real requests with real credentials. Use it only on applications you own,
lab targets such as [OWASP crAPI](https://github.com/OWASP/crAPI), or programs whose
rules allow automated multi-account testing. The scope guard enforces technical scope;
staying inside a program's policy is on you. See [`SECURITY.md`](SECURITY.md).

## License

MIT. See [`LICENSE`](LICENSE).

---

Built and maintained by **Nizar Jasim Mohammed Al-Zubaidi** ([@NizarJasim1](https://github.com/NizarJasim1)).
