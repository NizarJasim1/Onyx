# Third-party verification — run ONYX on a target its author never wrote

The proving world is anti-circular *by construction* (an AST guard proves the target
imports no detector code; which endpoints are vulnerable is randomized and hash-sealed
before any attack). But one honest objection remains: **ONYX's author wrote that world.**
This page closes it the only way it can truly be closed — **you** run ONYX against a
target **you** control, authored by a third party (OWASP), and read the scorecard
yourself. The author is out of the loop.

You need Docker and ~10 minutes. ONYX needs only Python 3 + `requests`.

## 1. Stand up crAPI (authored by OWASP, not by us)
```bash
curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml
docker compose -f docker-compose.yml up -d
# crAPI is now on http://localhost:8888
```

## 2. Create three users and collect their tokens + object ids
Register three accounts (A, B, C) in the crAPI web UI, add a vehicle to each, and note
for each user: the **JWT** (from the login response / browser dev-tools), the
**vehicle UUID** (dashboard), and any **report/order/video ids** you generate. crAPI's
challenge guide walks through creating these: <https://github.com/OWASP/crAPI>.

Fill `crapi_kit/principals.json`:
```json
{ "A": {"Authorization": "Bearer <A's JWT>"},
  "B": {"Authorization": "Bearer <B's JWT>"},
  "C": {"Authorization": "Bearer <C's JWT>"} }
```

## 3. Fill the plan with your instance's real ids
`crapi_kit/plan.example.json` is the active-loop plan (each user observes their OWN
objects, then attacks the others'). Replace the `<...>` placeholders with the UUIDs /
ids from step 2. The plan structure — observe-own then attack-foreign — is fixed; only
the ids are yours.

## 4. The oracle is OWASP's, not ours
`crapi_kit/oracle.json` lists which crAPI endpoints are vulnerable. These values are the
**OWASP-documented crAPI challenges** (BOLA on vehicle location and mechanic report,
BFLA admin video delete, mass-assignment on orders, excessive data exposure in the
community feed) — the ground truth was defined by crAPI's authors, independent of ONYX.
You can (and should) verify each against crAPI's own challenge list.

## 5. Run ONYX against your live crAPI
```bash
cd proving_world
python3 byo_target.py \
    --base-url http://localhost:8888 \
    --principals crapi_kit/principals.json \
    --plan       crapi_kit/plan.json \
    --oracle     crapi_kit/oracle.json
```
You will get a per-endpoint scorecard and a precision/recall line. Every confirmation
is a proven Δstate (a read-back showing the leak/mutation/deletion), never a status
code. **If ONYX flags a safe endpoint, that is a real false positive in a run its author
never saw** — the honest test.

## What this proves (and what it does not)
- **Proves:** ONYX's zero-false-positive behaviour and its Δstate confirmations hold on a
  live, externally-authored target, measured against a ground truth you control — not on
  a benchmark we wrote.
- **Does not claim:** a field-wide generalization. It is crAPI, one app. Recall is scoped
  to what your plan exercises. The headline that travels is **precision** — zero false
  positives on a target we did not author.

## Even stronger: bring your *own* app
`byo_target.py` takes any base URL, principals, plan, and oracle. Point it at your own
staging app or any third-party vulnerable API. The moment the target is one we never
wrote, the circularity objection is gone — and the tooling to do that ships here.

## Fastest independent check: VAmPI (already wired)
For a target neither you nor we authored, with zero setup beyond Docker:
```bash
docker run -p 5000:5000 erev0s/vampi:latest          # erev0s's real app
# then point byo_target.py at it (principals/plan/oracle for VAmPI ship in external_targets/)
```
Or run the in-repo faithful port over real loopback HTTP right now:
```bash
python3 external_targets/run_vampi.py
```
The faithful port's authorization logic is transcribed verbatim from VAmPI's source and
is diff-able against it; running the upstream Docker image should reproduce the same
ONYX verdicts (BOLA + excessive-data exposure found; zero findings on the fixed version).
