# CHANGELOG — GAP-3 (nested/aliased field authz) + GAP-9 (valueless confirmation as default)

One seam: **field-level exposure confirmed without possessing the victim's value.**
GAP-3 lets ONYX SEE the fields (any depth, any alias); GAP-9 lets it CONFIRM their
over-exposure valuelessly, against the backend's own disclosed contract.

## GAP-3 — nested + aliased GraphQL field extraction (`authpath/graphql_fields.py`)
The existing parser read only top-level root selections. `parse_field_leaves` walks the
full selection set and returns every leaf as its alias-resolved RESPONSE path, at any
depth — so a restricted field smuggled via an alias or a nested selection is now visible.
Best-effort and tolerant (fragments, inline fragments, comments, args), a measured fact
off the request, never a policy (RL1).

## GAP-9 — valueless structural confirmation as a first-class, default basis
ONYX could already confirm structurally without a value (SAIE), but only as an optional
adjunct; the hot path matched the victim's value, which you can only do for principals
you own. The highest-value giant leaks are third-party fields you must NOT harvest.
- **Registry extended with a SECOND, equally-strict basis** (`authpath/oracle_registry.py`):
  `confirmation_basis="structural-contract"`. Its zero-FP guard requires a real proof,
  observed out-of-band, **anchored to the target's own disclosed contract** (RL1), probed
  as a **tester-owned attacker** — no victim value, no second owned principal. Just as
  strict as `value-match`, which is unchanged.
- **`GraphQLFieldAuthzOracle`** confirms a field the backend's OWN contract denies for a
  principal yet returns present+populated — valuelessly by default; a tester-owned value
  leak only RAISES severity. This solves the third-party-exposure class without harvesting
  anyone's data.
- `EffectClass.GRAPHQL_FIELD_AUTHZ` + ImpactClass + remediation (CWE-213 / API3:2023).

## Verification (external oracles — AMP)
- `tests/run_all.py`: **773/773 PASSED, 0 FAILED, 0 IMPORT_ERRORS** (was 765; +8 new).
- `demo_live.py`: **precision 1.000, 0 false positives at every chaos level** — unchanged.
- The existing value-match guard tests still pass (that path is byte-identical); the new
  structural basis has its own could-have-failed downgrade test. Red lines held.

## Honest scope
Proven on self-authored contract-vs-response pairs (Tier-2 / AMP E2). A live GraphQL
target that discloses its own field-authz errors lifts it to T1 — the operator's run.
