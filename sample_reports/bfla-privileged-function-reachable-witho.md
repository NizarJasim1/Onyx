# BFLA — privileged function reachable without authority

**Finding ID:** `AP-C65724E6`  
**Severity:** High  
**Impact class:** Broken Function-Level Authorization (BFLA) / Confused Deputy  
**Effect-class:** `AUTHORITY`  
**Endpoint:** `GET /api/admin/users`  
**Classification source:** contract

## Summary
The action violates the conservation law **AUTHORITY: action.effect ⊆ principal.envelope**, which is true by the definition of the `AUTHORITY` effect-class. The violation was **confirmed by proven Δstate**, not a status-code diff.

## Causal path (proof)
1. Principal 'anon' issued GET /api/admin/users and received 200.
2. EIL law violated → AUTHORITY: action.effect ⊆ principal.envelope: anonymous principal successfully invoked privileged function GET /api/admin/users
3. Confirmed by Δstate via response-payload inspection + envelope authority check: BEFORE [function exposes data for principals ['A', 'B']] → AFTER ['anon' (no authority over this function) obtained that data] (read back as 'anon').

## Proof of Δstate
```
method : response-payload inspection + envelope authority check
before : function exposes data for principals ['A', 'B']
after  : 'anon' (no authority over this function) obtained that data
read as: anon
detail : privileged function returned cross-principal data to a non-authorised actor
```

## Reproduction (PoC)
1. As 'anon', send: GET /api/admin/users
2. Observe the privileged effect succeed (200).
3. As the legitimate owner 'anon', read the state back to confirm the change/leak persisted.

```bash
curl -X GET 'https://demo.local/api/admin/users' -H 'Authorization: Bearer $TOKEN_anon'
curl -X GET 'https://demo.local/api/admin/users' -H 'Authorization: Bearer $TOKEN_anon'
```

> Replace $TOKEN_<pid> with each principal's session credential. Run only within authorised program scope.

## Impact
Broken Function-Level Authorization (BFLA) / Confused Deputy.
