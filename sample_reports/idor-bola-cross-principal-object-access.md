# IDOR / BOLA — cross-principal object access

**Finding ID:** `AP-9A4E79C6`  
**Severity:** High  
**Impact class:** Data Exposure / Broken Object-Level Authorization  
**Effect-class:** `OBJECT_ACCESS`  
**Endpoint:** `GET /api/orders/{id}`  
**Classification source:** contract

## Summary
The action violates the conservation law **OBJECT_ACCESS: object_id ∈ self_envelope**, which is true by the definition of the `OBJECT_ACCESS` effect-class. The violation was **confirmed by proven Δstate**, not a status-code diff.

## Causal path (proof)
1. Principal 'B' issued GET /api/orders/101 and received 200.
2. The decisive value originated in principal 'A''s response to GET /api/orders/{id} (field id) — it was never granted to 'B'.
3. EIL law violated → OBJECT_ACCESS: object_id ∈ self_envelope: object_id=101 accessed by 'B' is not in its measured self-envelope; it provably originated in principal 'A''s response (GET /api/orders/{id} → id)
4. Confirmed by Δstate via authenticated read-back as the legitimate owner: BEFORE [object 101 is private to 'A'] → AFTER [object 101 fully readable by 'B' (owner's private fields reproduced verbatim)] (read back as 'A').

## Proof of Δstate
```
method : authenticated read-back as the legitimate owner
before : object 101 is private to 'A'
after  : object 101 fully readable by 'B' (owner's private fields reproduced verbatim)
read as: A
detail : attacker response reproduces the owner's substantive private data
```

## Reproduction (PoC)
1. As 'B', send: GET /api/orders/101
2. Observe the privileged effect succeed (200).
3. As the legitimate owner 'A', read the state back to confirm the change/leak persisted.

```bash
curl -X GET 'https://demo.local/api/orders/101' -H 'Authorization: Bearer $TOKEN_B'
curl -X GET 'https://demo.local/api/orders/101' -H 'Authorization: Bearer $TOKEN_A'
```

> Replace $TOKEN_<pid> with each principal's session credential. Run only within authorised program scope.

## Impact
Data Exposure / Broken Object-Level Authorization.
