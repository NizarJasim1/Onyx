# Business-Logic — workflow gate skipped

**Finding ID:** `AP-F81FF685`  
**Severity:** High  
**Impact class:** Business-Logic Bypass / State-Gate Skip  
**Effect-class:** `STATE_GATE`  
**Endpoint:** `POST /api/orders/{id}/fulfil`  
**Classification source:** contract

## Summary
The action violates the conservation law **STATE_GATE: terminal state requires its predecessor gate**, which is true by the definition of the `STATE_GATE` effect-class. The violation was **confirmed by proven Δstate**, not a status-code diff.

## Causal path (proof)
1. Principal 'B' issued POST /api/orders/303/fulfil and received 200.
2. EIL law violated → STATE_GATE: terminal state requires its predecessor gate: object reached terminal state 'fulfilled' without its declared predecessor gate 'paid' satisfied on the same object — workflow-order gate skipped
3. Confirmed by Δstate via authenticated read-back of object workflow state: BEFORE [predecessor gate 'paid' not satisfied] → AFTER [object reached terminal state 'fulfilled'] (read back as 'B').

## Proof of Δstate
```
method : authenticated read-back of object workflow state
before : predecessor gate 'paid' not satisfied
after  : object reached terminal state 'fulfilled'
read as: B
detail : terminal state persisted without its required predecessor
```

## Reproduction (PoC)
1. As 'B', send: POST /api/orders/303/fulfil
2. Observe the privileged effect succeed (200).
3. As the legitimate owner 'B', read the state back to confirm the change/leak persisted.

```bash
curl -X POST 'https://demo.local/api/orders/303/fulfil' -H 'Authorization: Bearer $TOKEN_B'
curl -X GET 'https://demo.local/api/orders/303' -H 'Authorization: Bearer $TOKEN_B'
```

> Replace $TOKEN_<pid> with each principal's session credential. Run only within authorised program scope.

## Impact
Business-Logic Bypass / State-Gate Skip.
